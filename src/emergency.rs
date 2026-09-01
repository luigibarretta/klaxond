use crate::config::{EmergencyConfig, RuntimeConfig};
use crate::delivery::channels::post_to_ntfy_with_config;
use crate::history::{EmergencyAttempt, EmergencyCandidate, EmergencyIncident, EmergencyPayload};
use crate::parsers::{Parts, action};
use crate::state::AppState;
use crate::util::{b64url_decode_padded, b64url_no_pad, hmac_hex, now_epoch, token_urlsafe};
use auth_modules::secrets::constant_time_eq;
use serde_json::json;
use std::collections::HashMap;

const ACK_HEADER: &str = "x-klaxond-emergency-token";

mod identity;
mod lifecycle;
mod scheduler;
#[cfg(test)]
mod tests;

use identity::{fingerprint, legacy_fingerprint};

pub use lifecycle::{
    acknowledge, active_stats, cancel, confirmation_page, confirmation_token_receipt, get, list,
    retry_now, token_from_headers, verify_receipt_token,
};
pub use scheduler::scheduler_tick;

pub enum PrepareResult {
    Normal,
    Duplicate(String),
    Managed {
        receipt_id: String,
        parts: Box<Parts>,
    },
}

pub async fn prepare(
    state: &AppState,
    severity: &str,
    parts: &Parts,
    labels: &HashMap<String, String>,
    source: &str,
) -> PrepareResult {
    let cfg = state.cfg();
    let fingerprint = fingerprint(source, parts, labels);
    let legacy_fingerprint = legacy_fingerprint(source, parts, labels);
    if severity == "resolved" {
        if cfg.emergency.enabled && cfg.emergency.auto_resolve {
            let mut fingerprints = vec![fingerprint.clone()];
            if legacy_fingerprint != fingerprint {
                // Receipts created before the stable Alertmanager group-key
                // rollout remain recoverable during an in-flight upgrade.
                fingerprints.push(legacy_fingerprint.clone());
            }
            for recovery_fingerprint in fingerprints {
                match state.history_store().emergency_terminalize_fingerprint(
                    &recovery_fingerprint,
                    "resolved",
                    "source-recovery",
                    now_epoch(),
                ) {
                    Ok(Some(incident)) if incident.state == "resolved" => {
                        transition_audit(state, &incident, "resolved", "source-recovery");
                        publish_terminal(
                            state,
                            &cfg,
                            &incident,
                            "Resolved automatically",
                            "The source reported recovery; emergency retries have stopped.",
                        )
                        .await;
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::error!("emergency recovery reconciliation failed: {err}")
                    }
                }
            }
        }
        return PrepareResult::Normal;
    }
    if !should_manage(&cfg.emergency, severity, labels, source) {
        return PrepareResult::Normal;
    }
    if legacy_fingerprint != fingerprint {
        match state.history_store().emergencies(Some("active"), 1_000) {
            Ok(active) => {
                if let Some(incident) = active
                    .into_iter()
                    .find(|incident| incident.fingerprint == legacy_fingerprint)
                {
                    state.metric_inc(
                        "klaxond_emergency_incidents_total",
                        &[("outcome", "coalesced")],
                        1,
                    );
                    return PrepareResult::Duplicate(incident.receipt_id);
                }
            }
            Err(err) => tracing::error!(
                "legacy emergency fingerprint reconciliation failed; continuing with stable identity: {err}"
            ),
        }
    }
    let now = now_epoch();
    let payload = EmergencyPayload {
        parts: parts.clone(),
    };
    let candidate = EmergencyCandidate {
        receipt_id: token_urlsafe(18),
        fingerprint,
        source: source.to_string(),
        severity: severity.to_string(),
        title: parts.title.chars().take(300).collect(),
        payload_json: match serde_json::to_string(&payload) {
            Ok(value) => value,
            Err(err) => {
                tracing::error!("serialize emergency payload failed: {err}");
                return PrepareResult::Normal;
            }
        },
        now,
        next_retry_at: now + cfg.emergency.retry_seconds as f64,
        expires_at: now + cfg.emergency.expire_seconds as f64,
        max_attempts: cfg.emergency.max_attempts,
    };
    match state.history_store().emergency_register(&candidate) {
        Ok(registration) if registration.created => {
            state.metric_inc(
                "klaxond_emergency_incidents_total",
                &[("outcome", "created")],
                1,
            );
            transition_audit(state, &registration.incident, "active", "ingest");
            PrepareResult::Managed {
                receipt_id: registration.incident.receipt_id.clone(),
                parts: Box::new(decorate_parts(
                    state,
                    &cfg,
                    &registration.incident,
                    parts.clone(),
                )),
            }
        }
        Ok(registration) => {
            state.metric_inc(
                "klaxond_emergency_incidents_total",
                &[("outcome", "coalesced")],
                1,
            );
            PrepareResult::Duplicate(registration.incident.receipt_id)
        }
        Err(err) => {
            // Fail open for delivery, but never silently claim durable emergency semantics.
            tracing::error!("emergency registration failed; delivering normally: {err}");
            state.metric_inc(
                "klaxond_emergency_storage_errors_total",
                &[("operation", "register")],
                1,
            );
            PrepareResult::Normal
        }
    }
}

pub fn record_initial_attempt(
    state: &AppState,
    receipt_id: &str,
    ntfy_ok: bool,
    telegram_ok: Option<bool>,
    smtp_ok: Option<bool>,
) {
    let cfg = state.cfg();
    let now = now_epoch();
    let attempt = EmergencyAttempt {
        receipt_id: receipt_id.to_string(),
        reservation_token: String::new(),
        now,
        next_retry_at: now + cfg.emergency.retry_seconds as f64,
        ntfy_ok,
        telegram_ok,
        smtp_ok,
        last_error: if ntfy_ok {
            String::new()
        } else {
            "initial ntfy delivery failed".into()
        },
    };
    if let Err(err) = state.history_store().emergency_initial_attempt(&attempt) {
        tracing::error!("record emergency initial attempt failed: {err}");
        state.metric_inc(
            "klaxond_emergency_storage_errors_total",
            &[("operation", "initial-attempt")],
            1,
        );
    }
    attempt_metric(state, "ntfy", ntfy_ok);
}

fn should_manage(
    cfg: &EmergencyConfig,
    severity: &str,
    labels: &HashMap<String, String>,
    source: &str,
) -> bool {
    if !cfg.enabled
        || cfg
            .exclude_sources
            .iter()
            .any(|item| item == &source.to_ascii_lowercase())
    {
        return false;
    }
    if let Some(value) = labels.get("emergency") {
        return matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    cfg.severities
        .iter()
        .any(|value| value.eq_ignore_ascii_case(severity))
}

fn decorate_parts(
    state: &AppState,
    cfg: &RuntimeConfig,
    incident: &EmergencyIncident,
    mut parts: Parts,
) -> Parts {
    let token = sign_token(
        state,
        &incident.receipt_id,
        incident.expires_at as i64 + 900,
    );
    parts.ntfy_sequence_id = Some(format!("klaxond-emergency-{}", incident.receipt_id));
    parts.emergency_ack_url = Some(format!(
        "{}/api/emergency/{}/ack",
        cfg.public_url, incident.receipt_id
    ));
    parts.emergency_ack_token = Some(token.clone());
    parts.skip_snooze = true;
    parts.actions.insert(
        0,
        action(
            "view",
            "Acknowledge emergency",
            &format!("{}/emergency/{token}", cfg.public_url),
        ),
    );
    parts
}

fn terminal_parts(incident: &EmergencyIncident, title: &str, body: &str) -> Parts {
    Parts {
        title: format!("{title}: {}", incident.title),
        body: body.to_string(),
        tags: vec!["white_check_mark".into(), "emergency".into()],
        actions: vec![],
        priority: "low".into(),
        alertname: incident.title.clone(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: Some(format!("klaxond-emergency-{}", incident.receipt_id)),
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}

async fn publish_terminal(
    state: &AppState,
    cfg: &RuntimeConfig,
    incident: &EmergencyIncident,
    title: &str,
    body: &str,
) {
    let parts = terminal_parts(incident, title, body);
    let ok = post_to_ntfy_with_config(
        state,
        cfg,
        &incident.severity,
        &parts,
        timeout_for(cfg, "ntfy", 15),
    )
    .await;
    attempt_metric(state, "ntfy-terminal", ok);
}

fn sign_token(state: &AppState, receipt: &str, exp: i64) -> String {
    let body = b64url_no_pad(
        json!({"r":receipt,"e":exp,"a":"ack"})
            .to_string()
            .as_bytes(),
    );
    format!(
        "{body}.{}",
        hmac_hex(state.session_key.as_slice(), body.as_bytes())
    )
}

fn verify_token(state: &AppState, token: &str) -> Option<String> {
    let (body, signature) = token.split_once('.')?;
    let expected = hmac_hex(state.session_key.as_slice(), body.as_bytes());
    if !constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
        return None;
    }
    let value: serde_json::Value =
        serde_json::from_slice(&b64url_decode_padded(body).ok()?).ok()?;
    if value.get("a")?.as_str()? != "ack" || value.get("e")?.as_i64()? < now_epoch() as i64 {
        return None;
    }
    value
        .get("r")?
        .as_str()
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn timeout_for(cfg: &RuntimeConfig, channel: &str, fallback: u64) -> u64 {
    cfg.tiers
        .iter()
        .find(|tier| tier.name == channel)
        .map(|tier| tier.timeout_seconds)
        .unwrap_or(fallback)
}

fn transition_audit(state: &AppState, incident: &EmergencyIncident, transition: &str, actor: &str) {
    tracing::info!(
        "AUDIT {}",
        json!({"audit":"emergency","receipt_id":incident.receipt_id,"source":incident.source,"severity":incident.severity,"transition":transition,"actor":actor,"attempts":incident.attempts,"timestamp": (now_epoch()*1000.0) as i64})
    );
    state.metric_inc(
        "klaxond_emergency_transitions_total",
        &[("transition", transition)],
        1,
    );
}

fn attempt_metric(state: &AppState, channel: &str, ok: bool) {
    state.metric_inc(
        "klaxond_emergency_attempts_total",
        &[("channel", channel), ("ok", if ok { "1" } else { "0" })],
        1,
    );
}

fn storage_error(state: &AppState, operation: &str, error: &anyhow::Error) {
    tracing::error!("emergency storage {operation} failed: {error}");
    state.metric_inc(
        "klaxond_emergency_storage_errors_total",
        &[("operation", operation)],
        1,
    );
}

fn format_epoch(value: f64) -> String {
    chrono::DateTime::from_timestamp(value as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "unknown time".into())
}
