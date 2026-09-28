use crate::config::{EmergencyProfile, RuntimeConfig};
use crate::delivery::channels::post_to_ntfy_with_config;
use crate::history::{
    EmergencyAttempt, EmergencyChannelSnapshot, EmergencyIncident, EmergencyPolicySnapshot,
};
use crate::parsers::{Parts, action};
use crate::state::AppState;
use crate::util::{b64url_decode_padded, b64url_no_pad, hmac_hex, now_epoch};
use auth_modules::secrets::constant_time_eq;
use serde_json::json;

const ACK_HEADER: &str = "x-klaxond-emergency-token";

mod identity;
mod inhibition;
mod lifecycle;
mod prepare;
mod scheduler;
#[cfg(test)]
mod tests;

pub use inhibition::reconcile_inhibited;
pub use lifecycle::{
    acknowledge, active_stats, cancel, confirmation_page, confirmation_token_receipt, get, list,
    retry_now, token_from_headers, verify_receipt_token,
};
pub use prepare::{PrepareResult, prepare};
pub use scheduler::scheduler_tick;

pub fn record_initial_attempt(
    state: &AppState,
    receipt_id: &str,
    ntfy_ok: bool,
    telegram_ok: Option<bool>,
    smtp_ok: Option<bool>,
) {
    let cfg = state.cfg();
    let snapshot = state
        .history_store()
        .emergency_get(receipt_id)
        .ok()
        .flatten()
        .map(|incident| snapshot_for_incident(&cfg, &incident))
        .unwrap_or_else(|| snapshot_from_profile(&EmergencyProfile::legacy_default()));
    let now = now_epoch();
    let attempt = EmergencyAttempt {
        receipt_id: receipt_id.to_string(),
        reservation_token: String::new(),
        now,
        next_retry_at: now + snapshot.retry_seconds as f64,
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
    if let Some(ok) = telegram_ok {
        attempt_metric(state, "telegram", ok);
    }
    if let Some(ok) = smtp_ok {
        attempt_metric(state, "smtp", ok);
    }
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
        json!({"audit":"emergency","receipt_id":incident.receipt_id,"source":incident.source,"severity":incident.severity,"policy_id":incident.policy_id,"policy_name":incident.policy_name,"transition":transition,"actor":actor,"attempts":incident.attempts,"timestamp": (now_epoch()*1000.0) as i64})
    );
    state.metric_inc(
        "klaxond_emergency_transitions_total",
        &[
            ("transition", transition),
            ("profile_id", &incident.policy_id),
        ],
        1,
    );
}

pub(crate) fn snapshot_from_profile(profile: &EmergencyProfile) -> EmergencyPolicySnapshot {
    EmergencyPolicySnapshot {
        schema_version: 1,
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        retry_seconds: profile.retry_seconds,
        expire_seconds: profile.expire_seconds,
        max_attempts: profile.max_attempts,
        lease_seconds: profile.lease_seconds,
        telegram: EmergencyChannelSnapshot {
            enabled: profile.telegram.enabled,
            after_attempts: profile.telegram.after_attempts,
        },
        smtp: EmergencyChannelSnapshot {
            enabled: profile.smtp.enabled,
            after_attempts: profile.smtp.after_attempts,
        },
        notify_on_expiry: profile.notify_on_expiry,
        auto_resolve: profile.auto_resolve,
    }
}

pub(crate) fn snapshot_for_incident(
    cfg: &RuntimeConfig,
    incident: &EmergencyIncident,
) -> EmergencyPolicySnapshot {
    incident.policy_snapshot().unwrap_or_else(|_| {
        let profile = cfg
            .emergency
            .profiles
            .iter()
            .find(|profile| profile.id == cfg.emergency.fallback_profile)
            .cloned()
            .unwrap_or_else(EmergencyProfile::legacy_default);
        let mut snapshot = snapshot_from_profile(&profile);
        snapshot.max_attempts = incident.max_attempts;
        snapshot.expire_seconds = (incident.expires_at - incident.created_at).max(0.0) as u64;
        snapshot
    })
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
