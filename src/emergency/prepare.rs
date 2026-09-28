use super::{
    decorate_parts, publish_terminal, snapshot_for_incident, snapshot_from_profile,
    transition_audit,
};
use crate::config::{EmergencyProfile, RuntimeConfig, select_emergency_profile};
use crate::emergency::identity::{fingerprint, legacy_fingerprint};
use crate::history::{EmergencyCandidate, EmergencyPayload, EmergencyPolicySnapshot};
use crate::parsers::Parts;
use crate::state::AppState;
use crate::util::{now_epoch, token_urlsafe};
use std::collections::HashMap;

pub enum PrepareResult {
    Normal,
    Duplicate(String),
    Managed {
        receipt_id: String,
        parts: Box<Parts>,
        policy: EmergencyPolicySnapshot,
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
    let stable = fingerprint(source, parts, labels);
    let legacy = legacy_fingerprint(source, parts, labels);
    if severity == "resolved" {
        reconcile_recovery(state, &cfg, &stable, &legacy).await;
        return PrepareResult::Normal;
    }
    let routing =
        select_emergency_profile(&cfg.emergency, severity, source, &parts.alertname, labels);
    let Some(profile) = routing.selected else {
        return PrepareResult::Normal;
    };
    if let Some(receipt_id) = legacy_duplicate(state, &stable, &legacy) {
        return PrepareResult::Duplicate(receipt_id);
    }
    let policy = snapshot_from_profile(&profile);
    let Some(candidate) = candidate(CandidateInput {
        fingerprint: stable,
        source,
        severity,
        parts,
        labels,
        profile: &profile,
        policy: &policy,
    }) else {
        return PrepareResult::Normal;
    };
    register(
        state,
        RegistrationInput {
            cfg: &cfg,
            parts,
            profile,
            policy,
            forced: routing.forced,
            candidate,
        },
    )
}

async fn reconcile_recovery(state: &AppState, cfg: &RuntimeConfig, stable: &str, legacy: &str) {
    let fingerprints = if legacy == stable {
        vec![stable]
    } else {
        vec![stable, legacy]
    };
    for fingerprint in fingerprints {
        let active = state
            .history_store()
            .emergencies(Some("active"), 1_000)
            .unwrap_or_default()
            .into_iter()
            .find(|incident| incident.fingerprint == fingerprint);
        if active
            .as_ref()
            .is_none_or(|incident| !snapshot_for_incident(cfg, incident).auto_resolve)
        {
            continue;
        }
        resolve_fingerprint(state, cfg, fingerprint).await;
    }
}

async fn resolve_fingerprint(state: &AppState, cfg: &RuntimeConfig, fingerprint: &str) {
    match state.history_store().emergency_terminalize_fingerprint(
        fingerprint,
        "resolved",
        "source-recovery",
        now_epoch(),
    ) {
        Ok(Some(incident)) if incident.state == "resolved" => {
            transition_audit(state, &incident, "resolved", "source-recovery");
            publish_terminal(
                state,
                cfg,
                &incident,
                "Resolved automatically",
                "The source reported recovery; emergency retries have stopped.",
            )
            .await;
        }
        Ok(_) => {}
        Err(error) => tracing::error!("emergency recovery reconciliation failed: {error}"),
    }
}

fn legacy_duplicate(state: &AppState, stable: &str, legacy: &str) -> Option<String> {
    if legacy == stable {
        return None;
    }
    let active = match state.history_store().emergencies(Some("active"), 1_000) {
        Ok(active) => active,
        Err(error) => {
            tracing::error!(
                "legacy emergency fingerprint reconciliation failed; continuing with stable identity: {error}"
            );
            return None;
        }
    };
    let incident = active
        .into_iter()
        .find(|incident| incident.fingerprint == legacy)?;
    state.metric_inc(
        "klaxond_emergency_incidents_total",
        &[
            ("outcome", "coalesced"),
            ("profile_id", &incident.policy_id),
        ],
        1,
    );
    Some(incident.receipt_id)
}

struct CandidateInput<'a> {
    fingerprint: String,
    source: &'a str,
    severity: &'a str,
    parts: &'a Parts,
    labels: &'a HashMap<String, String>,
    profile: &'a EmergencyProfile,
    policy: &'a EmergencyPolicySnapshot,
}

fn candidate(input: CandidateInput<'_>) -> Option<EmergencyCandidate> {
    let now = now_epoch();
    let payload = EmergencyPayload {
        parts: input.parts.clone(),
        labels: input.labels.clone(),
    };
    Some(EmergencyCandidate {
        receipt_id: token_urlsafe(18),
        fingerprint: input.fingerprint,
        source: input.source.to_string(),
        severity: input.severity.to_string(),
        title: input.parts.title.chars().take(300).collect(),
        payload_json: serialize(&payload, "payload")?,
        policy_id: input.profile.id.clone(),
        policy_name: input.profile.name.clone(),
        policy_snapshot_json: serialize(input.policy, "policy snapshot")?,
        now,
        next_retry_at: now + input.profile.retry_seconds as f64,
        expires_at: now + input.profile.expire_seconds as f64,
        max_attempts: input.profile.max_attempts,
    })
}

fn serialize(value: &impl serde::Serialize, label: &str) -> Option<String> {
    serde_json::to_string(value)
        .map_err(|error| tracing::error!("serialize emergency {label} failed: {error}"))
        .ok()
}

struct RegistrationInput<'a> {
    cfg: &'a RuntimeConfig,
    parts: &'a Parts,
    profile: EmergencyProfile,
    policy: EmergencyPolicySnapshot,
    forced: bool,
    candidate: EmergencyCandidate,
}

fn register(state: &AppState, input: RegistrationInput<'_>) -> PrepareResult {
    match state.history_store().emergency_register(&input.candidate) {
        Ok(registration) if registration.created => {
            record_created(state, &registration.incident, &input.profile, input.forced);
            PrepareResult::Managed {
                receipt_id: registration.incident.receipt_id.clone(),
                parts: Box::new(decorate_parts(
                    state,
                    input.cfg,
                    &registration.incident,
                    input.parts.clone(),
                )),
                policy: input.policy,
            }
        }
        Ok(registration) => {
            state.metric_inc(
                "klaxond_emergency_incidents_total",
                &[
                    ("outcome", "coalesced"),
                    ("profile_id", &registration.incident.policy_id),
                ],
                1,
            );
            PrepareResult::Duplicate(registration.incident.receipt_id)
        }
        Err(error) => {
            tracing::error!("emergency registration failed; delivering normally: {error}");
            state.metric_inc(
                "klaxond_emergency_storage_errors_total",
                &[("operation", "register")],
                1,
            );
            PrepareResult::Normal
        }
    }
}

fn record_created(
    state: &AppState,
    incident: &crate::history::EmergencyIncident,
    profile: &EmergencyProfile,
    forced: bool,
) {
    state.metric_inc(
        "klaxond_emergency_incidents_total",
        &[("outcome", "created"), ("profile_id", &profile.id)],
        1,
    );
    state.metric_inc(
        "klaxond_emergency_profile_matches_total",
        &[
            ("profile_id", &profile.id),
            ("forced", if forced { "1" } else { "0" }),
        ],
        1,
    );
    transition_audit(state, incident, "active", "ingest");
}
