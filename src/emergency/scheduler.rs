use super::{
    attempt_metric, decorate_parts, publish_terminal, snapshot_for_incident, storage_error,
    terminal_parts, timeout_for,
};
use crate::config::RuntimeConfig;
use crate::delivery::channels::{
    post_to_ntfy_with_config, post_to_smtp_with_config, post_to_telegram_with_config,
};
use crate::history::{EmergencyAttempt, EmergencyIncident};
use crate::state::AppState;
use crate::util::{now_epoch, token_urlsafe};

pub async fn scheduler_tick(state: &AppState) {
    let cfg = state.cfg();
    expire_due(state, &cfg).await;
    for _ in 0..50 {
        match reserve_due(state, &cfg) {
            Reservation::Ready(incident) => process_retry(state, &cfg, *incident).await,
            Reservation::Retry => continue,
            Reservation::Empty => break,
        }
    }
}

async fn expire_due(state: &AppState, cfg: &RuntimeConfig) {
    match state.history_store().emergency_expire_due(now_epoch(), 50) {
        Ok(expired) => {
            for incident in expired {
                let snapshot = snapshot_for_incident(cfg, &incident);
                super::transition_audit(state, &incident, "expired", "scheduler");
                publish_terminal(
                    state,
                    cfg,
                    &incident,
                    "Emergency expired",
                    "The retry window ended without an acknowledgement.",
                )
                .await;
                if snapshot.notify_on_expiry {
                    notify_expiry_channels(state, cfg, &incident).await;
                }
            }
        }
        Err(err) => storage_error(state, "expire", &err),
    }
}

async fn notify_expiry_channels(
    state: &AppState,
    cfg: &RuntimeConfig,
    incident: &EmergencyIncident,
) {
    let snapshot = snapshot_for_incident(cfg, incident);
    let parts = terminal_parts(
        incident,
        "Emergency expired",
        "The retry window ended without an acknowledgement.",
    );
    if snapshot.telegram.enabled {
        let ok = post_to_telegram_with_config(
            state,
            cfg,
            &incident.severity,
            &parts,
            timeout_for(cfg, "telegram", 8),
        )
        .await;
        attempt_metric(state, "telegram-expiry", ok);
    }
    if snapshot.smtp.enabled {
        let ok = post_to_smtp_with_config(
            cfg,
            &incident.severity,
            &parts,
            timeout_for(cfg, "smtp", 10),
        )
        .await;
        attempt_metric(state, "smtp-expiry", ok);
    }
}

enum Reservation {
    Ready(Box<EmergencyIncident>),
    Retry,
    Empty,
}

fn reserve_due(state: &AppState, cfg: &RuntimeConfig) -> Reservation {
    let now = now_epoch();
    let incident =
        match state
            .history_store()
            .emergency_reserve_due(now, now + 300.0, &token_urlsafe(18))
        {
            Ok(Some(incident)) => incident,
            Ok(None) => return Reservation::Empty,
            Err(error) => {
                storage_error(state, "reserve", &error);
                return Reservation::Empty;
            }
        };
    let snapshot = snapshot_for_incident(cfg, &incident);
    match state.history_store().emergency_adjust_lease(
        &incident.receipt_id,
        &incident.reservation_token,
        now + snapshot.lease_seconds as f64,
    ) {
        Ok(true) => Reservation::Ready(Box::new(incident)),
        Ok(false) => {
            tracing::info!(receipt_id=%incident.receipt_id, "emergency lease adjustment lost race");
            Reservation::Retry
        }
        Err(err) => {
            storage_error(state, "adjust-lease", &err);
            Reservation::Retry
        }
    }
}

async fn process_retry(state: &AppState, cfg: &RuntimeConfig, incident: EmergencyIncident) {
    let snapshot = snapshot_for_incident(cfg, &incident);
    let Some(payload) = retry_payload(state, &incident) else {
        return;
    };
    let parts = decorate_parts(state, cfg, &incident, payload.parts);
    let ntfy_ok = post_to_ntfy_with_config(
        state,
        cfg,
        &incident.severity,
        &parts,
        timeout_for(cfg, "ntfy", 15),
    )
    .await;
    attempt_metric(state, "ntfy", ntfy_ok);
    let attempt_number = incident.attempts.saturating_add(1);
    let (telegram_ok, smtp_ok) =
        escalation_attempts(state, cfg, &incident, &parts, attempt_number).await;
    let now = now_epoch();
    let attempt = EmergencyAttempt {
        receipt_id: incident.receipt_id.clone(),
        reservation_token: incident.reservation_token.clone(),
        now,
        next_retry_at: now + snapshot.retry_seconds as f64,
        ntfy_ok,
        telegram_ok,
        smtp_ok,
        last_error: if ntfy_ok {
            String::new()
        } else {
            "ntfy retry failed".into()
        },
    };
    match state.history_store().emergency_complete_attempt(&attempt) {
        Ok(true) => {
            tracing::info!(receipt_id=%incident.receipt_id, attempt=attempt_number, ntfy_ok, "emergency retry completed")
        }
        Ok(false) => {
            tracing::info!(receipt_id=%incident.receipt_id, "emergency retry completion lost race to terminal transition")
        }
        Err(err) => storage_error(state, "complete", &err),
    }
}

fn retry_payload(
    state: &AppState,
    incident: &EmergencyIncident,
) -> Option<crate::history::EmergencyPayload> {
    incident.payload().map_err(|error| {
        tracing::error!(receipt_id=%incident.receipt_id, "invalid durable emergency payload: {error}");
        if let Err(storage_error_value) = state.history_store().emergency_terminalize(
            &incident.receipt_id,
            "cancelled",
            "invalid-payload",
            now_epoch(),
        ) {
            storage_error(state, "invalid-payload", &storage_error_value);
        }
    }).ok()
}

async fn escalation_attempts(
    state: &AppState,
    cfg: &RuntimeConfig,
    incident: &EmergencyIncident,
    parts: &crate::parsers::Parts,
    attempt_number: u32,
) -> (Option<bool>, Option<bool>) {
    let snapshot = snapshot_for_incident(cfg, incident);
    let telegram_ok = if incident.telegram_escalated_at.is_none()
        && snapshot.telegram.enabled
        && attempt_number >= snapshot.telegram.after_attempts
    {
        Some(
            post_to_telegram_with_config(
                state,
                cfg,
                &incident.severity,
                parts,
                timeout_for(cfg, "telegram", 8),
            )
            .await,
        )
    } else {
        None
    };
    let smtp_ok = if incident.smtp_escalated_at.is_none()
        && snapshot.smtp.enabled
        && attempt_number >= snapshot.smtp.after_attempts
    {
        Some(
            post_to_smtp_with_config(cfg, &incident.severity, parts, timeout_for(cfg, "smtp", 10))
                .await,
        )
    } else {
        None
    };
    if let Some(ok) = telegram_ok {
        attempt_metric(state, "telegram", ok);
    }
    if let Some(ok) = smtp_ok {
        attempt_metric(state, "smtp", ok);
    }
    (telegram_ok, smtp_ok)
}
