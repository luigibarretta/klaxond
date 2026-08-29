use super::{
    attempt_metric, decorate_parts, publish_terminal, storage_error, terminal_parts, timeout_for,
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
    if !cfg.emergency.enabled {
        return;
    }
    let now = now_epoch();
    match state.history_store().emergency_expire_due(now, 50) {
        Ok(expired) => {
            for incident in expired {
                super::transition_audit(state, &incident, "expired", "scheduler");
                publish_terminal(
                    state,
                    &cfg,
                    &incident,
                    "Emergency expired",
                    "The retry window ended without an acknowledgement.",
                )
                .await;
                if cfg.emergency.notify_on_expiry {
                    let parts = terminal_parts(
                        &incident,
                        "Emergency expired",
                        "The retry window ended without an acknowledgement.",
                    );
                    let telegram = post_to_telegram_with_config(
                        state,
                        &cfg,
                        &incident.severity,
                        &parts,
                        timeout_for(&cfg, "telegram", 8),
                    )
                    .await;
                    let smtp = post_to_smtp_with_config(
                        &cfg,
                        &incident.severity,
                        &parts,
                        timeout_for(&cfg, "smtp", 10),
                    )
                    .await;
                    attempt_metric(state, "telegram-expiry", telegram);
                    attempt_metric(state, "smtp-expiry", smtp);
                }
            }
        }
        Err(err) => storage_error(state, "expire", &err),
    }
    for _ in 0..50 {
        let now = now_epoch();
        let token = token_urlsafe(18);
        let incident = match state.history_store().emergency_reserve_due(
            now,
            now + cfg.emergency.lease_seconds as f64,
            &token,
        ) {
            Ok(Some(incident)) => incident,
            Ok(None) => break,
            Err(err) => {
                storage_error(state, "reserve", &err);
                break;
            }
        };
        process_retry(state, &cfg, incident).await;
    }
}

async fn process_retry(state: &AppState, cfg: &RuntimeConfig, incident: EmergencyIncident) {
    let payload = match incident.payload() {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!(receipt_id=%incident.receipt_id, "invalid durable emergency payload: {err}");
            if let Err(storage_err) = state.history_store().emergency_terminalize(
                &incident.receipt_id,
                "cancelled",
                "invalid-payload",
                now_epoch(),
            ) {
                storage_error(state, "invalid-payload", &storage_err);
            }
            return;
        }
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
    let mut telegram_ok = None;
    let mut smtp_ok = None;
    if incident.telegram_escalated_at.is_none()
        && attempt_number >= cfg.emergency.telegram_after_attempts
    {
        telegram_ok = Some(
            post_to_telegram_with_config(
                state,
                cfg,
                &incident.severity,
                &parts,
                timeout_for(cfg, "telegram", 8),
            )
            .await,
        );
        attempt_metric(state, "telegram", telegram_ok.unwrap_or(false));
    }
    if incident.smtp_escalated_at.is_none() && attempt_number >= cfg.emergency.smtp_after_attempts {
        smtp_ok = Some(
            post_to_smtp_with_config(
                cfg,
                &incident.severity,
                &parts,
                timeout_for(cfg, "smtp", 10),
            )
            .await,
        );
        attempt_metric(state, "smtp", smtp_ok.unwrap_or(false));
    }
    let now = now_epoch();
    let attempt = EmergencyAttempt {
        receipt_id: incident.receipt_id.clone(),
        reservation_token: incident.reservation_token.clone(),
        now,
        next_retry_at: now + cfg.emergency.retry_seconds as f64,
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
