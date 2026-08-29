use super::{
    ACK_HEADER, format_epoch, publish_terminal, storage_error, transition_audit, verify_token,
};
use crate::history::EmergencyIncident;
use crate::state::AppState;
use crate::util::{html_escape, now_epoch};

pub async fn acknowledge(
    state: &AppState,
    receipt_id: &str,
    actor: &str,
) -> Result<EmergencyIncident, String> {
    let now = now_epoch();
    let transitioned = state
        .history_store()
        .emergency_terminalize(receipt_id, "acknowledged", actor, now)
        .map_err(|err| storage_failure(state, "acknowledge", &err))?;
    let Some(incident) = transitioned else {
        let incident = state
            .history_store()
            .emergency_get(receipt_id)
            .map_err(|err| storage_failure(state, "get", &err))?
            .ok_or_else(|| "receipt-not-found".to_string())?;
        return if matches!(
            incident.state.as_str(),
            "resolved" | "acknowledged" | "cancelled" | "expired"
        ) {
            Ok(incident)
        } else {
            Err("receipt-not-active".into())
        };
    };
    transition_audit(state, &incident, "acknowledged", actor);
    let cfg = state.cfg();
    publish_terminal(
        state,
        &cfg,
        &incident,
        "Acknowledged",
        &format!("Acknowledged by {actor}; emergency retries have stopped."),
    )
    .await;
    state.metric_inc(
        "klaxond_emergency_incidents_total",
        &[("outcome", "acknowledged")],
        1,
    );
    state.metric_set(
        "klaxond_emergency_last_ack_latency_seconds",
        &[],
        (now - incident.created_at).max(0.0),
    );
    Ok(incident)
}

pub async fn cancel(
    state: &AppState,
    receipt_id: &str,
    actor: &str,
) -> Result<EmergencyIncident, String> {
    let transitioned = state
        .history_store()
        .emergency_terminalize(receipt_id, "cancelled", actor, now_epoch())
        .map_err(|err| storage_failure(state, "cancel", &err))?;
    let Some(incident) = transitioned else {
        return state
            .history_store()
            .emergency_get(receipt_id)
            .map_err(|err| storage_failure(state, "get", &err))?
            .ok_or_else(|| "receipt-not-found".to_string());
    };
    transition_audit(state, &incident, "cancelled", actor);
    let cfg = state.cfg();
    publish_terminal(
        state,
        &cfg,
        &incident,
        "Emergency cancelled",
        &format!("Cancelled by {actor}; emergency retries have stopped."),
    )
    .await;
    Ok(incident)
}

pub fn retry_now(state: &AppState, receipt_id: &str) -> Result<bool, String> {
    state
        .history_store()
        .emergency_retry_now(receipt_id, now_epoch())
        .map_err(|err| storage_failure(state, "retry", &err))
}

pub fn verify_receipt_token(state: &AppState, receipt_id: &str, token: &str) -> bool {
    verify_token(state, token).is_some_and(|receipt| receipt == receipt_id)
}

pub fn token_from_headers(headers: &axum::http::HeaderMap) -> &str {
    headers
        .get(ACK_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

pub fn confirmation_token_receipt(state: &AppState, token: &str) -> Option<String> {
    verify_token(state, token)
}

pub fn confirmation_page(state: &AppState, token: &str) -> Result<String, String> {
    let receipt =
        verify_token(state, token).ok_or_else(|| "invalid-or-expired-token".to_string())?;
    let incident = state
        .history_store()
        .emergency_get(&receipt)
        .map_err(|err| storage_failure(state, "get", &err))?
        .ok_or_else(|| "receipt-not-found".to_string())?;
    let active = incident.state == "active";
    let button = if active {
        format!(
            "<form method='post' action='/emergency/{token}'><button type='submit' style='font:inherit;padding:.8em 1.2em;border:0;border-radius:.5em;background:#dc2626;color:white;font-weight:700'>Acknowledge and stop retries</button></form>"
        )
    } else {
        format!(
            "<p><strong>Current state:</strong> {}</p>",
            html_escape(&incident.state)
        )
    };
    Ok(format!(
        "<!doctype html><html><meta name='viewport' content='width=device-width'><body style='font-family:system-ui,sans-serif;max-width:42rem;margin:3rem auto;padding:1rem'><h1>Emergency acknowledgement</h1><h2>{}</h2><p>{} delivery attempts since {}.</p>{button}<p style='color:#666'>Receipt <code>{}</code></p></body></html>",
        html_escape(&incident.title),
        incident.attempts,
        format_epoch(incident.created_at),
        html_escape(&incident.receipt_id)
    ))
}

pub fn list(
    state: &AppState,
    filter: Option<&str>,
    limit: usize,
) -> Result<Vec<EmergencyIncident>, String> {
    state
        .history_store()
        .emergencies(filter, limit)
        .map_err(|err| storage_failure(state, "list", &err))
}

pub fn get(state: &AppState, receipt: &str) -> Result<Option<EmergencyIncident>, String> {
    state
        .history_store()
        .emergency_get(receipt)
        .map_err(|err| storage_failure(state, "get", &err))
}

pub fn active_stats(state: &AppState) -> Result<(usize, f64), String> {
    state
        .history_store()
        .emergency_active_stats(now_epoch())
        .map_err(|err| storage_failure(state, "active-stats", &err))
}

fn storage_failure(state: &AppState, operation: &str, error: &anyhow::Error) -> String {
    storage_error(state, operation, error);
    format!("storage: {error}")
}
