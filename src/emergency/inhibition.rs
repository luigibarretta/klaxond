use super::{publish_terminal, snapshot_for_incident, storage_error, transition_audit};
use crate::state::AppState;
use crate::util::now_epoch;

/// Terminalize emergency receipts covered by a currently active Klaxond
/// inhibition. Alertmanager does not emit resolved callbacks merely because an
/// alert becomes inhibited, so without this reconciliation a receipt created
/// before its inhibition source arrived would keep retrying until ACK/expiry.
///
/// The transition is deliberately recorded as `inhibited`, never as an
/// operator acknowledgement or producer recovery.
pub async fn reconcile_inhibited(state: &AppState) -> usize {
    let cfg = state.cfg();
    let active = match state.history_store().emergencies(Some("active"), 1_000) {
        Ok(active) => active,
        Err(err) => {
            storage_error(state, "inhibition-reconcile-list", &err);
            return 0;
        }
    };
    let mut transitioned = 0;
    for incident in active {
        if !snapshot_for_incident(&cfg, &incident).auto_resolve {
            continue;
        }
        let payload = match incident.payload() {
            Ok(payload) => payload,
            Err(err) => {
                tracing::error!(
                    receipt_id = %incident.receipt_id,
                    "invalid durable emergency payload during inhibition reconciliation: {err}"
                );
                continue;
            }
        };
        let Some(suppressed_by) =
            crate::inhibition::is_suppressed(state, &payload.labels, &incident.source)
        else {
            continue;
        };
        let actor = format!("inhibition-source:{suppressed_by}");
        match state.history_store().emergency_terminalize(
            &incident.receipt_id,
            "inhibited",
            &actor,
            now_epoch(),
        ) {
            Ok(Some(terminal)) if terminal.state == "inhibited" => {
                transition_audit(state, &terminal, "inhibited", &actor);
                publish_terminal(
                    state,
                    &cfg,
                    &terminal,
                    "Emergency inhibited",
                    &format!(
                        "Suppressed by the authoritative {suppressed_by} condition; emergency retries have stopped."
                    ),
                )
                .await;
                state.metric_inc(
                    "klaxond_emergency_incidents_total",
                    &[
                        ("outcome", "inhibited"),
                        ("profile_id", &terminal.policy_id),
                    ],
                    1,
                );
                transitioned += 1;
            }
            Ok(_) => {}
            Err(err) => storage_error(state, "inhibition-reconcile-terminalize", &err),
        }
    }
    transitioned
}
