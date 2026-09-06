use super::support::temp_paths;
use klaxond::emergency::{self, PrepareResult};
use klaxond::inhibition::{ack_match, ack_sign, ack_verify, apply_inhibition};
use klaxond::parsers::{Parts, normalize_labels};
use klaxond::state::AppState;
use serde_json::json;
use std::collections::HashMap;
use tempfile::TempDir;

#[test]
fn inhibition_order_and_ack_match_python() {
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();

    let source_payload = json!({
        "status": "firing",
        "commonLabels": {"alertname":"NodeDown","inhibition_source":"node-down","host":"dev-01"}
    });
    let source_labels = normalize_labels("grafana", &source_payload);
    let (send, reason) = apply_inhibition(&state, "grafana", &source_labels, false);
    assert!(send);
    assert_eq!(reason, "source");

    let beszel_labels = normalize_labels("beszel", &json!({"alert":"CPU high","system":"dev-01"}));
    let (send, reason) = apply_inhibition(&state, "beszel", &beszel_labels, false);
    assert!(!send);
    assert_eq!(reason, "inhibited-by-node-down");

    let token = ack_sign(&state, "CPU high", 3600);
    let (alertname, why) = ack_verify(&state, &token);
    assert_eq!(why, "ok");
    assert_eq!(alertname.as_deref(), Some("CPU high"));
    klaxond::inhibition::register_ack_suppression(&state, "CPU high", 3600);
    let labels =
        std::collections::HashMap::from([("alertname".to_string(), "CPU high".to_string())]);
    assert_eq!(ack_match(&state, &labels).as_deref(), Some("CPU high"));
}

#[tokio::test]
async fn firing_inhibition_source_terminalizes_matching_emergency_without_faking_ack() {
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();
    let mut cfg = state.cfg();
    cfg.emergency.enabled = true;
    state.replace_config(cfg);

    let parts = Parts {
        title: "CPU pressure on dev-01".into(),
        body: "Dependent alert".into(),
        tags: vec![],
        actions: vec![],
        priority: "urgent".into(),
        alertname: "CPUHigh".into(),
        skip_snooze: false,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    };
    let labels = HashMap::from([
        ("alertname".into(), "CPUHigh".into()),
        ("host".into(), "dev-01".into()),
    ]);
    let receipt = match emergency::prepare(&state, "critical", &parts, &labels, "beszel").await {
        PrepareResult::Managed { receipt_id, .. } => receipt_id,
        _ => panic!("expected managed emergency"),
    };

    let source_labels = normalize_labels(
        "grafana",
        &json!({
            "status": "firing",
            "commonLabels": {
                "alertname": "NodeDown",
                "inhibition_source": "node-down",
                "host": "dev-01"
            }
        }),
    );
    let (send, reason) = apply_inhibition(&state, "grafana", &source_labels, false);
    assert!(send);
    assert_eq!(reason, "source");

    assert_eq!(emergency::reconcile_inhibited(&state).await, 1);
    let incident = emergency::get(&state, &receipt).unwrap().unwrap();
    assert_eq!(incident.state, "inhibited");
    assert_eq!(incident.terminal_by, "inhibition-source:node-down");
}
