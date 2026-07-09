use super::support::temp_paths;
use klaxond::inhibition::{ack_match, ack_sign, ack_verify, apply_inhibition};
use klaxond::parsers::normalize_labels;
use klaxond::state::AppState;
use serde_json::json;
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
