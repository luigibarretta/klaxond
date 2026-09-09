use super::{common_labels, ingest_source};
use crate::config::{Paths, load_runtime_config};
use serde_json::json;
use tempfile::TempDir;

fn config() -> crate::config::RuntimeConfig {
    let temp = TempDir::new().unwrap();
    load_runtime_config(&Paths::for_root(temp.path())).unwrap()
}

#[test]
fn dedicated_blackstart_route_preserves_source_identity() {
    let cfg = config();
    assert_eq!(
        ingest_source("/blackstart/critical", &cfg).as_deref(),
        Some("blackstart")
    );
    assert_eq!(
        ingest_source("/webhook/critical", &cfg).as_deref(),
        Some("grafana")
    );
}

#[test]
fn dedicated_github_route_preserves_source_identity() {
    let cfg = config();
    assert_eq!(
        ingest_source("/github/info", &cfg).as_deref(),
        Some("github")
    );
    assert_eq!(
        ingest_source("/webhook/info", &cfg).as_deref(),
        Some("grafana")
    );
}

#[test]
fn custom_route_only_accepts_registered_sources() {
    let mut cfg = config();
    cfg.custom_ingest_sources
        .insert("home-assistant".into(), "Home Assistant".into());
    assert_eq!(
        ingest_source("/ingest/home-assistant/warning", &cfg).as_deref(),
        Some("home-assistant")
    );
    assert_eq!(ingest_source("/ingest/unknown/warning", &cfg), None);
    assert_eq!(
        ingest_source("/ingest/home-assistant/warning/extra", &cfg),
        None
    );
}

#[test]
fn alertmanager_group_key_survives_common_label_expansion() {
    let initial = json!({
        "groupKey": "{}:{alertname=\"TrivyFixableCriticalNewEntry\"}",
        "commonLabels": {
            "alertname": "TrivyFixableCriticalNewEntry",
            "host": "it1-prd-mgmt-01",
            "container": "alertmanager"
        }
    });
    let expanded = json!({
        "groupKey": "{}:{alertname=\"TrivyFixableCriticalNewEntry\"}",
        "commonLabels": {"alertname": "TrivyFixableCriticalNewEntry"}
    });

    let initial = common_labels("grafana", &initial);
    let expanded = common_labels("grafana", &expanded);
    assert_eq!(
        initial.get("__klaxond_incident_key"),
        expanded.get("__klaxond_incident_key")
    );
    assert_ne!(initial.get("host"), expanded.get("host"));
}

#[test]
fn alertmanager_group_labels_are_a_canonical_fallback() {
    let first = json!({
        "groupLabels": {"severity": "critical", "alertname": "DiskFull"}
    });
    let reordered = json!({
        "groupLabels": {"alertname": "DiskFull", "severity": "critical"}
    });

    assert_eq!(
        common_labels("grafana", &first).get("__klaxond_incident_key"),
        common_labels("grafana", &reordered).get("__klaxond_incident_key")
    );
}

#[test]
fn dedicated_revaulter_route_preserves_source_identity() {
    let cfg = config();
    assert_eq!(
        ingest_source("/revaulter/warning", &cfg).as_deref(),
        Some("revaulter")
    );
    assert_eq!(
        ingest_source("/webhook/warning", &cfg).as_deref(),
        Some("grafana")
    );
}
