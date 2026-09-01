use super::*;

#[test]
fn explicit_label_overrides_severity_policy() {
    let cfg = EmergencyConfig {
        enabled: true,
        ..EmergencyConfig::default()
    };
    assert!(should_manage(&cfg, "critical", &HashMap::new(), "grafana"));
    assert!(!should_manage(&cfg, "warning", &HashMap::new(), "grafana"));
    assert!(should_manage(
        &cfg,
        "warning",
        &HashMap::from([("emergency".into(), "true".into())]),
        "grafana"
    ));
    assert!(!should_manage(
        &cfg,
        "critical",
        &HashMap::from([("emergency".into(), "false".into())]),
        "grafana"
    ));
    assert!(!should_manage(
        &cfg,
        "critical",
        &HashMap::new(),
        "api-test"
    ));
}

#[test]
fn alertmanager_incident_key_is_stable_across_group_expansion_and_recovery() {
    let mut firing = test_parts("Critical workload issue");
    firing.alertname = "TrivyFixableCriticalNewEntry".into();
    let mut resolved = test_parts("Resolved workload issue");
    resolved.alertname = firing.alertname.clone();
    let initial = HashMap::from([
        (
            "__klaxond_incident_key".into(),
            "group-key:{}:{alertname=TrivyFixableCriticalNewEntry}".into(),
        ),
        ("host".into(), "it1-prd-mgmt-01".into()),
        ("component".into(), "alertmanager".into()),
    ]);
    let expanded = HashMap::from([(
        "__klaxond_incident_key".into(),
        "group-key:{}:{alertname=TrivyFixableCriticalNewEntry}".into(),
    )]);

    assert_eq!(
        fingerprint("grafana", &firing, &initial),
        fingerprint("grafana", &firing, &expanded)
    );
    assert_eq!(
        fingerprint("grafana", &firing, &initial),
        fingerprint("grafana", &resolved, &expanded)
    );
    assert_ne!(
        fingerprint("grafana", &firing, &initial),
        legacy_fingerprint("grafana", &firing, &initial)
    );
}

fn test_parts(title: &str) -> Parts {
    Parts {
        title: title.into(),
        body: String::new(),
        tags: vec![],
        actions: vec![],
        priority: String::new(),
        alertname: String::new(),
        skip_snooze: false,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}
