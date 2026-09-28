use super::super::{
    EmergencyConfig, EmergencyProfile, emergency_timeline, select_emergency_profile,
    validate_emergency_config,
};
use std::collections::HashMap;

#[test]
fn explicit_false_wins_and_true_uses_fallback() {
    let cfg = EmergencyConfig {
        enabled: true,
        ..EmergencyConfig::default()
    };
    let labels = HashMap::from([("emergency".to_string(), "false".to_string())]);
    assert_eq!(
        select_emergency_profile(&cfg, "critical", "grafana", "DiskFull", &labels).reason,
        "explicit-emergency-false"
    );
    let labels = HashMap::from([("emergency".to_string(), "true".to_string())]);
    let result = select_emergency_profile(&cfg, "page", "custom", "WakeUp", &labels);
    assert_eq!(result.selected.unwrap().id, "critical-default");
    assert!(result.forced);

    let labels = HashMap::from([("emergency".to_string(), "invalid".to_string())]);
    let result = select_emergency_profile(&cfg, "critical", "grafana", "DiskFull", &labels);
    assert_eq!(result.selected.unwrap().id, "critical-default");
    assert!(!result.forced);
}

#[test]
fn priority_then_array_order_is_deterministic() {
    let mut cfg = EmergencyConfig {
        enabled: true,
        ..EmergencyConfig::default()
    };
    let mut second = cfg.profiles[0].clone();
    second.id = "specific".into();
    second.name = "Specific".into();
    second.priority = 200;
    second.sources = vec!["grafana".into()];
    cfg.profiles.push(second);
    let result = select_emergency_profile(&cfg, "critical", "grafana", "DiskFull", &HashMap::new());
    assert_eq!(result.selected.unwrap().id, "specific");
    assert_eq!(result.matching_profiles, ["specific", "critical-default"]);
}

#[test]
fn timeline_marks_escalations_limit_and_real_expiry() {
    let profile = EmergencyProfile::legacy_default();
    let events = emergency_timeline(&profile);
    assert!(events.iter().any(|event| {
        event.kind == "escalation"
            && event.channel.as_deref() == Some("telegram")
            && event.attempt == Some(3)
    }));
    assert!(events.iter().any(|event| event.kind == "attempt-limit"));
    assert_eq!(events.last().unwrap().kind, "expiry");
    assert_eq!(events.last().unwrap().at_seconds, 3_600);
}

#[test]
fn timeline_includes_fallbacks_escalating_on_initial_attempt() {
    let mut profile = EmergencyProfile::legacy_default();
    profile.telegram.after_attempts = 1;
    let events = emergency_timeline(&profile);
    assert!(events.iter().any(|event| {
        event.kind == "escalation"
            && event.channel.as_deref() == Some("telegram")
            && event.attempt == Some(1)
            && event.at_seconds == 0
    }));
}

#[test]
fn enabled_routing_requires_an_enabled_fallback_profile() {
    let mut cfg = EmergencyConfig {
        enabled: true,
        ..EmergencyConfig::default()
    };
    cfg.profiles[0].enabled = false;
    assert!(validate_emergency_config(&mut cfg).is_err());
}
