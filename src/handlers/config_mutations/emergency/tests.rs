use super::*;

#[test]
fn patch_replaces_profiles_and_normalizes_values() {
    let patch: EmergencyConfigPatch = serde_json::from_value(json!({
        "enabled": true,
        "fallback_profile": "page",
        "profiles": [{
            "id": "PAGE", "name": "Page", "enabled": true, "priority": 200,
            "severities": [" Critical ", "PAGE"], "sources": [], "match": {},
            "retry_seconds": 90, "expire_seconds": 3600, "max_attempts": 20,
            "lease_seconds": 60,
            "telegram": {"enabled": true, "after_attempts": 3},
            "smtp": {"enabled": false, "after_attempts": 5},
            "notify_on_expiry": true, "auto_resolve": true
        }]
    }))
    .unwrap();
    let mut config = EmergencyConfig::default();
    patch.apply_to_config(&mut config);
    validate_emergency_config(&mut config).unwrap();
    assert!(config.enabled);
    assert_eq!(config.profiles[0].id, "page");
    assert_eq!(config.profiles[0].severities, ["critical", "page"]);
}

#[test]
fn managed_profile_fields_reject_a_profile_replacement() {
    let patch: EmergencyConfigPatch = serde_json::from_value(json!({"profiles": []})).unwrap();
    let managed = BTreeMap::from([(
        "profiles.critical-default.retry_seconds".to_string(),
        "KLAXOND_EMERGENCY_RETRY_SECONDS".to_string(),
    )]);
    let error = patch.reject_managed_fields(&managed).unwrap_err();
    assert!(error.contains("KLAXOND_EMERGENCY_RETRY_SECONDS"));
}

#[test]
fn canonical_export_contains_profiles_without_secrets() {
    let mut root = toml::Value::Table(toml::Table::new());
    apply_config_to_toml(&EmergencyConfig::default(), &mut root);
    let output = toml::to_string_pretty(&root).unwrap();
    assert!(output.contains("critical-default"));
    assert!(!output.contains("token"));
    assert!(!output.contains("password"));
}
