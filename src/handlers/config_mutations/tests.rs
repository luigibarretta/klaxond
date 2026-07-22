use super::*;

#[test]
fn dedup_config_request_applies_known_sources_and_preserves_leniency() {
    let request =
        DedupConfigRequest::from_value(dedup_request_payload()).expect("dedup settings request");

    let current = default_dedup();
    let settings = request
        .into_settings(default_dedup(), &current)
        .expect("valid settings");

    let grafana = settings.get("grafana").expect("grafana settings");
    assert!(grafana.enabled);
    assert_eq!(grafana.window_s, 3600);
    assert_eq!(grafana.strategy, "time");
    assert!(grafana.override_critical);
    assert!(grafana.repeat_suppression_enabled);
    assert_eq!(grafana.repeat_window_s, 604_800);
    assert!(grafana.repeat_override_critical);

    let beszel = settings.get("beszel").expect("beszel settings");
    assert!(!beszel.enabled);
    assert_eq!(beszel.window_s, 5);
    assert_eq!(beszel.strategy, "key");
    assert!(!beszel.override_critical);

    let default_wud = default_dedup().remove("wud").expect("default wud");
    assert_eq!(settings.get("wud"), Some(&default_wud));
    assert!(!settings.contains_key("unknown"));
}

fn dedup_request_payload() -> Value {
    json!({
        "settings": {
            "grafana": {
                "enabled": true,
                "window_s": 9999,
                "strategy": "time",
                "override_critical": true,
                "repeat_suppression_enabled": true,
                "repeat_window_s": 999999,
                "repeat_override_critical": true
            },
            "beszel": {
                "enabled": "yes",
                "window_s": 1,
                "strategy": "invalid",
                "override_critical": false
            },
            "wud": "ignore non-object source patch",
            "unknown": {
                "enabled": true,
                "window_s": 30,
                "strategy": "none"
            }
        }
    })
}

#[test]
fn dedup_config_request_requires_settings_object() {
    assert!(DedupConfigRequest::from_value(json!({})).is_err());
    assert!(DedupConfigRequest::from_value(json!({"settings": []})).is_err());
}

#[test]
fn legacy_dedup_update_preserves_repeat_suppression_fields() {
    let request = DedupConfigRequest::from_value(json!({
        "settings": {
            "grafana": {
                "enabled": true,
                "window_s": 42,
                "strategy": "time",
                "override_critical": false
            }
        }
    }))
    .expect("legacy dedup settings request");
    let mut current = default_dedup();
    for source in ["grafana", "wud"] {
        let setting = current.get_mut(source).expect("known source");
        setting.repeat_suppression_enabled = true;
        setting.repeat_window_s = 21_600;
        setting.repeat_override_critical = true;
    }

    let settings = request
        .into_settings(default_dedup(), &current)
        .expect("valid settings");

    for source in ["grafana", "wud"] {
        let setting = settings.get(source).expect("known source");
        assert!(setting.repeat_suppression_enabled);
        assert_eq!(setting.repeat_window_s, 21_600);
        assert!(setting.repeat_override_critical);
    }
}

#[test]
fn selective_noise_rules_are_normalized_validated_and_preserved() {
    let request = DedupConfigRequest::from_value(json!({
        "settings": {
            "grafana": {
                "rules": [{
                    "name": "  Disk noise  ",
                    "enabled": true,
                    "field": "label",
                    "label": " instance ",
                    "operator": "regex",
                    "pattern": " ^nas-[0-9]+$ ",
                    "case_sensitive": false,
                    "action": "suppress",
                    "cooldown_s": 999999,
                    "include_critical": false
                }]
            }
        }
    }))
    .expect("noise rule request");

    let settings = request
        .into_settings(default_dedup(), &default_dedup())
        .expect("valid noise rule");
    let rule = &settings["grafana"].rules[0];
    assert_eq!(rule.name, "Disk noise");
    assert_eq!(rule.label, "instance");
    assert_eq!(rule.pattern, "^nas-[0-9]+$");
    assert_eq!(rule.cooldown_s, 604_800);

    let invalid = DedupConfigRequest::from_value(json!({
        "settings": {"grafana": {"rules": [{
            "name": "broken", "pattern": "(", "operator": "regex"
        }]}}
    }))
    .unwrap()
    .into_settings(default_dedup(), &default_dedup())
    .unwrap_err();
    assert!(invalid.contains("invalid regex"));
}

#[test]
fn cascade_config_request_preserves_tier_normalization_and_leniency() {
    let request = CascadeConfigRequest::from_value(json!({
        "tiers": [
            { "name": "NTFY", "timeout_seconds": 0 },
            { "name": "telegram", "timeout_seconds": 99 },
            { "name": "smtp", "timeout_seconds": "slow" },
            { "name": "pagerduty", "timeout_seconds": 15 },
            "ignore non-object tier"
        ],
        "default_enabled_for_webhook": true
    }))
    .expect("cascade config request");

    assert_eq!(request.default_enabled_for_webhook, Some(true));
    assert_eq!(
        request.tier_values(),
        vec![
            json!({"name": "ntfy", "timeout_seconds": 1}),
            json!({"name": "telegram", "timeout_seconds": 60}),
            json!({"name": "smtp", "timeout_seconds": 5}),
        ]
    );
}

#[test]
fn cascade_config_request_requires_tiers_array() {
    assert!(CascadeConfigRequest::from_value(json!({})).is_err());
    assert!(CascadeConfigRequest::from_value(json!({"tiers": {}})).is_err());
    assert!(
        CascadeConfigRequest::from_value(json!({"tiers": []}))
            .expect("empty array is syntactically valid")
            .tier_values()
            .is_empty()
    );
}
