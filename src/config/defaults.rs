use super::{DedupSetting, InhibitionRule, Tier};
use std::collections::HashMap;

pub const DEDUP_SOURCES: &[&str] = &[
    "grafana",
    "beszel",
    "healthchecks",
    "wud",
    "authentik",
    "shelfmark",
    "prowlarr",
    "decypharr",
];

pub const TIER_TIMEOUT_MIN_SECONDS: u64 = 1;
pub const TIER_TIMEOUT_MAX_SECONDS: u64 = 60;
pub const NTFY_RECOMMENDED_TIMEOUT_SECONDS: u64 = 15;

pub fn recommended_tier_timeout(name: &str) -> u64 {
    match name {
        "ntfy" => NTFY_RECOMMENDED_TIMEOUT_SECONDS,
        "telegram" => 8,
        "smtp" => 10,
        _ => 5,
    }
}

pub fn default_tiers() -> Vec<Tier> {
    ["ntfy", "telegram", "smtp"]
        .into_iter()
        .map(|name| Tier {
            name: name.into(),
            timeout_seconds: recommended_tier_timeout(name),
        })
        .collect()
}

pub fn default_priorities() -> HashMap<String, String> {
    [
        ("info", "default"),
        ("warning", "high"),
        ("critical", "urgent"),
        ("resolved", "low"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

pub fn default_icons() -> HashMap<String, String> {
    [
        ("info", "ℹ️"),
        ("warning", "⚠️"),
        ("critical", "🚨"),
        ("resolved", "✅"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

pub fn default_tag_prefixes() -> HashMap<String, String> {
    [
        ("info", "information_source"),
        ("warning", "warning"),
        ("critical", "rotating_light"),
        ("resolved", "white_check_mark"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

pub fn default_component_dashboards() -> HashMap<String, [String; 2]> {
    [
        ("host", ["Logs", "/d/your-logs-dashboard"]),
        ("traefik", ["Traefik", "/d/your-traefik-dashboard"]),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), [v[0].to_string(), v[1].to_string()]))
    .collect()
}

pub fn default_dedup() -> HashMap<String, DedupSetting> {
    [
        ("grafana", false, 90, "key", false),
        ("beszel", false, 90, "key", false),
        ("healthchecks", false, 90, "key", false),
        ("wud", true, 90, "key", false),
        ("authentik", false, 60, "key", false),
        ("shelfmark", true, 120, "key", false),
        ("prowlarr", true, 90, "key", false),
        ("decypharr", true, 60, "key", false),
    ]
    .into_iter()
    .map(|(src, enabled, window_s, strategy, override_critical)| {
        (
            src.to_string(),
            DedupSetting {
                enabled,
                window_s,
                strategy: strategy.to_string(),
                override_critical,
                repeat_suppression_enabled: false,
                repeat_window_s: 7_200,
                repeat_override_critical: false,
                rules: Vec::new(),
            },
        )
    })
    .collect()
}

pub fn default_inhibition_rules() -> Vec<InhibitionRule> {
    vec![
        InhibitionRule {
            source: "node-down".into(),
            match_by: Some("host".into()),
            match_label: None,
            match_regex: None,
            match_all: false,
            applies_to: vec![],
            ttl_seconds: 900,
        },
        InhibitionRule {
            source: "traefik-down".into(),
            match_by: None,
            match_label: Some("job".into()),
            match_regex: Some("^blackbox-(https|http).*".into()),
            match_all: false,
            applies_to: vec!["grafana".into()],
            ttl_seconds: 900,
        },
        InhibitionRule {
            source: "authentik-down".into(),
            match_by: None,
            match_label: Some("job".into()),
            match_regex: Some("^blackbox-https.*".into()),
            match_all: false,
            applies_to: vec!["grafana".into()],
            ttl_seconds: 900,
        },
        InhibitionRule {
            source: "cluster-wide-restart".into(),
            match_by: None,
            match_label: None,
            match_regex: None,
            match_all: true,
            applies_to: vec![],
            ttl_seconds: 1800,
        },
    ]
}
