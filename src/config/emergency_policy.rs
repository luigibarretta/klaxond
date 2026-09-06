use super::{EmergencyConfig, EmergencyProfile};
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Serialize)]
pub struct EmergencyRoutingDecision {
    pub selected: Option<EmergencyProfile>,
    pub reason: String,
    pub forced: bool,
    pub matching_profiles: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EmergencyTimelineEvent {
    pub at_seconds: u64,
    pub attempt: Option<u32>,
    pub kind: String,
    pub channel: Option<String>,
}

pub fn select_emergency_profile(
    cfg: &EmergencyConfig,
    severity: &str,
    source: &str,
    event: &str,
    labels: &HashMap<String, String>,
) -> EmergencyRoutingDecision {
    if !cfg.enabled {
        return decision(None, "emergency-disabled", false, Vec::new());
    }
    if cfg
        .exclude_sources
        .iter()
        .any(|item| item.eq_ignore_ascii_case(source))
    {
        return decision(None, "source-excluded", false, Vec::new());
    }

    let emergency_flag = labels.get("emergency").and_then(|value| {
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    });
    if emergency_flag == Some(false) {
        return decision(None, "explicit-emergency-false", false, Vec::new());
    }

    let mut matches = cfg
        .profiles
        .iter()
        .enumerate()
        .filter(|(_, profile)| {
            profile.enabled && profile_matches(profile, severity, source, event, labels)
        })
        .collect::<Vec<_>>();
    matches.sort_by(|(left_index, left), (right_index, right)| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left_index.cmp(right_index))
    });
    let matching_profiles = matches
        .iter()
        .map(|(_, profile)| profile.id.clone())
        .collect::<Vec<_>>();
    if let Some((_, profile)) = matches.first() {
        let reason = if matching_profiles.len() > 1 {
            format!("priority-winner:{}", profile.id)
        } else {
            format!("matched:{}", profile.id)
        };
        return decision(
            Some((*profile).clone()),
            &reason,
            emergency_flag == Some(true),
            matching_profiles,
        );
    }

    if emergency_flag == Some(true) {
        if let Some(profile) = cfg
            .profiles
            .iter()
            .find(|profile| profile.enabled && profile.id == cfg.fallback_profile)
        {
            return decision(
                Some(profile.clone()),
                &format!("explicit-emergency-true→fallback:{}", profile.id),
                true,
                Vec::new(),
            );
        }
        return decision(None, "fallback-unavailable", true, Vec::new());
    }

    decision(None, "no-profile-matched", false, Vec::new())
}

fn decision(
    selected: Option<EmergencyProfile>,
    reason: &str,
    forced: bool,
    matching_profiles: Vec<String>,
) -> EmergencyRoutingDecision {
    EmergencyRoutingDecision {
        selected,
        reason: reason.to_string(),
        forced,
        matching_profiles,
    }
}

fn profile_matches(
    profile: &EmergencyProfile,
    severity: &str,
    source: &str,
    event: &str,
    labels: &HashMap<String, String>,
) -> bool {
    list_matches(&profile.severities, severity)
        && list_matches(&profile.sources, source)
        && profile.label_match.iter().all(|(key, expected)| {
            let actual = match key.as_str() {
                "severity" => severity,
                "source" => source,
                "event" | "alertname" => event,
                _ => labels.get(key).map(String::as_str).unwrap_or(""),
            };
            value_matches(expected, actual)
        })
}

fn list_matches(expected: &[String], actual: &str) -> bool {
    expected.is_empty() || expected.iter().any(|value| value_matches(value, actual))
}

fn value_matches(expected: &str, actual: &str) -> bool {
    expected
        .strip_prefix("re:")
        .map(|pattern| Regex::new(pattern).is_ok_and(|regex| regex.is_match(actual)))
        .unwrap_or_else(|| expected.eq_ignore_ascii_case(actual))
}

pub fn emergency_timeline(profile: &EmergencyProfile) -> Vec<EmergencyTimelineEvent> {
    let mut events = vec![EmergencyTimelineEvent {
        at_seconds: 0,
        attempt: Some(1),
        kind: "initial".to_string(),
        channel: Some("ntfy".to_string()),
    }];
    for (channel, enabled, after_attempts) in [
        (
            "telegram",
            profile.telegram.enabled,
            profile.telegram.after_attempts,
        ),
        ("smtp", profile.smtp.enabled, profile.smtp.after_attempts),
    ] {
        if enabled && after_attempts == 1 {
            events.push(EmergencyTimelineEvent {
                at_seconds: 0,
                attempt: Some(1),
                kind: "escalation".to_string(),
                channel: Some(channel.to_string()),
            });
        }
    }
    for attempt in 2..=profile.max_attempts {
        let at_seconds = u64::from(attempt - 1).saturating_mul(profile.retry_seconds);
        if at_seconds >= profile.expire_seconds {
            break;
        }
        events.push(EmergencyTimelineEvent {
            at_seconds,
            attempt: Some(attempt),
            kind: "retry".to_string(),
            channel: Some("ntfy".to_string()),
        });
        for (channel, enabled, after_attempts) in [
            (
                "telegram",
                profile.telegram.enabled,
                profile.telegram.after_attempts,
            ),
            ("smtp", profile.smtp.enabled, profile.smtp.after_attempts),
        ] {
            if enabled && after_attempts == attempt {
                events.push(EmergencyTimelineEvent {
                    at_seconds,
                    attempt: Some(attempt),
                    kind: "escalation".to_string(),
                    channel: Some(channel.to_string()),
                });
            }
        }
    }
    let attempts = events
        .iter()
        .filter_map(|event| event.attempt)
        .max()
        .unwrap_or(1);
    if attempts >= profile.max_attempts {
        events.push(EmergencyTimelineEvent {
            at_seconds: u64::from(profile.max_attempts.saturating_sub(1))
                .saturating_mul(profile.retry_seconds),
            attempt: Some(profile.max_attempts),
            kind: "attempt-limit".to_string(),
            channel: None,
        });
    }
    events.push(EmergencyTimelineEvent {
        at_seconds: profile.expire_seconds,
        attempt: None,
        kind: "expiry".to_string(),
        channel: None,
    });
    events.sort_by_key(|event| event.at_seconds);
    events
}

pub fn validate_emergency_config(cfg: &mut EmergencyConfig) -> Result<(), String> {
    cfg.exclude_sources = normalize_values(&cfg.exclude_sources, "exclude_sources", true, false)?;
    cfg.fallback_profile = normalize_id(&cfg.fallback_profile, "fallback_profile")?;
    if cfg.profiles.is_empty() {
        return Err("profiles cannot be empty".to_string());
    }
    if cfg.profiles.len() > 32 {
        return Err("profiles cannot contain more than 32 entries".to_string());
    }
    let mut ids = HashSet::new();
    for profile in &mut cfg.profiles {
        profile.id = normalize_id(&profile.id, "profile.id")?;
        if !ids.insert(profile.id.clone()) {
            return Err(format!("profile id '{}' is duplicated", profile.id));
        }
        profile.name = profile.name.trim().to_string();
        if profile.name.is_empty() || profile.name.chars().count() > 80 {
            return Err(format!(
                "profile '{}' name must contain 1..=80 characters",
                profile.id
            ));
        }
        profile.severities = normalize_values(
            &profile.severities,
            &format!("profiles.{}.severities", profile.id),
            true,
            true,
        )?;
        profile.sources = normalize_values(
            &profile.sources,
            &format!("profiles.{}.sources", profile.id),
            true,
            true,
        )?;
        if profile.severities.is_empty()
            && profile.sources.is_empty()
            && profile.label_match.is_empty()
        {
            return Err(format!(
                "profile '{}' must match a severity, source, event or label",
                profile.id
            ));
        }
        validate_label_match(profile)?;
        ensure_range("retry_seconds", profile.retry_seconds, 30, 3_600)?;
        ensure_range("expire_seconds", profile.expire_seconds, 30, 10_800)?;
        ensure_range("max_attempts", u64::from(profile.max_attempts), 1, 50)?;
        ensure_range("lease_seconds", profile.lease_seconds, 5, 300)?;
        if profile.expire_seconds < profile.retry_seconds {
            return Err(format!(
                "profile '{}' expiry must be greater than or equal to retry",
                profile.id
            ));
        }
        for (channel, fallback) in [("telegram", &profile.telegram), ("smtp", &profile.smtp)] {
            ensure_range(
                &format!("{channel}.after_attempts"),
                u64::from(fallback.after_attempts),
                1,
                u64::from(profile.max_attempts),
            )?;
        }
    }
    if !ids.contains(&cfg.fallback_profile) {
        return Err(format!(
            "fallback profile '{}' does not exist",
            cfg.fallback_profile
        ));
    }
    if cfg.enabled
        && !cfg
            .profiles
            .iter()
            .any(|profile| profile.id == cfg.fallback_profile && profile.enabled)
    {
        return Err(format!(
            "fallback profile '{}' must be enabled while emergency routing is enabled",
            cfg.fallback_profile
        ));
    }
    Ok(())
}

fn validate_label_match(profile: &mut EmergencyProfile) -> Result<(), String> {
    let mut normalized = HashMap::new();
    for (raw_key, raw_value) in &profile.label_match {
        let key = normalize_id(raw_key, "match key")?;
        let value = raw_value.trim();
        if value.is_empty() || value.len() > 256 {
            return Err(format!("profile '{}' has an invalid matcher", profile.id));
        }
        if let Some(pattern) = value.strip_prefix("re:") {
            Regex::new(pattern)
                .map_err(|error| format!("profile '{}' has invalid regex: {error}", profile.id))?;
        }
        normalized.insert(key, value.to_string());
    }
    profile.label_match = normalized;
    Ok(())
}

fn normalize_id(raw: &str, field: &str) -> Result<String, String> {
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!("{field} contains an invalid value: {value}"));
    }
    Ok(value)
}

fn normalize_values(
    values: &[String],
    field: &str,
    allow_empty: bool,
    allow_regex: bool,
) -> Result<Vec<String>, String> {
    if values.len() > 64 {
        return Err(format!("{field} cannot contain more than 64 values"));
    }
    let mut normalized = Vec::new();
    for raw in values {
        let value = raw.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        if allow_regex && value.starts_with("re:") {
            Regex::new(&value[3..])
                .map_err(|error| format!("{field} has invalid regex: {error}"))?;
        } else if value.len() > 64
            || !value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        {
            return Err(format!("{field} contains an invalid value: {value}"));
        }
        if !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    if normalized.is_empty() && !allow_empty {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(normalized)
}

fn ensure_range(field: &str, value: u64, min: u64, max: u64) -> Result<(), String> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(format!("{field} must be between {min} and {max}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let result =
            select_emergency_profile(&cfg, "critical", "grafana", "DiskFull", &HashMap::new());
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
}
