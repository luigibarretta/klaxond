use super::super::{EmergencyConfig, EmergencyProfile};
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize)]
pub struct EmergencyRoutingDecision {
    pub selected: Option<EmergencyProfile>,
    pub reason: String,
    pub forced: bool,
    pub matching_profiles: Vec<String>,
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

    let emergency_flag = parse_emergency_flag(labels);
    if emergency_flag == Some(false) {
        return decision(None, "explicit-emergency-false", false, Vec::new());
    }

    let matches = matching_profiles(cfg, severity, source, event, labels);
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
        return fallback_decision(cfg);
    }

    decision(None, "no-profile-matched", false, Vec::new())
}

fn parse_emergency_flag(labels: &HashMap<String, String>) -> Option<bool> {
    labels
        .get("emergency")
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}

fn matching_profiles<'a>(
    cfg: &'a EmergencyConfig,
    severity: &str,
    source: &str,
    event: &str,
    labels: &HashMap<String, String>,
) -> Vec<(usize, &'a EmergencyProfile)> {
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
    matches
}

fn fallback_decision(cfg: &EmergencyConfig) -> EmergencyRoutingDecision {
    cfg.profiles
        .iter()
        .find(|profile| profile.enabled && profile.id == cfg.fallback_profile)
        .map(|profile| {
            decision(
                Some(profile.clone()),
                &format!("explicit-emergency-true→fallback:{}", profile.id),
                true,
                Vec::new(),
            )
        })
        .unwrap_or_else(|| decision(None, "fallback-unavailable", true, Vec::new()))
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
