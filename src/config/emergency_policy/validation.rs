use super::super::{EmergencyConfig, EmergencyProfile};
use regex::Regex;
use std::collections::{HashMap, HashSet};

pub fn validate_emergency_config(cfg: &mut EmergencyConfig) -> Result<(), String> {
    cfg.exclude_sources = normalize_values(&cfg.exclude_sources, "exclude_sources", true, false)?;
    cfg.fallback_profile = normalize_id(&cfg.fallback_profile, "fallback_profile")?;
    if cfg.profiles.is_empty() {
        return Err("profiles cannot be empty".to_string());
    }
    if cfg.profiles.len() > 32 {
        return Err("profiles cannot contain more than 32 entries".to_string());
    }
    let ids = validate_profiles(&mut cfg.profiles)?;
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

fn validate_profiles(profiles: &mut [EmergencyProfile]) -> Result<HashSet<String>, String> {
    let mut ids = HashSet::new();
    for profile in profiles {
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
        validate_escalations(profile)?;
    }
    Ok(ids)
}

fn validate_escalations(profile: &EmergencyProfile) -> Result<(), String> {
    for (channel, fallback) in [("telegram", &profile.telegram), ("smtp", &profile.smtp)] {
        ensure_range(
            &format!("{channel}.after_attempts"),
            u64::from(fallback.after_attempts),
            1,
            u64::from(profile.max_attempts),
        )?;
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
