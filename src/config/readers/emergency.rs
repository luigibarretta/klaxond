use super::env::*;

use super::super::{
    EmergencyConfig, EmergencyFallback, EmergencyProfile, validate_emergency_config,
};
use crate::util::toml_get;

pub(crate) fn read_emergency(toml: &toml::Value) -> anyhow::Result<EmergencyConfig> {
    let defaults = EmergencyConfig::default();
    let emergency = toml_get(toml, &["emergency"]);
    let mut profiles: Vec<EmergencyProfile> = emergency
        .and_then(|value| value.get("profiles"))
        .and_then(toml::Value::as_array)
        .map(|values| values.iter().map(read_emergency_profile).collect())
        .transpose()?
        .unwrap_or_default();
    if profiles.is_empty() {
        profiles.push(read_legacy_emergency_profile(emergency)?);
    }
    let fallback_profile = emergency
        .and_then(|value| value.get("fallback_profile"))
        .and_then(toml::Value::as_str)
        .unwrap_or(&profiles[0].id)
        .to_string();
    let mut cfg = EmergencyConfig {
        enabled: env_or_toml_bool(
            emergency,
            "KLAXOND_EMERGENCY_ENABLED",
            "enabled",
            defaults.enabled,
        )?,
        allow_insecure_public_url: env_or_toml_bool(
            emergency,
            "KLAXOND_EMERGENCY_ALLOW_INSECURE_PUBLIC_URL",
            "allow_insecure_public_url",
            defaults.allow_insecure_public_url,
        )?,
        allow_ntfy_only: env_or_toml_bool(
            emergency,
            "KLAXOND_EMERGENCY_ALLOW_NTFY_ONLY",
            "allow_ntfy_only",
            defaults.allow_ntfy_only,
        )?,
        exclude_sources: env_or_toml_list(
            emergency,
            "KLAXOND_EMERGENCY_EXCLUDE_SOURCES",
            "exclude_sources",
            defaults.exclude_sources,
        ),
        fallback_profile,
        profiles,
    };
    if legacy_profile_env_present() {
        let fallback = cfg
            .profiles
            .iter_mut()
            .find(|profile| profile.id == cfg.fallback_profile)
            .ok_or_else(|| anyhow::anyhow!("emergency fallback profile is missing"))?;
        overlay_legacy_profile_env(fallback)?;
    }
    validate_emergency_config(&mut cfg).map_err(anyhow::Error::msg)?;
    Ok(cfg)
}

fn read_emergency_profile(value: &toml::Value) -> anyhow::Result<EmergencyProfile> {
    let defaults = EmergencyProfile::legacy_default();
    let table = value
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("emergency profile must be a table"))?;
    let fallback = |name: &str, default: &EmergencyFallback| EmergencyFallback {
        enabled: table
            .get(name)
            .and_then(|value| value.get("enabled"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(default.enabled),
        after_attempts: table
            .get(name)
            .and_then(|value| value.get("after_attempts"))
            .and_then(toml::Value::as_integer)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(default.after_attempts),
    };
    Ok(EmergencyProfile {
        id: table_string(table, "id", ""),
        name: table_string(table, "name", ""),
        enabled: table_bool(table, "enabled", true),
        priority: table
            .get("priority")
            .and_then(toml::Value::as_integer)
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or(0),
        severities: table_list(table, "severities"),
        sources: table_list(table, "sources"),
        label_match: table
            .get("match")
            .and_then(toml::Value::as_table)
            .map(|matcher| {
                matcher
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        retry_seconds: table_u64(table, "retry_seconds", defaults.retry_seconds),
        expire_seconds: table_u64(table, "expire_seconds", defaults.expire_seconds),
        max_attempts: table_u32(table, "max_attempts", defaults.max_attempts),
        lease_seconds: table_u64(table, "lease_seconds", defaults.lease_seconds),
        telegram: fallback("telegram", &defaults.telegram),
        smtp: fallback("smtp", &defaults.smtp),
        notify_on_expiry: table_bool(table, "notify_on_expiry", defaults.notify_on_expiry),
        auto_resolve: table_bool(table, "auto_resolve", defaults.auto_resolve),
    })
}

fn read_legacy_emergency_profile(
    emergency: Option<&toml::Value>,
) -> anyhow::Result<EmergencyProfile> {
    let mut profile = EmergencyProfile::legacy_default();
    profile.severities = env_or_toml_list(
        emergency,
        "KLAXOND_EMERGENCY_SEVERITIES",
        "severities",
        profile.severities,
    );
    profile.retry_seconds = env_or_toml_u64(
        emergency,
        "KLAXOND_EMERGENCY_RETRY_SECONDS",
        "retry_seconds",
        profile.retry_seconds,
    )?;
    profile.expire_seconds = env_or_toml_u64(
        emergency,
        "KLAXOND_EMERGENCY_EXPIRE_SECONDS",
        "expire_seconds",
        profile.expire_seconds,
    )?;
    profile.max_attempts = env_or_toml_u32(
        emergency,
        "KLAXOND_EMERGENCY_MAX_ATTEMPTS",
        "max_attempts",
        profile.max_attempts,
    )?;
    profile.lease_seconds = env_or_toml_u64(
        emergency,
        "KLAXOND_EMERGENCY_LEASE_SECONDS",
        "lease_seconds",
        profile.lease_seconds,
    )?;
    profile.telegram.after_attempts = env_or_toml_u32(
        emergency,
        "KLAXOND_EMERGENCY_TELEGRAM_AFTER_ATTEMPTS",
        "telegram_after_attempts",
        profile.telegram.after_attempts,
    )?;
    profile.smtp.after_attempts = env_or_toml_u32(
        emergency,
        "KLAXOND_EMERGENCY_SMTP_AFTER_ATTEMPTS",
        "smtp_after_attempts",
        profile.smtp.after_attempts,
    )?;
    profile.notify_on_expiry = env_or_toml_bool(
        emergency,
        "KLAXOND_EMERGENCY_NOTIFY_ON_EXPIRY",
        "notify_on_expiry",
        profile.notify_on_expiry,
    )?;
    profile.auto_resolve = env_or_toml_bool(
        emergency,
        "KLAXOND_EMERGENCY_AUTO_RESOLVE",
        "auto_resolve",
        profile.auto_resolve,
    )?;
    Ok(profile)
}

fn overlay_legacy_profile_env(profile: &mut EmergencyProfile) -> anyhow::Result<()> {
    if let Ok(value) = std::env::var("KLAXOND_EMERGENCY_SEVERITIES") {
        profile.severities = csv_list(&value);
    }
    profile.retry_seconds = env_u64("KLAXOND_EMERGENCY_RETRY_SECONDS", profile.retry_seconds)?;
    profile.expire_seconds = env_u64("KLAXOND_EMERGENCY_EXPIRE_SECONDS", profile.expire_seconds)?;
    profile.max_attempts = env_u32("KLAXOND_EMERGENCY_MAX_ATTEMPTS", profile.max_attempts)?;
    profile.lease_seconds = env_u64("KLAXOND_EMERGENCY_LEASE_SECONDS", profile.lease_seconds)?;
    profile.telegram.after_attempts = env_u32(
        "KLAXOND_EMERGENCY_TELEGRAM_AFTER_ATTEMPTS",
        profile.telegram.after_attempts,
    )?;
    profile.smtp.after_attempts = env_u32(
        "KLAXOND_EMERGENCY_SMTP_AFTER_ATTEMPTS",
        profile.smtp.after_attempts,
    )?;
    profile.notify_on_expiry = env_bool(
        "KLAXOND_EMERGENCY_NOTIFY_ON_EXPIRY",
        profile.notify_on_expiry,
    )?;
    profile.auto_resolve = env_bool("KLAXOND_EMERGENCY_AUTO_RESOLVE", profile.auto_resolve)?;
    Ok(())
}

fn legacy_profile_env_present() -> bool {
    [
        "KLAXOND_EMERGENCY_SEVERITIES",
        "KLAXOND_EMERGENCY_RETRY_SECONDS",
        "KLAXOND_EMERGENCY_EXPIRE_SECONDS",
        "KLAXOND_EMERGENCY_MAX_ATTEMPTS",
        "KLAXOND_EMERGENCY_LEASE_SECONDS",
        "KLAXOND_EMERGENCY_TELEGRAM_AFTER_ATTEMPTS",
        "KLAXOND_EMERGENCY_SMTP_AFTER_ATTEMPTS",
        "KLAXOND_EMERGENCY_NOTIFY_ON_EXPIRY",
        "KLAXOND_EMERGENCY_AUTO_RESOLVE",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
}
