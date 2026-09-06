use super::{
    DeliveryConfig, DeliveryPolicy, DeliveryRule, EmergencyConfig, EmergencyFallback,
    EmergencyProfile, HistoryConfig, InhibitionRule, Paths, Schedule, Tier,
    default_inhibition_rules, validate_emergency_config,
};
use crate::util::toml_get;
use std::collections::HashMap;

pub(super) fn read_emergency(toml: &toml::Value) -> anyhow::Result<EmergencyConfig> {
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

fn env_or_toml_bool(
    table: Option<&toml::Value>,
    env: &str,
    key: &str,
    fallback: bool,
) -> anyhow::Result<bool> {
    if std::env::var_os(env).is_some() {
        return env_bool(env, fallback);
    }
    Ok(table
        .and_then(|value| value.get(key))
        .and_then(toml::Value::as_bool)
        .unwrap_or(fallback))
}

fn env_or_toml_u64(
    table: Option<&toml::Value>,
    env: &str,
    key: &str,
    fallback: u64,
) -> anyhow::Result<u64> {
    if std::env::var_os(env).is_some() {
        return env_u64(env, fallback);
    }
    Ok(table
        .and_then(|value| value.get(key))
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(fallback))
}

fn env_or_toml_u32(
    table: Option<&toml::Value>,
    env: &str,
    key: &str,
    fallback: u32,
) -> anyhow::Result<u32> {
    let value = env_or_toml_u64(table, env, key, u64::from(fallback))?;
    u32::try_from(value).map_err(|_| anyhow::anyhow!("{env} must fit in an unsigned integer"))
}

fn env_or_toml_list(
    table: Option<&toml::Value>,
    env: &str,
    key: &str,
    fallback: Vec<String>,
) -> Vec<String> {
    std::env::var(env)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| csv_list(&value))
        .or_else(|| {
            table
                .and_then(|value| value.get(key))
                .and_then(toml::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
        })
        .unwrap_or(fallback)
}

fn env_bool(name: &str, fallback: bool) -> anyhow::Result<bool> {
    let Ok(value) = std::env::var(name) else {
        return Ok(fallback);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("{name} must be a boolean"),
    }
}

fn env_u64(name: &str, fallback: u64) -> anyhow::Result<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("{name} must be an unsigned integer")),
        Err(_) => Ok(fallback),
    }
}

fn env_u32(name: &str, fallback: u32) -> anyhow::Result<u32> {
    u32::try_from(env_u64(name, u64::from(fallback))?)
        .map_err(|_| anyhow::anyhow!("{name} must fit in an unsigned integer"))
}

fn csv_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn table_string(table: &toml::Table, key: &str, fallback: &str) -> String {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or(fallback)
        .to_string()
}

fn table_bool(table: &toml::Table, key: &str, fallback: bool) -> bool {
    table
        .get(key)
        .and_then(toml::Value::as_bool)
        .unwrap_or(fallback)
}

fn table_u64(table: &toml::Table, key: &str, fallback: u64) -> u64 {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(fallback)
}

fn table_u32(table: &toml::Table, key: &str, fallback: u32) -> u32 {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(fallback)
}

fn table_list(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn read_tiers(value: Option<&toml::Value>) -> Option<Vec<Tier>> {
    let arr = value?.as_array()?;
    let mut tiers = Vec::new();
    for item in arr {
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        tiers.push(Tier {
            name,
            timeout_seconds: item
                .get("timeout_seconds")
                .and_then(|v| v.as_integer())
                .unwrap_or(5)
                .max(1) as u64,
        });
    }
    if tiers.is_empty() { None } else { Some(tiers) }
}

pub(super) fn read_delivery(toml: &toml::Value) -> DeliveryConfig {
    let Some(delivery) = toml_get(toml, &["delivery"]) else {
        return DeliveryConfig::default();
    };
    let default_policy = delivery
        .get("default_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("cascade")
        .to_string();
    let policies = delivery
        .get("policies")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?.to_string();
            let mode = p
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("cascade")
                .to_string();
            let tiers = read_tiers(p.get("tiers")).unwrap_or_default();
            Some(DeliveryPolicy { name, mode, tiers })
        })
        .collect();
    let rules = delivery
        .get("rules")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|r| {
            let policy = r.get("policy")?.as_str()?.to_string();
            let mut m = HashMap::new();
            if let Some(t) = r.get("match").and_then(|v| v.as_table()) {
                for (k, v) in t {
                    if let Some(s) = v.as_str() {
                        m.insert(k.to_string(), s.to_string());
                    }
                }
            }
            Some(DeliveryRule { r#match: m, policy })
        })
        .collect();
    DeliveryConfig {
        default_policy,
        policies,
        rules,
    }
}

pub(super) fn read_history(toml: &toml::Value, paths: &Paths) -> HistoryConfig {
    let history = toml_get(toml, &["history"]);
    let backend = std::env::var("KLAXOND_HISTORY_BACKEND")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            history
                .and_then(|v| v.get("backend"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "sqlite".to_string())
        .trim()
        .to_ascii_lowercase();
    let postgres_url = std::env::var("KLAXOND_POSTGRES_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            history
                .and_then(|v| v.get("postgres_url"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();
    let retention = std::env::var("KLAXOND_HISTORY_RETENTION")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .or_else(|| {
            history
                .and_then(|v| v.get("retention"))
                .and_then(|v| v.as_integer())
                .map(|v| v.max(0) as usize)
        })
        .unwrap_or(5000);
    let default_limit = std::env::var("KLAXOND_HISTORY_DEFAULT_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .or_else(|| {
            history
                .and_then(|v| v.get("default_limit"))
                .and_then(|v| v.as_integer())
                .map(|v| v.max(1) as usize)
        })
        .unwrap_or(500)
        .clamp(1, 10_000);
    HistoryConfig {
        backend,
        sqlite_path: paths.history_db.clone(),
        postgres_url,
        retention,
        default_limit,
    }
}

pub(super) fn read_inhibition_rules(toml: &toml::Value) -> Vec<InhibitionRule> {
    let Some(arr) = toml.get("inhibitions").and_then(|v| v.as_array()) else {
        return default_inhibition_rules();
    };
    let mut out = Vec::new();
    for r in arr {
        let source = r
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if source.is_empty() {
            continue;
        }
        out.push(InhibitionRule {
            source,
            match_by: r
                .get("match_by")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            match_label: r
                .get("match_label")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            match_regex: r
                .get("match_regex")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            match_all: r
                .get("match_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            applies_to: r
                .get("applies_to")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            ttl_seconds: r
                .get("ttl_seconds")
                .and_then(|v| v.as_integer())
                .unwrap_or(900)
                .max(1) as u64,
        });
    }
    if out.is_empty() {
        default_inhibition_rules()
    } else {
        out
    }
}

pub(super) fn read_schedules(toml: &toml::Value) -> Vec<Schedule> {
    let Some(arr) = toml.get("schedules").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| {
            let name = s.get("name")?.as_str()?.trim().to_string();
            let cron = s.get("cron")?.as_str()?.trim().to_string();
            if name.is_empty() || cron.is_empty() {
                return None;
            }
            let mut m = HashMap::new();
            if let Some(t) = s.get("match").and_then(|v| v.as_table()) {
                for (k, v) in t {
                    if let Some(v) = v.as_str() {
                        m.insert(k.to_string(), v.to_string());
                    }
                }
            }
            let applies_to = s
                .get("applies_to")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            Some(Schedule {
                name,
                cron,
                duration_minutes: s
                    .get("duration_minutes")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(30)
                    .max(1) as u64,
                r#match: m,
                applies_to,
            })
        })
        .collect()
}
