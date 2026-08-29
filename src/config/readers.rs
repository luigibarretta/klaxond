use super::{
    DeliveryConfig, DeliveryPolicy, DeliveryRule, EmergencyConfig, HistoryConfig, InhibitionRule,
    Paths, Schedule, Tier, default_inhibition_rules,
};

pub(super) fn read_emergency(toml: &toml::Value) -> anyhow::Result<EmergencyConfig> {
    let defaults = EmergencyConfig::default();
    let emergency = toml_get(toml, &["emergency"]);
    let bool_value = |env: &str, key: &str, fallback: bool| -> anyhow::Result<bool> {
        if let Ok(value) = std::env::var(env) {
            return match value.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Ok(true),
                "0" | "false" | "no" | "off" => Ok(false),
                _ => anyhow::bail!("{env} must be a boolean"),
            };
        }
        Ok(emergency
            .and_then(|v| v.get(key))
            .and_then(toml::Value::as_bool)
            .unwrap_or(fallback))
    };
    let u64_value = |env: &str, key: &str, fallback: u64| -> anyhow::Result<u64> {
        if let Ok(value) = std::env::var(env) {
            return value
                .parse::<u64>()
                .map_err(|_| anyhow::anyhow!("{env} must be an unsigned integer"));
        }
        Ok(emergency
            .and_then(|v| v.get(key))
            .and_then(toml::Value::as_integer)
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(fallback))
    };
    let list_value = |env: &str, key: &str, fallback: Vec<String>| {
        std::env::var(env)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .or_else(|| {
                emergency
                    .and_then(|v| v.get(key))
                    .and_then(toml::Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(toml::Value::as_str)
                            .map(|s| s.trim().to_ascii_lowercase())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
            })
            .unwrap_or(fallback)
    };
    let cfg = EmergencyConfig {
        enabled: bool_value("KLAXOND_EMERGENCY_ENABLED", "enabled", defaults.enabled)?,
        allow_insecure_public_url: bool_value(
            "KLAXOND_EMERGENCY_ALLOW_INSECURE_PUBLIC_URL",
            "allow_insecure_public_url",
            defaults.allow_insecure_public_url,
        )?,
        allow_ntfy_only: bool_value(
            "KLAXOND_EMERGENCY_ALLOW_NTFY_ONLY",
            "allow_ntfy_only",
            defaults.allow_ntfy_only,
        )?,
        severities: list_value(
            "KLAXOND_EMERGENCY_SEVERITIES",
            "severities",
            defaults.severities,
        ),
        retry_seconds: u64_value(
            "KLAXOND_EMERGENCY_RETRY_SECONDS",
            "retry_seconds",
            defaults.retry_seconds,
        )?,
        expire_seconds: u64_value(
            "KLAXOND_EMERGENCY_EXPIRE_SECONDS",
            "expire_seconds",
            defaults.expire_seconds,
        )?,
        max_attempts: u32::try_from(u64_value(
            "KLAXOND_EMERGENCY_MAX_ATTEMPTS",
            "max_attempts",
            defaults.max_attempts as u64,
        )?)
        .unwrap_or(u32::MAX),
        lease_seconds: u64_value(
            "KLAXOND_EMERGENCY_LEASE_SECONDS",
            "lease_seconds",
            defaults.lease_seconds,
        )?,
        telegram_after_attempts: u32::try_from(u64_value(
            "KLAXOND_EMERGENCY_TELEGRAM_AFTER_ATTEMPTS",
            "telegram_after_attempts",
            defaults.telegram_after_attempts as u64,
        )?)
        .unwrap_or(u32::MAX),
        smtp_after_attempts: u32::try_from(u64_value(
            "KLAXOND_EMERGENCY_SMTP_AFTER_ATTEMPTS",
            "smtp_after_attempts",
            defaults.smtp_after_attempts as u64,
        )?)
        .unwrap_or(u32::MAX),
        notify_on_expiry: bool_value(
            "KLAXOND_EMERGENCY_NOTIFY_ON_EXPIRY",
            "notify_on_expiry",
            defaults.notify_on_expiry,
        )?,
        auto_resolve: bool_value(
            "KLAXOND_EMERGENCY_AUTO_RESOLVE",
            "auto_resolve",
            defaults.auto_resolve,
        )?,
        exclude_sources: list_value(
            "KLAXOND_EMERGENCY_EXCLUDE_SOURCES",
            "exclude_sources",
            defaults.exclude_sources,
        ),
    };
    anyhow::ensure!(
        (30..=3_600).contains(&cfg.retry_seconds),
        "emergency.retry_seconds must be in 30..=3600"
    );
    anyhow::ensure!(
        (30..=10_800).contains(&cfg.expire_seconds),
        "emergency.expire_seconds must be in 30..=10800"
    );
    anyhow::ensure!(
        (1..=50).contains(&cfg.max_attempts),
        "emergency.max_attempts must be in 1..=50"
    );
    anyhow::ensure!(
        (5..=300).contains(&cfg.lease_seconds),
        "emergency.lease_seconds must be in 5..=300"
    );
    anyhow::ensure!(
        (1..=cfg.max_attempts).contains(&cfg.telegram_after_attempts),
        "emergency.telegram_after_attempts must be in 1..=max_attempts"
    );
    anyhow::ensure!(
        (1..=cfg.max_attempts).contains(&cfg.smtp_after_attempts),
        "emergency.smtp_after_attempts must be in 1..=max_attempts"
    );
    anyhow::ensure!(
        !cfg.severities.is_empty(),
        "emergency.severities cannot be empty"
    );
    Ok(cfg)
}
use crate::util::toml_get;
use std::collections::HashMap;

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
