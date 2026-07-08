use super::{
    DeliveryConfig, DeliveryPolicy, DeliveryRule, HistoryConfig, InhibitionRule, Paths, Schedule,
    Tier, default_inhibition_rules,
};
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
