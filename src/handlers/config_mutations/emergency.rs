use super::super::config_admin::persist_reload;
use super::super::{json_body, json_response, text};
use crate::config::{
    EmergencyConfig, EmergencyProfile, emergency_timeline, select_emergency_profile,
    validate_emergency_config, validate_runtime_config,
};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

const GLOBAL_FIELD_ENV: &[(&str, &str)] = &[
    ("enabled", "KLAXOND_EMERGENCY_ENABLED"),
    (
        "allow_insecure_public_url",
        "KLAXOND_EMERGENCY_ALLOW_INSECURE_PUBLIC_URL",
    ),
    ("allow_ntfy_only", "KLAXOND_EMERGENCY_ALLOW_NTFY_ONLY"),
    ("exclude_sources", "KLAXOND_EMERGENCY_EXCLUDE_SOURCES"),
];

const LEGACY_PROFILE_ENV: &[(&str, &str)] = &[
    ("severities", "KLAXOND_EMERGENCY_SEVERITIES"),
    ("retry_seconds", "KLAXOND_EMERGENCY_RETRY_SECONDS"),
    ("expire_seconds", "KLAXOND_EMERGENCY_EXPIRE_SECONDS"),
    ("max_attempts", "KLAXOND_EMERGENCY_MAX_ATTEMPTS"),
    ("lease_seconds", "KLAXOND_EMERGENCY_LEASE_SECONDS"),
    (
        "telegram.after_attempts",
        "KLAXOND_EMERGENCY_TELEGRAM_AFTER_ATTEMPTS",
    ),
    (
        "smtp.after_attempts",
        "KLAXOND_EMERGENCY_SMTP_AFTER_ATTEMPTS",
    ),
    ("notify_on_expiry", "KLAXOND_EMERGENCY_NOTIFY_ON_EXPIRY"),
    ("auto_resolve", "KLAXOND_EMERGENCY_AUTO_RESOLVE"),
];

pub(in crate::handlers) fn emergency_config_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let managed_fields = managed_fields(&cfg.emergency.fallback_profile);
    let ownership = if managed_fields.is_empty() {
        "ui"
    } else if managed_fields.len() == GLOBAL_FIELD_ENV.len() + LEGACY_PROFILE_ENV.len() {
        "environment"
    } else {
        "mixed"
    };
    let known_severities = configured_severities(&cfg);
    let known_sources = cfg.ingest_sources();
    let timeout = |name: &str, fallback: u64| {
        cfg.tiers
            .iter()
            .find(|tier| tier.name == name)
            .map(|tier| tier.timeout_seconds)
            .unwrap_or(fallback)
    };
    json!({
        "settings": cfg.emergency,
        "constraints": {
            "profiles": {"max": 32},
            "retry_seconds": {"min": 30, "max": 3_600},
            "expire_seconds": {"min": 30, "max": 10_800},
            "max_attempts": {"min": 1, "max": 50},
            "lease_seconds": {"min": 5, "max": 300},
            "escalation_attempts": {"min": 1, "max_field": "max_attempts"},
        },
        "known_severities": known_severities,
        "known_sources": known_sources,
        "channel_timeouts": {
            "ntfy": timeout("ntfy", 15),
            "telegram": timeout("telegram", 8),
            "smtp": timeout("smtp", 10),
            "lease_margin": 5,
        },
        "precedence": "Highest priority wins; equal priorities use configured order.",
        "emergency_label": {
            "false": "Absolute bypass after global source exclusions.",
            "true": "Selects a matching profile or the configured fallback profile.",
        },
        "diagnostics": profile_diagnostics(&cfg.emergency, &known_severities, &known_sources),
        "managed_fields": managed_fields,
        "managed_by_environment": ownership != "ui",
        "source_of_truth": ownership,
        "config_path": state.paths.config.to_string_lossy(),
        "writeable": ownership != "environment",
    })
}

pub(in crate::handlers) fn update_emergency_config(
    state: &AppState,
    body: Bytes,
) -> Response<Body> {
    let Ok(value) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let patch: EmergencyConfigPatch = match serde_json::from_value(value) {
        Ok(patch) => patch,
        Err(error) => return text(StatusCode::BAD_REQUEST, &format!("invalid policy: {error}")),
    };
    let current = state.cfg();
    if let Err(error) =
        patch.reject_managed_fields(&managed_fields(&current.emergency.fallback_profile))
    {
        return text(StatusCode::CONFLICT, &error);
    }

    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let mut candidate = cfg.emergency.clone();
            patch.apply_to_config(&mut candidate);
            if let Err(error) = validate_emergency_config(&mut candidate) {
                return text(StatusCode::BAD_REQUEST, &error);
            }
            let mut prospective = cfg.clone();
            prospective.emergency = candidate.clone();
            if let Err(error) = validate_runtime_config(&prospective) {
                return text(StatusCode::BAD_REQUEST, &error.to_string());
            }
            apply_config_to_toml(&candidate, &mut cfg.toml);
            match persist_reload(state, cfg.toml) {
                Ok(()) => json_response(json!({
                    "ok": true,
                    "config": emergency_config_payload(state),
                })),
                Err(error) => text(StatusCode::INTERNAL_SERVER_ERROR, &error),
            }
        })
        .unwrap_or_else(|error| text(StatusCode::INTERNAL_SERVER_ERROR, &error))
}

pub(in crate::handlers) fn export_emergency_config(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    let mut root = toml::Value::Table(toml::Table::new());
    apply_config_to_toml(&cfg.emergency, &mut root);
    let body = toml::to_string_pretty(&root).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/toml; charset=utf-8")
        .header(
            "content-disposition",
            "attachment; filename=klaxond-emergency.toml",
        )
        .body(Body::from(body))
        .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "build export response"))
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmergencyConfigPatch {
    enabled: Option<bool>,
    allow_insecure_public_url: Option<bool>,
    allow_ntfy_only: Option<bool>,
    exclude_sources: Option<Vec<String>>,
    fallback_profile: Option<String>,
    profiles: Option<Vec<EmergencyProfile>>,
}

impl EmergencyConfigPatch {
    fn reject_managed_fields(&self, managed: &BTreeMap<String, String>) -> Result<(), String> {
        let mut conflicts = Vec::new();
        for (field, present) in [
            ("enabled", self.enabled.is_some()),
            (
                "allow_insecure_public_url",
                self.allow_insecure_public_url.is_some(),
            ),
            ("allow_ntfy_only", self.allow_ntfy_only.is_some()),
            ("exclude_sources", self.exclude_sources.is_some()),
            ("fallback_profile", self.fallback_profile.is_some()),
        ] {
            if present && managed.contains_key(field) {
                conflicts.push(format!("{field} ({})", managed[field]));
            }
        }
        if self.profiles.is_some() {
            conflicts.extend(
                managed
                    .iter()
                    .filter(|(field, _)| field.starts_with("profiles."))
                    .map(|(field, owner)| format!("{field} ({owner})")),
            );
        }
        if conflicts.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "environment-managed fields cannot be changed: {}",
                conflicts.join(", ")
            ))
        }
    }

    fn apply_to_config(&self, config: &mut EmergencyConfig) {
        apply_option(&mut config.enabled, self.enabled);
        apply_option(
            &mut config.allow_insecure_public_url,
            self.allow_insecure_public_url,
        );
        apply_option(&mut config.allow_ntfy_only, self.allow_ntfy_only);
        if let Some(value) = &self.exclude_sources {
            config.exclude_sources.clone_from(value);
        }
        if let Some(value) = &self.fallback_profile {
            config.fallback_profile.clone_from(value);
        }
        if let Some(value) = &self.profiles {
            config.profiles.clone_from(value);
        }
    }
}

fn managed_fields(fallback_profile: &str) -> BTreeMap<String, String> {
    let mut managed = GLOBAL_FIELD_ENV
        .iter()
        .filter(|(_, env)| std::env::var_os(env).is_some())
        .map(|(field, env)| ((*field).to_string(), (*env).to_string()))
        .collect::<BTreeMap<_, _>>();
    for (field, env) in LEGACY_PROFILE_ENV {
        if std::env::var_os(env).is_some() {
            managed.insert(
                format!("profiles.{fallback_profile}.{field}"),
                (*env).to_string(),
            );
        }
    }
    managed
}

fn apply_config_to_toml(config: &EmergencyConfig, root: &mut toml::Value) {
    let table = toml_table_mut(root, &["emergency"]);
    for legacy in [
        "severities",
        "retry_seconds",
        "expire_seconds",
        "max_attempts",
        "lease_seconds",
        "telegram_after_attempts",
        "smtp_after_attempts",
        "notify_on_expiry",
        "auto_resolve",
    ] {
        table.remove(legacy);
    }
    table.insert("enabled".into(), toml::Value::Boolean(config.enabled));
    table.insert(
        "allow_insecure_public_url".into(),
        toml::Value::Boolean(config.allow_insecure_public_url),
    );
    table.insert(
        "allow_ntfy_only".into(),
        toml::Value::Boolean(config.allow_ntfy_only),
    );
    table.insert(
        "exclude_sources".into(),
        toml::Value::Array(
            config
                .exclude_sources
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );
    table.insert(
        "fallback_profile".into(),
        toml::Value::String(config.fallback_profile.clone()),
    );
    table.insert(
        "profiles".into(),
        toml::Value::try_from(&config.profiles).unwrap_or_else(|_| toml::Value::Array(Vec::new())),
    );
}

fn configured_severities(cfg: &crate::config::RuntimeConfig) -> Vec<String> {
    let mut severities = cfg.known_severities();
    for profile in &cfg.emergency.profiles {
        severities.extend(
            profile
                .severities
                .iter()
                .filter(|value| !value.starts_with("re:"))
                .cloned(),
        );
    }
    severities.retain(|severity| severity != "resolved");
    severities.sort();
    severities.dedup();
    severities
}

fn profile_diagnostics(
    config: &EmergencyConfig,
    severities: &[String],
    sources: &[String],
) -> Value {
    let shadowed = config
        .profiles
        .iter()
        .enumerate()
        .filter_map(|(index, profile)| {
            if !profile.enabled {
                return None;
            }
            config
                .profiles
                .iter()
                .enumerate()
                .filter(|(candidate_index, candidate)| {
                    *candidate_index != index
                        && candidate.enabled
                        && (candidate.priority > profile.priority
                            || (candidate.priority == profile.priority && *candidate_index < index))
                })
                .find(|(_, candidate)| {
                    candidate.severities == profile.severities
                        && candidate.sources == profile.sources
                        && candidate.label_match == profile.label_match
                })
                .map(|(_, winner)| json!({"profile": profile.id, "shadowed_by": winner.id}))
        })
        .collect::<Vec<_>>();
    let mut routing_config = config.clone();
    routing_config.enabled = true;
    let unrouted_severities = severities
        .iter()
        .filter(|severity| {
            sources.iter().all(|source| {
                select_emergency_profile(&routing_config, severity, source, "", &HashMap::new())
                    .selected
                    .is_none()
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    let timelines = config
        .profiles
        .iter()
        .map(|profile| (profile.id.clone(), emergency_timeline(profile)))
        .collect::<BTreeMap<_, _>>();
    let priorities = config
        .profiles
        .iter()
        .map(|profile| profile.priority)
        .collect::<Vec<_>>();
    let duplicate_priorities = priorities
        .iter()
        .filter(|priority| {
            priorities
                .iter()
                .filter(|value| *value == *priority)
                .count()
                > 1
        })
        .copied()
        .collect::<HashSet<_>>();
    json!({
        "shadowed_profiles": shadowed,
        "unrouted_severities": unrouted_severities,
        "equal_priorities": duplicate_priorities,
        "timelines": timelines,
    })
}

fn apply_option<T: Copy>(target: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *target = value;
    }
}

#[cfg(test)]
mod tests {
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
}
