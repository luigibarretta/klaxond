use super::super::config_admin::persist_reload;
use super::super::{json_body, json_response, text};
use crate::config::{EmergencyConfig, validate_runtime_config};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const FIELD_ENV: &[(&str, &str)] = &[
    ("enabled", "KLAXOND_EMERGENCY_ENABLED"),
    (
        "allow_insecure_public_url",
        "KLAXOND_EMERGENCY_ALLOW_INSECURE_PUBLIC_URL",
    ),
    ("allow_ntfy_only", "KLAXOND_EMERGENCY_ALLOW_NTFY_ONLY"),
    ("severities", "KLAXOND_EMERGENCY_SEVERITIES"),
    ("retry_seconds", "KLAXOND_EMERGENCY_RETRY_SECONDS"),
    ("expire_seconds", "KLAXOND_EMERGENCY_EXPIRE_SECONDS"),
    ("max_attempts", "KLAXOND_EMERGENCY_MAX_ATTEMPTS"),
    ("lease_seconds", "KLAXOND_EMERGENCY_LEASE_SECONDS"),
    (
        "telegram_after_attempts",
        "KLAXOND_EMERGENCY_TELEGRAM_AFTER_ATTEMPTS",
    ),
    (
        "smtp_after_attempts",
        "KLAXOND_EMERGENCY_SMTP_AFTER_ATTEMPTS",
    ),
    ("notify_on_expiry", "KLAXOND_EMERGENCY_NOTIFY_ON_EXPIRY"),
    ("auto_resolve", "KLAXOND_EMERGENCY_AUTO_RESOLVE"),
    ("exclude_sources", "KLAXOND_EMERGENCY_EXCLUDE_SOURCES"),
];

pub(in crate::handlers) fn emergency_config_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let managed_fields = managed_fields();
    json!({
        "settings": cfg.emergency,
        "constraints": {
            "retry_seconds": {"min": 30, "max": 3_600},
            "expire_seconds": {"min": 30, "max": 10_800},
            "max_attempts": {"min": 1, "max": 50},
            "lease_seconds": {"min": 5, "max": 300},
            "escalation_attempts": {"min": 1, "max_field": "max_attempts"},
        },
        "managed_fields": managed_fields,
        "managed_by_environment": !managed_fields.is_empty(),
        "writeable": managed_fields.len() < FIELD_ENV.len(),
    })
}

pub(in crate::handlers) fn update_emergency_config(
    state: &AppState,
    body: Bytes,
) -> Response<Body> {
    let Ok(value) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let mut patch: EmergencyConfigPatch = match serde_json::from_value(value) {
        Ok(patch) => patch,
        Err(error) => return text(StatusCode::BAD_REQUEST, &format!("invalid policy: {error}")),
    };
    if let Err(error) = patch.reject_managed_fields(&managed_fields()) {
        return text(StatusCode::CONFLICT, &error);
    }

    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let mut candidate = cfg.emergency.clone();
            patch.apply_to_config(&mut candidate);
            if let Err(error) = validate_emergency(&mut candidate) {
                return text(StatusCode::BAD_REQUEST, &error);
            }
            if patch.severities.is_some() {
                patch.severities = Some(candidate.severities.clone());
            }
            if patch.exclude_sources.is_some() {
                patch.exclude_sources = Some(candidate.exclude_sources.clone());
            }
            let mut prospective = cfg.clone();
            prospective.emergency = candidate;
            if let Err(error) = validate_runtime_config(&prospective) {
                return text(StatusCode::BAD_REQUEST, &error.to_string());
            }
            patch.apply_to_toml(&mut cfg.toml);
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

fn managed_fields() -> BTreeMap<String, String> {
    FIELD_ENV
        .iter()
        .filter(|(_, env)| std::env::var_os(env).is_some())
        .map(|(field, env)| ((*field).to_string(), (*env).to_string()))
        .collect()
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmergencyConfigPatch {
    enabled: Option<bool>,
    allow_insecure_public_url: Option<bool>,
    allow_ntfy_only: Option<bool>,
    severities: Option<Vec<String>>,
    retry_seconds: Option<u64>,
    expire_seconds: Option<u64>,
    max_attempts: Option<u32>,
    lease_seconds: Option<u64>,
    telegram_after_attempts: Option<u32>,
    smtp_after_attempts: Option<u32>,
    notify_on_expiry: Option<bool>,
    auto_resolve: Option<bool>,
    exclude_sources: Option<Vec<String>>,
}

impl EmergencyConfigPatch {
    fn reject_managed_fields(&self, managed: &BTreeMap<String, String>) -> Result<(), String> {
        let supplied = [
            ("enabled", self.enabled.is_some()),
            (
                "allow_insecure_public_url",
                self.allow_insecure_public_url.is_some(),
            ),
            ("allow_ntfy_only", self.allow_ntfy_only.is_some()),
            ("severities", self.severities.is_some()),
            ("retry_seconds", self.retry_seconds.is_some()),
            ("expire_seconds", self.expire_seconds.is_some()),
            ("max_attempts", self.max_attempts.is_some()),
            ("lease_seconds", self.lease_seconds.is_some()),
            (
                "telegram_after_attempts",
                self.telegram_after_attempts.is_some(),
            ),
            ("smtp_after_attempts", self.smtp_after_attempts.is_some()),
            ("notify_on_expiry", self.notify_on_expiry.is_some()),
            ("auto_resolve", self.auto_resolve.is_some()),
            ("exclude_sources", self.exclude_sources.is_some()),
        ];
        let conflicts = supplied
            .into_iter()
            .filter(|(field, present)| *present && managed.contains_key(*field))
            .map(|(field, _)| format!("{field} ({})", managed[field]))
            .collect::<Vec<_>>();
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
        if let Some(value) = self.severities.as_ref() {
            config.severities = value.clone();
        }
        apply_option(&mut config.retry_seconds, self.retry_seconds);
        apply_option(&mut config.expire_seconds, self.expire_seconds);
        apply_option(&mut config.max_attempts, self.max_attempts);
        apply_option(&mut config.lease_seconds, self.lease_seconds);
        apply_option(
            &mut config.telegram_after_attempts,
            self.telegram_after_attempts,
        );
        apply_option(&mut config.smtp_after_attempts, self.smtp_after_attempts);
        apply_option(&mut config.notify_on_expiry, self.notify_on_expiry);
        apply_option(&mut config.auto_resolve, self.auto_resolve);
        if let Some(value) = self.exclude_sources.as_ref() {
            config.exclude_sources = value.clone();
        }
    }

    fn apply_to_toml(&self, root: &mut toml::Value) {
        let table = toml_table_mut(root, &["emergency"]);
        insert_bool(table, "enabled", self.enabled);
        insert_bool(
            table,
            "allow_insecure_public_url",
            self.allow_insecure_public_url,
        );
        insert_bool(table, "allow_ntfy_only", self.allow_ntfy_only);
        insert_list(table, "severities", self.severities.as_ref());
        insert_integer(table, "retry_seconds", self.retry_seconds);
        insert_integer(table, "expire_seconds", self.expire_seconds);
        insert_integer(table, "max_attempts", self.max_attempts.map(u64::from));
        insert_integer(table, "lease_seconds", self.lease_seconds);
        insert_integer(
            table,
            "telegram_after_attempts",
            self.telegram_after_attempts.map(u64::from),
        );
        insert_integer(
            table,
            "smtp_after_attempts",
            self.smtp_after_attempts.map(u64::from),
        );
        insert_bool(table, "notify_on_expiry", self.notify_on_expiry);
        insert_bool(table, "auto_resolve", self.auto_resolve);
        insert_list(table, "exclude_sources", self.exclude_sources.as_ref());
    }
}

fn validate_emergency(config: &mut EmergencyConfig) -> Result<(), String> {
    config.severities = normalize_list(&config.severities, "severities", false)?;
    config.exclude_sources = normalize_list(&config.exclude_sources, "exclude_sources", true)?;
    ensure_range("retry_seconds", config.retry_seconds, 30, 3_600)?;
    ensure_range("expire_seconds", config.expire_seconds, 30, 10_800)?;
    ensure_range("max_attempts", u64::from(config.max_attempts), 1, 50)?;
    ensure_range("lease_seconds", config.lease_seconds, 5, 300)?;
    ensure_range(
        "telegram_after_attempts",
        u64::from(config.telegram_after_attempts),
        1,
        u64::from(config.max_attempts),
    )?;
    ensure_range(
        "smtp_after_attempts",
        u64::from(config.smtp_after_attempts),
        1,
        u64::from(config.max_attempts),
    )?;
    if config.expire_seconds < config.retry_seconds {
        return Err("expire_seconds must be greater than or equal to retry_seconds".into());
    }
    Ok(())
}

fn normalize_list(
    values: &[String],
    field: &str,
    allow_empty: bool,
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
        if value.len() > 64
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

fn apply_option<T: Copy>(target: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *target = value;
    }
}

fn insert_bool(table: &mut toml::Table, field: &str, value: Option<bool>) {
    if let Some(value) = value {
        table.insert(field.into(), toml::Value::Boolean(value));
    }
}

fn insert_integer(table: &mut toml::Table, field: &str, value: Option<u64>) {
    if let Some(value) = value {
        table.insert(field.into(), toml::Value::Integer(value as i64));
    }
}

fn insert_list(table: &mut toml::Table, field: &str, values: Option<&Vec<String>>) {
    if let Some(values) = values {
        table.insert(
            field.into(),
            toml::Value::Array(
                values
                    .iter()
                    .map(|value| toml::Value::String(value.clone()))
                    .collect(),
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_normalizes_lists_and_applies_partial_updates() {
        let patch: EmergencyConfigPatch = serde_json::from_value(json!({
            "enabled": true,
            "severities": [" Critical ", "critical", "PAGE"],
            "retry_seconds": 90,
            "exclude_sources": [" API-Test "]
        }))
        .unwrap();
        let mut config = EmergencyConfig::default();
        patch.apply_to_config(&mut config);
        validate_emergency(&mut config).unwrap();
        assert!(config.enabled);
        assert_eq!(config.severities, ["critical", "page"]);
        assert_eq!(config.retry_seconds, 90);
        assert_eq!(config.exclude_sources, ["api-test"]);
        assert_eq!(config.max_attempts, 50);
    }

    #[test]
    fn validation_rejects_incoherent_or_unsafe_values() {
        let mut config = EmergencyConfig {
            retry_seconds: 120,
            expire_seconds: 60,
            ..EmergencyConfig::default()
        };
        assert!(validate_emergency(&mut config).is_err());
        config.expire_seconds = 3_600;
        config.telegram_after_attempts = 51;
        assert!(validate_emergency(&mut config).is_err());
    }

    #[test]
    fn managed_fields_are_rejected_instead_of_silently_ignored() {
        let patch: EmergencyConfigPatch =
            serde_json::from_value(json!({"enabled": true, "retry_seconds": 60})).unwrap();
        let managed = BTreeMap::from([(
            "enabled".to_string(),
            "KLAXOND_EMERGENCY_ENABLED".to_string(),
        )]);
        let error = patch.reject_managed_fields(&managed).unwrap_err();
        assert!(error.contains("KLAXOND_EMERGENCY_ENABLED"));
    }
}
