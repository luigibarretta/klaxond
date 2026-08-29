use super::super::config_admin::persist_reload;
use super::super::{json_body, json_response, text};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use url::Url;

const FIELD_ENV: &[(&str, &str)] = &[
    ("backend", "KLAXOND_HISTORY_BACKEND"),
    ("sqlite_path", "KLAXOND_SQLITE_PATH"),
    ("postgres_url", "KLAXOND_POSTGRES_URL"),
    ("retention", "KLAXOND_HISTORY_RETENTION"),
    ("default_limit", "KLAXOND_HISTORY_DEFAULT_LIMIT"),
];

pub(in crate::handlers) fn history_config_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    json!({
        "settings": {
            "backend": cfg.history.backend,
            "sqlite_path": cfg.history.sqlite_path,
            "postgres_url_configured": !cfg.history.postgres_url.trim().is_empty(),
            "postgres_target": postgres_target(&cfg.history.postgres_url),
            "retention": cfg.history.retention,
            "default_limit": cfg.history.default_limit,
        },
        "constraints": {
            "backends": ["sqlite", "postgres"],
            "retention": {"min": 100, "max": 1_000_000},
            "default_limit": {"min": 1, "max": 10_000},
        },
        "managed_fields": managed_fields(),
        "restart_required": false,
    })
}

pub(in crate::handlers) fn update_history_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(value) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let patch: HistoryConfigPatch = match serde_json::from_value(value) {
        Ok(patch) => patch,
        Err(error) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("invalid storage: {error}"),
            );
        }
    };
    if let Err(error) = patch.reject_managed_fields(&managed_fields()) {
        return text(StatusCode::CONFLICT, &error);
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            if let Err(error) = patch.validate(&cfg.history) {
                return text(StatusCode::BAD_REQUEST, &error);
            }
            patch.apply_to_toml(&mut cfg.toml);
            match persist_reload(state, cfg.toml) {
                Ok(()) => json_response(json!({
                    "ok": true,
                    "config": history_config_payload(state),
                })),
                Err(error) => text(StatusCode::BAD_REQUEST, &error),
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

fn postgres_target(raw: &str) -> String {
    let Ok(url) = Url::parse(raw) else {
        return String::new();
    };
    let host = url.host_str().unwrap_or("");
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    format!("{}://{host}{port}{}", url.scheme(), url.path())
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryConfigPatch {
    backend: Option<String>,
    postgres_url: Option<String>,
    retention: Option<usize>,
    default_limit: Option<usize>,
}

impl HistoryConfigPatch {
    fn reject_managed_fields(&self, managed: &BTreeMap<String, String>) -> Result<(), String> {
        let supplied = [
            ("backend", self.backend.is_some()),
            ("postgres_url", self.postgres_url.is_some()),
            ("retention", self.retention.is_some()),
            ("default_limit", self.default_limit.is_some()),
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

    fn validate(&self, current: &crate::config::HistoryConfig) -> Result<(), String> {
        let backend = self
            .backend
            .as_deref()
            .unwrap_or(&current.backend)
            .trim()
            .to_ascii_lowercase();
        if !matches!(backend.as_str(), "sqlite" | "postgres") {
            return Err("backend must be sqlite or postgres".into());
        }
        let postgres_url = self
            .postgres_url
            .as_deref()
            .unwrap_or(&current.postgres_url)
            .trim();
        if backend == "postgres" {
            let parsed = Url::parse(postgres_url)
                .map_err(|_| "postgres_url must be an absolute PostgreSQL URL".to_string())?;
            if !matches!(parsed.scheme(), "postgres" | "postgresql") || parsed.host_str().is_none()
            {
                return Err(
                    "postgres_url must use postgres:// or postgresql:// with a host".into(),
                );
            }
        }
        let retention = self.retention.unwrap_or(current.retention);
        if !(100..=1_000_000).contains(&retention) {
            return Err("retention must be between 100 and 1000000".into());
        }
        let default_limit = self.default_limit.unwrap_or(current.default_limit);
        if !(1..=10_000).contains(&default_limit) {
            return Err("default_limit must be between 1 and 10000".into());
        }
        Ok(())
    }

    fn apply_to_toml(&self, root: &mut toml::Value) {
        let table = toml_table_mut(root, &["history"]);
        if let Some(backend) = self.backend.as_ref() {
            table.insert(
                "backend".into(),
                toml::Value::String(backend.trim().to_ascii_lowercase()),
            );
        }
        if let Some(postgres_url) = self.postgres_url.as_ref() {
            table.insert(
                "postgres_url".into(),
                toml::Value::String(postgres_url.trim().to_string()),
            );
        }
        if let Some(retention) = self.retention {
            table.insert("retention".into(), toml::Value::Integer(retention as i64));
        }
        if let Some(default_limit) = self.default_limit {
            table.insert(
                "default_limit".into(),
                toml::Value::Integer(default_limit as i64),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HistoryConfig;
    use std::path::PathBuf;

    fn config() -> HistoryConfig {
        HistoryConfig {
            backend: "sqlite".into(),
            sqlite_path: PathBuf::from("/data/klaxond.db"),
            postgres_url: String::new(),
            retention: 5_000,
            default_limit: 500,
        }
    }

    #[test]
    fn validates_backend_bounds_and_postgres_target() {
        let current = config();
        assert!(
            HistoryConfigPatch {
                retention: Some(99),
                ..Default::default()
            }
            .validate(&current)
            .is_err()
        );
        assert!(
            HistoryConfigPatch {
                backend: Some("postgres".into()),
                ..Default::default()
            }
            .validate(&current)
            .is_err()
        );
        assert!(
            HistoryConfigPatch {
                backend: Some("postgres".into()),
                postgres_url: Some("postgres://db.example.test/klaxond".into()),
                ..Default::default()
            }
            .validate(&current)
            .is_ok()
        );
    }

    #[test]
    fn redacted_target_never_contains_credentials() {
        let target = postgres_target("postgres://user:secret@db.example.test:5433/klaxond");
        assert_eq!(target, "postgres://db.example.test:5433/klaxond");
        assert!(!target.contains("secret"));
    }
}
