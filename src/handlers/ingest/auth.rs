use super::super::config_admin::persist_reload;
use super::super::{json_body, json_response, text};
use crate::config::{
    MAX_CUSTOM_INGEST_SOURCES, RuntimeConfig, environment_custom_ingest_secrets,
    environment_custom_ingest_sources, source_is_builtin, valid_ingest_source_slug,
};
use crate::state::AppState;
use crate::util::{env_string, random_hex, toml_table_mut};
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

#[derive(Deserialize)]
struct IngestAuthRequest {
    source: String,
    action: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    display_name: String,
}

pub(in crate::handlers) fn update_ingest_auth(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let request = match serde_json::from_value::<IngestAuthRequest>(payload) {
        Ok(request) => request,
        Err(error) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("invalid request: {error}"),
            );
        }
    };
    let src = request.source.trim().to_ascii_lowercase();
    let action = request.action.trim().to_ascii_lowercase();
    let display_name = request.display_name.trim().to_string();
    let current = state.cfg();
    let is_custom = current.custom_ingest_source(&src).is_some();
    if !matches!(
        action.as_str(),
        "add" | "set" | "generate" | "clear" | "remove"
    ) {
        return text(
            StatusCode::BAD_REQUEST,
            "action must be one of: add, set, generate, clear, remove",
        );
    }
    if action == "add" {
        if !valid_ingest_source_slug(&src) {
            return text(
                StatusCode::BAD_REQUEST,
                "source must be 2-40 lowercase letters, digits or single hyphens",
            );
        }
        if source_is_builtin(&src) || is_custom {
            return text(StatusCode::CONFLICT, "source already exists");
        }
        if display_name.is_empty() || display_name.chars().count() > 64 {
            return text(
                StatusCode::BAD_REQUEST,
                "display_name must contain 1-64 characters",
            );
        }
        if current.custom_ingest_sources.len() >= MAX_CUSTOM_INGEST_SOURCES {
            return text(StatusCode::BAD_REQUEST, "custom source limit reached");
        }
    } else if !source_is_builtin(&src) && !is_custom {
        return text(StatusCode::BAD_REQUEST, "source is not registered");
    }
    if action == "remove" && source_is_builtin(&src) {
        return text(
            StatusCode::BAD_REQUEST,
            "built-in sources cannot be removed",
        );
    }
    if action == "remove" && environment_custom_ingest_sources().contains_key(&src) {
        return text(
            StatusCode::CONFLICT,
            "environment-managed source definitions cannot be removed from the UI",
        );
    }
    if matches!(action.as_str(), "remove" | "clear")
        && (!env_string(&ingest_secret_env_key(&src)).trim().is_empty()
            || environment_custom_ingest_secrets().contains_key(&src))
    {
        return text(
            StatusCode::CONFLICT,
            "environment-managed sources cannot be cleared or removed from the UI",
        );
    }
    if action == "set" {
        let sec = request.secret.trim();
        if sec.len() < 16 {
            return text(
                StatusCode::BAD_REQUEST,
                "secret missing or shorter than 16 chars",
            );
        }
    }
    let new_secret = match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        let mut new_secret = None;
        match action.as_str() {
            "add" => {
                toml_table_mut(&mut cfg.toml, &["ingest", "custom_sources"])
                    .insert(src.clone(), toml::Value::String(display_name));
                let sec = random_hex(32);
                toml_table_mut(&mut cfg.toml, &["ingest", "secrets"])
                    .insert(src.clone(), toml::Value::String(sec.clone()));
                new_secret = Some(sec);
            }
            "remove" => {
                toml_table_mut(&mut cfg.toml, &["ingest", "secrets"]).remove(&src);
                toml_table_mut(&mut cfg.toml, &["ingest", "custom_sources"]).remove(&src);
            }
            "clear" => {
                toml_table_mut(&mut cfg.toml, &["ingest", "secrets"]).remove(&src);
            }
            "generate" => {
                let sec = random_hex(32);
                toml_table_mut(&mut cfg.toml, &["ingest", "secrets"])
                    .insert(src.clone(), toml::Value::String(sec.clone()));
                new_secret = Some(sec);
            }
            _ => {
                toml_table_mut(&mut cfg.toml, &["ingest", "secrets"]).insert(
                    src.clone(),
                    toml::Value::String(request.secret.trim().into()),
                );
            }
        }
        persist_reload(state, cfg.toml).map(|_| new_secret)
    }) {
        Ok(Ok(new_secret)) => new_secret,
        Ok(Err(err)) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    let endpoint = state.with_cfg(|cfg| ingest_endpoint(cfg, &src));
    let mut resp = json!({
        "ok": true,
        "source": src,
        "action": action,
        "endpoint": endpoint,
    });
    if let Some(sec) = new_secret {
        resp["secret"] = json!(sec);
    }
    json_response(resp)
}

pub(super) fn verify_ingest_auth(
    state: &AppState,
    source: &str,
    headers: &HeaderMap,
    qs: &HashMap<String, String>,
) -> (bool, String) {
    let secret = ingest_secret_for(state, source);
    if secret.is_empty() {
        return (false, "source-disabled-no-secret".into());
    }
    if let Some(auth) = headers.get("Authorization").and_then(|v| v.to_str().ok())
        && let Some((scheme, tok)) = auth.split_once(char::is_whitespace)
        && scheme.eq_ignore_ascii_case("bearer")
        && auth_modules::secrets::constant_time_eq(tok.trim().as_bytes(), secret.as_bytes())
    {
        return (true, "bearer".into());
    }
    if let Some(tok) = headers.get("X-Klaxond-Token").and_then(|v| v.to_str().ok())
        && auth_modules::secrets::constant_time_eq(tok.trim().as_bytes(), secret.as_bytes())
    {
        return (true, "x-klaxond-token".into());
    }
    if let Some(tok) = qs.get("token")
        && auth_modules::secrets::constant_time_eq(tok.as_bytes(), secret.as_bytes())
    {
        return (true, "query".into());
    }
    (false, "secret-required-but-missing-or-mismatch".into())
}

pub(in crate::handlers) fn ingest_secret_for(state: &AppState, source: &str) -> String {
    if let Some(secret) = environment_custom_ingest_secrets().get(source) {
        return secret.trim().to_string();
    }
    let env_key = ingest_secret_env_key(source);
    let env_val = env_string(&env_key);
    if !env_val.trim().is_empty() {
        return env_val.trim().into();
    }
    state
        .cfg()
        .toml
        .get("ingest")
        .and_then(|v| v.get("secrets"))
        .and_then(|v| v.get(source))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

pub(in crate::handlers) fn ingest_auth_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let mut sources = serde_json::Map::new();
    let mut custom_env_secrets = environment_custom_ingest_secrets();
    for src in cfg.ingest_sources() {
        let env_val = custom_env_secrets
            .remove(&src)
            .unwrap_or_else(|| env_string(&ingest_secret_env_key(&src)));
        let toml_val = cfg
            .toml
            .get("ingest")
            .and_then(|v| v.get("secrets"))
            .and_then(|v| v.get(&src))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        sources.insert(
            src.clone(),
            if !env_val.trim().is_empty() {
                source_payload(&cfg, &src, true, "env")
            } else if !toml_val.trim().is_empty() {
                source_payload(&cfg, &src, true, "toml")
            } else {
                source_payload(&cfg, &src, false, "")
            },
        );
    }
    json!({
        "sources": sources,
        "auth_methods_accepted": ["Authorization: Bearer <secret>", "X-Klaxond-Token: <secret>", "?token=<secret> query param"],
        "note": "Sources without a configured secret are disabled and reject delivery. Setting or generating a secret enables the source.",
    })
}

fn source_payload(cfg: &RuntimeConfig, source: &str, configured: bool, from: &str) -> Value {
    let custom = cfg.custom_ingest_source(source).is_some();
    let definition_from = if environment_custom_ingest_sources().contains_key(source) {
        "env"
    } else if custom {
        "toml"
    } else {
        "builtin"
    };
    json!({
        "configured": configured,
        "from": from,
        "custom": custom,
        "definition_from": definition_from,
        "display_name": cfg.ingest_source_display_name(source),
        "endpoint": ingest_endpoint(cfg, source),
    })
}

fn ingest_endpoint(cfg: &RuntimeConfig, source: &str) -> String {
    if cfg.custom_ingest_source(source).is_some() {
        format!("/ingest/{source}/{{severity}}")
    } else if source == "grafana" {
        "/webhook/{severity}".to_string()
    } else {
        format!("/{source}/{{severity}}")
    }
}

fn ingest_secret_env_key(source: &str) -> String {
    format!(
        "KLAXOND_INGEST_SECRET_{}",
        source.to_ascii_uppercase().replace('-', "_")
    )
}

#[cfg(test)]
mod tests {
    use super::ingest_secret_env_key;

    #[test]
    fn source_names_map_to_portable_environment_keys() {
        assert_eq!(
            ingest_secret_env_key("uptime-kuma"),
            "KLAXOND_INGEST_SECRET_UPTIME_KUMA"
        );
        assert_eq!(
            ingest_secret_env_key("grafana"),
            "KLAXOND_INGEST_SECRET_GRAFANA"
        );
    }
}
