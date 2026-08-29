use super::super::config_admin::persist_reload;
use super::super::{json_body, json_response, text};
use crate::config::INGEST_SOURCES;
use crate::state::AppState;
use crate::util::{env_string, random_hex, toml_table_mut};
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use serde_json::{Value, json};
use std::collections::HashMap;

pub(in crate::handlers) fn update_ingest_auth(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let src = payload
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let action = payload
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !INGEST_SOURCES.contains(&src.as_str()) {
        return text(
            StatusCode::BAD_REQUEST,
            &format!("source must be one of {:?}", INGEST_SOURCES),
        );
    }
    if !matches!(action.as_str(), "set" | "generate" | "clear") {
        return text(
            StatusCode::BAD_REQUEST,
            "action must be one of: set, generate, clear",
        );
    }
    if action == "set" {
        let sec = payload
            .get("secret")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if sec.len() < 16 {
            return text(
                StatusCode::BAD_REQUEST,
                "secret missing or shorter than 16 chars",
            );
        }
    }
    let new_secret = match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        let secrets = toml_table_mut(&mut cfg.toml, &["ingest", "secrets"]);
        let mut new_secret = None;
        match action.as_str() {
            "clear" => {
                secrets.remove(&src);
            }
            "generate" => {
                let sec = random_hex(32);
                secrets.insert(src.clone(), toml::Value::String(sec.clone()));
                new_secret = Some(sec);
            }
            _ => {
                let sec = payload
                    .get("secret")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                secrets.insert(src.clone(), toml::Value::String(sec.into()));
            }
        }
        persist_reload(state, cfg.toml).map(|_| new_secret)
    }) {
        Ok(Ok(new_secret)) => new_secret,
        Ok(Err(err)) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    let mut resp = json!({"ok": true, "source": src, "action": action});
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
    let mut sources = serde_json::Map::new();
    for src in INGEST_SOURCES {
        let env_val = env_string(&ingest_secret_env_key(src));
        let toml_val = state
            .cfg()
            .toml
            .get("ingest")
            .and_then(|v| v.get("secrets"))
            .and_then(|v| v.get(*src))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        sources.insert(
            (*src).into(),
            if !env_val.trim().is_empty() {
                json!({"configured": true, "from": "env"})
            } else if !toml_val.trim().is_empty() {
                json!({"configured": true, "from": "toml"})
            } else {
                json!({"configured": false, "from": ""})
            },
        );
    }
    json!({
        "sources": sources,
        "auth_methods_accepted": ["Authorization: Bearer <secret>", "X-Klaxond-Token: <secret>", "?token=<secret> query param"],
        "note": "Sources without a configured secret are disabled and reject delivery. Setting or generating a secret enables the source.",
    })
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
