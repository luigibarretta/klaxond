use crate::config::{
    RuntimeConfig, environment_custom_ingest_secrets, environment_custom_ingest_sources,
};
use crate::state::AppState;
use crate::util::env_string;
use axum::http::HeaderMap;
use serde_json::{Value, json};
use std::collections::HashMap;

mod update;

pub(in crate::handlers) use update::update_ingest_auth;

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

pub(super) fn ingest_endpoint(cfg: &RuntimeConfig, source: &str) -> String {
    if cfg.custom_ingest_source(source).is_some() {
        format!("/ingest/{source}/{{severity}}")
    } else if source == "grafana" {
        "/webhook/{severity}".to_string()
    } else {
        format!("/{source}/{{severity}}")
    }
}

pub(super) fn ingest_secret_env_key(source: &str) -> String {
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
