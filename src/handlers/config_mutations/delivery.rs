use super::super::config_admin::persist_reload;
use super::{json_body, json_response, json_to_toml, text};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::json;

pub(in crate::handlers) fn update_delivery_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let delivery = toml_table_mut(&mut cfg.toml, &["delivery"]);
            if let Some(value) = payload
                .get("default_policy")
                .and_then(|value| value.as_str())
            {
                delivery.insert("default_policy".into(), toml::Value::String(value.into()));
            }
            if let Some(policies) = payload.get("policies") {
                delivery.insert("policies".into(), json_to_toml(policies.clone()));
            }
            if let Some(rules) = payload.get("rules") {
                delivery.insert("rules".into(), json_to_toml(rules.clone()));
            }
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true})))
                .unwrap_or_else(|error| text(StatusCode::INTERNAL_SERVER_ERROR, &error))
        })
        .unwrap_or_else(|error| text(StatusCode::INTERNAL_SERVER_ERROR, &error))
}
