use super::config_admin::persist_reload;
use super::{json_body, json_response, json_to_toml, text};
use crate::config::{DEDUP_SOURCES, default_dedup, save_dedup};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

mod channel;
mod ntfy_topics;
mod render;

pub(super) use self::channel::update_channel_config;
pub(super) use self::ntfy_topics::update_ntfy_topics;
pub(super) use self::render::{render_preview, update_render_config};

pub(super) fn cascade_toggle(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let next = if let Some(v) = payload.get("enabled").and_then(|v| v.as_bool()) {
        v
    } else {
        !state.cascade_runtime_enabled.load(Ordering::Relaxed)
    };
    state.cascade_runtime_enabled.store(next, Ordering::Relaxed);
    json_response(json!({"cascade_enabled_runtime": next}))
}

pub(super) fn update_dedup_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(new) = payload.get("settings").and_then(|v| v.as_object()) else {
        return text(StatusCode::BAD_REQUEST, "missing 'settings' object");
    };
    let mut cleaned = default_dedup();
    for src in DEDUP_SOURCES {
        if let Some(incoming) = new.get(*src).and_then(|v| v.as_object())
            && let Some(base) = cleaned.get_mut(*src)
        {
            if let Some(v) = incoming.get("enabled").and_then(|v| v.as_bool()) {
                base.enabled = v;
            }
            if let Some(v) = incoming.get("window_s").and_then(|v| v.as_u64()) {
                base.window_s = v.clamp(5, 3600);
            }
            if let Some(v) = incoming.get("strategy").and_then(|v| v.as_str())
                && matches!(v, "none" | "time" | "key")
            {
                base.strategy = v.into();
            }
            if let Some(v) = incoming.get("override_critical").and_then(|v| v.as_bool()) {
                base.override_critical = v;
            }
        }
    }
    state
        .with_config_write_lock(|| {
            if let Err(err) = save_dedup(&state.paths, &cleaned) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            let mut cfg = state.cfg();
            cfg.dedup = cleaned.clone();
            state.replace_config(cfg);
            json_response(json!({"ok": true, "settings": cleaned}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

pub(super) fn update_cascade_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(arr) = payload.get("tiers").and_then(|v| v.as_array()) else {
        return text(StatusCode::BAD_REQUEST, "tiers must be a non-empty list");
    };
    let mut tiers = Vec::new();
    for t in arr {
        let name = t
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(name.as_str(), "ntfy" | "telegram" | "smtp") {
            continue;
        }
        tiers.push(json!({"name": name, "timeout_seconds": t.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(5).clamp(1, 60)}));
    }
    if tiers.is_empty() {
        return text(StatusCode::BAD_REQUEST, "no valid tiers");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            {
                let cas = toml_table_mut(&mut cfg.toml, &["cascade"]);
                cas.insert("tiers".into(), json_to_toml(Value::Array(tiers.clone())));
                if let Some(v) = payload
                    .get("default_enabled_for_webhook")
                    .and_then(|v| v.as_bool())
                {
                    cas.insert(
                        "default_enabled_for_webhook".into(),
                        toml::Value::Boolean(v),
                    );
                }
            }
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true, "tiers": state.cfg().tiers})))
                .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

pub(super) fn update_delivery_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let delivery = toml_table_mut(&mut cfg.toml, &["delivery"]);
            if let Some(v) = payload.get("default_policy").and_then(|v| v.as_str()) {
                delivery.insert("default_policy".into(), toml::Value::String(v.into()));
            }
            if let Some(p) = payload.get("policies") {
                delivery.insert("policies".into(), json_to_toml(p.clone()));
            }
            if let Some(r) = payload.get("rules") {
                delivery.insert("rules".into(), json_to_toml(r.clone()));
            }
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true})))
                .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}
