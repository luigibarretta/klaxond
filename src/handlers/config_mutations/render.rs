use super::super::config_admin::persist_reload;
use super::super::{json_body, json_response, text};
use crate::config::save_render_config;
use crate::parsers::{
    parse_beszel_payload, parse_grafana_payload, parse_healthchecks_payload, parse_wud_payload,
};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use std::collections::HashMap;

pub(in crate::handlers) fn render_preview(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let severity = payload
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("warning")
        .to_string();
    let sample = payload.get("payload").cloned().unwrap_or_else(|| json!({}));
    let (parts, url) = state.with_cfg(|cfg| {
        let parts = if sample.get("alerts").is_some() || sample.get("commonLabels").is_some() {
            parse_grafana_payload(&sample, &severity, cfg)
        } else if sample.get("check").is_some() && sample.get("status").is_some() {
            parse_healthchecks_payload(&sample, &severity, cfg)
        } else if sample.get("title").is_some()
            && sample.get("body").is_some()
            && sample.get("alert").is_none()
        {
            parse_wud_payload(&sample, &severity, cfg)
        } else {
            parse_beszel_payload(&sample, &severity, cfg)
        };
        let url = cfg
            .ntfy_topics
            .iter()
            .find(|t| t.handles.iter().any(|h| h == &severity))
            .map(|t| format!("{}/{}", cfg.ntfy_url, t.name))
            .unwrap_or_else(|| format!("{}/(no topic handles '{}')", cfg.ntfy_url, severity));
        (parts, url)
    });
    let title_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        parts.title.as_bytes(),
    );
    json_response(json!({
        "url": url,
        "headers": {
            "Title (raw)": parts.title,
            "Title (RFC2047)": format!("=?UTF-8?B?{title_b64}?="),
            "Tags": parts.tags.join(","),
            "Priority": parts.priority,
            "Actions": parts.actions.iter().map(|[k,l,t]| format!("{k}, {l}, {t}")).collect::<Vec<_>>().join("; "),
        },
        "body": parts.body,
    }))
}

pub(in crate::handlers) fn update_render_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let has_dashboards = payload.get("component_dashboards").is_some();
    let mut cleaned: HashMap<String, [String; 2]> = HashMap::new();
    if let Some(obj) = payload
        .get("component_dashboards")
        .and_then(|v| v.as_object())
    {
        for (k, v) in obj {
            if let Some(arr) = v.as_array() {
                let label = arr
                    .first()
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let url = arr
                    .get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !k.is_empty() && !label.is_empty() && !url.is_empty() {
                    cleaned.insert(k.clone(), [label, url]);
                }
            }
        }
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            if has_dashboards {
                if let Err(err) = save_render_config(&state.paths, &cleaned) {
                    return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
                }
                cfg.component_dashboards = cleaned.clone();
                toml_table_mut(&mut cfg.toml, &["render"])
                    .insert("component_dashboards".into(), dashboards_to_toml(&cleaned));
            }
            if let Some(settings) = payload.get("settings").and_then(|v| v.as_object()) {
                {
                    let render = toml_table_mut(&mut cfg.toml, &["render"]);
                    if let Some(v) = settings.get("grafana_base").and_then(|v| v.as_str()) {
                        render.insert(
                            "grafana_base".into(),
                            toml::Value::String(v.trim_end_matches('/').into()),
                        );
                    }
                    if let Some(v) = settings.get("grafana_render_base").and_then(|v| v.as_str()) {
                        render.insert(
                            "grafana_render_base".into(),
                            toml::Value::String(v.trim_end_matches('/').into()),
                        );
                    }
                    if let Some(v) = settings
                        .get("grafana_render_token")
                        .and_then(|v| v.as_str())
                        .filter(|v| *v != "***SET***")
                    {
                        render.insert("grafana_render_token".into(), toml::Value::String(v.into()));
                    }
                    if let Some(v) = settings.get("render_image_ttl").and_then(|v| v.as_u64()) {
                        render.insert(
                            "render_image_ttl".into(),
                            toml::Value::Integer(v.clamp(1, 86_400) as i64),
                        );
                    }
                }
                if let Some(v) = settings.get("public_url").and_then(|v| v.as_str()) {
                    toml_table_mut(&mut cfg.toml, &["server"]).insert(
                        "public_url".into(),
                        toml::Value::String(v.trim_end_matches('/').into()),
                    );
                }
                if let Some(v) = settings.get("ack_default_ttl").and_then(|v| v.as_u64()) {
                    toml_table_mut(&mut cfg.toml, &["acks"]).insert(
                        "default_ttl_seconds".into(),
                        toml::Value::Integer(v.clamp(60, 86_400) as i64),
                    );
                }
                return persist_reload(state, cfg.toml)
                    .map(|_| json_response(json!({"ok": true, "count": cleaned.len()})))
                    .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e));
            }
            if has_dashboards {
                return persist_reload(state, cfg.toml)
                    .map(|_| json_response(json!({"ok": true, "count": cleaned.len()})))
                    .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e));
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true, "count": cleaned.len()}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn dashboards_to_toml(dashboards: &HashMap<String, [String; 2]>) -> toml::Value {
    let mut table = toml::map::Map::new();
    let mut keys = dashboards.keys().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        if let Some([label, url]) = dashboards.get(key) {
            table.insert(
                key.clone(),
                toml::Value::Array(vec![
                    toml::Value::String(label.clone()),
                    toml::Value::String(url.clone()),
                ]),
            );
        }
    }
    toml::Value::Table(table)
}
