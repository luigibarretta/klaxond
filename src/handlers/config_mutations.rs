use super::config_admin::persist_reload;
use super::{json_body, json_response, json_to_toml, text};
use crate::config::{
    DEDUP_SOURCES, NtfyTopic, default_dedup, load_runtime_config, save_dedup, save_ntfy_topics,
    save_render_config,
};
use crate::parsers::{
    parse_beszel_payload, parse_grafana_payload, parse_healthchecks_payload, parse_wud_payload,
};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

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

pub(super) fn render_preview(state: &AppState, body: Bytes) -> Response<Body> {
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

pub(super) fn update_render_config(state: &AppState, body: Bytes) -> Response<Body> {
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

pub(super) fn update_ntfy_topics(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(incoming) = payload.get("topics").and_then(|v| v.as_array()) else {
        return text(StatusCode::BAD_REQUEST, "missing 'topics' list");
    };
    state.with_config_write_lock(|| {
        let existing = state
            .cfg()
            .ntfy_topics
            .into_iter()
            .map(|t| (t.name, t.token))
            .collect::<HashMap<_, _>>();
        let mut cleaned = Vec::new();
        let mut names = std::collections::HashSet::new();
        let mut errors = Vec::new();
        for (idx, t) in incoming.iter().enumerate() {
            let name = t
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if name.is_empty() {
                errors.push(format!("topic[{idx}]: empty name"));
                continue;
            }
            if !names.insert(name.clone()) {
                errors.push(format!("topic[{idx}]: duplicate name '{name}'"));
                continue;
            }
            let Some(handles_arr) = t.get("handles").and_then(|v| v.as_array()) else {
                errors.push(format!("topic[{idx}] '{name}': handles must be a list"));
                continue;
            };
            let handles = handles_arr
                .iter()
                .filter_map(|h| h.as_str().map(|s| s.trim().to_ascii_lowercase()))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            if handles.is_empty() {
                errors.push(format!("topic[{idx}] '{name}': handles is empty"));
                continue;
            }
            let token_in = t.get("token").and_then(|v| v.as_str()).unwrap_or("");
            let token = if token_in == "***SET***" {
                existing.get(&name).cloned().unwrap_or_default()
            } else {
                token_in.to_string()
            };
            cleaned.push(NtfyTopic {
                name,
                token,
                handles,
            });
        }
        if !errors.is_empty() {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("validation errors:\n  - {}", errors.join("\n  - ")),
            );
        }
        if cleaned.is_empty() {
            return text(StatusCode::BAD_REQUEST, "need at least one valid topic");
        }
        if let Err(err) = save_ntfy_topics(&state.paths, &cleaned) {
            return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }
        match load_runtime_config(&state.paths) {
            Ok(cfg) => {
                if let Err(err) = state.try_replace_config(cfg) {
                    return text(StatusCode::INTERNAL_SERVER_ERROR, &err);
                }
            }
            Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
        let cfg = state.cfg();
        let redacted = cfg
            .ntfy_topics
            .iter()
            .map(|t| json!({"name": t.name, "token": if t.token.is_empty() { "" } else { "***SET***" }, "handles": t.handles}))
            .collect::<Vec<_>>();
        json_response(
            json!({"ok": true, "topics": redacted, "known_severities": cfg.known_severities(), "persisted_at": state.paths.ntfy_topics}),
        )
    })
    .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
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

pub(super) fn update_channel_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            if let Some(n) = payload.get("ntfy").and_then(|v| v.as_object()) {
                let ntfy = toml_table_mut(&mut cfg.toml, &["ntfy"]);
                if let Some(url) = n.get("url").and_then(|v| v.as_str()) {
                    ntfy.insert(
                        "url".into(),
                        toml::Value::String(url.trim_end_matches('/').into()),
                    );
                }
                if let Some(topics) = n.get("topics").and_then(|v| v.as_object()) {
                    let ntfy_topics = toml_table_mut(&mut cfg.toml, &["ntfy", "topics"]);
                    for sev in ["info", "warning", "critical"] {
                        if let Some(v) = topics.get(sev).and_then(|v| v.as_str()) {
                            ntfy_topics.insert(sev.into(), toml::Value::String(v.into()));
                        }
                    }
                }
            }
            if let Some(t) = payload.get("telegram").and_then(|v| v.as_object()) {
                let tg = toml_table_mut(&mut cfg.toml, &["telegram"]);
                if let Some(v) = t.get("chat_id").and_then(|v| v.as_str()) {
                    tg.insert("chat_id".into(), toml::Value::String(v.into()));
                }
                if let Some(v) = t.get("api_base").and_then(|v| v.as_str()) {
                    tg.insert(
                        "api_base".into(),
                        toml::Value::String(v.trim_end_matches('/').into()),
                    );
                }
                if let Some(v) = t
                    .get("bot_token")
                    .and_then(|v| v.as_str())
                    .filter(|v| *v != "***SET***")
                {
                    tg.insert("bot_token".into(), toml::Value::String(v.into()));
                }
            }
            if let Some(s) = payload.get("smtp").and_then(|v| v.as_object()) {
                let smtp = toml_table_mut(&mut cfg.toml, &["smtp"]);
                for k in ["host", "from_addr", "to_addr"] {
                    if let Some(v) = s.get(k).and_then(|v| v.as_str()) {
                        smtp.insert(k.into(), toml::Value::String(v.into()));
                    }
                }
                if let Some(v) = s.get("user").and_then(|v| v.as_str()) {
                    smtp.insert("user".into(), toml::Value::String(v.into()));
                }
                if let Some(v) = s
                    .get("password")
                    .and_then(|v| v.as_str())
                    .filter(|v| *v != "***SET***")
                {
                    smtp.insert("password".into(), toml::Value::String(v.into()));
                }
                if let Some(p) = s.get("port").and_then(|v| v.as_i64()) {
                    smtp.insert("port".into(), toml::Value::Integer(p));
                }
                if let Some(v) = s.get("starttls").and_then(|v| v.as_bool()) {
                    smtp.insert("starttls".into(), toml::Value::Boolean(v));
                }
            }
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true})))
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
