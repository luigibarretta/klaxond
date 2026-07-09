use super::super::config_admin::persist_reload;
use super::super::{json_body, json_response, text};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Map, Value, json};

pub(in crate::handlers) fn update_channel_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            apply_ntfy_config(&mut cfg.toml, payload.get("ntfy"));
            apply_telegram_config(&mut cfg.toml, payload.get("telegram"));
            apply_smtp_config(&mut cfg.toml, payload.get("smtp"));
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true})))
                .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn apply_ntfy_config(toml: &mut toml::Value, value: Option<&Value>) {
    let Some(ntfy_in) = value.and_then(Value::as_object) else {
        return;
    };
    let ntfy = toml_table_mut(toml, &["ntfy"]);
    if let Some(url) = string_field(ntfy_in, "url") {
        ntfy.insert(
            "url".into(),
            toml::Value::String(url.trim_end_matches('/').into()),
        );
    }
    if let Some(topics) = ntfy_in.get("topics").and_then(Value::as_object) {
        let ntfy_topics = toml_table_mut(toml, &["ntfy", "topics"]);
        for severity in ["info", "warning", "critical"] {
            if let Some(topic) = string_field(topics, severity) {
                ntfy_topics.insert(severity.into(), toml::Value::String(topic.into()));
            }
        }
    }
}

fn apply_telegram_config(toml: &mut toml::Value, value: Option<&Value>) {
    let Some(telegram_in) = value.and_then(Value::as_object) else {
        return;
    };
    let telegram = toml_table_mut(toml, &["telegram"]);
    insert_string(telegram, telegram_in, "chat_id");
    if let Some(api_base) = string_field(telegram_in, "api_base") {
        telegram.insert(
            "api_base".into(),
            toml::Value::String(api_base.trim_end_matches('/').into()),
        );
    }
    if let Some(token) =
        string_field(telegram_in, "bot_token").filter(|value| *value != "***SET***")
    {
        telegram.insert("bot_token".into(), toml::Value::String(token.into()));
    }
}

fn apply_smtp_config(toml: &mut toml::Value, value: Option<&Value>) {
    let Some(smtp_in) = value.and_then(Value::as_object) else {
        return;
    };
    let smtp = toml_table_mut(toml, &["smtp"]);
    for key in ["host", "from_addr", "to_addr", "user"] {
        insert_string(smtp, smtp_in, key);
    }
    if let Some(password) = string_field(smtp_in, "password").filter(|value| *value != "***SET***")
    {
        smtp.insert("password".into(), toml::Value::String(password.into()));
    }
    if let Some(port) = smtp_in.get("port").and_then(Value::as_i64) {
        smtp.insert("port".into(), toml::Value::Integer(port));
    }
    if let Some(starttls) = smtp_in.get("starttls").and_then(Value::as_bool) {
        smtp.insert("starttls".into(), toml::Value::Boolean(starttls));
    }
}

fn insert_string(
    target: &mut toml::map::Map<String, toml::Value>,
    source: &Map<String, Value>,
    key: &str,
) {
    if let Some(value) = string_field(source, key) {
        target.insert(key.into(), toml::Value::String(value.into()));
    }
}

fn string_field<'a>(source: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    source.get(key).and_then(Value::as_str)
}
