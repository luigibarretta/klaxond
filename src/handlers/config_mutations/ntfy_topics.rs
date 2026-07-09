use super::super::{json_body, json_response, text};
use crate::config::{NtfyTopic, load_runtime_config, save_ntfy_topics};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

pub(in crate::handlers) fn update_ntfy_topics(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(incoming) = payload.get("topics").and_then(Value::as_array) else {
        return text(StatusCode::BAD_REQUEST, "missing 'topics' list");
    };
    state
        .with_config_write_lock(|| update_topics_under_lock(state, incoming))
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn update_topics_under_lock(state: &AppState, incoming: &[Value]) -> Response<Body> {
    let existing = existing_tokens(state);
    let cleaned = match clean_topics(incoming, &existing) {
        Ok(topics) => topics,
        Err(message) => return text(StatusCode::BAD_REQUEST, &message),
    };
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
    json_response(updated_topics_payload(state))
}

fn existing_tokens(state: &AppState) -> HashMap<String, String> {
    state
        .cfg()
        .ntfy_topics
        .into_iter()
        .map(|topic| (topic.name, topic.token))
        .collect()
}

fn clean_topics(
    incoming: &[Value],
    existing: &HashMap<String, String>,
) -> Result<Vec<NtfyTopic>, String> {
    let mut cleaned = Vec::new();
    let mut names = HashSet::new();
    let mut errors = Vec::new();
    for (idx, topic) in incoming.iter().enumerate() {
        match clean_topic(idx, topic, existing, &mut names) {
            Ok(topic) => cleaned.push(topic),
            Err(err) => errors.push(err),
        }
    }
    if !errors.is_empty() {
        return Err(format!("validation errors:\n  - {}", errors.join("\n  - ")));
    }
    if cleaned.is_empty() {
        return Err("need at least one valid topic".into());
    }
    Ok(cleaned)
}

fn clean_topic(
    idx: usize,
    topic: &Value,
    existing: &HashMap<String, String>,
    names: &mut HashSet<String>,
) -> Result<NtfyTopic, String> {
    let name = topic_name(idx, topic)?;
    if !names.insert(name.clone()) {
        return Err(format!("topic[{idx}]: duplicate name '{name}'"));
    }
    let handles = topic_handles(idx, &name, topic)?;
    let token = topic_token(topic, &name, existing);
    Ok(NtfyTopic {
        name,
        token,
        handles,
    })
}

fn topic_name(idx: usize, topic: &Value) -> Result<String, String> {
    let name = topic
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() {
        return Err(format!("topic[{idx}]: empty name"));
    }
    Ok(name)
}

fn topic_handles(idx: usize, name: &str, topic: &Value) -> Result<Vec<String>, String> {
    let Some(handles_arr) = topic.get("handles").and_then(Value::as_array) else {
        return Err(format!("topic[{idx}] '{name}': handles must be a list"));
    };
    let handles = handles_arr
        .iter()
        .filter_map(|handle| handle.as_str().map(|raw| raw.trim().to_ascii_lowercase()))
        .filter(|handle| !handle.is_empty())
        .collect::<Vec<_>>();
    if handles.is_empty() {
        return Err(format!("topic[{idx}] '{name}': handles is empty"));
    }
    Ok(handles)
}

fn topic_token(topic: &Value, name: &str, existing: &HashMap<String, String>) -> String {
    let token_in = topic.get("token").and_then(Value::as_str).unwrap_or("");
    if token_in == "***SET***" {
        existing.get(name).cloned().unwrap_or_default()
    } else {
        token_in.to_string()
    }
}

fn updated_topics_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let redacted = cfg
        .ntfy_topics
        .iter()
        .map(|topic| {
            json!({
                "name": topic.name,
                "token": if topic.token.is_empty() { "" } else { "***SET***" },
                "handles": topic.handles,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "ok": true,
        "topics": redacted,
        "known_severities": cfg.known_severities(),
        "persisted_at": state.paths.ntfy_topics,
    })
}
