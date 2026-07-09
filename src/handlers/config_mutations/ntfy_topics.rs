use super::super::{json_body, json_response, text};
use crate::config::{NtfyTopic, load_runtime_config, save_ntfy_topics};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

pub(in crate::handlers) fn update_ntfy_topics(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Ok(request) = NtfyTopicsRequest::from_value(payload) else {
        return text(StatusCode::BAD_REQUEST, "missing 'topics' list");
    };
    state
        .with_config_write_lock(|| update_topics_under_lock(state, &request.topics))
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn update_topics_under_lock(state: &AppState, incoming: &[NtfyTopicPatch]) -> Response<Body> {
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
    incoming: &[NtfyTopicPatch],
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
    topic: &NtfyTopicPatch,
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

fn topic_name(idx: usize, topic: &NtfyTopicPatch) -> Result<String, String> {
    let name = topic.name.as_deref().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return Err(format!("topic[{idx}]: empty name"));
    }
    Ok(name)
}

fn topic_handles(idx: usize, name: &str, topic: &NtfyTopicPatch) -> Result<Vec<String>, String> {
    let Some(handles_arr) = topic.handles.as_ref() else {
        return Err(format!("topic[{idx}] '{name}': handles must be a list"));
    };
    let handles = handles_arr
        .iter()
        .map(|raw| raw.trim().to_ascii_lowercase())
        .filter(|handle| !handle.is_empty())
        .collect::<Vec<_>>();
    if handles.is_empty() {
        return Err(format!("topic[{idx}] '{name}': handles is empty"));
    }
    Ok(handles)
}

fn topic_token(topic: &NtfyTopicPatch, name: &str, existing: &HashMap<String, String>) -> String {
    let token_in = topic.token.as_deref().unwrap_or("");
    if token_in == "***SET***" {
        existing.get(name).cloned().unwrap_or_default()
    } else {
        token_in.to_string()
    }
}

#[derive(Debug, Default)]
struct NtfyTopicsRequest {
    topics: Vec<NtfyTopicPatch>,
}

impl NtfyTopicsRequest {
    fn from_value(value: Value) -> Result<Self, ()> {
        let topics = value
            .get("topics")
            .and_then(Value::as_array)
            .ok_or(())?
            .iter()
            .map(NtfyTopicPatch::from_value)
            .collect();
        Ok(Self { topics })
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct NtfyTopicPatch {
    #[serde(default, deserialize_with = "optional_string")]
    name: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    token: Option<String>,
    #[serde(default, deserialize_with = "optional_string_vec")]
    handles: Option<Vec<String>>,
}

impl NtfyTopicPatch {
    fn from_value(value: &Value) -> Self {
        if !value.is_object() {
            return Self::default();
        }
        serde_json::from_value(value.clone()).unwrap_or_default()
    }
}

fn optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::String(value)) => Some(value),
        _ => None,
    })
}

fn optional_string_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Array(values)) => Some(
            values
                .into_iter()
                .filter_map(|value| match value {
                    Value::String(value) => Some(value),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntfy_topics_request_preserves_normalization_and_secret_sentinel() {
        let request = NtfyTopicsRequest::from_value(json!({
            "topics": [
                {
                    "name": " info-topic ",
                    "token": "plain-token",
                    "handles": [" Info ", "", 42, "PAGE"]
                },
                {
                    "name": "page-topic",
                    "token": "***SET***",
                    "handles": ["critical"]
                }
            ]
        }))
        .expect("topics request");
        let existing = HashMap::from([("page-topic".to_string(), "existing-token".to_string())]);

        let topics = clean_topics(&request.topics, &existing).expect("clean topics");

        assert_eq!(
            topics,
            vec![
                NtfyTopic {
                    name: "info-topic".to_string(),
                    token: "plain-token".to_string(),
                    handles: vec!["info".to_string(), "page".to_string()],
                },
                NtfyTopic {
                    name: "page-topic".to_string(),
                    token: "existing-token".to_string(),
                    handles: vec!["critical".to_string()],
                },
            ]
        );
    }

    #[test]
    fn ntfy_topics_request_preserves_validation_errors() {
        let request = NtfyTopicsRequest::from_value(json!({
            "topics": [
                "not an object",
                { "name": "missing-handles", "handles": "critical" },
                { "name": "dup", "handles": ["info"] },
                { "name": "dup", "handles": ["critical"] },
                { "name": "empty-handles", "handles": [42, " "] }
            ]
        }))
        .expect("topics request");

        let err = clean_topics(&request.topics, &HashMap::new()).expect_err("validation errors");

        assert!(err.contains("topic[0]: empty name"));
        assert!(err.contains("topic[1] 'missing-handles': handles must be a list"));
        assert!(err.contains("topic[3]: duplicate name 'dup'"));
        assert!(err.contains("topic[4] 'empty-handles': handles is empty"));
    }

    #[test]
    fn ntfy_topics_request_requires_topics_array() {
        assert!(NtfyTopicsRequest::from_value(json!({})).is_err());
        assert!(NtfyTopicsRequest::from_value(json!({"topics": {}})).is_err());
        assert_eq!(
            clean_topics(
                &NtfyTopicsRequest::from_value(json!({"topics": []}))
                    .expect("empty topics array")
                    .topics,
                &HashMap::new(),
            )
            .expect_err("no valid topics"),
            "need at least one valid topic"
        );
    }
}
