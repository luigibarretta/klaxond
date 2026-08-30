use crate::parsers::Parts;
use serde_json::Value;
use std::collections::HashMap;

pub fn dedup_key(
    source: &str,
    payload: &Value,
    parts: &Parts,
    common_labels: &HashMap<String, String>,
) -> String {
    source_key(source, payload, common_labels)
        .unwrap_or_else(|| format!("{source}:{}", title_fallback(parts)))
}

fn title_fallback(parts: &Parts) -> &str {
    if parts.title.is_empty() {
        "?"
    } else {
        &parts.title
    }
}

fn source_key(
    source: &str,
    payload: &Value,
    common_labels: &HashMap<String, String>,
) -> Option<String> {
    match source {
        "wud" => wud_key(payload),
        "grafana" => grafana_key(common_labels),
        "beszel" => beszel_key(payload, common_labels),
        "healthchecks" => healthchecks_key(payload),
        "uptime-kuma" => uptime_kuma_key(payload),
        "pve" => pve_key(payload),
        "authentik" => authentik_key(payload),
        "shelfmark" => shelfmark_key(payload),
        "prowlarr" => prowlarr_key(payload),
        "decypharr" => decypharr_key(payload),
        "github" => github_key(payload),
        _ => None,
    }
}

fn uptime_kuma_key(payload: &Value) -> Option<String> {
    let monitor = payload.get("monitor")?;
    let identity = monitor
        .get("id")
        .and_then(|value| match value {
            Value::Number(number) => Some(number.to_string()),
            Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
            _ => None,
        })
        .or_else(|| {
            monitor
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })?;
    Some(format!("uptime-kuma:{identity}"))
}

fn wud_key(payload: &Value) -> Option<String> {
    let payload = payload
        .as_array()
        .and_then(|a| a.first())
        .unwrap_or(payload);
    payload
        .get("image")
        .and_then(|image| image.get("name"))
        .and_then(Value::as_str)
        .or_else(|| payload.get("name").and_then(Value::as_str))
        .map(|image| format!("wud:{image}"))
}

fn grafana_key(common_labels: &HashMap<String, String>) -> Option<String> {
    common_labels
        .get("alertname")
        .filter(|alertname| !alertname.is_empty())
        .map(|alertname| format!("grafana:{alertname}"))
}

fn beszel_key(payload: &Value, common_labels: &HashMap<String, String>) -> Option<String> {
    payload
        .get("container_name")
        .and_then(Value::as_str)
        .or_else(|| common_labels.get("container_name").map(String::as_str))
        .map(|container_name| format!("beszel:{container_name}"))
}

fn healthchecks_key(payload: &Value) -> Option<String> {
    payload
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("check")
                .and_then(|check| check.get("name"))
                .and_then(Value::as_str)
        })
        .map(|check_name| format!("hc:{check_name}"))
}

fn pve_key(payload: &Value) -> Option<String> {
    payload
        .get("type")
        .and_then(Value::as_str)
        .filter(|event_type| !event_type.is_empty())
        .map(|event_type| format!("pve:{event_type}"))
}

fn authentik_key(payload: &Value) -> Option<String> {
    let data = payload.get("data").unwrap_or(&Value::Null);
    let user = data.get("user").and_then(Value::as_str).unwrap_or("");
    let action = data
        .get("event")
        .or_else(|| data.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("");
    (!user.is_empty() || !action.is_empty()).then(|| format!("authentik:{action}:{user}"))
}

fn shelfmark_key(payload: &Value) -> Option<String> {
    let title = payload
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let event = payload
        .get("event")
        .or_else(|| payload.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    (!title.is_empty() || !event.is_empty()).then(|| format!("shelfmark:{event}:{title}"))
}

fn prowlarr_key(payload: &Value) -> Option<String> {
    let event = payload
        .get("eventType")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if event.is_empty() {
        return None;
    }
    Some(format!("prowlarr:{event}:{}", prowlarr_message(payload)))
}

fn prowlarr_message(payload: &Value) -> String {
    let health = payload.get("health").unwrap_or(&Value::Null);
    health
        .get("message")
        .or_else(|| payload.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .chars()
        .take(60)
        .collect::<String>()
}

fn decypharr_key(payload: &Value) -> Option<String> {
    let event = trimmed_lowercase(payload, "event");
    let hash = trimmed_lowercase(payload, "hash");
    (!event.is_empty() || !hash.is_empty()).then(|| format!("decypharr:{event}:{hash}"))
}

fn github_key(payload: &Value) -> Option<String> {
    payload
        .get("comment_id")
        .map(|value| match value {
            Value::Number(number) => number.to_string(),
            Value::String(value) => value.trim().to_string(),
            _ => String::new(),
        })
        .filter(|value| !value.is_empty())
        .map(|comment_id| format!("github:{comment_id}"))
}

fn trimmed_lowercase(payload: &Value, key: &str) -> String {
    payload
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}
