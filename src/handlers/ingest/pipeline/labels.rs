use serde_json::Value;
use std::collections::HashMap;

pub(super) fn common_labels(source: &str, payload: &Value) -> HashMap<String, String> {
    if !matches!(source, "grafana" | "blackstart") {
        return HashMap::new();
    }
    let mut labels: HashMap<String, String> = payload
        .get("commonLabels")
        .and_then(Value::as_object)
        .map(|labels| {
            labels
                .iter()
                .map(|(key, value)| (key.clone(), crate::parsers::scalar_to_string(value)))
                .collect()
        })
        .unwrap_or_default();
    if let Some(key) = alertmanager_incident_key(payload) {
        // Alertmanager can remove labels from commonLabels when a group gains
        // another instance. Preserve a stable identity for emergency recovery.
        labels.insert("__klaxond_incident_key".into(), key);
    }
    labels
}

fn alertmanager_incident_key(payload: &Value) -> Option<String> {
    let group_key = payload
        .get("groupKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(group_key) = group_key {
        return Some(format!("group-key:{group_key}"));
    }
    let group_labels = payload.get("groupLabels")?.as_object()?;
    if group_labels.is_empty() {
        return None;
    }
    let mut entries = group_labels
        .iter()
        .map(|(key, value)| {
            (
                key.trim().to_ascii_lowercase(),
                crate::parsers::scalar_to_string(value)
                    .trim()
                    .to_ascii_lowercase(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort_unstable();
    Some(format!(
        "group-labels:{}",
        entries
            .into_iter()
            .map(|(key, value)| format!("{}:{}={}:{}", key.len(), key, value.len(), value))
            .collect::<Vec<_>>()
            .join("|")
    ))
}
