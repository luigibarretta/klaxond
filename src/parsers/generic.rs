use super::{Parts, action, first_non_empty, scalar_to_string};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use serde_json::Value;

pub fn generic_delivery_severity(payload: &Value, fallback: &str) -> String {
    let status = json_get_str(payload, "status").trim().to_ascii_lowercase();
    if matches!(status.as_str(), "resolved" | "ok" | "closed" | "recovered") {
        "resolved".into()
    } else {
        fallback.to_string()
    }
}

pub fn parse_generic_payload(
    source: &str,
    payload: &Value,
    severity: &str,
    cfg: &RuntimeConfig,
) -> Parts {
    let delivery_severity = generic_delivery_severity(payload, severity);
    let label = cfg.ingest_source_display_name(source);
    let alert = first_non_empty(&[
        json_get_str(payload, "title"),
        json_get_str(payload, "alertname"),
        json_get_str(payload, "alert"),
        json_get_str(payload, "name"),
    ])
    .trim()
    .to_string();
    let alert = if alert.is_empty() {
        "Notification".to_string()
    } else {
        alert
    };
    let body = first_non_empty(&[
        json_get_str(payload, "message"),
        json_get_str(payload, "body"),
        json_get_str(payload, "description"),
        json_get_str(payload, "summary"),
    ])
    .trim()
    .to_string();
    let body = if body.is_empty() {
        payload
            .as_object()
            .filter(|object| !object.is_empty())
            .and_then(|_| serde_json::to_string_pretty(payload).ok())
            .unwrap_or_else(|| alert.clone())
    } else {
        body
    };
    let url = payload.get("url").map(scalar_to_string).unwrap_or_default();
    let actions = (!url.trim().is_empty())
        .then(|| action("view", "Open source", url.trim()))
        .into_iter()
        .collect();

    Parts {
        title: format!("{} {label}: {alert}", cfg.icon(&delivery_severity)),
        body,
        tags: vec![cfg.tag_prefix(&delivery_severity), source.to_string()],
        actions,
        priority: cfg.priority(&delivery_severity),
        alertname: alert,
        skip_snooze: delivery_severity == "resolved",
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_generic_payload;
    use crate::config::{Paths, load_runtime_config};
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn generic_payload_uses_common_notification_fields() {
        let temp = TempDir::new().unwrap();
        let cfg = load_runtime_config(&Paths::for_root(temp.path())).unwrap();
        let parts = parse_generic_payload(
            "home-assistant",
            &json!({"title": "Door open", "message": "Front door", "url": "https://example.test"}),
            "warning",
            &cfg,
        );
        assert!(parts.title.contains("home-assistant: Door open"));
        assert_eq!(parts.body, "Front door");
        assert_eq!(parts.actions[0][2], "https://example.test");
    }
}
