use super::super::{EmptyStrExt, Parts, action, capitalize};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use serde_json::Value;

pub fn parse_decypharr_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let event = json_get_str(payload, "event").trim().to_ascii_lowercase();
    let name = json_get_str(payload, "name")
        .if_empty("<unknown>")
        .trim()
        .to_string();
    let event_human = decypharr_event_human(&event);
    Parts {
        title: format!("{} Decypharr: {event_human}: {name}", cfg.icon(severity)),
        body: decypharr_body(payload, &event_human, &name),
        tags: decypharr_tags(severity, cfg),
        actions: vec![action(
            "view",
            "Open Decypharr",
            "https://decypharr.luigibarretta.com",
        )],
        priority: cfg.priority(severity),
        alertname: String::new(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}

fn decypharr_event_human(event: &str) -> String {
    match event {
        "download_start" => "Download started".to_string(),
        "download_complete" => "Download completed".to_string(),
        "download_fail" | "download_failed" => "Download failed".to_string(),
        "download_error" => "Download error".to_string(),
        "" => "Event".to_string(),
        _ => capitalize(&event.replace('_', " ")),
    }
}

fn decypharr_body(payload: &Value, event_human: &str, name: &str) -> String {
    let mut body = base_decypharr_body(payload, event_human, name);
    let debrid = json_get_str(payload, "debrid").trim().to_string();
    if !debrid.is_empty()
        && !body
            .to_ascii_lowercase()
            .contains(&debrid.to_ascii_lowercase())
    {
        body.push_str(&format!("\n[backend: {debrid}]"));
    }
    body
}

fn base_decypharr_body(payload: &Value, event_human: &str, name: &str) -> String {
    let message = json_get_str(payload, "message").trim().to_string();
    if !message.is_empty() {
        return message;
    }
    let mut parts = vec![format!("{event_human}: {name}")];
    let content_path = json_get_str(payload, "content_path").trim().to_string();
    if !content_path.is_empty() {
        parts.push(format!("-> {content_path}"));
    }
    parts.join("\n")
}

fn decypharr_tags(severity: &str, cfg: &RuntimeConfig) -> Vec<String> {
    let mut tags = vec![
        cfg.tag_prefix(severity),
        severity.into(),
        "decypharr".into(),
        "download".into(),
    ];
    let sev_tag = cfg.tag_prefix(severity);
    if !tags.contains(&sev_tag) {
        tags.insert(0, sev_tag);
    }
    tags
}

pub fn decypharr_severity(payload: &Value, fallback: &str, cfg: &RuntimeConfig) -> String {
    let mapped = match json_get_str(payload, "status")
        .to_ascii_lowercase()
        .as_str()
    {
        "success" => Some("info"),
        "failure" => Some("warning"),
        "error" => Some("critical"),
        _ => None,
    };
    mapped
        .filter(|s| cfg.known_severities().iter().any(|k| k == *s))
        .unwrap_or(fallback)
        .to_string()
}
