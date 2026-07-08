use super::super::{EmptyStrExt, Parts, action, first_non_empty};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use serde_json::Value;

struct ProwlarrMessage {
    event: String,
    title: String,
    body: String,
    wiki: String,
    app_url: String,
}

pub fn parse_prowlarr_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let message = prowlarr_message(payload);
    let tags = prowlarr_tags(&message.event, severity, cfg);
    let actions = prowlarr_actions(&message);
    Parts {
        title: format!("{} Prowlarr: {}", cfg.icon(severity), message.title),
        body: message.body,
        tags,
        actions,
        priority: cfg.priority(severity),
        alertname: String::new(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

fn prowlarr_message(payload: &Value) -> ProwlarrMessage {
    let event = json_get_str(payload, "eventType").if_empty("Unknown");
    let health = payload.get("health").unwrap_or(&Value::Null);
    let health_message = first_non_empty(&[
        json_get_str(health, "message"),
        json_get_str(payload, "message"),
    ]);
    let health_wiki = first_non_empty(&[
        json_get_str(health, "wikiUrl"),
        json_get_str(payload, "wikiUrl"),
    ]);
    let (title, body, wiki) = prowlarr_event_text(payload, event, &health_message, &health_wiki);
    ProwlarrMessage {
        event: event.to_string(),
        title,
        body,
        wiki,
        app_url: json_get_str(payload, "applicationUrl")
            .if_empty("https://prowlarr.luigibarretta.com")
            .to_string(),
    }
}

fn prowlarr_event_text(
    payload: &Value,
    event: &str,
    health_message: &str,
    health_wiki: &str,
) -> (String, String, String) {
    match event {
        "Health" => (
            "Health issue".to_string(),
            health_message.if_empty("Unknown health issue").to_string(),
            health_wiki.to_string(),
        ),
        "HealthRestored" => (
            "Health restored".to_string(),
            health_message
                .if_empty("All health issues resolved")
                .to_string(),
            String::new(),
        ),
        "ApplicationUpdate" => prowlarr_update_text(payload),
        "Test" => (
            "Test notification".to_string(),
            "Klaxond webhook test successful".to_string(),
            String::new(),
        ),
        _ => (
            event.to_string(),
            json_get_str(payload, "message").to_string(),
            String::new(),
        ),
    }
}

fn prowlarr_update_text(payload: &Value) -> (String, String, String) {
    let instance = json_get_str(payload, "instanceName").if_empty("Prowlarr");
    (
        "Application updated".to_string(),
        format!(
            "{} {} → {}",
            instance,
            json_get_str(payload, "previousVersion").if_empty("?"),
            json_get_str(payload, "newVersion").if_empty("?")
        ),
        String::new(),
    )
}

fn prowlarr_tags(event: &str, severity: &str, cfg: &RuntimeConfig) -> Vec<String> {
    let mut tags = vec![cfg.tag_prefix(severity), severity.into(), "prowlarr".into()];
    if event == "Health" {
        tags.push("health".into());
    } else if event == "ApplicationUpdate" {
        tags.push("update".into());
    } else if event == "Test" {
        tags.push("test".into());
    }
    tags
}

fn prowlarr_actions(message: &ProwlarrMessage) -> Vec<super::super::Action> {
    let mut actions = vec![action("view", "Open Prowlarr", &message.app_url)];
    if !message.wiki.is_empty() {
        actions.push(action("view", "Wiki", &message.wiki));
    }
    actions
}

pub fn prowlarr_severity(payload: &Value, fallback: &str) -> String {
    let event = json_get_str(payload, "eventType");
    let health = payload.get("health").unwrap_or(&Value::Null);
    let health_type = json_get_str(health, "type").to_ascii_lowercase();
    if event == "Health" {
        if health_type == "warning" {
            return "warning".into();
        }
        if matches!(health_type.as_str(), "error" | "critical") {
            return "critical".into();
        }
    } else if matches!(event, "HealthRestored" | "Test" | "ApplicationUpdate") {
        return "info".into();
    }
    fallback.to_string()
}
