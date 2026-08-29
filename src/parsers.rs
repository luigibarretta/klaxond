use crate::config::RuntimeConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type Action = [String; 3];

mod core_sources;
mod grafana;
mod integrations;
mod labels;
mod uptime_kuma;

pub use core_sources::{parse_beszel_payload, parse_healthchecks_payload, parse_pve_payload};
pub use grafana::parse_grafana_payload;
pub use integrations::{
    decypharr_severity, parse_authentik_payload, parse_decypharr_payload, parse_prowlarr_payload,
    parse_shelfmark_payload, parse_wud_payload, prowlarr_severity, shelfmark_severity,
};
pub use labels::normalize_labels;
pub use uptime_kuma::parse_uptime_kuma_payload;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Parts {
    pub title: String,
    pub body: String,
    pub tags: Vec<String>,
    pub actions: Vec<Action>,
    pub priority: String,
    #[serde(default)]
    pub alertname: String,
    #[serde(default)]
    pub skip_snooze: bool,
    #[serde(default)]
    pub render_slug: Option<String>,
    #[serde(default)]
    pub render_panel: Option<u64>,
    #[serde(default)]
    pub render_instance: String,
    #[serde(default)]
    pub attach_url: Option<String>,
    #[serde(default)]
    pub ntfy_sequence_id: Option<String>,
    #[serde(default)]
    pub emergency_ack_url: Option<String>,
    #[serde(default)]
    pub emergency_ack_token: Option<String>,
}

impl Parts {
    pub fn public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "title": self.title,
            "body": self.body,
            "tags": self.tags,
            "actions": self.actions,
            "priority": self.priority,
        })
    }
}

pub fn action(kind: &str, label: &str, target: &str) -> Action {
    [kind.to_string(), label.to_string(), target.to_string()]
}

pub fn parse_source(
    source: &str,
    payload: &Value,
    severity: &str,
    cfg: &RuntimeConfig,
) -> (String, Parts) {
    match source {
        "grafana" | "blackstart" => (
            severity.to_string(),
            parse_grafana_payload(payload, severity, cfg),
        ),
        "beszel" => (
            severity.to_string(),
            parse_beszel_payload(payload, severity, cfg),
        ),
        "healthchecks" => (
            severity.to_string(),
            parse_healthchecks_payload(payload, severity, cfg),
        ),
        "uptime-kuma" => parse_uptime_kuma_payload(payload, severity, cfg),
        "wud" => (
            severity.to_string(),
            parse_wud_payload(payload, severity, cfg),
        ),
        "authentik" => {
            let sev = payload
                .get("data")
                .and_then(|d| d.get("severity"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| cfg.known_severities().contains(s))
                .unwrap_or_else(|| severity.to_string());
            (sev.clone(), parse_authentik_payload(payload, &sev, cfg))
        }
        "shelfmark" => {
            let sev = shelfmark_severity(payload, severity, cfg);
            (sev.clone(), parse_shelfmark_payload(payload, &sev, cfg))
        }
        "prowlarr" => {
            let sev = prowlarr_severity(payload, severity);
            (sev.clone(), parse_prowlarr_payload(payload, &sev, cfg))
        }
        "decypharr" => {
            let sev = decypharr_severity(payload, severity, cfg);
            (sev.clone(), parse_decypharr_payload(payload, &sev, cfg))
        }
        "pve" => (
            severity.to_string(),
            parse_pve_payload(payload, severity, cfg),
        ),
        _ => (
            severity.to_string(),
            parse_beszel_payload(payload, severity, cfg),
        ),
    }
}

pub fn scalar_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        _ => v.to_string(),
    }
}

pub fn first_non_empty(values: &[&str]) -> String {
    values
        .iter()
        .find(|s| !s.is_empty())
        .copied()
        .unwrap_or("")
        .to_string()
}

trait EmptyStrExt {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str;
}

impl EmptyStrExt for str {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.is_empty() { fallback } else { self }
    }
}

trait EmptyStringExt {
    fn if_empty_else<F: FnOnce() -> String>(self, f: F) -> String;
}

impl EmptyStringExt for String {
    fn if_empty_else<F: FnOnce() -> String>(self, f: F) -> String {
        if self.is_empty() { f() } else { self }
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}
