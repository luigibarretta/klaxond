use super::{EmptyStrExt, EmptyStringExt, Parts, action, first_non_empty, scalar_to_string};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use serde_json::Value;

pub fn parse_beszel_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let alert = beszel_alert(payload);
    let is_resolved = beszel_is_resolved(payload);
    Parts {
        title: beszel_title(payload, severity, cfg, &alert, is_resolved),
        body: beszel_body(payload, &alert, is_resolved),
        tags: source_tags("beszel", severity, cfg, is_resolved),
        actions: beszel_actions(payload, cfg),
        priority: source_priority(severity, cfg, is_resolved),
        alertname: alert,
        skip_snooze: is_resolved,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}

pub fn parse_healthchecks_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let check = healthcheck_name(payload);
    let is_resolved = healthcheck_is_resolved(payload);
    Parts {
        title: healthcheck_title(&check, severity, cfg, is_resolved),
        body: healthcheck_body(payload, is_resolved),
        tags: source_tags("healthchecks", severity, cfg, is_resolved),
        actions: healthcheck_actions(payload, cfg),
        priority: source_priority(severity, cfg, is_resolved),
        alertname: check,
        skip_snooze: is_resolved,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}

fn beszel_alert(payload: &Value) -> String {
    first_non_empty(&[
        json_get_str(payload, "alert"),
        json_get_str(payload, "name"),
    ])
    .if_empty("Beszel alert")
    .to_string()
}

fn beszel_is_resolved(payload: &Value) -> bool {
    let status = json_get_str(payload, "status")
        .if_empty("triggered")
        .to_ascii_lowercase();
    matches!(status.as_str(), "resolved" | "ok" | "back to normal")
}

fn beszel_title(
    payload: &Value,
    severity: &str,
    cfg: &RuntimeConfig,
    alert: &str,
    is_resolved: bool,
) -> String {
    let emoji = source_icon(severity, cfg, is_resolved);
    let system = first_non_empty(&[
        json_get_str(payload, "system"),
        json_get_str(payload, "host"),
    ]);
    let mut title = format!("{emoji} Beszel: {alert}");
    if !system.is_empty() {
        title.push_str(&format!(" — {system}"));
    }
    title
}

fn beszel_body(payload: &Value, alert: &str, is_resolved: bool) -> String {
    let mut body_parts = Vec::new();
    if is_resolved {
        body_parts.push("Status: RESOLVED".into());
    }
    let value = payload
        .get("value")
        .map(scalar_to_string)
        .unwrap_or_default();
    let threshold = payload
        .get("threshold")
        .map(scalar_to_string)
        .unwrap_or_default();
    if !value.is_empty() && !threshold.is_empty() {
        body_parts.push(format!("value={value} (threshold={threshold})"));
    } else if !value.is_empty() {
        body_parts.push(format!("value={value}"));
    }
    if body_parts.is_empty() {
        alert.to_string()
    } else {
        body_parts.join("\n")
    }
}

fn beszel_actions(payload: &Value, cfg: &RuntimeConfig) -> Vec<super::Action> {
    let mut actions = Vec::new();
    if let Some(rb) = cfg
        .fallback_runbooks
        .get("beszel")
        .filter(|s| !s.is_empty())
    {
        actions.push(action("view", "📖 Runbook", rb));
    }
    actions.push(action("view", "📊 Beszel UI", json_get_str(payload, "url")));
    actions
}

fn healthcheck_name(payload: &Value) -> String {
    first_non_empty(&[
        json_get_str(payload, "check"),
        json_get_str(payload, "name"),
    ])
    .if_empty("healthcheck")
    .to_string()
}

fn healthcheck_is_resolved(payload: &Value) -> bool {
    let status = json_get_str(payload, "status")
        .if_empty("down")
        .to_ascii_lowercase();
    matches!(status.as_str(), "up" | "ok" | "resolved")
}

fn healthcheck_title(
    check: &str,
    severity: &str,
    cfg: &RuntimeConfig,
    is_resolved: bool,
) -> String {
    let state_word = if is_resolved { "UP" } else { "DOWN" };
    format!(
        "{} HC {state_word}: {check}",
        source_icon(severity, cfg, is_resolved)
    )
}

fn healthcheck_body(payload: &Value, is_resolved: bool) -> String {
    let state_word = if is_resolved { "RESOLVED" } else { "DOWN" };
    let mut body_parts = vec![format!("Status: {state_word}")];
    for (label, key) in [
        ("Last ping", "last_ping"),
        ("Observed at", "observed_at"),
        ("Code", "code"),
        ("Tags", "tags"),
    ] {
        let value = payload.get(key).map(scalar_to_string).unwrap_or_default();
        if !value.is_empty() {
            body_parts.push(format!("{label}: {value}"));
        }
    }
    body_parts.join("\n")
}

fn healthcheck_actions(payload: &Value, cfg: &RuntimeConfig) -> Vec<super::Action> {
    let mut actions = Vec::new();
    let runbook = json_get_str(payload, "runbook_url")
        .to_string()
        .if_empty_else(|| {
            cfg.fallback_runbooks
                .get("healthchecks")
                .cloned()
                .unwrap_or_default()
        });
    if !runbook.is_empty() {
        actions.push(action("view", "📖 Runbook", &runbook));
    }
    if let Some(open) = healthcheck_open_action(payload, cfg) {
        actions.push(open);
    }
    actions
}

fn healthcheck_open_action(payload: &Value, cfg: &RuntimeConfig) -> Option<super::Action> {
    let url = json_get_str(payload, "url");
    if !url.is_empty() {
        return Some(action("view", "📊 Open in HC", url));
    }
    cfg.source_url("healthchecks")
        .map(|url| action("view", "📊 Open Healthchecks", url))
}

fn source_icon(severity: &str, cfg: &RuntimeConfig, is_resolved: bool) -> String {
    if is_resolved {
        cfg.icon("resolved")
    } else {
        cfg.icon(severity)
    }
}

fn source_tags(
    source: &str,
    severity: &str,
    cfg: &RuntimeConfig,
    is_resolved: bool,
) -> Vec<String> {
    if is_resolved {
        vec![cfg.tag_prefix("resolved"), source.into()]
    } else {
        vec![cfg.tag_prefix(severity), severity.into(), source.into()]
    }
}

fn source_priority(severity: &str, cfg: &RuntimeConfig, is_resolved: bool) -> String {
    if is_resolved {
        "low".into()
    } else {
        cfg.priority(severity)
    }
}

pub fn parse_pve_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let title_raw = json_get_str(payload, "title")
        .if_empty("Proxmox notification")
        .trim()
        .to_string();
    let message = json_get_str(payload, "message").trim().to_string();
    let node = json_get_str(payload, "node")
        .if_empty("pve")
        .trim()
        .to_string();
    let pve_sev = json_get_str(payload, "severity").to_ascii_lowercase();
    let ntype = json_get_str(payload, "type").trim().to_string();
    let mut body_parts = Vec::new();
    if !ntype.is_empty() {
        body_parts.push(format!("Type: {ntype}"));
    }
    if !pve_sev.is_empty() && pve_sev != severity {
        body_parts.push(format!("PVE severity: {pve_sev}"));
    }
    if !message.is_empty() {
        body_parts.push(if message.len() <= 1500 {
            message
        } else {
            format!("{} …[troncato]", &message[..1500])
        });
    }
    let mut actions = Vec::new();
    if let Some(rb) = cfg.fallback_runbooks.get("pve").filter(|s| !s.is_empty()) {
        actions.push(action("view", "📖 Runbook", rb));
    }
    if let Some(url) = cfg.source_url("pve") {
        actions.push(action("view", "🖥 Open Proxmox", url));
    }
    Parts {
        title: format!("{} PVE {node}: {title_raw}", cfg.icon(severity)),
        body: if body_parts.is_empty() {
            title_raw
        } else {
            body_parts.join("\n")
        },
        tags: vec![cfg.tag_prefix(severity), severity.into(), "pve".into()],
        actions,
        priority: cfg.priority(severity),
        alertname: if ntype.is_empty() {
            "pve-notification".into()
        } else {
            format!("pve-{ntype}")
        },
        skip_snooze: false,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}
