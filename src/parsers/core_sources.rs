use super::{EmptyStrExt, EmptyStringExt, Parts, action, first_non_empty, scalar_to_string};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use serde_json::Value;

pub fn parse_beszel_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let alert = first_non_empty(&[
        json_get_str(payload, "alert"),
        json_get_str(payload, "name"),
    ])
    .if_empty("Beszel alert")
    .to_string();
    let system = first_non_empty(&[
        json_get_str(payload, "system"),
        json_get_str(payload, "host"),
    ]);
    let value = payload
        .get("value")
        .map(scalar_to_string)
        .unwrap_or_default();
    let threshold = payload
        .get("threshold")
        .map(scalar_to_string)
        .unwrap_or_default();
    let status = json_get_str(payload, "status")
        .if_empty("triggered")
        .to_ascii_lowercase();
    let is_resolved = matches!(status.as_str(), "resolved" | "ok" | "back to normal");
    let emoji = if is_resolved {
        cfg.icon("resolved")
    } else {
        cfg.icon(severity)
    };
    let mut title = format!("{emoji} Beszel: {alert}");
    if !system.is_empty() {
        title.push_str(&format!(" — {system}"));
    }
    let mut body_parts = Vec::new();
    if is_resolved {
        body_parts.push("Status: RESOLVED".into());
    }
    if !value.is_empty() && !threshold.is_empty() {
        body_parts.push(format!("value={value} (threshold={threshold})"));
    } else if !value.is_empty() {
        body_parts.push(format!("value={value}"));
    }
    let mut actions = Vec::new();
    if let Some(rb) = cfg
        .fallback_runbooks
        .get("beszel")
        .filter(|s| !s.is_empty())
    {
        actions.push(action("view", "📖 Runbook", rb));
    }
    actions.push(action("view", "📊 Beszel UI", json_get_str(payload, "url")));
    Parts {
        title,
        body: if body_parts.is_empty() {
            alert.clone()
        } else {
            body_parts.join("\n")
        },
        tags: if is_resolved {
            vec![cfg.tag_prefix("resolved"), "beszel".into()]
        } else {
            vec![cfg.tag_prefix(severity), severity.into(), "beszel".into()]
        },
        actions,
        priority: if is_resolved {
            "low".into()
        } else {
            cfg.priority(severity)
        },
        alertname: alert,
        skip_snooze: is_resolved,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

pub fn parse_healthchecks_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let check = first_non_empty(&[
        json_get_str(payload, "check"),
        json_get_str(payload, "name"),
    ])
    .if_empty("healthcheck")
    .to_string();
    let status = json_get_str(payload, "status")
        .if_empty("down")
        .to_ascii_lowercase();
    let is_resolved = matches!(status.as_str(), "up" | "ok" | "resolved");
    let emoji = if is_resolved {
        cfg.icon("resolved")
    } else {
        cfg.icon(severity)
    };
    let state_word_title = if is_resolved { "UP" } else { "DOWN" };
    let state_word_body = if is_resolved { "RESOLVED" } else { "DOWN" };
    let mut body_parts = vec![format!("Status: {state_word_body}")];
    for (label, key) in [
        ("Last ping", "last_ping"),
        ("Code", "code"),
        ("Tags", "tags"),
    ] {
        let v = payload.get(key).map(scalar_to_string).unwrap_or_default();
        if !v.is_empty() {
            body_parts.push(format!("{label}: {v}"));
        }
    }
    let mut actions = Vec::new();
    let rb = json_get_str(payload, "runbook_url")
        .to_string()
        .if_empty_else(|| {
            cfg.fallback_runbooks
                .get("healthchecks")
                .cloned()
                .unwrap_or_default()
        });
    if !rb.is_empty() {
        actions.push(action("view", "📖 Runbook", &rb));
    }
    let url = json_get_str(payload, "url");
    if url.is_empty() {
        actions.push(action(
            "view",
            "📊 Open Healthchecks",
            "https://hc.luigibarretta.com/projects/",
        ));
    } else {
        actions.push(action("view", "📊 Open in HC", url));
    }
    Parts {
        title: format!("{emoji} HC {state_word_title}: {check}"),
        body: body_parts.join("\n"),
        tags: if is_resolved {
            vec![cfg.tag_prefix("resolved"), "healthchecks".into()]
        } else {
            vec![
                cfg.tag_prefix(severity),
                severity.into(),
                "healthchecks".into(),
            ]
        },
        actions,
        priority: if is_resolved {
            "low".into()
        } else {
            cfg.priority(severity)
        },
        alertname: check,
        skip_snooze: is_resolved,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
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
    actions.push(action(
        "view",
        "🖥 Open Proxmox",
        "https://proxmox.luigibarretta.com/",
    ));
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
    }
}
