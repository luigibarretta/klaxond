mod decypharr;
mod prowlarr;
mod wud;

pub use decypharr::{decypharr_severity, parse_decypharr_payload};
pub use prowlarr::{parse_prowlarr_payload, prowlarr_severity};
pub use wud::parse_wud_payload;

use super::{EmptyStrExt, Parts, action, scalar_to_string};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use serde_json::Value;

const GITHUB_COMMENT_BODY_LIMIT: usize = 4_000;

fn bounded_text(value: &str, max_chars: usize) -> String {
    let mut text = value.chars().take(max_chars + 1).collect::<String>();
    if text.chars().count() > max_chars {
        text = text.chars().take(max_chars).collect::<String>();
        text.push_str("\n…");
    }
    text
}

pub fn parse_github_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let repository = json_get_str(payload, "repository").trim();
    let issue_number = payload
        .get("issue_number")
        .map(scalar_to_string)
        .unwrap_or_default();
    let actor = json_get_str(payload, "comment_author").trim();
    let issue_title = bounded_text(json_get_str(payload, "issue_title").trim(), 240);
    let comment_body = bounded_text(
        json_get_str(payload, "comment_body").trim(),
        GITHUB_COMMENT_BODY_LIMIT,
    );
    let target = json_get_str(payload, "comment_url")
        .trim()
        .if_empty(json_get_str(payload, "issue_url").trim());

    let issue_ref = match (repository.is_empty(), issue_number.is_empty()) {
        (false, false) => format!("{repository}#{issue_number}"),
        (false, true) => repository.to_string(),
        _ => "issue".into(),
    };
    let actor_text = if actor.is_empty() {
        "new reply".into()
    } else {
        format!("reply from {actor}")
    };
    let body = match (issue_title.is_empty(), comment_body.is_empty()) {
        (false, false) => format!("{issue_title}\n\n{comment_body}"),
        (false, true) => issue_title,
        (true, false) => comment_body,
        (true, true) => "A GitHub issue received a new reply.".into(),
    };
    let actions = if target.is_empty() {
        Vec::new()
    } else {
        vec![action("view", "Open reply", target)]
    };

    Parts {
        title: format!("{} GitHub: {issue_ref} — {actor_text}", cfg.icon(severity)),
        body,
        tags: vec![
            cfg.tag_prefix(severity),
            severity.into(),
            "github".into(),
            "speech_balloon".into(),
            "github-analysis-enqueued".into(),
        ],
        actions,
        priority: cfg.priority(severity),
        alertname: "github-issue-comment".into(),
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

pub fn parse_authentik_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let title_raw = json_get_str(payload, "title").if_empty("Authentik notification");
    let body_raw = json_get_str(payload, "message").to_string();
    let mut tags = payload
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(scalar_to_string).collect::<Vec<_>>())
        .unwrap_or_default();
    let sev_tag = cfg.tag_prefix(severity);
    if !tags.contains(&sev_tag) {
        tags.insert(0, sev_tag);
    }
    if !tags.iter().any(|t| t == "authentik") {
        tags.push("authentik".into());
    }
    let mut actions = Vec::new();
    if !json_get_str(payload, "click").is_empty() {
        actions.push(action(
            "view",
            "Open Authentik",
            json_get_str(payload, "click"),
        ));
    }
    if let Some(arr) = payload.get("actions").and_then(|v| v.as_array()) {
        for a in arr.iter().take(3) {
            if !json_get_str(a, "url").is_empty() && !json_get_str(a, "label").is_empty() {
                actions.push(action(
                    "view",
                    json_get_str(a, "label"),
                    json_get_str(a, "url"),
                ));
            }
        }
    }
    actions.truncate(3);
    Parts {
        title: format!("{} Authentik: {title_raw}", cfg.icon(severity)),
        body: body_raw,
        tags,
        actions,
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

pub fn parse_shelfmark_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let title_raw = json_get_str(payload, "title").if_empty("Shelfmark notification");
    let body_raw = json_get_str(payload, "message").to_string();
    let mut tags = vec![
        cfg.tag_prefix(severity),
        severity.into(),
        "shelfmark".into(),
        "book".into(),
    ];
    let sev_tag = cfg.tag_prefix(severity);
    if !tags.contains(&sev_tag) {
        tags.insert(0, sev_tag);
    }
    Parts {
        title: format!("{} Shelfmark: {title_raw}", cfg.icon(severity)),
        body: body_raw,
        tags,
        actions: cfg
            .source_url("shelfmark")
            .map(|url| vec![action("view", "Open Shelfmark", url)])
            .unwrap_or_default(),
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

pub fn shelfmark_severity(payload: &Value, fallback: &str, cfg: &RuntimeConfig) -> String {
    let mapped = match json_get_str(payload, "type").to_ascii_lowercase().as_str() {
        "info" | "success" => Some("info"),
        "warning" => Some("warning"),
        "failure" => Some("critical"),
        _ => None,
    };
    mapped
        .filter(|s| cfg.known_severities().iter().any(|k| k == *s))
        .unwrap_or(fallback)
        .to_string()
}
