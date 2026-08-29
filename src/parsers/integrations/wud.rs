use super::super::{EmptyStrExt, EmptyStringExt, Parts, action};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use serde_json::Value;

struct WudPayloadParts {
    title: String,
    body: String,
    extras: Value,
}

pub fn parse_wud_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let parsed = parse_wud_message(payload);
    Parts {
        title: format!("{} WUD: {}", cfg.icon(severity), parsed.title),
        body: parsed.body,
        tags: vec![
            cfg.tag_prefix(severity),
            severity.into(),
            "package".into(),
            "wud".into(),
            "container-update".into(),
        ],
        actions: wud_actions(&parsed.extras, cfg),
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

fn parse_wud_message(payload: &Value) -> WudPayloadParts {
    if let Some(arr) = payload.as_array() {
        return parse_wud_batch(arr);
    }
    if payload.is_object() && payload.get("name").is_some() && payload.get("updateKind").is_some() {
        return parse_wud_single(payload);
    }
    parse_wud_fallback(payload)
}

fn parse_wud_batch(items: &[Value]) -> WudPayloadParts {
    let count = items.len();
    let mut lines = items
        .iter()
        .take(10)
        .map(wud_update_line)
        .collect::<Vec<_>>();
    if count > 10 {
        lines.push(format!("… +{} more", count - 10));
    }
    WudPayloadParts {
        title: format!(
            "{count} container update{} available",
            if count != 1 { "s" } else { "" }
        ),
        body: lines.join("\n"),
        extras: Value::Null,
    }
}

fn parse_wud_single(payload: &Value) -> WudPayloadParts {
    let name = json_get_str(payload, "name").if_empty("?");
    let watcher = json_get_str(payload, "watcher").if_empty("local");
    let mut body = wud_update_line(payload);
    if let Some(link) = wud_result_link(payload) {
        body.push('\n');
        body.push_str(link);
    }
    WudPayloadParts {
        title: format!("Update available for {name} on {watcher}"),
        body,
        extras: payload.clone(),
    }
}

fn parse_wud_fallback(payload: &Value) -> WudPayloadParts {
    WudPayloadParts {
        title: json_get_str(payload, "title")
            .if_empty("Container update available")
            .to_string(),
        body: json_get_str(payload, "body")
            .if_empty("Container update detected — see WUD UI for details.")
            .to_string(),
        extras: payload.clone(),
    }
}

fn wud_update_line(item: &Value) -> String {
    let name = json_get_str(item, "name").if_empty("?");
    let uk = item.get("updateKind").unwrap_or(&Value::Null);
    let local = json_get_str(uk, "localValue").if_empty("?");
    let remote = json_get_str(uk, "remoteValue").if_empty("?");
    let kind = json_get_str(uk, "kind").if_empty("tag");
    format!("• {name}: {kind} {local} ⇒ {remote}{}", semver_suffix(uk))
}

fn semver_suffix(update_kind: &Value) -> String {
    match json_get_str(update_kind, "semverDiff") {
        "" => String::new(),
        semv => format!(" ({semv})"),
    }
}

fn wud_result_link(payload: &Value) -> Option<&str> {
    payload
        .get("result")
        .and_then(|r| r.get("link"))
        .and_then(Value::as_str)
        .filter(|link| !link.is_empty())
}

fn wud_actions(extras: &Value, cfg: &RuntimeConfig) -> Vec<super::super::Action> {
    let mut actions = Vec::new();
    let runbook = json_get_str(extras, "runbook_url")
        .to_string()
        .if_empty_else(|| {
            cfg.fallback_runbooks
                .get("wud")
                .cloned()
                .unwrap_or_default()
        });
    if !runbook.is_empty() {
        actions.push(action("view", "📖 Runbook", &runbook));
    }
    let supplied_url = json_get_str(extras, "wud_url");
    let open_url = if supplied_url.is_empty() {
        cfg.source_url("wud").unwrap_or("")
    } else {
        supplied_url
    };
    if !open_url.is_empty() {
        actions.push(action("view", "📦 Open WUD", open_url));
    }
    actions
}
