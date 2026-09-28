use super::Labels;
use crate::parsers::{EmptyStrExt, first_non_empty, scalar_to_string};
use crate::util::json_get_str;
use serde_json::Value;

pub(super) fn normalize_shelfmark_labels(payload: &Value, out: &mut Labels) {
    let event = first_non_empty(&[
        json_get_str(payload, "event"),
        json_get_str(payload, "type"),
    ]);
    out.insert("alertname".into(), source_alertname("shelfmark", &event));
    let user = payload
        .get("user")
        .map(scalar_to_string)
        .or_else(|| {
            payload
                .get("data")
                .and_then(|data| data.get("user"))
                .map(scalar_to_string)
        })
        .unwrap_or_default();
    if !user.is_empty() {
        out.insert("host".into(), user);
    }
    out.insert("job".into(), "shelfmark".into());
}

pub(super) fn normalize_prowlarr_labels(payload: &Value, out: &mut Labels) {
    let event = json_get_str(payload, "eventType").trim();
    out.insert("alertname".into(), source_alertname("prowlarr", event));
    out.insert(
        "host".into(),
        json_get_str(payload, "instanceName")
            .if_empty("prowlarr")
            .to_string(),
    );
    out.insert("job".into(), "prowlarr".into());
}

pub(super) fn normalize_decypharr_labels(payload: &Value, out: &mut Labels) {
    let event = json_get_str(payload, "event").trim();
    out.insert("alertname".into(), source_alertname("decypharr", event));
    out.insert(
        "host".into(),
        json_get_str(payload, "debrid")
            .if_empty("decypharr")
            .to_string(),
    );
    out.insert("job".into(), "decypharr".into());
}

pub(super) fn normalize_pve_labels(payload: &Value, out: &mut Labels) {
    out.insert(
        "host".into(),
        json_get_str(payload, "node").if_empty("pve").to_string(),
    );
    let kind = json_get_str(payload, "type");
    out.insert(
        "alertname".into(),
        if kind.is_empty() {
            "pve-notification".into()
        } else {
            format!("pve-{kind}")
        },
    );
    out.insert("service".into(), kind.to_string());
    out.insert("job".into(), "pve".into());
}

pub(super) fn normalize_github_labels(payload: &Value, out: &mut Labels) {
    let repository = json_get_str(payload, "repository").trim();
    if !repository.is_empty() {
        out.insert("repository".into(), repository.into());
    }
    let issue_number = payload
        .get("issue_number")
        .map(scalar_to_string)
        .unwrap_or_default();
    if !issue_number.is_empty() {
        out.insert("issue_number".into(), issue_number);
    }
    let actor = json_get_str(payload, "comment_author").trim();
    if !actor.is_empty() {
        out.insert("actor".into(), actor.into());
    }
    out.insert("alertname".into(), "github-issue-comment".into());
    out.insert("job".into(), "github".into());
}

pub(super) fn normalize_revaulter_labels(payload: &Value, out: &mut Labels) {
    let host = json_get_str(payload, "host").trim();
    if !host.is_empty() {
        out.insert("host".into(), host.into());
    }
    let event = json_get_str(payload, "event").trim();
    if !event.is_empty() {
        out.insert("event".into(), event.into());
    }
    out.insert("alertname".into(), "revaulter-approval-required".into());
    out.insert("job".into(), "revaulter".into());
}

fn source_alertname(source: &str, event: &str) -> String {
    if event.is_empty() {
        source.into()
    } else {
        format!("{source}-{event}")
    }
}
