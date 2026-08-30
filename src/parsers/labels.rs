use super::{EmptyStrExt, first_non_empty, scalar_to_string};
use crate::util::json_get_str;
use serde_json::Value;
use std::collections::HashMap;

type Labels = HashMap<String, String>;

pub fn normalize_labels(source: &str, payload: &Value) -> Labels {
    let mut out = HashMap::from([
        ("source".to_string(), source.to_string()),
        ("status".to_string(), "firing".to_string()),
    ]);
    match source {
        "grafana" | "blackstart" => normalize_grafana_labels(payload, &mut out),
        "beszel" => normalize_beszel_labels(payload, &mut out),
        "healthchecks" => normalize_healthchecks_labels(payload, &mut out),
        "wud" => normalize_wud_labels(payload, &mut out),
        "authentik" => normalize_authentik_labels(payload, &mut out),
        "shelfmark" => normalize_shelfmark_labels(payload, &mut out),
        "prowlarr" => normalize_prowlarr_labels(payload, &mut out),
        "decypharr" => normalize_decypharr_labels(payload, &mut out),
        "pve" => normalize_pve_labels(payload, &mut out),
        "github" => normalize_github_labels(payload, &mut out),
        _ => {}
    }
    out
}

fn normalize_grafana_labels(payload: &Value, out: &mut Labels) {
    if let Some(common) = payload.get("commonLabels").and_then(|v| v.as_object()) {
        for (k, v) in common {
            out.insert(k.to_string(), scalar_to_string(v));
        }
    }
    if !out.contains_key("host")
        && let Some(instance) = out.get("instance").cloned()
    {
        out.insert("host".to_string(), instance);
    }
    out.insert(
        "status".to_string(),
        json_get_str(payload, "status")
            .if_empty("firing")
            .to_string(),
    );
}

fn normalize_beszel_labels(payload: &Value, out: &mut Labels) {
    let host = first_non_empty(&[
        json_get_str(payload, "system"),
        json_get_str(payload, "host"),
    ]);
    if !host.is_empty() {
        out.insert("host".into(), host);
    }
    let alert = first_non_empty(&[
        json_get_str(payload, "alert"),
        json_get_str(payload, "name"),
    ]);
    if !alert.is_empty() {
        out.insert("alertname".into(), alert);
    }
    if is_resolved_status(payload, &["resolved", "ok", "back to normal"]) {
        out.insert("status".into(), "resolved".into());
    }
    out.insert("job".into(), "beszel".into());
}

fn normalize_healthchecks_labels(payload: &Value, out: &mut Labels) {
    let check = payload
        .get("check")
        .map(scalar_to_string)
        .filter(|s| !s.is_empty())
        .or_else(|| payload.get("name").map(scalar_to_string))
        .unwrap_or_default();
    if !check.is_empty() {
        out.insert("alertname".into(), check);
    }
    if let Some(tags) = payload.get("tags").and_then(|v| v.as_str()) {
        for tok in tags.split_whitespace() {
            if let Some((k, v)) = tok.split_once('=') {
                let k = k.trim().to_ascii_lowercase();
                if matches!(k.as_str(), "host" | "service") && !v.is_empty() {
                    out.insert(k, v.to_string());
                }
            }
        }
    }
    if is_resolved_status(payload, &["up", "ok", "resolved"]) {
        out.insert("status".into(), "resolved".into());
    }
    out.insert("job".into(), "healthchecks".into());
}

fn normalize_wud_labels(payload: &Value, out: &mut Labels) {
    if let Some(obj) = payload.as_object() {
        let watcher = obj.get("watcher").map(scalar_to_string).unwrap_or_default();
        let host_value = obj.get("host").map(scalar_to_string).unwrap_or_default();
        let host = first_non_empty(&[watcher.as_str(), host_value.as_str()]);
        if !host.is_empty() {
            out.insert("host".into(), host);
        }
        if let Some(name) = obj
            .get("name")
            .map(scalar_to_string)
            .filter(|s| !s.is_empty())
        {
            out.insert("service".into(), name);
            out.insert("alertname".into(), "container-update".into());
        }
    } else if let Some(arr) = payload.as_array() {
        if let Some(first) = arr.first().and_then(|v| v.as_object()) {
            let host = first
                .get("watcher")
                .or_else(|| first.get("host"))
                .map(scalar_to_string)
                .unwrap_or_default();
            if !host.is_empty() {
                out.insert("host".into(), host);
            }
        }
        if !arr.is_empty() {
            out.insert("alertname".into(), "container-update-batch".into());
        }
    }
    out.insert("job".into(), "wud".into());
}

fn normalize_authentik_labels(payload: &Value, out: &mut Labels) {
    if let Some(data) = payload.get("data").and_then(|v| v.as_object()) {
        let host = data
            .get("host")
            .or_else(|| data.get("client_ip"))
            .map(scalar_to_string)
            .unwrap_or_default();
        if !host.is_empty() {
            out.insert("host".into(), host);
        }
    }
    out.insert("job".into(), "authentik".into());
}

fn normalize_shelfmark_labels(payload: &Value, out: &mut Labels) {
    let evt = first_non_empty(&[
        json_get_str(payload, "event"),
        json_get_str(payload, "type"),
    ]);
    out.insert(
        "alertname".into(),
        if evt.is_empty() {
            "shelfmark".into()
        } else {
            format!("shelfmark-{evt}")
        },
    );
    let user = payload
        .get("user")
        .map(scalar_to_string)
        .or_else(|| {
            payload
                .get("data")
                .and_then(|d| d.get("user"))
                .map(scalar_to_string)
        })
        .unwrap_or_default();
    if !user.is_empty() {
        out.insert("host".into(), user);
    }
    out.insert("job".into(), "shelfmark".into());
}

fn normalize_prowlarr_labels(payload: &Value, out: &mut Labels) {
    let evt = json_get_str(payload, "eventType").trim();
    out.insert("alertname".into(), source_alertname("prowlarr", evt));
    out.insert(
        "host".into(),
        json_get_str(payload, "instanceName")
            .if_empty("prowlarr")
            .to_string(),
    );
    out.insert("job".into(), "prowlarr".into());
}

fn normalize_decypharr_labels(payload: &Value, out: &mut Labels) {
    let evt = json_get_str(payload, "event").trim();
    out.insert("alertname".into(), source_alertname("decypharr", evt));
    out.insert(
        "host".into(),
        json_get_str(payload, "debrid")
            .if_empty("decypharr")
            .to_string(),
    );
    out.insert("job".into(), "decypharr".into());
}

fn normalize_pve_labels(payload: &Value, out: &mut Labels) {
    out.insert(
        "host".into(),
        json_get_str(payload, "node").if_empty("pve").to_string(),
    );
    let ntype = json_get_str(payload, "type");
    out.insert(
        "alertname".into(),
        if ntype.is_empty() {
            "pve-notification".into()
        } else {
            format!("pve-{ntype}")
        },
    );
    out.insert("service".into(), ntype.to_string());
    out.insert("job".into(), "pve".into());
}

fn normalize_github_labels(payload: &Value, out: &mut Labels) {
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

fn is_resolved_status(payload: &Value, values: &[&str]) -> bool {
    let status = json_get_str(payload, "status").to_ascii_lowercase();
    values.iter().any(|value| status == *value)
}

fn source_alertname(source: &str, event: &str) -> String {
    if event.is_empty() {
        source.into()
    } else {
        format!("{source}-{event}")
    }
}
