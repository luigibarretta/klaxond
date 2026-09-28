use super::{EmptyStrExt, first_non_empty, scalar_to_string};
use crate::util::json_get_str;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

mod integrations;

use self::integrations::{
    normalize_decypharr_labels, normalize_github_labels, normalize_prowlarr_labels,
    normalize_pve_labels, normalize_revaulter_labels, normalize_shelfmark_labels,
};

pub(super) type Labels = HashMap<String, String>;

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
        "revaulter" => normalize_revaulter_labels(payload, &mut out),
        _ => normalize_generic_labels(payload, &mut out),
    }
    out
}

fn normalize_generic_labels(payload: &Value, out: &mut Labels) {
    if let Some(labels) = payload.get("labels").and_then(Value::as_object) {
        for (key, value) in labels {
            out.insert(key.to_ascii_lowercase(), scalar_to_string(value));
        }
    }
    for key in ["alertname", "host", "service", "component", "job"] {
        if let Some(value) = payload.get(key).map(scalar_to_string)
            && !value.trim().is_empty()
        {
            out.insert(key.to_string(), value);
        }
    }
    if !out.contains_key("alertname") {
        for key in ["title", "alert", "name"] {
            if let Some(value) = payload.get(key).map(scalar_to_string)
                && !value.trim().is_empty()
            {
                out.insert("alertname".into(), value);
                break;
            }
        }
    }
    if payload
        .get("status")
        .map(scalar_to_string)
        .is_some_and(|status| {
            matches!(
                status.trim().to_ascii_lowercase().as_str(),
                "resolved" | "ok" | "closed" | "recovered"
            )
        })
    {
        out.insert("status".into(), "resolved".into());
    }
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
        out.insert("alertname".into(), check.clone());
    }
    let code = payload
        .get("code")
        .map(scalar_to_string)
        .unwrap_or_default();
    let incident_identity = if code.trim().is_empty() {
        &check
    } else {
        &code
    };
    if !incident_identity.trim().is_empty() {
        // Healthchecks sends DOWN and UP through different severity endpoints.
        // Bind both callbacks to a digest of the immutable check code when
        // available (or the check name for portable payloads) so recovery
        // neither stores the ping credential nor depends on mutable labels.
        out.insert(
            "__klaxond_incident_key".into(),
            format!(
                "healthchecks-check:{}",
                hex::encode(Sha256::digest(
                    incident_identity.trim().to_ascii_lowercase().as_bytes()
                ))
            ),
        );
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

fn is_resolved_status(payload: &Value, values: &[&str]) -> bool {
    let status = json_get_str(payload, "status").to_ascii_lowercase();
    values.iter().any(|value| status == *value)
}
