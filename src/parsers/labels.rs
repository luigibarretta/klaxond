use super::{EmptyStrExt, first_non_empty, scalar_to_string};
use crate::util::json_get_str;
use serde_json::Value;
use std::collections::HashMap;

pub fn normalize_labels(source: &str, payload: &Value) -> HashMap<String, String> {
    let mut out = HashMap::from([
        ("source".to_string(), source.to_string()),
        ("status".to_string(), "firing".to_string()),
    ]);
    match source {
        "grafana" => {
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
        "beszel" => {
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
            if matches!(
                json_get_str(payload, "status")
                    .to_ascii_lowercase()
                    .as_str(),
                "resolved" | "ok" | "back to normal"
            ) {
                out.insert("status".into(), "resolved".into());
            }
            out.insert("job".into(), "beszel".into());
        }
        "healthchecks" => {
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
            if matches!(
                json_get_str(payload, "status")
                    .to_ascii_lowercase()
                    .as_str(),
                "up" | "ok" | "resolved"
            ) {
                out.insert("status".into(), "resolved".into());
            }
            out.insert("job".into(), "healthchecks".into());
        }
        "wud" => {
            if let Some(obj) = payload.as_object() {
                let host = first_non_empty(&[
                    obj.get("watcher")
                        .map(scalar_to_string)
                        .unwrap_or_default()
                        .as_str(),
                    obj.get("host")
                        .map(scalar_to_string)
                        .unwrap_or_default()
                        .as_str(),
                ]);
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
        "authentik" => {
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
        "shelfmark" => {
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
        "prowlarr" => {
            let evt = json_get_str(payload, "eventType").trim();
            out.insert(
                "alertname".into(),
                if evt.is_empty() {
                    "prowlarr".into()
                } else {
                    format!("prowlarr-{evt}")
                },
            );
            out.insert(
                "host".into(),
                json_get_str(payload, "instanceName")
                    .if_empty("prowlarr")
                    .to_string(),
            );
            out.insert("job".into(), "prowlarr".into());
        }
        "decypharr" => {
            let evt = json_get_str(payload, "event").trim();
            out.insert(
                "alertname".into(),
                if evt.is_empty() {
                    "decypharr".into()
                } else {
                    format!("decypharr-{evt}")
                },
            );
            out.insert(
                "host".into(),
                json_get_str(payload, "debrid")
                    .if_empty("decypharr")
                    .to_string(),
            );
            out.insert("job".into(), "decypharr".into());
        }
        "pve" => {
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
        _ => {}
    }
    out
}
