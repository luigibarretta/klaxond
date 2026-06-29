use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use regex::Regex;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

pub type Action = [String; 3];

static SHORT_HOST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(it1-prd-)?[a-z]+-\d+$").unwrap());
static HOST_IN_TEXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(it1-prd-[a-z]+-\d+|[a-z]+-\d+)\b").unwrap());

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

pub fn parse_source(
    source: &str,
    payload: &Value,
    severity: &str,
    cfg: &RuntimeConfig,
) -> (String, Parts) {
    match source {
        "grafana" => (
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

pub fn parse_grafana_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let status = json_get_str(payload, "status").if_empty("firing");
    let common_labels = payload.get("commonLabels").and_then(|v| v.as_object());
    let common_annot = payload.get("commonAnnotations").and_then(|v| v.as_object());
    let alertname_raw = object_scalar_cow(common_labels, "alertname");
    let alertname = if alertname_raw.is_empty() {
        "Grafana alert".to_string()
    } else {
        alertname_raw.into_owned()
    };
    let component = object_scalar_cow(common_labels, "component").into_owned();
    let host_label = object_scalar_cow(common_labels, "host");
    let instance_label = object_scalar_cow(common_labels, "instance");
    let summary = object_scalar_cow(common_annot, "summary");
    let mut host = first_non_empty(&[host_label.as_ref(), instance_label.as_ref()]);
    if host.is_empty() && SHORT_HOST_RE.is_match(&component) {
        host = if component.starts_with("it1-prd-") {
            component.clone()
        } else {
            format!("it1-prd-{component}")
        };
    }
    if host.is_empty() {
        let hay = format!("{} {}", alertname, summary);
        if let Some(caps) = HOST_IN_TEXT_RE.captures(&hay) {
            let h = caps.get(1).unwrap().as_str();
            host = if h.starts_with("it1-prd-") {
                h.to_string()
            } else {
                format!("it1-prd-{h}")
            };
        }
    }
    let state_emoji = if status == "resolved" {
        cfg.icon("resolved")
    } else {
        cfg.icon(severity)
    };
    let mut title = format!("{state_emoji} Grafana: {alertname}");
    if !host.is_empty() {
        title.push_str(&format!(" — {host}"));
    }

    let description = object_scalar_cow(common_annot, "description");
    let mut body_parts = Vec::new();
    if status == "resolved" {
        body_parts.push("Status: RESOLVED".to_string());
    }
    if !summary.is_empty() {
        body_parts.push(summary.to_string());
    }
    if !description.is_empty() && description.as_ref() != summary.as_ref() {
        body_parts.push(description.into_owned());
    }
    let mut affected = Vec::new();
    if let Some(alerts) = payload.get("alerts").and_then(|v| v.as_array()) {
        for a in alerts.iter().take(5) {
            if let Some(lbls) = a.get("labels").and_then(|v| v.as_object()) {
                let h = lbls
                    .get("host")
                    .or_else(|| lbls.get("instance"))
                    .or_else(|| lbls.get("container_name"))
                    .map(scalar_to_string)
                    .unwrap_or_default();
                if !h.is_empty() && !affected.contains(&h) {
                    affected.push(h);
                }
            }
        }
    }
    if affected.len() > 1 || (!affected.is_empty() && affected[0] != host) {
        body_parts.push(format!("Affected: {}", affected.join(", ")));
    }
    let body = if body_parts.is_empty() {
        "(no body)".to_string()
    } else {
        body_parts.join("\n")
    };
    let mut body = body;
    if status != "resolved"
        && let Some(extra) = enrich_grafana_body(&alertname, &host, &body, cfg)
        && !extra.is_empty()
    {
        body.push_str(&extra);
    }

    let tags = if status == "resolved" {
        vec![
            cfg.tag_prefix("resolved"),
            "grafana".into(),
            component.if_empty("homelab").to_string(),
        ]
    } else {
        vec![
            cfg.tag_prefix(severity),
            severity.to_string(),
            "grafana".into(),
            component.if_empty("homelab").to_string(),
        ]
    };
    let mut actions = Vec::new();
    let runbook = object_scalar_cow(common_annot, "runbook_url");
    if !runbook.is_empty() {
        actions.push(action("view", "📖 Runbook", &runbook));
    }
    if let Some([label, slug]) = cfg.component_dashboards.get(&component) {
        actions.push(action(
            "view",
            &format!("📊 {label}"),
            &format!("{}{}", cfg.grafana_base, slug),
        ));
    }
    let rule_url = payload
        .get("alerts")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|a| a.get("generatorURL"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| json_get_str(payload, "externalURL").to_string());
    if !rule_url.is_empty() {
        actions.push(action("view", "View rule", &rule_url));
    }
    let mut render_slug = None;
    let mut render_panel = None;
    if let Some((uid, panel)) = cfg.component_image.get(&component) {
        render_slug = Some(format!("/d/{uid}"));
        render_panel = *panel;
    } else if let Some([_, slug]) = cfg.component_dashboards.get(&component) {
        render_slug = Some(slug.clone());
    }

    Parts {
        title,
        body,
        tags,
        actions,
        priority: if status == "resolved" {
            "low".into()
        } else {
            cfg.priority(severity)
        },
        alertname,
        skip_snooze: status == "resolved",
        render_slug,
        render_panel,
        render_instance: instance_label.into_owned(),
        attach_url: None,
    }
}

fn object_scalar_cow<'a>(
    object: Option<&'a serde_json::Map<String, Value>>,
    key: &str,
) -> Cow<'a, str> {
    match object.and_then(|m| m.get(key)) {
        Some(Value::String(s)) => Cow::Borrowed(s.as_str()),
        Some(v) => Cow::Owned(scalar_to_string(v)),
        None => Cow::Borrowed(""),
    }
}

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

pub fn parse_wud_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let (title_raw, body_raw, extras) = if let Some(arr) = payload.as_array() {
        let count = arr.len();
        let mut lines = Vec::new();
        for c in arr.iter().take(10) {
            let name = json_get_str(c, "name").if_empty("?");
            let uk = c.get("updateKind").unwrap_or(&Value::Null);
            let local = json_get_str(uk, "localValue").if_empty("?");
            let remote = json_get_str(uk, "remoteValue").if_empty("?");
            let kind = json_get_str(uk, "kind").if_empty("tag");
            let semv = json_get_str(uk, "semverDiff");
            let sv = if semv.is_empty() {
                String::new()
            } else {
                format!(" ({semv})")
            };
            lines.push(format!("• {name}: {kind} {local} ⇒ {remote}{sv}"));
        }
        if count > 10 {
            lines.push(format!("… +{} more", count - 10));
        }
        (
            format!(
                "{count} container update{} available",
                if count != 1 { "s" } else { "" }
            ),
            lines.join("\n"),
            Value::Null,
        )
    } else if payload.is_object()
        && payload.get("name").is_some()
        && payload.get("updateKind").is_some()
    {
        let name = json_get_str(payload, "name").if_empty("?");
        let watcher = json_get_str(payload, "watcher").if_empty("local");
        let uk = payload.get("updateKind").unwrap_or(&Value::Null);
        let local = json_get_str(uk, "localValue").if_empty("?");
        let remote = json_get_str(uk, "remoteValue").if_empty("?");
        let kind = json_get_str(uk, "kind").if_empty("tag");
        let semv = json_get_str(uk, "semverDiff");
        let sv = if semv.is_empty() {
            String::new()
        } else {
            format!(" ({semv})")
        };
        let link = payload
            .get("result")
            .and_then(|r| r.get("link"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut body = format!("{name}: {kind} {local} ⇒ {remote}{sv}");
        if !link.is_empty() {
            body.push('\n');
            body.push_str(link);
        }
        (
            format!("Update available for {name} on {watcher}"),
            body,
            payload.clone(),
        )
    } else {
        (
            json_get_str(payload, "title")
                .if_empty("Container update available")
                .to_string(),
            json_get_str(payload, "body")
                .if_empty("Container update detected — see WUD UI for details.")
                .to_string(),
            payload.clone(),
        )
    };
    let rb = json_get_str(&extras, "runbook_url")
        .to_string()
        .if_empty_else(|| {
            cfg.fallback_runbooks
                .get("wud")
                .cloned()
                .unwrap_or_default()
        });
    let mut actions = Vec::new();
    if !rb.is_empty() {
        actions.push(action("view", "📖 Runbook", &rb));
    }
    actions.push(action(
        "view",
        "📦 Open WUD",
        json_get_str(&extras, "wud_url").if_empty("http://192.168.50.110:3033/"),
    ));
    Parts {
        title: format!("{} WUD: {title_raw}", cfg.icon(severity)),
        body: body_raw,
        tags: vec![
            cfg.tag_prefix(severity),
            severity.into(),
            "package".into(),
            "wud".into(),
            "container-update".into(),
        ],
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
    }
}

pub fn parse_prowlarr_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let evt = json_get_str(payload, "eventType").if_empty("Unknown");
    let instance = json_get_str(payload, "instanceName").if_empty("Prowlarr");
    let app_url =
        json_get_str(payload, "applicationUrl").if_empty("https://prowlarr.luigibarretta.com");
    let health = payload.get("health").unwrap_or(&Value::Null);
    let health_message = first_non_empty(&[
        json_get_str(health, "message"),
        json_get_str(payload, "message"),
    ]);
    let health_wiki = first_non_empty(&[
        json_get_str(health, "wikiUrl"),
        json_get_str(payload, "wikiUrl"),
    ]);
    let (title_raw, body_raw, wiki) = match evt {
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
        "ApplicationUpdate" => (
            "Application updated".to_string(),
            format!(
                "{} {} → {}",
                instance,
                json_get_str(payload, "previousVersion").if_empty("?"),
                json_get_str(payload, "newVersion").if_empty("?")
            ),
            String::new(),
        ),
        "Test" => (
            "Test notification".to_string(),
            "Klaxond webhook test successful".to_string(),
            String::new(),
        ),
        _ => (
            evt.to_string(),
            json_get_str(payload, "message").to_string(),
            String::new(),
        ),
    };
    let mut tags = vec![cfg.tag_prefix(severity), severity.into(), "prowlarr".into()];
    if evt == "Health" {
        tags.push("health".into());
    } else if evt == "ApplicationUpdate" {
        tags.push("update".into());
    } else if evt == "Test" {
        tags.push("test".into());
    }
    let mut actions = vec![action("view", "Open Prowlarr", app_url)];
    if !wiki.is_empty() {
        actions.push(action("view", "Wiki", &wiki));
    }
    Parts {
        title: format!("{} Prowlarr: {title_raw}", cfg.icon(severity)),
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
        actions: vec![action(
            "view",
            "Open Shelfmark",
            "https://bookdl.luigibarretta.com",
        )],
        priority: cfg.priority(severity),
        alertname: String::new(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

pub fn parse_decypharr_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let event = json_get_str(payload, "event").trim().to_ascii_lowercase();
    let name = json_get_str(payload, "name")
        .if_empty("<unknown>")
        .trim()
        .to_string();
    let debrid = json_get_str(payload, "debrid").trim().to_string();
    let content_path = json_get_str(payload, "content_path").trim().to_string();
    let msg = json_get_str(payload, "message").trim().to_string();
    let event_human = match event.as_str() {
        "download_start" => "Download started".to_string(),
        "download_complete" => "Download completed".to_string(),
        "download_fail" | "download_failed" => "Download failed".to_string(),
        "download_error" => "Download error".to_string(),
        "" => "Event".to_string(),
        _ => capitalize(&event.replace('_', " ")),
    };
    let mut body = if !msg.is_empty() {
        msg
    } else {
        let mut bp = vec![format!("{event_human}: {name}")];
        if !content_path.is_empty() {
            bp.push(format!("-> {content_path}"));
        }
        bp.join("\n")
    };
    if !debrid.is_empty()
        && !body
            .to_ascii_lowercase()
            .contains(&debrid.to_ascii_lowercase())
    {
        body.push_str(&format!("\n[backend: {debrid}]"));
    }
    let mut tags = vec![
        cfg.tag_prefix(severity),
        severity.into(),
        "decypharr".into(),
        "download".into(),
    ];
    let sev_tag = cfg.tag_prefix(severity);
    if !tags.contains(&sev_tag) {
        tags.insert(0, sev_tag);
    }
    Parts {
        title: format!("{} Decypharr: {event_human}: {name}", cfg.icon(severity)),
        body,
        tags,
        actions: vec![action(
            "view",
            "Open Decypharr",
            "https://decypharr.luigibarretta.com",
        )],
        priority: cfg.priority(severity),
        alertname: String::new(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
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

pub fn prowlarr_severity(payload: &Value, fallback: &str) -> String {
    let evt = json_get_str(payload, "eventType");
    let health = payload.get("health").unwrap_or(&Value::Null);
    let ht = json_get_str(health, "type").to_ascii_lowercase();
    if evt == "Health" {
        if ht == "warning" {
            return "warning".into();
        }
        if matches!(ht.as_str(), "error" | "critical") {
            return "critical".into();
        }
    } else if matches!(evt, "HealthRestored" | "Test" | "ApplicationUpdate") {
        return "info".into();
    }
    fallback.to_string()
}

pub fn decypharr_severity(payload: &Value, fallback: &str, cfg: &RuntimeConfig) -> String {
    let mapped = match json_get_str(payload, "status")
        .to_ascii_lowercase()
        .as_str()
    {
        "success" => Some("info"),
        "failure" => Some("warning"),
        "error" => Some("critical"),
        _ => None,
    };
    mapped
        .filter(|s| cfg.known_severities().iter().any(|k| k == *s))
        .unwrap_or(fallback)
        .to_string()
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

fn enrich_grafana_body(
    alertname: &str,
    host: &str,
    body: &str,
    cfg: &RuntimeConfig,
) -> Option<String> {
    let haystack = format!("{alertname} {body}");
    let patterns = [
        (
            r"(swap|ram|memory).*(high|pressure|exhausted|used|usage|above|averaged|\d+(\.\d+)?\s*%)",
            "mem",
        ),
        (r"(cpu|load(avg)?|load[\s_-]aver)", "cpu"),
        (
            r"network.*(high|saturation|bandwidth|saturated|\d+(\.\d+)?\s*%)",
            "net",
        ),
        (
            r"(disk|filesystem|fs|root|/pool|/dev/sd).*(full|high|low|usage|above|\d+(\.\d+)?\s*%)",
            "disk",
        ),
        (
            r"(internet|wan|icmp|blackbox).*(latency|slow|saturat|degrad|p\d+|loss)",
            "wan",
        ),
    ];
    for (pattern, kind) in patterns {
        if Regex::new(pattern).ok()?.is_match(&haystack) {
            return match kind {
                "wan" => top_containers_global(cfg, "net", 5).map(|items| {
                    if items.is_empty() {
                        return String::new();
                    }
                    let mut lines = vec!["\nTop network consumers (cluster-wide):".to_string()];
                    for (h, name, val, unit) in items {
                        let h_short = h.replace("it1-prd-", "");
                        lines.push(format!("  • {name:20} @ {h_short:8} {val:>7.1}{unit}"));
                    }
                    lines.join("\n")
                }),
                "disk" => {
                    if host.is_empty() {
                        return Some(String::new());
                    }
                    top_filesystems(cfg, host, 5).map(|items| {
                        if items.is_empty() {
                            return String::new();
                        }
                        let mut lines = vec![format!("\nFilesystem usage ({host}):")];
                        for (name, used, total, pct) in items {
                            lines.push(format!(
                                "  • {name:15} {used:>7.1}G / {total:>7.1}G  ({pct:>5.1}%)"
                            ));
                        }
                        lines.join("\n")
                    })
                }
                _ => {
                    if host.is_empty() {
                        return Some(String::new());
                    }
                    top_containers(cfg, host, kind, 3).map(|items| {
                        if items.is_empty() {
                            return String::new();
                        }
                        let label = match kind {
                            "mem" => "RAM",
                            "cpu" => "CPU",
                            "net" => "network",
                            _ => kind,
                        };
                        let mut lines = vec![format!("\nTop {label} consumers ({host}):")];
                        for (name, val, unit) in items {
                            lines.push(format!("  • {name:25} {val:>7.1}{unit}"));
                        }
                        lines.join("\n")
                    })
                }
            };
        }
    }
    Some(String::new())
}

fn beszel_open(cfg: &RuntimeConfig) -> Option<Connection> {
    if !cfg.beszel_db.exists() {
        return None;
    }
    let uri = format!("file:{}?mode=ro&immutable=1", cfg.beszel_db.display());
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
}

fn beszel_system_id(conn: &Connection, host: &str) -> Option<i64> {
    conn.query_row(
        "SELECT id FROM systems WHERE name = ?1 OR name LIKE ?2 LIMIT 1",
        (host, format!("%{host}%")),
        |row| row.get::<_, i64>(0),
    )
    .ok()
}

fn top_containers(
    cfg: &RuntimeConfig,
    host: &str,
    by: &str,
    n: usize,
) -> Option<Vec<(String, f64, &'static str)>> {
    let conn = beszel_open(cfg)?;
    let system_id = beszel_system_id(&conn, host)?;
    let raw: String = conn
        .query_row(
            "SELECT stats FROM container_stats WHERE system = ?1 ORDER BY created DESC LIMIT 1",
            [system_id],
            |row| row.get(0),
        )
        .ok()?;
    let stats: Vec<Value> = serde_json::from_str(&raw).ok()?;
    let mut rows = Vec::new();
    for s in stats {
        let name = json_get_str(&s, "n").if_empty("?").to_string();
        match by {
            "net" => {
                let b = s
                    .get("b")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let tx = b.first().and_then(|v| v.as_f64()).unwrap_or(0.0);
                let rx = b.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0);
                rows.push((name, (tx + rx) / 1024.0, "kB/s"));
            }
            "mem" => rows.push((
                name,
                s.get("m").and_then(|v| v.as_f64()).unwrap_or(0.0),
                "MB",
            )),
            _ => rows.push((
                name,
                s.get("c").and_then(|v| v.as_f64()).unwrap_or(0.0),
                "%",
            )),
        }
    }
    rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    rows.truncate(n);
    Some(rows)
}

fn top_containers_global(
    cfg: &RuntimeConfig,
    by: &str,
    n: usize,
) -> Option<Vec<(String, String, f64, &'static str)>> {
    let conn = beszel_open(cfg)?;
    let mut systems_stmt = conn.prepare("SELECT id, name FROM systems").ok()?;
    let systems = systems_stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .ok()?
        .flatten()
        .collect::<Vec<_>>();
    let mut rows = Vec::new();
    for (system_id, host) in systems {
        let raw: String = match conn.query_row(
            "SELECT stats FROM container_stats WHERE system = ?1 ORDER BY created DESC LIMIT 1",
            [system_id],
            |row| row.get(0),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Ok(stats) = serde_json::from_str::<Vec<Value>>(&raw) else {
            continue;
        };
        for s in stats {
            let name = json_get_str(&s, "n").if_empty("?").to_string();
            if by == "net" {
                let b = s
                    .get("b")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let tx = b.first().and_then(|v| v.as_f64()).unwrap_or(0.0);
                let rx = b.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0);
                rows.push((host.clone(), name, (tx + rx) / 1024.0, "kB/s"));
            }
        }
    }
    rows.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    rows.truncate(n);
    Some(rows)
}

fn top_filesystems(
    cfg: &RuntimeConfig,
    host: &str,
    n: usize,
) -> Option<Vec<(String, f64, f64, f64)>> {
    let conn = beszel_open(cfg)?;
    let system_id = beszel_system_id(&conn, host)?;
    let raw: String = conn
        .query_row(
            "SELECT stats FROM system_stats WHERE system = ?1 ORDER BY created DESC LIMIT 1",
            [system_id],
            |row| row.get(0),
        )
        .ok()?;
    let stats: Value = serde_json::from_str(&raw).ok()?;
    let mut rows = Vec::new();
    if let (Some(d), Some(du)) = (
        stats.get("d").and_then(|v| v.as_f64()),
        stats.get("du").and_then(|v| v.as_f64()),
    ) {
        let pct = stats
            .get("dp")
            .and_then(|v| v.as_f64())
            .unwrap_or(if d > 0.0 { du / d * 100.0 } else { 0.0 });
        rows.push(("root".to_string(), du, d, pct));
    }
    if let Some(efs) = stats.get("efs").and_then(|v| v.as_object()) {
        for (name, fs) in efs {
            let d = fs.get("d").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let du = fs.get("du").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let pct = if d > 0.0 { du / d * 100.0 } else { 0.0 };
            rows.push((name.clone(), du, d, pct));
        }
    }
    rows.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
    rows.truncate(n);
    Some(rows)
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
