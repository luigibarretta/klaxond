use super::{EmptyStrExt, Parts, action, first_non_empty, scalar_to_string};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use regex::Regex;
use serde_json::Value;
use std::borrow::Cow;
use std::sync::LazyLock;

mod beszel;

use self::beszel::{top_containers, top_containers_global, top_filesystems};

static SHORT_HOST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(it1-prd-)?[a-z]+-\d+$").unwrap());
static HOST_IN_TEXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(it1-prd-[a-z]+-\d+|[a-z]+-\d+)\b").unwrap());

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
