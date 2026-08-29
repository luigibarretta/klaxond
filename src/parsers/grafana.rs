use super::{Action, EmptyStrExt, Parts, action, first_non_empty, scalar_to_string};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use regex::Regex;
use serde_json::Value;
use std::borrow::Cow;
use std::sync::LazyLock;

mod beszel;
mod enrich;

use self::enrich::enrich_grafana_body;

static SHORT_HOST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(it1-prd-)?[a-z]+-\d+$").unwrap());
static HOST_IN_TEXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(it1-prd-[a-z]+-\d+|[a-z]+-\d+)\b").unwrap());

pub fn parse_grafana_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let status = json_get_str(payload, "status").if_empty("firing");
    let common_labels = payload.get("commonLabels").and_then(|v| v.as_object());
    let common_annot = payload.get("commonAnnotations").and_then(|v| v.as_object());
    let alertname = grafana_alertname(common_labels);
    let component = object_scalar_cow(common_labels, "component").into_owned();
    let instance_label = object_scalar_cow(common_labels, "instance");
    let summary = object_scalar_cow(common_annot, "summary");
    let description = object_scalar_cow(common_annot, "description");
    let host = grafana_host(common_labels, &alertname, summary.as_ref(), &component);
    let body = grafana_body(GrafanaBodyInput {
        payload,
        status,
        alertname: &alertname,
        host: &host,
        summary: summary.as_ref(),
        description: description.as_ref(),
        cfg,
    });
    let (render_slug, render_panel) = grafana_render_target(&component, cfg);

    Parts {
        title: grafana_title(status, severity, &alertname, &host, cfg),
        body,
        tags: grafana_tags(status, severity, &component, cfg),
        actions: grafana_actions(payload, common_annot, &component, cfg),
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
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}

struct GrafanaBodyInput<'a> {
    payload: &'a Value,
    status: &'a str,
    alertname: &'a str,
    host: &'a str,
    summary: &'a str,
    description: &'a str,
    cfg: &'a RuntimeConfig,
}

fn grafana_alertname(common_labels: Option<&serde_json::Map<String, Value>>) -> String {
    let alertname = object_scalar_cow(common_labels, "alertname");
    if alertname.is_empty() {
        "Grafana alert".to_string()
    } else {
        alertname.into_owned()
    }
}

fn grafana_host(
    common_labels: Option<&serde_json::Map<String, Value>>,
    alertname: &str,
    summary: &str,
    component: &str,
) -> String {
    let host_label = object_scalar_cow(common_labels, "host");
    let instance_label = object_scalar_cow(common_labels, "instance");
    let mut host = first_non_empty(&[host_label.as_ref(), instance_label.as_ref()]);
    if host.is_empty() && SHORT_HOST_RE.is_match(component) {
        return host_from_short_component(component);
    }
    if host.is_empty() {
        let hay = format!("{alertname} {summary}");
        if let Some(caps) = HOST_IN_TEXT_RE.captures(&hay) {
            host = normalize_host(caps.get(1).unwrap().as_str());
        }
    }
    host
}

fn grafana_title(
    status: &str,
    severity: &str,
    alertname: &str,
    host: &str,
    cfg: &RuntimeConfig,
) -> String {
    let state_emoji = if status == "resolved" {
        cfg.icon("resolved")
    } else {
        cfg.icon(severity)
    };
    let mut title = format!("{state_emoji} Grafana: {alertname}");
    if !host.is_empty() {
        title.push_str(&format!(" — {host}"));
    }
    title
}

fn grafana_body(input: GrafanaBodyInput<'_>) -> String {
    let mut body_parts = Vec::new();
    if input.status == "resolved" {
        body_parts.push("Status: RESOLVED".to_string());
    }
    if !input.summary.is_empty() {
        body_parts.push(input.summary.to_string());
    }
    if !input.description.is_empty() && input.description != input.summary {
        body_parts.push(input.description.to_string());
    }
    // Grafana removes annotations from commonAnnotations when grouped alert
    // instances render different values (for example one Trivy service/image
    // per instance). Preserve those actionable details as a compact list.
    if input.summary.is_empty() {
        let (summaries, omitted) = alert_summaries(input.payload, 12);
        if !summaries.is_empty() {
            body_parts.push(
                summaries
                    .into_iter()
                    .map(|summary| format!("• {summary}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
            if omitted > 0 {
                body_parts.push(format!("… and {omitted} more"));
            }
        }
    }
    let affected = affected_hosts(input.payload);
    if affected.len() > 1 || (!affected.is_empty() && affected[0] != input.host) {
        body_parts.push(format!("Affected: {}", affected.join(", ")));
    }
    let mut body = if body_parts.is_empty() {
        "(no body)".to_string()
    } else {
        body_parts.join("\n")
    };
    if input.status != "resolved"
        && let Some(extra) = enrich_grafana_body(input.alertname, input.host, &body, input.cfg)
        && !extra.is_empty()
    {
        body.push_str(&extra);
    }
    body
}

fn alert_summaries(payload: &Value, limit: usize) -> (Vec<String>, usize) {
    let Some(alerts) = payload.get("alerts").and_then(|v| v.as_array()) else {
        return (Vec::new(), 0);
    };
    let mut unique = Vec::new();
    for alert in alerts {
        let summary = alert
            .get("annotations")
            .and_then(|v| v.as_object())
            .map(|annotations| object_scalar_cow(Some(annotations), "summary").into_owned())
            .unwrap_or_default();
        if !summary.is_empty() && !unique.contains(&summary) {
            unique.push(summary);
        }
    }
    let omitted = unique.len().saturating_sub(limit);
    unique.truncate(limit);
    (unique, omitted)
}

fn affected_hosts(payload: &Value) -> Vec<String> {
    let mut affected = Vec::new();
    if let Some(alerts) = payload.get("alerts").and_then(|v| v.as_array()) {
        for alert in alerts.iter().take(5) {
            if let Some(host) = alert_host(alert)
                && !affected.contains(&host)
            {
                affected.push(host);
            }
        }
    }
    affected
}

fn alert_host(alert: &Value) -> Option<String> {
    alert
        .get("labels")
        .and_then(|v| v.as_object())
        .map(|lbls| {
            lbls.get("host")
                .or_else(|| lbls.get("instance"))
                .or_else(|| lbls.get("container_name"))
                .map(scalar_to_string)
                .unwrap_or_default()
        })
        .filter(|host| !host.is_empty())
}

fn grafana_tags(status: &str, severity: &str, component: &str, cfg: &RuntimeConfig) -> Vec<String> {
    if status == "resolved" {
        return vec![
            cfg.tag_prefix("resolved"),
            "grafana".into(),
            component.if_empty("homelab").to_string(),
        ];
    }
    vec![
        cfg.tag_prefix(severity),
        severity.to_string(),
        "grafana".into(),
        component.if_empty("homelab").to_string(),
    ]
}

fn grafana_actions(
    payload: &Value,
    common_annot: Option<&serde_json::Map<String, Value>>,
    component: &str,
    cfg: &RuntimeConfig,
) -> Vec<Action> {
    let mut actions = Vec::new();
    let runbook = object_scalar_cow(common_annot, "runbook_url");
    if !runbook.is_empty() {
        actions.push(action("view", "📖 Runbook", &runbook));
    }
    if let Some([label, slug]) = cfg.component_dashboards.get(component) {
        actions.push(action(
            "view",
            &format!("📊 {label}"),
            &format!("{}{}", cfg.grafana_base, slug),
        ));
    }
    let rule_url = grafana_rule_url(payload);
    if !rule_url.is_empty() {
        actions.push(action("view", "View rule", &rule_url));
    }
    actions
}

fn grafana_rule_url(payload: &Value) -> String {
    payload
        .get("alerts")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|a| a.get("generatorURL"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| json_get_str(payload, "externalURL").to_string())
}

fn grafana_render_target(component: &str, cfg: &RuntimeConfig) -> (Option<String>, Option<u64>) {
    if let Some((uid, panel)) = cfg.component_image.get(component) {
        return (Some(format!("/d/{uid}")), *panel);
    }
    if let Some([_, slug]) = cfg.component_dashboards.get(component) {
        return (Some(slug.clone()), None);
    }
    (None, None)
}

fn host_from_short_component(component: &str) -> String {
    if component.starts_with("it1-prd-") {
        component.to_string()
    } else {
        format!("it1-prd-{component}")
    }
}

fn normalize_host(host: &str) -> String {
    if host.starts_with("it1-prd-") {
        host.to_string()
    } else {
        format!("it1-prd-{host}")
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
