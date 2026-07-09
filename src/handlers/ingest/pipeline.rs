use super::super::{json_response, parse_query, text};
use crate::dedup;
use crate::parsers::{Parts, parse_source};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::collections::HashMap;

pub(super) struct IngestRoute {
    pub(super) source: &'static str,
    pub(super) severity: String,
    pub(super) qs: HashMap<String, String>,
}

pub(super) enum IngestRouteError {
    NotFound,
    UnknownSeverity(String),
}

pub(super) struct DeliveryCandidate {
    pub(super) severity: String,
    pub(super) parts: Parts,
    pub(super) with_cascade: bool,
    pub(super) common_labels: HashMap<String, String>,
}

pub(super) fn ingest_route(
    state: &AppState,
    path: &str,
    full_path: &str,
) -> Result<IngestRoute, IngestRouteError> {
    let Some(source) = ingest_source(path) else {
        return Err(IngestRouteError::NotFound);
    };
    let severity = path.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    if !state.with_cfg(|cfg| cfg.handles_severity(&severity)) {
        return Err(IngestRouteError::UnknownSeverity(severity));
    }
    Ok(IngestRoute {
        source,
        severity,
        qs: parse_query(full_path),
    })
}

pub(super) fn ingest_route_error_response(err: IngestRouteError) -> Response<Body> {
    match err {
        IngestRouteError::NotFound => StatusCode::NOT_FOUND.into_response(),
        IngestRouteError::UnknownSeverity(severity) => text(
            StatusCode::BAD_REQUEST,
            &format!("unknown severity {severity} (no topic handles it)"),
        ),
    }
}

fn ingest_source(path: &str) -> Option<&'static str> {
    [
        ("/webhook/", "grafana"),
        ("/beszel/", "beszel"),
        ("/healthchecks/", "healthchecks"),
        ("/wud/", "wud"),
        ("/authentik/", "authentik"),
        ("/shelfmark/", "shelfmark"),
        ("/prowlarr/", "prowlarr"),
        ("/decypharr/", "decypharr"),
        ("/pve/", "pve"),
    ]
    .iter()
    .find_map(|(prefix, source)| path.starts_with(prefix).then_some(*source))
}

pub(super) fn parse_ingest_payload(body: &Bytes) -> serde_json::Result<Value> {
    if body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(body)
}

pub(super) fn dry_run_requested(qs: &HashMap<String, String>, payload: &Value) -> bool {
    qs.get("dry_run")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
        || payload
            .get("_klaxond_dry_run")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

pub(super) fn suppressed_ingest_response(
    state: &AppState,
    source: &str,
    severity: &str,
    labels: &HashMap<String, String>,
    reason: String,
    dry_run: bool,
) -> Response<Body> {
    let title = labels
        .get("alertname")
        .or_else(|| labels.get("host"))
        .cloned()
        .unwrap_or_else(|| "alert".into());
    let (suppressed_by, channel) = suppression_detail(&reason, dry_run);
    state.log_delivery(source, severity, &title, channel, &suppressed_by);
    if dry_run {
        return json_response(json!({
            "dry_run": true,
            "would_send": false,
            "reason": reason,
            "suppressed_by": suppressed_by,
            "title": title,
        }));
    }
    text(StatusCode::OK, &format!("suppressed by {reason}"))
}

fn suppression_detail(reason: &str, dry_run: bool) -> (String, &'static str) {
    if let Some(rest) = reason.strip_prefix("ack-snoozed-") {
        return (
            rest.to_string(),
            if dry_run {
                "dry-run-ack-snoozed"
            } else {
                "ack-snoozed"
            },
        );
    }
    if let Some(rest) = reason.strip_prefix("scheduled-mute-") {
        return (
            rest.to_string(),
            if dry_run {
                "dry-run-scheduled-mute"
            } else {
                "scheduled-mute"
            },
        );
    }
    if let Some(rest) = reason.strip_prefix("inhibited-by-") {
        return (
            rest.to_string(),
            if dry_run {
                "dry-run-suppressed"
            } else {
                "suppressed"
            },
        );
    }
    (
        reason.to_string(),
        if dry_run {
            "dry-run-suppressed"
        } else {
            "suppressed"
        },
    )
}

pub(super) fn delivery_candidate(
    state: &AppState,
    source: &str,
    severity: &str,
    payload: &Value,
) -> DeliveryCandidate {
    let (severity, parts, with_cascade) = state.with_cfg(|cfg| {
        let (severity, parts) = parse_source(source, payload, severity, cfg);
        let with_cascade = if source == "grafana" {
            cfg.cascade_default
        } else {
            true
        };
        (severity, parts, with_cascade)
    });
    DeliveryCandidate {
        severity,
        parts,
        with_cascade,
        common_labels: common_labels(source, payload),
    }
}

fn common_labels(source: &str, payload: &Value) -> HashMap<String, String> {
    if source != "grafana" {
        return HashMap::new();
    }
    payload
        .get("commonLabels")
        .and_then(Value::as_object)
        .map(|labels| {
            labels
                .iter()
                .map(|(key, value)| (key.clone(), crate::parsers::scalar_to_string(value)))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn dry_run_delivery_response(
    state: &AppState,
    source: &str,
    delivery: DeliveryCandidate,
    reason: String,
) -> Response<Body> {
    state.log_delivery(
        source,
        &delivery.severity,
        &delivery.parts.title,
        "dry-run",
        "",
    );
    json_response(json!({
        "dry_run": true,
        "would_send": true,
        "reason": reason,
        "source": source,
        "severity": delivery.severity,
        "with_cascade": delivery.with_cascade,
        "parsed": delivery.parts.public_json(),
    }))
}

pub(super) async fn maybe_buffer_dedup(
    state: &AppState,
    source: &str,
    payload: &Value,
    delivery: &DeliveryCandidate,
) -> bool {
    source != "pve"
        && dedup::submit(
            state,
            dedup::SubmitInput {
                source: source.to_string(),
                severity: delivery.severity.clone(),
                payload: payload.clone(),
                parts: delivery.parts.clone(),
                common_labels: delivery.common_labels.clone(),
                with_cascade: delivery.with_cascade,
            },
        )
        .await
}
