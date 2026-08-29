use super::{html, json_body, json_response, text};
use crate::delivery::deliver;
use crate::inhibition;
use crate::parsers::{Parts, normalize_labels, parse_grafana_payload};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

mod auth;
mod pipeline;

use self::auth::verify_ingest_auth;
pub(super) use self::auth::{ingest_auth_payload, ingest_secret_for, update_ingest_auth};
use self::pipeline::{
    delivery_candidate, dry_run_delivery_response, dry_run_requested, ingest_route,
    ingest_route_error_response, maybe_buffer_dedup, parse_ingest_payload,
    suppressed_ingest_response,
};

pub(super) async fn ingest(
    state: &AppState,
    path: &str,
    full_path: &str,
    headers: &HeaderMap,
    body: Bytes,
    peer: SocketAddr,
) -> Response<Body> {
    let route = match ingest_route(state, path, full_path) {
        Ok(route) => route,
        Err(err) => return ingest_route_error_response(err),
    };
    let source = route.source;
    let (auth_ok, auth_reason) = verify_ingest_auth(state, source, headers, &route.qs);
    if !auth_ok {
        tracing::warn!(
            "[{}/{}] webhook auth rejected: {} (from {})",
            source,
            route.severity,
            auth_reason,
            peer.ip()
        );
        return text(
            StatusCode::UNAUTHORIZED,
            "unauthorized (per-source secret required)",
        );
    }
    let payload = match parse_ingest_payload(&body) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!("invalid JSON: {}", err);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let dry_run = dry_run_requested(&route.qs, &payload);

    let norm = normalize_labels(source, &payload);
    let (should_send, reason) = inhibition::apply_inhibition(state, source, &norm, dry_run);
    if !should_send {
        return suppressed_ingest_response(state, source, &route.severity, &norm, reason, dry_run);
    }

    let delivery = delivery_candidate(state, source, &route.severity, &payload);

    if dry_run {
        return dry_run_delivery_response(state, source, delivery, reason);
    }

    if maybe_buffer_dedup(state, source, &payload, &delivery).await {
        return text(StatusCode::ACCEPTED, "buffered (dedup window)");
    }
    let (ok, channel) = deliver(
        state,
        &delivery.severity,
        delivery.parts,
        delivery.with_cascade,
        delivery.common_labels,
        source,
    )
    .await;
    if channel == "repeat-suppressed" {
        text(StatusCode::OK, "suppressed duplicate (repeat cooldown)")
    } else if channel == "emergency-coalesced" {
        text(StatusCode::OK, "coalesced into active emergency receipt")
    } else if ok {
        text(StatusCode::OK, &format!("delivered via {channel}"))
    } else {
        text(
            StatusCode::BAD_GATEWAY,
            &format!("all channels failed ({channel})"),
        )
    }
}

pub(super) async fn api_test(state: &AppState, path: &str, body: Bytes) -> Response<Body> {
    let severity = path.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    if !state.with_cfg(|cfg| cfg.handles_severity(&severity)) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let title = payload
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let title = if title.is_empty() {
        format!("klaxond test [{severity}]")
    } else {
        title
    };
    let body_txt = payload
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("Synthetic alert from /api/test endpoint")
        .to_string();
    let component = payload
        .get("component")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let host = payload
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let cfg = state.cfg();
    let (parts, labels) = if !component.is_empty() || !host.is_empty() {
        let fake = json!({
            "status": "firing",
            "commonLabels": {"alertname": title, "severity": severity, "component": component, "host": host},
            "commonAnnotations": {"summary": body_txt},
            "alerts": [{"labels": {"alertname": title, "host": host, "component": component}, "annotations": {"summary": body_txt}, "generatorURL": ""}],
        });
        (
            parse_grafana_payload(&fake, &severity, &cfg),
            HashMap::from([("component".into(), component), ("host".into(), host)]),
        )
    } else {
        (
            Parts {
                title,
                body: body_txt,
                tags: vec![severity.clone(), "test".into()],
                actions: vec![],
                priority: cfg.priority(&severity),
                alertname: String::new(),
                skip_snooze: false,
                render_slug: None,
                render_panel: None,
                render_instance: String::new(),
                attach_url: None,
                ntfy_sequence_id: None,
                emergency_ack_url: None,
                emergency_ack_token: None,
            },
            HashMap::new(),
        )
    };
    let with_cascade = state.cascade_runtime_enabled.load(Ordering::Relaxed);
    let (ok, channel) = deliver(
        state,
        &severity,
        parts.clone(),
        with_cascade,
        labels,
        "api-test",
    )
    .await;
    json_response(json!({"ok": ok, "channel": channel, "title": parts.title}))
}

pub(super) fn ack_response(state: &AppState, path: &str) -> Response<Body> {
    let token = path
        .trim_start_matches("/api/ack/")
        .split('?')
        .next()
        .unwrap_or("");
    let (alertname, reason) = inhibition::ack_verify(state, token);
    let Some(alertname) = alertname else {
        return html(
            StatusCode::BAD_REQUEST,
            &format!("<html><body><h2>Ack rejected</h2><p>{reason}</p></body></html>"),
        );
    };
    let ttl = state.cfg().ack_default_ttl;
    inhibition::register_ack_suppression(state, &alertname, ttl);
    html(
        StatusCode::OK,
        &format!(
            "<html><body style='font-family:system-ui,sans-serif;padding:2em;max-width:480px;margin:auto'><h2 style='color:#22c55e'>✓ Snooze armed</h2><p>Alerts with <code style='background:#eee;padding:0.1em 0.4em;border-radius:3px'>alertname={alertname}</code> are silenced for the next <b>{} minutes</b>.</p><p style='color:#666;font-size:0.9em'>This page can be closed. The snooze auto-expires; you'll get the next occurrence when the condition recurs.</p></body></html>",
            ttl / 60
        ),
    )
}
