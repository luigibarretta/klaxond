use super::{html, json_body, json_response, parse_query, text};
use crate::dedup;
use crate::delivery::deliver;
use crate::inhibition;
use crate::parsers::{Parts, normalize_labels, parse_grafana_payload, parse_source};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

mod auth;

use self::auth::verify_ingest_auth;
pub(super) use self::auth::{ingest_auth_payload, ingest_secret_for, update_ingest_auth};

pub(super) async fn ingest(
    state: &AppState,
    path: &str,
    full_path: &str,
    headers: &HeaderMap,
    body: Bytes,
    peer: SocketAddr,
) -> Response<Body> {
    let source = if path.starts_with("/webhook/") {
        "grafana"
    } else if path.starts_with("/beszel/") {
        "beszel"
    } else if path.starts_with("/healthchecks/") {
        "healthchecks"
    } else if path.starts_with("/wud/") {
        "wud"
    } else if path.starts_with("/authentik/") {
        "authentik"
    } else if path.starts_with("/shelfmark/") {
        "shelfmark"
    } else if path.starts_with("/prowlarr/") {
        "prowlarr"
    } else if path.starts_with("/decypharr/") {
        "decypharr"
    } else if path.starts_with("/pve/") {
        "pve"
    } else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let severity = path.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    if !state.with_cfg(|cfg| cfg.handles_severity(&severity)) {
        return text(
            StatusCode::BAD_REQUEST,
            &format!("unknown severity {severity} (no topic handles it)"),
        );
    }
    let qs = parse_query(full_path);
    let (auth_ok, auth_reason) = verify_ingest_auth(state, source, headers, &qs);
    if !auth_ok {
        tracing::warn!(
            "[{}/{}] webhook auth rejected: {} (from {})",
            source,
            severity,
            auth_reason,
            peer.ip()
        );
        return text(
            StatusCode::UNAUTHORIZED,
            "unauthorized (per-source secret required)",
        );
    }
    let payload: Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => {
                tracing::error!("invalid JSON: {}", err);
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    };
    let dry_run = qs
        .get("dry_run")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
        || payload
            .get("_klaxond_dry_run")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

    let norm = normalize_labels(source, &payload);
    let (should_send, reason) = inhibition::apply_inhibition(state, source, &norm, dry_run);
    if !should_send {
        let title = norm
            .get("alertname")
            .or_else(|| norm.get("host"))
            .cloned()
            .unwrap_or_else(|| "alert".into());
        let (suppressed_by, ch) = if let Some(rest) = reason.strip_prefix("ack-snoozed-") {
            (
                rest.to_string(),
                if dry_run {
                    "dry-run-ack-snoozed"
                } else {
                    "ack-snoozed"
                },
            )
        } else if let Some(rest) = reason.strip_prefix("scheduled-mute-") {
            (
                rest.to_string(),
                if dry_run {
                    "dry-run-scheduled-mute"
                } else {
                    "scheduled-mute"
                },
            )
        } else if let Some(rest) = reason.strip_prefix("inhibited-by-") {
            (
                rest.to_string(),
                if dry_run {
                    "dry-run-suppressed"
                } else {
                    "suppressed"
                },
            )
        } else {
            (
                reason.clone(),
                if dry_run {
                    "dry-run-suppressed"
                } else {
                    "suppressed"
                },
            )
        };
        state.log_delivery(source, &severity, &title, ch, &suppressed_by);
        if dry_run {
            return json_response(
                json!({"dry_run": true, "would_send": false, "reason": reason, "suppressed_by": suppressed_by, "title": title}),
            );
        }
        return text(StatusCode::OK, &format!("suppressed by {reason}"));
    }

    let (severity2, parts, with_cascade) = state.with_cfg(|cfg| {
        let (severity2, parts) = parse_source(source, &payload, &severity, cfg);
        let with_cascade = if source == "grafana" {
            cfg.cascade_default
        } else {
            true
        };
        (severity2, parts, with_cascade)
    });
    let common_labels = if source == "grafana" {
        payload
            .get("commonLabels")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), crate::parsers::scalar_to_string(v)))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    if dry_run {
        state.log_delivery(source, &severity2, &parts.title, "dry-run", "");
        return json_response(json!({
            "dry_run": true,
            "would_send": true,
            "reason": reason,
            "source": source,
            "severity": severity2,
            "with_cascade": with_cascade,
            "parsed": parts.public_json(),
        }));
    }

    if source != "pve"
        && dedup::submit(
            state,
            source,
            &severity2,
            payload.clone(),
            parts.clone(),
            common_labels.clone(),
            with_cascade,
        )
        .await
    {
        return text(StatusCode::ACCEPTED, "buffered (dedup window)");
    }
    let (ok, channel) = deliver(
        state,
        &severity2,
        parts,
        with_cascade,
        common_labels,
        source,
    )
    .await;
    if ok {
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
