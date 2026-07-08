use super::ingest::ingest_secret_for;
use super::{json_response, parse_query, text};
use crate::audit;
use crate::auth::User;
use crate::config::DEDUP_SOURCES;
use crate::log_buffer;
use crate::state::{AppState, esc_label, lock_mutex};
use crate::util::env_string;
use axum::body::{Body, Bytes};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub(super) async fn status_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    json!({
        "version": crate::config::VERSION,
        "cascade_enabled_runtime": state.cascade_runtime_enabled.load(Ordering::Relaxed),
        "cascade_enabled_default": cfg.cascade_default,
        "channels": check_channel_reachability(state).await,
        "ntfy_url": cfg.ntfy_url,
        "smtp_host": cfg.smtp_host,
        "telegram_configured": !cfg.tg_token.is_empty() && !cfg.tg_chat.is_empty(),
        "logs": log_buffer::stats_global(),
    })
}

pub(super) fn setup_status_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let secrets_configured = DEDUP_SOURCES
        .iter()
        .filter(|src| !ingest_secret_for(state, src).is_empty())
        .count();
    let channel_count = [
        !cfg.ntfy_url.is_empty() && !cfg.ntfy_topics.is_empty(),
        !cfg.tg_token.is_empty() && !cfg.tg_chat.is_empty(),
        !cfg.smtp_host.is_empty() && !cfg.smtp_from.is_empty() && !cfg.smtp_to.is_empty(),
    ]
    .iter()
    .filter(|v| **v)
    .count();
    let backup_ready = state.paths.backup_dir.is_dir();
    let items = vec![
        json!({
            "key": "auth",
            "label": "Authentication",
            "status": if cfg.auth.mode == "none" { "warn" } else { "ok" },
            "detail": if cfg.auth.mode == "none" { "admin UI is unauthenticated" } else { "authentication is enabled" },
            "values": {"mode": cfg.auth.mode},
        }),
        json!({
            "key": "ingest_auth",
            "label": "Inbound webhook auth",
            "status": if secrets_configured == DEDUP_SOURCES.len() { "ok" } else if secrets_configured == 0 { "warn" } else { "partial" },
            "detail": format!("{secrets_configured}/{} sources have a shared secret", DEDUP_SOURCES.len()),
            "values": {"configured": secrets_configured, "total": DEDUP_SOURCES.len()},
        }),
        json!({
            "key": "channels",
            "label": "Notification channels",
            "status": if channel_count > 0 { "ok" } else { "warn" },
            "detail": format!("{channel_count}/3 channel families configured"),
            "values": {"configured": channel_count, "total": 3},
        }),
        json!({
            "key": "backups",
            "label": "Config backups",
            "status": if backup_ready { "ok" } else { "error" },
            "detail": state.paths.backup_dir.to_string_lossy(),
            "values": {"path": state.paths.backup_dir.to_string_lossy()},
        }),
        json!({
            "key": "public_url",
            "label": "Public URL",
            "status": if cfg.public_url.trim().is_empty() { "warn" } else { "ok" },
            "detail": if cfg.public_url.trim().is_empty() { "not configured".into() } else { cfg.public_url.clone() },
            "values": {"url": cfg.public_url},
        }),
        json!({
            "key": "passkeys",
            "label": "Passkeys",
            "status": if cfg.auth.webauthn.enabled { "ok" } else { "info" },
            "detail": if cfg.auth.webauthn.enabled { "WebAuthn enabled" } else { "optional WebAuthn disabled" },
            "values": {"enabled": cfg.auth.webauthn.enabled},
        }),
    ];
    let errors = items
        .iter()
        .filter(|item| item.get("status").and_then(Value::as_str) == Some("error"))
        .count();
    let warnings = items
        .iter()
        .filter(|item| {
            matches!(
                item.get("status").and_then(Value::as_str),
                Some("warn" | "partial")
            )
        })
        .count();
    json!({
        "ok": errors == 0,
        "summary": { "errors": errors, "warnings": warnings, "items": items.len() },
        "items": items,
    })
}

pub(super) async fn channel_test_matrix_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let reach = check_channel_reachability(state).await;
    let reach_bool = |name: &str| reach.get(name).and_then(Value::as_bool).unwrap_or(false);
    json!({
        "dry_run": true,
        "generated_at": Utc::now().to_rfc3339(),
        "note": "Connectivity checks only; no notification message is sent.",
        "channels": [
            {
                "name": "ntfy",
                "configured": !cfg.ntfy_url.is_empty() && !cfg.ntfy_topics.is_empty(),
                "reachable": reach_bool("ntfy"),
                "endpoint": cfg.ntfy_url,
                "checks": ["GET /v1/health", "topic severity coverage"],
                "severity_coverage": cfg.known_severities(),
            },
            {
                "name": "telegram",
                "configured": !cfg.tg_token.is_empty() && !cfg.tg_chat.is_empty(),
                "reachable": reach_bool("telegram"),
                "endpoint": if cfg.tg_token.is_empty() { "" } else { cfg.telegram_api_base.as_str() },
                "checks": ["bot getMe", "chat id configured"],
            },
            {
                "name": "smtp",
                "configured": !cfg.smtp_host.is_empty() && !cfg.smtp_from.is_empty() && !cfg.smtp_to.is_empty(),
                "reachable": reach_bool("smtp"),
                "endpoint": if cfg.smtp_host.is_empty() { String::new() } else { format!("{}:{}", cfg.smtp_host, cfg.smtp_port) },
                "checks": ["TCP connect", "from/to configured"],
            }
        ],
    })
}

async fn check_channel_reachability(state: &AppState) -> Value {
    let cfg = state.cfg();
    let mut ntfy = false;
    let mut telegram = false;
    let mut smtp = false;
    if !cfg.ntfy_url.is_empty() {
        ntfy = state
            .http
            .get(format!("{}/v1/health", cfg.ntfy_url))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
    }
    if !cfg.tg_token.is_empty() {
        let base = cfg.telegram_api_base.trim_end_matches('/');
        telegram = state
            .http
            .get(format!("{base}/bot{}/getMe", cfg.tg_token))
            .timeout(Duration::from_secs(4))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
    }
    if !cfg.smtp_host.is_empty() {
        smtp = tokio::time::timeout(
            Duration::from_secs(4),
            tokio::net::TcpStream::connect(format!("{}:{}", cfg.smtp_host, cfg.smtp_port)),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    }
    json!({"ntfy": ntfy, "telegram": telegram, "smtp": smtp})
}

pub(super) fn channel_config_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let mut legacy_topics = serde_json::Map::new();
    let mut legacy_tokens = serde_json::Map::new();
    for sev in ["info", "warning", "critical"] {
        let matches = cfg.topics_for(sev);
        legacy_topics.insert(
            sev.into(),
            json!(matches.first().map(|t| t.name.clone()).unwrap_or_default()),
        );
        legacy_tokens.insert(
            sev.into(),
            json!(
                matches
                    .first()
                    .map(|t| !t.token.is_empty())
                    .unwrap_or(false)
            ),
        );
    }
    json!({
        "ntfy": {
            "url": cfg.ntfy_url,
            "topics": legacy_topics,
            "url_from_env": !env_string("NTFY_URL").is_empty(),
            "topics_from_env": {
                "info": !env_string("TOPIC_INFO").is_empty(),
                "warning": !env_string("TOPIC_WARN").is_empty(),
                "critical": !env_string("TOPIC_CRIT").is_empty(),
            },
            "tokens_configured": legacy_tokens,
        },
        "telegram": {
            "chat_id": cfg.tg_chat,
            "api_base": cfg.telegram_api_base,
            "chat_id_from_env": !env_string("TELEGRAM_CHAT_ID").is_empty(),
            "api_base_from_env": !env_string("TELEGRAM_API_BASE").is_empty(),
            "bot_token_configured": !cfg.tg_token.is_empty(),
            "bot_token_from_env": !env_string("TELEGRAM_BOT_TOKEN").is_empty(),
        },
        "smtp": {
            "host": cfg.smtp_host,
            "port": cfg.smtp_port,
            "starttls": cfg.smtp_starttls,
            "from_addr": cfg.smtp_from,
            "to_addr": cfg.smtp_to,
            "user": cfg.smtp_user,
            "host_from_env": !env_string("SMTP_HOST").is_empty(),
            "port_from_env": std::env::var("SMTP_PORT").is_ok(),
            "starttls_from_env": std::env::var("SMTP_STARTTLS").is_ok(),
            "from_from_env": !env_string("SMTP_FROM").is_empty(),
            "to_from_env": !env_string("SMTP_TO").is_empty(),
            "user_configured": !cfg.smtp_user.is_empty(),
            "user_from_env": !env_string("SMTP_USER").is_empty(),
            "password_configured": !cfg.smtp_pass.is_empty(),
            "password_from_env": !env_string("SMTP_PASSWORD").is_empty(),
        },
    })
}

pub(super) fn inhibition_rules_payload(state: &AppState) -> Value {
    let rules = state
        .cfg()
        .inhibition_rules
        .iter()
        .map(|r| {
            json!({
                "source": r.source,
                "ttl_seconds": r.ttl_seconds,
                "match_by": r.match_by,
                "match_label": r.match_label,
                "match_regex": r.match_regex,
                "match_all": r.match_all,
                "applies_to": r.applies_to,
            })
        })
        .collect::<Vec<_>>();
    json!({"rules": rules, "available_sources": DEDUP_SOURCES})
}

pub(super) fn client_log_response(body: Bytes, authed_user: Option<&User>) -> Response<Body> {
    if body.len() > 8192 {
        return text(
            StatusCode::PAYLOAD_TOO_LARGE,
            "client log payload too large",
        );
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return text(StatusCode::BAD_REQUEST, "invalid client log payload");
    };
    let level = payload
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("error")
        .trim()
        .to_ascii_lowercase();
    let key = client_log_field(&payload, "key", 96);
    let message = client_log_field(&payload, "message", 512);
    let path = client_log_field(&payload, "path", 160);
    let stack = client_log_field(&payload, "stack", 1024);
    let user_agent = client_log_field(&payload, "userAgent", 256);
    let user = authed_user
        .map(|u| {
            if u.sub.is_empty() {
                "anonymous"
            } else {
                u.sub.as_str()
            }
        })
        .unwrap_or("anonymous");

    match level.as_str() {
        "warn" | "warning" => tracing::warn!(
            target: "klaxond::frontend",
            ui_context = %key,
            ui_path = %path,
            ui_user = %user,
            ui_user_agent = %user_agent,
            ui_stack = %stack,
            "frontend warning [{key}]: {message}"
        ),
        "info" => tracing::info!(
            target: "klaxond::frontend",
            ui_context = %key,
            ui_path = %path,
            ui_user = %user,
            ui_user_agent = %user_agent,
            ui_stack = %stack,
            "frontend info [{key}]: {message}"
        ),
        _ => tracing::error!(
            target: "klaxond::frontend",
            ui_context = %key,
            ui_path = %path,
            ui_user = %user,
            ui_user_agent = %user_agent,
            ui_stack = %stack,
            "frontend error [{key}]: {message}"
        ),
    }

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap()
}

fn client_log_field(payload: &Value, key: &str, max_chars: usize) -> String {
    let raw = payload.get(key).and_then(|v| v.as_str()).unwrap_or("");
    let compact = raw
        .chars()
        .map(|ch| {
            if ch.is_control() && ch != '\n' && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>();
    compact.chars().take(max_chars).collect()
}

pub(super) fn metrics_response(state: &AppState) -> Response<Body> {
    let uptime = state.started.elapsed().as_secs();
    state.metric_set(
        "klaxond_suppressions_active",
        &[],
        lock_mutex(&state.suppressions, "suppressions").len() as f64,
    );
    if let Ok(d) = state.dedup.try_lock() {
        for src in DEDUP_SOURCES {
            state.metric_set(
                "klaxond_dedup_pending",
                &[("source", src)],
                d.queues.get(*src).map(|q| q.len()).unwrap_or(0) as f64,
            );
        }
    }
    let mut lines = vec![
        "# HELP klaxond_info Static info (version, etc).".to_string(),
        "# TYPE klaxond_info gauge".to_string(),
        format!("klaxond_info{{version=\"{}\"}} 1", crate::config::VERSION),
        "# HELP klaxond_uptime_seconds Seconds since klaxond started.".to_string(),
        "# TYPE klaxond_uptime_seconds counter".to_string(),
        format!("klaxond_uptime_seconds {uptime}"),
    ];
    let counters = lock_mutex(&state.metrics.counters, "metrics counters");
    emit_metrics(
        &mut lines,
        "counter",
        &counters,
        &HashMap::from([
            (
                "klaxond_deliveries_total",
                "Cumulative deliveries (or attempts) per source/severity/channel/ok.",
            ),
            (
                "klaxond_suppressions_armed_total",
                "Inhibition source-alerts that armed a suppression.",
            ),
            (
                "klaxond_render_errors_total",
                "Render-time exceptions per source.",
            ),
            (
                "klaxond_dedup_buffered_total",
                "Events queued in the dedup buffer per source.",
            ),
            (
                "klaxond_dedup_flushed_total",
                "Events flushed from the dedup buffer per source.",
            ),
        ]),
    );
    let gauges = lock_mutex(&state.metrics.gauges, "metrics gauges");
    let gauge_i = gauges
        .iter()
        .map(|(k, v)| (k.clone(), *v as i64))
        .collect::<HashMap<_, _>>();
    emit_metrics(
        &mut lines,
        "gauge",
        &gauge_i,
        &HashMap::from([
            (
                "klaxond_suppressions_active",
                "Currently-armed in-memory suppressions.",
            ),
            (
                "klaxond_dedup_pending",
                "Events pending in the dedup buffer per source.",
            ),
        ]),
    );
    let body = lines.join("\n") + "\n";
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

fn emit_metrics(
    lines: &mut Vec<String>,
    kind: &str,
    samples: &HashMap<String, i64>,
    helps: &HashMap<&str, &str>,
) {
    let mut by_name: HashMap<String, Vec<(String, i64)>> = HashMap::new();
    for (key, val) in samples {
        let (name, labels) = key.split_once('|').unwrap_or((key, ""));
        by_name
            .entry(name.into())
            .or_default()
            .push((labels.into(), *val));
    }
    let mut names = by_name.keys().cloned().collect::<Vec<_>>();
    names.sort();
    for name in names {
        lines.push(format!(
            "# HELP {name} {}",
            helps
                .get(name.as_str())
                .copied()
                .unwrap_or("(no description)")
        ));
        lines.push(format!("# TYPE {name} {kind}"));
        for (labels, val) in by_name.remove(&name).unwrap_or_default() {
            let label_render = if labels.is_empty() {
                String::new()
            } else {
                let labels = labels
                    .split(',')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| format!("{k}=\"{}\"", esc_label(v)))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{{{labels}}}")
            };
            lines.push(format!("{name}{label_render} {val}"));
        }
    }
}

pub(super) fn logs_payload(full_path: &str) -> log_buffer::LogQuery {
    let qs = parse_query(full_path);
    let limit = qs
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200);
    let offset = qs
        .get("offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let query = qs.get("q").map(String::as_str).unwrap_or("");
    let level = qs.get("level").map(String::as_str).unwrap_or("all");
    log_buffer::query_global(query, level, limit, offset)
}

pub(super) fn audit_payload(full_path: &str) -> Value {
    let qs = parse_query(full_path);
    let limit = qs
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100);
    let offset = qs
        .get("offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let query = qs.get("q").map(String::as_str).unwrap_or("");
    audit::query(query, limit, offset)
}

pub(super) fn deliveries_response(state: &AppState, full_path: &str) -> Response<Body> {
    let qs = parse_query(full_path);
    let paginated = qs.contains_key("limit") || qs.contains_key("offset");
    if !paginated {
        return json_response(state.recent_deliveries());
    }
    let default_limit = state.with_cfg(|cfg| cfg.history.default_limit);
    let limit = qs
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default_limit)
        .clamp(1, 10_000);
    let offset = qs
        .get("offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    json_response(state.deliveries_page(limit, offset))
}
