use super::{json_response, parse_query};
use crate::audit;
use crate::config::DEDUP_SOURCES;
use crate::log_buffer;
use crate::state::AppState;
use crate::util::env_string;
use axum::body::Body;
use axum::http::Response;
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use std::time::Duration;

mod client_logs;
mod metrics;
mod setup;

pub(super) use client_logs::client_log_response;
pub(super) use metrics::metrics_response;
pub(super) use setup::setup_ready;

pub(super) async fn setup_status_payload(state: &AppState) -> Value {
    let matrix = channel_test_matrix_payload(state).await;
    setup::setup_status_payload(state, Some(&matrix))
}

pub(super) async fn status_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let emergency_stats = crate::emergency::active_stats(state);
    let emergency_storage_ok = emergency_stats.is_ok();
    let (emergency_active, emergency_oldest_age_seconds) = emergency_stats.unwrap_or((0, 0.0));
    json!({
        "version": crate::config::VERSION,
        "cascade_enabled_runtime": state.cascade_runtime_enabled.load(Ordering::Relaxed),
        "cascade_enabled_default": cfg.cascade_default,
        "channels": check_channel_reachability(state).await,
        "ntfy_url": cfg.ntfy_url,
        "smtp_host": cfg.smtp_host,
        "telegram_configured": !cfg.tg_token.is_empty() && !cfg.tg_chat.is_empty(),
        "logs": log_buffer::stats_global(),
        "emergency": {
            "enabled": cfg.emergency.enabled,
            "storage_ok": emergency_storage_ok,
            "active": emergency_active,
            "oldest_active_age_seconds": emergency_oldest_age_seconds,
            "retry_seconds": cfg.emergency.retry_seconds,
            "expire_seconds": cfg.emergency.expire_seconds,
            "max_attempts": cfg.emergency.max_attempts,
        },
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
