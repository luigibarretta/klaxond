use super::super::ingest::ingest_secret_for;
use crate::config::{DEDUP_SOURCES, RuntimeConfig};
use crate::state::AppState;
use serde_json::{Value, json};

pub(in crate::handlers) fn setup_status_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let items = vec![
        auth_item(&cfg),
        ingest_auth_item(count_ingest_secrets(state)),
        channels_item(configured_channel_count(&cfg)),
        backups_item(state),
        public_url_item(&cfg.public_url),
        passkeys_item(cfg.auth.webauthn.enabled),
    ];
    setup_response(items)
}

fn count_ingest_secrets(state: &AppState) -> usize {
    DEDUP_SOURCES
        .iter()
        .filter(|source| !ingest_secret_for(state, source).is_empty())
        .count()
}

fn configured_channel_count(cfg: &RuntimeConfig) -> usize {
    [
        !cfg.ntfy_url.is_empty() && !cfg.ntfy_topics.is_empty(),
        !cfg.tg_token.is_empty() && !cfg.tg_chat.is_empty(),
        !cfg.smtp_host.is_empty() && !cfg.smtp_from.is_empty() && !cfg.smtp_to.is_empty(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count()
}

fn auth_item(cfg: &RuntimeConfig) -> Value {
    json!({
        "key": "auth",
        "label": "Authentication",
        "status": if cfg.auth.mode == "none" { "warn" } else { "ok" },
        "detail": if cfg.auth.mode == "none" { "admin UI is unauthenticated" } else { "authentication is enabled" },
        "values": {"mode": cfg.auth.mode},
    })
}

fn ingest_auth_item(configured: usize) -> Value {
    let total = DEDUP_SOURCES.len();
    json!({
        "key": "ingest_auth",
        "label": "Inbound webhook auth",
        "status": if configured == total { "ok" } else if configured == 0 { "warn" } else { "partial" },
        "detail": format!("{configured}/{total} sources have a shared secret"),
        "values": {"configured": configured, "total": total},
    })
}

fn channels_item(configured: usize) -> Value {
    json!({
        "key": "channels",
        "label": "Notification channels",
        "status": if configured > 0 { "ok" } else { "warn" },
        "detail": format!("{configured}/3 channel families configured"),
        "values": {"configured": configured, "total": 3},
    })
}

fn backups_item(state: &AppState) -> Value {
    let path = state.paths.backup_dir.to_string_lossy();
    json!({
        "key": "backups",
        "label": "Config backups",
        "status": if state.paths.backup_dir.is_dir() { "ok" } else { "error" },
        "detail": path,
        "values": {"path": path},
    })
}

fn public_url_item(public_url: &str) -> Value {
    json!({
        "key": "public_url",
        "label": "Public URL",
        "status": if public_url.trim().is_empty() { "warn" } else { "ok" },
        "detail": if public_url.trim().is_empty() { "not configured" } else { public_url },
        "values": {"url": public_url},
    })
}

fn passkeys_item(enabled: bool) -> Value {
    json!({
        "key": "passkeys",
        "label": "Passkeys",
        "status": if enabled { "ok" } else { "info" },
        "detail": if enabled { "WebAuthn enabled" } else { "optional WebAuthn disabled" },
        "values": {"enabled": enabled},
    })
}

fn setup_response(items: Vec<Value>) -> Value {
    let errors = status_count(&items, |status| status == "error");
    let warnings = status_count(&items, |status| matches!(status, "warn" | "partial"));
    json!({
        "ok": errors == 0,
        "summary": { "errors": errors, "warnings": warnings, "items": items.len() },
        "items": items,
    })
}

fn status_count(items: &[Value], matches_status: fn(&str) -> bool) -> usize {
    items
        .iter()
        .filter(|item| {
            item.get("status")
                .and_then(Value::as_str)
                .is_some_and(matches_status)
        })
        .count()
}
