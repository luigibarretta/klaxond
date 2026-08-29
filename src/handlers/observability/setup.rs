use super::super::ingest::ingest_secret_for;
use crate::config::{INGEST_SOURCES, RuntimeConfig};
use crate::state::AppState;
use serde_json::{Value, json};

pub(super) fn setup_status_payload(state: &AppState, matrix: Option<&Value>) -> Value {
    let cfg = state.cfg();
    let mut items = vec![
        auth_item(&cfg),
        ingest_auth_item(count_ingest_secrets(state)),
        channels_item(configured_channel_count(&cfg)),
        backups_item(state),
        public_url_item(&cfg.public_url),
        emergency_item(&cfg),
        passkeys_item(cfg.auth.webauthn.enabled),
    ];
    if let Some(matrix) = matrix {
        items.push(connectivity_item(matrix));
    }
    let mut response = setup_response(items);
    if let Some(matrix) = matrix {
        response["matrix"] = matrix.clone();
    }
    response
}

pub(in crate::handlers) fn setup_ready(state: &AppState) -> bool {
    setup_status_payload(state, None)
        .get("ready")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn connectivity_item(matrix: &Value) -> Value {
    let channels = matrix
        .get("channels")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let configured = channels
        .iter()
        .filter(|channel| channel.get("configured").and_then(Value::as_bool) == Some(true))
        .count();
    let reachable = channels
        .iter()
        .filter(|channel| {
            channel.get("configured").and_then(Value::as_bool) == Some(true)
                && channel.get("reachable").and_then(Value::as_bool) == Some(true)
        })
        .count();
    let status = if configured > 0 && reachable == configured {
        "ok"
    } else if reachable == 0 {
        "error"
    } else {
        "partial"
    };
    json!({
        "key": "connectivity",
        "label": "Live channel connectivity",
        "status": status,
        "detail": format!("{reachable}/{configured} configured channels are reachable"),
        "values": {"configured": configured, "reachable": reachable},
        "required": true,
        "action": {"key": "connectivity", "path": "/setup", "label": "Run channel checks"},
    })
}

fn count_ingest_secrets(state: &AppState) -> usize {
    INGEST_SOURCES
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
        "required": true,
        "action": {"key": "auth", "path": "/authentication", "label": "Configure authentication"},
    })
}

fn ingest_auth_item(configured: usize) -> Value {
    let total = INGEST_SOURCES.len();
    let disabled = total.saturating_sub(configured);
    json!({
        "key": "ingest_auth",
        "label": "Inbound webhook auth",
        "status": if configured > 0 { "ok" } else { "warn" },
        "detail": if configured > 0 {
            format!("{configured} sources enabled and protected; {disabled} disabled")
        } else {
            "all inbound sources are disabled".to_string()
        },
        "values": {"configured": configured, "total": total, "disabled": disabled},
        "required": true,
        "action": {"key": "ingest_auth", "path": "/routing", "label": "Secure webhooks"},
    })
}

fn channels_item(configured: usize) -> Value {
    json!({
        "key": "channels",
        "label": "Notification channels",
        "status": if configured > 0 { "ok" } else { "warn" },
        "detail": format!("{configured}/3 channel families configured"),
        "values": {"configured": configured, "total": 3},
        "required": true,
        "action": {"key": "channels", "path": "/routing", "label": "Configure channels"},
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
        "required": true,
        "action": {"key": "backups", "path": "/status", "label": "Review backups"},
    })
}

fn public_url_item(public_url: &str) -> Value {
    let configured = !public_url.trim().is_empty();
    let secure = public_url
        .trim()
        .to_ascii_lowercase()
        .starts_with("https://");
    let (status, detail) = if !configured {
        ("warn", "not configured".to_string())
    } else if !secure {
        (
            "warn",
            format!("{public_url} (HTTPS required for production)"),
        )
    } else {
        ("ok", public_url.to_string())
    };
    json!({
        "key": "public_url",
        "label": "Public URL",
        "status": status,
        "detail": detail,
        "values": {"url": public_url, "secure": secure},
        "required": true,
        "action": {"key": "public_url", "path": "/render", "label": "Set public URL"},
    })
}

fn emergency_item(cfg: &RuntimeConfig) -> Value {
    json!({
        "key": "emergency",
        "label": "Emergency delivery",
        "status": if cfg.emergency.enabled { "ok" } else { "info" },
        "detail": if cfg.emergency.enabled {
            format!(
                "enabled: retry every {}s, expire after {}s",
                cfg.emergency.retry_seconds, cfg.emergency.expire_seconds
            )
        } else {
            "optional durable retries are disabled".to_string()
        },
        "values": {"enabled": cfg.emergency.enabled},
        "required": false,
        "action": {"key": "emergency", "path": "/emergencies", "label": "Configure emergency mode"},
    })
}

fn passkeys_item(enabled: bool) -> Value {
    json!({
        "key": "passkeys",
        "label": "Passkeys",
        "status": if enabled { "ok" } else { "info" },
        "detail": if enabled { "WebAuthn enabled" } else { "optional WebAuthn disabled" },
        "values": {"enabled": enabled},
        "required": false,
        "action": {"key": "passkeys", "path": "/authentication", "label": "Configure passkeys"},
    })
}

fn setup_response(items: Vec<Value>) -> Value {
    let errors = status_count(&items, |status| status == "error");
    let warnings = status_count(&items, |status| matches!(status, "warn" | "partial"));
    let required = items
        .iter()
        .filter(|item| item.get("required").and_then(Value::as_bool) == Some(true))
        .count();
    let complete = items
        .iter()
        .filter(|item| {
            item.get("required").and_then(Value::as_bool) == Some(true)
                && item.get("status").and_then(Value::as_str) == Some("ok")
        })
        .count();
    let blocking = required.saturating_sub(complete);
    let next_action = items.iter().find(|item| {
        item.get("required").and_then(Value::as_bool) == Some(true)
            && item.get("status").and_then(Value::as_str) != Some("ok")
    });
    json!({
        "ok": errors == 0,
        "ready": blocking == 0,
        "summary": {
            "errors": errors,
            "warnings": warnings,
            "blocking": blocking,
            "complete": complete,
            "required": required,
            "items": items.len(),
        },
        "next_action": next_action.and_then(|item| item.get("action")).cloned(),
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

#[cfg(test)]
mod tests {
    use super::ingest_auth_item;

    #[test]
    fn readiness_requires_one_enabled_and_protected_ingest_source() {
        let disabled = ingest_auth_item(0);
        assert_eq!(disabled["status"], "warn");

        let enabled = ingest_auth_item(1);
        assert_eq!(enabled["status"], "ok");
        assert_eq!(enabled["values"]["configured"], 1);
        assert!(enabled["values"]["disabled"].as_u64().unwrap() > 0);
    }
}
