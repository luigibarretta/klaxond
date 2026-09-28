use crate::state::AppState;
use serde_json::{Value, json};
use std::fs;

pub(super) fn config_full_export_payload(state: &AppState) -> Result<Value, String> {
    let cfg = state.cfg();
    let toml_text = fs::read_to_string(&state.paths.config)
        .map_err(|err| format!("read {} failed: {err}", state.paths.config.display()))?;
    let render_sidecar = json!({ "component_dashboards": &cfg.component_dashboards });
    let ntfy_sidecar = json!({ "topics": &cfg.ntfy_topics });
    let mut files = serde_json::Map::new();
    files.insert("klaxond.toml".into(), json!(toml_text));
    files.insert(
        "render-config.json".into(),
        json!(json_pretty_string(&render_sidecar)?),
    );
    files.insert(
        "ntfy-topics.json".into(),
        json!(json_pretty_string(&ntfy_sidecar)?),
    );
    files.insert(
        "dedup-config.json".into(),
        json!(json_pretty_string(&cfg.dedup)?),
    );
    files.insert(
        "auth-config.json".into(),
        json!(json_pretty_string(&cfg.auth)?),
    );
    Ok(json!({
        "kind": "klaxond.full-settings",
        "format_version": 1,
        "klaxond_version": crate::config::VERSION,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "includes_secrets": true,
        "files_are_effective": true,
        "files": Value::Object(files),
        "source_paths": {
            "klaxond.toml": state.paths.config.to_string_lossy(),
            "render-config.json": state.paths.render_config.to_string_lossy(),
            "ntfy-topics.json": state.paths.ntfy_topics.to_string_lossy(),
            "dedup-config.json": state.paths.dedup_config.to_string_lossy(),
            "auth-config.json": state.paths.auth_config.to_string_lossy(),
        },
        "effective_runtime": {
            "ntfy_url": cfg.ntfy_url,
            "telegram": { "api_base": cfg.telegram_api_base, "bot_token": cfg.tg_token, "chat_id": cfg.tg_chat },
            "smtp": { "host": cfg.smtp_host, "port": cfg.smtp_port, "starttls": cfg.smtp_starttls, "from_addr": cfg.smtp_from, "to_addr": cfg.smtp_to, "user": cfg.smtp_user, "password": cfg.smtp_pass },
            "grafana": { "base": cfg.grafana_base, "render_base": cfg.grafana_render_base, "render_token": cfg.grafana_render_token },
            "public_url": cfg.public_url,
            "render_image_ttl": cfg.render_image_ttl,
            "ack_default_ttl": cfg.ack_default_ttl,
            "beszel_db": cfg.beszel_db.to_string_lossy(),
        }
    }))
}

fn json_pretty_string<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|err| err.to_string())
}
