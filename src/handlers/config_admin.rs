use super::text;
use crate::config::{load_runtime_config, save_toml};
use crate::state::AppState;
use crate::util::atomic_write;
use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{Response, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::fs;

mod restore;

pub(super) use self::restore::{config_import_preview_response, restore_config};

pub(super) fn config_backup_response(state: &AppState) -> Response<Body> {
    let Ok(bytes) = fs::read(&state.paths.config) else {
        return text(StatusCode::NOT_FOUND, "klaxond.toml not found");
    };
    let stamp = Utc::now().format("%Y%m%d-%H%M%S-%f");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/toml")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"klaxond-{stamp}.toml\""),
        )
        .header(CONTENT_LENGTH, bytes.len().to_string())
        .body(Body::from(bytes))
        .unwrap()
}

pub(super) fn config_full_export_response(state: &AppState) -> Response<Body> {
    let payload = match state.with_config_write_lock(|| config_full_export_payload(state)) {
        Ok(Ok(payload)) => payload,
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    let bytes = match serde_json::to_vec_pretty(&payload) {
        Ok(bytes) => bytes,
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    };
    let stamp = Utc::now().format("%Y%m%d-%H%M%S-%f");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"klaxond-full-settings-{stamp}.json\""),
        )
        .header(CONTENT_LENGTH, bytes.len().to_string())
        .body(Body::from(bytes))
        .unwrap()
}

fn config_full_export_payload(state: &AppState) -> Result<Value, String> {
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
        "exported_at": Utc::now().to_rfc3339(),
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
            "telegram": {
                "api_base": cfg.telegram_api_base,
                "bot_token": cfg.tg_token,
                "chat_id": cfg.tg_chat,
            },
            "smtp": {
                "host": cfg.smtp_host,
                "port": cfg.smtp_port,
                "starttls": cfg.smtp_starttls,
                "from_addr": cfg.smtp_from,
                "to_addr": cfg.smtp_to,
                "user": cfg.smtp_user,
                "password": cfg.smtp_pass,
            },
            "grafana": {
                "base": cfg.grafana_base,
                "render_base": cfg.grafana_render_base,
                "render_token": cfg.grafana_render_token,
            },
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

pub(super) fn config_backups_payload(state: &AppState) -> Value {
    let mut backups = Vec::new();
    if let Ok(entries) = fs::read_dir(&state.paths.backup_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !(name.starts_with("klaxond-") && name.ends_with(".toml")) {
                continue;
            }
            if let Ok(meta) = e.metadata() {
                let mtime_iso = meta
                    .modified()
                    .ok()
                    .map(DateTime::<Utc>::from)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default();
                backups.push(json!({"name": name, "size": meta.len(), "mtime_iso": mtime_iso}));
            }
        }
    }
    backups.sort_by(|a, b| {
        b.get("mtime_iso")
            .and_then(|v| v.as_str())
            .cmp(&a.get("mtime_iso").and_then(|v| v.as_str()))
    });
    json!({"backups": backups, "keep_max": 10, "dir": state.paths.backup_dir})
}

fn config_auto_backup(state: &AppState) -> anyhow::Result<Option<String>> {
    if !state.paths.config.exists() {
        return Ok(None);
    }
    fs::create_dir_all(&state.paths.backup_dir).ok();
    let stamp = Utc::now().format("%Y%m%d-%H%M%S-%f");
    let dest = state.paths.backup_dir.join(format!("klaxond-{stamp}.toml"));
    fs::copy(&state.paths.config, &dest)?;
    let mut files = fs::read_dir(&state.paths.backup_dir)?
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("klaxond-") && name.ends_with(".toml")
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|e| std::cmp::Reverse(e.file_name()));
    for stale in files.into_iter().skip(10) {
        let _ = fs::remove_file(stale.path());
    }
    Ok(Some(dest.to_string_lossy().to_string()))
}

pub(super) fn persist_reload(state: &AppState, toml_value: toml::Value) -> Result<(), String> {
    config_auto_backup(state).map_err(|e| e.to_string()).ok();
    let previous = fs::read(&state.paths.config).ok();
    save_toml(&state.paths, &toml_value).map_err(|e| e.to_string())?;
    let cfg = match load_runtime_config(&state.paths) {
        Ok(cfg) => cfg,
        Err(error) => {
            restore_config_file(state, previous.as_deref());
            return Err(error.to_string());
        }
    };
    if let Err(error) = state.try_replace_config(cfg) {
        restore_config_file(state, previous.as_deref());
        return Err(error);
    }
    Ok(())
}

fn restore_config_file(state: &AppState, previous: Option<&[u8]>) {
    match previous {
        Some(bytes) => {
            if let Err(error) = atomic_write(&state.paths.config, bytes) {
                tracing::error!("failed to roll back rejected config: {error}");
            }
        }
        None => {
            if let Err(error) = fs::remove_file(&state.paths.config)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                tracing::error!("failed to remove rejected bootstrap config: {error}");
            }
        }
    }
}
