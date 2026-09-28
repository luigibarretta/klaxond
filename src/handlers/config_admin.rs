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

mod export;
mod restore;

use self::export::config_full_export_payload;
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
