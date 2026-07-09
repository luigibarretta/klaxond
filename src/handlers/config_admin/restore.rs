use super::{config_auto_backup, config_full_export_payload};
use crate::auth::User;
use crate::config::{load_runtime_config, restore_sidecars_from_toml};
use crate::state::AppState;
use crate::util::atomic_write;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};
use std::collections::HashMap;

use super::super::{json_response, text};

mod input;

use self::input::{
    BundleSidecar, parse_restore_input, restore_input_files, restore_input_would_restore,
    validate_restore_input,
};

pub(in crate::handlers) fn restore_config(
    state: &AppState,
    body: Bytes,
    _authed_user: Option<&User>,
) -> Response<Body> {
    if body.is_empty() || body.len() > 5_000_000 {
        return text(StatusCode::BAD_REQUEST, "empty or oversized body");
    }
    let body_len = body.len();
    let input = match parse_restore_input(&body) {
        Ok(input) => input,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    if let Err(err) = validate_restore_input(&input) {
        return text(StatusCode::BAD_REQUEST, &err);
    }
    let (backup, restored_sidecars) = match state.with_config_write_lock(|| {
        let backup = config_auto_backup(state).ok().flatten();
        if let Err(err) = atomic_write(&state.paths.config, input.toml_text.as_bytes()) {
            return Err(format!("write failed: {err}"));
        }
        let restored_sidecars = if input.sidecars.is_empty() {
            restore_sidecars_from_toml(&state.paths, &input.parsed)
                .map_err(|err| format!("restore sidecars failed: {err}"))?
        } else {
            let mut restored = Vec::new();
            for sidecar in &input.sidecars {
                write_bundle_sidecar(state, sidecar)?;
                restored.push(sidecar.name);
            }
            restored
        };
        match load_runtime_config(&state.paths) {
            Ok(cfg) => {
                if let Err(err) = state.try_replace_config(cfg) {
                    return Err(format!("reload failed: {err}"));
                }
            }
            Err(err) => return Err(format!("reload failed: {err}")),
        }
        Ok((backup, restored_sidecars))
    }) {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    json_response(
        json!({"ok": true, "source_kind": input.source_kind, "bytes_written": body_len, "toml_bytes_written": input.toml_text.len(), "pre_restore_backup": backup, "restored_sidecars": restored_sidecars}),
    )
}

pub(in crate::handlers) fn config_import_preview_response(
    state: &AppState,
    body: Bytes,
) -> Response<Body> {
    if body.is_empty() || body.len() > 5_000_000 {
        return text(StatusCode::BAD_REQUEST, "empty or oversized body");
    }
    let input = match parse_restore_input(&body) {
        Ok(input) => input,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    if let Err(err) = validate_restore_input(&input) {
        return text(StatusCode::BAD_REQUEST, &err);
    }
    let current = match config_current_files(state) {
        Ok(files) => files,
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    let incoming = restore_input_files(&input);
    let would_restore = restore_input_would_restore(&input);
    let mut changed_files = Vec::new();
    let mut unchanged_files = Vec::new();
    for (name, text) in &incoming {
        if current.get(*name).map(String::as_str) == Some(*text) {
            unchanged_files.push(*name);
        } else {
            changed_files.push(*name);
        }
    }
    for name in &would_restore {
        if !incoming
            .iter()
            .any(|(incoming_name, _)| incoming_name == name)
            && !changed_files.contains(name)
        {
            changed_files.push(*name);
        }
    }
    let warnings = if input.source_kind == "full-bundle" {
        vec!["full bundle includes secrets; keep exported files private"]
    } else {
        vec!["TOML import may regenerate supported sidecar files from TOML sections"]
    };
    json_response(json!({
        "ok": true,
        "source_kind": input.source_kind,
        "bytes_received": body.len(),
        "toml_bytes": input.toml_text.len(),
        "would_restore": would_restore,
        "changed_files": changed_files,
        "unchanged_files": unchanged_files,
        "warnings": warnings,
        "backup_will_be_created": state.paths.config.exists(),
    }))
}

fn config_current_files(state: &AppState) -> Result<HashMap<String, String>, String> {
    let payload = config_full_export_payload(state)?;
    let files = payload
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| "current export missing files object".to_string())?;
    Ok(files
        .iter()
        .filter_map(|(name, value)| value.as_str().map(|text| (name.clone(), text.to_string())))
        .collect())
}

fn write_bundle_sidecar(state: &AppState, sidecar: &BundleSidecar) -> Result<(), String> {
    let path = match sidecar.name {
        "render-config.json" => &state.paths.render_config,
        "ntfy-topics.json" => &state.paths.ntfy_topics,
        "dedup-config.json" => &state.paths.dedup_config,
        "auth-config.json" => &state.paths.auth_config,
        _ => return Err(format!("unsupported sidecar {}", sidecar.name)),
    };
    atomic_write(path, sidecar.text.as_bytes())
        .map_err(|err| format!("write {} failed: {err}", sidecar.name))
}
