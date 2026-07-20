use super::{config_auto_backup, config_full_export_payload};
use crate::auth::User;
use crate::config::{Paths, RuntimeConfig, load_runtime_config, restore_sidecars_from_toml};
use crate::state::AppState;
use crate::util::atomic_write;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::super::{json_response, text};

mod input;

use self::input::{
    BundleSidecar, RestoreInput, parse_restore_input, restore_input_files,
    restore_input_would_restore, validate_restore_input,
};

pub(in crate::handlers) async fn restore_config(
    state: &AppState,
    body: Bytes,
    _authed_user: Option<&User>,
) -> Response<Body> {
    if body.is_empty() || body.len() > 5_000_000 {
        return text(StatusCode::BAD_REQUEST, "empty or oversized body");
    }
    let body_len = body.len();
    let worker_state = state.clone();
    let restored =
        crate::auth::blocking::run(state, move || restore_config_on_worker(&worker_state, body))
            .await;
    let restored = match restored {
        Ok(Ok(result)) => result,
        Ok(Err(RestoreFailure::Invalid(err))) => return text(StatusCode::BAD_REQUEST, &err),
        Ok(Err(RestoreFailure::Internal(err))) | Err(err) => {
            return text(StatusCode::INTERNAL_SERVER_ERROR, &err);
        }
    };
    json_response(
        json!({"ok": true, "source_kind": restored.source_kind, "bytes_written": body_len, "toml_bytes_written": restored.toml_len, "pre_restore_backup": restored.backup, "restored_sidecars": restored.sidecars}),
    )
}

struct RestoreSuccess {
    source_kind: &'static str,
    toml_len: usize,
    backup: Option<String>,
    sidecars: Vec<&'static str>,
}

enum RestoreFailure {
    Invalid(String),
    Internal(String),
}

fn restore_config_on_worker(
    state: &AppState,
    body: Bytes,
) -> Result<RestoreSuccess, RestoreFailure> {
    let input = parse_restore_input(&body).map_err(RestoreFailure::Invalid)?;
    validate_restore_input(&input).map_err(RestoreFailure::Invalid)?;
    let source_kind = input.source_kind;
    let toml_len = input.toml_text.len();
    let (backup, sidecars) = state
        .with_config_write_lock(|| {
            let cfg = prepare_runtime_config(state, &input)?;
            let snapshots = restore_file_snapshots(&state.paths, &input)?;
            state.try_replace_config_with_commit(
                cfg,
                || {
                    let backup = config_auto_backup(state).ok().flatten();
                    let sidecars = persist_restore_files(&state.paths, &input)?;
                    Ok((backup, sidecars))
                },
                || restore_snapshots(&snapshots),
            )
        })
        .map_err(RestoreFailure::Internal)?
        .map_err(RestoreFailure::Internal)?;
    Ok(RestoreSuccess {
        source_kind,
        toml_len,
        backup,
        sidecars,
    })
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

fn prepare_runtime_config(state: &AppState, input: &RestoreInput) -> Result<RuntimeConfig, String> {
    let stage_dir = state
        .paths
        .backup_dir
        .join(format!(".restore-stage-{}", crate::util::token_urlsafe(12)));
    fs::create_dir_all(&stage_dir)
        .map_err(|err| format!("create restore staging directory failed: {err}"))?;
    let mut paths = state.paths.clone();
    paths.config = stage_dir.join("klaxond.toml");
    paths.render_config = stage_dir.join("render-config.json");
    paths.ntfy_topics = stage_dir.join("ntfy-topics.json");
    paths.dedup_config = stage_dir.join("dedup-config.json");
    paths.auth_config = stage_dir.join("auth-config.json");
    let result = (|| {
        if input.sidecars.is_empty() {
            seed_stage_sidecars(&state.paths, &paths)?;
        }
        atomic_write(&paths.config, input.toml_text.as_bytes())
            .map_err(|err| format!("stage config failed: {err}"))?;
        write_restore_sidecars(&paths, input)
            .map_err(|err| format!("stage sidecars failed: {err}"))?;
        load_runtime_config(&paths).map_err(|err| format!("load staged config failed: {err}"))
    })();
    if let Err(err) = fs::remove_dir_all(&stage_dir) {
        tracing::warn!(
            "remove restore staging directory {} failed: {err}",
            stage_dir.display()
        );
    }
    result
}

fn seed_stage_sidecars(source: &Paths, stage: &Paths) -> Result<(), String> {
    for (source_path, stage_path) in [
        (&source.render_config, &stage.render_config),
        (&source.ntfy_topics, &stage.ntfy_topics),
        (&source.dedup_config, &stage.dedup_config),
        (&source.auth_config, &stage.auth_config),
    ] {
        match fs::read(source_path) {
            Ok(bytes) => atomic_write(stage_path, &bytes)
                .map_err(|err| format!("stage {} failed: {err}", source_path.display()))?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("read {} failed: {err}", source_path.display())),
        }
    }
    Ok(())
}

fn persist_restore_files(paths: &Paths, input: &RestoreInput) -> Result<Vec<&'static str>, String> {
    atomic_write(&paths.config, input.toml_text.as_bytes())
        .map_err(|err| format!("write config failed: {err}"))?;
    write_restore_sidecars(paths, input)
}

fn write_restore_sidecars(
    paths: &Paths,
    input: &RestoreInput,
) -> Result<Vec<&'static str>, String> {
    if input.sidecars.is_empty() {
        return restore_sidecars_from_toml(paths, &input.parsed)
            .map_err(|err| format!("restore sidecars failed: {err}"));
    }
    let mut restored = Vec::new();
    for sidecar in &input.sidecars {
        write_bundle_sidecar(paths, sidecar)?;
        restored.push(sidecar.name);
    }
    Ok(restored)
}

fn write_bundle_sidecar(paths: &Paths, sidecar: &BundleSidecar) -> Result<(), String> {
    let path = match sidecar.name {
        "render-config.json" => &paths.render_config,
        "ntfy-topics.json" => &paths.ntfy_topics,
        "dedup-config.json" => &paths.dedup_config,
        "auth-config.json" => &paths.auth_config,
        _ => return Err(format!("unsupported sidecar {}", sidecar.name)),
    };
    atomic_write(path, sidecar.text.as_bytes())
        .map_err(|err| format!("write {} failed: {err}", sidecar.name))
}

struct FileSnapshot {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
}

fn restore_file_snapshots(
    paths: &Paths,
    input: &RestoreInput,
) -> Result<Vec<FileSnapshot>, String> {
    restore_input_would_restore(input)
        .into_iter()
        .map(|name| {
            let path = restore_path(paths, name)?.to_path_buf();
            let bytes = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(format!("snapshot {} failed: {err}", path.display())),
            };
            Ok(FileSnapshot { path, bytes })
        })
        .collect()
}

fn restore_snapshots(snapshots: &[FileSnapshot]) -> Result<(), String> {
    let mut errors = Vec::new();
    for snapshot in snapshots {
        let result = if let Some(bytes) = snapshot.bytes.as_deref() {
            atomic_write(&snapshot.path, bytes).map_err(|err| err.to_string())
        } else {
            match fs::remove_file(&snapshot.path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err.to_string()),
            }
        };
        if let Err(err) = result {
            errors.push(format!("{}: {err}", snapshot.path.display()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn restore_path<'a>(paths: &'a Paths, name: &str) -> Result<&'a Path, String> {
    match name {
        "klaxond.toml" => Ok(&paths.config),
        "render-config.json" => Ok(&paths.render_config),
        "ntfy-topics.json" => Ok(&paths.ntfy_topics),
        "dedup-config.json" => Ok(&paths.dedup_config),
        "auth-config.json" => Ok(&paths.auth_config),
        _ => Err(format!("unsupported restore file {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_support::temp_paths;
    use crate::config::{AuthConfig, save_auth};
    use tempfile::TempDir;

    #[test]
    fn staged_partial_restore_preserves_unmentioned_sidecars() {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let paths = temp_paths(&tmp);
        let mut auth = AuthConfig {
            mode: "basic".to_string(),
            ..AuthConfig::default()
        };
        auth.basic.username = "staged-user".to_string();
        save_auth(&paths, &auth).unwrap();
        let state = AppState::new(paths).unwrap();
        let input = parse_restore_input(&Bytes::from_static(
            b"[delivery]\nseverity_floor = \"warning\"\n",
        ))
        .unwrap();

        let staged = prepare_runtime_config(&state, &input).unwrap();

        assert_eq!(staged.auth.mode, "basic");
        assert_eq!(staged.auth.basic.username, "staged-user");
    }
}
