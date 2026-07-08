use super::{config_auto_backup, config_full_export_payload};
use crate::auth::User;
use crate::config::{
    AuthConfig, DedupSetting, NtfyTopic, load_runtime_config, restore_sidecars_from_toml,
};
use crate::state::AppState;
use crate::util::atomic_write;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};
use std::collections::HashMap;

use super::super::{json_response, text};

struct RestoreInput {
    source_kind: &'static str,
    toml_text: String,
    parsed: toml::Value,
    sidecars: Vec<BundleSidecar>,
}

struct BundleSidecar {
    name: &'static str,
    text: String,
}

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

fn validate_restore_input(input: &RestoreInput) -> Result<(), String> {
    if !["cascade", "delivery", "render", "ntfy", "auth"]
        .iter()
        .any(|k| input.parsed.get(k).is_some())
    {
        return Err("no recognised top-level sections; refusing as likely empty".into());
    }
    Ok(())
}

fn restore_input_files(input: &RestoreInput) -> Vec<(&'static str, &str)> {
    let mut files = vec![("klaxond.toml", input.toml_text.as_str())];
    for sidecar in &input.sidecars {
        files.push((sidecar.name, sidecar.text.as_str()));
    }
    files
}

fn restore_input_would_restore(input: &RestoreInput) -> Vec<&'static str> {
    let mut names = restore_input_files(input)
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();
    if input.sidecars.is_empty() {
        if input
            .parsed
            .get("render")
            .and_then(|v| v.get("component_dashboards"))
            .is_some()
        {
            push_unique(&mut names, "render-config.json");
        }
        if input.parsed.get("dedup").is_some() {
            push_unique(&mut names, "dedup-config.json");
        }
        if input.parsed.get("auth").is_some() {
            push_unique(&mut names, "auth-config.json");
        }
        if input
            .parsed
            .get("ntfy")
            .and_then(|v| v.get("topics"))
            .is_some()
        {
            push_unique(&mut names, "ntfy-topics.json");
        }
    }
    names
}

fn push_unique(list: &mut Vec<&'static str>, value: &'static str) {
    if !list.contains(&value) {
        list.push(value);
    }
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

fn parse_restore_input(body: &Bytes) -> Result<RestoreInput, String> {
    let text_body = String::from_utf8(body.to_vec()).map_err(|e| format!("invalid UTF-8: {e}"))?;
    if text_body.trim_start().starts_with('{') {
        return parse_restore_bundle(&text_body);
    }
    let parsed: toml::Value =
        toml::from_str(&text_body).map_err(|e| format!("invalid TOML: {e}"))?;
    Ok(RestoreInput {
        source_kind: "toml",
        toml_text: text_body,
        parsed,
        sidecars: Vec::new(),
    })
}

fn parse_restore_bundle(raw: &str) -> Result<RestoreInput, String> {
    let bundle: Value = serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    if bundle.get("kind").and_then(Value::as_str) != Some("klaxond.full-settings") {
        return Err("JSON bundle kind must be klaxond.full-settings".into());
    }
    if bundle
        .get("format_version")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        != 1
    {
        return Err("unsupported config bundle format_version".into());
    }
    let files = bundle
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| "bundle missing files object".to_string())?;
    let allowed_files = [
        "klaxond.toml",
        "render-config.json",
        "ntfy-topics.json",
        "dedup-config.json",
        "auth-config.json",
    ];
    for name in files.keys() {
        if !allowed_files.contains(&name.as_str()) {
            return Err(format!("unsupported sidecar {name}"));
        }
    }
    let toml_text = bundle_file(files, "klaxond.toml")?
        .ok_or_else(|| "bundle missing files.klaxond.toml".to_string())?;
    let parsed: toml::Value =
        toml::from_str(&toml_text).map_err(|e| format!("invalid bundled TOML: {e}"))?;
    let mut sidecars = Vec::new();
    for name in [
        "render-config.json",
        "ntfy-topics.json",
        "dedup-config.json",
        "auth-config.json",
    ] {
        let Some(text) = bundle_file(files, name)? else {
            return Err(format!("bundle missing files.{name}"));
        };
        validate_bundle_sidecar(name, &text)?;
        sidecars.push(BundleSidecar { name, text });
    }
    Ok(RestoreInput {
        source_kind: "full-bundle",
        toml_text,
        parsed,
        sidecars,
    })
}

fn bundle_file(
    files: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<String>, String> {
    files
        .get(name)
        .map(|v| {
            v.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("files.{name} must be a string"))
        })
        .transpose()
}

fn validate_bundle_sidecar(name: &str, raw: &str) -> Result<(), String> {
    match name {
        "render-config.json" => {
            let v: Value = serde_json::from_str(raw).map_err(|e| format!("invalid {name}: {e}"))?;
            if !v
                .get("component_dashboards")
                .and_then(Value::as_object)
                .map(|_| true)
                .unwrap_or(false)
            {
                return Err(format!("{name} must contain component_dashboards object"));
            }
        }
        "ntfy-topics.json" => {
            let v: Value = serde_json::from_str(raw).map_err(|e| format!("invalid {name}: {e}"))?;
            let arr = v
                .get("topics")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{name} must contain topics array"))?;
            for topic in arr {
                serde_json::from_value::<NtfyTopic>(topic.clone())
                    .map_err(|e| format!("invalid topic in {name}: {e}"))?;
            }
        }
        "dedup-config.json" => {
            serde_json::from_str::<HashMap<String, DedupSetting>>(raw)
                .map_err(|e| format!("invalid {name}: {e}"))?;
        }
        "auth-config.json" => {
            serde_json::from_str::<AuthConfig>(raw).map_err(|e| format!("invalid {name}: {e}"))?;
        }
        _ => return Err(format!("unsupported sidecar {name}")),
    }
    Ok(())
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
