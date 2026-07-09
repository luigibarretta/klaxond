use crate::config::{AuthConfig, DedupSetting, NtfyTopic};
use axum::body::Bytes;
use serde_json::Value;
use std::collections::HashMap;

pub(super) struct RestoreInput {
    pub(super) source_kind: &'static str,
    pub(super) toml_text: String,
    pub(super) parsed: toml::Value,
    pub(super) sidecars: Vec<BundleSidecar>,
}

pub(super) struct BundleSidecar {
    pub(super) name: &'static str,
    pub(super) text: String,
}

pub(super) fn parse_restore_input(body: &Bytes) -> Result<RestoreInput, String> {
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

pub(super) fn validate_restore_input(input: &RestoreInput) -> Result<(), String> {
    if !["cascade", "delivery", "render", "ntfy", "auth"]
        .iter()
        .any(|k| input.parsed.get(k).is_some())
    {
        return Err("no recognised top-level sections; refusing as likely empty".into());
    }
    Ok(())
}

pub(super) fn restore_input_files(input: &RestoreInput) -> Vec<(&'static str, &str)> {
    let mut files = vec![("klaxond.toml", input.toml_text.as_str())];
    for sidecar in &input.sidecars {
        files.push((sidecar.name, sidecar.text.as_str()));
    }
    files
}

pub(super) fn restore_input_would_restore(input: &RestoreInput) -> Vec<&'static str> {
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

fn push_unique(list: &mut Vec<&'static str>, value: &'static str) {
    if !list.contains(&value) {
        list.push(value);
    }
}
