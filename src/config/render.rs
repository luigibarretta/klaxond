use super::{Paths, default_component_dashboards};
use crate::util::atomic_write_json;
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::fs;

pub(super) fn read_component_dashboards(
    value: Option<&toml::Value>,
) -> HashMap<String, [String; 2]> {
    let mut out = HashMap::new();
    if let Some(table) = value.and_then(|v| v.as_table()) {
        for (k, v) in table {
            if let Some(arr) = v.as_array() {
                let label = arr
                    .first()
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let url = arr
                    .get(1)
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                if !label.is_empty() && !url.is_empty() {
                    out.insert(k.to_string(), [label, url]);
                }
            }
        }
    }
    out
}

pub(super) fn read_component_image(
    value: Option<&toml::Value>,
) -> HashMap<String, (String, Option<u64>)> {
    let mut out = HashMap::new();
    if let Some(table) = value.and_then(|v| v.as_table()) {
        for (comp, spec) in table {
            let s = spec.as_str().unwrap_or("").trim();
            if s.is_empty() {
                continue;
            }
            if let Some((uid, panel)) = s.rsplit_once(':')
                && !uid.is_empty()
            {
                out.insert(
                    comp.to_string(),
                    (uid.to_string(), panel.parse::<u64>().ok()),
                );
                continue;
            }
            out.insert(comp.to_string(), (s.to_string(), None));
        }
    }
    out
}

pub(super) fn load_render_config(
    paths: &Paths,
    seed: &HashMap<String, [String; 2]>,
) -> Result<HashMap<String, [String; 2]>> {
    if paths.render_config.exists() {
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&paths.render_config)?)?;
        let mut out = HashMap::new();
        if let Some(obj) = raw.get("component_dashboards").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                if let Some(arr) = v.as_array() {
                    let label = arr
                        .first()
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let url = arr
                        .get(1)
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !label.is_empty() && !url.is_empty() {
                        out.insert(k.to_string(), [label, url]);
                    }
                }
            }
        }
        return Ok(out);
    }
    let initial = if seed.is_empty() {
        default_component_dashboards()
    } else {
        seed.clone()
    };
    save_render_config(paths, &initial)?;
    Ok(initial)
}

pub fn save_render_config(paths: &Paths, dashboards: &HashMap<String, [String; 2]>) -> Result<()> {
    atomic_write_json(
        &paths.render_config,
        &json!({ "component_dashboards": dashboards }),
    )
}
