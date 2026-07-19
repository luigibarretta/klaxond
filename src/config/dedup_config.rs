use super::{DEDUP_SOURCES, DedupSetting, Paths, default_dedup};
use crate::util::atomic_write_json;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;

pub(super) fn load_dedup(
    paths: &Paths,
    seed: Option<&toml::Value>,
) -> Result<HashMap<String, DedupSetting>> {
    if paths.dedup_config.exists() {
        let mut out = default_dedup();
        let raw: HashMap<String, DedupSetting> =
            serde_json::from_slice(&fs::read(&paths.dedup_config)?)?;
        for (k, mut v) in raw {
            normalize_setting(&mut v);
            out.insert(k, v);
        }
        return Ok(out);
    }
    let out = dedup_from_toml(seed);
    save_dedup(paths, &out)?;
    Ok(out)
}

pub(super) fn dedup_from_toml(seed: Option<&toml::Value>) -> HashMap<String, DedupSetting> {
    let mut out = default_dedup();
    if let Some(seed_table) = seed.and_then(|v| v.as_table()) {
        for src in DEDUP_SOURCES {
            if let Some(t) = seed_table.get(*src).and_then(|v| v.as_table())
                && let Some(s) = out.get_mut(*src)
            {
                if let Some(v) = t.get("enabled").and_then(|v| v.as_bool()) {
                    s.enabled = v;
                }
                if let Some(v) = t.get("window_s").and_then(|v| v.as_integer()) {
                    s.window_s = v.max(1) as u64;
                }
                if let Some(v) = t.get("strategy").and_then(|v| v.as_str()) {
                    s.strategy = v.to_string();
                }
                if let Some(v) = t.get("override_critical").and_then(|v| v.as_bool()) {
                    s.override_critical = v;
                }
                if let Some(v) = t
                    .get("repeat_suppression_enabled")
                    .and_then(|v| v.as_bool())
                {
                    s.repeat_suppression_enabled = v;
                }
                if let Some(v) = t.get("repeat_window_s").and_then(|v| v.as_integer()) {
                    s.repeat_window_s = v.clamp(60, 604_800) as u64;
                }
                if let Some(v) = t.get("repeat_override_critical").and_then(|v| v.as_bool()) {
                    s.repeat_override_critical = v;
                }
            }
        }
    }
    out.values_mut().for_each(normalize_setting);
    out
}

pub fn save_dedup(paths: &Paths, settings: &HashMap<String, DedupSetting>) -> Result<()> {
    let normalized = settings
        .iter()
        .map(|(source, setting)| {
            let mut setting = setting.clone();
            normalize_setting(&mut setting);
            (source.clone(), setting)
        })
        .collect::<HashMap<_, _>>();
    atomic_write_json(&paths.dedup_config, &normalized)
}

fn normalize_setting(setting: &mut DedupSetting) {
    setting.repeat_window_s = setting.repeat_window_s.clamp(60, 604_800);
}
