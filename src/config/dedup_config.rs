use super::{DEDUP_SOURCES, DedupSetting, Paths, default_dedup, default_dedup_setting};
use crate::util::atomic_write_json;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;

pub(super) fn load_dedup(
    paths: &Paths,
    seed: Option<&toml::Value>,
    custom_sources: impl Iterator<Item = impl AsRef<str>>,
) -> Result<HashMap<String, DedupSetting>> {
    let custom_sources = custom_sources
        .map(|source| source.as_ref().to_string())
        .collect::<Vec<_>>();
    if paths.dedup_config.exists() {
        let mut out = default_dedup();
        let raw: HashMap<String, DedupSetting> =
            serde_json::from_slice(&fs::read(&paths.dedup_config)?)?;
        let supported = DEDUP_SOURCES
            .iter()
            .map(|source| (*source).to_string())
            .chain(custom_sources.iter().cloned())
            .collect::<HashSet<_>>();
        let missing_supported_source = DEDUP_SOURCES
            .iter()
            .copied()
            .chain(custom_sources.iter().map(String::as_str))
            .any(|source| !raw.contains_key(source));
        let stale_source = raw.keys().any(|source| !supported.contains(source));
        for (k, mut v) in raw {
            if !supported.contains(&k) {
                continue;
            }
            normalize_setting(&mut v);
            out.insert(k, v);
        }
        for source in &custom_sources {
            out.entry(source.clone())
                .or_insert_with(default_dedup_setting);
        }
        if missing_supported_source || stale_source {
            save_dedup(paths, &out)?;
        }
        return Ok(out);
    }
    let out = dedup_from_toml(seed, custom_sources.iter());
    save_dedup(paths, &out)?;
    Ok(out)
}

pub(super) fn dedup_from_toml(
    seed: Option<&toml::Value>,
    custom_sources: impl Iterator<Item = impl AsRef<str>>,
) -> HashMap<String, DedupSetting> {
    let mut out = default_dedup();
    for source in custom_sources {
        out.entry(source.as_ref().to_string())
            .or_insert_with(default_dedup_setting);
    }
    if let Some(seed_table) = seed.and_then(|v| v.as_table()) {
        for (src, s) in &mut out {
            if let Some(t) = seed_table.get(src).and_then(|v| v.as_table()) {
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
                if let Some(value) = t.get("rules") {
                    match value.clone().try_into() {
                        Ok(rules) => s.rules = rules,
                        Err(error) => tracing::warn!(
                            source = src,
                            %error,
                            "ignoring invalid TOML noise-control rules"
                        ),
                    }
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
    setting.rules.iter_mut().for_each(|rule| rule.normalize());
}
