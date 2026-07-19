use super::config_admin::persist_reload;
use super::{json_body, json_response, json_to_toml, text};
use crate::config::{DEDUP_SOURCES, DedupSetting, default_dedup, save_dedup};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

mod channel;
mod ntfy_topics;
mod render;
#[cfg(test)]
mod tests;

pub(super) use self::channel::update_channel_config;
pub(super) use self::ntfy_topics::update_ntfy_topics;
pub(super) use self::render::{render_preview, update_render_config};

pub(super) fn cascade_toggle(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let next = if let Some(v) = payload.get("enabled").and_then(|v| v.as_bool()) {
        v
    } else {
        !state.cascade_runtime_enabled.load(Ordering::Relaxed)
    };
    state.cascade_runtime_enabled.store(next, Ordering::Relaxed);
    json_response(json!({"cascade_enabled_runtime": next}))
}

pub(super) fn update_dedup_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Ok(request) = DedupConfigRequest::from_value(payload) else {
        return text(StatusCode::BAD_REQUEST, "missing 'settings' object");
    };
    state
        .with_config_write_lock(move || {
            let current = state.cfg();
            let cleaned = request.into_settings(default_dedup(), &current.dedup);
            if let Err(err) = save_dedup(&state.paths, &cleaned) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            let mut cfg = current;
            cfg.dedup = cleaned.clone();
            state.replace_config(cfg);
            json_response(json!({"ok": true, "settings": cleaned}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

#[derive(Debug, Default)]
struct DedupConfigRequest {
    settings: HashMap<String, DedupSettingPatch>,
}

impl DedupConfigRequest {
    fn from_value(value: Value) -> Result<Self, ()> {
        let settings = value
            .get("settings")
            .and_then(Value::as_object)
            .ok_or(())?
            .iter()
            .filter(|(_, patch)| patch.is_object())
            .map(|(source, patch)| {
                (
                    source.clone(),
                    serde_json::from_value::<DedupSettingPatch>(patch.clone()).unwrap_or_default(),
                )
            })
            .collect();
        Ok(Self { settings })
    }

    fn into_settings(
        self,
        mut settings: HashMap<String, DedupSetting>,
        current: &HashMap<String, DedupSetting>,
    ) -> HashMap<String, DedupSetting> {
        for source in DEDUP_SOURCES {
            if let (Some(setting), Some(current)) =
                (settings.get_mut(*source), current.get(*source))
            {
                setting.repeat_suppression_enabled = current.repeat_suppression_enabled;
                setting.repeat_window_s = current.repeat_window_s;
                setting.repeat_override_critical = current.repeat_override_critical;
            }
            if let Some(patch) = self.settings.get(*source)
                && let Some(setting) = settings.get_mut(*source)
            {
                patch.apply_to(setting);
            }
        }
        settings
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct DedupSettingPatch {
    #[serde(default, deserialize_with = "optional_bool")]
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "optional_u64")]
    window_s: Option<u64>,
    #[serde(default, deserialize_with = "optional_string")]
    strategy: Option<String>,
    #[serde(default, deserialize_with = "optional_bool")]
    override_critical: Option<bool>,
    #[serde(default, deserialize_with = "optional_bool")]
    repeat_suppression_enabled: Option<bool>,
    #[serde(default, deserialize_with = "optional_u64")]
    repeat_window_s: Option<u64>,
    #[serde(default, deserialize_with = "optional_bool")]
    repeat_override_critical: Option<bool>,
}

impl DedupSettingPatch {
    fn apply_to(&self, setting: &mut DedupSetting) {
        if let Some(enabled) = self.enabled {
            setting.enabled = enabled;
        }
        if let Some(window_s) = self.window_s {
            setting.window_s = window_s.clamp(5, 3600);
        }
        if let Some(strategy) = self.strategy.as_deref()
            && matches!(strategy, "none" | "time" | "key")
        {
            setting.strategy = strategy.to_string();
        }
        if let Some(override_critical) = self.override_critical {
            setting.override_critical = override_critical;
        }
        if let Some(enabled) = self.repeat_suppression_enabled {
            setting.repeat_suppression_enabled = enabled;
        }
        if let Some(window_s) = self.repeat_window_s {
            setting.repeat_window_s = window_s.clamp(60, 604_800);
        }
        if let Some(override_critical) = self.repeat_override_critical {
            setting.repeat_override_critical = override_critical;
        }
    }
}

fn optional_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Bool(value)) => Some(value),
        _ => None,
    })
}

fn optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(value)) => value.as_u64(),
        _ => None,
    })
}

fn optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::String(value)) => Some(value),
        _ => None,
    })
}

pub(super) fn update_cascade_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Ok(request) = CascadeConfigRequest::from_value(payload) else {
        return text(StatusCode::BAD_REQUEST, "tiers must be a non-empty list");
    };
    let tiers = request.tier_values();
    if tiers.is_empty() {
        return text(StatusCode::BAD_REQUEST, "no valid tiers");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            {
                let cas = toml_table_mut(&mut cfg.toml, &["cascade"]);
                cas.insert("tiers".into(), json_to_toml(Value::Array(tiers.clone())));
                if let Some(v) = request.default_enabled_for_webhook {
                    cas.insert(
                        "default_enabled_for_webhook".into(),
                        toml::Value::Boolean(v),
                    );
                }
            }
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true, "tiers": state.cfg().tiers})))
                .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

#[derive(Debug, Default)]
struct CascadeConfigRequest {
    tiers: Vec<CascadeTierPatch>,
    default_enabled_for_webhook: Option<bool>,
}

impl CascadeConfigRequest {
    fn from_value(value: Value) -> Result<Self, ()> {
        let tiers = value
            .get("tiers")
            .and_then(Value::as_array)
            .ok_or(())?
            .iter()
            .filter(|tier| tier.is_object())
            .map(|tier| {
                serde_json::from_value::<CascadeTierPatch>(tier.clone()).unwrap_or_default()
            })
            .collect();
        let default_enabled_for_webhook = value
            .get("default_enabled_for_webhook")
            .and_then(Value::as_bool);
        Ok(Self {
            tiers,
            default_enabled_for_webhook,
        })
    }

    fn tier_values(&self) -> Vec<Value> {
        self.tiers
            .iter()
            .filter_map(CascadeTierPatch::to_tier_value)
            .collect()
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CascadeTierPatch {
    #[serde(default, deserialize_with = "optional_string")]
    name: Option<String>,
    #[serde(default, deserialize_with = "optional_u64")]
    timeout_seconds: Option<u64>,
}

impl CascadeTierPatch {
    fn to_tier_value(&self) -> Option<Value> {
        let name = self.name.as_deref().unwrap_or("").to_ascii_lowercase();
        if !matches!(name.as_str(), "ntfy" | "telegram" | "smtp") {
            return None;
        }
        Some(json!({
            "name": name,
            "timeout_seconds": self.timeout_seconds.unwrap_or(5).clamp(1, 60),
        }))
    }
}

pub(super) fn update_delivery_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let delivery = toml_table_mut(&mut cfg.toml, &["delivery"]);
            if let Some(v) = payload.get("default_policy").and_then(|v| v.as_str()) {
                delivery.insert("default_policy".into(), toml::Value::String(v.into()));
            }
            if let Some(p) = payload.get("policies") {
                delivery.insert("policies".into(), json_to_toml(p.clone()));
            }
            if let Some(r) = payload.get("rules") {
                delivery.insert("rules".into(), json_to_toml(r.clone()));
            }
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true})))
                .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}
