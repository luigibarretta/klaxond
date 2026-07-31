use super::config_admin::persist_reload;
use super::{json_body, json_response, json_to_toml, text};
use crate::config::{
    DEDUP_SOURCES, DedupSetting, NTFY_RECOMMENDED_TIMEOUT_SECONDS, NoiseControlRule,
    TIER_TIMEOUT_MAX_SECONDS, TIER_TIMEOUT_MIN_SECONDS, default_dedup, save_dedup,
};
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
    let request = match DedupConfigRequest::from_value(payload) {
        Ok(request) => request,
        Err(error) => return text(StatusCode::BAD_REQUEST, &error),
    };
    state
        .with_config_write_lock(move || {
            let current = state.cfg();
            let cleaned = match request.into_settings(default_dedup(), &current.dedup) {
                Ok(cleaned) => cleaned,
                Err(error) => return text(StatusCode::BAD_REQUEST, &error),
            };
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
    fn from_value(value: Value) -> Result<Self, String> {
        let raw_settings = value
            .get("settings")
            .and_then(Value::as_object)
            .ok_or_else(|| "missing 'settings' object".to_string())?;
        let mut settings = HashMap::new();
        for (source, patch) in raw_settings {
            if !patch.is_object() {
                continue;
            }
            let patch = serde_json::from_value::<DedupSettingPatch>(patch.clone())
                .map_err(|error| format!("settings.{source}: {error}"))?;
            settings.insert(source.clone(), patch);
        }
        Ok(Self { settings })
    }

    fn into_settings(
        self,
        mut settings: HashMap<String, DedupSetting>,
        current: &HashMap<String, DedupSetting>,
    ) -> Result<HashMap<String, DedupSetting>, String> {
        for source in DEDUP_SOURCES {
            if let (Some(setting), Some(current)) =
                (settings.get_mut(*source), current.get(*source))
            {
                setting.repeat_suppression_enabled = current.repeat_suppression_enabled;
                setting.repeat_window_s = current.repeat_window_s;
                setting.repeat_override_critical = current.repeat_override_critical;
                setting.rules = current.rules.clone();
            }
            if let Some(patch) = self.settings.get(*source)
                && let Some(setting) = settings.get_mut(*source)
            {
                patch.apply_to(setting);
            }
            if let Some(setting) = settings.get(*source) {
                if setting.rules.len() > 50 {
                    return Err(format!(
                        "settings.{source}.rules: at most 50 rules are allowed"
                    ));
                }
                for (index, rule) in setting.rules.iter().enumerate() {
                    rule.validate().map_err(|error| {
                        format!("settings.{source}.rules[{index}] ({}): {error}", rule.name)
                    })?;
                }
            }
        }
        Ok(settings)
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
    #[serde(default)]
    rules: Option<Vec<NoiseControlRule>>,
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
        if let Some(mut rules) = self.rules.clone() {
            rules.iter_mut().for_each(NoiseControlRule::normalize);
            setting.rules = rules;
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
    let request = match CascadeConfigRequest::from_value(payload) {
        Ok(request) => request,
        Err(error) => return text(StatusCode::BAD_REQUEST, &error),
    };
    let tiers = request.tier_values();
    let warnings = request.warnings();
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
                .map(|_| {
                    json_response(json!({
                        "ok": true,
                        "tiers": state.cfg().tiers,
                        "warnings": warnings,
                    }))
                })
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
    fn from_value(value: Value) -> Result<Self, String> {
        let raw_tiers = value
            .get("tiers")
            .and_then(Value::as_array)
            .ok_or_else(|| "tiers must be a non-empty list".to_string())?;
        if raw_tiers.is_empty() {
            return Err("tiers must be a non-empty list".to_string());
        }
        let mut tiers = Vec::with_capacity(raw_tiers.len());
        for (index, tier) in raw_tiers.iter().enumerate() {
            let tier = tier
                .as_object()
                .ok_or_else(|| format!("tiers[{index}] must be an object"))?;
            let name = tier
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("tiers[{index}].name must be a string"))?
                .to_ascii_lowercase();
            if !matches!(name.as_str(), "ntfy" | "telegram" | "smtp") {
                return Err(format!("tiers[{index}].name is not a supported channel"));
            }
            let timeout_seconds = tier
                .get("timeout_seconds")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    format!(
                        "tiers[{index}].timeout_seconds must be an integer between \
                         {TIER_TIMEOUT_MIN_SECONDS} and {TIER_TIMEOUT_MAX_SECONDS}"
                    )
                })?;
            if !(TIER_TIMEOUT_MIN_SECONDS..=TIER_TIMEOUT_MAX_SECONDS).contains(&timeout_seconds) {
                return Err(format!(
                    "tiers[{index}].timeout_seconds must be between \
                     {TIER_TIMEOUT_MIN_SECONDS} and {TIER_TIMEOUT_MAX_SECONDS}"
                ));
            }
            tiers.push(CascadeTierPatch {
                name,
                timeout_seconds,
            });
        }
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
            .map(CascadeTierPatch::to_tier_value)
            .collect()
    }

    fn warnings(&self) -> Vec<Value> {
        self.tiers
            .iter()
            .filter(|tier| {
                tier.name == "ntfy" && tier.timeout_seconds < NTFY_RECOMMENDED_TIMEOUT_SECONDS
            })
            .map(|tier| {
                json!({
                    "code": "ntfy_timeout_below_recommended",
                    "tier": tier.name,
                    "timeout_seconds": tier.timeout_seconds,
                    "recommended_seconds": NTFY_RECOMMENDED_TIMEOUT_SECONDS,
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
struct CascadeTierPatch {
    name: String,
    timeout_seconds: u64,
}

impl CascadeTierPatch {
    fn to_tier_value(&self) -> Value {
        json!({
            "name": self.name,
            "timeout_seconds": self.timeout_seconds,
        })
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
