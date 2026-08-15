use super::{json_body, json_response, text};
use crate::config::{DEDUP_SOURCES, DedupSetting, NoiseControlRule, default_dedup, save_dedup};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

pub(in crate::handlers) fn update_dedup_config(state: &AppState, body: Bytes) -> Response<Body> {
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
pub(super) struct DedupConfigRequest {
    settings: HashMap<String, DedupSettingPatch>,
}

impl DedupConfigRequest {
    pub(super) fn from_value(value: Value) -> Result<Self, String> {
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

    pub(super) fn into_settings(
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
