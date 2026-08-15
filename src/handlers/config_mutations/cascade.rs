use super::super::config_admin::persist_reload;
use super::{json_body, json_response, json_to_toml, text};
use crate::config::{
    NTFY_RECOMMENDED_TIMEOUT_SECONDS, TIER_TIMEOUT_MAX_SECONDS, TIER_TIMEOUT_MIN_SECONDS,
};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};

pub(in crate::handlers) fn update_cascade_config(state: &AppState, body: Bytes) -> Response<Body> {
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
                if let Some(value) = request.default_enabled_for_webhook {
                    cas.insert(
                        "default_enabled_for_webhook".into(),
                        toml::Value::Boolean(value),
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
                .unwrap_or_else(|error| text(StatusCode::INTERNAL_SERVER_ERROR, &error))
        })
        .unwrap_or_else(|error| text(StatusCode::INTERNAL_SERVER_ERROR, &error))
}

#[derive(Debug, Default)]
pub(super) struct CascadeConfigRequest {
    tiers: Vec<CascadeTierPatch>,
    pub(super) default_enabled_for_webhook: Option<bool>,
}

impl CascadeConfigRequest {
    pub(super) fn from_value(value: Value) -> Result<Self, String> {
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

    pub(super) fn tier_values(&self) -> Vec<Value> {
        self.tiers
            .iter()
            .map(CascadeTierPatch::to_tier_value)
            .collect()
    }

    pub(super) fn warnings(&self) -> Vec<Value> {
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
