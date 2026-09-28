use super::super::config_admin::persist_reload;
use super::{json_body, json_response, json_to_toml, text};
use crate::config::{DeliveryConfig, DeliveryPolicy, DeliveryRule};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

pub(in crate::handlers) fn update_delivery_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let request = match DeliveryConfigPatch::from_value(payload) {
        Ok(request) => request,
        Err(error) => return text(StatusCode::BAD_REQUEST, &error),
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            if let Err(error) = request.validate_against(&cfg.delivery) {
                return text(StatusCode::BAD_REQUEST, &error);
            }
            request.apply_to(toml_table_mut(&mut cfg.toml, &["delivery"]));
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true})))
                .unwrap_or_else(|error| text(StatusCode::INTERNAL_SERVER_ERROR, &error))
        })
        .unwrap_or_else(|error| text(StatusCode::INTERNAL_SERVER_ERROR, &error))
}

#[derive(Debug, Deserialize)]
struct DeliveryConfigPatch {
    #[serde(default)]
    default_policy: Option<String>,
    #[serde(default)]
    policies: Option<Vec<DeliveryPolicy>>,
    #[serde(default)]
    rules: Option<Vec<DeliveryRule>>,
}

impl DeliveryConfigPatch {
    fn from_value(value: Value) -> Result<Self, String> {
        serde_json::from_value(value).map_err(|error| format!("invalid delivery config: {error}"))
    }

    fn validate_against(&self, current: &DeliveryConfig) -> Result<(), String> {
        let mut prospective = current.clone();
        if let Some(default_policy) = &self.default_policy {
            prospective.default_policy.clone_from(default_policy);
        }
        if let Some(policies) = &self.policies {
            prospective.policies.clone_from(policies);
        }
        if let Some(rules) = &self.rules {
            prospective.rules.clone_from(rules);
        }
        prospective.validate()
    }

    fn apply_to(self, delivery: &mut toml::map::Map<String, toml::Value>) {
        if let Some(value) = self.default_policy {
            delivery.insert("default_policy".into(), toml::Value::String(value));
        }
        if let Some(policies) = self.policies {
            delivery.insert("policies".into(), serialized_toml(policies));
        }
        if let Some(rules) = self.rules {
            delivery.insert("rules".into(), serialized_toml(rules));
        }
    }
}

fn serialized_toml<T: serde::Serialize>(value: T) -> toml::Value {
    let json = serde_json::to_value(value).expect("serializable delivery configuration");
    json_to_toml(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn current_config() -> DeliveryConfig {
        DeliveryConfig::default()
    }

    #[test]
    fn delivery_patch_accepts_valid_regex_and_references() {
        let request = DeliveryConfigPatch::from_value(json!({
            "default_policy": "ops",
            "policies": [{
                "name": "ops",
                "mode": "broadcast",
                "tiers": [{"name": "ntfy", "timeout_seconds": 15}]
            }],
            "rules": [{
                "match": {"host": "re:^prod-[0-9]+$"},
                "policy": "ops"
            }]
        }))
        .expect("valid request");

        assert!(request.validate_against(&current_config()).is_ok());
    }

    #[test]
    fn delivery_patch_rejects_invalid_regex() {
        let request = DeliveryConfigPatch::from_value(json!({
            "rules": [{"match": {"host": "re:["}, "policy": "cascade"}]
        }))
        .expect("typed request");

        let error = request
            .validate_against(&current_config())
            .expect_err("invalid regex must fail");
        assert!(error.contains("rule 1"));
        assert!(error.contains("invalid regex"));
    }

    #[test]
    fn delivery_patch_rejects_unknown_policy_references() {
        let request = DeliveryConfigPatch::from_value(json!({
            "default_policy": "missing",
            "policies": [],
            "rules": []
        }))
        .expect("typed request");

        assert_eq!(
            request
                .validate_against(&current_config())
                .expect_err("unknown policy must fail"),
            "unknown default delivery policy 'missing'"
        );
    }
}
