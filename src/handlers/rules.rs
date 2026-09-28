use super::{json_body, json_response, json_to_toml, text};
use crate::state::{AppState, lock_mutex};
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Serialize;
use serde_json::json;

mod inhibition_config;
mod schedules;
mod simulate;

pub(in crate::handlers) use self::inhibition_config::update_inhibition_rules;
pub(in crate::handlers) use self::schedules::update_schedules;
pub(super) use self::simulate::{
    inhibition_regex_validate, inhibition_rules_test, policy_simulate,
};

pub(super) fn clear_acks(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let target = payload
        .get("alertname")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let mut acks = lock_mutex(&state.ack_suppressions, "ack suppressions");
    let before = acks.len();
    if target.is_empty() {
        acks.clear();
    } else {
        acks.remove(&target);
    }
    let after = acks.len();
    json_response(json!({"ok": true, "cleared": before - after, "remaining": after}))
}

fn persist_toml_section<T: Serialize>(
    toml: &mut toml::Value,
    key: &str,
    value: &T,
) -> Result<(), String> {
    let table = toml
        .as_table_mut()
        .ok_or_else(|| "runtime TOML root is not a table".to_string())?;
    let value = serde_json::to_value(value)
        .map_err(|err| format!("serialize {key} config failed: {err}"))?;
    table.insert(key.into(), json_to_toml(value));
    Ok(())
}

pub(super) fn clear_inhibitions(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let clear_all = payload.as_object().map(|o| o.is_empty()).unwrap_or(true)
        || payload
            .get("all")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    let source = payload
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let anchor = payload
        .get("anchor")
        .and_then(|v| v.as_str())
        .map(|s| if s == "*" { None } else { Some(s.to_string()) })
        .unwrap_or(None);
    let cfg = state.cfg();
    let mut suppressions = lock_mutex(&state.suppressions, "suppressions");
    let before = suppressions.len();
    if clear_all {
        suppressions.clear();
    } else {
        if source.is_empty() {
            return text(
                StatusCode::BAD_REQUEST,
                "source is required (or pass {'all': true})",
            );
        }
        suppressions.retain(|s| {
            let rule = cfg.inhibition_rules.get(s.rule_idx);
            !(rule.map(|r| r.source == source).unwrap_or(false)
                && (anchor.is_none() || s.anchor == anchor))
        });
    }
    let after = suppressions.len();
    json_response(json!({"ok": true, "cleared": before - after, "remaining": after}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_toml_section_inserts_serialized_value() {
        let mut toml = toml::Value::Table(toml::map::Map::new());

        persist_toml_section(&mut toml, "items", &vec!["one", "two"]).expect("persist section");

        assert_eq!(
            toml.get("items")
                .and_then(toml::Value::as_array)
                .map(Vec::len),
            Some(2)
        );
    }

    #[test]
    fn persist_toml_section_returns_error_for_non_table_root() {
        let mut toml = toml::Value::String("invalid".to_string());

        let err = persist_toml_section(&mut toml, "items", &vec!["one"]).expect_err("root error");

        assert_eq!(err, "runtime TOML root is not a table");
    }
}
