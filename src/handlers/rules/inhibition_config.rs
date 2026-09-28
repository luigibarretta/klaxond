use super::persist_toml_section;
use crate::config::InhibitionRule;
use crate::handlers::config_admin::persist_reload;
use crate::handlers::{json_body, json_response, text};
use crate::inhibition;
use crate::state::{AppState, lock_mutex};
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};

pub(in crate::handlers) fn update_inhibition_rules(
    state: &AppState,
    body: Bytes,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(rules) = payload.get("rules").and_then(Value::as_array) else {
        return text(StatusCode::BAD_REQUEST, "rules must be a list");
    };
    let available_sources = state.with_cfg(|cfg| cfg.dedup.keys().cloned().collect::<Vec<_>>());
    let cleaned = match parse_rules(rules, &available_sources) {
        Ok(cleaned) => cleaned,
        Err(errors) => return text(StatusCode::BAD_REQUEST, &errors.join("\n")),
    };
    match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        persist_toml_section(&mut cfg.toml, "inhibitions", &cleaned)?;
        persist_reload(state, cfg.toml)
    }) {
        Ok(Ok(())) => {}
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
    let cleared = {
        let mut suppressions = lock_mutex(&state.suppressions, "suppressions");
        let count = suppressions.len();
        suppressions.clear();
        count
    };
    json_response(json!({
        "ok": true,
        "count": cleaned.len(),
        "cleared_suppressions": cleared,
    }))
}

fn parse_rules(
    values: &[Value],
    available_sources: &[String],
) -> Result<Vec<InhibitionRule>, Vec<String>> {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for (index, value) in values.iter().enumerate() {
        match parse_rule(index, value, available_sources) {
            Ok(rule) => rules.push(rule),
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(errors)
    }
}

fn parse_rule(
    index: usize,
    value: &Value,
    available_sources: &[String],
) -> Result<InhibitionRule, String> {
    let source = string_field(value, "source").unwrap_or_default();
    if source.is_empty() {
        return Err(format!("rule[{index}]: source is required"));
    }
    match match_type_count(value) {
        0 => {
            return Err(format!(
                "rule[{index}] ({source}): one of match_by / match_label+match_regex / match_all is required"
            ));
        }
        1 => {}
        _ => {
            return Err(format!(
                "rule[{index}] ({source}): only one match type may be set"
            ));
        }
    }
    let rule = InhibitionRule {
        source,
        match_by: string_field(value, "match_by"),
        match_label: string_field(value, "match_label"),
        match_regex: string_field(value, "match_regex"),
        match_all: value
            .get("match_all")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        applies_to: source_list(value, "applies_to", available_sources),
        ttl_seconds: value
            .get("ttl_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(900)
            .clamp(30, 86400),
    };
    inhibition::validate_regex(&rule)
        .map_err(|error| format!("rule[{index}] regex invalid: {error}"))?;
    Ok(rule)
}

fn match_type_count(value: &Value) -> u8 {
    u8::from(nonempty_raw_string(value, "match_by"))
        + u8::from(
            value
                .get("match_all")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        )
        + u8::from(
            nonempty_raw_string(value, "match_label") && nonempty_raw_string(value, "match_regex"),
        )
}

fn nonempty_raw_string(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn source_list(value: &Value, key: &str, available_sources: &[String]) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .filter(|source| available_sources.contains(source))
                .collect()
        })
        .unwrap_or_default()
}
