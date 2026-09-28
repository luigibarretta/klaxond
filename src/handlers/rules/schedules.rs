use super::persist_toml_section;
use crate::config::Schedule;
use crate::handlers::config_admin::persist_reload;
use crate::handlers::{json_body, json_response, text};
use crate::state::{AppState, lock_mutex};
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

pub(in crate::handlers) fn update_schedules(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(schedules) = payload.get("schedules").and_then(Value::as_array) else {
        return text(StatusCode::BAD_REQUEST, "schedules must be a list");
    };
    let available_sources = state.with_cfg(|cfg| cfg.dedup.keys().cloned().collect::<Vec<_>>());
    let cleaned = match parse_schedules(schedules, &available_sources) {
        Ok(cleaned) => cleaned,
        Err(errors) => return text(StatusCode::BAD_REQUEST, &errors.join("\n")),
    };
    match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        persist_toml_section(&mut cfg.toml, "schedules", &cleaned)?;
        persist_reload(state, cfg.toml)
    }) {
        Ok(Ok(())) => {}
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
    retain_active_schedules(state, &cleaned);
    json_response(json!({"ok": true, "count": cleaned.len()}))
}

fn parse_schedules(
    values: &[Value],
    available_sources: &[String],
) -> Result<Vec<Schedule>, Vec<String>> {
    let mut schedules = Vec::new();
    let mut errors = Vec::new();
    for (index, value) in values.iter().enumerate() {
        match parse_schedule(index, value, available_sources) {
            Ok(schedule) => schedules.push(schedule),
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(schedules)
    } else {
        Err(errors)
    }
}

fn parse_schedule(
    index: usize,
    value: &Value,
    available_sources: &[String],
) -> Result<Schedule, String> {
    let name = string_field(value, "name");
    let cron = string_field(value, "cron");
    if name.is_empty() {
        return Err(format!("schedule[{index}]: name required"));
    }
    if cron.split_whitespace().count() != 5 {
        return Err(format!(
            "schedule[{index}] ({name}): cron must have 5 fields"
        ));
    }
    let duration_minutes = value
        .get("duration_minutes")
        .and_then(Value::as_u64)
        .unwrap_or(30);
    if !(1..=1440).contains(&duration_minutes) {
        return Err(format!(
            "schedule[{index}] ({name}): duration_minutes must be 1..1440"
        ));
    }
    Ok(Schedule {
        name,
        cron,
        duration_minutes,
        r#match: match_labels(value),
        applies_to: applies_to(value, available_sources),
    })
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn match_labels(value: &Value) -> HashMap<String, String> {
    value
        .get("match")
        .and_then(Value::as_object)
        .map(|labels| {
            labels
                .iter()
                .filter_map(|(key, value)| {
                    value
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn applies_to(value: &Value, available_sources: &[String]) -> Vec<String> {
    value
        .get("applies_to")
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

fn retain_active_schedules(state: &AppState, schedules: &[Schedule]) {
    let names = schedules
        .iter()
        .map(|schedule| schedule.name.clone())
        .collect::<HashSet<_>>();
    lock_mutex(&state.active_mutes, "active mutes").retain(|name, _| names.contains(name));
}
