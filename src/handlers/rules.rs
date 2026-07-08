use super::config_admin::persist_reload;
use super::{json_body, json_response, json_to_toml, text};
use crate::config::{DEDUP_SOURCES, InhibitionRule, Schedule};
use crate::inhibition;
use crate::state::{AppState, lock_mutex};
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::json;

mod simulate;

pub(super) use self::simulate::{inhibition_rules_test, policy_simulate};

pub(super) fn update_inhibition_rules(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(arr) = payload.get("rules").and_then(|v| v.as_array()) else {
        return text(StatusCode::BAD_REQUEST, "rules must be a list");
    };
    let mut cleaned = Vec::new();
    let mut errors = Vec::new();
    for (i, r) in arr.iter().enumerate() {
        let source = r
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if source.is_empty() {
            errors.push(format!("rule[{i}]: source is required"));
            continue;
        }
        let ttl = r
            .get("ttl_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(900)
            .clamp(30, 86400);
        let match_types = (r
            .get("match_by")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .is_some() as u8)
            + (r.get("match_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false) as u8)
            + ((r
                .get("match_label")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .is_some()
                && r.get("match_regex")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .is_some()) as u8);
        if match_types == 0 {
            errors.push(format!("rule[{i}] ({source}): one of match_by / match_label+match_regex / match_all is required"));
            continue;
        }
        if match_types > 1 {
            errors.push(format!(
                "rule[{i}] ({source}): only one match type may be set"
            ));
            continue;
        }
        let rule = InhibitionRule {
            source,
            match_by: r
                .get("match_by")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            match_label: r
                .get("match_label")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            match_regex: r
                .get("match_regex")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            match_all: r
                .get("match_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            applies_to: r
                .get("applies_to")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                        .filter(|s| DEDUP_SOURCES.contains(&s.as_str()))
                        .collect()
                })
                .unwrap_or_default(),
            ttl_seconds: ttl,
        };
        if let Err(err) = inhibition::validate_regex(&rule) {
            errors.push(format!("rule[{i}] regex invalid: {err}"));
            continue;
        }
        cleaned.push(rule);
    }
    if !errors.is_empty() {
        return text(StatusCode::BAD_REQUEST, &errors.join("\n"));
    }
    match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        cfg.toml.as_table_mut().unwrap().insert(
            "inhibitions".into(),
            json_to_toml(serde_json::to_value(&cleaned).unwrap()),
        );
        persist_reload(state, cfg.toml)
    }) {
        Ok(Ok(())) => {}
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
    let cleared = {
        let mut s = lock_mutex(&state.suppressions, "suppressions");
        let c = s.len();
        s.clear();
        c
    };
    json_response(json!({"ok": true, "count": cleaned.len(), "cleared_suppressions": cleared}))
}

pub(super) fn update_schedules(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(arr) = payload.get("schedules").and_then(|v| v.as_array()) else {
        return text(StatusCode::BAD_REQUEST, "schedules must be a list");
    };
    let mut cleaned = Vec::<Schedule>::new();
    let mut errors = Vec::new();
    for (i, s) in arr.iter().enumerate() {
        let name = s
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let cron = s
            .get("cron")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if name.is_empty() {
            errors.push(format!("schedule[{i}]: name required"));
            continue;
        }
        if cron.split_whitespace().count() != 5 {
            errors.push(format!("schedule[{i}] ({name}): cron must have 5 fields"));
            continue;
        }
        let duration = s
            .get("duration_minutes")
            .and_then(|v| v.as_u64())
            .unwrap_or(30);
        if !(1..=1440).contains(&duration) {
            errors.push(format!(
                "schedule[{i}] ({name}): duration_minutes must be 1..1440"
            ));
            continue;
        }
        let m = s
            .get("match")
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| {
                        v.as_str()
                            .filter(|s| !s.is_empty())
                            .map(|s| (k.clone(), s.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let applies_to = s
            .get("applies_to")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .filter(|s| DEDUP_SOURCES.contains(&s.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        cleaned.push(Schedule {
            name,
            cron,
            duration_minutes: duration,
            r#match: m,
            applies_to,
        });
    }
    if !errors.is_empty() {
        return text(StatusCode::BAD_REQUEST, &errors.join("\n"));
    }
    match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        cfg.toml.as_table_mut().unwrap().insert(
            "schedules".into(),
            json_to_toml(serde_json::to_value(&cleaned).unwrap()),
        );
        persist_reload(state, cfg.toml)
    }) {
        Ok(Ok(())) => {}
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
    {
        let mut active = lock_mutex(&state.active_mutes, "active mutes");
        let names = cleaned
            .iter()
            .map(|s| s.name.clone())
            .collect::<std::collections::HashSet<_>>();
        active.retain(|k, _| names.contains(k));
    }
    json_response(json!({"ok": true, "count": cleaned.len()}))
}

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
