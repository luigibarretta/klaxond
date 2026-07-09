use crate::state::{AppState, lock_mutex};
use crate::util::now_epoch;
use chrono::{Datelike, Local, Timelike};
use serde_json::json;
use std::collections::HashMap;

pub fn cron_field_matches(field: &str, value: u32, lo: u32, hi: u32) -> bool {
    if field == "*" || field.is_empty() {
        return true;
    }
    for raw in field.split(',') {
        let mut token = raw.trim();
        let mut step = 1_u32;
        if let Some((base, step_s)) = token.split_once('/') {
            let Ok(parsed) = step_s.parse::<u32>() else {
                return false;
            };
            step = parsed.max(1);
            token = base;
        }
        if token == "*" {
            if (lo..=hi).step_by(step as usize).any(|v| v == value) {
                return true;
            }
        } else if let Some((a, b)) = token.split_once('-') {
            let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) else {
                return false;
            };
            if (a..=b).step_by(step as usize).any(|v| v == value) {
                return true;
            }
        } else if token.parse::<u32>().map(|v| v == value).unwrap_or(false) {
            return true;
        }
    }
    false
}

pub fn cron_matches(cron: &str, now: chrono::DateTime<Local>) -> bool {
    let parts = cron.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 5 {
        return false;
    }
    let (minute, hour, dom, month, dow) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
    if !cron_field_matches(minute, now.minute(), 0, 59) {
        return false;
    }
    if !cron_field_matches(hour, now.hour(), 0, 23) {
        return false;
    }
    if !cron_field_matches(month, now.month(), 1, 12) {
        return false;
    }
    let cron_dow = now.weekday().num_days_from_sunday();
    let dom_restricted = dom != "*";
    let dow_restricted = dow != "*";
    if dom_restricted && dow_restricted {
        return cron_field_matches(dom, now.day(), 1, 31)
            || cron_field_matches(dow, cron_dow, 0, 7);
    }
    if dom_restricted {
        return cron_field_matches(dom, now.day(), 1, 31);
    }
    if dow_restricted {
        return cron_field_matches(dow, cron_dow, 0, 7);
    }
    true
}

pub fn scheduler_tick(state: &AppState) {
    let now_dt = Local::now();
    let now = now_epoch();
    let cfg = state.cfg();
    let mut active = lock_mutex(&state.active_mutes, "active mutes");
    active.retain(|name, expiry| {
        let keep = *expiry > now;
        if !keep {
            tracing::info!("schedule '{}' expired", name);
        }
        keep
    });
    for s in cfg.schedules {
        if cron_matches(&s.cron, now_dt) {
            let expiry = now + (s.duration_minutes * 60) as f64;
            let cur = active.get(&s.name).copied().unwrap_or(0.0);
            if expiry > cur {
                active.insert(s.name.clone(), expiry);
            }
        }
    }
}

pub fn scheduled_mute_match(
    state: &AppState,
    labels: &HashMap<String, String>,
    source: &str,
) -> Option<String> {
    let active_names = {
        let active = lock_mutex(&state.active_mutes, "active mutes");
        if active.is_empty() {
            return None;
        }
        active.keys().cloned().collect::<Vec<_>>()
    };
    for s in state.cfg().schedules {
        if !active_names.contains(&s.name) {
            continue;
        }
        if !s.applies_to.is_empty() && !s.applies_to.iter().any(|x| x == source) {
            continue;
        }
        let mut ok = true;
        for (k, v) in &s.r#match {
            if labels.get(k).map(|x| x != v).unwrap_or(true) {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(s.name);
        }
    }
    None
}

pub fn scheduler_status(state: &AppState) -> serde_json::Value {
    let now = now_epoch();
    let active = lock_mutex(&state.active_mutes, "active mutes")
        .iter()
        .filter(|(_, exp)| **exp > now)
        .map(|(k, v)| (k.clone(), (*v - now) as i64))
        .collect::<HashMap<_, _>>();
    json!({
        "schedules": state.cfg().schedules,
        "active_mutes": active,
    })
}
