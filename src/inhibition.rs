use crate::config::InhibitionRule;
use crate::state::{AppState, Suppression, lock_mutex};
use crate::util::{b64url_decode_padded, b64url_no_pad, hmac_hex, now_epoch};
use anyhow::Result;
use chrono::{Datelike, Local, Timelike};
use constant_time_eq::constant_time_eq;
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;

pub fn cleanup_expired(state: &AppState) {
    let now = now_epoch();
    lock_mutex(&state.suppressions, "suppressions").retain(|s| s.expiry > now);
}

pub fn alert_is_source(
    labels: &HashMap<String, String>,
    rules: &[InhibitionRule],
) -> Option<usize> {
    let source = labels.get("inhibition_source")?;
    rules.iter().position(|r| &r.source == source)
}

pub fn register_suppression(
    state: &AppState,
    rule_idx: usize,
    labels: &HashMap<String, String>,
    resolved: bool,
) {
    let Some(rule) = state.with_cfg(|cfg| cfg.inhibition_rules.get(rule_idx).cloned()) else {
        return;
    };
    let mut anchor = None;
    if let Some(match_by) = &rule.match_by {
        let val = labels.get(match_by).cloned().unwrap_or_default();
        if val.is_empty() {
            tracing::warn!("source {} missing match label {}", rule.source, match_by);
            return;
        }
        anchor = Some(val);
    }
    let mut supp = lock_mutex(&state.suppressions, "suppressions");
    supp.retain(|s| !(s.rule_idx == rule_idx && s.anchor == anchor));
    if !resolved {
        supp.push(Suppression {
            rule_idx,
            anchor,
            expiry: now_epoch() + rule.ttl_seconds as f64,
        });
        state.metric_inc(
            "klaxond_suppressions_armed_total",
            &[("rule", &rule.source)],
            1,
        );
    }
}

pub fn is_suppressed(
    state: &AppState,
    labels: &HashMap<String, String>,
    source: &str,
) -> Option<String> {
    cleanup_expired(state);
    let active = lock_mutex(&state.suppressions, "suppressions").clone();
    if active.is_empty() {
        return None;
    }
    state.with_cfg(|cfg| {
        let own_source = labels.get("inhibition_source").cloned().unwrap_or_default();
        for s in active {
            let Some(rule) = cfg.inhibition_rules.get(s.rule_idx) else {
                continue;
            };
            if rule.source == own_source {
                return None;
            }
            if !rule.applies_to.is_empty() && !rule.applies_to.iter().any(|x| x == source) {
                continue;
            }
            if rule.match_all {
                return Some(rule.source.clone());
            }
            if let Some(match_by) = &rule.match_by {
                let target = labels.get(match_by).cloned().unwrap_or_default();
                if !target.is_empty() && Some(target) == s.anchor {
                    return Some(rule.source.clone());
                }
            }
            if let (Some(label), Some(pattern)) = (&rule.match_label, &rule.match_regex) {
                let target = labels.get(label).cloned().unwrap_or_default();
                if !target.is_empty()
                    && Regex::new(pattern)
                        .map(|r| r.is_match(&target))
                        .unwrap_or(false)
                {
                    return Some(rule.source.clone());
                }
            }
        }
        None
    })
}

pub fn ack_sign(state: &AppState, alertname: &str, ttl_sec: u64) -> String {
    let exp = now_epoch() as i64 + ttl_sec as i64;
    let payload = json!({"a": alertname, "t": ttl_sec, "e": exp}).to_string();
    let b = b64url_no_pad(payload.as_bytes());
    let sig = hmac_hex(state.session_key.as_slice(), b.as_bytes());
    format!("{b}.{sig}")
}

pub fn ack_verify(state: &AppState, token: &str) -> (Option<String>, String) {
    let Some((body_b64, sig)) = token.split_once('.') else {
        return (None, "malformed".into());
    };
    let expected = hmac_hex(state.session_key.as_slice(), body_b64.as_bytes());
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return (None, "bad-signature".into());
    }
    let Ok(bytes) = b64url_decode_padded(body_b64) else {
        return (None, "bad-payload".into());
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (None, "bad-payload".into());
    };
    if payload.get("e").and_then(|v| v.as_i64()).unwrap_or(0) < now_epoch() as i64 {
        return (None, "expired".into());
    }
    let alertname = payload
        .get("a")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if alertname.is_empty() {
        return (None, "no-alertname".into());
    }
    (Some(alertname), "ok".into())
}

pub fn register_ack_suppression(state: &AppState, alertname: &str, ttl_sec: u64) {
    lock_mutex(&state.ack_suppressions, "ack suppressions")
        .insert(alertname.to_string(), now_epoch() + ttl_sec as f64);
}

pub fn ack_match(state: &AppState, labels: &HashMap<String, String>) -> Option<String> {
    let name = labels.get("alertname")?;
    if name.is_empty() {
        return None;
    }
    let now = now_epoch();
    let mut acks = lock_mutex(&state.ack_suppressions, "ack suppressions");
    if let Some(exp) = acks.get(name).copied() {
        if exp > now {
            return Some(name.clone());
        }
        acks.remove(name);
    }
    None
}

pub fn apply_inhibition(
    state: &AppState,
    source: &str,
    labels: &HashMap<String, String>,
    dry_run: bool,
) -> (bool, String) {
    if source == "grafana"
        && let Some(idx) = state.with_cfg(|cfg| alert_is_source(labels, &cfg.inhibition_rules))
    {
        if !dry_run {
            register_suppression(
                state,
                idx,
                labels,
                labels
                    .get("status")
                    .map(|s| s == "resolved")
                    .unwrap_or(false),
            );
        }
        return (true, "source".into());
    }
    if let Some(ack) = ack_match(state, labels) {
        return (false, format!("ack-snoozed-{ack}"));
    }
    if let Some(sched) = scheduled_mute_match(state, labels, source) {
        return (false, format!("scheduled-mute-{sched}"));
    }
    if let Some(src) = is_suppressed(state, labels, source) {
        return (false, format!("inhibited-by-{src}"));
    }
    (true, "ok".into())
}

pub fn inhibition_status(state: &AppState) -> Vec<serde_json::Value> {
    cleanup_expired(state);
    let cfg = state.cfg();
    let now = now_epoch();
    lock_mutex(&state.suppressions, "suppressions")
        .iter()
        .filter_map(|s| {
            let rule = cfg.inhibition_rules.get(s.rule_idx)?;
            Some(json!({
                "source": rule.source,
                "anchor": s.anchor.clone().unwrap_or_else(|| "*".into()),
                "applies_to": if rule.applies_to.is_empty() { vec!["*".to_string()] } else { rule.applies_to.clone() },
                "expires_in_seconds": (s.expiry - now).max(0.0) as i64,
            }))
        })
        .collect()
}

pub fn ack_status_snapshot(state: &AppState) -> Vec<serde_json::Value> {
    let now = now_epoch();
    let mut rows = lock_mutex(&state.ack_suppressions, "ack suppressions")
        .iter()
        .filter(|(_, exp)| **exp > now)
        .map(|(name, exp)| json!({"alertname": name, "expires_in_seconds": (*exp - now) as i64}))
        .collect::<Vec<_>>();
    rows.sort_by_key(|r| {
        r.get("expires_in_seconds")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
    });
    rows
}

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

pub fn validate_regex(rule: &InhibitionRule) -> Result<()> {
    if let Some(rx) = &rule.match_regex {
        Regex::new(rx)?;
    }
    Ok(())
}
