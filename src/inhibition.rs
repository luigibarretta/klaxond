use crate::config::InhibitionRule;
use crate::state::{AppState, Suppression, lock_mutex};
use crate::util::now_epoch;
use anyhow::Result;
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;

mod ack;
mod schedule;

pub use self::ack::{
    ack_match, ack_sign, ack_status_snapshot, ack_verify, register_ack_suppression,
};
pub use self::schedule::{
    cron_field_matches, cron_matches, scheduled_mute_match, scheduler_status, scheduler_tick,
};

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

pub fn validate_regex(rule: &InhibitionRule) -> Result<()> {
    if let Some(rx) = &rule.match_regex {
        Regex::new(rx)?;
    }
    Ok(())
}
