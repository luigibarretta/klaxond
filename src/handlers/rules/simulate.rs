use super::super::{json_body, json_response, text};
use crate::config::{DEDUP_SOURCES, default_dedup};
use crate::delivery::pick_policy;
use crate::inhibition;
use crate::parsers::normalize_labels;
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};
use std::collections::HashMap;

pub(in crate::handlers) fn inhibition_rules_test(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let source = payload
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if source.is_empty() {
        return text(StatusCode::BAD_REQUEST, "source is required");
    }
    let labels = payload
        .get("labels")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), crate::parsers::scalar_to_string(v)))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    let cfg = state.cfg();
    let considered = cfg
        .inhibition_rules
        .iter()
        .filter(|r| r.applies_to.is_empty() || r.applies_to.contains(&source))
        .map(|r| r.source.clone())
        .collect::<Vec<_>>();
    let arm_idx = if source == "grafana" {
        inhibition::alert_is_source(&labels, &cfg.inhibition_rules)
    } else {
        None
    };
    let suppressed = inhibition::is_suppressed(state, &labels, &source);
    let (would_send, reason, matched) = if let Some(idx) = arm_idx {
        (
            true,
            "source".to_string(),
            cfg.inhibition_rules.get(idx).map(|r| r.source.clone()),
        )
    } else if let Some(s) = suppressed {
        (false, format!("inhibited-by-{s}"), Some(s))
    } else {
        (true, "ok".to_string(), None)
    };
    json_response(
        json!({"would_send": would_send, "reason": reason, "matched_rule": matched, "would_arm_suppression": arm_idx.is_some(), "considered_rules": considered}),
    )
}

pub(in crate::handlers) fn policy_simulate(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let source = payload
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("grafana")
        .trim()
        .to_ascii_lowercase();
    if !DEDUP_SOURCES.contains(&source.as_str()) {
        return text(StatusCode::BAD_REQUEST, "unknown source");
    }
    let severity = payload
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("warning")
        .trim()
        .to_ascii_lowercase();
    let mut labels = payload
        .get("payload")
        .map(|body| normalize_labels(&source, body))
        .unwrap_or_else(|| {
            HashMap::from([
                ("source".to_string(), source.clone()),
                ("status".to_string(), "firing".to_string()),
            ])
        });
    if let Some(obj) = payload.get("labels").and_then(Value::as_object) {
        for (key, value) in obj {
            labels.insert(key.clone(), crate::parsers::scalar_to_string(value));
        }
    }
    labels.insert("severity".into(), severity.clone());

    let (would_send, reason) = inhibition::apply_inhibition(state, &source, &labels, true);
    let cfg = state.cfg();
    let considered = cfg
        .inhibition_rules
        .iter()
        .filter(|rule| rule.applies_to.is_empty() || rule.applies_to.contains(&source))
        .map(|rule| rule.source.clone())
        .collect::<Vec<_>>();
    let arm_idx = if source == "grafana" {
        inhibition::alert_is_source(&labels, &cfg.inhibition_rules)
    } else {
        None
    };
    let matched_rule = if let Some(idx) = arm_idx {
        cfg.inhibition_rules
            .get(idx)
            .map(|rule| rule.source.clone())
    } else {
        reason
            .strip_prefix("inhibited-by-")
            .map(ToOwned::to_owned)
            .or_else(|| {
                reason
                    .strip_prefix("scheduled-mute-")
                    .map(ToOwned::to_owned)
            })
            .or_else(|| reason.strip_prefix("ack-snoozed-").map(ToOwned::to_owned))
    };
    let (policy, matched_by) = pick_policy(&cfg, &labels);
    let defaults = default_dedup();
    let dedup = cfg
        .dedup
        .get(&source)
        .or_else(|| defaults.get(&source))
        .cloned();
    json_response(json!({
        "source": source,
        "severity": severity,
        "labels": labels,
        "inhibition": {
            "would_send": would_send,
            "reason": reason,
            "matched_rule": matched_rule,
            "would_arm_suppression": arm_idx.is_some(),
            "considered_rules": considered,
        },
        "delivery": {
            "policy": policy.name,
            "mode": policy.mode,
            "matched_by": matched_by,
            "tiers": policy.tiers,
        },
        "dedup": dedup.map(|d| json!({
            "enabled": d.enabled,
            "window_s": d.window_s,
            "strategy": d.strategy,
            "override_critical": d.override_critical,
        })).unwrap_or_else(|| json!({
            "enabled": false,
            "window_s": 0,
            "strategy": "none",
            "override_critical": false,
        })),
    }))
}
