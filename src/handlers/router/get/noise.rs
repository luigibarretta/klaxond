use crate::config::{DEDUP_SOURCES, default_dedup};
use crate::state::AppState;
use axum::body::Body;
use axum::http::Response;
use serde_json::{Value, json};
use std::collections::HashMap;

pub(super) async fn response(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    let pending_counts = {
        let dedup = state.dedup.lock().await;
        DEDUP_SOURCES
            .iter()
            .map(|source| {
                (
                    (*source).to_string(),
                    dedup
                        .queues
                        .get(*source)
                        .map(|queue| queue.len())
                        .unwrap_or(0),
                )
            })
            .collect::<HashMap<_, _>>()
    };
    let recent_suppressed = state
        .recent_repeat_suppressions(50)
        .into_iter()
        .map(|entry| suppression_json(&cfg, entry))
        .collect::<Vec<_>>();
    super::super::super::json_response(json!({
        "sources": DEDUP_SOURCES,
        "settings": cfg.dedup,
        "pending_counts": pending_counts,
        "recent_suppressed": recent_suppressed,
        "limits": {
            "grouping_window_s": {"min": 5, "max": 3600},
            "repeat_window_s": {"min": 60, "max": 604800},
        },
        "defaults": default_dedup(),
    }))
}

fn suppression_json(
    cfg: &crate::config::RuntimeConfig,
    entry: crate::history::RepeatSuppressionSummary,
) -> Value {
    let next_allowed_at = entry.last_delivered_at.and_then(|last_delivered_at| {
        let cooldown_s = (entry.cooldown_s > 0)
            .then_some(entry.cooldown_s)
            .or_else(|| {
                cfg.dedup
                    .get(&entry.source)
                    .filter(|setting| {
                        setting.repeat_suppression_enabled
                            && (entry.severity != "critical" || setting.repeat_override_critical)
                    })
                    .map(|setting| setting.repeat_window_s)
            })?;
        Some(last_delivered_at + cooldown_s as f64)
    });
    json!({
        "source": entry.source,
        "severity": entry.severity,
        "title": entry.title,
        "last_delivered_at": entry.last_delivered_at,
        "last_suppressed_at": entry.last_suppressed_at,
        "suppressed_count": entry.suppressed_count,
        "cooldown_s": entry.cooldown_s,
        "matched_rule": entry.matched_rule,
        "next_allowed_at": next_allowed_at,
    })
}
