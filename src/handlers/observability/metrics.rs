use crate::state::{AppState, esc_label, lock_mutex};
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use std::collections::HashMap;

pub(in crate::handlers) fn metrics_response(state: &AppState) -> Response<Body> {
    let uptime = state.started.elapsed().as_secs();
    initialize_emergency_metrics(state);
    refresh_runtime_gauges(state);
    let mut lines = metric_preamble(uptime);
    let counters = lock_mutex(&state.metrics.counters, "metrics counters");
    emit_metrics(&mut lines, "counter", &counters, &counter_help());
    let gauges = lock_mutex(&state.metrics.gauges, "metrics gauges");
    let gauge_values = gauges
        .iter()
        .map(|(key, value)| (key.clone(), *value as i64))
        .collect::<HashMap<_, _>>();
    emit_metrics(&mut lines, "gauge", &gauge_values, &gauge_help());
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(lines.join("\n") + "\n"))
        .expect("static metrics response headers are valid")
}

fn initialize_emergency_metrics(state: &AppState) {
    for operation in [
        "register",
        "initial-attempt",
        "expire",
        "reserve",
        "complete",
        "resolve",
        "acknowledge",
        "cancel",
        "retry",
        "list",
        "get",
        "active-stats",
        "invalid-payload",
        "adjust-lease",
        "materialize-policy-snapshot",
    ] {
        state.metric_inc(
            "klaxond_emergency_storage_errors_total",
            &[("operation", operation)],
            0,
        );
    }
}

fn refresh_runtime_gauges(state: &AppState) {
    state.metric_set(
        "klaxond_suppressions_active",
        &[],
        lock_mutex(&state.suppressions, "suppressions").len() as f64,
    );
    if let Ok(d) = state.dedup.try_lock() {
        for src in state.with_cfg(|cfg| cfg.dedup.keys().cloned().collect::<Vec<_>>()) {
            state.metric_set(
                "klaxond_dedup_pending",
                &[("source", &src)],
                d.queues.get(&src).map(|q| q.len()).unwrap_or(0) as f64,
            );
        }
    }
    if let Ok((active, oldest_age)) = crate::emergency::active_stats(state) {
        state.metric_set("klaxond_emergencies_active", &[], active as f64);
        state.metric_set(
            "klaxond_emergency_oldest_active_age_seconds",
            &[],
            oldest_age,
        );
    }
    refresh_profile_gauges(state);
}

fn refresh_profile_gauges(state: &AppState) {
    let mut profile_ids = state.with_cfg(|cfg| {
        cfg.emergency
            .profiles
            .iter()
            .map(|profile| profile.id.clone())
            .collect::<Vec<_>>()
    });
    for profile_id in &profile_ids {
        for forced in ["0", "1"] {
            state.metric_inc(
                "klaxond_emergency_profile_matches_total",
                &[("profile_id", profile_id), ("forced", forced)],
                0,
            );
        }
    }
    let active_receipts = state
        .history_store()
        .emergencies(Some("active"), 1_000)
        .unwrap_or_default();
    profile_ids.extend(
        active_receipts
            .iter()
            .map(|incident| incident.policy_id.clone()),
    );
    profile_ids.sort();
    profile_ids.dedup();
    for profile_id in profile_ids {
        let count = active_receipts
            .iter()
            .filter(|incident| incident.policy_id == profile_id)
            .count();
        state.metric_set(
            "klaxond_emergency_profile_active",
            &[("profile_id", &profile_id)],
            count as f64,
        );
    }
}

fn metric_preamble(uptime: u64) -> Vec<String> {
    vec![
        "# HELP klaxond_info Static info (version, etc).".to_string(),
        "# TYPE klaxond_info gauge".to_string(),
        format!("klaxond_info{{version=\"{}\"}} 1", crate::config::VERSION),
        "# HELP klaxond_uptime_seconds Seconds since klaxond started.".to_string(),
        "# TYPE klaxond_uptime_seconds counter".to_string(),
        format!("klaxond_uptime_seconds {uptime}"),
    ]
}

fn counter_help() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        (
            "klaxond_deliveries_total",
            "Cumulative deliveries (or attempts) per source/severity/channel/ok.",
        ),
        (
            "klaxond_delivery_tier_attempts_total",
            "Cumulative delivery tier attempts per source/severity/tier/component/ok.",
        ),
        (
            "klaxond_suppressions_armed_total",
            "Inhibition source-alerts that armed a suppression.",
        ),
        (
            "klaxond_render_errors_total",
            "Render-time exceptions per source.",
        ),
        (
            "klaxond_dedup_buffered_total",
            "Events queued in the dedup buffer per source.",
        ),
        (
            "klaxond_dedup_flushed_total",
            "Events flushed from the dedup buffer per source.",
        ),
        (
            "klaxond_repeat_suppressed_total",
            "Repeated notifications suppressed after a successful delivery.",
        ),
        (
            "klaxond_repeat_suppression_errors_total",
            "Repeat-suppression persistence errors; delivery fails open.",
        ),
        (
            "klaxond_emergency_incidents_total",
            "Emergency receipts created or coalesced.",
        ),
        (
            "klaxond_emergency_transitions_total",
            "Durable emergency state transitions.",
        ),
        (
            "klaxond_emergency_attempts_total",
            "Emergency delivery attempts by channel and outcome.",
        ),
        (
            "klaxond_emergency_storage_errors_total",
            "Emergency persistence operation failures.",
        ),
        (
            "klaxond_emergency_profile_matches_total",
            "Emergency profile selections by stable profile ID and explicit-force flag.",
        ),
    ])
}

fn gauge_help() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        (
            "klaxond_suppressions_active",
            "Currently-armed in-memory suppressions.",
        ),
        (
            "klaxond_dedup_pending",
            "Events pending in the dedup buffer per source.",
        ),
        (
            "klaxond_emergencies_active",
            "Emergency receipts currently awaiting acknowledgement.",
        ),
        (
            "klaxond_emergency_oldest_active_age_seconds",
            "Age of the oldest active emergency receipt.",
        ),
        (
            "klaxond_emergency_last_ack_latency_seconds",
            "Acknowledgement latency of the last acknowledged emergency.",
        ),
        (
            "klaxond_emergency_profile_active",
            "Active emergency receipts by stable policy profile ID.",
        ),
    ])
}

fn emit_metrics(
    lines: &mut Vec<String>,
    kind: &str,
    samples: &HashMap<String, i64>,
    helps: &HashMap<&str, &str>,
) {
    let mut by_name: HashMap<String, Vec<(String, i64)>> = HashMap::new();
    for (key, val) in samples {
        let (name, labels) = key.split_once('|').unwrap_or((key, ""));
        by_name
            .entry(name.into())
            .or_default()
            .push((labels.into(), *val));
    }
    let mut names = by_name.keys().cloned().collect::<Vec<_>>();
    names.sort();
    for name in names {
        lines.push(format!(
            "# HELP {name} {}",
            helps
                .get(name.as_str())
                .copied()
                .unwrap_or("(no description)")
        ));
        lines.push(format!("# TYPE {name} {kind}"));
        for (labels, val) in by_name.remove(&name).unwrap_or_default() {
            let label_render = if labels.is_empty() {
                String::new()
            } else {
                let labels = labels
                    .split(',')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| format!("{k}=\"{}\"", esc_label(v)))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{{{labels}}}")
            };
            lines.push(format!("{name}{label_render} {val}"));
        }
    }
}
