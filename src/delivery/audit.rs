use crate::parsers::Parts;
use crate::state::AppState;
use crate::util::now_epoch;
use serde_json::json;
use std::collections::HashMap;

pub struct DeliveryAudit<'a> {
    pub severity: &'a str,
    pub parts: &'a Parts,
    pub labels: &'a HashMap<String, String>,
    pub source: &'a str,
    pub tiers_attempted: &'a [String],
    pub tier_results: &'a [(String, bool)],
    pub ok: bool,
    pub channel: &'a str,
    pub started_at: f64,
}

pub fn audit_log_delivery(state: &AppState, audit: DeliveryAudit<'_>) {
    let ended_at = now_epoch();
    let component = audit
        .labels
        .get("component")
        .map(String::as_str)
        .unwrap_or("");
    let tier_results = audit
        .tier_results
        .iter()
        .map(|(tier, ok)| json!({"tier": tier, "ok": ok}))
        .collect::<Vec<_>>();
    let record = json!({
        "audit": "delivery",
        "source": audit.source,
        "severity": audit.severity,
        "alertname": audit.labels.get("alertname").cloned().unwrap_or_else(|| audit.parts.title.chars().take(120).collect()),
        "component": audit.labels.get("component").cloned().unwrap_or_default(),
        "host": audit.labels.get("host").or_else(|| audit.labels.get("instance_name")).cloned().unwrap_or_default(),
        "title": audit.parts.title.chars().take(200).collect::<String>(),
        "tiers_attempted": audit.tiers_attempted,
        "tier_results": tier_results,
        "ok": audit.ok,
        "channel": audit.channel,
        "duration_ms": ((ended_at - audit.started_at) * 1000.0) as i64,
        "timestamp": (ended_at * 1000.0) as i64,
    });
    tracing::info!("AUDIT {}", record);
    state.log_delivery(
        audit.source,
        audit.severity,
        &audit.parts.title,
        audit.channel,
        "",
    );
    state.metric_inc(
        "klaxond_deliveries_total",
        &[
            ("source", audit.source),
            ("severity", audit.severity),
            ("channel", audit.channel),
            ("ok", if audit.ok { "1" } else { "0" }),
        ],
        1,
    );
    for (tier, ok) in audit.tier_results {
        state.metric_inc(
            "klaxond_delivery_tier_attempts_total",
            &[
                ("source", audit.source),
                ("severity", audit.severity),
                ("tier", tier.as_str()),
                ("ok", if *ok { "1" } else { "0" }),
                ("component", component),
            ],
            1,
        );
    }
}
