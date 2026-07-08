use crate::config::{DeliveryPolicy, RuntimeConfig, Tier, default_tiers};
use crate::parsers::Parts;
use crate::state::{AppState, RenderedImage, lock_mutex};
use crate::util::{now_epoch, token_urlsafe};
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;

mod channels;
mod render;
#[cfg(test)]
mod tests;

pub use channels::{post_to_ntfy, post_to_smtp, post_to_telegram};
use render::render_alert_image;

pub async fn deliver(
    state: &AppState,
    severity: &str,
    mut parts: Parts,
    with_cascade: bool,
    labels: HashMap<String, String>,
    source: &str,
) -> (bool, String) {
    let mut labels = labels;
    labels.insert("severity".into(), severity.to_string());
    let cfg = state.cfg();
    let (policy, reason) = pick_policy(&cfg, &labels);
    tracing::info!(
        "policy picked: {} (mode={}, {} tiers)",
        reason,
        policy.mode,
        policy.tiers.len()
    );

    if !cfg.grafana_render_base.is_empty()
        && let Some(slug) = parts.render_slug.as_deref()
        && parts.attach_url.is_none()
        && let Some(png) = render_alert_image(
            state,
            &cfg,
            slug,
            &parts.render_instance,
            parts.render_panel,
        )
        .await
    {
        let tok = token_urlsafe(12);
        let url = format!("{}/img/{tok}.png", cfg.public_url);
        lock_mutex(&state.rendered_images, "rendered images").insert(
            tok,
            RenderedImage {
                bytes: png,
                expires_at: now_epoch() + cfg.render_image_ttl as f64,
            },
        );
        parts.attach_url = Some(url);
    }

    let started = now_epoch();
    let mut attempted = Vec::new();

    if policy.mode == "broadcast" {
        let mut succeeded = Vec::new();
        for tier in &policy.tiers {
            if post_tier(state, severity, &parts, tier).await {
                succeeded.push(tier.name.clone());
            }
            attempted.push(tier.name.clone());
        }
        let ok = !succeeded.is_empty();
        let channel = if ok {
            succeeded.join("+")
        } else {
            "broadcast-all-failed".into()
        };
        audit_log_delivery(
            state, severity, &parts, &labels, source, &attempted, ok, &channel, started,
        );
        return (ok, channel);
    }

    let tiers = if policy.tiers.is_empty() {
        default_tiers()
    } else {
        policy.tiers
    };
    let first = tiers.first().cloned();
    if let Some(first) = first {
        attempted.push(first.name.clone());
        if post_tier(state, severity, &parts, &first).await {
            audit_log_delivery(
                state,
                severity,
                &parts,
                &labels,
                source,
                &attempted,
                true,
                &first.name,
                started,
            );
            return (true, first.name);
        }
        if !with_cascade {
            let channel = format!("{}-failed", first.name);
            audit_log_delivery(
                state, severity, &parts, &labels, source, &attempted, false, &channel, started,
            );
            return (false, channel);
        }
        for tier in tiers.iter().skip(1) {
            attempted.push(tier.name.clone());
            if post_tier(state, severity, &parts, tier).await {
                audit_log_delivery(
                    state, severity, &parts, &labels, source, &attempted, true, &tier.name, started,
                );
                return (true, tier.name.clone());
            }
        }
    }
    audit_log_delivery(
        state,
        severity,
        &parts,
        &labels,
        source,
        &attempted,
        false,
        "all-failed",
        started,
    );
    (false, "all-failed".into())
}

async fn post_tier(state: &AppState, severity: &str, parts: &Parts, tier: &Tier) -> bool {
    match tier.name.as_str() {
        "ntfy" => post_to_ntfy(state, severity, parts, tier.timeout_seconds).await,
        "telegram" => post_to_telegram(state, severity, parts, tier.timeout_seconds).await,
        "smtp" => post_to_smtp(state, severity, parts, tier.timeout_seconds).await,
        _ => false,
    }
}

pub fn pick_policy(
    cfg: &RuntimeConfig,
    labels: &HashMap<String, String>,
) -> (DeliveryPolicy, String) {
    for (idx, rule) in cfg.delivery.rules.iter().enumerate() {
        if matcher_matches(&rule.r#match, labels)
            && let Some(policy) = resolve_policy(cfg, &rule.policy)
        {
            return (policy, format!("rule#{}→{}", idx + 1, rule.policy));
        }
    }
    if let Some(policy) = resolve_policy(cfg, &cfg.delivery.default_policy) {
        return (policy, format!("default→{}", cfg.delivery.default_policy));
    }
    (legacy_cascade_policy(cfg), "fallback→legacy".into())
}

fn resolve_policy(cfg: &RuntimeConfig, name: &str) -> Option<DeliveryPolicy> {
    if name == "cascade" {
        return Some(legacy_cascade_policy(cfg));
    }
    cfg.delivery
        .policies
        .iter()
        .find(|p| p.name == name)
        .cloned()
}

fn legacy_cascade_policy(cfg: &RuntimeConfig) -> DeliveryPolicy {
    DeliveryPolicy {
        name: "cascade".into(),
        mode: "cascade".into(),
        tiers: if cfg.tiers.is_empty() {
            default_tiers()
        } else {
            cfg.tiers.clone()
        },
    }
}

fn matcher_matches(matcher: &HashMap<String, String>, labels: &HashMap<String, String>) -> bool {
    for (k, v) in matcher {
        let actual = labels.get(k).map(String::as_str).unwrap_or("");
        if let Some(pattern) = v.strip_prefix("re:") {
            if !Regex::new(pattern)
                .map(|r| r.is_match(actual))
                .unwrap_or(false)
            {
                return false;
            }
        } else if actual != v {
            return false;
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
pub fn audit_log_delivery(
    state: &AppState,
    severity: &str,
    parts: &Parts,
    labels: &HashMap<String, String>,
    source: &str,
    tiers_attempted: &[String],
    ok: bool,
    channel: &str,
    started_at: f64,
) {
    let ended_at = now_epoch();
    let record = json!({
        "audit": "delivery",
        "source": source,
        "severity": severity,
        "alertname": labels.get("alertname").cloned().unwrap_or_else(|| parts.title.chars().take(120).collect()),
        "component": labels.get("component").cloned().unwrap_or_default(),
        "host": labels.get("host").or_else(|| labels.get("instance_name")).cloned().unwrap_or_default(),
        "title": parts.title.chars().take(200).collect::<String>(),
        "tiers_attempted": tiers_attempted,
        "ok": ok,
        "channel": channel,
        "duration_ms": ((ended_at - started_at) * 1000.0) as i64,
        "timestamp": (ended_at * 1000.0) as i64,
    });
    tracing::info!("AUDIT {}", record);
    state.log_delivery(source, severity, &parts.title, channel, "");
    state.metric_inc(
        "klaxond_deliveries_total",
        &[
            ("source", source),
            ("severity", severity),
            ("channel", channel),
            ("ok", if ok { "1" } else { "0" }),
        ],
        1,
    );
}
