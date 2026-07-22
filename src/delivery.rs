use crate::config::{DeliveryPolicy, RuntimeConfig, Tier, default_tiers};
use crate::parsers::Parts;
use crate::state::{AppState, RenderedImage, lock_mutex};
use crate::util::{now_epoch, token_urlsafe};
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;

mod channels;
mod render;
mod repeat;
#[cfg(test)]
mod tests;

pub use channels::{post_to_ntfy, post_to_smtp, post_to_telegram};
use channels::{post_to_ntfy_with_config, post_to_smtp_with_config, post_to_telegram_with_config};
use render::render_alert_image;

pub async fn deliver(
    state: &AppState,
    severity: &str,
    mut parts: Parts,
    with_cascade: bool,
    labels: HashMap<String, String>,
    source: &str,
) -> (bool, String) {
    let labels = delivery_labels(severity, labels);
    let cfg = state.cfg();
    let (policy, reason) = pick_policy(&cfg, &labels);
    tracing::info!(
        "policy picked: {} (mode={}, {} tiers)",
        reason,
        policy.mode,
        policy.tiers.len()
    );
    let repeat_reservation = match repeat::reserve(
        state,
        &cfg,
        repeat::RepeatRequest {
            source,
            severity,
            parts: &parts,
            labels: &labels,
            policy: &policy,
            with_cascade,
        },
    )
    .await
    {
        repeat::RepeatGate::Deliver(reservation) => reservation,
        repeat::RepeatGate::Suppress => return (true, "repeat-suppressed".to_string()),
    };

    attach_rendered_image(state, &cfg, &mut parts).await;

    let started = now_epoch();
    let outcome = dispatch_policy(state, &cfg, severity, &parts, policy, with_cascade).await;
    repeat::complete(state, &cfg, repeat_reservation, outcome.ok);
    audit_log_delivery(
        state,
        DeliveryAudit {
            severity,
            parts: &parts,
            labels: &labels,
            source,
            tiers_attempted: &outcome.attempted,
            ok: outcome.ok,
            channel: &outcome.channel,
            started_at: started,
        },
    );
    (outcome.ok, outcome.channel)
}

fn delivery_labels(severity: &str, mut labels: HashMap<String, String>) -> HashMap<String, String> {
    labels.insert("severity".into(), severity.to_string());
    labels
}

async fn attach_rendered_image(state: &AppState, cfg: &RuntimeConfig, parts: &mut Parts) {
    if !cfg.grafana_render_base.is_empty()
        && let Some(slug) = parts.render_slug.as_deref()
        && parts.attach_url.is_none()
        && let Some(png) =
            render_alert_image(state, cfg, slug, &parts.render_instance, parts.render_panel).await
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
}

async fn dispatch_policy(
    state: &AppState,
    cfg: &RuntimeConfig,
    severity: &str,
    parts: &Parts,
    policy: DeliveryPolicy,
    with_cascade: bool,
) -> DeliveryOutcome {
    if policy.mode == "broadcast" {
        return deliver_broadcast(state, cfg, severity, parts, &policy).await;
    }
    deliver_cascade(state, cfg, severity, parts, policy, with_cascade).await
}

async fn deliver_broadcast(
    state: &AppState,
    cfg: &RuntimeConfig,
    severity: &str,
    parts: &Parts,
    policy: &DeliveryPolicy,
) -> DeliveryOutcome {
    let mut attempted = Vec::new();
    let mut succeeded = Vec::new();
    for tier in &policy.tiers {
        if post_tier(state, cfg, severity, parts, tier).await {
            succeeded.push(tier.name.clone());
        }
        attempted.push(tier.name.clone());
    }
    if succeeded.is_empty() {
        DeliveryOutcome::failed("broadcast-all-failed", attempted)
    } else {
        DeliveryOutcome::success(succeeded.join("+"), attempted)
    }
}

async fn deliver_cascade(
    state: &AppState,
    cfg: &RuntimeConfig,
    severity: &str,
    parts: &Parts,
    policy: DeliveryPolicy,
    with_cascade: bool,
) -> DeliveryOutcome {
    let tiers = if policy.tiers.is_empty() {
        default_tiers()
    } else {
        policy.tiers
    };
    let mut attempted = Vec::new();
    let first = tiers.first().cloned();
    if let Some(first) = first {
        attempted.push(first.name.clone());
        if post_tier(state, cfg, severity, parts, &first).await {
            return DeliveryOutcome::success(first.name, attempted);
        }
        if !with_cascade {
            return DeliveryOutcome::failed(format!("{}-failed", first.name), attempted);
        }
        for tier in tiers.iter().skip(1) {
            attempted.push(tier.name.clone());
            if post_tier(state, cfg, severity, parts, tier).await {
                return DeliveryOutcome::success(tier.name.clone(), attempted);
            }
        }
    }
    DeliveryOutcome::failed("all-failed", attempted)
}

struct DeliveryOutcome {
    ok: bool,
    channel: String,
    attempted: Vec<String>,
}

impl DeliveryOutcome {
    fn success(channel: impl Into<String>, attempted: Vec<String>) -> Self {
        Self {
            ok: true,
            channel: channel.into(),
            attempted,
        }
    }

    fn failed(channel: impl Into<String>, attempted: Vec<String>) -> Self {
        Self {
            ok: false,
            channel: channel.into(),
            attempted,
        }
    }
}

async fn post_tier(
    state: &AppState,
    cfg: &RuntimeConfig,
    severity: &str,
    parts: &Parts,
    tier: &Tier,
) -> bool {
    match tier.name.as_str() {
        "ntfy" => post_to_ntfy_with_config(state, cfg, severity, parts, tier.timeout_seconds).await,
        "telegram" => {
            post_to_telegram_with_config(state, cfg, severity, parts, tier.timeout_seconds).await
        }
        "smtp" => post_to_smtp_with_config(cfg, severity, parts, tier.timeout_seconds).await,
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

pub struct DeliveryAudit<'a> {
    pub severity: &'a str,
    pub parts: &'a Parts,
    pub labels: &'a HashMap<String, String>,
    pub source: &'a str,
    pub tiers_attempted: &'a [String],
    pub ok: bool,
    pub channel: &'a str,
    pub started_at: f64,
}

pub fn audit_log_delivery(state: &AppState, audit: DeliveryAudit<'_>) {
    let ended_at = now_epoch();
    let record = json!({
        "audit": "delivery",
        "source": audit.source,
        "severity": audit.severity,
        "alertname": audit.labels.get("alertname").cloned().unwrap_or_else(|| audit.parts.title.chars().take(120).collect()),
        "component": audit.labels.get("component").cloned().unwrap_or_default(),
        "host": audit.labels.get("host").or_else(|| audit.labels.get("instance_name")).cloned().unwrap_or_default(),
        "title": audit.parts.title.chars().take(200).collect::<String>(),
        "tiers_attempted": audit.tiers_attempted,
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
}
