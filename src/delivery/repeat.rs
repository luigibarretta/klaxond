use crate::config::{DeliveryPolicy, RuntimeConfig, default_tiers};
use crate::history::HistoryStore;
use crate::history::{RepeatCandidate, RepeatDecision, RepeatSuppressionReason};
use crate::parsers::Parts;
use crate::state::AppState;
use crate::util::{now_epoch, token_urlsafe};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

mod matcher;

use self::matcher::{RepeatPolicy, select_policy};

pub(super) enum RepeatGate {
    Deliver(Option<RepeatReservation>),
    Suppress,
}

pub(super) struct RepeatReservation {
    fingerprint: String,
    reservation_token: String,
    store: Arc<HistoryStore>,
}

pub(super) struct RepeatRequest<'a> {
    pub source: &'a str,
    pub severity: &'a str,
    pub parts: &'a Parts,
    pub labels: &'a std::collections::HashMap<String, String>,
    pub policy: &'a DeliveryPolicy,
    pub with_cascade: bool,
}

pub(super) async fn reserve(
    state: &AppState,
    cfg: &RuntimeConfig,
    request: RepeatRequest<'_>,
) -> RepeatGate {
    let RepeatPolicy::Suppress {
        window_s,
        matched_by,
    } = select_policy(
        cfg,
        request.source,
        request.severity,
        request.parts,
        request.labels,
    )
    else {
        return RepeatGate::Deliver(None);
    };

    let fingerprint = fingerprint(request.source, request.severity, request.parts);
    let store = state.history_store();
    let mut candidate = repeat_candidate(
        fingerprint.clone(),
        &request,
        window_s,
        reservation_ttl_s(
            cfg,
            request.severity,
            request.policy,
            request.with_cascade,
            request.parts,
        ),
        &matched_by,
    );
    loop {
        candidate.now = now_epoch();
        match store.reserve_repeat(&candidate) {
            Ok(RepeatDecision::Deliver { reservation_token }) => {
                return RepeatGate::Deliver(Some(RepeatReservation {
                    fingerprint,
                    reservation_token,
                    store,
                }));
            }
            Ok(RepeatDecision::Suppress {
                reason,
                last_delivered_at,
                suppressed_count,
            }) => {
                log_suppression(
                    state,
                    &candidate,
                    reason,
                    last_delivered_at,
                    suppressed_count,
                    &matched_by,
                );
                return RepeatGate::Suppress;
            }
            Ok(RepeatDecision::WaitForDelivery) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(err) => {
                tracing::error!(
                    "repeat suppression check failed for {}/{}; delivering fail-open: {err}",
                    request.source,
                    request.severity
                );
                state.metric_inc(
                    "klaxond_repeat_suppression_errors_total",
                    &[("operation", "reserve"), ("backend", &cfg.history.backend)],
                    1,
                );
                return RepeatGate::Deliver(None);
            }
        }
    }
}

pub(super) fn complete(
    state: &AppState,
    cfg: &RuntimeConfig,
    reservation: Option<RepeatReservation>,
    delivered: bool,
) {
    let Some(reservation) = reservation else {
        return;
    };
    let delivered_at = delivered.then(now_epoch);
    if let Err(err) = reservation.store.complete_repeat(
        &reservation.fingerprint,
        &reservation.reservation_token,
        delivered_at,
    ) {
        tracing::error!("repeat suppression completion failed: {err}");
        state.metric_inc(
            "klaxond_repeat_suppression_errors_total",
            &[("operation", "complete"), ("backend", &cfg.history.backend)],
            1,
        );
    }
}

fn repeat_candidate(
    fingerprint: String,
    request: &RepeatRequest<'_>,
    window_s: u64,
    reservation_ttl_s: f64,
    matched_by: &str,
) -> RepeatCandidate {
    RepeatCandidate {
        fingerprint,
        source: request.source.to_string(),
        severity: request.severity.to_string(),
        title: request.parts.title.chars().take(200).collect(),
        now: now_epoch(),
        window_s,
        reservation_token: token_urlsafe(18),
        reservation_ttl_s,
        matched_rule: (matched_by != "source default").then(|| matched_by.to_string()),
    }
}

fn log_suppression(
    state: &AppState,
    candidate: &RepeatCandidate,
    reason: RepeatSuppressionReason,
    last_delivered_at: Option<f64>,
    suppressed_count: u64,
    matched_by: &str,
) {
    let reason_label = match reason {
        RepeatSuppressionReason::RecentDelivery => "cooldown",
    };
    tracing::info!(
        source = candidate.source,
        severity = candidate.severity,
        reason = reason_label,
        last_delivered_at,
        suppressed_count,
        matched_by,
        "repeat notification suppressed"
    );
    state.log_delivery(
        &candidate.source,
        &candidate.severity,
        &candidate.title,
        "repeat-suppressed",
        reason_label,
    );
    state.metric_inc(
        "klaxond_repeat_suppressed_total",
        &[
            ("source", &candidate.source),
            ("severity", &candidate.severity),
            ("reason", reason_label),
        ],
        1,
    );
}

fn fingerprint(source: &str, severity: &str, parts: &Parts) -> String {
    let mut hash = Sha256::new();
    for field in [source, severity, &parts.title, &parts.body, &parts.priority] {
        hash_field(&mut hash, field.as_bytes());
    }
    for tag in &parts.tags {
        hash_field(&mut hash, tag.as_bytes());
    }
    for action in &parts.actions {
        for field in action {
            hash_field(&mut hash, field.as_bytes());
        }
    }
    hash_field(&mut hash, parts.alertname.as_bytes());
    hash_field(&mut hash, &[u8::from(parts.skip_snooze)]);
    hash_field(
        &mut hash,
        parts.render_slug.as_deref().unwrap_or("").as_bytes(),
    );
    hash_field(
        &mut hash,
        parts
            .render_panel
            .map(|panel| panel.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    hash_field(&mut hash, parts.render_instance.as_bytes());
    hex::encode(hash.finalize())
}

fn hash_field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn reservation_ttl_s(
    cfg: &RuntimeConfig,
    severity: &str,
    policy: &DeliveryPolicy,
    with_cascade: bool,
    parts: &Parts,
) -> f64 {
    let tiers = if policy.mode != "broadcast" && policy.tiers.is_empty() {
        default_tiers()
    } else {
        policy.tiers.clone()
    };
    let channel_timeout = if policy.mode == "broadcast" || with_cascade {
        tiers.iter().fold(0_u64, |total, tier| {
            total.saturating_add(tier_timeout_budget(cfg, severity, tier))
        })
    } else {
        tiers
            .first()
            .map(|tier| tier_timeout_budget(cfg, severity, tier))
            .unwrap_or(0)
    };
    let render_timeout = u64::from(parts.render_slug.is_some()) * 35;
    channel_timeout
        .saturating_add(render_timeout)
        .saturating_add(30)
        .max(120) as f64
}

fn tier_timeout_budget(cfg: &RuntimeConfig, severity: &str, tier: &crate::config::Tier) -> u64 {
    let attempts = match tier.name.as_str() {
        "ntfy" => cfg
            .topics_for(severity)
            .iter()
            .filter(|topic| !topic.token.is_empty())
            .count() as u64,
        "telegram" | "smtp" => 1,
        _ => 0,
    };
    tier.timeout_seconds.saturating_mul(attempts)
}

#[cfg(test)]
mod tests;
