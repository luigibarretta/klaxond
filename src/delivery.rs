use crate::config::RuntimeConfig;
use crate::parsers::Parts;
use crate::state::{AppState, RenderedImage, lock_mutex};
use crate::util::{now_epoch, token_urlsafe};
use std::collections::HashMap;

mod audit;
pub(crate) mod channels;
mod emergency;
mod policy;
mod render;
mod repeat;
#[cfg(test)]
mod tests;

pub use audit::{DeliveryAudit, audit_log_delivery};
pub use channels::{post_to_ntfy, post_to_smtp, post_to_telegram};
use emergency::Preparation;
use policy::dispatch;
pub use policy::pick_policy;
use render::render_alert_image;

pub async fn deliver(
    state: &AppState,
    severity: &str,
    parts: Parts,
    with_cascade: bool,
    labels: HashMap<String, String>,
    source: &str,
) -> (bool, String) {
    let labels = delivery_labels(severity, labels);
    let cfg = state.cfg();
    let prepared = emergency::prepare(state, &cfg, severity, parts, &labels, source).await;
    let Preparation::Ready {
        mut parts,
        receipt_id: emergency_receipt,
        policy,
        reason,
    } = prepared
    else {
        if let Preparation::Coalesced(receipt_id) = prepared {
            tracing::info!(receipt_id, "coalesced firing into active emergency receipt");
        }
        return (true, "emergency-coalesced".to_string());
    };
    tracing::info!(
        "policy picked: {} (mode={}, {} tiers)",
        reason,
        policy.mode,
        policy.tiers.len()
    );
    let repeat_request = repeat::RepeatRequest {
        source,
        severity,
        parts: &parts,
        labels: &labels,
        policy: &policy,
        with_cascade,
    };
    let repeat::RepeatGate::Deliver(repeat_reservation) =
        repeat_gate(state, &cfg, repeat_request, emergency_receipt.is_some()).await
    else {
        return (true, "repeat-suppressed".to_string());
    };

    attach_rendered_image(state, &cfg, &mut parts).await;

    let started = now_epoch();
    let outcome = dispatch(state, &cfg, severity, &parts, policy, with_cascade).await;
    DeliveryRun {
        state,
        cfg: &cfg,
        severity,
        parts: &parts,
        labels: &labels,
        source,
        started,
        emergency_receipt: emergency_receipt.as_deref(),
    }
    .finish(outcome, repeat_reservation)
}

struct DeliveryRun<'a> {
    state: &'a AppState,
    cfg: &'a RuntimeConfig,
    severity: &'a str,
    parts: &'a Parts,
    labels: &'a HashMap<String, String>,
    source: &'a str,
    started: f64,
    emergency_receipt: Option<&'a str>,
}

impl DeliveryRun<'_> {
    fn finish(
        self,
        outcome: policy::DeliveryOutcome,
        repeat_reservation: Option<repeat::RepeatReservation>,
    ) -> (bool, String) {
        if let Some(receipt_id) = self.emergency_receipt {
            emergency::complete(self.state, receipt_id, &outcome);
        } else {
            repeat::complete(self.state, self.cfg, repeat_reservation, outcome.ok);
        }
        audit_log_delivery(
            self.state,
            DeliveryAudit {
                severity: self.severity,
                parts: self.parts,
                labels: self.labels,
                source: self.source,
                tiers_attempted: &outcome.attempted,
                tier_results: &outcome.tier_results,
                ok: outcome.ok,
                channel: &outcome.channel,
                started_at: self.started,
                emergency_receipt_id: self.emergency_receipt,
            },
        );
        (outcome.ok, outcome.channel)
    }
}

async fn repeat_gate(
    state: &AppState,
    cfg: &RuntimeConfig,
    request: repeat::RepeatRequest<'_>,
    emergency: bool,
) -> repeat::RepeatGate {
    if emergency {
        repeat::RepeatGate::Deliver(None)
    } else {
        repeat::reserve(state, cfg, request).await
    }
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
