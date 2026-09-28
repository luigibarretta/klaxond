use super::policy::{DeliveryOutcome, pick_policy};
use crate::config::{DeliveryPolicy, RuntimeConfig, Tier};
use crate::history::EmergencyPolicySnapshot;
use crate::parsers::Parts;
use crate::state::AppState;
use std::collections::HashMap;

pub(super) enum Preparation {
    Coalesced(String),
    Ready {
        parts: Box<Parts>,
        receipt_id: Option<String>,
        policy: DeliveryPolicy,
        reason: String,
    },
}

pub(super) async fn prepare(
    state: &AppState,
    cfg: &RuntimeConfig,
    severity: &str,
    parts: Parts,
    labels: &HashMap<String, String>,
    source: &str,
) -> Preparation {
    match crate::emergency::prepare(state, severity, &parts, labels, source).await {
        crate::emergency::PrepareResult::Normal => {
            let (policy, reason) = pick_policy(cfg, labels);
            Preparation::Ready {
                parts: Box::new(parts),
                receipt_id: None,
                policy,
                reason,
            }
        }
        crate::emergency::PrepareResult::Duplicate(receipt_id) => {
            Preparation::Coalesced(receipt_id)
        }
        crate::emergency::PrepareResult::Managed {
            receipt_id,
            parts,
            policy,
        } => Preparation::Ready {
            parts,
            receipt_id: Some(receipt_id),
            policy: initial_policy(cfg, &policy),
            reason: "emergency-profile→initial-attempt".to_string(),
        },
    }
}

pub(super) fn complete(state: &AppState, receipt_id: &str, outcome: &DeliveryOutcome) {
    let result = |name: &str| {
        outcome
            .tier_results
            .iter()
            .find(|(tier, _)| tier == name)
            .map(|(_, ok)| *ok)
    };
    crate::emergency::record_initial_attempt(
        state,
        receipt_id,
        result("ntfy").unwrap_or(false),
        result("telegram"),
        result("smtp"),
    );
}

fn initial_policy(cfg: &RuntimeConfig, snapshot: &EmergencyPolicySnapshot) -> DeliveryPolicy {
    let mut tiers = vec![tier(cfg, "ntfy", 15)];
    for (name, enabled, after_attempts, timeout) in [
        (
            "telegram",
            snapshot.telegram.enabled,
            snapshot.telegram.after_attempts,
            8,
        ),
        (
            "smtp",
            snapshot.smtp.enabled,
            snapshot.smtp.after_attempts,
            10,
        ),
    ] {
        if enabled && after_attempts == 1 {
            tiers.push(tier(cfg, name, timeout));
        }
    }
    DeliveryPolicy {
        name: "emergency-initial".to_string(),
        mode: if tiers.len() > 1 {
            "broadcast"
        } else {
            "cascade"
        }
        .to_string(),
        tiers,
    }
}

fn tier(cfg: &RuntimeConfig, name: &str, fallback_timeout: u64) -> Tier {
    Tier {
        name: name.to_string(),
        timeout_seconds: cfg
            .tiers
            .iter()
            .find(|tier| tier.name == name)
            .map(|tier| tier.timeout_seconds)
            .unwrap_or(fallback_timeout),
    }
}
