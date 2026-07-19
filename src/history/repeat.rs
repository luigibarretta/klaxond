use serde::{Deserialize, Serialize};

pub(super) const REPEAT_STATE_RETENTION_SECONDS: f64 = 604_800.0;

#[derive(Clone, Debug)]
pub struct RepeatCandidate {
    pub fingerprint: String,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub now: f64,
    pub window_s: u64,
    pub reservation_token: String,
    pub reservation_ttl_s: f64,
}

impl RepeatCandidate {
    pub(super) fn cutoff(&self) -> f64 {
        self.now - self.window_s as f64
    }

    pub(super) fn reservation_until(&self) -> f64 {
        self.now + self.reservation_ttl_s
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepeatSuppressionReason {
    RecentDelivery,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RepeatDecision {
    Deliver {
        reservation_token: String,
    },
    Suppress {
        reason: RepeatSuppressionReason,
        last_delivered_at: Option<f64>,
        suppressed_count: u64,
    },
    WaitForDelivery,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepeatState {
    pub fingerprint: String,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub last_delivered_at: Option<f64>,
    pub last_suppressed_at: Option<f64>,
    pub suppressed_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RepeatSuppressionSummary {
    pub source: String,
    pub severity: String,
    pub title: String,
    pub last_delivered_at: Option<f64>,
    pub last_suppressed_at: f64,
    pub suppressed_count: u64,
}

impl RepeatState {
    pub(super) fn summary(self) -> Option<RepeatSuppressionSummary> {
        Some(RepeatSuppressionSummary {
            source: self.source,
            severity: self.severity,
            title: self.title,
            last_delivered_at: self.last_delivered_at,
            last_suppressed_at: self.last_suppressed_at?,
            suppressed_count: self.suppressed_count,
        })
    }
}
