use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub remaining: usize,
    pub retry_after: Option<Duration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed {
        remaining: usize,
        reset_after: Option<Duration>,
    },
    Denied {
        retry_after: Duration,
    },
    Locked {
        retry_after: Duration,
    },
}

impl RateLimitOutcome {
    pub fn allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Allowed { .. } => None,
            Self::Denied { retry_after } | Self::Locked { retry_after } => Some(*retry_after),
        }
    }
}

impl From<RateLimitDecision> for RateLimitOutcome {
    fn from(decision: RateLimitDecision) -> Self {
        if decision.allowed {
            Self::Allowed {
                remaining: decision.remaining,
                reset_after: decision.retry_after,
            }
        } else {
            Self::Denied {
                retry_after: decision
                    .retry_after
                    .unwrap_or_else(|| Duration::from_secs(1)),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitBucket<'a> {
    pub key: &'a str,
    pub max_attempts: usize,
    pub window: Duration,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PersistentRateLimitRecord {
    pub failure_epochs: Vec<i64>,
    pub locked_until_epoch: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentRateLimitPolicy {
    pub max_failures: usize,
    pub failure_window: Duration,
    pub lockout_window: Duration,
}

impl PersistentRateLimitPolicy {
    pub fn new(max_failures: usize, failure_window: Duration, lockout_window: Duration) -> Self {
        Self {
            max_failures,
            failure_window,
            lockout_window,
        }
    }

    pub fn locked(&self, record: &mut PersistentRateLimitRecord, now_epoch: i64) -> bool {
        self.prune_record(record, now_epoch);
        record
            .locked_until_epoch
            .is_some_and(|locked_until| locked_until > now_epoch)
    }

    pub fn record_failure(&self, record: &mut PersistentRateLimitRecord, now_epoch: i64) {
        self.prune_record(record, now_epoch);
        record.failure_epochs.push(now_epoch);
        let threshold = self.max_failures.max(1);
        if record.failure_epochs.len() >= threshold {
            record.locked_until_epoch =
                Some(now_epoch.saturating_add(duration_secs_i64(self.lockout_window)));
        }
        if record.failure_epochs.len() > threshold {
            let excess = record.failure_epochs.len() - threshold;
            record.failure_epochs.drain(..excess);
        }
    }

    pub fn retain_record(&self, record: &mut PersistentRateLimitRecord, now_epoch: i64) -> bool {
        self.prune_record(record, now_epoch);
        record
            .locked_until_epoch
            .is_some_and(|locked_until| locked_until > now_epoch)
            || !record.failure_epochs.is_empty()
    }

    fn prune_record(&self, record: &mut PersistentRateLimitRecord, now_epoch: i64) {
        let cutoff = now_epoch.saturating_sub(duration_secs_i64(self.failure_window));
        record
            .failure_epochs
            .retain(|failure_epoch| *failure_epoch >= cutoff);
        if record
            .locked_until_epoch
            .is_some_and(|locked_until| locked_until <= now_epoch)
        {
            record.locked_until_epoch = None;
        }
    }
}

fn duration_secs_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}
