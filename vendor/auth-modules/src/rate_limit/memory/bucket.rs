use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub(super) struct AttemptBucket {
    pub(super) attempts: Vec<Instant>,
    pub(super) window: Duration,
}

pub(super) fn ensure_capacity_for_key(
    attempts: &mut HashMap<String, AttemptBucket>,
    key: &str,
    now: Instant,
    max_buckets: usize,
) -> bool {
    if attempts.contains_key(key) {
        return true;
    }
    if attempts.len() >= max_buckets {
        attempts.retain(|_, bucket| {
            retain_recent(&mut bucket.attempts, now, bucket.window);
            !bucket.attempts.is_empty()
        });
    }
    attempts.len() < max_buckets
}

pub(super) fn retain_recent(bucket: &mut Vec<Instant>, now: Instant, window: Duration) {
    bucket.retain(|instant| now.duration_since(*instant) <= window);
}

pub(super) fn retry_after_for_bucket(
    bucket: &[Instant],
    max_attempts: usize,
    now: Instant,
    window: Duration,
) -> Option<Duration> {
    if bucket.len() < max_attempts {
        return None;
    }
    bucket
        .first()
        .copied()
        .and_then(|oldest| window.checked_sub(now.duration_since(oldest)))
        .unwrap_or_else(|| Duration::from_secs(1))
        .max(Duration::from_secs(1))
        .into()
}
