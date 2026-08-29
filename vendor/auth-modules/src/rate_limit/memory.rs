use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use self::bucket::{ensure_capacity_for_key, retain_recent, retry_after_for_bucket, AttemptBucket};
use super::{RateLimitBucket, RateLimitDecision, RateLimitOutcome};

mod bucket;

const DEFAULT_MAX_BUCKETS: usize = 4096;

#[derive(Clone)]
pub struct InMemoryRateLimiter {
    inner: Arc<Mutex<HashMap<String, AttemptBucket>>>,
    max_buckets: usize,
}

impl fmt::Debug for InMemoryRateLimiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bucket_count = self
            .inner
            .lock()
            .map(|attempts| attempts.len())
            .unwrap_or_default();
        formatter
            .debug_struct("InMemoryRateLimiter")
            .field("bucket_count", &bucket_count)
            .field("max_buckets", &self.max_buckets)
            .finish()
    }
}

impl Default for InMemoryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRateLimiter {
    pub fn new() -> Self {
        Self::with_max_buckets(DEFAULT_MAX_BUCKETS)
    }

    pub fn with_max_buckets(max_buckets: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_buckets: max_buckets.max(1),
        }
    }

    pub fn blocked(&self, key: &str, max_attempts: usize, window: Duration) -> bool {
        self.retry_after([key], max_attempts, window).is_some()
    }

    pub fn retry_after<I, K>(
        &self,
        keys: I,
        max_attempts: usize,
        window: Duration,
    ) -> Option<Duration>
    where
        I: IntoIterator<Item = K>,
        K: AsRef<str>,
    {
        if max_attempts == 0 {
            return Some(window.max(Duration::from_secs(1)));
        }

        let now = Instant::now();
        let mut attempts = self.lock_attempts();
        let mut longest_retry = None;
        let mut empty_keys = Vec::new();
        for key in keys {
            let key = key.as_ref();
            let Some(bucket) = attempts.get_mut(key) else {
                if attempts.len() >= self.max_buckets {
                    longest_retry = longest_retry.max(Some(window.max(Duration::from_secs(1))));
                }
                continue;
            };
            bucket.window = bucket.window.max(window);
            retain_recent(&mut bucket.attempts, now, bucket.window);
            longest_retry = longest_retry.max(retry_after_for_bucket(
                &bucket.attempts,
                max_attempts,
                now,
                bucket.window,
            ));
            if bucket.attempts.is_empty() {
                empty_keys.push(key.to_string());
            }
        }
        for key in empty_keys {
            attempts.remove(&key);
        }
        longest_retry
    }

    pub fn record(&self, key: &str, window: Duration) {
        self.record_many([key], window);
    }

    pub fn record_attempt(
        &self,
        key: &str,
        max_attempts: usize,
        window: Duration,
    ) -> RateLimitDecision {
        if max_attempts == 0 {
            return RateLimitDecision {
                allowed: false,
                remaining: 0,
                retry_after: Some(window.max(Duration::from_secs(1))),
            };
        }

        let now = Instant::now();
        let mut attempts = self.lock_attempts();
        if !ensure_capacity_for_key(&mut attempts, key, now, self.max_buckets) {
            return RateLimitDecision {
                allowed: false,
                remaining: 0,
                retry_after: Some(window.max(Duration::from_secs(1))),
            };
        }
        let bucket = attempts
            .entry(key.to_string())
            .or_insert_with(|| AttemptBucket {
                attempts: Vec::new(),
                window,
            });
        bucket.window = bucket.window.max(window);
        retain_recent(&mut bucket.attempts, now, bucket.window);
        if let Some(retry_after) =
            retry_after_for_bucket(&bucket.attempts, max_attempts, now, bucket.window)
        {
            return RateLimitDecision {
                allowed: false,
                remaining: 0,
                retry_after: Some(retry_after),
            };
        }

        bucket.attempts.push(now);
        RateLimitDecision {
            allowed: true,
            remaining: max_attempts - bucket.attempts.len(),
            retry_after: None,
        }
    }

    pub fn record_attempt_outcome(
        &self,
        key: &str,
        max_attempts: usize,
        window: Duration,
    ) -> RateLimitOutcome {
        self.record_attempt(key, max_attempts, window).into()
    }

    pub fn retry_after_for_buckets<'a, I>(&self, buckets: I) -> Option<Duration>
    where
        I: IntoIterator<Item = RateLimitBucket<'a>>,
    {
        buckets
            .into_iter()
            .filter_map(|bucket| self.retry_after([bucket.key], bucket.max_attempts, bucket.window))
            .max()
    }

    pub fn record_buckets<'a, I>(&self, buckets: I)
    where
        I: IntoIterator<Item = RateLimitBucket<'a>>,
    {
        for bucket in buckets {
            self.record(bucket.key, bucket.window);
        }
    }

    pub fn record_many<I, K>(&self, keys: I, window: Duration)
    where
        I: IntoIterator<Item = K>,
        K: AsRef<str>,
    {
        let now = Instant::now();
        let mut attempts = self.lock_attempts();
        for key in keys {
            let key = key.as_ref();
            if !ensure_capacity_for_key(&mut attempts, key, now, self.max_buckets) {
                continue;
            }
            let bucket = attempts
                .entry(key.to_string())
                .or_insert_with(|| AttemptBucket {
                    attempts: Vec::new(),
                    window,
                });
            bucket.window = bucket.window.max(window);
            retain_recent(&mut bucket.attempts, now, bucket.window);
            bucket.attempts.push(now);
        }
    }

    pub fn clear(&self, key: &str) {
        self.clear_many([key]);
    }

    pub fn clear_many<I, K>(&self, keys: I)
    where
        I: IntoIterator<Item = K>,
        K: AsRef<str>,
    {
        let mut attempts = self.lock_attempts();
        for key in keys {
            attempts.remove(key.as_ref());
        }
    }

    fn lock_attempts(&self) -> std::sync::MutexGuard<'_, HashMap<String, AttemptBucket>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests;
