use std::time::Duration;

use super::*;

#[test]
fn blocks_after_threshold_and_clears() {
    let limiter = InMemoryRateLimiter::new();
    let window = Duration::from_secs(60);
    let key = "password-login:alice";

    assert!(!limiter.blocked(key, 2, window));
    limiter.record(key, window);
    assert!(!limiter.blocked(key, 2, window));
    limiter.record(key, window);
    assert!(limiter.blocked(key, 2, window));

    limiter.clear(key);
    assert!(!limiter.blocked(key, 2, window));
}

#[test]
fn record_attempt_reports_remaining_and_retry_after() {
    let limiter = InMemoryRateLimiter::new();
    let window = Duration::from_secs(60);
    let key = "pat:42:requests";

    let first = limiter.record_attempt(key, 2, window);
    assert_eq!(
        first,
        RateLimitDecision {
            allowed: true,
            remaining: 1,
            retry_after: None,
        }
    );

    let second = limiter.record_attempt(key, 2, window);
    assert_eq!(
        second,
        RateLimitDecision {
            allowed: true,
            remaining: 0,
            retry_after: None,
        }
    );

    let blocked = limiter.record_attempt(key, 2, window);
    assert!(!blocked.allowed);
    assert_eq!(blocked.remaining, 0);
    assert!(blocked.retry_after.is_some());
}

#[test]
fn record_attempt_outcome_wraps_decision_shape() {
    let limiter = InMemoryRateLimiter::new();
    let window = Duration::from_secs(60);
    let key = "login:alice";

    assert_eq!(
        limiter.record_attempt_outcome(key, 1, window),
        RateLimitOutcome::Allowed {
            remaining: 0,
            reset_after: None,
        }
    );
    let outcome = limiter.record_attempt_outcome(key, 1, window);
    assert!(!outcome.allowed());
    assert!(outcome.retry_after().is_some());
}

#[test]
fn bucket_helpers_check_independent_limits() {
    let limiter = InMemoryRateLimiter::new();
    let buckets = [
        RateLimitBucket {
            key: "user:alice",
            max_attempts: 1,
            window: Duration::from_secs(60),
        },
        RateLimitBucket {
            key: "ip:203.0.113.7",
            max_attempts: 2,
            window: Duration::from_secs(60),
        },
    ];

    assert!(limiter.retry_after_for_buckets(buckets).is_none());
    limiter.record_buckets(buckets);
    assert!(limiter.retry_after_for_buckets(buckets).is_some());
}

#[test]
fn retry_after_uses_max_remaining_for_multiple_keys() {
    let limiter = InMemoryRateLimiter::new();
    let window = Duration::from_secs(60);
    let keys = ["password-login:ip:203.0.113.7", "password-login:user:alice"];

    limiter.record_many(keys, window);
    limiter.record_many(keys, window);

    let retry = limiter.retry_after(keys, 2, window).expect("retry-after");

    assert!(retry >= Duration::from_secs(1));
    assert!(retry <= window);
}

#[test]
fn zero_threshold_is_always_blocked() {
    let limiter = InMemoryRateLimiter::new();

    assert!(limiter.blocked("any", 0, Duration::from_secs(60)));
}

#[test]
fn persistent_policy_locks_after_threshold() {
    let policy =
        PersistentRateLimitPolicy::new(2, Duration::from_secs(60), Duration::from_secs(300));
    let mut record = PersistentRateLimitRecord::default();

    assert!(!policy.locked(&mut record, 1_000));
    policy.record_failure(&mut record, 1_000);
    assert!(!policy.locked(&mut record, 1_001));
    policy.record_failure(&mut record, 1_002);

    assert!(policy.locked(&mut record, 1_003));
    assert_eq!(record.locked_until_epoch, Some(1_302));
}

#[test]
fn gold_account_failure_policy_uses_standard_thresholds() {
    let policy = gold_auth_account_failure_policy();

    assert_eq!(policy.max_failures, GOLD_AUTH_ACCOUNT_FAILURE_MAX);
    assert_eq!(policy.failure_window, Duration::from_secs(5 * 60));
    assert_eq!(policy.lockout_window, Duration::from_secs(10 * 60));
    assert_eq!(GOLD_AUTH_IP_BURST_MAX, 50);
    assert_eq!(GOLD_AUTH_IP_BURST_WINDOW, Duration::from_secs(60));
    assert_eq!(GOLD_AUTH_SHORT_BURST_MAX, 10);
    assert_eq!(GOLD_AUTH_SHORT_BURST_WINDOW, Duration::from_secs(60));
}

#[test]
fn persistent_policy_retain_keeps_active_lockouts_after_failures_expire() {
    let policy =
        PersistentRateLimitPolicy::new(2, Duration::from_secs(60), Duration::from_secs(300));
    let mut record = PersistentRateLimitRecord {
        failure_epochs: vec![1_000, 1_001],
        locked_until_epoch: Some(1_300),
    };

    assert!(policy.retain_record(&mut record, 1_100));
    assert!(record.failure_epochs.is_empty());
    assert_eq!(record.locked_until_epoch, Some(1_300));

    assert!(!policy.retain_record(&mut record, 1_301));
    assert_eq!(record.locked_until_epoch, None);
}
