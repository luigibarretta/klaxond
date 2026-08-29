use super::*;

#[test]
fn checking_an_unknown_key_does_not_allocate_a_bucket() {
    let limiter = InMemoryRateLimiter::with_max_buckets(2);

    assert_eq!(
        limiter.retry_after(["unknown"], 2, Duration::from_secs(60)),
        None
    );
    assert!(limiter.lock_attempts().is_empty());
}

#[test]
fn bucket_count_stays_within_the_configured_bound() {
    let limiter = InMemoryRateLimiter::with_max_buckets(2);
    let window = Duration::from_secs(60);

    limiter.record("one", window);
    limiter.record("two", window);
    limiter.record("three", window);

    let attempts = limiter.lock_attempts();
    assert_eq!(attempts.len(), 2);
    assert!(!attempts.contains_key("three"));
}

#[test]
fn capacity_exhaustion_fails_closed_for_unknown_keys() {
    let limiter = InMemoryRateLimiter::with_max_buckets(1);
    let window = Duration::from_secs(60);
    limiter.record("known", window);

    let decision = limiter.record_attempt("unknown", 10, window);

    assert!(!decision.allowed);
    assert_eq!(decision.retry_after, Some(window));
    assert!(limiter.blocked("another-unknown", 10, window));
}

#[test]
fn poisoned_mutex_does_not_disable_rate_limiting() {
    let limiter = InMemoryRateLimiter::with_max_buckets(2);
    let shared = limiter.inner.clone();
    let _ = std::panic::catch_unwind(move || {
        let _guard = shared.lock().expect("test lock");
        panic!("poison limiter mutex");
    });

    let first = limiter.record_attempt("account", 1, Duration::from_secs(60));
    let second = limiter.record_attempt("account", 1, Duration::from_secs(60));

    assert!(first.allowed);
    assert!(!second.allowed);
}

#[test]
fn debug_output_does_not_expose_rate_limit_keys() {
    let limiter = InMemoryRateLimiter::new();
    limiter.record("password:user@example.test", Duration::from_secs(60));

    let debug = format!("{limiter:?}");
    assert!(debug.contains("bucket_count"));
    assert!(!debug.contains("user@example.test"));
}
