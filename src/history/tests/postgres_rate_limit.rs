use super::*;
use auth_modules::rate_limit::GOLD_AUTH_ACCOUNT_FAILURE_MAX;

fn postgres_cfg(url: String) -> HistoryConfig {
    HistoryConfig {
        backend: "postgres".to_string(),
        sqlite_path: PathBuf::from("/tmp/klaxond-unused.db"),
        postgres_url: url,
        retention: 0,
        default_limit: 500,
    }
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_auth_failure_updates_are_atomic_across_workers() {
    let _guard = postgres_test_guard();
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    let cfg = postgres_cfg(url);
    let first = HistoryStore::open(&cfg).unwrap();
    let second = HistoryStore::open(&cfg).unwrap();
    let key_hash = format!("postgres-rate-limit-{}", crate::util::token_urlsafe(12));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let first_barrier = barrier.clone();
    let first_key = key_hash.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        for _ in 0..GOLD_AUTH_ACCOUNT_FAILURE_MAX / 2 {
            first.record_auth_failure(&first_key, 1_000).unwrap();
        }
    });
    let second_barrier = barrier.clone();
    let second_key = key_hash.clone();
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        for _ in 0..GOLD_AUTH_ACCOUNT_FAILURE_MAX / 2 {
            second.record_auth_failure(&second_key, 1_000).unwrap();
        }
    });

    barrier.wait();
    first_thread.join().unwrap();
    second_thread.join().unwrap();

    let reopened = HistoryStore::open(&cfg).unwrap();
    assert!(reopened.auth_rate_limited(&key_hash, 1_001).unwrap());
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_rate_limit_import_is_monotonic_and_idempotent() {
    let _guard = postgres_test_guard();
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    let store = HistoryStore::open(&postgres_cfg(url)).unwrap();
    let key_hash = format!("postgres-rate-import-{}", crate::util::token_urlsafe(12));
    let stronger = AuthRateLimitRecord {
        key_hash: key_hash.clone(),
        state: auth_modules::rate_limit::PersistentRateLimitRecord {
            failure_epochs: vec![1_001, 1_002],
            locked_until_epoch: Some(1_800),
        },
        updated_at: 1_300,
    };
    let stale = AuthRateLimitRecord {
        key_hash: key_hash.clone(),
        state: auth_modules::rate_limit::PersistentRateLimitRecord {
            failure_epochs: vec![1_000, 1_001, 1_001],
            locked_until_epoch: Some(1_500),
        },
        updated_at: 1_200,
    };
    import_rate_limit(&store, stronger);
    import_rate_limit(&store, stale.clone());
    import_rate_limit(&store, stale);

    let merged = store
        .export_auth_rate_limits()
        .unwrap()
        .into_iter()
        .find(|record| record.key_hash == key_hash)
        .unwrap();
    assert_eq!(merged.state.failure_epochs, vec![1_000, 1_001, 1_002]);
    assert_eq!(merged.state.locked_until_epoch, Some(1_800));
    assert_eq!(merged.updated_at, 1_300);
}
