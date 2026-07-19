use super::*;

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
fn postgres_repeat_reservation_is_atomic_across_workers() {
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    let cfg = postgres_cfg(url);
    let open_barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let first_cfg = cfg.clone();
    let first_barrier = open_barrier.clone();
    let first_open = std::thread::spawn(move || {
        first_barrier.wait();
        HistoryStore::open(&first_cfg)
    });
    let second_cfg = cfg.clone();
    let second_barrier = open_barrier.clone();
    let second_open = std::thread::spawn(move || {
        second_barrier.wait();
        HistoryStore::open(&second_cfg)
    });
    open_barrier.wait();
    let first = first_open.join().unwrap().unwrap();
    let second = second_open.join().unwrap().unwrap();
    let fingerprint = format!("postgres-concurrent-{}", crate::util::token_urlsafe(12));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let first_barrier = barrier.clone();
    let second_barrier = barrier.clone();
    let mut first_candidate = repeat_candidate(1_000.0, "worker-a");
    first_candidate.fingerprint = fingerprint.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first.reserve_repeat(&first_candidate)
    });
    let mut second_candidate = repeat_candidate(1_000.0, "worker-b");
    second_candidate.fingerprint = fingerprint;
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second.reserve_repeat(&second_candidate)
    });

    barrier.wait();
    let decisions = [
        first_thread.join().unwrap().unwrap(),
        second_thread.join().unwrap().unwrap(),
    ];
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, RepeatDecision::Deliver { .. }))
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, RepeatDecision::WaitForDelivery))
            .count(),
        1
    );
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_repeat_import_preserves_non_null_timestamps() {
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    let store = HistoryStore::open(&postgres_cfg(url)).unwrap();
    let fingerprint = format!("postgres-null-import-{}", crate::util::token_urlsafe(12));
    let populated = RepeatState {
        fingerprint: fingerprint.clone(),
        source: "grafana".into(),
        severity: "warning".into(),
        title: "Populated".into(),
        last_delivered_at: Some(100.0),
        last_suppressed_at: Some(101.0),
        suppressed_count: 2,
    };
    store.import_repeat_state(&populated).unwrap();
    store
        .import_repeat_state(&RepeatState {
            last_delivered_at: None,
            last_suppressed_at: None,
            suppressed_count: 1,
            ..populated
        })
        .unwrap();

    let state = store
        .export_repeat_states()
        .unwrap()
        .into_iter()
        .find(|state| state.fingerprint == fingerprint)
        .expect("imported repeat state");
    assert_eq!(state.last_delivered_at, Some(100.0));
    assert_eq!(state.last_suppressed_at, Some(101.0));
    assert_eq!(state.suppressed_count, 2);
}
