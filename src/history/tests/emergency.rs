use super::*;

fn candidate(receipt: &str, fingerprint: &str, now: f64) -> EmergencyCandidate {
    EmergencyCandidate {
        receipt_id: receipt.into(),
        fingerprint: fingerprint.into(),
        source: "grafana".into(),
        severity: "critical".into(),
        title: "Host is down".into(),
        payload_json: "{}".into(),
        now,
        next_retry_at: now + 60.0,
        expires_at: now + 3_600.0,
        max_attempts: 50,
    }
}

#[test]
fn sqlite_emergency_coalesces_and_survives_restart() {
    let tmp = TempDir::new().unwrap();
    let cfg = sqlite_cfg(tmp.path().join("history.db"), 0);
    {
        let store = HistoryStore::open(&cfg).unwrap();
        let first = store
            .emergency_register(&candidate("receipt-a", "same-incident", 1_000.0))
            .unwrap();
        assert!(first.created);
        let second = store
            .emergency_register(&candidate("receipt-b", "same-incident", 1_001.0))
            .unwrap();
        assert!(!second.created);
        assert_eq!(second.incident.receipt_id, "receipt-a");
    }
    let reopened = HistoryStore::open(&cfg).unwrap();
    let incident = reopened.emergency_get("receipt-a").unwrap().unwrap();
    assert_eq!(incident.state, "active");
    assert_eq!(reopened.emergencies(Some("active"), 10).unwrap().len(), 1);
}

#[test]
fn sqlite_emergency_lease_and_ack_are_race_safe() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    store
        .emergency_register(&candidate("receipt", "incident", 1_000.0))
        .unwrap();
    let reserved = store
        .emergency_reserve_due(1_060.0, 1_090.0, "lease-a")
        .unwrap()
        .unwrap();
    assert_eq!(reserved.reservation_token, "lease-a");
    assert!(
        store
            .emergency_reserve_due(1_061.0, 1_091.0, "lease-b")
            .unwrap()
            .is_none()
    );
    let acked = store
        .emergency_terminalize("receipt", "acknowledged", "test", 1_062.0)
        .unwrap()
        .unwrap();
    assert_eq!(acked.state, "acknowledged");
    assert!(
        !store
            .emergency_complete_attempt(&EmergencyAttempt {
                receipt_id: "receipt".into(),
                reservation_token: "lease-a".into(),
                now: 1_063.0,
                next_retry_at: 1_123.0,
                ntfy_ok: true,
                telegram_ok: None,
                smtp_ok: None,
                last_error: String::new(),
            })
            .unwrap()
    );
    assert_eq!(store.emergency_get("receipt").unwrap().unwrap().attempts, 0);
}

#[test]
fn sqlite_emergency_expires_at_time_or_attempt_cap() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    let mut time = candidate("time", "time-incident", 1_000.0);
    time.expires_at = 1_030.0;
    store.emergency_register(&time).unwrap();
    let mut attempts = candidate("attempts", "attempt-incident", 1_000.0);
    attempts.max_attempts = 1;
    store.emergency_register(&attempts).unwrap();
    store
        .emergency_initial_attempt(&EmergencyAttempt {
            receipt_id: "attempts".into(),
            reservation_token: String::new(),
            now: 1_001.0,
            next_retry_at: 1_061.0,
            ntfy_ok: true,
            telegram_ok: None,
            smtp_ok: None,
            last_error: String::new(),
        })
        .unwrap();
    let expired = store.emergency_expire_due(1_031.0, 10).unwrap();
    assert_eq!(expired.len(), 2);
    assert!(expired.iter().all(|incident| incident.state == "expired"));
}

#[test]
fn sqlite_storage_migration_copies_emergency_receipts() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    HistoryStore::open(&src)
        .unwrap()
        .emergency_register(&candidate("migrated", "migrated-incident", 1_000.0))
        .unwrap();
    migrate_between(&src, &dst).unwrap();
    assert_eq!(
        HistoryStore::open(&dst)
            .unwrap()
            .emergency_get("migrated")
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
}

#[test]
fn sqlite_storage_migration_accepts_pre_emergency_source_schema() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src-v5.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst-v6.db"), 0);
    drop(HistoryStore::open(&src).unwrap());
    rusqlite::Connection::open(&src.sqlite_path)
        .unwrap()
        .execute_batch(
            "DROP TABLE klaxond_emergencies;
             DELETE FROM klaxond_schema_migrations WHERE version = 6;",
        )
        .unwrap();

    migrate_between(&src, &dst).unwrap();

    assert!(
        HistoryStore::open(&dst)
            .unwrap()
            .emergencies(None, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_emergency_registration_is_atomic_across_workers() {
    let _guard = postgres_test_guard();
    let url =
        std::env::var("KLAXOND_TEST_POSTGRES_URL").expect("KLAXOND_TEST_POSTGRES_URL is required");
    let cfg = HistoryConfig {
        backend: "postgres".into(),
        sqlite_path: PathBuf::from("/tmp/unused"),
        postgres_url: url,
        retention: 0,
        default_limit: 500,
    };
    let fingerprint = format!("emergency-concurrent-{}", crate::util::token_urlsafe(8));
    let first = HistoryStore::open(&cfg).unwrap();
    let second = HistoryStore::open(&cfg).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let b1 = barrier.clone();
    let fp1 = fingerprint.clone();
    let t1 = std::thread::spawn(move || {
        b1.wait();
        first
            .emergency_register(&candidate("pg-a", &fp1, 1_000.0))
            .unwrap()
    });
    let b2 = barrier.clone();
    let fp2 = fingerprint.clone();
    let t2 = std::thread::spawn(move || {
        b2.wait();
        second
            .emergency_register(&candidate("pg-b", &fp2, 1_000.0))
            .unwrap()
    });
    barrier.wait();
    let registrations = [t1.join().unwrap(), t2.join().unwrap()];
    assert_eq!(registrations.iter().filter(|r| r.created).count(), 1);
    assert_eq!(
        registrations[0].incident.receipt_id,
        registrations[1].incident.receipt_id
    );
}
