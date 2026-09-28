use super::*;

#[test]
fn sqlite_repeat_suppression_reserves_completes_and_expires() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();

    assert_eq!(
        store
            .reserve_repeat(&repeat_candidate(1_000.0, "first"))
            .unwrap(),
        RepeatDecision::Deliver {
            reservation_token: "first".to_string()
        }
    );
    assert!(matches!(
        store
            .reserve_repeat(&repeat_candidate(1_001.0, "concurrent"))
            .unwrap(),
        RepeatDecision::WaitForDelivery
    ));

    store
        .complete_repeat("same-rendered-notification", "first", Some(1_002.0))
        .unwrap();
    assert!(matches!(
        store
            .reserve_repeat(&repeat_candidate(1_003.0, "duplicate"))
            .unwrap(),
        RepeatDecision::Suppress {
            reason: RepeatSuppressionReason::RecentDelivery,
            last_delivered_at: Some(1_002.0),
            suppressed_count: 1,
        }
    ));

    let recent = store.recent_repeat_suppressions(10).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].title, "Host down");
    assert_eq!(recent[0].suppressed_count, 1);
    assert_eq!(recent[0].cooldown_s, 7_200);
    assert_eq!(recent[0].matched_rule.as_deref(), Some("test rule"));

    assert_eq!(
        store
            .reserve_repeat(&repeat_candidate(8_203.0, "after-cooldown"))
            .unwrap(),
        RepeatDecision::Deliver {
            reservation_token: "after-cooldown".to_string()
        }
    );
}

#[test]
fn failed_repeat_delivery_releases_reservation() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();

    store
        .reserve_repeat(&repeat_candidate(1_000.0, "failed"))
        .unwrap();
    store
        .complete_repeat("same-rendered-notification", "failed", None)
        .unwrap();

    assert!(matches!(
        store
            .reserve_repeat(&repeat_candidate(1_001.0, "retry"))
            .unwrap(),
        RepeatDecision::Deliver { .. }
    ));
}

#[test]
fn repeat_reservation_retry_with_same_token_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    let candidate = repeat_candidate(1_000.0, "same-attempt");

    assert!(matches!(
        store.reserve_repeat(&candidate).unwrap(),
        RepeatDecision::Deliver { .. }
    ));
    assert_eq!(
        store.reserve_repeat(&candidate).unwrap(),
        RepeatDecision::Deliver {
            reservation_token: "same-attempt".to_string()
        }
    );
}

#[test]
fn repeat_state_prunes_entries_older_than_supported_cooldown() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    store
        .reserve_repeat(&repeat_candidate(1_000.0, "old-delivery"))
        .unwrap();
    store
        .complete_repeat("same-rendered-notification", "old-delivery", Some(1_001.0))
        .unwrap();
    store
        .reserve_repeat(&repeat_candidate(1_002.0, "old-suppression"))
        .unwrap();
    assert_eq!(store.recent_repeat_suppressions(10).unwrap().len(), 1);

    let mut new_fingerprint = repeat_candidate(605_803.0, "new-delivery");
    new_fingerprint.fingerprint = "new-rendered-notification".to_string();
    store.reserve_repeat(&new_fingerprint).unwrap();

    assert!(store.recent_repeat_suppressions(10).unwrap().is_empty());
}
