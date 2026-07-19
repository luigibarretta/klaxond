use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

mod postgres_repeat;

fn sqlite_cfg(path: PathBuf, retention: usize) -> HistoryConfig {
    HistoryConfig {
        backend: "sqlite".to_string(),
        sqlite_path: path,
        postgres_url: String::new(),
        retention,
        default_limit: 500,
    }
}

fn entry(i: usize) -> DeliveryEntry {
    DeliveryEntry {
        ts: 1000.0 + i as f64,
        source: "grafana".to_string(),
        severity: "warning".to_string(),
        title: format!("Alert {i}"),
        channel: "ntfy".to_string(),
        suppressed_by: String::new(),
    }
}

fn repeat_candidate(now: f64, token: &str) -> RepeatCandidate {
    RepeatCandidate {
        fingerprint: "same-rendered-notification".to_string(),
        source: "grafana".to_string(),
        severity: "warning".to_string(),
        title: "Host down".to_string(),
        now,
        window_s: 7_200,
        reservation_token: token.to_string(),
        reservation_ttl_s: 120.0,
    }
}

#[test]
fn sqlite_history_paginates_and_prunes_by_retention() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 3)).unwrap();
    for i in 0..5 {
        store.record_delivery(&entry(i)).unwrap();
    }

    let page = store.deliveries_page(2, 0).unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].title, "Alert 4");
    assert_eq!(page.entries[1].title, "Alert 3");

    let second = store.deliveries_page(2, 2).unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].title, "Alert 2");
}

#[test]
fn sqlite_history_migration_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let src_store = HistoryStore::open(&src).unwrap();
    src_store.record_delivery(&entry(1)).unwrap();
    src_store.record_delivery(&entry(2)).unwrap();

    assert_eq!(migrate_between(&src, &dst).unwrap(), 2);
    assert_eq!(migrate_between(&src, &dst).unwrap(), 2);

    let dst_store = HistoryStore::open(&dst).unwrap();
    let page = dst_store.deliveries_page(10, 0).unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(page.entries[0].title, "Alert 2");
}

#[test]
fn sqlite_history_migration_requires_existing_source() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("missing.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let err = migrate_between(&src, &dst).unwrap_err().to_string();
    assert!(err.contains("open source history store"));
    assert!(!src.sqlite_path.exists());
}

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

#[test]
fn sqlite_history_migration_copies_repeat_suppression_state() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let src_store = HistoryStore::open(&src).unwrap();
    src_store
        .reserve_repeat(&repeat_candidate(1_000.0, "delivered"))
        .unwrap();
    src_store
        .complete_repeat("same-rendered-notification", "delivered", Some(1_001.0))
        .unwrap();
    src_store
        .reserve_repeat(&repeat_candidate(1_002.0, "suppressed"))
        .unwrap();

    migrate_between(&src, &dst).unwrap();

    let dst_store = HistoryStore::open(&dst).unwrap();
    let recent = dst_store.recent_repeat_suppressions(10).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].last_delivered_at, Some(1_001.0));
    assert_eq!(recent[0].suppressed_count, 1);
}
