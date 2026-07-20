use super::*;
use auth_modules::rate_limit::GOLD_AUTH_ACCOUNT_FAILURE_MAX;

#[test]
fn sqlite_auth_lockout_survives_restart_and_clear() {
    let tmp = TempDir::new().unwrap();
    let cfg = sqlite_cfg(tmp.path().join("history.db"), 0);
    let key_hash = "hashed-account-key";
    {
        let store = HistoryStore::open(&cfg).unwrap();
        for _ in 0..GOLD_AUTH_ACCOUNT_FAILURE_MAX {
            store.record_auth_failure(key_hash, 1_000).unwrap();
        }
        assert!(store.auth_rate_limited(key_hash, 1_001).unwrap());
    }

    let store = HistoryStore::open(&cfg).unwrap();
    assert!(store.auth_rate_limited(key_hash, 1_002).unwrap());
    store.clear_auth_failures(key_hash).unwrap();
    assert!(!store.auth_rate_limited(key_hash, 1_003).unwrap());
}

#[test]
fn sqlite_storage_migration_copies_active_auth_lockout() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let key_hash = "migrated-account-key";
    let src_store = HistoryStore::open(&src).unwrap();
    for _ in 0..GOLD_AUTH_ACCOUNT_FAILURE_MAX {
        src_store.record_auth_failure(key_hash, 1_000).unwrap();
    }

    migrate_between(&src, &dst).unwrap();

    let dst_store = HistoryStore::open(&dst).unwrap();
    assert!(dst_store.auth_rate_limited(key_hash, 1_001).unwrap());
}

#[test]
fn sqlite_rate_limit_import_merges_failures_and_strongest_lockout() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let key_hash = "merged-account-key";
    let src_store = HistoryStore::open(&src).unwrap();
    let dst_store = HistoryStore::open(&dst).unwrap();
    import_rate_limit(
        &src_store,
        AuthRateLimitRecord {
            key_hash: key_hash.to_string(),
            state: auth_modules::rate_limit::PersistentRateLimitRecord {
                failure_epochs: vec![1_000, 1_001, 1_001],
                locked_until_epoch: Some(1_500),
            },
            updated_at: 1_200,
        },
    );
    import_rate_limit(
        &dst_store,
        AuthRateLimitRecord {
            key_hash: key_hash.to_string(),
            state: auth_modules::rate_limit::PersistentRateLimitRecord {
                failure_epochs: vec![1_001, 1_002],
                locked_until_epoch: Some(1_800),
            },
            updated_at: 1_300,
        },
    );

    migrate_between(&src, &dst).unwrap();
    migrate_between(&src, &dst).unwrap();

    let records = dst_store.export_auth_rate_limits().unwrap();
    let merged = records
        .iter()
        .find(|record| record.key_hash == key_hash)
        .unwrap();
    assert_eq!(merged.state.failure_epochs, vec![1_000, 1_001, 1_002]);
    assert_eq!(merged.state.locked_until_epoch, Some(1_800));
    assert_eq!(merged.updated_at, 1_300);
}

#[test]
fn sqlite_runtime_auth_state_import_rolls_back_as_one_transaction() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let src_store = HistoryStore::open(&src).unwrap();
    let dst_store = HistoryStore::open(&dst).unwrap();
    let session = auth_session("atomic-session", "basic", 1_000);
    src_store
        .create_auth_session(&session, None, 3, 1_000)
        .unwrap();
    src_store
        .record_auth_failure("atomic-rate-key", 1_000)
        .unwrap();
    let conn = rusqlite::Connection::open(&dst.sqlite_path).unwrap();
    conn.execute_batch(
        r#"
CREATE TRIGGER fail_atomic_auth_rate_import
BEFORE INSERT ON klaxond_auth_rate_limits
WHEN NEW.key_hash = 'atomic-rate-key'
BEGIN
  SELECT RAISE(ABORT, 'forced auth state import failure');
END;
"#,
    )
    .unwrap();

    let result = crate::history::migration::copy_runtime_auth_state(&src_store, &dst_store);

    assert!(result.is_err());
    assert!(dst_store.export_auth_sessions().unwrap().is_empty());
    assert!(dst_store.export_auth_rate_limits().unwrap().is_empty());
}
