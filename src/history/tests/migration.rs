use super::*;

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
fn sqlite_history_migration_accepts_delivery_schema_without_receipt_id() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("old.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("new.db"), 0);
    let conn = rusqlite::Connection::open(&src.sqlite_path).unwrap();
    conn.execute_batch(
        r#"
CREATE TABLE klaxond_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  channel TEXT NOT NULL,
  suppressed_by TEXT NOT NULL DEFAULT '',
  dedupe_hash TEXT NOT NULL
);
INSERT INTO klaxond_deliveries
  (ts, source, severity, title, channel, suppressed_by, dedupe_hash)
VALUES (1000, 'grafana', 'critical', 'Old emergency', 'ntfy', '', 'old-row');
"#,
    )
    .unwrap();
    drop(conn);

    assert_eq!(migrate_between(&src, &dst).unwrap(), 1);
    let page = HistoryStore::open(&dst)
        .unwrap()
        .deliveries_page(10, 0)
        .unwrap();
    assert_eq!(page.entries[0].emergency_receipt_id, None);
}

#[test]
fn sqlite_repeat_state_migrates_selective_rule_columns() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("history.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        r#"
CREATE TABLE klaxond_repeat_state (
  fingerprint TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  last_delivered_at REAL,
  last_suppressed_at REAL,
  suppressed_count INTEGER NOT NULL DEFAULT 0,
  reserved_until REAL NOT NULL DEFAULT 0,
  reservation_token TEXT NOT NULL DEFAULT ''
);
"#,
    )
    .unwrap();
    drop(conn);

    let store = HistoryStore::open(&sqlite_cfg(path.clone(), 0)).unwrap();
    drop(store);

    let conn = rusqlite::Connection::open(path).unwrap();
    let mut statement = conn
        .prepare("PRAGMA table_info(klaxond_repeat_state)")
        .unwrap();
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(columns.iter().any(|column| column == "cooldown_s"));
    assert!(columns.iter().any(|column| column == "matched_rule"));
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
