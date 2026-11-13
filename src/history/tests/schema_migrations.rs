//! Schema runner adoption: history databases written by the last pre-runner
//! release (fixtures generated at 28a0dac, see fixtures/README.md) keep
//! their schema and data, the version-only ledger is upgraded once and its
//! row 9 adopted, nothing is applied twice; both backends keep parity.

use super::*;
use crate::history::schema::{BASELINE_VERSION, LEDGER_TABLE};
use dual_db::schema::SnapshotOptions;
use std::collections::BTreeMap;

const SQLITE_FIXTURE: &str = include_str!("fixtures/pre_dual_db.sqlitedump");

fn options() -> SnapshotOptions {
    SnapshotOptions::default().exclude(LEDGER_TABLE)
}

fn sqlite_rows(conn: &rusqlite::Connection) -> BTreeMap<String, Vec<String>> {
    let tables: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    tables
        .into_iter()
        .filter(|table| table != LEDGER_TABLE)
        .map(|table| {
            let mut statement = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let width = statement.column_count();
            let mut rows: Vec<String> = statement
                .query_map([], |row| {
                    (0..width)
                        .map(|i| row.get_ref(i).map(|value| format!("{value:?}")))
                        .collect::<Result<Vec<_>, _>>()
                        .map(|cells| cells.join("|"))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            rows.sort();
            (table, rows)
        })
        .collect()
}

type LedgerRows = Vec<(i64, Option<String>, Option<String>)>;

fn sqlite_ledger(conn: &rusqlite::Connection) -> LedgerRows {
    conn.prepare(&format!(
        "SELECT version, name, checksum FROM {LEDGER_TABLE} ORDER BY version"
    ))
    .unwrap()
    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

/// History rows 5 to 8 (a database upgraded release after release) and the
/// adopted baseline row.
fn expected_ledger(checksum: String) -> LedgerRows {
    let mut rows: LedgerRows = (5..BASELINE_VERSION).map(|v| (v, None, None)).collect();
    rows.push((BASELINE_VERSION, Some("baseline".into()), Some(checksum)));
    rows
}

#[test]
fn sqlite_history_of_the_previous_release_is_adopted_unchanged() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("history.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(SQLITE_FIXTURE).unwrap();
    conn.execute_batch(&format!(
        "INSERT INTO {LEDGER_TABLE}(version) VALUES (5), (6), (7), (8)"
    ))
    .unwrap();
    let ddl = dual_db::sqlite::ddl_fingerprint(&conn, &options()).unwrap();
    let logical = dual_db::sqlite::snapshot(&conn, &options()).unwrap();
    let rows = sqlite_rows(&conn);
    assert_eq!(rows["klaxond_deliveries"].len(), 3);

    let report = super::super::sqlite::migrate_sqlite(&conn).unwrap();
    assert_eq!(report.adopted, vec![BASELINE_VERSION]);
    assert!(report.applied.is_empty(), "nothing is applied as new");
    let again = super::super::sqlite::migrate_sqlite(&conn).unwrap();
    assert!(again.applied.is_empty() && again.adopted.is_empty());
    drop(conn);
    let store = HistoryStore::open(&sqlite_cfg(path.clone(), 0)).unwrap();
    assert_eq!(store.deliveries_page(10, 0).unwrap().total, 3);
    drop(store);

    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        dual_db::sqlite::ddl_fingerprint(&conn, &options()).unwrap(),
        ddl
    );
    assert_eq!(
        dual_db::sqlite::snapshot(&conn, &options()).unwrap(),
        logical
    );
    assert_eq!(sqlite_rows(&conn), rows);
    let checksum = super::super::sqlite::sqlite_migrations()[0].checksum();
    assert_eq!(sqlite_ledger(&conn), expected_ledger(checksum));
}

#[test]
fn fresh_sqlite_history_matches_the_previous_release_schema() {
    let tmp = TempDir::new().unwrap();
    let legacy = rusqlite::Connection::open(tmp.path().join("legacy.db")).unwrap();
    legacy.execute_batch(SQLITE_FIXTURE).unwrap();
    let path = tmp.path().join("fresh.db");
    drop(HistoryStore::open(&sqlite_cfg(path.clone(), 0)).unwrap());
    let fresh = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        dual_db::sqlite::ddl_fingerprint(&fresh, &options()).unwrap(),
        dual_db::sqlite::ddl_fingerprint(&legacy, &options()).unwrap()
    );
}

#[test]
fn history_migrated_by_a_newer_release_is_refused() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("history.db");
    drop(HistoryStore::open(&sqlite_cfg(path.clone(), 0)).unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            &format!("INSERT INTO {LEDGER_TABLE}(version) VALUES (10)"),
            [],
        )
        .unwrap();
    let error = HistoryStore::open(&sqlite_cfg(path, 0))
        .err()
        .expect("a newer schema must stop the start");
    assert!(
        format!("{error:#}").contains("newer than this binary"),
        "{error:#}"
    );
}

#[test]
fn released_migrations_are_immutable() {
    // Applied migrations are immutable; add a new migration. Any byte change
    // (SCHEMA text, whitespace, CRLF, ADDED_COLUMNS order) lands here.
    let sqlite = dual_db::verify_pinned_checksums(
        &super::super::sqlite::sqlite_migrations(),
        crate::history::schema::RELEASED_CHECKSUMS_SQLITE,
    );
    let postgres = dual_db::verify_pinned_checksums(
        &super::super::postgres::postgres_migrations(),
        crate::history::schema::RELEASED_CHECKSUMS_POSTGRES,
    );
    for (label, result) in [("sqlite", sqlite), ("postgres", postgres)] {
        if let Err(error) = result {
            panic!("{label}: {error} (applied migrations are immutable; add a new migration)");
        }
    }
}

/// Schema 8 history: no emergency policy, no search columns, no family.
const SQLITE_SCHEMA_8: &str = r#"
CREATE TABLE klaxond_schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
INSERT INTO klaxond_schema_migrations(version) VALUES (1), (2), (4), (5), (6), (7), (8);
CREATE TABLE klaxond_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, source TEXT NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL, channel TEXT NOT NULL,
  suppressed_by TEXT NOT NULL DEFAULT '', dedupe_hash TEXT NOT NULL
);
CREATE TABLE klaxond_repeat_state (
  fingerprint TEXT PRIMARY KEY, source TEXT NOT NULL, severity TEXT NOT NULL,
  title TEXT NOT NULL, last_delivered_at REAL, last_suppressed_at REAL,
  suppressed_count INTEGER NOT NULL DEFAULT 0, reserved_until REAL NOT NULL DEFAULT 0,
  reservation_token TEXT NOT NULL DEFAULT ''
);
CREATE TABLE klaxond_auth_sessions (
  id_hash TEXT PRIMARY KEY, user_json TEXT NOT NULL, user_sub TEXT NOT NULL,
  auth_mode TEXT NOT NULL, provider_issuer TEXT, provider_session_id TEXT,
  created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
  last_rotated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
);
INSERT INTO klaxond_deliveries (ts, source, severity, title, channel, dedupe_hash)
VALUES (1000, 'grafana', 'warning', 'Disk OLD', 'ntfy', 'old-row');
INSERT INTO klaxond_auth_sessions VALUES
  ('sess-old', '{}', 'luigi', 'basic', NULL, NULL, 1, 1, 1, 4102444800, NULL);
"#;

/// Table -> column names and index names (nullability and column order of
/// added columns legitimately differ from a fresh database, as before).
fn shape(conn: &rusqlite::Connection) -> (BTreeMap<String, Vec<String>>, Vec<String>) {
    let snapshot = dual_db::sqlite::snapshot(conn, &options()).unwrap();
    let tables = snapshot
        .tables
        .into_iter()
        .map(|(name, table)| (name, table.columns.into_keys().collect()))
        .collect();
    (tables, snapshot.indexes.into_keys().collect())
}

#[test]
fn sqlite_history_at_schema_8_gets_the_baseline_applied() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("history.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(SQLITE_SCHEMA_8).unwrap();
    let report = super::super::sqlite::migrate_sqlite(&conn).unwrap();
    assert_eq!(
        report.applied,
        vec![BASELINE_VERSION],
        "applied, not adopted"
    );
    assert!(report.adopted.is_empty());
    drop(conn);
    let store = HistoryStore::open(&sqlite_cfg(path.clone(), 0)).unwrap();
    let mut query = DeliveryQuery::page(10, 0);
    query.q = Some("disk old".into());
    assert_eq!(
        store.query_deliveries(&query).unwrap().total,
        1,
        "search backfilled"
    );
    drop(store);

    let fresh_path = tmp.path().join("fresh.db");
    drop(HistoryStore::open(&sqlite_cfg(fresh_path.clone(), 0)).unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        shape(&conn),
        shape(&rusqlite::Connection::open(&fresh_path).unwrap())
    );
    let family: String = conn
        .query_row("SELECT family_hash FROM klaxond_auth_sessions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(family, "sess-old");
    let ledger = sqlite_ledger(&conn);
    assert_eq!(ledger.len(), 8);
    assert!(ledger[..7].iter().all(|row| row.2.is_none()));
    assert_eq!(ledger[7].0, BASELINE_VERSION);
    assert!(ledger[7].2.is_some());
}

#[path = "schema_migrations_pg.rs"]
mod postgres_backend;
