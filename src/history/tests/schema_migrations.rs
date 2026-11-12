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

#[path = "schema_migrations_pg.rs"]
mod postgres_backend;
