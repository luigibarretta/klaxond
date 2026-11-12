//! Delivery history.

use crate::history::delivery_search_values;
use dual_db::BoxError;
use rusqlite::{Connection, params};

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  channel TEXT NOT NULL,
  suppressed_by TEXT NOT NULL DEFAULT '',
  emergency_receipt_id TEXT,
  search_source TEXT NOT NULL DEFAULT '',
  search_severity TEXT NOT NULL DEFAULT '',
  search_title TEXT NOT NULL DEFAULT '',
  search_channel TEXT NOT NULL DEFAULT '',
  search_suppressed_by TEXT NOT NULL DEFAULT '',
  search_version INTEGER NOT NULL DEFAULT 0,
  dedupe_hash TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_klaxond_deliveries_dedupe_hash ON klaxond_deliveries(dedupe_hash);
CREATE INDEX IF NOT EXISTS idx_klaxond_deliveries_ts_id_desc ON klaxond_deliveries(ts DESC, id DESC);
"#;

/// Columns added after the table first shipped.
pub(super) const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    ("klaxond_deliveries", "emergency_receipt_id", "TEXT"),
    (
        "klaxond_deliveries",
        "search_source",
        "TEXT NOT NULL DEFAULT ''",
    ),
    (
        "klaxond_deliveries",
        "search_severity",
        "TEXT NOT NULL DEFAULT ''",
    ),
    (
        "klaxond_deliveries",
        "search_title",
        "TEXT NOT NULL DEFAULT ''",
    ),
    (
        "klaxond_deliveries",
        "search_channel",
        "TEXT NOT NULL DEFAULT ''",
    ),
    (
        "klaxond_deliveries",
        "search_suppressed_by",
        "TEXT NOT NULL DEFAULT ''",
    ),
    (
        "klaxond_deliveries",
        "search_version",
        "INTEGER NOT NULL DEFAULT 0",
    ),
];

/// Checksummed id of the search backfill: bump it if its effect changes.
pub(super) const BACKFILL_SEARCH_ID: &str = "delivery_search_backfill_v1";

type LegacyDeliverySearchRow = (i64, String, String, String, String, String);

/// Fills the search columns of rows written before they existed. Runs
/// inside the migration transaction.
pub(super) fn backfill_search_columns(conn: &Connection) -> Result<(), BoxError> {
    let rows = load_legacy_search_rows(conn)?;
    let mut update = conn.prepare(
        r#"
UPDATE klaxond_deliveries SET
  search_source = ?2,
  search_severity = ?3,
  search_title = ?4,
  search_channel = ?5,
  search_suppressed_by = ?6,
  search_version = 1
WHERE id = ?1
"#,
    )?;
    for (id, source, severity, title, channel, suppressed_by) in rows {
        let values = delivery_search_values(&source, &severity, &title, &channel, &suppressed_by);
        update.execute(params![
            id, &values[0], &values[1], &values[2], &values[3], &values[4]
        ])?;
    }
    Ok(())
}

fn load_legacy_search_rows(conn: &Connection) -> rusqlite::Result<Vec<LegacyDeliverySearchRow>> {
    let mut statement = conn.prepare(
        "SELECT id, source, severity, title, channel, suppressed_by \
         FROM klaxond_deliveries WHERE search_version < 1",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    })?;
    rows.collect()
}
