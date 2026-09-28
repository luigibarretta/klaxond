use super::super::sqlite_column_exists;
use crate::history::delivery_search_values;
use anyhow::Result;
use rusqlite::{Connection, params};

const SCHEMA: &str = r#"
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

type LegacyDeliverySearchRow = (i64, String, String, String, String, String);

pub(super) fn create(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

pub(super) fn add_receipt_column(conn: &Connection) -> Result<()> {
    if !sqlite_column_exists(conn, "klaxond_deliveries", "emergency_receipt_id")? {
        conn.execute_batch("ALTER TABLE klaxond_deliveries ADD COLUMN emergency_receipt_id TEXT;")?;
    }
    Ok(())
}

pub(super) fn migrate_search_columns(conn: &Connection) -> Result<()> {
    add_search_columns(conn)?;
    backfill_search_columns(conn)
}

fn add_search_columns(conn: &Connection) -> Result<()> {
    for column in [
        "search_source",
        "search_severity",
        "search_title",
        "search_channel",
        "search_suppressed_by",
    ] {
        if !sqlite_column_exists(conn, "klaxond_deliveries", column)? {
            conn.execute_batch(&format!(
                "ALTER TABLE klaxond_deliveries ADD COLUMN {column} TEXT NOT NULL DEFAULT '';"
            ))?;
        }
    }
    if !sqlite_column_exists(conn, "klaxond_deliveries", "search_version")? {
        conn.execute_batch(
            "ALTER TABLE klaxond_deliveries ADD COLUMN search_version INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    Ok(())
}

fn backfill_search_columns(conn: &Connection) -> Result<()> {
    let rows = load_legacy_search_rows(conn)?;
    let tx = conn.unchecked_transaction()?;
    {
        let mut update = tx.prepare(
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
            let values =
                delivery_search_values(&source, &severity, &title, &channel, &suppressed_by);
            update.execute(params![
                id, &values[0], &values[1], &values[2], &values[3], &values[4]
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn load_legacy_search_rows(conn: &Connection) -> Result<Vec<LegacyDeliverySearchRow>> {
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
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}
