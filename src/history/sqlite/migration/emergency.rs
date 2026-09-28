use super::super::sqlite_column_exists;
use anyhow::Result;
use rusqlite::Connection;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_emergencies (
  receipt_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  policy_id TEXT NOT NULL DEFAULT '',
  policy_name TEXT NOT NULL DEFAULT '',
  policy_snapshot_json TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  next_retry_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  last_sent_at REAL,
  terminal_at REAL,
  terminal_by TEXT NOT NULL DEFAULT '',
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL,
  telegram_escalated_at REAL,
  smtp_escalated_at REAL,
  last_error TEXT NOT NULL DEFAULT '',
  reserved_until REAL NOT NULL DEFAULT 0,
  reservation_token TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_klaxond_emergencies_active_fingerprint
  ON klaxond_emergencies(fingerprint) WHERE state='active';
CREATE INDEX IF NOT EXISTS idx_klaxond_emergencies_due
  ON klaxond_emergencies(state,next_retry_at,reserved_until);
CREATE INDEX IF NOT EXISTS idx_klaxond_emergencies_created
  ON klaxond_emergencies(created_at DESC);
"#;

pub(super) fn create(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

pub(super) fn add_policy_columns(conn: &Connection) -> Result<()> {
    for (column, definition) in [
        ("policy_id", "TEXT NOT NULL DEFAULT ''"),
        ("policy_name", "TEXT NOT NULL DEFAULT ''"),
        ("policy_snapshot_json", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !sqlite_column_exists(conn, "klaxond_emergencies", column)? {
            conn.execute_batch(&format!(
                "ALTER TABLE klaxond_emergencies ADD COLUMN {column} {definition};"
            ))?;
        }
    }
    Ok(())
}
