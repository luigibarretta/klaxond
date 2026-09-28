use super::super::sqlite_column_exists;
use anyhow::Result;
use rusqlite::Connection;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_repeat_state (
  fingerprint TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  last_delivered_at REAL,
  last_suppressed_at REAL,
  suppressed_count INTEGER NOT NULL DEFAULT 0,
  reserved_until REAL NOT NULL DEFAULT 0,
  reservation_token TEXT NOT NULL DEFAULT '',
  cooldown_s INTEGER NOT NULL DEFAULT 0,
  matched_rule TEXT
);

CREATE INDEX IF NOT EXISTS idx_klaxond_repeat_suppressed_desc
  ON klaxond_repeat_state(last_suppressed_at DESC)
  WHERE last_suppressed_at IS NOT NULL;
"#;

pub(super) fn create(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

pub(super) fn add_rule_columns(conn: &Connection) -> Result<()> {
    if !sqlite_column_exists(conn, "klaxond_repeat_state", "cooldown_s")? {
        conn.execute_batch(
            "ALTER TABLE klaxond_repeat_state ADD COLUMN cooldown_s INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    if !sqlite_column_exists(conn, "klaxond_repeat_state", "matched_rule")? {
        conn.execute_batch("ALTER TABLE klaxond_repeat_state ADD COLUMN matched_rule TEXT;")?;
    }
    Ok(())
}
