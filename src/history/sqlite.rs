use super::SCHEMA_VERSION;
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags, params};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub(super) mod auth_state;
mod delivery;
pub(super) mod emergency;
pub(super) mod rate_limit;
pub(super) mod repeat;
pub(super) mod session;

pub(super) use delivery::{
    activity as sqlite_delivery_activity, count as sqlite_delivery_count,
    export_all as sqlite_export_all, insert as sqlite_insert, page as sqlite_delivery_page,
    prune as sqlite_prune,
};

pub(super) type SqliteConnection = Connection;

pub(super) fn open_sqlite(path: &Path, create_schema: bool) -> Result<Connection> {
    let flags = if create_schema {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        if !path.exists() {
            bail!("source sqlite history {} does not exist", path.display());
        }
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let conn = Connection::open_with_flags(path, flags)
        .with_context(|| format!("open sqlite history {}", path.display()))?;
    conn.busy_timeout(Duration::from_secs(5))?;
    if create_schema {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
    }
    Ok(conn)
}

pub(super) fn validate_sqlite_schema(conn: &Connection) -> Result<()> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'klaxond_deliveries'",
        [],
        |row| row.get(0),
    )?;
    if count == 0 {
        bail!("source sqlite history does not contain klaxond_deliveries");
    }
    Ok(())
}

pub(super) fn migrate_sqlite(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS klaxond_schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

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

CREATE TABLE IF NOT EXISTS klaxond_auth_sessions (
  id_hash TEXT PRIMARY KEY,
  family_hash TEXT NOT NULL,
  user_json TEXT NOT NULL,
  user_sub TEXT NOT NULL,
  auth_mode TEXT NOT NULL,
  provider_issuer TEXT,
  provider_session_id TEXT,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  last_rotated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_user
  ON klaxond_auth_sessions(user_sub, auth_mode, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_concurrent
  ON klaxond_auth_sessions(user_sub, last_seen_at DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_oidc_sid
  ON klaxond_auth_sessions(provider_issuer, provider_session_id)
  WHERE auth_mode = 'oidc' AND provider_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_oidc_sub
  ON klaxond_auth_sessions(provider_issuer, user_sub)
  WHERE auth_mode = 'oidc';

CREATE TABLE IF NOT EXISTS klaxond_oidc_logout_tokens (
  issuer TEXT NOT NULL,
  token_id_hash TEXT NOT NULL,
  consumed_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (issuer, token_id_hash)
);

CREATE INDEX IF NOT EXISTS idx_klaxond_oidc_logout_tokens_expiry
  ON klaxond_oidc_logout_tokens(expires_at);

CREATE TABLE IF NOT EXISTS klaxond_auth_rate_limits (
  key_hash TEXT PRIMARY KEY,
  failure_epochs_json TEXT NOT NULL,
  locked_until_epoch INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_klaxond_auth_rate_limits_updated
  ON klaxond_auth_rate_limits(updated_at);

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
"#,
    )?;
    if !sqlite_column_exists(conn, "klaxond_auth_sessions", "family_hash")? {
        conn.execute_batch(
            "ALTER TABLE klaxond_auth_sessions ADD COLUMN family_hash TEXT NOT NULL DEFAULT '';",
        )?;
    }
    if !sqlite_column_exists(conn, "klaxond_repeat_state", "cooldown_s")? {
        conn.execute_batch(
            "ALTER TABLE klaxond_repeat_state ADD COLUMN cooldown_s INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    if !sqlite_column_exists(conn, "klaxond_repeat_state", "matched_rule")? {
        conn.execute_batch("ALTER TABLE klaxond_repeat_state ADD COLUMN matched_rule TEXT;")?;
    }
    if !sqlite_column_exists(conn, "klaxond_emergencies", "policy_id")? {
        conn.execute_batch(
            "ALTER TABLE klaxond_emergencies ADD COLUMN policy_id TEXT NOT NULL DEFAULT '';",
        )?;
    }
    if !sqlite_column_exists(conn, "klaxond_emergencies", "policy_name")? {
        conn.execute_batch(
            "ALTER TABLE klaxond_emergencies ADD COLUMN policy_name TEXT NOT NULL DEFAULT '';",
        )?;
    }
    if !sqlite_column_exists(conn, "klaxond_emergencies", "policy_snapshot_json")? {
        conn.execute_batch(
            "ALTER TABLE klaxond_emergencies ADD COLUMN policy_snapshot_json TEXT NOT NULL DEFAULT '';",
        )?;
    }
    if !sqlite_column_exists(conn, "klaxond_deliveries", "emergency_receipt_id")? {
        conn.execute_batch("ALTER TABLE klaxond_deliveries ADD COLUMN emergency_receipt_id TEXT;")?;
    }
    migrate_delivery_search_columns(conn)?;
    conn.execute(
        "UPDATE klaxond_auth_sessions SET family_hash = id_hash WHERE family_hash = ''",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_family ON klaxond_auth_sessions(family_hash)",
        [],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO klaxond_schema_migrations(version) VALUES (?1)",
        params![SCHEMA_VERSION],
    )?;
    Ok(())
}

fn migrate_delivery_search_columns(conn: &Connection) -> Result<()> {
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

    let rows = {
        let mut statement = conn.prepare(
            "SELECT id, source, severity, title, channel, suppressed_by \
             FROM klaxond_deliveries WHERE search_version < 1",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
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
                super::delivery_search_values(&source, &severity, &title, &channel, &suppressed_by);
            update.execute(params![
                id, &values[0], &values[1], &values[2], &values[3], &values[4]
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn sqlite_column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(true);
        }
    }
    Ok(false)
}
