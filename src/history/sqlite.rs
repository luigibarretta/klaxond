use super::{DeliveryEntry, SCHEMA_VERSION, dedupe_hash};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags, params};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub(super) mod auth_state;
pub(super) mod rate_limit;
pub(super) mod repeat;
pub(super) mod session;

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

pub(super) fn sqlite_insert(conn: &Connection, entry: &DeliveryEntry) -> Result<()> {
    let hash = dedupe_hash(entry);
    conn.execute(
        r#"
INSERT OR IGNORE INTO klaxond_deliveries
  (ts, source, severity, title, channel, suppressed_by, dedupe_hash)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
"#,
        params![
            entry.ts,
            &entry.source,
            &entry.severity,
            &entry.title,
            &entry.channel,
            &entry.suppressed_by,
            hash,
        ],
    )?;
    Ok(())
}

pub(super) fn sqlite_count(conn: &Connection) -> Result<usize> {
    Ok(
        conn.query_row("SELECT COUNT(*) FROM klaxond_deliveries", [], |row| {
            row.get::<_, i64>(0)
        })? as usize,
    )
}

pub(super) fn sqlite_page(
    conn: &Connection,
    limit: usize,
    offset: usize,
) -> Result<Vec<DeliveryEntry>> {
    let mut stmt = conn.prepare(
        r#"
SELECT ts, source, severity, title, channel, suppressed_by
FROM klaxond_deliveries
ORDER BY ts DESC, id DESC
LIMIT ?1 OFFSET ?2
"#,
    )?;
    let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
        Ok(DeliveryEntry {
            ts: row.get(0)?,
            source: row.get(1)?,
            severity: row.get(2)?,
            title: row.get(3)?,
            channel: row.get(4)?,
            suppressed_by: row.get(5)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub(super) fn sqlite_export_all(conn: &mut Connection) -> Result<Vec<DeliveryEntry>> {
    let tx = conn.unchecked_transaction()?;
    let rows = {
        let mut stmt = tx.prepare(
            r#"
SELECT ts, source, severity, title, channel, suppressed_by
FROM klaxond_deliveries
ORDER BY ts ASC, id ASC
"#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DeliveryEntry {
                ts: row.get(0)?,
                source: row.get(1)?,
                severity: row.get(2)?,
                title: row.get(3)?,
                channel: row.get(4)?,
                suppressed_by: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    tx.commit()?;
    Ok(rows)
}

pub(super) fn sqlite_prune(conn: &Connection, retention: usize) -> Result<()> {
    if retention == 0 {
        return Ok(());
    }
    conn.execute(
        r#"
DELETE FROM klaxond_deliveries
WHERE id NOT IN (
  SELECT id FROM klaxond_deliveries ORDER BY ts DESC, id DESC LIMIT ?1
)
"#,
        params![retention as i64],
    )?;
    Ok(())
}
