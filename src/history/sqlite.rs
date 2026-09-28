use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub(super) mod auth_state;
mod delivery;
pub(super) mod emergency;
mod migration;
pub(super) mod rate_limit;
pub(super) mod repeat;
pub(super) mod session;

pub(super) use delivery::{
    activity as sqlite_delivery_activity, count as sqlite_delivery_count,
    export_all as sqlite_export_all, insert as sqlite_insert, page as sqlite_delivery_page,
    prune as sqlite_prune,
};
pub(super) use migration::migrate as migrate_sqlite;

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

pub(super) fn sqlite_column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(true);
        }
    }
    Ok(false)
}
