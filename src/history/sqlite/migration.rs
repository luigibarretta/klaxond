use crate::history::SCHEMA_VERSION;
use anyhow::Result;
use rusqlite::{Connection, params};

mod auth;
mod delivery;
mod emergency;
mod repeat;

const MIGRATIONS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
"#;

pub(in crate::history) fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(MIGRATIONS_SCHEMA)?;
    delivery::create(conn)?;
    repeat::create(conn)?;
    auth::create(conn)?;
    emergency::create(conn)?;

    auth::add_family_column(conn)?;
    repeat::add_rule_columns(conn)?;
    emergency::add_policy_columns(conn)?;
    delivery::add_receipt_column(conn)?;
    delivery::migrate_search_columns(conn)?;
    auth::backfill_family(conn)?;

    conn.execute(
        "INSERT OR IGNORE INTO klaxond_schema_migrations(version) VALUES (?1)",
        params![SCHEMA_VERSION],
    )?;
    Ok(())
}
