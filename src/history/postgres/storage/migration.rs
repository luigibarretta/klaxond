use crate::history::SCHEMA_VERSION;
use anyhow::Result;
use postgres::Client;

mod auth;
mod delivery;
mod emergency;
mod repeat;

const MIGRATION_LOCK_KEY: i64 = 5_426_893_470_587_711_020;
const MIGRATIONS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_schema_migrations (
  version BIGINT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"#;

pub(in crate::history::postgres) fn migrate(client: &mut Client) -> Result<()> {
    let mut tx = client.transaction()?;
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])?;
    tx.batch_execute(MIGRATIONS_SCHEMA)?;
    delivery::create(&mut tx)?;
    repeat::create(&mut tx)?;
    delivery::add_columns(&mut tx)?;
    auth::create(&mut tx)?;
    emergency::create(&mut tx)?;
    delivery::backfill_search_columns(&mut tx)?;
    tx.execute(
        "INSERT INTO klaxond_schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING",
        &[&SCHEMA_VERSION],
    )?;
    tx.commit()?;
    Ok(())
}
