use crate::history::schema::{BASELINE_VERSION, MIGRATION_LOCK_KEY, ledger};
use anyhow::{Context, Result, anyhow};
use dual_db::{MigrationReport, postgres as pg};
use postgres::Client;

mod auth;
mod delivery;
mod emergency;
mod repeat;

/// PostgreSQL migrations. Version 9 reproduces, in order, the ensure-schema
/// of the pre-runner releases (see `history::schema`).
pub(in crate::history) fn migrations() -> Vec<pg::Migration> {
    vec![
        pg::Migration::new(BASELINE_VERSION, "baseline")
            .sql(delivery::SCHEMA)
            .sql(repeat::SCHEMA)
            .sql(delivery::ADD_COLUMNS)
            .sql(auth::SCHEMA)
            .sql(emergency::SCHEMA)
            .code(
                delivery::BACKFILL_SEARCH_ID,
                delivery::backfill_search_columns,
            ),
    ]
}

/// Runs the migrations, then the per-start reconciliation under the same
/// advisory lock: rows written without search columns or session family by a
/// pre-v9 binary (a rollback across schema 9) are repaired on every start,
/// as the pre-runner releases did.
pub(in crate::history) fn migrate(client: &mut Client) -> Result<MigrationReport> {
    let report = pg::migrate(client, &ledger()?, &migrations())
        .context("postgres history schema migration")?;
    let mut tx = client.transaction()?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])?;
    delivery::backfill_search_columns(&mut tx)
        .map_err(|error| anyhow!("postgres delivery search reconciliation: {error}"))?;
    tx.batch_execute(
        "UPDATE klaxond_auth_sessions SET family_hash = id_hash WHERE family_hash = ''",
    )?;
    tx.commit()?;
    Ok(report)
}
