use crate::history::schema::{BASELINE_VERSION, ledger};
use anyhow::{Context, Result, anyhow};
use dual_db::{MigrationReport, sqlite};
use rusqlite::{Connection, Transaction, TransactionBehavior};

mod auth;
mod delivery;
mod emergency;
mod repeat;

/// SQLite migrations. Version 9 reproduces, in order, the ensure-schema of
/// the pre-runner releases (see `history::schema`).
pub(in crate::history) fn migrations() -> Vec<sqlite::Migration> {
    let mut baseline = sqlite::Migration::new(BASELINE_VERSION, "baseline")
        .sql(delivery::SCHEMA)
        .sql(repeat::SCHEMA)
        .sql(auth::SCHEMA)
        .sql(emergency::SCHEMA)
        .add_column_if_missing(
            "klaxond_auth_sessions",
            "family_hash",
            "TEXT NOT NULL DEFAULT ''",
        );
    for (table, column, definition) in repeat::ADDED_COLUMNS
        .iter()
        .chain(emergency::ADDED_COLUMNS)
        .chain(delivery::ADDED_COLUMNS)
    {
        baseline = baseline.add_column_if_missing(table, column, definition);
    }
    vec![
        baseline
            .code(
                delivery::BACKFILL_SEARCH_ID,
                delivery::backfill_search_columns,
            )
            .sql(auth::BACKFILL_FAMILY),
    ]
}

/// Runs the migrations, then the per-start reconciliation: rows written
/// without search columns or session family by a pre-v9 binary (a rollback
/// across schema 9) are repaired on every start, as the pre-runner releases
/// did. Both statements touch only rows that still need it.
pub(in crate::history) fn migrate(conn: &Connection) -> Result<MigrationReport> {
    let report = sqlite::migrate(conn, &ledger()?, &migrations())
        .context("sqlite history schema migration")?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    delivery::backfill_search_columns(&tx)
        .map_err(|error| anyhow!("sqlite delivery search reconciliation: {error}"))?;
    tx.execute_batch(auth::RECONCILE_FAMILY)?;
    tx.commit()?;
    Ok(report)
}
