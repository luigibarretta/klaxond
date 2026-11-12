//! Schema-parity check for consumer test suites (features `sqlite` and
//! `postgres`).
//!
//! ```no_run
//! # fn demo(
//! #     sqlite: &rusqlite::Connection,
//! #     pg: &mut postgres::Client,
//! #     ledger: &dual_db::LedgerConfig,
//! #     sqlite_migrations: &[dual_db::sqlite::Migration],
//! #     pg_migrations: &[dual_db::postgres::Migration],
//! # ) -> dual_db::Result<()> {
//! dual_db::parity::migrate_and_compare(sqlite, sqlite_migrations, pg, pg_migrations, ledger)?;
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
use crate::ledger::LedgerConfig;
use crate::schema::{LogicalSchema, SnapshotOptions};

/// Compares two snapshots; `Err(Error::ParityMismatch)` lists every
/// difference.
pub fn compare(sqlite: &LogicalSchema, postgres: &LogicalSchema) -> Result<()> {
    let diffs = sqlite.diff(postgres);
    if diffs.is_empty() {
        Ok(())
    } else {
        Err(Error::ParityMismatch(diffs))
    }
}

/// Applies both registries (fresh or partially migrated databases alike),
/// snapshots both schemas without the ledger table and compares them.
/// The PostgreSQL client should point at an empty, dedicated schema or
/// database.
pub fn migrate_and_compare(
    sqlite: &rusqlite::Connection,
    sqlite_migrations: &[crate::sqlite::Migration],
    postgres: &mut postgres::Client,
    postgres_migrations: &[crate::postgres::Migration],
    ledger: &LedgerConfig,
) -> Result<()> {
    crate::sqlite::migrate(sqlite, ledger, sqlite_migrations)?;
    crate::postgres::migrate(postgres, ledger, postgres_migrations)?;
    let options = SnapshotOptions::default().exclude(ledger.table());
    let left = crate::sqlite::snapshot(sqlite, &options)?;
    let right = crate::postgres::snapshot(postgres, &options)?;
    compare(&left, &right)
}
