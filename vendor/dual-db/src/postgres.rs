//! PostgreSQL backend (synchronous `postgres` 0.19): runner, additive
//! helpers and snapshot.
//!
//! Every migration runs in its own transaction that first takes
//! `pg_advisory_xact_lock(lock_key)` and only then reads the ledger, so
//! concurrent runners (rolling restarts, several replicas) apply each
//! migration exactly once. The transaction-scoped lock is released by
//! COMMIT or ROLLBACK, so an error can never leak a held lock into a
//! pooled connection. All objects live in `current_schema()`.

use crate::error::{BoxError, Error, Result};
use crate::ledger::{plan, LedgerConfig, LedgerRow, MigrationReport, Next};
use crate::migration::{require_additive_column, require_identifier, validate_registry, Step};
use postgres::{Client, GenericClient, IsolationLevel, Transaction};

mod snapshot;

pub use snapshot::{ddl_fingerprint, snapshot};

/// Code-step function for PostgreSQL: runs inside the migration transaction.
pub type StepFn = fn(&mut Transaction<'_>) -> std::result::Result<(), BoxError>;

/// A PostgreSQL migration.
pub type Migration = crate::migration::Migration<StepFn>;

/// Applies every pending migration, one transaction each, and returns what
/// was done.
pub fn migrate(
    client: &mut Client,
    ledger: &LedgerConfig,
    migrations: &[Migration],
) -> Result<MigrationReport> {
    validate_registry(migrations)?;
    let mut report = MigrationReport::default();
    // Each pass records one migration or finishes, so len + 1 passes suffice.
    for _ in 0..=migrations.len() {
        // READ COMMITTED whatever default_transaction_isolation says: under
        // REPEATABLE READ or SERIALIZABLE the snapshot would predate the lock
        // wait, so a runner could miss the rows a concurrent one committed.
        let mut tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()?;
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&ledger.lock_key()])?;
        ensure_ledger(&mut tx, ledger.table())?;
        let rows = read_ledger(&mut tx, ledger.table())?;
        let next = plan(migrations, &rows, ledger.legacy())?;
        let (index, adopt) = match next {
            Next::Done(current) => {
                tx.commit()?;
                report.current = current;
                return Ok(report);
            }
            Next::Apply(index) => (index, false),
            Next::Adopt(index) => (index, true),
        };
        let Some(migration) = migrations.get(index) else {
            return Err(Error::InvalidRegistry("planned index out of range".into()));
        };
        run_preconditions(&mut tx, migration)?;
        run_steps(&mut tx, migration)?;
        if adopt {
            stamp_legacy_row(&mut tx, ledger.table(), migration)?;
            report.adopted.push(migration.version());
        } else {
            insert_row(&mut tx, ledger.table(), migration)?;
            report.applied.push(migration.version());
        }
        tx.commit()?;
    }
    Err(Error::InvalidRegistry("the runner did not converge".into()))
}

/// Read-only check that every migration is applied with a matching
/// checksum; nothing is created or written (usable by a runtime role that
/// does not own the schema).
pub fn verify(
    client: &mut impl GenericClient,
    ledger: &LedgerConfig,
    migrations: &[Migration],
) -> Result<MigrationReport> {
    validate_registry(migrations)?;
    if !table_exists(client, ledger.table())? {
        return Err(Error::LedgerFormat(format!(
            "{} is missing",
            ledger.table()
        )));
    }
    let rows = read_ledger(client, ledger.table())?;
    match plan(migrations, &rows, ledger.legacy())? {
        Next::Done(current) => Ok(MigrationReport {
            current,
            ..MigrationReport::default()
        }),
        Next::Apply(index) | Next::Adopt(index) => Err(Error::LedgerFormat(format!(
            "migration {} is not applied",
            migrations.get(index).map_or(0, |m| m.version())
        ))),
    }
}

/// True when `table` exists in `current_schema()`.
pub fn table_exists(client: &mut impl GenericClient, table: &str) -> Result<bool> {
    require_identifier("table", table)?;
    let row = client.query_one(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables
                         WHERE table_schema = current_schema() AND table_name = $1)",
        &[&table],
    )?;
    Ok(row.get(0))
}

/// True when `table` in `current_schema()` has `column`.
pub fn column_exists(client: &mut impl GenericClient, table: &str, column: &str) -> Result<bool> {
    require_identifier("table", table)?;
    require_identifier("column", column)?;
    let row = client.query_one(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns
                         WHERE table_schema = current_schema()
                           AND table_name = $1 AND column_name = $2)",
        &[&table, &column],
    )?;
    Ok(row.get(0))
}

/// Adds `column` to `table` unless it exists (`ADD COLUMN IF NOT EXISTS`);
/// returns whether it was added. Unquoted identifiers fold to lower case,
/// so pass lower-case names.
pub fn add_column_if_missing(
    client: &mut impl GenericClient,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<bool> {
    require_additive_column(table, column, definition)?;
    if column_exists(client, table, column)? {
        return Ok(false);
    }
    client.batch_execute(&format!(
        "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}"
    ))?;
    Ok(true)
}

fn run_steps(tx: &mut Transaction<'_>, migration: &Migration) -> Result<()> {
    for (index, step) in migration.steps().iter().enumerate() {
        let outcome: std::result::Result<(), BoxError> = match step {
            Step::Sql(sql) => tx.batch_execute(sql).map_err(Into::into),
            Step::AddColumnIfMissing {
                table,
                column,
                definition,
            } => add_column_if_missing(tx, table, column, definition)
                .map(|_| ())
                .map_err(Into::into),
            Step::Code { run, .. } => run(tx),
        };
        outcome.map_err(|source| Error::Step {
            version: migration.version(),
            name: migration.name().to_owned(),
            step: index,
            source,
        })?;
    }
    Ok(())
}

fn ensure_ledger(tx: &mut Transaction<'_>, table: &str) -> Result<()> {
    if !table_exists(tx, table)? {
        tx.batch_execute(&format!(
            "CREATE TABLE {table} (
               version BIGINT PRIMARY KEY,
               applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
               name TEXT,
               checksum TEXT
             )"
        ))?;
        return Ok(());
    }
    if !column_exists(tx, table, "version")? {
        return Err(Error::LedgerFormat(format!(
            "{table} has no version column"
        )));
    }
    add_column_if_missing(tx, table, "name", "TEXT")?;
    add_column_if_missing(tx, table, "checksum", "TEXT")?;
    Ok(())
}

fn read_ledger(client: &mut impl GenericClient, table: &str) -> Result<Vec<LedgerRow>> {
    let rows = client.query(
        &format!("SELECT version::bigint, name, checksum FROM {table} ORDER BY version"),
        &[],
    )?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(LedgerRow {
            version: row.try_get(0)?,
            name: row.try_get(1)?,
            checksum: row.try_get(2)?,
        });
    }
    Ok(out)
}

fn insert_row(tx: &mut Transaction<'_>, table: &str, migration: &Migration) -> Result<()> {
    tx.execute(
        &format!("INSERT INTO {table} (version, name, checksum) VALUES ($1, $2, $3)"),
        &[
            &migration.version(),
            &migration.name(),
            &migration.checksum(),
        ],
    )?;
    Ok(())
}

fn stamp_legacy_row(tx: &mut Transaction<'_>, table: &str, migration: &Migration) -> Result<()> {
    let changed = tx.execute(
        &format!(
            "UPDATE {table} SET name = $2, checksum = $3 WHERE version = $1 AND checksum IS NULL"
        ),
        &[
            &migration.version(),
            &migration.name(),
            &migration.checksum(),
        ],
    )?;
    if changed != 1 {
        return Err(Error::LedgerFormat(format!(
            "legacy row {} changed while it was adopted",
            migration.version()
        )));
    }
    Ok(())
}

fn run_preconditions(tx: &mut Transaction<'_>, migration: &Migration) -> Result<()> {
    for check in migration.preconditions() {
        check(tx).map_err(|source| Error::Precondition {
            version: migration.version(),
            name: migration.name().to_owned(),
            source,
        })?;
    }
    Ok(())
}
