//! SQLite backend (rusqlite 0.41): runner, additive helpers and snapshot.
//!
//! Every migration runs in its own `BEGIN IMMEDIATE` transaction. The
//! immediate transaction takes the database write lock before the ledger is
//! read, so a second process migrating the same file waits (up to the
//! connection's `busy_timeout`) and then sees the first one's ledger rows:
//! this is the SQLite equivalent of the PostgreSQL advisory lock.

use crate::error::{BoxError, Error, Result};
use crate::ledger::{plan, LedgerConfig, LedgerRow, MigrationReport, Next};
use crate::migration::{require_additive_column, require_identifier, validate_registry, Step};
use rusqlite::{params, Connection, OptionalExtension};

mod snapshot;

pub use snapshot::{ddl_fingerprint, snapshot};

/// Code-step function for SQLite: runs inside the migration transaction.
pub type StepFn = fn(&Connection) -> std::result::Result<(), BoxError>;

/// A SQLite migration.
pub type Migration = crate::migration::Migration<StepFn>;

/// Applies every pending migration, one transaction each, and returns what
/// was done. The connection must not be inside a transaction.
pub fn migrate(
    conn: &Connection,
    ledger: &LedgerConfig,
    migrations: &[Migration],
) -> Result<MigrationReport> {
    validate_registry(migrations)?;
    if !conn.is_autocommit() {
        return Err(Error::TransactionInProgress);
    }
    let mut report = MigrationReport::default();
    // Each pass records one migration or finishes, so len + 1 passes suffice.
    for _ in 0..=migrations.len() {
        let tx = ImmediateTx::begin(conn)?;
        ensure_ledger(conn, ledger.table())?;
        let rows = read_ledger(conn, ledger.table())?;
        let plan_next = plan(migrations, &rows, ledger.legacy())?;
        match plan_next {
            Next::Done(current) => {
                tx.commit()?;
                report.current = current;
                return Ok(report);
            }
            Next::Apply(index) | Next::Adopt(index) => {
                let adopt = matches!(plan_next, Next::Adopt(_));
                let Some(migration) = migrations.get(index) else {
                    return Err(Error::InvalidRegistry("planned index out of range".into()));
                };
                run_steps(conn, migration)?;
                if adopt {
                    stamp_legacy_row(conn, ledger.table(), migration)?;
                    report.adopted.push(migration.version());
                } else {
                    insert_row(conn, ledger.table(), migration)?;
                    report.applied.push(migration.version());
                }
                tx.commit()?;
            }
        }
    }
    Err(Error::InvalidRegistry("the runner did not converge".into()))
}

/// Read-only check that every migration is applied with a matching
/// checksum; nothing is created or written.
pub fn verify(
    conn: &Connection,
    ledger: &LedgerConfig,
    migrations: &[Migration],
) -> Result<MigrationReport> {
    validate_registry(migrations)?;
    if !table_exists(conn, ledger.table())? {
        return Err(Error::LedgerFormat(format!(
            "{} is missing",
            ledger.table()
        )));
    }
    let rows = read_ledger(conn, ledger.table())?;
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

/// True when `table` exists.
pub fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    require_identifier("table", table)?;
    let found = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 COLLATE NOCASE",
            [table],
            |_| Ok(()),
        )
        .optional()?;
    Ok(found.is_some())
}

/// True when `table` has `column` (SQLite names are case-insensitive).
pub fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    require_identifier("table", table)?;
    require_identifier("column", column)?;
    let found = conn
        .query_row(
            "SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2 COLLATE NOCASE",
            params![table, column],
            |_| Ok(()),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Adds `column` to `table` unless it exists; returns whether it was added.
/// The existing column's type is not compared (the consumers' historical
/// schemas are trusted as they are).
pub fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<bool> {
    require_additive_column(table, column, definition)?;
    if column_exists(conn, table, column)? {
        return Ok(false);
    }
    conn.execute_batch(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition}"
    ))?;
    Ok(true)
}

fn run_steps(conn: &Connection, migration: &Migration) -> Result<()> {
    for (index, step) in migration.steps().iter().enumerate() {
        let outcome: std::result::Result<(), BoxError> = match step {
            Step::Sql(sql) => conn.execute_batch(sql).map_err(Into::into),
            Step::AddColumnIfMissing {
                table,
                column,
                definition,
            } => add_column_if_missing(conn, table, column, definition)
                .map(|_| ())
                .map_err(Into::into),
            Step::Code { run, .. } => run(conn),
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

fn ensure_ledger(conn: &Connection, table: &str) -> Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {table} (
           version INTEGER PRIMARY KEY,
           applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
           name TEXT,
           checksum TEXT
         )"
    ))?;
    if !column_exists(conn, table, "version")? {
        return Err(Error::LedgerFormat(format!(
            "{table} has no version column"
        )));
    }
    add_column_if_missing(conn, table, "name", "TEXT")?;
    add_column_if_missing(conn, table, "checksum", "TEXT")?;
    Ok(())
}

fn read_ledger(conn: &Connection, table: &str) -> Result<Vec<LedgerRow>> {
    let mut statement = conn.prepare(&format!(
        "SELECT version, name, checksum FROM {table} ORDER BY version"
    ))?;
    let rows = statement
        .query_map([], |row| {
            Ok(LedgerRow {
                version: row.get(0)?,
                name: row.get(1)?,
                checksum: row.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn insert_row(conn: &Connection, table: &str, migration: &Migration) -> Result<()> {
    conn.execute(
        &format!("INSERT INTO {table} (version, name, checksum) VALUES (?1, ?2, ?3)"),
        params![migration.version(), migration.name(), migration.checksum()],
    )?;
    Ok(())
}

fn stamp_legacy_row(conn: &Connection, table: &str, migration: &Migration) -> Result<()> {
    let changed = conn.execute(
        &format!(
            "UPDATE {table} SET name = ?2, checksum = ?3 WHERE version = ?1 AND checksum IS NULL"
        ),
        params![migration.version(), migration.name(), migration.checksum()],
    )?;
    if changed != 1 {
        return Err(Error::LedgerFormat(format!(
            "legacy row {} changed while it was adopted",
            migration.version()
        )));
    }
    Ok(())
}

/// `BEGIN IMMEDIATE` guard: rolls back on drop unless committed.
struct ImmediateTx<'c> {
    conn: &'c Connection,
    open: bool,
}

impl<'c> ImmediateTx<'c> {
    fn begin(conn: &'c Connection) -> Result<Self> {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(Self { conn, open: true })
    }

    fn commit(mut self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        self.open = false;
        Ok(())
    }
}

impl Drop for ImmediateTx<'_> {
    fn drop(&mut self) {
        if self.open && !self.conn.is_autocommit() {
            // Best effort: the original error is what the caller reports.
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}
