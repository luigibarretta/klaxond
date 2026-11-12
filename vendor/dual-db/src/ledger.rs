//! Ledger configuration and the backend-independent planning step.
//!
//! Ledger table (both backends, column order of a fresh table):
//!
//! | column       | SQLite                                   | PostgreSQL                          |
//! |--------------|------------------------------------------|-------------------------------------|
//! | `version`    | `INTEGER PRIMARY KEY`                    | `BIGINT PRIMARY KEY`                |
//! | `applied_at` | `INTEGER NOT NULL DEFAULT (unix seconds)`| `TIMESTAMPTZ NOT NULL DEFAULT now()`|
//! | `name`       | `TEXT` (NULL only on legacy rows)        | `TEXT`                              |
//! | `checksum`   | `TEXT` (NULL only on legacy rows)        | `TEXT`                              |
//!
//! An existing table that has `version` but lacks `name` or `checksum` gets
//! them added (nullable) inside the migration transaction: that is the
//! one-time ledger-format upgrade. Its pre-existing rows become legacy rows.

use crate::error::{Error, Result};
use crate::migration::{require_identifier, Migration};

/// What to do with legacy rows: ledger rows with a version but no checksum,
/// written by an earlier implementation that recorded only a schema version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyRows {
    /// Refuse to run (default): a ledger row without checksum is an error.
    Reject,
    /// Accept legacy rows up to the newest registered version. A legacy row
    /// below the first registered migration is kept as history. A legacy row
    /// whose version matches a registered migration is *adopted*: the
    /// migration runs once more (so it must be idempotent, as the
    /// ensure-schema code that wrote the row was) and the row is stamped
    /// with name and checksum in the same transaction.
    Adopt,
}

/// Where the ledger lives and how the runner serialises writers.
#[derive(Clone, Debug)]
pub struct LedgerConfig {
    table: String,
    lock_key: i64,
    legacy: LegacyRows,
}

impl LedgerConfig {
    /// A ledger in `table` (plain identifier). `lock_key` is the PostgreSQL
    /// advisory-lock key; SQLite uses `BEGIN IMMEDIATE` and ignores it.
    pub fn new(table: &str, lock_key: i64) -> Result<Self> {
        require_identifier("ledger table", table)?;
        Ok(Self {
            table: table.to_owned(),
            lock_key,
            legacy: LegacyRows::Reject,
        })
    }

    /// Sets the legacy-row policy.
    #[must_use]
    pub fn legacy_rows(mut self, legacy: LegacyRows) -> Self {
        self.legacy = legacy;
        self
    }

    /// Ledger table name.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// PostgreSQL advisory-lock key.
    pub fn lock_key(&self) -> i64 {
        self.lock_key
    }

    /// Legacy-row policy.
    pub fn legacy(&self) -> LegacyRows {
        self.legacy
    }
}

/// One ledger row as read back from the database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerRow {
    /// Migration version.
    pub version: i64,
    /// Migration name (`None` on legacy rows).
    pub name: Option<String>,
    /// Migration checksum (`None` on legacy rows).
    pub checksum: Option<String>,
}

/// What a run did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Versions applied for the first time, in order.
    pub applied: Vec<i64>,
    /// Versions whose legacy row was adopted (migration re-run idempotently,
    /// row stamped with name and checksum).
    pub adopted: Vec<i64>,
    /// Newest version recorded with a checksum after the run.
    pub current: Option<i64>,
}

/// The next action of the runner loop.
#[cfg_attr(not(any(feature = "sqlite", feature = "postgres")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// Nothing pending; carries the newest applied version.
    Done(Option<i64>),
    /// Run the migration at this registry index and insert its row.
    Apply(usize),
    /// Run the migration at this registry index and stamp its legacy row.
    Adopt(usize),
}

/// Validates the ledger rows against the registry and picks the next step.
/// The registry must already be validated (contiguous, non-empty).
#[cfg_attr(not(any(feature = "sqlite", feature = "postgres")), allow(dead_code))]
pub(crate) fn plan<F>(
    migrations: &[Migration<F>],
    rows: &[LedgerRow],
    legacy: LegacyRows,
) -> Result<Next> {
    let (Some(first), Some(last)) = (migrations.first(), migrations.last()) else {
        return Err(Error::InvalidRegistry("no migrations".into()));
    };
    let latest = last.version();
    let mut newest_applied = None;
    for row in rows {
        if row.version > latest {
            return Err(Error::LedgerAhead {
                found: row.version,
                latest,
            });
        }
        match &row.checksum {
            None => {
                if legacy == LegacyRows::Reject {
                    return Err(Error::LegacyRowRejected(row.version));
                }
            }
            Some(checksum) => {
                let index = registry_index(first.version(), row.version)
                    .ok_or(Error::UnknownVersion(row.version))?;
                let migration = migrations
                    .get(index)
                    .ok_or(Error::UnknownVersion(row.version))?;
                verify_row(migration, row.name.as_deref(), checksum)?;
                newest_applied = newest_applied.max(Some(row.version));
            }
        }
    }
    for (index, migration) in migrations.iter().enumerate() {
        let row = rows.iter().find(|row| row.version == migration.version());
        match row {
            Some(row) if row.checksum.is_some() => continue,
            _ => {}
        }
        if let Some(applied) = newest_applied.filter(|applied| *applied > migration.version()) {
            return Err(Error::OutOfOrder {
                pending: migration.version(),
                applied,
            });
        }
        return Ok(if row.is_some() {
            Next::Adopt(index)
        } else {
            Next::Apply(index)
        });
    }
    Ok(Next::Done(newest_applied))
}

#[cfg_attr(not(any(feature = "sqlite", feature = "postgres")), allow(dead_code))]
fn registry_index(first: i64, version: i64) -> Option<usize> {
    usize::try_from(version.checked_sub(first)?).ok()
}

#[cfg_attr(not(any(feature = "sqlite", feature = "postgres")), allow(dead_code))]
fn verify_row<F>(migration: &Migration<F>, name: Option<&str>, checksum: &str) -> Result<()> {
    if name != Some(migration.name()) {
        return Err(Error::NameMismatch {
            version: migration.version(),
            expected: migration.name().to_owned(),
            found: name.unwrap_or_default().to_owned(),
        });
    }
    let expected = migration.checksum();
    if checksum != expected {
        return Err(Error::ChecksumMismatch {
            version: migration.version(),
            name: migration.name().to_owned(),
            expected,
            found: checksum.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;
