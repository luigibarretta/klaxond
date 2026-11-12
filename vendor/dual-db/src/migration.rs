//! Backend-independent migration definitions and their checksum.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// One step of a migration. All steps of a migration run in one transaction.
///
/// `F` is the backend's code-step function type
/// ([`crate::sqlite::StepFn`] or [`crate::postgres::StepFn`]).
#[derive(Clone)]
pub enum Step<F> {
    /// One or more SQL statements, executed as a batch.
    Sql(&'static str),
    /// `ALTER TABLE <table> ADD COLUMN <column> <definition>` unless the
    /// column already exists (on PostgreSQL: `ADD COLUMN IF NOT EXISTS`).
    AddColumnIfMissing {
        /// Table name (plain identifier).
        table: &'static str,
        /// Column name (plain identifier).
        column: &'static str,
        /// Column type and constraints, e.g. `TEXT NOT NULL DEFAULT ''`.
        definition: &'static str,
    },
    /// Rust code, e.g. a backfill that needs application logic. `id` is part
    /// of the checksum: bump it (e.g. `backfill_search_v2`) whenever the
    /// code's effect changes, because the code body itself is not hashed.
    Code {
        /// Stable identifier of the code step.
        id: &'static str,
        /// The code, run inside the migration's transaction.
        run: F,
    },
}

impl<F> std::fmt::Debug for Step<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sql(sql) => f.debug_tuple("Sql").field(sql).finish(),
            Self::AddColumnIfMissing {
                table,
                column,
                definition,
            } => f
                .debug_struct("AddColumnIfMissing")
                .field("table", table)
                .field("column", column)
                .field("definition", definition)
                .finish(),
            Self::Code { id, .. } => f.debug_struct("Code").field("id", id).finish(),
        }
    }
}

/// An ordered, checksummed migration: a version, a name and its steps.
#[derive(Clone, Debug)]
pub struct Migration<F> {
    version: i64,
    name: &'static str,
    steps: Vec<Step<F>>,
}

impl<F> Migration<F> {
    /// A migration without steps; add them with the builder methods.
    pub fn new(version: i64, name: &'static str) -> Self {
        Self {
            version,
            name,
            steps: Vec::new(),
        }
    }

    /// Appends a SQL batch.
    #[must_use]
    pub fn sql(mut self, sql: &'static str) -> Self {
        self.steps.push(Step::Sql(sql));
        self
    }

    /// Appends an idempotent additive column.
    #[must_use]
    pub fn add_column_if_missing(
        mut self,
        table: &'static str,
        column: &'static str,
        definition: &'static str,
    ) -> Self {
        self.steps.push(Step::AddColumnIfMissing {
            table,
            column,
            definition,
        });
        self
    }

    /// Appends a code step identified by `id` (see [`Step::Code`]).
    #[must_use]
    pub fn code(mut self, id: &'static str, run: F) -> Self {
        self.steps.push(Step::Code { id, run });
        self
    }

    /// Migration version (ledger primary key).
    pub fn version(&self) -> i64 {
        self.version
    }

    /// Migration name, stored in the ledger.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The steps, in execution order.
    pub fn steps(&self) -> &[Step<F>] {
        &self.steps
    }

    /// Lowercase hex SHA-256 checksum stored in the ledger.
    ///
    /// A migration made of exactly one SQL step hashes the SQL text alone, so
    /// ledgers that store `sha256(sql)` (CoveyOS) stay valid. Any other shape
    /// hashes a length-framed encoding of every step.
    pub fn checksum(&self) -> String {
        if let [Step::Sql(sql)] = self.steps.as_slice() {
            return hex(&Sha256::digest(sql.as_bytes()));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"dual-db/steps/v1\n");
        for step in &self.steps {
            let fields: &[&str] = match step {
                Step::Sql(sql) => &["sql", sql],
                Step::AddColumnIfMissing {
                    table,
                    column,
                    definition,
                } => &["add_column_if_missing", table, column, definition],
                Step::Code { id, .. } => &["code", id],
            };
            for field in fields {
                hasher.update(field.len().to_string().as_bytes());
                hasher.update(b":");
                hasher.update(field.as_bytes());
                hasher.update(b"\n");
            }
        }
        hex(&hasher.finalize())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// True for a plain SQL identifier: ASCII letter or `_`, then letters,
/// digits or `_`, at most 63 bytes (the PostgreSQL limit).
pub fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= 63
        && (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(crate) fn require_identifier(kind: &str, value: &str) -> Result<()> {
    if is_identifier(value) {
        Ok(())
    } else {
        Err(Error::InvalidIdentifier(format!("{kind} {value:?}")))
    }
}

/// Validates an additive column (identifiers and a definition without `;`).
pub(crate) fn require_additive_column(table: &str, column: &str, definition: &str) -> Result<()> {
    require_identifier("table", table)?;
    require_identifier("column", column)?;
    if definition.trim().is_empty() || definition.contains(';') {
        return Err(Error::InvalidIdentifier(format!(
            "column definition {definition:?} for {table}.{column}"
        )));
    }
    Ok(())
}

/// Checks the registry: not empty, versions positive, contiguous and
/// increasing, names unique and non-empty, every migration has steps and
/// valid additive columns.
pub fn validate_registry<F>(migrations: &[Migration<F>]) -> Result<()> {
    let Some(first) = migrations.first() else {
        return Err(Error::InvalidRegistry("no migrations".into()));
    };
    if first.version < 1 {
        return Err(Error::InvalidRegistry(format!(
            "versions start at 1 or later, found {}",
            first.version
        )));
    }
    let mut names = HashSet::new();
    let mut expected = first.version;
    for migration in migrations {
        if migration.version != expected {
            return Err(Error::InvalidRegistry(format!(
                "expected version {expected}, found {}",
                migration.version
            )));
        }
        if migration.name.trim().is_empty() || !names.insert(migration.name) {
            return Err(Error::InvalidRegistry(format!(
                "empty or duplicate name {:?} at version {}",
                migration.name, migration.version
            )));
        }
        if migration.steps.is_empty() {
            return Err(Error::InvalidRegistry(format!(
                "migration {} has no steps",
                migration.version
            )));
        }
        validate_steps(&migration.steps)?;
        expected = expected.saturating_add(1);
    }
    Ok(())
}

fn validate_steps<F>(steps: &[Step<F>]) -> Result<()> {
    for step in steps {
        match step {
            Step::AddColumnIfMissing {
                table,
                column,
                definition,
            } => require_additive_column(table, column, definition)?,
            Step::Code { id, .. } if id.trim().is_empty() => {
                return Err(Error::InvalidRegistry("code step with empty id".into()));
            }
            Step::Sql(sql) if sql.trim().is_empty() => {
                return Err(Error::InvalidRegistry("empty SQL step".into()));
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "migration_tests.rs"]
mod tests;
