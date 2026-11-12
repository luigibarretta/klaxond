//! Backend-neutral logical schema and the parity comparison.
//!
//! A snapshot keeps what both backends can express identically: tables,
//! columns with a logical type family and nullability, the primary key,
//! unique constraints and explicitly created indexes (name, uniqueness, key
//! columns with direction, partial or not). Defaults, collations, check
//! constraints and partial-index predicates are dialect text and are not
//! compared.

use std::collections::{BTreeMap, BTreeSet};

/// Logical type family of a column.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogicalType {
    /// SQLite INTEGER affinity; PostgreSQL `smallint`, `integer`, `bigint`.
    Integer,
    /// SQLite REAL affinity; PostgreSQL `real`, `double precision`.
    Real,
    /// SQLite TEXT affinity; PostgreSQL `text`, `character varying`, `character`.
    Text,
    /// SQLite BLOB affinity (or no type); PostgreSQL `bytea`.
    Blob,
    /// SQLite NUMERIC affinity; PostgreSQL `numeric`.
    Numeric,
    /// PostgreSQL `boolean` (SQLite has no such affinity).
    Boolean,
    /// Any other PostgreSQL type, by its `data_type` name.
    Other(String),
}

impl LogicalType {
    /// Maps a SQLite declared type with the SQLite affinity rules.
    pub fn from_sqlite(declared: &str) -> Self {
        let upper = declared.to_ascii_uppercase();
        if upper.contains("INT") {
            Self::Integer
        } else if ["CHAR", "CLOB", "TEXT"].iter().any(|t| upper.contains(t)) {
            Self::Text
        } else if upper.contains("BLOB") || upper.trim().is_empty() {
            Self::Blob
        } else if ["REAL", "FLOA", "DOUB"].iter().any(|t| upper.contains(t)) {
            Self::Real
        } else {
            Self::Numeric
        }
    }

    /// Maps an `information_schema.columns.data_type` value.
    pub fn from_postgres(data_type: &str) -> Self {
        match data_type {
            "smallint" | "integer" | "bigint" => Self::Integer,
            "real" | "double precision" => Self::Real,
            "text" | "character varying" | "character" => Self::Text,
            "bytea" => Self::Blob,
            "numeric" => Self::Numeric,
            "boolean" => Self::Boolean,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// One column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    /// Logical type family.
    pub logical_type: LogicalType,
    /// NOT NULL (primary-key columns always count as NOT NULL).
    pub not_null: bool,
}

/// One explicitly created index (not one backing a constraint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    /// Table the index belongs to.
    pub table: String,
    /// UNIQUE index.
    pub unique: bool,
    /// Key columns (or expressions) with `true` for descending order.
    pub columns: Vec<(String, bool)>,
    /// The index has a WHERE predicate.
    pub partial: bool,
}

/// One table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    /// Columns by name.
    pub columns: BTreeMap<String, Column>,
    /// Primary-key columns in key order (empty when there is none).
    pub primary_key: Vec<String>,
    /// UNIQUE constraints, each as its column list.
    pub unique_constraints: BTreeSet<Vec<String>>,
}

/// A logical schema snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogicalSchema {
    /// Tables by name.
    pub tables: BTreeMap<String, Table>,
    /// Explicit indexes by name.
    pub indexes: BTreeMap<String, Index>,
}

/// Which tables a snapshot skips. Backend internal tables (`sqlite_*`) are
/// always skipped.
#[derive(Clone, Debug, Default)]
pub struct SnapshotOptions {
    exclude: BTreeSet<String>,
}

impl SnapshotOptions {
    /// Skips `table` (typically the migration ledger, whose `applied_at`
    /// type differs between backends by design).
    #[must_use]
    pub fn exclude(mut self, table: &str) -> Self {
        self.exclude.insert(table.to_owned());
        self
    }

    #[cfg_attr(not(any(feature = "sqlite", feature = "postgres")), allow(dead_code))]
    pub(crate) fn includes(&self, table: &str) -> bool {
        !table.starts_with("sqlite_") && !self.exclude.contains(table)
    }
}

impl LogicalSchema {
    /// Differences from `other`, one human-readable line each; empty when
    /// the two schemas are logically identical.
    pub fn diff(&self, other: &LogicalSchema) -> Vec<String> {
        let mut out = Vec::new();
        diff_maps(
            &self.tables,
            &other.tables,
            "table",
            &mut out,
            |name, a, b, out| {
                diff_table(name, a, b, out);
            },
        );
        diff_maps(
            &self.indexes,
            &other.indexes,
            "index",
            &mut out,
            |name, a, b, out| {
                if a != b {
                    out.push(format!("index {name}: {a:?} != {b:?}"));
                }
            },
        );
        out
    }
}

fn diff_maps<V>(
    left: &BTreeMap<String, V>,
    right: &BTreeMap<String, V>,
    kind: &str,
    out: &mut Vec<String>,
    mut both: impl FnMut(&str, &V, &V, &mut Vec<String>),
) {
    for (name, value) in left {
        match right.get(name) {
            Some(other) => both(name, value, other, out),
            None => out.push(format!("{kind} {name} only on the left")),
        }
    }
    for name in right.keys().filter(|name| !left.contains_key(*name)) {
        out.push(format!("{kind} {name} only on the right"));
    }
}

fn diff_table(name: &str, left: &Table, right: &Table, out: &mut Vec<String>) {
    diff_maps(
        &left.columns,
        &right.columns,
        &format!("table {name} column"),
        out,
        |column, a, b, out| {
            if a != b {
                out.push(format!("column {name}.{column}: {a:?} != {b:?}"));
            }
        },
    );
    if left.primary_key != right.primary_key {
        out.push(format!(
            "table {name} primary key: {:?} != {:?}",
            left.primary_key, right.primary_key
        ));
    }
    if left.unique_constraints != right.unique_constraints {
        out.push(format!(
            "table {name} unique constraints: {:?} != {:?}",
            left.unique_constraints, right.unique_constraints
        ));
    }
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
