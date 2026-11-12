//! Shared PostgreSQL + SQLite migration runner and schema-parity check.
//!
//! * [`Migration`]: an ordered, versioned, checksummed list of [`Step`]s
//!   (SQL batches, idempotent additive columns, code backfills).
//! * [`sqlite::migrate`] / [`postgres::migrate`]: apply pending migrations,
//!   one transaction each, under a single-writer guard (`BEGIN IMMEDIATE` /
//!   `pg_advisory_xact_lock`), recording `version, name, checksum` in a
//!   ledger table; an applied migration whose checksum changed, an unknown
//!   version or a ledger newer than the binary stops the run.
//! * [`LegacyRows::Adopt`]: one-time upgrade of a version-only ledger
//!   written by an older ensure-schema implementation.
//! * [`schema`] snapshots and [`parity`] comparison for test suites.
//!
//! See `docs/adr/0001-dual-db-migration-runner.md` for scope and ledger format.

mod error;
mod ledger;
mod migration;
pub mod schema;

#[cfg(all(feature = "sqlite", feature = "postgres"))]
pub mod parity;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use error::{BoxError, Error, Result};
pub use ledger::{LedgerConfig, LedgerRow, LegacyRows, MigrationReport};
pub use migration::{is_identifier, validate_registry, Migration, Step};
