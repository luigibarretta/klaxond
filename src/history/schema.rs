//! History schema ledger, shared by both backends.
//!
//! The versioned migrations run through the shared `dual-db` runner
//! (vendor/dual-db, ADR 0001 there): one transaction per migration under
//! `pg_advisory_xact_lock` (PostgreSQL) or `BEGIN IMMEDIATE` (SQLite), with
//! `version, name, checksum` recorded in `klaxond_schema_migrations`.
//!
//! Releases up to 0.24 replayed an idempotent ensure-schema on every start
//! and wrote only `version` rows (1 to 9) into the same table. The runner
//! upgrades that table once (adds the nullable `name` and `checksum`
//! columns) and keeps rows 1 to 8 as history. Migration 9 (`baseline`) is
//! that ensure-schema, step for step: on a database at version 9 it adopts
//! row 9 (runs once more, changes nothing, stamps the row); on an older one
//! it brings the schema to version 9 as the old code did. Afterwards it never
//! runs again; a database migrated by a newer binary is refused.
//!
//! The search-column and session-family backfills also run on every start,
//! after the migrations, as a reconciliation: a pre-v9 binary started on this
//! schema (a rollback) writes rows that need them, as before.

use anyhow::{Context, Result};
use dual_db::{LedgerConfig, LegacyRows};

/// Ledger table (pre-runner releases wrote version-only rows into it).
pub(super) const LEDGER_TABLE: &str = "klaxond_schema_migrations";
/// Advisory-lock key of the pre-runner PostgreSQL migration, kept so a
/// previous release and this one exclude each other during a restart.
pub(in crate::history) const MIGRATION_LOCK_KEY: i64 = 5_426_893_470_587_711_020;
/// Version of the baseline migration: the last pre-runner schema version.
pub(super) const BASELINE_VERSION: i64 = 9;

pub(super) fn ledger() -> Result<LedgerConfig> {
    Ok(LedgerConfig::new(LEDGER_TABLE, MIGRATION_LOCK_KEY)
        .context("invalid schema ledger")?
        .legacy_rows(LegacyRows::Adopt))
}
