# Changelog

All notable changes to `dual-db` are recorded here. The crate follows
semantic versioning; while it is `0.x`, a minor release may deprecate APIs,
and deprecated APIs are removed only after every known consumer has migrated.

## 0.2.0 - 2026-11-12

Fixes from the independent review of 0.1.0 (baac890). Checksums of
existing migrations are unchanged.

### Added

- `verify_pinned_checksums`: consumers pin the checksum each released
  migration produced; a mismatch says that applied migrations are
  immutable.
- `Migration::precondition`: checks run in the migration transaction before
  the first step, able to refuse it, excluded from the checksum (CoveyOS
  privilege pre-checks).
- `Migration::without_foreign_keys` (SQLite): enforcement off before
  `BEGIN IMMEDIATE`, `PRAGMA foreign_key_check` before `COMMIT` (violations
  roll back, `Error::ForeignKeyViolation`), enforcement restored after.

### Fixed

- PostgreSQL migration transactions run at READ COMMITTED explicitly: under
  a REPEATABLE READ or SERIALIZABLE default the snapshot predated the
  advisory-lock wait.
- A `Sql` step with a top-level transaction-control statement (`BEGIN`,
  `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE`, `END`, `START`, `ABORT`) is
  refused at registry validation.
- ADR 0001: CoveyOS privilege pre-checks become preconditions (not `Code`
  steps, which would change migration 24's checksum); rollback past the
  runner requires idempotent later migrations.

## 0.1.0 - 2026-11-12

First release, extracted in phase 6 of the 2026-11-07 fleet audit from the
CoveyOS runners and the Blackstart and klaxond ensure-schema code
(ADR 0001).

### Added

- `Migration` / `Step` (`Sql`, `AddColumnIfMissing`, `Code { id, run }`),
  contiguous registry validation and a SHA-256 checksum (single-SQL
  migrations hash the SQL alone, compatible with the CoveyOS PostgreSQL
  ledger).
- `sqlite::migrate` (one `BEGIN IMMEDIATE` transaction per migration) and
  `postgres::migrate` (one transaction per migration under
  `pg_advisory_xact_lock`), recording `version, name, checksum` and refusing
  checksum or name drift, unknown versions, out-of-order gaps and ledgers
  newer than the binary.
- `LegacyRows::Adopt`: one-time, transactional upgrade of a version-only
  ledger, adopting the idempotent baseline that matches a legacy row.
- `verify` (read-only), `add_column_if_missing`, `column_exists`,
  `table_exists` for both backends.
- `schema::LogicalSchema` snapshots for both backends, `LogicalSchema::diff`
  and `parity::migrate_and_compare` for consumer test suites.
- Tests against real SQLite files and a real PostgreSQL (disposable
  container through the ci-local `postgres` fixture).
