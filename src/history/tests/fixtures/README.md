# Pre-runner history schema fixtures

History databases written by the last release before the `dual-db` schema
runner, used by `schema_migrations.rs` to prove that adopting the runner
upgrades the version-only `klaxond_schema_migrations` ledger once, adopts
row 9, applies nothing twice and leaves schema and data unchanged.

- Generated at klaxond commit `28a0dac` (0.24.1 plus a test-only commit) by
  opening a fresh store with that commit's `HistoryStore::open` (its
  ensure-schema migration, ledger row 9), recording three deliveries and
  inserting a repeat state, an OIDC session, a logout tombstone, a rate
  limit and an active emergency.
- `pre_dual_db.sqlitedump`: `sqlite3 <file> .dump` of the SQLite store.
- `pre_dual_db.pgdump`: `pg_dump --inserts --no-owner --no-privileges` of
  the PostgreSQL store (server and pg_dump: `postgres:17.6-alpine`, the CI
  service image). The tests drop psql meta-commands (`\restrict`) and load
  it into a database of their own.

The tests add legacy rows 5 to 8 to mirror a database upgraded release
after release. Do not regenerate these files from a newer commit.
