use crate::history::delivery_search_values;
use anyhow::Result;
use postgres::Transaction;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_deliveries (
  id BIGSERIAL PRIMARY KEY,
  ts DOUBLE PRECISION NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  channel TEXT NOT NULL,
  suppressed_by TEXT NOT NULL DEFAULT '',
  emergency_receipt_id TEXT,
  search_source TEXT NOT NULL DEFAULT '',
  search_severity TEXT NOT NULL DEFAULT '',
  search_title TEXT NOT NULL DEFAULT '',
  search_channel TEXT NOT NULL DEFAULT '',
  search_suppressed_by TEXT NOT NULL DEFAULT '',
  search_version SMALLINT NOT NULL DEFAULT 0,
  dedupe_hash TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_klaxond_deliveries_dedupe_hash ON klaxond_deliveries(dedupe_hash);
CREATE INDEX IF NOT EXISTS idx_klaxond_deliveries_ts_id_desc ON klaxond_deliveries(ts DESC, id DESC);
"#;

const ADD_COLUMNS: &str = r#"
ALTER TABLE klaxond_deliveries
  ADD COLUMN IF NOT EXISTS emergency_receipt_id TEXT;
ALTER TABLE klaxond_deliveries
  ADD COLUMN IF NOT EXISTS search_source TEXT NOT NULL DEFAULT '';
ALTER TABLE klaxond_deliveries
  ADD COLUMN IF NOT EXISTS search_severity TEXT NOT NULL DEFAULT '';
ALTER TABLE klaxond_deliveries
  ADD COLUMN IF NOT EXISTS search_title TEXT NOT NULL DEFAULT '';
ALTER TABLE klaxond_deliveries
  ADD COLUMN IF NOT EXISTS search_channel TEXT NOT NULL DEFAULT '';
ALTER TABLE klaxond_deliveries
  ADD COLUMN IF NOT EXISTS search_suppressed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE klaxond_deliveries
  ADD COLUMN IF NOT EXISTS search_version SMALLINT NOT NULL DEFAULT 0;
"#;

pub(super) fn create(tx: &mut Transaction<'_>) -> Result<()> {
    tx.batch_execute(SCHEMA)?;
    Ok(())
}

pub(super) fn add_columns(tx: &mut Transaction<'_>) -> Result<()> {
    tx.batch_execute(ADD_COLUMNS)?;
    Ok(())
}

pub(super) fn backfill_search_columns(tx: &mut Transaction<'_>) -> Result<()> {
    let rows = tx.query(
        "SELECT id, source, severity, title, channel, suppressed_by \
         FROM klaxond_deliveries WHERE search_version < 1",
        &[],
    )?;
    for row in rows {
        let id = row.get::<_, i64>(0);
        let source = row.get::<_, String>(1);
        let severity = row.get::<_, String>(2);
        let title = row.get::<_, String>(3);
        let channel = row.get::<_, String>(4);
        let suppressed_by = row.get::<_, String>(5);
        let values = delivery_search_values(&source, &severity, &title, &channel, &suppressed_by);
        tx.execute(
            UPDATE_SEARCH,
            &[
                &id, &values[0], &values[1], &values[2], &values[3], &values[4],
            ],
        )?;
    }
    Ok(())
}

const UPDATE_SEARCH: &str = r#"
UPDATE klaxond_deliveries SET
  search_source = $2,
  search_severity = $3,
  search_title = $4,
  search_channel = $5,
  search_suppressed_by = $6,
  search_version = 1
WHERE id = $1
"#;
