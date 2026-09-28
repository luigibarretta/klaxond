use anyhow::Result;
use postgres::Transaction;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_repeat_state (
  fingerprint TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  last_delivered_at DOUBLE PRECISION,
  last_suppressed_at DOUBLE PRECISION,
  suppressed_count BIGINT NOT NULL DEFAULT 0,
  reserved_until DOUBLE PRECISION NOT NULL DEFAULT 0,
  reservation_token TEXT NOT NULL DEFAULT '',
  cooldown_s BIGINT NOT NULL DEFAULT 0,
  matched_rule TEXT
);

CREATE INDEX IF NOT EXISTS idx_klaxond_repeat_suppressed_desc
  ON klaxond_repeat_state(last_suppressed_at DESC)
  WHERE last_suppressed_at IS NOT NULL;

ALTER TABLE klaxond_repeat_state
  ADD COLUMN IF NOT EXISTS cooldown_s BIGINT NOT NULL DEFAULT 0;
ALTER TABLE klaxond_repeat_state
  ADD COLUMN IF NOT EXISTS matched_rule TEXT;
"#;

pub(super) fn create(tx: &mut Transaction<'_>) -> Result<()> {
    tx.batch_execute(SCHEMA)?;
    Ok(())
}
