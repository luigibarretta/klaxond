use anyhow::Result;
use postgres::Transaction;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_emergencies (
  receipt_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  policy_id TEXT NOT NULL DEFAULT '',
  policy_name TEXT NOT NULL DEFAULT '',
  policy_snapshot_json TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  created_at DOUBLE PRECISION NOT NULL,
  updated_at DOUBLE PRECISION NOT NULL,
  next_retry_at DOUBLE PRECISION NOT NULL,
  expires_at DOUBLE PRECISION NOT NULL,
  last_sent_at DOUBLE PRECISION,
  terminal_at DOUBLE PRECISION,
  terminal_by TEXT NOT NULL DEFAULT '',
  attempts BIGINT NOT NULL DEFAULT 0,
  max_attempts BIGINT NOT NULL,
  telegram_escalated_at DOUBLE PRECISION,
  smtp_escalated_at DOUBLE PRECISION,
  last_error TEXT NOT NULL DEFAULT '',
  reserved_until DOUBLE PRECISION NOT NULL DEFAULT 0,
  reservation_token TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_klaxond_emergencies_active_fingerprint
  ON klaxond_emergencies(fingerprint) WHERE state='active';
CREATE INDEX IF NOT EXISTS idx_klaxond_emergencies_due
  ON klaxond_emergencies(state,next_retry_at,reserved_until);
CREATE INDEX IF NOT EXISTS idx_klaxond_emergencies_created
  ON klaxond_emergencies(created_at DESC);

ALTER TABLE klaxond_emergencies
  ADD COLUMN IF NOT EXISTS policy_id TEXT NOT NULL DEFAULT '';
ALTER TABLE klaxond_emergencies
  ADD COLUMN IF NOT EXISTS policy_name TEXT NOT NULL DEFAULT '';
ALTER TABLE klaxond_emergencies
  ADD COLUMN IF NOT EXISTS policy_snapshot_json TEXT NOT NULL DEFAULT '';
"#;

pub(super) fn create(tx: &mut Transaction<'_>) -> Result<()> {
    tx.batch_execute(SCHEMA)?;
    Ok(())
}
