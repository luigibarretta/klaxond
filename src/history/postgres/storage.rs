use crate::history::{SCHEMA_VERSION, delivery_search_values};
use anyhow::{Result, bail};
use postgres::Client;

pub(super) fn validate_schema(client: &mut Client) -> Result<()> {
    let row = client.query_one("SELECT to_regclass('klaxond_deliveries')::text", &[])?;
    let table: Option<String> = row.get(0);
    if table.is_none() {
        bail!("source postgres history does not contain klaxond_deliveries");
    }
    Ok(())
}

pub(super) fn migrate(client: &mut Client) -> Result<()> {
    const MIGRATION_LOCK_KEY: i64 = 5_426_893_470_587_711_020;
    let mut tx = client.transaction()?;
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])?;
    tx.batch_execute(
        r#"
CREATE TABLE IF NOT EXISTS klaxond_schema_migrations (
  version BIGINT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

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

CREATE TABLE IF NOT EXISTS klaxond_auth_sessions (
  id_hash TEXT PRIMARY KEY,
  family_hash TEXT NOT NULL,
  user_json TEXT NOT NULL,
  user_sub TEXT NOT NULL,
  auth_mode TEXT NOT NULL,
  provider_issuer TEXT,
  provider_session_id TEXT,
  created_at BIGINT NOT NULL,
  last_seen_at BIGINT NOT NULL,
  last_rotated_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  revoked_at BIGINT
);

ALTER TABLE klaxond_auth_sessions
  ADD COLUMN IF NOT EXISTS family_hash TEXT NOT NULL DEFAULT '';
UPDATE klaxond_auth_sessions
SET family_hash = id_hash
WHERE family_hash = '';

CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_user
  ON klaxond_auth_sessions(user_sub, auth_mode, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_concurrent
  ON klaxond_auth_sessions(user_sub, last_seen_at DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_family
  ON klaxond_auth_sessions(family_hash);
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_oidc_sid
  ON klaxond_auth_sessions(provider_issuer, provider_session_id)
  WHERE auth_mode = 'oidc' AND provider_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_oidc_sub
  ON klaxond_auth_sessions(provider_issuer, user_sub)
  WHERE auth_mode = 'oidc';

CREATE TABLE IF NOT EXISTS klaxond_oidc_logout_tokens (
  issuer TEXT NOT NULL,
  token_id_hash TEXT NOT NULL,
  consumed_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  PRIMARY KEY (issuer, token_id_hash)
);

CREATE INDEX IF NOT EXISTS idx_klaxond_oidc_logout_tokens_expiry
  ON klaxond_oidc_logout_tokens(expires_at);

CREATE TABLE IF NOT EXISTS klaxond_auth_rate_limits (
  key_hash TEXT PRIMARY KEY,
  failure_epochs_json TEXT NOT NULL,
  locked_until_epoch BIGINT,
  updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_klaxond_auth_rate_limits_updated
  ON klaxond_auth_rate_limits(updated_at);

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
"#,
    )?;
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
            r#"
UPDATE klaxond_deliveries SET
  search_source = $2,
  search_severity = $3,
  search_title = $4,
  search_channel = $5,
  search_suppressed_by = $6,
  search_version = 1
WHERE id = $1
"#,
            &[
                &id, &values[0], &values[1], &values[2], &values[3], &values[4],
            ],
        )?;
    }
    tx.execute(
        "INSERT INTO klaxond_schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING",
        &[&SCHEMA_VERSION],
    )?;
    tx.commit()?;
    Ok(())
}
