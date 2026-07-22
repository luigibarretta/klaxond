use crate::history::{DeliveryEntry, SCHEMA_VERSION, dedupe_hash};
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
"#,
    )?;
    tx.execute(
        "INSERT INTO klaxond_schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING",
        &[&SCHEMA_VERSION],
    )?;
    tx.commit()?;
    Ok(())
}

pub(super) fn insert(client: &mut Client, entry: &DeliveryEntry) -> Result<()> {
    let hash = dedupe_hash(entry);
    client.execute(
        r#"
INSERT INTO klaxond_deliveries
  (ts, source, severity, title, channel, suppressed_by, dedupe_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (dedupe_hash) DO NOTHING
"#,
        &[
            &entry.ts,
            &entry.source,
            &entry.severity,
            &entry.title,
            &entry.channel,
            &entry.suppressed_by,
            &hash,
        ],
    )?;
    Ok(())
}

pub(super) fn count(client: &mut Client) -> Result<usize> {
    let row = client.query_one("SELECT COUNT(*) FROM klaxond_deliveries", &[])?;
    Ok(row.get::<_, i64>(0) as usize)
}

pub(super) fn page(client: &mut Client, limit: usize, offset: usize) -> Result<Vec<DeliveryEntry>> {
    let rows = client.query(
        r#"
SELECT ts, source, severity, title, channel, suppressed_by
FROM klaxond_deliveries
ORDER BY ts DESC, id DESC
LIMIT $1 OFFSET $2
"#,
        &[&(limit as i64), &(offset as i64)],
    )?;
    Ok(rows
        .into_iter()
        .map(|row| DeliveryEntry {
            ts: row.get(0),
            source: row.get(1),
            severity: row.get(2),
            title: row.get(3),
            channel: row.get(4),
            suppressed_by: row.get(5),
        })
        .collect())
}

pub(super) fn export_all(client: &mut Client) -> Result<Vec<DeliveryEntry>> {
    let mut tx = client.transaction()?;
    let rows = tx.query(
        r#"
SELECT ts, source, severity, title, channel, suppressed_by
FROM klaxond_deliveries
ORDER BY ts ASC, id ASC
"#,
        &[],
    )?;
    let entries = rows
        .into_iter()
        .map(|row| DeliveryEntry {
            ts: row.get(0),
            source: row.get(1),
            severity: row.get(2),
            title: row.get(3),
            channel: row.get(4),
            suppressed_by: row.get(5),
        })
        .collect();
    tx.commit()?;
    Ok(entries)
}

pub(super) fn prune(client: &mut Client, retention: usize) -> Result<()> {
    if retention == 0 {
        return Ok(());
    }
    client.execute(
        r#"
DELETE FROM klaxond_deliveries
WHERE id NOT IN (
  SELECT id FROM klaxond_deliveries ORDER BY ts DESC, id DESC LIMIT $1
)
"#,
        &[&(retention as i64)],
    )?;
    Ok(())
}
