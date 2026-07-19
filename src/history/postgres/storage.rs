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
  reservation_token TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_klaxond_repeat_suppressed_desc
  ON klaxond_repeat_state(last_suppressed_at DESC)
  WHERE last_suppressed_at IS NOT NULL;
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
