use crate::history::AuthRateLimitRecord;
use crate::history::rate_limit::merge_import;
use anyhow::Result;
use auth_modules::rate_limit::{PersistentRateLimitRecord, gold_auth_account_failure_policy};
use postgres::{Client, Transaction};

const STALE_RECORD_SECONDS: i64 = 10 * 60;

pub(super) fn limited(client: &mut Client, key_hash: &str, now: i64) -> Result<bool> {
    let mut tx = client.transaction()?;
    lock_key(&mut tx, key_hash)?;
    let mut record = load(&mut tx, key_hash)?.unwrap_or_else(|| empty(key_hash, now));
    let policy = gold_auth_account_failure_policy();
    let limited = policy.locked(&mut record.state, now);
    persist_or_delete(&mut tx, &record, now)?;
    tx.commit()?;
    Ok(limited)
}

pub(super) fn record_failure(client: &mut Client, key_hash: &str, now: i64) -> Result<bool> {
    let mut tx = client.transaction()?;
    lock_key(&mut tx, key_hash)?;
    let mut record = load(&mut tx, key_hash)?.unwrap_or_else(|| empty(key_hash, now));
    let policy = gold_auth_account_failure_policy();
    policy.record_failure(&mut record.state, now);
    record.updated_at = now;
    upsert(&mut tx, &record)?;
    prune_stale(&mut tx, now)?;
    let limited = policy.locked(&mut record.state, now);
    tx.commit()?;
    Ok(limited)
}

pub(super) fn clear(client: &mut Client, key_hash: &str) -> Result<()> {
    let mut tx = client.transaction()?;
    lock_key(&mut tx, key_hash)?;
    delete(&mut tx, key_hash)?;
    tx.commit()?;
    Ok(())
}

fn delete(client: &mut impl postgres::GenericClient, key_hash: &str) -> Result<()> {
    client.execute(
        "DELETE FROM klaxond_auth_rate_limits WHERE key_hash = $1",
        &[&key_hash],
    )?;
    Ok(())
}

pub(super) fn export_all(client: &mut Client) -> Result<Vec<AuthRateLimitRecord>> {
    if !table_exists(client)? {
        return Ok(Vec::new());
    }
    client
        .query(
            r#"
SELECT key_hash, failure_epochs_json, locked_until_epoch, updated_at
FROM klaxond_auth_rate_limits
ORDER BY key_hash
"#,
            &[],
        )?
        .iter()
        .map(from_row)
        .collect()
}

pub(super) fn import_locked(tx: &mut Transaction<'_>, record: &AuthRateLimitRecord) -> Result<()> {
    let merged = merge_import(load(tx, &record.key_hash)?.as_ref(), record);
    upsert(tx, &merged)?;
    Ok(())
}

fn load(tx: &mut Transaction<'_>, key_hash: &str) -> Result<Option<AuthRateLimitRecord>> {
    tx.query_opt(
        r#"
SELECT key_hash, failure_epochs_json, locked_until_epoch, updated_at
FROM klaxond_auth_rate_limits
WHERE key_hash = $1
FOR UPDATE
"#,
        &[&key_hash],
    )?
    .as_ref()
    .map(from_row)
    .transpose()
}

fn from_row(row: &postgres::Row) -> Result<AuthRateLimitRecord> {
    let failure_epochs_json: String = row.get(1);
    Ok(AuthRateLimitRecord {
        key_hash: row.get(0),
        state: PersistentRateLimitRecord {
            failure_epochs: serde_json::from_str(&failure_epochs_json)?,
            locked_until_epoch: row.get(2),
        },
        updated_at: row.get(3),
    })
}

fn empty(key_hash: &str, now: i64) -> AuthRateLimitRecord {
    AuthRateLimitRecord {
        key_hash: key_hash.to_string(),
        state: PersistentRateLimitRecord::default(),
        updated_at: now,
    }
}

fn persist_or_delete(
    tx: &mut Transaction<'_>,
    record: &AuthRateLimitRecord,
    now: i64,
) -> Result<()> {
    let policy = gold_auth_account_failure_policy();
    let mut state = record.state.clone();
    if policy.retain_record(&mut state, now) {
        upsert(
            tx,
            &AuthRateLimitRecord {
                state,
                updated_at: now,
                ..record.clone()
            },
        )
    } else {
        delete(tx, &record.key_hash)
    }
}

fn upsert(client: &mut impl postgres::GenericClient, record: &AuthRateLimitRecord) -> Result<()> {
    let epochs = serde_json::to_string(&record.state.failure_epochs)?;
    client.execute(
        r#"
INSERT INTO klaxond_auth_rate_limits
  (key_hash, failure_epochs_json, locked_until_epoch, updated_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (key_hash) DO UPDATE SET
  failure_epochs_json = EXCLUDED.failure_epochs_json,
  locked_until_epoch = EXCLUDED.locked_until_epoch,
  updated_at = EXCLUDED.updated_at
"#,
        &[
            &record.key_hash,
            &epochs,
            &record.state.locked_until_epoch,
            &record.updated_at,
        ],
    )?;
    Ok(())
}

fn prune_stale(tx: &mut Transaction<'_>, now: i64) -> Result<()> {
    tx.execute(
        r#"
DELETE FROM klaxond_auth_rate_limits
WHERE updated_at < $1
  AND (locked_until_epoch IS NULL OR locked_until_epoch <= $2)
"#,
        &[&now.saturating_sub(STALE_RECORD_SECONDS), &now],
    )?;
    Ok(())
}

fn table_exists(client: &mut Client) -> Result<bool> {
    Ok(client
        .query_one(
            "SELECT to_regclass('public.klaxond_auth_rate_limits')::text",
            &[],
        )?
        .get::<_, Option<String>>(0)
        .is_some())
}

pub(super) fn lock_key(tx: &mut Transaction<'_>, key_hash: &str) -> Result<()> {
    const LOCK_SEED: i64 = 5_426_893_470_587_711_021;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
        &[&key_hash, &LOCK_SEED],
    )?;
    Ok(())
}
