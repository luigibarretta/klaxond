use crate::history::AuthRateLimitRecord;
use crate::history::rate_limit::merge_import;
use anyhow::Result;
use auth_modules::rate_limit::{PersistentRateLimitRecord, gold_auth_account_failure_policy};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

const STALE_RECORD_SECONDS: i64 = 10 * 60;

pub(in crate::history) fn limited(conn: &mut Connection, key_hash: &str, now: i64) -> Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut record = load(&tx, key_hash)?.unwrap_or_else(|| empty(key_hash, now));
    let policy = gold_auth_account_failure_policy();
    let limited = policy.locked(&mut record.state, now);
    persist_or_delete(&tx, &record, now)?;
    tx.commit()?;
    Ok(limited)
}

pub(in crate::history) fn record_failure(
    conn: &mut Connection,
    key_hash: &str,
    now: i64,
) -> Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut record = load(&tx, key_hash)?.unwrap_or_else(|| empty(key_hash, now));
    let policy = gold_auth_account_failure_policy();
    policy.record_failure(&mut record.state, now);
    record.updated_at = now;
    upsert(&tx, &record)?;
    prune_stale(&tx, now)?;
    let limited = policy.locked(&mut record.state, now);
    tx.commit()?;
    Ok(limited)
}

pub(in crate::history) fn clear(conn: &Connection, key_hash: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM klaxond_auth_rate_limits WHERE key_hash = ?1",
        params![key_hash],
    )?;
    Ok(())
}

pub(in crate::history) fn export_all(conn: &Connection) -> Result<Vec<AuthRateLimitRecord>> {
    if !table_exists(conn)? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        r#"
SELECT key_hash, failure_epochs_json, locked_until_epoch, updated_at
FROM klaxond_auth_rate_limits
ORDER BY key_hash
"#,
    )?;
    let rows = stmt.query_map([], from_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub(in crate::history) fn import_in_transaction(
    tx: &Transaction<'_>,
    record: &AuthRateLimitRecord,
) -> Result<()> {
    let merged = merge_import(load(tx, &record.key_hash)?.as_ref(), record);
    upsert(tx, &merged)?;
    Ok(())
}

fn load(tx: &Transaction<'_>, key_hash: &str) -> Result<Option<AuthRateLimitRecord>> {
    tx.query_row(
        r#"
SELECT key_hash, failure_epochs_json, locked_until_epoch, updated_at
FROM klaxond_auth_rate_limits
WHERE key_hash = ?1
"#,
        params![key_hash],
        from_row,
    )
    .optional()
    .map_err(Into::into)
}

fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthRateLimitRecord> {
    let failure_epochs_json: String = row.get(1)?;
    let failure_epochs = serde_json::from_str(&failure_epochs_json).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            failure_epochs_json.len(),
            rusqlite::types::Type::Text,
            Box::new(err),
        )
    })?;
    Ok(AuthRateLimitRecord {
        key_hash: row.get(0)?,
        state: PersistentRateLimitRecord {
            failure_epochs,
            locked_until_epoch: row.get(2)?,
        },
        updated_at: row.get(3)?,
    })
}

fn empty(key_hash: &str, now: i64) -> AuthRateLimitRecord {
    AuthRateLimitRecord {
        key_hash: key_hash.to_string(),
        state: PersistentRateLimitRecord::default(),
        updated_at: now,
    }
}

fn persist_or_delete(tx: &Transaction<'_>, record: &AuthRateLimitRecord, now: i64) -> Result<()> {
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
        clear(tx, &record.key_hash)
    }
}

fn upsert(conn: &Connection, record: &AuthRateLimitRecord) -> Result<()> {
    let epochs = serde_json::to_string(&record.state.failure_epochs)?;
    conn.execute(
        r#"
INSERT INTO klaxond_auth_rate_limits
  (key_hash, failure_epochs_json, locked_until_epoch, updated_at)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(key_hash) DO UPDATE SET
  failure_epochs_json = excluded.failure_epochs_json,
  locked_until_epoch = excluded.locked_until_epoch,
  updated_at = excluded.updated_at
"#,
        params![
            &record.key_hash,
            epochs,
            record.state.locked_until_epoch,
            record.updated_at,
        ],
    )?;
    Ok(())
}

fn prune_stale(tx: &Transaction<'_>, now: i64) -> Result<()> {
    tx.execute(
        r#"
DELETE FROM klaxond_auth_rate_limits
WHERE updated_at < ?1
  AND (locked_until_epoch IS NULL OR locked_until_epoch <= ?2)
"#,
        params![now.saturating_sub(STALE_RECORD_SECONDS), now],
    )?;
    Ok(())
}

fn table_exists(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'klaxond_auth_rate_limits')",
        [],
        |row| row.get(0),
    )?)
}
