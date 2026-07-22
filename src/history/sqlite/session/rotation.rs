use super::{prune_concurrent, prune_expired, select, touch};
use crate::history::AuthSessionRecord;
use crate::history::session::{
    is_idempotent_rotation_retry, is_recent_rotation_successor, session_is_valid,
};
use anyhow::{Result, bail};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};

pub(in crate::history) fn create(
    conn: &mut Connection,
    record: &AuthSessionRecord,
    replace_id_hash: Option<&str>,
    max_concurrent: usize,
    now: i64,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !should_insert_session(&tx, record, replace_id_hash, now)? {
        tx.commit()?;
        return Ok(());
    }
    tx.execute(
        r#"
INSERT INTO klaxond_auth_sessions (
  id_hash, family_hash, user_json, user_sub, auth_mode, provider_issuer,
  provider_session_id, created_at, last_seen_at, last_rotated_at, expires_at, revoked_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
"#,
        params![
            &record.id_hash,
            &record.family_hash,
            &record.user_json,
            &record.user_sub,
            &record.auth_mode,
            &record.provider_issuer,
            &record.provider_session_id,
            record.created_at,
            record.last_seen_at,
            record.last_rotated_at,
            record.expires_at,
            record.revoked_at,
        ],
    )?;
    if let Some(previous) = replace_id_hash {
        tx.execute(
            "UPDATE klaxond_auth_sessions SET revoked_at = ?1 WHERE id_hash = ?2 AND revoked_at IS NULL",
            params![now, previous],
        )?;
    }
    prune_concurrent(&tx, record, max_concurrent.max(1), now)?;
    prune_expired(&tx, now)?;
    tx.commit()?;
    Ok(())
}

fn should_insert_session(
    tx: &Transaction<'_>,
    record: &AuthSessionRecord,
    replace_id_hash: Option<&str>,
    now: i64,
) -> Result<bool> {
    let Some(previous) = replace_id_hash else {
        return Ok(true);
    };
    let predecessor = select(tx, previous)?;
    let valid_predecessor = predecessor.as_ref().is_some_and(|predecessor| {
        predecessor.family_hash == record.family_hash
            && predecessor.user_sub == record.user_sub
            && session_is_valid(predecessor, now, i64::MAX)
    });
    if valid_predecessor {
        return Ok(true);
    }
    let stored = select(tx, &record.id_hash)?;
    if predecessor
        .as_ref()
        .zip(stored.as_ref())
        .is_some_and(|(predecessor, stored)| {
            is_idempotent_rotation_retry(predecessor, stored, record, now)
        })
    {
        return Ok(false);
    }
    bail!("session rotation predecessor is not active in the same family")
}

pub(in crate::history) fn lookup_rotation_successor(
    conn: &mut Connection,
    predecessor_hash: &str,
    successor_hash: &str,
    now: i64,
    idle_timeout_seconds: i64,
) -> Result<Option<AuthSessionRecord>> {
    let tx = conn.transaction()?;
    let predecessor = select(&tx, predecessor_hash)?;
    let successor = select(&tx, successor_hash)?;
    let Some(mut successor) =
        predecessor
            .as_ref()
            .zip(successor)
            .and_then(|(predecessor, successor)| {
                is_recent_rotation_successor(
                    predecessor,
                    &successor,
                    successor_hash,
                    now,
                    idle_timeout_seconds,
                )
                .then_some(successor)
            })
    else {
        tx.commit()?;
        return Ok(None);
    };
    touch(&tx, &mut successor, now)?;
    tx.commit()?;
    Ok(Some(successor))
}
