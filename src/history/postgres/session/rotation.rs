use super::{prune_concurrent, select_for_update, touch};
use crate::history::AuthSessionRecord;
use crate::history::postgres::session_locks::{lock_provider_session, lock_user};
use crate::history::session::{
    is_idempotent_rotation_retry, is_recent_rotation_successor, session_is_valid,
};
use anyhow::{Result, bail};
use postgres::{Client, Transaction};

pub(in crate::history::postgres) fn create(
    client: &mut Client,
    record: &AuthSessionRecord,
    replace_id_hash: Option<&str>,
    max_concurrent: usize,
    now: i64,
) -> Result<()> {
    let mut tx = client.transaction()?;
    lock_provider_session(
        &mut tx,
        record.provider_issuer.as_deref(),
        record.provider_session_id.as_deref(),
    )?;
    lock_user(&mut tx, &record.user_sub)?;
    if !should_insert_session(&mut tx, record, replace_id_hash, now)? {
        tx.commit()?;
        return Ok(());
    }
    tx.execute(
        r#"
INSERT INTO klaxond_auth_sessions (
  id_hash, family_hash, user_json, user_sub, auth_mode, provider_issuer,
  provider_session_id, created_at, last_seen_at, last_rotated_at, expires_at, revoked_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
"#,
        &[
            &record.id_hash,
            &record.family_hash,
            &record.user_json,
            &record.user_sub,
            &record.auth_mode,
            &record.provider_issuer,
            &record.provider_session_id,
            &record.created_at,
            &record.last_seen_at,
            &record.last_rotated_at,
            &record.expires_at,
            &record.revoked_at,
        ],
    )?;
    if let Some(previous) = replace_id_hash {
        tx.execute(
            "UPDATE klaxond_auth_sessions SET revoked_at = $1 WHERE id_hash = $2 AND revoked_at IS NULL",
            &[&now, &previous],
        )?;
    }
    prune_concurrent(&mut tx, record, max_concurrent.max(1), now)?;
    tx.execute(
        "DELETE FROM klaxond_auth_sessions WHERE expires_at <= $1 AND expires_at < $2",
        &[&now, &now.saturating_sub(86_400)],
    )?;
    tx.commit()?;
    Ok(())
}

fn should_insert_session(
    tx: &mut Transaction<'_>,
    record: &AuthSessionRecord,
    replace_id_hash: Option<&str>,
    now: i64,
) -> Result<bool> {
    let Some(previous) = replace_id_hash else {
        return Ok(true);
    };
    let predecessor = select_for_update(tx, previous)?;
    let valid_predecessor = predecessor.as_ref().is_some_and(|predecessor| {
        predecessor.family_hash == record.family_hash
            && predecessor.user_sub == record.user_sub
            && session_is_valid(predecessor, now, i64::MAX)
    });
    if valid_predecessor {
        return Ok(true);
    }
    let stored = select_for_update(tx, &record.id_hash)?;
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

pub(in crate::history::postgres) fn lookup_rotation_successor(
    client: &mut Client,
    predecessor_hash: &str,
    successor_hash: &str,
    now: i64,
    idle_timeout_seconds: i64,
) -> Result<Option<AuthSessionRecord>> {
    let mut tx = client.transaction()?;
    let predecessor = select_for_update(&mut tx, predecessor_hash)?;
    let successor = select_for_update(&mut tx, successor_hash)?;
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
    touch(&mut tx, &mut successor, now)?;
    tx.commit()?;
    Ok(Some(successor))
}
