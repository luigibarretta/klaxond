use super::session_locks::{lock_oidc_users, lock_provider_session, lock_user};
use crate::history::session::{SESSION_TOUCH_INTERVAL_SECONDS, session_is_valid};
use crate::history::{AuthSessionRecord, OidcLogoutResult, OidcLogoutTokenRecord};
use anyhow::Result;
use postgres::{Client, Transaction};

mod rotation;
mod state;

pub(super) use rotation::{create, lookup_rotation_successor};
use state::session_from_row;
pub(super) use state::{
    export_logout_tokens, export_sessions, import_logout_token, import_session_locked,
};

pub(super) fn lookup(
    client: &mut Client,
    id_hash: &str,
    now: i64,
    idle_timeout_seconds: i64,
) -> Result<Option<AuthSessionRecord>> {
    let mut tx = client.transaction()?;
    let record = tx
        .query_opt(
            r#"
SELECT id_hash, user_json, user_sub, auth_mode, provider_issuer, provider_session_id,
       family_hash, created_at, last_seen_at, last_rotated_at, expires_at, revoked_at
FROM klaxond_auth_sessions
WHERE id_hash = $1
FOR UPDATE
"#,
            &[&id_hash],
        )?
        .map(|row| session_from_row(&row));
    let Some(mut record) = record else {
        tx.commit()?;
        return Ok(None);
    };
    if !session_is_valid(&record, now, idle_timeout_seconds) {
        tx.execute(
            "UPDATE klaxond_auth_sessions SET revoked_at = COALESCE(revoked_at, $1) WHERE id_hash = $2",
            &[&now, &id_hash],
        )?;
        tx.commit()?;
        return Ok(None);
    }
    touch(&mut tx, &mut record, now)?;
    tx.commit()?;
    Ok(Some(record))
}

pub(super) fn revoke(client: &mut Client, id_hash: &str, now: i64) -> Result<bool> {
    Ok(client.execute(
        "UPDATE klaxond_auth_sessions SET revoked_at = $1 WHERE id_hash = $2 AND revoked_at IS NULL",
        &[&now, &id_hash],
    )? > 0)
}

pub(super) fn revoke_family_by_id(client: &mut Client, id_hash: &str, now: i64) -> Result<usize> {
    let mut tx = client.transaction()?;
    let family = tx.query_opt(
        "SELECT user_sub, family_hash FROM klaxond_auth_sessions WHERE id_hash = $1",
        &[&id_hash],
    )?;
    let changed = if let Some(row) = family {
        let user_sub = row.get::<_, String>(0);
        let family_hash = row.get::<_, String>(1);
        lock_user(&mut tx, &user_sub)?;
        tx.execute(
            r#"
UPDATE klaxond_auth_sessions
SET revoked_at = $1
WHERE user_sub = $2 AND family_hash = $3 AND revoked_at IS NULL
"#,
            &[&now, &user_sub, &family_hash],
        )? as usize
    } else {
        0
    };
    tx.commit()?;
    Ok(changed)
}

pub(super) fn consume_oidc_logout(
    client: &mut Client,
    token: &OidcLogoutTokenRecord,
    provider_session_id: Option<&str>,
    subject: Option<&str>,
    now: i64,
) -> Result<OidcLogoutResult> {
    let mut tx = client.transaction()?;
    lock_provider_session(&mut tx, Some(&token.issuer), provider_session_id)?;
    lock_oidc_users(&mut tx, &token.issuer, provider_session_id, subject)?;
    tx.execute(
        "DELETE FROM klaxond_oidc_logout_tokens WHERE expires_at <= $1",
        &[&now],
    )?;
    let inserted = tx.execute(
        r#"
INSERT INTO klaxond_oidc_logout_tokens
  (issuer, token_id_hash, consumed_at, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (issuer, token_id_hash) DO NOTHING
"#,
        &[
            &token.issuer,
            &token.token_id_hash,
            &token.consumed_at,
            &token.expires_at,
        ],
    )?;
    if inserted == 0 {
        tx.commit()?;
        return Ok(OidcLogoutResult {
            replayed: true,
            revoked_sessions: 0,
        });
    }
    let revoked_sessions =
        revoke_oidc_sessions(&mut tx, &token.issuer, provider_session_id, subject, now)?;
    tx.commit()?;
    Ok(OidcLogoutResult {
        replayed: false,
        revoked_sessions,
    })
}

fn select_for_update(tx: &mut Transaction<'_>, id_hash: &str) -> Result<Option<AuthSessionRecord>> {
    Ok(tx
        .query_opt(
            r#"
SELECT id_hash, user_json, user_sub, auth_mode, provider_issuer, provider_session_id,
       family_hash, created_at, last_seen_at, last_rotated_at, expires_at, revoked_at
FROM klaxond_auth_sessions
WHERE id_hash = $1
FOR UPDATE
"#,
            &[&id_hash],
        )?
        .map(|row| session_from_row(&row)))
}

fn touch(tx: &mut Transaction<'_>, record: &mut AuthSessionRecord, now: i64) -> Result<()> {
    if now.saturating_sub(record.last_seen_at) >= SESSION_TOUCH_INTERVAL_SECONDS {
        tx.execute(
            "UPDATE klaxond_auth_sessions SET last_seen_at = $1 WHERE id_hash = $2 AND revoked_at IS NULL",
            &[&now, &record.id_hash],
        )?;
        record.last_seen_at = now;
    }
    Ok(())
}

fn prune_concurrent(
    tx: &mut Transaction<'_>,
    record: &AuthSessionRecord,
    max_concurrent: usize,
    now: i64,
) -> Result<()> {
    tx.execute(
        r#"
WITH stale AS (
  SELECT id_hash
  FROM klaxond_auth_sessions
  WHERE user_sub = $2
    AND id_hash <> $3
    AND revoked_at IS NULL
    AND expires_at > $1
  ORDER BY last_seen_at DESC, created_at DESC, id_hash DESC
  OFFSET $4
)
UPDATE klaxond_auth_sessions
SET revoked_at = $1
WHERE id_hash IN (SELECT id_hash FROM stale)
"#,
        &[
            &now,
            &record.user_sub,
            &record.id_hash,
            &(max_concurrent.saturating_sub(1) as i64),
        ],
    )?;
    Ok(())
}

fn revoke_oidc_sessions(
    tx: &mut Transaction<'_>,
    issuer: &str,
    provider_session_id: Option<&str>,
    subject: Option<&str>,
    now: i64,
) -> Result<usize> {
    let changed = match (provider_session_id, subject) {
        (Some(session_id), Some(subject)) => tx.execute(
            r#"
UPDATE klaxond_auth_sessions SET revoked_at = $1
WHERE auth_mode = 'oidc' AND provider_issuer = $2
  AND provider_session_id = $3 AND user_sub = $4 AND revoked_at IS NULL
"#,
            &[&now, &issuer, &session_id, &subject],
        )?,
        (Some(session_id), None) => tx.execute(
            r#"
UPDATE klaxond_auth_sessions SET revoked_at = $1
WHERE auth_mode = 'oidc' AND provider_issuer = $2
  AND provider_session_id = $3 AND revoked_at IS NULL
"#,
            &[&now, &issuer, &session_id],
        )?,
        (None, Some(subject)) => tx.execute(
            r#"
UPDATE klaxond_auth_sessions SET revoked_at = $1
WHERE auth_mode = 'oidc' AND provider_issuer = $2
  AND user_sub = $3 AND revoked_at IS NULL
"#,
            &[&now, &issuer, &subject],
        )?,
        (None, None) => 0,
    };
    Ok(changed as usize)
}
