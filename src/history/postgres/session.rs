use super::session_locks::{lock_oidc_users, lock_provider_session, lock_user};
use crate::history::session::{SESSION_TOUCH_INTERVAL_SECONDS, session_is_valid};
use crate::history::{AuthSessionRecord, OidcLogoutResult, OidcLogoutTokenRecord};
use anyhow::{Result, bail};
use postgres::{Client, Transaction};

pub(super) fn create(
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
    if let Some(previous) = replace_id_hash {
        let predecessor = select_for_update(&mut tx, previous)?;
        let valid_predecessor = predecessor.as_ref().is_some_and(|predecessor| {
            predecessor.family_hash == record.family_hash
                && predecessor.user_sub == record.user_sub
                && session_is_valid(predecessor, now, i64::MAX)
        });
        if !valid_predecessor {
            bail!("session rotation predecessor is not active in the same family");
        }
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
    if now.saturating_sub(record.last_seen_at) >= SESSION_TOUCH_INTERVAL_SECONDS {
        tx.execute(
            "UPDATE klaxond_auth_sessions SET last_seen_at = $1 WHERE id_hash = $2 AND revoked_at IS NULL",
            &[&now, &id_hash],
        )?;
        record.last_seen_at = now;
    }
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

pub(super) fn export_sessions(client: &mut Client) -> Result<Vec<AuthSessionRecord>> {
    if !table_exists(client, "klaxond_auth_sessions")? {
        return Ok(Vec::new());
    }
    Ok(client
        .query(
            r#"
SELECT id_hash, user_json, user_sub, auth_mode, provider_issuer, provider_session_id,
       family_hash, created_at, last_seen_at, last_rotated_at, expires_at, revoked_at
FROM klaxond_auth_sessions
ORDER BY created_at, id_hash
"#,
            &[],
        )?
        .iter()
        .map(session_from_row)
        .collect())
}

pub(super) fn import_session_locked(
    client: &mut impl postgres::GenericClient,
    record: &AuthSessionRecord,
) -> Result<()> {
    client.execute(
        r#"
INSERT INTO klaxond_auth_sessions (
  id_hash, family_hash, user_json, user_sub, auth_mode, provider_issuer,
  provider_session_id, created_at, last_seen_at, last_rotated_at, expires_at, revoked_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id_hash) DO UPDATE SET
  created_at = LEAST(klaxond_auth_sessions.created_at, EXCLUDED.created_at),
  last_seen_at = GREATEST(klaxond_auth_sessions.last_seen_at, EXCLUDED.last_seen_at),
  last_rotated_at = GREATEST(
    klaxond_auth_sessions.last_rotated_at,
    EXCLUDED.last_rotated_at
  ),
  expires_at = LEAST(klaxond_auth_sessions.expires_at, EXCLUDED.expires_at),
  revoked_at = CASE
    WHEN klaxond_auth_sessions.revoked_at IS NULL THEN EXCLUDED.revoked_at
    WHEN EXCLUDED.revoked_at IS NULL THEN klaxond_auth_sessions.revoked_at
    ELSE LEAST(klaxond_auth_sessions.revoked_at, EXCLUDED.revoked_at)
  END
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
    Ok(())
}

pub(super) fn export_logout_tokens(client: &mut Client) -> Result<Vec<OidcLogoutTokenRecord>> {
    if !table_exists(client, "klaxond_oidc_logout_tokens")? {
        return Ok(Vec::new());
    }
    Ok(client
        .query(
            r#"
SELECT issuer, token_id_hash, consumed_at, expires_at
FROM klaxond_oidc_logout_tokens
ORDER BY consumed_at, issuer, token_id_hash
"#,
            &[],
        )?
        .into_iter()
        .map(|row| OidcLogoutTokenRecord {
            issuer: row.get(0),
            token_id_hash: row.get(1),
            consumed_at: row.get(2),
            expires_at: row.get(3),
        })
        .collect())
}

pub(super) fn import_logout_token(
    client: &mut impl postgres::GenericClient,
    token: &OidcLogoutTokenRecord,
) -> Result<()> {
    client.execute(
        r#"
INSERT INTO klaxond_oidc_logout_tokens
  (issuer, token_id_hash, consumed_at, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (issuer, token_id_hash) DO UPDATE SET
  consumed_at = LEAST(klaxond_oidc_logout_tokens.consumed_at, EXCLUDED.consumed_at),
  expires_at = GREATEST(klaxond_oidc_logout_tokens.expires_at, EXCLUDED.expires_at)
"#,
        &[
            &token.issuer,
            &token.token_id_hash,
            &token.consumed_at,
            &token.expires_at,
        ],
    )?;
    Ok(())
}

fn session_from_row(row: &postgres::Row) -> AuthSessionRecord {
    AuthSessionRecord {
        id_hash: row.get(0),
        user_json: row.get(1),
        user_sub: row.get(2),
        auth_mode: row.get(3),
        provider_issuer: row.get(4),
        provider_session_id: row.get(5),
        family_hash: row.get(6),
        created_at: row.get(7),
        last_seen_at: row.get(8),
        last_rotated_at: row.get(9),
        expires_at: row.get(10),
        revoked_at: row.get(11),
    }
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

fn table_exists(client: &mut Client, table: &str) -> Result<bool> {
    let name = format!("public.{table}");
    let row = client.query_one("SELECT to_regclass($1)::text", &[&name])?;
    Ok(row.get::<_, Option<String>>(0).is_some())
}
