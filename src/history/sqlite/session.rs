use crate::history::session::{SESSION_TOUCH_INTERVAL_SECONDS, session_is_valid};
use crate::history::{AuthSessionRecord, OidcLogoutResult, OidcLogoutTokenRecord};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

mod rotation;

pub(in crate::history) use rotation::{create, lookup_rotation_successor};

pub(in crate::history) fn lookup(
    conn: &mut Connection,
    id_hash: &str,
    now: i64,
    idle_timeout_seconds: i64,
) -> Result<Option<AuthSessionRecord>> {
    let tx = conn.transaction()?;
    let record = select(&tx, id_hash)?;
    let Some(mut record) = record else {
        tx.commit()?;
        return Ok(None);
    };
    if !session_is_valid(&record, now, idle_timeout_seconds) {
        tx.execute(
            "UPDATE klaxond_auth_sessions SET revoked_at = COALESCE(revoked_at, ?1) WHERE id_hash = ?2",
            params![now, id_hash],
        )?;
        tx.commit()?;
        return Ok(None);
    }
    touch(&tx, &mut record, now)?;
    tx.commit()?;
    Ok(Some(record))
}

pub(in crate::history) fn revoke(conn: &Connection, id_hash: &str, now: i64) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE klaxond_auth_sessions SET revoked_at = ?1 WHERE id_hash = ?2 AND revoked_at IS NULL",
        params![now, id_hash],
    )? > 0)
}

pub(in crate::history) fn revoke_family_by_id(
    conn: &mut Connection,
    id_hash: &str,
    now: i64,
) -> Result<usize> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let family = tx
        .query_row(
            "SELECT user_sub, family_hash FROM klaxond_auth_sessions WHERE id_hash = ?1",
            params![id_hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let changed = if let Some((user_sub, family_hash)) = family {
        tx.execute(
            r#"
UPDATE klaxond_auth_sessions
SET revoked_at = ?1
WHERE user_sub = ?2 AND family_hash = ?3 AND revoked_at IS NULL
"#,
            params![now, user_sub, family_hash],
        )?
    } else {
        0
    };
    tx.commit()?;
    Ok(changed)
}

pub(in crate::history) fn consume_oidc_logout(
    conn: &mut Connection,
    token: &OidcLogoutTokenRecord,
    provider_session_id: Option<&str>,
    subject: Option<&str>,
    now: i64,
) -> Result<OidcLogoutResult> {
    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM klaxond_oidc_logout_tokens WHERE expires_at <= ?1",
        params![now],
    )?;
    let inserted = tx.execute(
        r#"
INSERT OR IGNORE INTO klaxond_oidc_logout_tokens
  (issuer, token_id_hash, consumed_at, expires_at)
VALUES (?1, ?2, ?3, ?4)
"#,
        params![
            &token.issuer,
            &token.token_id_hash,
            token.consumed_at,
            token.expires_at,
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
        revoke_oidc_sessions(&tx, &token.issuer, provider_session_id, subject, now)?;
    tx.commit()?;
    Ok(OidcLogoutResult {
        replayed: false,
        revoked_sessions,
    })
}

pub(in crate::history) fn export_sessions(conn: &Connection) -> Result<Vec<AuthSessionRecord>> {
    if !table_exists(conn, "klaxond_auth_sessions")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        r#"
SELECT id_hash, user_json, user_sub, auth_mode, provider_issuer, provider_session_id,
       family_hash, created_at, last_seen_at, last_rotated_at, expires_at, revoked_at
FROM klaxond_auth_sessions
ORDER BY created_at, id_hash
"#,
    )?;
    let rows = stmt.query_map([], session_from_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub(in crate::history) fn import_session(
    conn: &Connection,
    record: &AuthSessionRecord,
) -> Result<()> {
    conn.execute(
        r#"
INSERT INTO klaxond_auth_sessions (
  id_hash, family_hash, user_json, user_sub, auth_mode, provider_issuer,
  provider_session_id, created_at, last_seen_at, last_rotated_at, expires_at, revoked_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
ON CONFLICT(id_hash) DO UPDATE SET
  created_at = MIN(klaxond_auth_sessions.created_at, excluded.created_at),
  last_seen_at = MAX(klaxond_auth_sessions.last_seen_at, excluded.last_seen_at),
  last_rotated_at = MAX(klaxond_auth_sessions.last_rotated_at, excluded.last_rotated_at),
  expires_at = MIN(klaxond_auth_sessions.expires_at, excluded.expires_at),
  revoked_at = CASE
    WHEN klaxond_auth_sessions.revoked_at IS NULL THEN excluded.revoked_at
    WHEN excluded.revoked_at IS NULL THEN klaxond_auth_sessions.revoked_at
    ELSE MIN(klaxond_auth_sessions.revoked_at, excluded.revoked_at)
  END
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
    Ok(())
}

pub(in crate::history) fn export_logout_tokens(
    conn: &Connection,
) -> Result<Vec<OidcLogoutTokenRecord>> {
    if !table_exists(conn, "klaxond_oidc_logout_tokens")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        r#"
SELECT issuer, token_id_hash, consumed_at, expires_at
FROM klaxond_oidc_logout_tokens
ORDER BY consumed_at, issuer, token_id_hash
"#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(OidcLogoutTokenRecord {
            issuer: row.get(0)?,
            token_id_hash: row.get(1)?,
            consumed_at: row.get(2)?,
            expires_at: row.get(3)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub(in crate::history) fn import_logout_token(
    conn: &Connection,
    token: &OidcLogoutTokenRecord,
) -> Result<()> {
    conn.execute(
        r#"
INSERT INTO klaxond_oidc_logout_tokens
  (issuer, token_id_hash, consumed_at, expires_at)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(issuer, token_id_hash) DO UPDATE SET
  consumed_at = MIN(klaxond_oidc_logout_tokens.consumed_at, excluded.consumed_at),
  expires_at = MAX(klaxond_oidc_logout_tokens.expires_at, excluded.expires_at)
"#,
        params![
            &token.issuer,
            &token.token_id_hash,
            token.consumed_at,
            token.expires_at,
        ],
    )?;
    Ok(())
}

fn select(tx: &Transaction<'_>, id_hash: &str) -> Result<Option<AuthSessionRecord>> {
    tx.query_row(
        r#"
SELECT id_hash, user_json, user_sub, auth_mode, provider_issuer, provider_session_id,
       family_hash, created_at, last_seen_at, last_rotated_at, expires_at, revoked_at
FROM klaxond_auth_sessions
WHERE id_hash = ?1
"#,
        params![id_hash],
        session_from_row,
    )
    .optional()
    .map_err(Into::into)
}

fn touch(tx: &Transaction<'_>, record: &mut AuthSessionRecord, now: i64) -> Result<()> {
    if now.saturating_sub(record.last_seen_at) >= SESSION_TOUCH_INTERVAL_SECONDS {
        tx.execute(
            "UPDATE klaxond_auth_sessions SET last_seen_at = ?1 WHERE id_hash = ?2 AND revoked_at IS NULL",
            params![now, &record.id_hash],
        )?;
        record.last_seen_at = now;
    }
    Ok(())
}

fn session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthSessionRecord> {
    Ok(AuthSessionRecord {
        id_hash: row.get(0)?,
        user_json: row.get(1)?,
        user_sub: row.get(2)?,
        auth_mode: row.get(3)?,
        provider_issuer: row.get(4)?,
        provider_session_id: row.get(5)?,
        family_hash: row.get(6)?,
        created_at: row.get(7)?,
        last_seen_at: row.get(8)?,
        last_rotated_at: row.get(9)?,
        expires_at: row.get(10)?,
        revoked_at: row.get(11)?,
    })
}

fn prune_concurrent(
    tx: &Transaction<'_>,
    record: &AuthSessionRecord,
    max_concurrent: usize,
    now: i64,
) -> Result<()> {
    tx.execute(
        r#"
UPDATE klaxond_auth_sessions
SET revoked_at = ?1
WHERE id_hash IN (
  SELECT id_hash
  FROM klaxond_auth_sessions
  WHERE user_sub = ?2
    AND id_hash <> ?3
    AND revoked_at IS NULL
    AND expires_at > ?1
  ORDER BY last_seen_at DESC, created_at DESC, rowid DESC
  LIMIT -1 OFFSET ?4
)
"#,
        params![
            now,
            &record.user_sub,
            &record.id_hash,
            max_concurrent.saturating_sub(1) as i64,
        ],
    )?;
    Ok(())
}

fn prune_expired(tx: &Transaction<'_>, now: i64) -> Result<()> {
    tx.execute(
        "DELETE FROM klaxond_auth_sessions WHERE expires_at <= ?1 AND expires_at < ?2",
        params![now, now.saturating_sub(86_400)],
    )?;
    Ok(())
}

fn revoke_oidc_sessions(
    tx: &Transaction<'_>,
    issuer: &str,
    provider_session_id: Option<&str>,
    subject: Option<&str>,
    now: i64,
) -> Result<usize> {
    let changed = match (provider_session_id, subject) {
        (Some(session_id), Some(subject)) => tx.execute(
            r#"
UPDATE klaxond_auth_sessions
SET revoked_at = ?1
WHERE auth_mode = 'oidc' AND provider_issuer = ?2
  AND provider_session_id = ?3 AND user_sub = ?4 AND revoked_at IS NULL
"#,
            params![now, issuer, session_id, subject],
        )?,
        (Some(session_id), None) => tx.execute(
            r#"
UPDATE klaxond_auth_sessions
SET revoked_at = ?1
WHERE auth_mode = 'oidc' AND provider_issuer = ?2
  AND provider_session_id = ?3 AND revoked_at IS NULL
"#,
            params![now, issuer, session_id],
        )?,
        (None, Some(subject)) => tx.execute(
            r#"
UPDATE klaxond_auth_sessions
SET revoked_at = ?1
WHERE auth_mode = 'oidc' AND provider_issuer = ?2
  AND user_sub = ?3 AND revoked_at IS NULL
"#,
            params![now, issuer, subject],
        )?,
        (None, None) => 0,
    };
    Ok(changed)
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![table],
        |row| row.get(0),
    )?)
}
