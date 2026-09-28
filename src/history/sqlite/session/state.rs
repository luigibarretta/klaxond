use crate::history::{AuthSessionRecord, OidcLogoutTokenRecord};
use anyhow::Result;
use rusqlite::{Connection, params};

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

pub(super) fn session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthSessionRecord> {
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

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![table],
        |row| row.get(0),
    )?)
}
