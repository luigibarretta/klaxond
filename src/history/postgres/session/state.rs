use crate::history::{AuthSessionRecord, OidcLogoutTokenRecord};
use anyhow::Result;
use postgres::{Client, GenericClient, Row};

pub(in crate::history::postgres) fn export_sessions(
    client: &mut Client,
) -> Result<Vec<AuthSessionRecord>> {
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

pub(in crate::history::postgres) fn import_session_locked(
    client: &mut impl GenericClient,
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

pub(in crate::history::postgres) fn export_logout_tokens(
    client: &mut Client,
) -> Result<Vec<OidcLogoutTokenRecord>> {
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

pub(in crate::history::postgres) fn import_logout_token(
    client: &mut impl GenericClient,
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

pub(super) fn session_from_row(row: &Row) -> AuthSessionRecord {
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

fn table_exists(client: &mut Client, table: &str) -> Result<bool> {
    let name = format!("public.{table}");
    let row = client.query_one("SELECT to_regclass($1)::text", &[&name])?;
    Ok(row.get::<_, Option<String>>(0).is_some())
}
