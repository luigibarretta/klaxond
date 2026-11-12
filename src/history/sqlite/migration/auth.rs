//! Authentication tables (sessions, OIDC logout replay, rate limits).

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_auth_sessions (
  id_hash TEXT PRIMARY KEY,
  family_hash TEXT NOT NULL,
  user_json TEXT NOT NULL,
  user_sub TEXT NOT NULL,
  auth_mode TEXT NOT NULL,
  provider_issuer TEXT,
  provider_session_id TEXT,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  last_rotated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_user
  ON klaxond_auth_sessions(user_sub, auth_mode, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_concurrent
  ON klaxond_auth_sessions(user_sub, last_seen_at DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_oidc_sid
  ON klaxond_auth_sessions(provider_issuer, provider_session_id)
  WHERE auth_mode = 'oidc' AND provider_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_oidc_sub
  ON klaxond_auth_sessions(provider_issuer, user_sub)
  WHERE auth_mode = 'oidc';

CREATE TABLE IF NOT EXISTS klaxond_oidc_logout_tokens (
  issuer TEXT NOT NULL,
  token_id_hash TEXT NOT NULL,
  consumed_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (issuer, token_id_hash)
);

CREATE INDEX IF NOT EXISTS idx_klaxond_oidc_logout_tokens_expiry
  ON klaxond_oidc_logout_tokens(expires_at);

CREATE TABLE IF NOT EXISTS klaxond_auth_rate_limits (
  key_hash TEXT PRIMARY KEY,
  failure_epochs_json TEXT NOT NULL,
  locked_until_epoch INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_klaxond_auth_rate_limits_updated
  ON klaxond_auth_rate_limits(updated_at);
"#;

/// Sessions created before `family_hash` existed form their own family.
pub(super) const BACKFILL_FAMILY: &str = r#"
UPDATE klaxond_auth_sessions SET family_hash = id_hash WHERE family_hash = '';
CREATE INDEX IF NOT EXISTS idx_klaxond_auth_sessions_family ON klaxond_auth_sessions(family_hash);
"#;

/// Per-start repair of sessions written without a family (see `migrate`).
pub(super) const RECONCILE_FAMILY: &str =
    "UPDATE klaxond_auth_sessions SET family_hash = id_hash WHERE family_hash = ''";
