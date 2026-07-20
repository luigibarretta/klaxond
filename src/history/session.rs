use auth_modules::session_policy::SessionPolicy;
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthSessionRecord {
    pub id_hash: String,
    pub family_hash: String,
    pub user_json: String,
    pub user_sub: String,
    pub auth_mode: String,
    pub provider_issuer: Option<String>,
    pub provider_session_id: Option<String>,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub last_rotated_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLogoutTokenRecord {
    pub issuer: String,
    pub token_id_hash: String,
    pub consumed_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OidcLogoutResult {
    pub replayed: bool,
    pub revoked_sessions: usize,
}

pub const SESSION_TOUCH_INTERVAL_SECONDS: i64 = 60;

pub fn session_is_valid(record: &AuthSessionRecord, now: i64, idle_timeout_seconds: i64) -> bool {
    let mut policy = SessionPolicy::gold_standard();
    policy.idle_timeout =
        Duration::from_secs(u64::try_from(idle_timeout_seconds).unwrap_or_default());

    record.revoked_at.is_none()
        && record.expires_at > now
        && !policy.is_expired(record.created_at, record.last_seen_at, now)
}
