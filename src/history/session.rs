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
// Covers requests dispatched with the same browser cookie while rotation commits.
pub const SESSION_ROTATION_GRACE_SECONDS: i64 = 10;

pub fn session_is_valid(record: &AuthSessionRecord, now: i64, idle_timeout_seconds: i64) -> bool {
    let mut policy = SessionPolicy::gold_standard();
    policy.idle_timeout =
        Duration::from_secs(u64::try_from(idle_timeout_seconds).unwrap_or_default());

    record.revoked_at.is_none()
        && record.expires_at > now
        && !policy.is_expired(record.created_at, record.last_seen_at, now)
}

pub fn is_recent_rotation_successor(
    predecessor: &AuthSessionRecord,
    successor: &AuthSessionRecord,
    expected_successor_hash: &str,
    now: i64,
    idle_timeout_seconds: i64,
) -> bool {
    let Some(revoked_at) = predecessor.revoked_at else {
        return false;
    };
    revoked_at <= now
        && now.saturating_sub(revoked_at) <= SESSION_ROTATION_GRACE_SECONDS
        && successor.id_hash == expected_successor_hash
        && successor.family_hash == predecessor.family_hash
        && successor.user_sub == predecessor.user_sub
        && successor.auth_mode == predecessor.auth_mode
        && successor.provider_issuer == predecessor.provider_issuer
        && successor.provider_session_id == predecessor.provider_session_id
        && successor.created_at == predecessor.created_at
        && successor.last_rotated_at >= revoked_at
        && session_is_valid(successor, now, idle_timeout_seconds)
}

pub fn is_idempotent_rotation_retry(
    predecessor: &AuthSessionRecord,
    stored_successor: &AuthSessionRecord,
    candidate: &AuthSessionRecord,
    now: i64,
) -> bool {
    is_recent_rotation_successor(
        predecessor,
        stored_successor,
        &candidate.id_hash,
        now,
        i64::MAX,
    ) && stored_successor.user_json == candidate.user_json
        && stored_successor.expires_at == candidate.expires_at
}
