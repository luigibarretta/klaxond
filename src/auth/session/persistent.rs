use super::token::{new_session_token, rotated_session_token};
use super::{VerifiedSession, session_cookie};
use crate::auth::User;
use crate::auth::blocking::{AUTH_STORE_TIMEOUT, run_with_timeout};
use crate::config::AuthConfig;
use crate::history::AuthSessionRecord;
use crate::state::AppState;
use crate::util::{now_epoch_i64, token_urlsafe};
use auth_modules::one_time_token::hash_token;
use auth_modules::session_policy::SessionPolicy;

#[derive(Clone, Copy)]
enum SessionOperation {
    Issue,
    Rotate,
}

pub(in crate::auth) fn issue_session(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
) -> Result<String, String> {
    issue_session_with_expiry(state, cfg, user, None)
}

pub(in crate::auth) fn rotate_session(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
) -> Result<String, String> {
    issue_session_with_expiry(state, cfg, user, Some(user.exp))
}

pub(in crate::auth) async fn issue_session_on_worker(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
) -> Result<String, String> {
    issue_session_on_worker_with_operation(state, cfg, user, SessionOperation::Issue).await
}

pub(in crate::auth) async fn rotate_session_on_worker(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
) -> Result<String, String> {
    issue_session_on_worker_with_operation(state, cfg, user, SessionOperation::Rotate).await
}

async fn issue_session_on_worker_with_operation(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
    operation: SessionOperation,
) -> Result<String, String> {
    let state_for_store = state.clone();
    let cfg = cfg.clone();
    let mut owned_user = user.clone();
    let (updated_user, cookie) = run_with_timeout(state, AUTH_STORE_TIMEOUT, move || {
        let result = match operation {
            SessionOperation::Issue => issue_session(&state_for_store, &cfg, &mut owned_user),
            SessionOperation::Rotate => rotate_session(&state_for_store, &cfg, &mut owned_user),
        };
        result.map(|cookie| (owned_user, cookie))
    })
    .await??;
    *user = updated_user;
    Ok(cookie)
}

fn issue_session_with_expiry(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
    preserve_expiry: Option<i64>,
) -> Result<String, String> {
    if user.csrf.is_empty() {
        user.csrf = format!("klx_csrf_{}", token_urlsafe(24));
    }
    let now = now_epoch_i64();
    let policy = SessionPolicy::gold_standard();
    let created_at = apply_session_expiry(cfg, user, preserve_expiry, now, &policy);
    if user.mode == "oidc" && user.provider_issuer.is_empty() {
        user.provider_issuer = cfg.oidc.issuer.trim().to_string();
    }
    let previous_hash = (!user.session_id_hash.is_empty()).then_some(user.session_id_hash.as_str());
    let token = previous_hash.map_or_else(new_session_token, |predecessor_hash| {
        rotated_session_token(state, predecessor_hash)
    });
    let id_hash = hash_token(&token);
    let family_hash = if previous_hash.is_some() && !user.session_family_hash.is_empty() {
        user.session_family_hash.clone()
    } else {
        hash_token(&format!("klx_family_{}", token_urlsafe(32)))
    };
    let record = AuthSessionRecord {
        id_hash: id_hash.clone(),
        family_hash: family_hash.clone(),
        user_json: serde_json::to_string(user)
            .map_err(|err| format!("serialize persistent session: {err}"))?,
        user_sub: user.sub.clone(),
        auth_mode: user.mode.clone(),
        provider_issuer: non_empty(&user.provider_issuer),
        provider_session_id: non_empty(&user.provider_session_id),
        created_at,
        last_seen_at: now,
        last_rotated_at: now,
        expires_at: user.exp,
        revoked_at: None,
    };
    state
        .with_auth_store(|store| {
            store.create_auth_session(
                &record,
                previous_hash,
                policy.max_concurrent_sessions as usize,
                now,
            )
        })
        .map_err(|err| format!("persist session: {err}"))?;
    user.session_id_hash = id_hash;
    user.session_family_hash = family_hash;
    user.session_created_at = created_at;
    let remaining = user.exp.saturating_sub(now);
    Ok(session_cookie(state, &token, remaining.max(0) as u64))
}

fn apply_session_expiry(
    cfg: &AuthConfig,
    user: &mut User,
    preserve_expiry: Option<i64>,
    now: i64,
    policy: &SessionPolicy,
) -> i64 {
    let timeout_seconds =
        i64::try_from(cfg.session_timeout_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    let created_at = if preserve_expiry.is_some() && user.session_created_at > 0 {
        user.session_created_at
    } else {
        now
    };
    let policy_lifetime = i64::try_from(policy.max_lifetime.as_secs()).unwrap_or(i64::MAX);
    let absolute_deadline = created_at.saturating_add(policy_lifetime);
    user.exp = preserve_expiry
        .filter(|expires_at| *expires_at > now)
        .unwrap_or_else(|| now.saturating_add(timeout_seconds))
        .min(absolute_deadline);
    created_at
}

pub fn issue_session_cookie(state: &AppState, user: &mut User) -> Result<String, String> {
    let cfg = state.cfg().auth;
    issue_session(state, &cfg, user)
}

pub(super) async fn verify_persistent_session(
    state: &AppState,
    id_hash: String,
) -> Result<Option<VerifiedSession>, String> {
    let now = now_epoch_i64();
    let policy = SessionPolicy::gold_standard();
    let idle_timeout_seconds = i64::try_from(policy.idle_timeout.as_secs()).unwrap_or(i64::MAX);
    let replacement_token = rotated_session_token(state, &id_hash);
    let replacement_hash = hash_token(&replacement_token);
    let state_for_store = state.clone();
    let predecessor_hash = id_hash.clone();
    let (record, recovered_rotation) = run_with_timeout(state, AUTH_STORE_TIMEOUT, move || {
        state_for_store.with_auth_store(|store| {
            if let Some(record) = store
                .auth_session(&predecessor_hash, now, idle_timeout_seconds)
                .map_err(|err| err.to_string())?
            {
                return Ok::<_, String>((Some(record), false));
            }
            let successor = store
                .auth_session_rotation_successor(
                    &predecessor_hash,
                    &replacement_hash,
                    now,
                    idle_timeout_seconds,
                )
                .map_err(|err| err.to_string())?;
            Ok::<_, String>((successor, true))
        })
    })
    .await??;
    let Some(record) = record else {
        return Ok(None);
    };
    let mut user: User = serde_json::from_str(&record.user_json)
        .map_err(|err| format!("decode persistent session: {err}"))?;
    if user.sub != record.user_sub || user.mode != record.auth_mode {
        return Err("persistent session identity metadata mismatch".to_string());
    }
    user.exp = record.expires_at;
    user.session_id_hash = record.id_hash;
    user.session_family_hash = record.family_hash;
    user.session_created_at = record.created_at;
    user.provider_issuer = record.provider_issuer.unwrap_or_default();
    user.provider_session_id = record.provider_session_id.unwrap_or_default();
    Ok(Some(VerifiedSession {
        should_rotate: policy.should_rotate(record.last_rotated_at, now),
        user,
        legacy: false,
        replacement_cookie: recovered_rotation.then(|| {
            let remaining = record.expires_at.saturating_sub(now);
            session_cookie(state, &replacement_token, remaining.max(0) as u64)
        }),
    }))
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}
