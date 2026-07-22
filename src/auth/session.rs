use super::blocking::{AUTH_STORE_TIMEOUT, run_with_timeout};
use super::{AUTH_SESSION_COOKIE, User, json_response};
use crate::config::AuthConfig;
use crate::history::AuthSessionRecord;
use crate::state::AppState;
use crate::util::{b64url_decode_padded, hmac_hex, now_epoch_i64, token_urlsafe};
use auth_modules::one_time_token::hash_token;
use auth_modules::session_policy::{SameSitePolicy, SessionPolicy};
use axum::body::Body;
use axum::http::header::{HOST, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use constant_time_eq::constant_time_eq;
use serde_json::json;
use std::net::IpAddr;

mod token;

pub(super) use token::persistent_session_hash;
use token::{new_session_token, rotated_session_token};

pub(super) struct VerifiedSession {
    pub user: User,
    pub legacy: bool,
    pub should_rotate: bool,
    pub replacement_cookie: Option<String>,
}

fn same_site_header(value: SameSitePolicy) -> &'static str {
    match value {
        SameSitePolicy::Lax => "Lax",
        SameSitePolicy::Strict => "Strict",
        SameSitePolicy::None => "None",
    }
}

pub async fn api_logout(state: &AppState, headers: &HeaderMap) -> Response<Body> {
    let hashes = headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|cookie| {
            cookie_values(cookie, AUTH_SESSION_COOKIE)
                .into_iter()
                .filter_map(persistent_session_hash)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let state_for_store = state.clone();
    let now = now_epoch_i64();
    let revoked = run_with_timeout(state, AUTH_STORE_TIMEOUT, move || {
        for hash in hashes {
            state_for_store
                .with_auth_store(|store| store.revoke_auth_session_family(&hash, now))
                .map_err(|err| err.to_string())?;
        }
        Ok::<_, String>(())
    })
    .await
    .and_then(|result| result);
    let mut resp = if let Err(err) = revoked {
        tracing::error!("persistent session logout failed: {err}");
        let mut response = json_response(json!({"ok": false}));
        *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        response
    } else {
        json_response(json!({"ok": true}))
    };
    for cookie in expired_session_cookies(headers) {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().append(SET_COOKIE, value);
        }
    }
    resp
}

pub(super) fn issue_session(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
) -> Result<String, String> {
    issue_session_with_expiry(state, cfg, user, None)
}

pub(super) fn rotate_session(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
) -> Result<String, String> {
    issue_session_with_expiry(state, cfg, user, Some(user.exp))
}

pub(super) async fn issue_session_on_worker(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
) -> Result<String, String> {
    issue_session_on_worker_with_mode(state, cfg, user, false).await
}

pub(super) async fn rotate_session_on_worker(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
) -> Result<String, String> {
    issue_session_on_worker_with_mode(state, cfg, user, true).await
}

async fn issue_session_on_worker_with_mode(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
    rotate: bool,
) -> Result<String, String> {
    let state_for_store = state.clone();
    let cfg = cfg.clone();
    let mut owned_user = user.clone();
    let (updated_user, cookie) = run_with_timeout(state, AUTH_STORE_TIMEOUT, move || {
        let result = if rotate {
            rotate_session(&state_for_store, &cfg, &mut owned_user)
        } else {
            issue_session(&state_for_store, &cfg, &mut owned_user)
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

fn session_cookie(state: &AppState, token: &str, max_age: u64) -> String {
    let policy = SessionPolicy::gold_standard().cookie;
    let http_only = if policy.http_only { "; HttpOnly" } else { "" };
    let secure = if state.with_cfg(|cfg| cfg.public_url.starts_with("https://")) {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{AUTH_SESSION_COOKIE}={token}{http_only}{secure}; Path={}; SameSite={}; Max-Age={max_age}",
        policy.path,
        same_site_header(policy.same_site),
    )
}

pub(super) fn set_session_cookie(resp: &mut Response<Body>, cookie: &str) {
    match HeaderValue::from_str(cookie) {
        Ok(value) => {
            resp.headers_mut().insert(SET_COOKIE, value);
        }
        Err(err) => {
            tracing::error!(?err, "failed to build session cookie header");
        }
    }
}

pub fn issue_session_cookie(state: &AppState, user: &mut User) -> Result<String, String> {
    let cfg = state.cfg().auth;
    issue_session(state, &cfg, user)
}

pub(super) async fn verify_session(
    state: &AppState,
    cookie_value: &str,
) -> Result<Option<VerifiedSession>, String> {
    if let Some(id_hash) = persistent_session_hash(cookie_value) {
        return verify_persistent_session(state, id_hash).await;
    }
    Ok(
        verify_legacy_session(state, cookie_value).map(|user| VerifiedSession {
            user,
            legacy: true,
            should_rotate: false,
            replacement_cookie: None,
        }),
    )
}

async fn verify_persistent_session(
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

fn verify_legacy_session(state: &AppState, cookie_value: &str) -> Option<User> {
    let (body, sig) = cookie_value.split_once('.')?;
    let expected = hmac_hex(state.session_key.as_slice(), body.as_bytes());
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return None;
    }
    let bytes = b64url_decode_padded(body).ok()?;
    let user: User = serde_json::from_slice(&bytes).ok()?;
    if user.exp > 0 && user.exp <= now_epoch_i64() {
        return None;
    }
    Some(user)
}

pub(super) fn cookie_values<'a>(cookie: &'a str, name: &str) -> Vec<&'a str> {
    cookie
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then_some(value)
        })
        .collect()
}

pub(super) fn sanitize_return_to(value: &str) -> String {
    auth_modules::oidc_pkce::sanitize_local_redirect(
        Some(value),
        auth_modules::oidc_pkce::LocalRedirectPolicy::default(),
    )
}

fn expired_session_cookies(headers: &HeaderMap) -> Vec<String> {
    let mut cookies = Vec::new();
    let domains = logout_domain_candidates(headers);
    for path in ["/", "/api/auth/login", "/api/auth/callback"] {
        cookies.push(expired_session_cookie(path, None));
        for domain in &domains {
            cookies.push(expired_session_cookie(path, Some(domain)));
        }
    }
    cookies
}

fn expired_session_cookie(path: &str, domain: Option<&str>) -> String {
    let mut cookie = format!(
        "{AUTH_SESSION_COOKIE}=; HttpOnly; Path={path}; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
    if let Some(domain) = domain {
        cookie.push_str("; Domain=");
        cookie.push_str(domain);
    }
    cookie
}

fn logout_domain_candidates(headers: &HeaderMap) -> Vec<String> {
    let Some(host) = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(':').next())
        .map(|v| v.trim().trim_end_matches('.'))
        .filter(|v| !v.is_empty())
    else {
        return Vec::new();
    };
    if host.parse::<IpAddr>().is_ok() || host.contains(['/', '\\']) {
        return Vec::new();
    }

    let mut domains = vec![host.to_string(), format!(".{host}")];
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() > 2 {
        let parent = labels[labels.len() - 2..].join(".");
        domains.push(parent.clone());
        domains.push(format!(".{parent}"));
    }
    domains.sort();
    domains.dedup();
    domains
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}
