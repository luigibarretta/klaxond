use super::session::{issue_session, sanitize_return_to};
use super::step_up::redirect_location_after_primary;
use super::{
    AuthAuditKind, User, json_response, login_payload, record_auth_audit_failure, redirect,
};
use crate::config::AuthConfig;
use crate::state::{AppState, PendingMagicLink, lock_mutex};
use auth_modules::errors;
use auth_modules::one_time_token::{self, OneTimeTokenPolicy};
use auth_modules::rate_limit::{
    GOLD_AUTH_SHORT_BURST_MAX, GOLD_AUTH_SHORT_BURST_WINDOW, RateLimitOutcome,
};
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::{Body, Bytes};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;

pub fn magic_link_enabled(cfg: &AuthConfig) -> bool {
    cfg.mode == "basic"
        && !cfg.basic.username.trim().is_empty()
        && !cfg.basic.password_hash.trim().is_empty()
}

pub fn magic_link_request(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: Bytes,
) -> Response<Body> {
    let cfg = state.cfg();
    if !magic_link_enabled(&cfg.auth) {
        return (StatusCode::NOT_FOUND, "magic link login is not configured").into_response();
    }
    let payload = login_payload(&body);
    let username = payload.username().trim();
    if username.is_empty() {
        return (StatusCode::BAD_REQUEST, "username is required").into_response();
    }
    let return_to = sanitize_return_to(payload.return_to_or_status());
    let rate_key = magic_link_rate_key(username, headers, peer);
    let decision = state.auth_failures.record_attempt(
        &rate_key,
        GOLD_AUTH_SHORT_BURST_MAX,
        GOLD_AUTH_SHORT_BURST_WINDOW,
    );
    if !decision.allowed {
        record_auth_audit_failure(
            rate_key,
            "auth.magic_link",
            AuthAuditKind::RateLimitExceeded,
            errors::RATE_LIMITED.to_string(),
        );
        return rate_limited_retry_after(RateLimitOutcome::from(decision).retry_after());
    }

    let token = issue_magic_link(state, &cfg.auth, username, &return_to);
    let link = token
        .as_deref()
        .map(|token| magic_link_callback_url(&cfg.public_url, token));
    if payload.wants_json(&body) {
        return json_response(json!({
            "sent": true,
            "link": link,
            "expiresInSeconds": magic_link_ttl_seconds(),
        }));
    }
    if let Some(link) = link {
        return redirect(&link);
    }
    redirect(&format!(
        "/api/auth/login?magic_sent=1&return_to={}",
        urlencoding::encode(&return_to)
    ))
}

pub fn magic_link_callback(state: &AppState, token: &str) -> Response<Body> {
    let cfg = state.cfg().auth;
    if !magic_link_enabled(&cfg) {
        return (StatusCode::NOT_FOUND, "magic link login is not configured").into_response();
    }
    let (mut user, return_to) = match consume_magic_link(state, &cfg, token) {
        Ok(value) => value,
        Err(error) => {
            return redirect(&format!("/api/auth/login?magic_error={}", error.code()));
        }
    };
    if let Some(location) = redirect_location_after_primary(
        state,
        &cfg,
        user.clone(),
        &return_to,
        PrimaryAuthMethod::MagicLink,
    ) {
        return redirect(&location);
    }
    let cookie = issue_session(state, &cfg, &mut user);
    let mut resp = redirect(&return_to);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, value);
    }
    resp
}

pub(super) fn issue_magic_link(
    state: &AppState,
    cfg: &AuthConfig,
    username: &str,
    return_to: &str,
) -> Option<String> {
    if cfg.basic.username != username {
        let now = crate::util::now_epoch();
        let mut pending = lock_mutex(&state.magic_links, "magic links");
        prune_magic_links(&mut pending, now);
        return None;
    }
    let policy = OneTimeTokenPolicy::magic_link();
    let token = one_time_token::generate_token(policy.token_bytes);
    let token_hash = one_time_token::hash_token(&token);
    let now = crate::util::now_epoch();
    let mut pending = lock_mutex(&state.magic_links, "magic links");
    prune_magic_links(&mut pending, now);
    pending.insert(
        token_hash,
        PendingMagicLink {
            created_at: now,
            expires_at: now + policy.ttl.as_secs() as f64,
            username: username.to_string(),
            return_to: return_to.to_string(),
            used_at: None,
        },
    );
    Some(token)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MagicLinkError {
    Invalid,
    Used,
    Expired,
    Unavailable,
}

impl MagicLinkError {
    fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Unavailable => "unavailable",
        }
    }
}

pub(super) fn consume_magic_link(
    state: &AppState,
    cfg: &AuthConfig,
    token: &str,
) -> Result<(User, String), MagicLinkError> {
    let token_hash = one_time_token::hash_token(token);
    let now = crate::util::now_epoch();
    let challenge = {
        let mut pending = lock_mutex(&state.magic_links, "magic links");
        let Some(challenge) = pending.get_mut(&token_hash) else {
            return Err(MagicLinkError::Invalid);
        };
        if challenge.used_at.is_some() {
            return Err(MagicLinkError::Used);
        }
        if challenge.expires_at <= now {
            return Err(MagicLinkError::Expired);
        }
        challenge.used_at = Some(now);
        challenge.clone()
    };
    if cfg.basic.username != challenge.username {
        return Err(MagicLinkError::Unavailable);
    }
    Ok((
        User {
            sub: challenge.username,
            email: String::new(),
            name: String::new(),
            groups: vec!["magic-link".into()],
            mode: "magic_link".into(),
            exp: 0,
            csrf: String::new(),
            sudo_until: 0,
            via_authorization: false,
            second_factor: String::new(),
        },
        challenge.return_to,
    ))
}

fn prune_magic_links(pending: &mut HashMap<String, PendingMagicLink>, now: f64) {
    pending.retain(|_, challenge| challenge.expires_at > now);
}

pub(super) fn magic_link_ttl_seconds() -> i64 {
    i64::try_from(OneTimeTokenPolicy::magic_link().ttl.as_secs()).unwrap_or(i64::MAX)
}

pub fn magic_link_callback_url(public_url: &str, token: &str) -> String {
    let path = format!("/api/auth/magic/callback/{token}");
    let public_url = public_url.trim().trim_end_matches('/');
    if public_url.is_empty() {
        path
    } else {
        format!("{public_url}{path}")
    }
}

fn magic_link_rate_key(username: &str, headers: &HeaderMap, peer: SocketAddr) -> String {
    let subject = username.trim().to_ascii_lowercase();
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(str::to_string)
        .unwrap_or_else(|| peer.ip().to_string());
    format!(
        "magic_link:{}:{ip}",
        if subject.is_empty() {
            "unknown"
        } else {
            subject.as_str()
        }
    )
}

fn rate_limited_retry_after(retry_after: Option<std::time::Duration>) -> Response<Body> {
    let seconds = retry_after
        .unwrap_or(GOLD_AUTH_SHORT_BURST_WINDOW)
        .as_secs()
        .max(1);
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", seconds.to_string())
        .body(Body::from("too many authentication attempts"))
        .unwrap()
}
