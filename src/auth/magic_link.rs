use super::session::{issue_session_on_worker, sanitize_return_to};
use super::step_up::{redirect_location_after_primary, user_has_totp};
use super::{
    AuthAuditKind, User, json_response, login_payload, record_auth_audit_failure, redirect,
};
use crate::config::{AuthConfig, RuntimeConfig};
use crate::delivery::channels::{send_operator_text, smtp_ready};
use crate::state::{AppState, PendingMagicLink, lock_mutex};
use auth_modules::errors;
use auth_modules::one_time_token::{
    self, DeliverableToken, OneTimeTokenPolicy, OneTimeTokenPurpose, issue_for_delivery,
};
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

const MAGIC_LINK_SMTP_TIMEOUT_SECONDS: u64 = 10;
/// Global cap on magic links issued (and e-mailed) across all requesters,
/// on top of the per-username/IP burst limit. It bounds mail volume to the
/// operator inbox even when an attacker rotates source IPs. Once the cap is
/// reached the request still answers with the uniform 202, but no token is
/// issued, no mail is sent and the existing pending link stays valid.
const MAGIC_LINK_GLOBAL_ISSUE_MAX: usize = 5;
const MAGIC_LINK_GLOBAL_ISSUE_WINDOW: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const MAGIC_LINK_GLOBAL_ISSUE_KEY: &str = "magic_link_issue:global";

/// Magic-link login is fail-closed. It requires an explicit opt-in
/// (`auth.magic_link_enabled`), a configured local account, an absolute
/// public URL for the link, an SMTP channel for out-of-band delivery, and no
/// TOTP on the local account: the callback cannot verify that TOTP, so it
/// must never become a way to skip it. The SMTP channel must also use
/// STARTTLS: the link is a bearer credential and must not travel in clear
/// text (the transport has no implicit-TLS mode). Ordinary SMTP alerts keep
/// accepting `smtp_starttls = false`.
pub fn magic_link_enabled(cfg: &RuntimeConfig) -> bool {
    let auth = &cfg.auth;
    auth.magic_link_enabled
        && auth.mode == "basic"
        && !auth.basic.username.trim().is_empty()
        && !auth.basic.password_hash.trim().is_empty()
        && !user_has_totp(auth, &auth.basic.username)
        && !cfg.public_url.trim().is_empty()
        && smtp_ready(cfg)
        && cfg.smtp_starttls
}

pub fn magic_link_request(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: Bytes,
) -> Response<Body> {
    let cfg = state.cfg();
    if !magic_link_enabled(&cfg) {
        return (StatusCode::NOT_FOUND, "magic link login is not configured").into_response();
    }
    let payload = login_payload(&body);
    let username = payload.username().trim();
    if username.is_empty() {
        return (StatusCode::BAD_REQUEST, "username is required").into_response();
    }
    let return_to = sanitize_return_to(payload.return_to_or_status());
    let client_ip = super::rate_limit::client_ip(state, headers, Some(peer));
    let rate_key = magic_link_rate_key(username, &client_ip);
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

    if let Some(token) = issue_magic_link(state, &cfg.auth, username, &return_to) {
        deliver_magic_link(&cfg, token, &client_ip);
    }
    // Uniform answer for known and unknown users: the link is delivered only
    // out of band and never appears in the response or in a redirect.
    if payload.wants_json(&body) {
        let mut resp = json_response(json!({
            "sent": true,
            "expiresInSeconds": magic_link_ttl_seconds(),
        }));
        *resp.status_mut() = StatusCode::ACCEPTED;
        return resp;
    }
    redirect(&format!(
        "/api/auth/login?magic_sent=1&return_to={}",
        urlencoding::encode(&return_to)
    ))
}

pub async fn magic_link_callback(state: &AppState, token: &str) -> Response<Body> {
    let runtime = state.cfg();
    if !magic_link_enabled(&runtime) {
        return (StatusCode::NOT_FOUND, "magic link login is not configured").into_response();
    }
    let cfg = runtime.auth;
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
    let cookie = match issue_session_on_worker(state, &cfg, &mut user).await {
        Ok(cookie) => cookie,
        Err(err) => {
            tracing::error!("persist magic-link session failed: {err}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut resp = redirect(&return_to);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, value);
    }
    resp
}

/// Hands the link to the SMTP channel; the plaintext token exists only inside
/// this delivery and never reaches the HTTP response.
fn deliver_magic_link(cfg: &RuntimeConfig, token: DeliverableToken, client_ip: &str) {
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let Ok(()) = token.deliver(|token: &str| {
        let link = magic_link_callback_url(&cfg.public_url, token);
        spawn_magic_link_delivery(cfg, magic_link_email_body(&link, client_ip, &requested_at));
        Ok::<(), std::convert::Infallible>(())
    });
}

/// Plain-text mail body. The requester IP (as resolved through the trusted
/// proxy chain) and the request time let the operator spot unsolicited links.
pub(super) fn magic_link_email_body(link: &str, client_ip: &str, requested_at: &str) -> String {
    let minutes = (magic_link_ttl_seconds() / 60).max(1);
    format!(
        "A Klaxond sign-in link was requested for the local account.\n\n\
         Requested from: {client_ip}\n\
         Requested at: {requested_at}\n\n\
         {link}\n\n\
         The link works once and expires in {minutes} minutes. Requesting a new \
         link invalidates this one. If you did not request it, ignore this \
         message.\n"
    )
}

fn spawn_magic_link_delivery(cfg: &RuntimeConfig, body: String) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!("magic link not delivered: no async runtime available");
        return;
    };
    let cfg = cfg.clone();
    handle.spawn(async move {
        let subject = "Klaxond sign-in link";
        if !send_operator_text(&cfg, subject, body, MAGIC_LINK_SMTP_TIMEOUT_SECONDS).await {
            tracing::warn!("magic link delivery over SMTP failed");
        }
    });
}

pub(super) fn issue_magic_link(
    state: &AppState,
    cfg: &AuthConfig,
    username: &str,
    return_to: &str,
) -> Option<DeliverableToken> {
    if cfg.basic.username != username {
        let now = crate::util::now_epoch();
        let mut pending = lock_mutex(&state.magic_links, "magic links");
        prune_magic_links(&mut pending, now);
        return None;
    }
    let budget = state.auth_failures.record_attempt(
        MAGIC_LINK_GLOBAL_ISSUE_KEY,
        MAGIC_LINK_GLOBAL_ISSUE_MAX,
        MAGIC_LINK_GLOBAL_ISSUE_WINDOW,
    );
    if !budget.allowed {
        tracing::warn!("magic link not issued: global issuance cap reached");
        return None;
    }
    let now = crate::util::now_epoch();
    // Only the hash is stored; the plaintext leaves through `deliver`.
    let (record, token) = issue_for_delivery(
        username,
        OneTimeTokenPurpose::MagicLink,
        OneTimeTokenPolicy::magic_link(),
        now as i64,
    );
    let mut pending = lock_mutex(&state.magic_links, "magic links");
    prune_magic_links(&mut pending, now);
    // One valid link per user: a new request revokes every unused one.
    pending.retain(|_, challenge| challenge.username != username || challenge.used_at.is_some());
    pending.insert(
        record.token_hash,
        PendingMagicLink {
            created_at: now,
            expires_at: record.expires_at_epoch as f64,
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
            session_id_hash: String::new(),
            session_family_hash: String::new(),
            session_created_at: 0,
            provider_issuer: String::new(),
            provider_session_id: String::new(),
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

fn magic_link_rate_key(username: &str, ip: &str) -> String {
    let subject = username.trim().to_ascii_lowercase();
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
