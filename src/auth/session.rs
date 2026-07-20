use super::{AUTH_SESSION_COOKIE, User, json_response};
use crate::config::AuthConfig;
use crate::state::AppState;
use crate::util::{b64url_decode_padded, b64url_no_pad, hmac_hex, now_epoch_i64, token_urlsafe};
use auth_modules::session_policy::{SameSitePolicy, SessionPolicy};
use axum::body::Body;
use axum::http::header::{HOST, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Response};
use constant_time_eq::constant_time_eq;
use serde_json::json;
use std::net::IpAddr;

fn same_site_header(value: SameSitePolicy) -> &'static str {
    match value {
        SameSitePolicy::Lax => "Lax",
        SameSitePolicy::Strict => "Strict",
        SameSitePolicy::None => "None",
    }
}

pub fn api_logout(headers: &HeaderMap) -> Response<Body> {
    let mut resp = json_response(json!({"ok": true}));
    for cookie in expired_session_cookies(headers) {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().append(SET_COOKIE, value);
        }
    }
    resp
}

pub(super) fn issue_session(state: &AppState, cfg: &AuthConfig, user: &mut User) -> String {
    if user.csrf.is_empty() {
        user.csrf = format!("klx_csrf_{}", token_urlsafe(24));
    }
    user.exp = now_epoch_i64() + (cfg.session_timeout_hours * 3600) as i64;
    let payload = serde_json::to_vec(user).unwrap_or_default();
    let body = b64url_no_pad(&payload);
    let sig = hmac_hex(state.session_key.as_slice(), body.as_bytes());
    let val = format!("{body}.{sig}");
    let cookie = SessionPolicy::gold_standard().cookie;
    let http_only = if cookie.http_only { "; HttpOnly" } else { "" };
    format!(
        "{AUTH_SESSION_COOKIE}={val}{}; Path={}; SameSite={}; Max-Age={}",
        http_only,
        cookie.path,
        same_site_header(cookie.same_site),
        cfg.session_timeout_hours * 3600
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

pub fn issue_session_cookie(state: &AppState, user: &mut User) -> String {
    let cfg = state.cfg().auth;
    issue_session(state, &cfg, user)
}

pub(super) fn verify_session(state: &AppState, cookie_value: &str) -> Option<User> {
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
