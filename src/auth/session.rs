use super::{AUTH_SESSION_COOKIE, User};
use crate::state::AppState;
use crate::util::{b64url_decode_padded, hmac_hex, now_epoch_i64};
use auth_modules::secrets::constant_time_eq;
use auth_modules::session_policy::{SameSitePolicy, SessionPolicy};
use axum::body::Body;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderValue, Response};

mod logout;
mod persistent;
mod token;

pub use logout::api_logout;
pub use persistent::issue_session_cookie;
#[cfg(test)]
pub(in crate::auth) use persistent::{issue_session, rotate_session};
pub(in crate::auth) use persistent::{issue_session_on_worker, rotate_session_on_worker};
pub(super) use token::persistent_session_hash;

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

pub(super) fn session_cookie(state: &AppState, token: &str, max_age: u64) -> String {
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

pub(super) fn set_session_cookie(response: &mut Response<Body>, cookie: &str) {
    match HeaderValue::from_str(cookie) {
        Ok(value) => {
            response.headers_mut().insert(SET_COOKIE, value);
        }
        Err(err) => {
            tracing::error!(?err, "failed to build session cookie header");
        }
    }
}

pub(super) async fn verify_session(
    state: &AppState,
    cookie_value: &str,
) -> Result<Option<VerifiedSession>, String> {
    if let Some(id_hash) = persistent_session_hash(cookie_value) {
        return persistent::verify_persistent_session(state, id_hash).await;
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
