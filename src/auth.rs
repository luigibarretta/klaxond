use crate::config::AuthConfig;
use crate::endpoints;
use crate::state::AppState;
use crate::util::{now_epoch_i64, token_urlsafe};
use axum::body::{Body, Bytes};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, COOKIE};
use axum::http::{HeaderMap, Method, Response, StatusCode};
use axum::response::IntoResponse;
use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use url::form_urlencoded;

use auth_modules::audit::AuthAuditKind;

mod local;
mod login;
mod magic_link;
mod rate_limit;
mod session;
#[cfg(test)]
mod tests;
mod tokens;
mod totp_handlers;

pub use local::{ldap_login_enabled, local_login, sudo};
pub use login::{login, oidc_callback};
pub use magic_link::{
    magic_link_callback, magic_link_callback_url, magic_link_enabled, magic_link_request,
};
pub use session::{api_logout, issue_session_cookie};
pub use tokens::{public_token, required_scope, scopes_allow, token_hash};
pub use totp_handlers::{totp_disable, totp_enable, totp_start};

use local::{authenticate_basic, authenticate_ldap_basic, authenticate_trusted_proxy};
use rate_limit::{
    auth_rate_key, auth_rate_limited, clear_auth_failures, record_auth_audit_failure,
    record_auth_failure,
};
use session::{cookie_values, issue_session, set_session_cookie, verify_session};
use tokens::{authenticate_api_token, bearer_token, viewer_allows_scope};

pub const AUTH_SESSION_COOKIE: &str = "klaxond_session";
pub const MIN_PASSWORD_LEN: usize = auth_modules::password::DEFAULT_MIN_PASSWORD_LENGTH;
const SUDO_WINDOW_SECS: i64 = 10 * 60;

pub const TOKEN_SCOPES: &[&str] = &[
    "admin:*",
    "admin:read",
    "viewer:*",
    "status:read",
    "logs:read",
    "audit:read",
    "config:read",
    "config:write",
    "auth:read",
    "auth:write",
    "routing:write",
    "render:write",
    "cascade:write",
    "delivery:write",
    "dedup:write",
    "inhibitions:write",
    "test:write",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub sub: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub mode: String,
    #[serde(default)]
    pub exp: i64,
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub sudo_until: i64,
    #[serde(default, skip_serializing)]
    pub via_authorization: bool,
}

pub enum AuthOutcome {
    Authorized(User, Option<String>),
    Rejected(Response<Body>),
}

pub fn is_public(path: &str) -> bool {
    endpoints::is_public(path)
}

pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    let cfg = state.cfg().auth;
    if cfg.mode == "none" {
        return AuthOutcome::Authorized(
            User {
                sub: "anonymous".into(),
                email: String::new(),
                name: String::new(),
                groups: vec![],
                mode: "none".into(),
                exp: 0,
                csrf: String::new(),
                sudo_until: 0,
                via_authorization: false,
            },
            None,
        );
    }
    if let Some(token) = bearer_token(headers) {
        return authenticate_api_token(state, &token, method, path);
    }
    if let Some(cookie) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        for value in cookie_values(cookie, AUTH_SESSION_COOKIE).into_iter().rev() {
            if let Some(mut user) = verify_session(state, value) {
                let refresh_cookie = ensure_session_security_fields(state, &cfg, &mut user);
                return authorize_interactive_user(user, refresh_cookie, method, path);
            }
        }
    }
    let outcome = match cfg.mode.as_str() {
        "basic" => {
            let outcome = authenticate_basic(state, &cfg, headers);
            match outcome {
                AuthOutcome::Rejected(resp)
                    if resp.status() == StatusCode::UNAUTHORIZED && is_ui_fetch(headers) =>
                {
                    let location =
                        format!("/api/auth/login?return_to={}", urlencoding::encode(path));
                    AuthOutcome::Rejected(auth_required(&location))
                }
                other => other,
            }
        }
        "ldap" => {
            let outcome = authenticate_ldap_basic(state, &cfg, headers).await;
            match outcome {
                AuthOutcome::Rejected(resp)
                    if resp.status() == StatusCode::UNAUTHORIZED && is_ui_fetch(headers) =>
                {
                    let location =
                        format!("/api/auth/login?return_to={}", urlencoding::encode(path));
                    AuthOutcome::Rejected(auth_required(&location))
                }
                other => other,
            }
        }
        "trusted-proxy" => authenticate_trusted_proxy(&cfg, headers, peer),
        "oidc" => {
            let location = format!("/api/auth/login?return_to={}", urlencoding::encode(path));
            if is_ui_fetch(headers) {
                AuthOutcome::Rejected(auth_required(&location))
            } else {
                AuthOutcome::Rejected(redirect(&location))
            }
        }
        _ => AuthOutcome::Rejected(StatusCode::FORBIDDEN.into_response()),
    };
    match outcome {
        AuthOutcome::Authorized(user, cookie) => {
            authorize_interactive_user(user, cookie, method, path)
        }
        rejected => rejected,
    }
}

fn ensure_session_security_fields(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
) -> Option<String> {
    let needs_refresh = user.csrf.is_empty();
    if user.csrf.is_empty() {
        user.csrf = format!("klx_csrf_{}", token_urlsafe(24));
    }
    needs_refresh.then(|| issue_session(state, cfg, user))
}

fn authorize_interactive_user(
    user: User,
    cookie: Option<String>,
    method: &Method,
    path: &str,
) -> AuthOutcome {
    let required = required_scope(method, path);
    if user_has_viewer_role(&user) && !viewer_allows_scope(required) {
        return AuthOutcome::Rejected(
            (
                StatusCode::FORBIDDEN,
                format!("viewer user missing required scope '{required}'"),
            )
                .into_response(),
        );
    }
    AuthOutcome::Authorized(user, cookie)
}

fn user_has_viewer_role(user: &User) -> bool {
    user.groups.iter().any(|group| {
        matches!(
            group.as_str(),
            "viewer" | "klaxond-viewer" | "klaxond:viewer" | "viewer:*"
        )
    })
}

fn is_ui_fetch(headers: &HeaderMap) -> bool {
    headers
        .get("x-klaxond-request")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("fetch"))
}

pub fn csrf_required(_headers: &HeaderMap, path: &str, user: &User) -> bool {
    user.mode != "none" && !user.via_authorization && is_mutation_path(path)
}

pub fn csrf_valid(headers: &HeaderMap, user: &User) -> bool {
    let Some(expected) = (!user.csrf.is_empty()).then_some(user.csrf.as_bytes()) else {
        return false;
    };
    headers
        .get("X-Klaxond-CSRF")
        .or_else(|| headers.get("X-CSRF-Token"))
        .and_then(|v| v.to_str().ok())
        .is_some_and(|actual| constant_time_eq(actual.as_bytes(), expected))
}

pub fn csrf_rejected() -> Response<Body> {
    (StatusCode::FORBIDDEN, "CSRF token missing or invalid").into_response()
}

pub fn sudo_required(_headers: &HeaderMap, path: &str, user: &User) -> bool {
    matches!(
        user.mode.as_str(),
        "basic" | "ldap" | "passkey" | "magic_link"
    ) && !user.via_authorization
        && is_sensitive_mutation_path(path)
}

pub fn sudo_valid(user: &User) -> bool {
    user.sudo_until > now_epoch_i64()
}

pub fn sudo_required_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PRECONDITION_REQUIRED)
        .header("X-Klaxond-Reauth", "required")
        .header("Cache-Control", "no-store")
        .body(Body::from("reauthentication required"))
        .unwrap()
}

pub fn sudo_until_deadline() -> i64 {
    now_epoch_i64() + sudo_window_seconds()
}

fn is_mutation_path(path: &str) -> bool {
    !endpoints::csrf_exempt_mutation(path)
}

fn is_sensitive_mutation_path(path: &str) -> bool {
    endpoints::requires_sudo(path)
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    auth_modules::password::hash_password(password).map_err(|err| anyhow::anyhow!(err))
}

pub fn validate_password_policy(
    password: &str,
    username: Option<&str>,
) -> Result<(), auth_modules::password::PolicyError> {
    auth_modules::password::validate_gold_standard(password, username)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    auth_modules::password::verify_password(password, hash)
}

fn json_response(value: Value) -> Response<Body> {
    let body = serde_json::to_vec_pretty(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap()
}

fn login_payload(body: &Bytes) -> HashMap<String, String> {
    let raw = std::str::from_utf8(body).unwrap_or("");
    if body_is_json(body) {
        return serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .map(|obj| {
                obj.into_iter()
                    .map(|(key, value)| {
                        let value = value
                            .as_str()
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| value.to_string());
                        (key, value)
                    })
                    .collect()
            })
            .unwrap_or_default();
    }
    form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect()
}

fn body_is_json(body: &Bytes) -> bool {
    std::str::from_utf8(body)
        .map(|s| s.trim_start().starts_with('{'))
        .unwrap_or(false)
}

fn sudo_window_seconds() -> i64 {
    SUDO_WINDOW_SECS
}

fn redirect(location: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Body::empty())
        .unwrap()
}

fn auth_required(location: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("X-Klaxond-Login", location)
        .header("Cache-Control", "no-store")
        .body(Body::empty())
        .unwrap()
}
