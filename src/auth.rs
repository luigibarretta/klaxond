use crate::endpoints;
use crate::util::now_epoch_i64;
use axum::body::Body;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use auth_modules::audit::AuthAuditKind;

mod authenticate;
mod local;
mod login;
mod magic_link;
mod payload;
mod rate_limit;
mod session;
mod step_up;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_step_up;
mod tokens;
mod totp_handlers;

pub use authenticate::authenticate;
pub use local::{ldap_login_enabled, local_login, sudo};
pub use login::{login, oidc_callback};
pub use magic_link::{
    magic_link_callback, magic_link_callback_url, magic_link_enabled, magic_link_request,
};
pub use session::{api_logout, issue_session_cookie};
pub(crate) use step_up::{
    StepUpChallenge, finish_totp_step_up, finish_webauthn_step_up, pending_step_up_challenge,
    pending_step_up_user_sub, redirect_location_after_primary,
};
pub use tokens::{public_token, required_scope, scopes_allow, token_hash};
pub use totp_handlers::{totp_disable, totp_enable, totp_start};

pub(in crate::auth) use payload::login_payload;
use rate_limit::{
    auth_rate_key, auth_rate_limited, clear_auth_failures, record_auth_audit_failure,
    record_auth_failure,
};

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
    #[serde(default)]
    pub second_factor: String,
}

pub enum AuthOutcome {
    Authorized(User, Option<String>),
    Rejected(Response<Body>),
}

pub fn is_public(path: &str) -> bool {
    endpoints::is_public(path)
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
