use crate::config::{AuthConfig, AuthToken, save_auth};
use crate::endpoints;
use crate::state::{AppState, PendingMagicLink, PendingOidcState, lock_mutex};
use crate::totp;
use crate::util::{b64url_decode_padded, b64url_no_pad, hmac_hex, now_epoch_i64, token_urlsafe};
use axum::body::{Body, Bytes};
use axum::http::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, SET_COOKIE, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use axum::response::IntoResponse;
use constant_time_eq::constant_time_eq;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use url::{Url, form_urlencoded};

use auth_modules::oidc::{OidcClientConfig, async_client as oidc_client};
use auth_modules::rate_limit::{
    GOLD_AUTH_ACCOUNT_FAILURE_MAX, GOLD_AUTH_ACCOUNT_FAILURE_WINDOW, GOLD_AUTH_SHORT_BURST_MAX,
    GOLD_AUTH_SHORT_BURST_WINDOW,
};

pub const AUTH_SESSION_COOKIE: &str = "klaxond_session";
pub const MIN_PASSWORD_LEN: usize = auth_modules::password::DEFAULT_MIN_PASSWORD_LENGTH;
const SUDO_WINDOW_SECS: i64 = 10 * 60;
const MAGIC_LINK_TTL_SECS: i64 = 10 * 60;

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

const TOKEN_LAST_USED_PERSIST_INTERVAL_SECS: i64 = 60;

fn authenticate_api_token(
    state: &AppState,
    token: &str,
    method: &Method,
    path: &str,
) -> AuthOutcome {
    let cfg = state.cfg().auth;
    let hash = token_hash(token);
    let now = now_epoch_i64();
    let Some(record) = cfg.api_keys.iter().find(|record| {
        record.enabled
            && record
                .expires_at
                .map(|expires_at| expires_at > now)
                .unwrap_or(true)
            && constant_time_eq(record.token_hash.as_bytes(), hash.as_bytes())
    }) else {
        return AuthOutcome::Rejected(
            (StatusCode::UNAUTHORIZED, "invalid bearer token").into_response(),
        );
    };
    let required = required_scope(method, path);
    if !has_scope(&record.scopes, required) {
        return AuthOutcome::Rejected(
            (
                StatusCode::FORBIDDEN,
                format!("token missing required scope '{required}'"),
            )
                .into_response(),
        );
    }
    let record = record.clone();
    let should_persist_last_used = record
        .last_used_at
        .map(|last| now.saturating_sub(last) >= TOKEN_LAST_USED_PERSIST_INTERVAL_SECS)
        .unwrap_or(true);
    if should_persist_last_used {
        let record_id = record.id.clone();
        if let Err(err) = state.with_config_write_lock(|| {
            let mut cfg = state.cfg();
            if let Some(stored) = cfg
                .auth
                .api_keys
                .iter_mut()
                .find(|stored| stored.id == record_id && stored.token_hash == hash)
            {
                let still_due = stored
                    .last_used_at
                    .map(|last| now.saturating_sub(last) >= TOKEN_LAST_USED_PERSIST_INTERVAL_SECS)
                    .unwrap_or(true);
                if !still_due {
                    return;
                }
                stored.last_used_at = Some(now);
                if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                    tracing::warn!("failed to persist auth token last_used_at: {err}");
                    return;
                }
                state.replace_config_preserving_runtime(cfg);
            }
        }) {
            tracing::warn!("failed to update auth token last_used_at: {err}");
        }
    }

    AuthOutcome::Authorized(
        User {
            sub: format!("token:{}", record.name),
            email: String::new(),
            name: record.name.clone(),
            groups: record.scopes.clone(),
            mode: record.kind.clone(),
            exp: record.expires_at.unwrap_or(0),
            csrf: String::new(),
            sudo_until: 0,
            via_authorization: true,
        },
        None,
    )
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn public_token(record: &AuthToken) -> Value {
    serde_json::json!({
        "id": record.id,
        "name": record.name,
        "kind": record.kind,
        "prefix": record.prefix,
        "scopes": record.scopes,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "last_used_at": record.last_used_at,
        "enabled": record.enabled,
    })
}

pub fn required_scope(method: &Method, path: &str) -> &'static str {
    endpoints::required_scope(method, path)
}

fn has_scope(scopes: &[String], required: &str) -> bool {
    scopes.iter().any(|scope| {
        let scope = scope.as_str();
        scope == "admin:*"
            || scope == required
            || (scope == "admin:read" && required.ends_with(":read"))
            || (scope == "viewer:*" && viewer_allows_scope(required))
            || scope
                .strip_suffix(":*")
                .zip(required.split_once(':'))
                .map(|(prefix, (group, _))| prefix == group)
                .unwrap_or(false)
    })
}

pub fn scopes_allow(scopes: &[String], required: &str) -> bool {
    has_scope(scopes, required)
}

fn viewer_allows_scope(required: &str) -> bool {
    matches!(required, "status:read" | "logs:read" | "audit:read")
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

fn authenticate_basic(state: &AppState, cfg: &AuthConfig, headers: &HeaderMap) -> AuthOutcome {
    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(raw) = auth.strip_prefix("Basic ")
        && let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw)
        && let Ok(s) = String::from_utf8(decoded)
        && let Some((user, pwd)) = s.split_once(':')
        && cfg.basic.username == user
        && !cfg.basic.password_hash.is_empty()
        && verify_password(pwd, &cfg.basic.password_hash)
        && (!cfg.basic.totp_enabled
            || headers
                .get("X-Klaxond-TOTP")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|code| {
                    totp::verify_code(&cfg.basic.totp_secret, code, now_epoch_i64())
                }))
    {
        let mut u = User {
            sub: user.to_string(),
            email: String::new(),
            name: String::new(),
            groups: vec![],
            mode: "basic".into(),
            exp: 0,
            csrf: String::new(),
            sudo_until: now_epoch_i64() + sudo_window_seconds(),
            via_authorization: false,
        };
        let cookie = issue_session(state, cfg, &mut u);
        return AuthOutcome::Authorized(u, Some(cookie));
    }
    let mut resp = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::empty())
        .unwrap();
    resp.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&format!("Basic realm=\"{}\"", cfg.basic.realm)).unwrap(),
    );
    AuthOutcome::Rejected(resp)
}

async fn authenticate_ldap_basic(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
) -> AuthOutcome {
    let Some((username, password)) = basic_credentials(headers) else {
        return AuthOutcome::Rejected(basic_challenge("klaxond ldap"));
    };
    let rate_key = auth_rate_key("ldap", &username);
    if auth_rate_limited(state, &rate_key) {
        record_auth_failure(state, &rate_key, "auth.ldap", "rate_limited");
        return AuthOutcome::Rejected(
            (
                StatusCode::TOO_MANY_REQUESTS,
                "too many authentication failures",
            )
                .into_response(),
        );
    }
    let identity = match authenticate_ldap_credentials(cfg, &username, &password).await {
        Ok(identity) => identity,
        Err(err) => {
            tracing::warn!(?err, "LDAP Basic authentication failed");
            record_auth_failure(state, &rate_key, "auth.ldap", "ldap authentication failed");
            return AuthOutcome::Rejected(basic_challenge("klaxond ldap"));
        }
    };
    clear_auth_failures(state, &rate_key);
    let mut user = ldap_user(identity);
    user.sudo_until = now_epoch_i64() + sudo_window_seconds();
    let cookie = issue_session(state, cfg, &mut user);
    AuthOutcome::Authorized(user, Some(cookie))
}

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())?;
    let raw = auth.strip_prefix("Basic ")?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

fn basic_challenge(realm: &str) -> Response<Body> {
    let mut resp = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::empty())
        .unwrap();
    resp.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&format!("Basic realm=\"{realm}\"")).unwrap(),
    );
    resp
}

fn authenticate_trusted_proxy(
    cfg: &AuthConfig,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    let peer_ip = peer.map(|p| p.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
    if !cidr_match(peer_ip, &cfg.trusted_proxy.trusted_cidrs) {
        return AuthOutcome::Rejected(
            (StatusCode::FORBIDDEN, "untrusted peer (trusted-proxy mode)").into_response(),
        );
    }
    let uh = &cfg.trusted_proxy.user_header;
    let Some(user_val) = header_by_name(headers, uh) else {
        return AuthOutcome::Rejected(
            (StatusCode::UNAUTHORIZED, format!("missing {uh} header")).into_response(),
        );
    };
    AuthOutcome::Authorized(
        User {
            sub: user_val,
            email: header_by_name(headers, &cfg.trusted_proxy.email_header).unwrap_or_default(),
            groups: header_by_name(headers, &cfg.trusted_proxy.groups_header)
                .unwrap_or_default()
                .split(',')
                .map(|s| s.to_string())
                .collect(),
            name: String::new(),
            mode: "trusted-proxy".into(),
            exp: 0,
            csrf: String::new(),
            sudo_until: 0,
            via_authorization: false,
        },
        None,
    )
}

pub async fn login(state: &AppState, headers: HeaderMap, uri: &str) -> Response<Body> {
    let return_to = login_return_to(uri);
    let logged_out = Url::parse(&format!("http://localhost{uri}"))
        .ok()
        .is_some_and(|u| u.query_pairs().any(|(k, _)| k == "logged_out"));
    let start = Url::parse(&format!("http://localhost{uri}"))
        .ok()
        .is_some_and(|u| {
            u.query_pairs()
                .any(|(k, v)| (k == "start" || k == "oidc") && v != "0")
        });
    let auth = state.cfg().auth;
    if auth.mode == "none" {
        return redirect(&return_to);
    }
    if !logged_out && let Some(cookie) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        for value in cookie_values(cookie, AUTH_SESSION_COOKIE).into_iter().rev() {
            if verify_session(state, value).is_some() {
                return redirect(&return_to);
            }
        }
    }
    if start && auth.mode == "oidc" {
        return oidc_login_redirect(state, headers, uri).await;
    }
    login_page(
        &auth.mode,
        auth.webauthn.enabled,
        magic_link_enabled(&auth),
        &return_to,
    )
}

pub fn magic_link_enabled(cfg: &AuthConfig) -> bool {
    cfg.mode == "basic"
        && !cfg.basic.username.trim().is_empty()
        && !cfg.basic.password_hash.trim().is_empty()
}

pub fn ldap_login_enabled(cfg: &AuthConfig) -> bool {
    cfg.mode == "ldap" && cfg.ldap.to_auth_modules_config().is_some()
}

pub async fn local_login(state: &AppState, body: Bytes) -> Response<Body> {
    let cfg = state.cfg().auth;
    if !matches!(cfg.mode.as_str(), "basic" | "ldap") {
        return (
            StatusCode::BAD_REQUEST,
            "local login is available only in basic or ldap mode",
        )
            .into_response();
    }
    let payload = login_payload(&body);
    let username = payload
        .get("username")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    let password = payload.get("password").map(String::as_str).unwrap_or("");
    let code = payload.get("totp").map(String::as_str).unwrap_or("");
    let rate_key = auth_rate_key("login", username);
    if auth_rate_limited(state, &rate_key) {
        record_auth_failure(state, &rate_key, "auth.login", "rate_limited");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many authentication failures",
        )
            .into_response();
    }
    let return_to = sanitize_return_to(
        payload
            .get("return_to")
            .map(String::as_str)
            .unwrap_or("/status"),
    );
    let mut user = if cfg.mode == "ldap" {
        match authenticate_ldap_credentials(&cfg, username, password).await {
            Ok(identity) => ldap_user(identity),
            Err(err) => {
                tracing::warn!(?err, "LDAP login failed");
                record_auth_failure(state, &rate_key, "auth.ldap", "ldap authentication failed");
                return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response();
            }
        }
    } else {
        if username != cfg.basic.username
            || cfg.basic.password_hash.is_empty()
            || !verify_password(password, &cfg.basic.password_hash)
        {
            record_auth_failure(
                state,
                &rate_key,
                "auth.login",
                "invalid username or password",
            );
            return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response();
        }
        if cfg.basic.totp_enabled
            && !totp::verify_code(&cfg.basic.totp_secret, code, now_epoch_i64())
        {
            record_auth_failure(state, &rate_key, "auth.login", "invalid TOTP code");
            return (StatusCode::UNAUTHORIZED, "TOTP code required or invalid").into_response();
        }
        User {
            sub: username.to_string(),
            email: String::new(),
            name: String::new(),
            groups: vec![],
            mode: "basic".into(),
            exp: 0,
            csrf: String::new(),
            sudo_until: 0,
            via_authorization: false,
        }
    };
    clear_auth_failures(state, &rate_key);
    let cookie = issue_session(state, &cfg, &mut user);
    let mut resp = if payload
        .get("fetch")
        .map(|v| v == "1")
        .unwrap_or_else(|| body_is_json(&body))
    {
        json_response(json!({"ok": true, "return_to": return_to, "csrf": user.csrf}))
    } else {
        redirect(&return_to)
    };
    resp.headers_mut()
        .insert(SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

pub fn sudo(state: &AppState, body: Bytes, user: Option<&User>) -> Response<Body> {
    let Some(user) = user else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    if !matches!(user.mode.as_str(), "basic" | "ldap" | "magic_link") {
        return (
            StatusCode::BAD_REQUEST,
            "sudo reauth is available only for local or LDAP login",
        )
            .into_response();
    }
    let cfg = state.cfg().auth;
    let payload = login_payload(&body);
    let password = payload.get("password").map(String::as_str).unwrap_or("");
    let code = payload.get("totp").map(String::as_str).unwrap_or("");
    let rate_key = auth_rate_key("sudo", &user.sub);
    if auth_rate_limited(state, &rate_key) {
        record_auth_failure(state, &rate_key, "auth.sudo", "rate_limited");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many authentication failures",
        )
            .into_response();
    }
    if user.mode == "ldap" {
        let cfg_for_ldap = cfg.clone();
        let username = user.sub.clone();
        let password = password.to_string();
        let result = tokio::task::block_in_place(|| {
            cfg_for_ldap
                .ldap
                .to_auth_modules_config()
                .ok_or_else(|| "LDAP is not configured".to_string())?
                .authenticate(&username, &password)
                .map_err(|err| err.to_string())
        });
        if let Err(err) = result {
            tracing::warn!(?err, "LDAP sudo reauth failed");
            record_auth_failure(state, &rate_key, "auth.sudo", "ldap reauth failed");
            return (StatusCode::UNAUTHORIZED, "invalid password").into_response();
        }
    } else {
        if cfg.basic.password_hash.is_empty()
            || !verify_password(password, &cfg.basic.password_hash)
        {
            record_auth_failure(state, &rate_key, "auth.sudo", "invalid password");
            return (StatusCode::UNAUTHORIZED, "invalid password").into_response();
        }
        if cfg.basic.totp_enabled
            && !totp::verify_code(&cfg.basic.totp_secret, code, now_epoch_i64())
        {
            record_auth_failure(state, &rate_key, "auth.sudo", "invalid TOTP code");
            return (StatusCode::UNAUTHORIZED, "TOTP code required or invalid").into_response();
        }
    }
    clear_auth_failures(state, &rate_key);
    let mut refreshed = user.clone();
    refreshed.sudo_until = now_epoch_i64() + sudo_window_seconds();
    let cookie = issue_session(state, &cfg, &mut refreshed);
    let mut resp = json_response(
        json!({"ok": true, "sudo_until": refreshed.sudo_until, "csrf": refreshed.csrf}),
    );
    resp.headers_mut()
        .insert(SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

async fn authenticate_ldap_credentials(
    cfg: &AuthConfig,
    username: &str,
    password: &str,
) -> Result<auth_modules::ldap::LdapIdentity, String> {
    let ldap = cfg
        .ldap
        .to_auth_modules_config()
        .ok_or_else(|| "LDAP is not configured".to_string())?;
    let username = username.to_string();
    let password = password.to_string();
    tokio::task::spawn_blocking(move || {
        ldap.authenticate(&username, &password)
            .map_err(|err| err.to_string())
    })
    .await
    .map_err(|err| format!("LDAP worker failed: {err}"))?
}

fn ldap_user(identity: auth_modules::ldap::LdapIdentity) -> User {
    User {
        sub: identity.username,
        email: identity.email.unwrap_or_default(),
        name: identity.name,
        groups: identity.groups,
        mode: "ldap".into(),
        exp: 0,
        csrf: String::new(),
        sudo_until: 0,
        via_authorization: false,
    }
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
    let username = payload
        .get("username")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    if username.is_empty() {
        return (StatusCode::BAD_REQUEST, "username is required").into_response();
    }
    let return_to = sanitize_return_to(
        payload
            .get("return_to")
            .map(String::as_str)
            .unwrap_or("/status"),
    );
    let rate_key = magic_link_rate_key(username, headers, peer);
    let decision = state.auth_failures.record_attempt(
        &rate_key,
        GOLD_AUTH_SHORT_BURST_MAX,
        GOLD_AUTH_SHORT_BURST_WINDOW,
    );
    if !decision.allowed {
        crate::audit::record(
            rate_key,
            "auth.magic_link",
            "error",
            "rate_limited".to_string(),
        );
        return rate_limited_retry_after(decision.retry_after);
    }

    let token = issue_magic_link(state, &cfg.auth, username, &return_to);
    let link = token
        .as_deref()
        .map(|token| magic_link_callback_url(&cfg.public_url, token));
    let wants_json = payload
        .get("fetch")
        .map(|value| value == "1")
        .unwrap_or_else(|| body_is_json(&body));
    if wants_json {
        return json_response(json!({
            "sent": true,
            "link": link,
            "expiresInSeconds": MAGIC_LINK_TTL_SECS,
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
    let cookie = issue_session(state, &cfg, &mut user);
    let mut resp = redirect(&return_to);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, value);
    }
    resp
}

fn issue_magic_link(
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
    let token = token_urlsafe(32);
    let now = crate::util::now_epoch();
    let mut pending = lock_mutex(&state.magic_links, "magic links");
    prune_magic_links(&mut pending, now);
    pending.insert(
        token_hash(&token),
        PendingMagicLink {
            created_at: now,
            expires_at: now + MAGIC_LINK_TTL_SECS as f64,
            username: username.to_string(),
            return_to: return_to.to_string(),
            used_at: None,
        },
    );
    Some(token)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MagicLinkError {
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

fn consume_magic_link(
    state: &AppState,
    cfg: &AuthConfig,
    token: &str,
) -> Result<(User, String), MagicLinkError> {
    let token_hash = token_hash(token);
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
        },
        challenge.return_to,
    ))
}

fn prune_magic_links(pending: &mut HashMap<String, PendingMagicLink>, now: f64) {
    pending.retain(|_, challenge| challenge.expires_at > now);
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

pub fn totp_start(state: &AppState) -> Response<Body> {
    let cfg = state.cfg().auth;
    let secret = totp::generate_secret();
    let label = if cfg.basic.username.trim().is_empty() {
        "klaxond".to_string()
    } else {
        format!("klaxond:{}", cfg.basic.username)
    };
    let otpauth_uri = totp::otpauth_uri(&label, "klaxond", &secret);
    json_response(json!({"ok": true, "secret": secret, "otpauth_uri": otpauth_uri}))
}

pub fn totp_enable(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = login_payload(&body);
    let secret = payload
        .get("secret")
        .map(String::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();
    let code = payload.get("code").map(String::as_str).unwrap_or("").trim();
    if !totp::is_valid_secret(&secret) {
        return (StatusCode::BAD_REQUEST, "invalid TOTP secret").into_response();
    }
    if !totp::verify_code(&secret, code, now_epoch_i64()) {
        return (StatusCode::BAD_REQUEST, "invalid TOTP code").into_response();
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            cfg.auth.basic.totp_enabled = true;
            cfg.auth.basic.totp_secret = secret.clone();
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true, "enabled": true}))
        })
        .unwrap_or_else(|err| (StatusCode::INTERNAL_SERVER_ERROR, err).into_response())
}

pub fn totp_disable(state: &AppState) -> Response<Body> {
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            cfg.auth.basic.totp_enabled = false;
            cfg.auth.basic.totp_secret.clear();
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true, "enabled": false}))
        })
        .unwrap_or_else(|err| (StatusCode::INTERNAL_SERVER_ERROR, err).into_response())
}

async fn oidc_login_redirect(state: &AppState, headers: HeaderMap, uri: &str) -> Response<Body> {
    let cfg = state.cfg().auth.oidc;
    let issuer = cfg.issuer.trim_end_matches('/').to_string();
    if issuer.is_empty() || cfg.client_id.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "OIDC not configured (set issuer + client_id in Auth tab)",
        )
            .into_response();
    }
    let return_to = login_return_to(uri);
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let scheme = if headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https")
        == "https"
    {
        "https"
    } else {
        "http"
    };
    let redirect_uri = format!("{scheme}://{host}{}", cfg.redirect_path);
    let state_token = token_urlsafe(24);
    let flow = match oidc_client::authorization_url(
        &oidc_client_config(&cfg, &redirect_uri),
        &state_token,
    )
    .await
    {
        Ok(flow) => flow,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("OIDC discovery failed: {err}"),
            )
                .into_response();
        }
    };
    {
        let mut states = lock_mutex(&state.oidc_states, "oidc states");
        let now = crate::util::now_epoch();
        states.insert(
            state_token.clone(),
            PendingOidcState {
                created_at: now,
                return_to,
                nonce: flow.nonce,
                code_verifier: flow.pkce_verifier,
            },
        );
        let cutoff = now - 600.0;
        states.retain(|_, pending| pending.created_at >= cutoff);
    }
    redirect(&flow.authorization_url)
}

fn login_return_to(uri: &str) -> String {
    let return_to = Url::parse(&format!("http://localhost{uri}"))
        .ok()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "return_to")
                .map(|(_, v)| v.to_string())
        })
        .unwrap_or_else(|| "/status".into());
    sanitize_return_to(&return_to)
}

fn login_page(
    mode: &str,
    passkeys_enabled: bool,
    magic_link_enabled: bool,
    return_to: &str,
) -> Response<Body> {
    let start_url = format!(
        "/api/auth/login?start=1&return_to={}",
        urlencoding::encode(return_to)
    );
    let start_url = html_attr(&start_url);
    let return_to = html_attr(return_to);
    let primary = match mode {
        "oidc" => format!(r#"<a class="btn primary" href="{start_url}">Continue with SSO</a>"#),
        "basic" => format!(
            r#"<form class="login-form" method="post" action="/api/auth/local/login">
<input type="hidden" name="return_to" value="{return_to}">
<label><span>Username</span><input name="username" autocomplete="username" required></label>
<label><span>Password</span><input name="password" type="password" autocomplete="current-password" required></label>
<label><span>TOTP code</span><input name="totp" inputmode="numeric" pattern="[0-9]{{6}}" autocomplete="one-time-code" placeholder="000000"></label>
<button class="btn primary" type="submit">Sign in</button>
</form>"#
        ),
        "trusted-proxy" => {
            format!(
                r#"<a class="btn primary" href="{return_to}">Continue through trusted proxy</a>"#
            )
        }
        _ => format!(r#"<a class="btn primary" href="{return_to}">Continue</a>"#),
    };
    let passkey = if passkeys_enabled {
        r#"<a class="btn" href="/api/auth/passkey/login">Use passkey</a>"#
    } else {
        ""
    };
    let magic_link = if magic_link_enabled {
        format!(
            r#"<form class="login-form" method="post" action="/api/auth/magic/request">
<input type="hidden" name="return_to" value="{return_to}">
<label><span>Username</span><input name="username" autocomplete="username" required></label>
<button class="btn" type="submit">Use magic link</button>
</form>"#
        )
    } else {
        String::new()
    };
    let author_link = author_link_html();
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>klaxond login</title><link rel="stylesheet" href="/ui/style.css"></head>
<body><main class="auth-login"><section class="card auth-login-card">
<div class="login-brand">
<img class="login-logo" src="/ui/favicon.svg" alt="" aria-hidden="true">
<div class="login-brand-text"><h1>klaxond</h1><span>notification daemon</span></div>
<span class="login-version">v{version}</span>
</div>
<h2>Sign in</h2>
<p class="login-note">You are signed out locally. If your SSO session is still active, continuing may sign you back in without asking for credentials.</p>
<div class="login-actions">{primary}{passkey}{magic_link}</div>
<nav class="login-legal" aria-label="Legal links">
<a href="/legal/privacy?from=login">Privacy</a>
<a href="/legal/accessibility?from=login">Accessibility</a>
<a href="/legal/terms?from=login">Terms</a>
<a href="/legal/cookies?from=login">Cookies</a>
<a href="/legal/notice?from=login">Legal notice</a>
</nav>
<p class="muted login-byline">by {author_link}</p>
</section></main></body></html>"#,
        version = crate::config::VERSION
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("Cache-Control", "no-store")
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

fn author_link_html() -> String {
    format!(
        r#"<a href="{}" target="_blank" rel="noopener">{}</a>"#,
        html_attr(crate::config::AUTHOR_URL),
        html_attr(crate::config::AUTHOR_NAME)
    )
}

fn html_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

fn auth_rate_key(action: &str, subject: &str) -> String {
    let subject = subject.trim().to_ascii_lowercase();
    format!(
        "{action}:{}",
        if subject.is_empty() {
            "unknown"
        } else {
            subject.as_str()
        }
    )
}

fn auth_rate_limited(state: &AppState, key: &str) -> bool {
    state
        .auth_failures
        .blocked(key, GOLD_AUTH_ACCOUNT_FAILURE_MAX, auth_failure_window())
}

fn record_auth_failure(state: &AppState, key: &str, action: &'static str, detail: &'static str) {
    state.auth_failures.record(key, auth_failure_window());
    crate::audit::record(key.to_string(), action, "error", detail.to_string());
}

fn clear_auth_failures(state: &AppState, key: &str) {
    state.auth_failures.clear(key);
}

fn auth_failure_window() -> std::time::Duration {
    GOLD_AUTH_ACCOUNT_FAILURE_WINDOW
}

fn sudo_window_seconds() -> i64 {
    SUDO_WINDOW_SECS
}

pub async fn oidc_callback(state: &AppState, headers: HeaderMap, uri: &str) -> Response<Body> {
    let cfg = state.cfg().auth.oidc;
    let parsed = Url::parse(&format!("http://localhost{uri}")).unwrap();
    let code = parsed
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string());
    let state_param = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string());
    let (Some(code), Some(state_param)) = (code, state_param) else {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };
    let pending = {
        let mut states = lock_mutex(&state.oidc_states, "oidc states");
        match states.remove(&state_param) {
            Some(pending) => pending,
            None => return redirect("/"),
        }
    };
    let return_to = sanitize_return_to(&pending.return_to);
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let scheme = if headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https")
        == "https"
    {
        "https"
    } else {
        "http"
    };
    let redirect_uri = format!("{scheme}://{host}{}", cfg.redirect_path);
    let identity = match oidc_client::exchange_code(
        &oidc_client_config(&cfg, &redirect_uri),
        &code,
        &pending.nonce,
        &pending.code_verifier,
    )
    .await
    {
        Ok(identity) => identity,
        Err(err) => {
            return (
                StatusCode::UNAUTHORIZED,
                format!("id_token verify failed: {err}"),
            )
                .into_response();
        }
    };
    if !cfg.required_group.trim().is_empty() {
        if !identity
            .groups
            .iter()
            .any(|group| group == cfg.required_group.as_str())
        {
            return (
                StatusCode::FORBIDDEN,
                format!("required_group '{}' not in user claims", cfg.required_group),
            )
                .into_response();
        }
    }
    let mut user = User {
        sub: identity.subject,
        email: identity.email.unwrap_or_default(),
        name: if identity.name.trim().is_empty() {
            identity.username
        } else {
            identity.name
        },
        groups: identity.groups,
        mode: "oidc".into(),
        exp: 0,
        csrf: String::new(),
        sudo_until: 0,
        via_authorization: false,
    };
    let cfg_all = state.cfg().auth;
    let cookie = issue_session(state, &cfg_all, &mut user);
    let mut resp = redirect(if return_to.is_empty() {
        "/"
    } else {
        &return_to
    });
    resp.headers_mut()
        .insert(SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
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

fn issue_session(state: &AppState, cfg: &AuthConfig, user: &mut User) -> String {
    if user.csrf.is_empty() {
        user.csrf = format!("klx_csrf_{}", token_urlsafe(24));
    }
    user.exp = now_epoch_i64() + (cfg.session_timeout_hours * 3600) as i64;
    let payload = serde_json::to_vec(user).unwrap_or_default();
    let body = b64url_no_pad(&payload);
    let sig = hmac_hex(state.session_key.as_slice(), body.as_bytes());
    let val = format!("{body}.{sig}");
    format!(
        "{AUTH_SESSION_COOKIE}={val}; HttpOnly; Path=/; SameSite=Lax; Max-Age={}",
        cfg.session_timeout_hours * 3600
    )
}

pub fn issue_session_cookie(state: &AppState, user: &mut User) -> String {
    let cfg = state.cfg().auth;
    issue_session(state, &cfg, user)
}

fn verify_session(state: &AppState, cookie_value: &str) -> Option<User> {
    let (body, sig) = cookie_value.split_once('.')?;
    let expected = hmac_hex(state.session_key.as_slice(), body.as_bytes());
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return None;
    }
    let bytes = b64url_decode_padded(body).ok()?;
    let user: User = serde_json::from_slice(&bytes).ok()?;
    if user.exp > 0 && user.exp < now_epoch_i64() {
        return None;
    }
    Some(user)
}

fn cookie_values<'a>(cookie: &'a str, name: &str) -> Vec<&'a str> {
    cookie
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then_some(value)
        })
        .collect()
}

fn sanitize_return_to(value: &str) -> String {
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

fn cidr_match(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}

fn header_by_name(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
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

fn oidc_client_config(cfg: &crate::config::OidcConfig, redirect_uri: &str) -> OidcClientConfig {
    OidcClientConfig::new(
        cfg.issuer.trim_end_matches('/').to_string(),
        cfg.client_id.clone(),
        Some(cfg.client_secret.clone()),
        redirect_uri.to_string(),
        cfg.scopes
            .split_whitespace()
            .filter(|scope| !scope.trim().is_empty())
            .map(str::to_string)
            .collect(),
    )
    .with_userinfo(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn temp_paths(tmp: &TempDir) -> Paths {
        let data = tmp.path();
        Paths {
            config: data.join("klaxond.toml"),
            default_config: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("klaxond.default.toml"),
            render_config: data.join("render-config.json"),
            ntfy_topics: data.join("ntfy-topics.json"),
            dedup_config: data.join("dedup-config.json"),
            dedup_pending_dir: data.join("dedup_pending"),
            auth_config: data.join("auth-config.json"),
            auth_session_key: data.join("auth-session.key"),
            backup_dir: data.join("backups"),
            static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
            beszel_db: data.join("missing-beszel.db"),
            history_db: data.join("klaxond.db"),
        }
    }

    #[test]
    fn password_helpers_use_shared_argon2_contract() {
        let hash = hash_password("correct horse battery staple").unwrap();

        assert_eq!(
            MIN_PASSWORD_LEN,
            auth_modules::password::DEFAULT_MIN_PASSWORD_LENGTH
        );
        assert!(hash.starts_with("$argon2id$"));
        assert!(validate_password_policy("Unique passphrase 123", Some("luigi")).is_ok());
        assert!(validate_password_policy("welcome12345", Some("luigi")).is_err());
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn cookie_values_keeps_duplicate_session_cookies_in_order() {
        let values = cookie_values(
            "klaxond_session=stale; theme=dark; klaxond_session=fresh",
            AUTH_SESSION_COOKIE,
        );

        assert_eq!(values, vec!["stale", "fresh"]);
    }

    #[test]
    fn sanitize_return_to_allows_only_local_non_auth_paths() {
        assert_eq!(sanitize_return_to("/inhibitions"), "/inhibitions");
        assert_eq!(sanitize_return_to("/authentication"), "/authentication");
        assert_eq!(sanitize_return_to("https://example.test/"), "/");
        assert_eq!(sanitize_return_to("//example.test/"), "/");
        assert_eq!(sanitize_return_to("/ui\r\nLocation: //example.test"), "/");
        assert_eq!(sanitize_return_to("/api/auth/login?return_to=%2F"), "/");
        assert_eq!(sanitize_return_to("/api/auth"), "/");
        assert_eq!(sanitize_return_to("/api/auth/callback"), "/");
        assert_eq!(sanitize_return_to(""), "/");
    }

    #[test]
    fn magic_link_issue_and_consume_is_single_use() {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let state = AppState::new(temp_paths(&tmp)).unwrap();
        let mut runtime = state.cfg();
        runtime.public_url = "https://klaxond.example.test".to_string();
        runtime.auth.mode = "basic".to_string();
        runtime.auth.basic.username = "luigi".to_string();
        runtime.auth.basic.password_hash = hash_password("correct horse battery staple").unwrap();
        state.replace_config(runtime.clone());

        assert!(magic_link_enabled(&runtime.auth));
        assert!(issue_magic_link(&state, &runtime.auth, "nobody", "/status").is_none());

        let token = issue_magic_link(&state, &runtime.auth, "luigi", "/status").expect("token");
        assert_eq!(
            magic_link_callback_url(&runtime.public_url, &token),
            format!("https://klaxond.example.test/api/auth/magic/callback/{token}")
        );
        {
            let pending = lock_mutex(&state.magic_links, "magic links");
            let stored = pending
                .get(&token_hash(&token))
                .expect("stored token hash only");
            assert_eq!(stored.username, "luigi");
            assert!(stored.created_at <= stored.expires_at);
        }

        let (user, return_to) =
            consume_magic_link(&state, &runtime.auth, &token).expect("consume token");
        assert_eq!(user.sub, "luigi");
        assert_eq!(user.mode, "magic_link");
        assert_eq!(return_to, "/status");
        assert!(matches!(
            consume_magic_link(&state, &runtime.auth, &token),
            Err(MagicLinkError::Used)
        ));

        let expired = "expired-token";
        {
            let mut pending = lock_mutex(&state.magic_links, "magic links");
            let now = crate::util::now_epoch();
            pending.insert(
                token_hash(expired),
                PendingMagicLink {
                    created_at: now - MAGIC_LINK_TTL_SECS as f64,
                    expires_at: now - 1.0,
                    username: "luigi".to_string(),
                    return_to: "/status".to_string(),
                    used_at: None,
                },
            );
        }
        assert!(matches!(
            consume_magic_link(&state, &runtime.auth, expired),
            Err(MagicLinkError::Expired)
        ));
    }

    #[test]
    fn legal_ui_pages_and_assets_are_public_but_admin_routes_are_not() {
        assert!(is_public("/legal/privacy"));
        assert!(is_public("/legal/accessibility"));
        assert!(is_public("/legal/terms"));
        assert!(is_public("/legal/cookies"));
        assert!(is_public("/legal/notice"));
        assert!(is_public("/ui/privacy"));
        assert!(is_public("/ui/accessibility"));
        assert!(is_public("/ui/style.css"));
        assert!(is_public("/ui/meta.js"));
        assert!(is_public("/ui/app.js"));
        assert!(is_public("/"));
        assert!(is_public("/ui"));
        assert!(is_public("/ui/deliveries"));
        assert!(is_public("/ui/auth"));
        assert!(!is_public("/status"));
        assert!(!is_public("/authentication"));
    }

    #[test]
    fn client_log_remains_csrf_exempt_for_interactive_sessions() {
        let headers = HeaderMap::new();
        let mut user = test_user("basic");

        assert!(!csrf_required(&headers, "/api/client-log", &user));
        assert!(csrf_required(&headers, "/api/cascade/toggle", &user));

        user.via_authorization = true;
        assert!(!csrf_required(&headers, "/api/cascade/toggle", &user));
    }

    #[test]
    fn ui_fetch_auth_required_is_machine_readable() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Klaxond-Request", HeaderValue::from_static("fetch"));
        assert!(is_ui_fetch(&headers));

        let resp = auth_required("/api/auth/login?return_to=%2Fstatus");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get("X-Klaxond-Login")
                .and_then(|v| v.to_str().ok()),
            Some("/api/auth/login?return_to=%2Fstatus")
        );
        assert_eq!(
            resp.headers()
                .get("Cache-Control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }

    fn test_user(mode: &str) -> User {
        User {
            sub: "test-user".into(),
            email: String::new(),
            name: String::new(),
            groups: vec![],
            mode: mode.into(),
            exp: 0,
            csrf: "csrf-token".into(),
            sudo_until: 0,
            via_authorization: false,
        }
    }

    #[test]
    fn logout_clears_host_and_parent_domain_cookie_variants() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("klaxond.example.com"));
        let resp = api_logout(&headers);
        assert_eq!(resp.status(), StatusCode::OK);
        let cookies = resp
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>();

        assert!(
            cookies
                .iter()
                .any(|c| c.starts_with("klaxond_session=;") && c.contains("Path=/;"))
        );
        assert!(cookies.iter().any(|c| c.contains("Domain=example.com")));
        assert!(cookies.iter().any(|c| c.contains("Domain=.example.com")));
        assert!(
            cookies
                .iter()
                .any(|c| c.contains("Path=/api/auth/callback;"))
        );
    }
}
