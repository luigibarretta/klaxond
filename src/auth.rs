use crate::config::{AuthConfig, AuthToken, save_auth};
use crate::state::{AppState, lock_mutex};
use crate::util::{
    b64url_decode_padded, b64url_no_pad, hmac_hex, now_epoch, now_epoch_i64, random_bytes,
    token_urlsafe,
};
use axum::body::{Body, Bytes};
use axum::http::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, SET_COOKIE, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use axum::response::IntoResponse;
use bcrypt::verify;
use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use url::{Url, form_urlencoded};

const PUBLIC_PREFIXES: &[&str] = &[
    "/webhook/",
    "/beszel/",
    "/healthchecks/",
    "/wud/",
    "/authentik/",
    "/shelfmark/",
    "/prowlarr/",
    "/decypharr/",
    "/pve/",
    "/healthz",
    "/metrics",
    "/api/ack/",
    "/img/",
    "/auth/login",
    "/auth/callback",
    "/auth/logout",
    "/auth/passkey",
    "/static/",
    "/favicon.ico",
];

const PUBLIC_PATHS: &[&str] = &[
    "/ui/privacy",
    "/ui/accessibility",
    "/ui/terms",
    "/ui/cookies",
    "/ui/legal",
];

pub const AUTH_SESSION_COOKIE: &str = "klaxond_session";
const SUDO_WINDOW_SECS: i64 = 10 * 60;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const AUTH_FAILURE_WINDOW_SECS: f64 = 300.0;
const AUTH_FAILURE_MAX: usize = 10;

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
    if PUBLIC_PATHS.contains(&path) || is_public_ui_asset(path) {
        return true;
    }
    PUBLIC_PREFIXES
        .iter()
        .any(|p| path == *p || path.starts_with(p))
}

fn is_public_ui_asset(path: &str) -> bool {
    path.starts_with("/ui/")
        && path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.contains('.'))
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
                    let location = format!("/auth/login?return_to={}", urlencoding::encode(path));
                    AuthOutcome::Rejected(auth_required(&location))
                }
                other => other,
            }
        }
        "trusted-proxy" => authenticate_trusted_proxy(&cfg, headers, peer),
        "oidc" => {
            let location = format!("/auth/login?return_to={}", urlencoding::encode(path));
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
    user.mode != "none"
        && !user.via_authorization
        && is_mutation_path(path)
        && path != "/api/client-log"
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
    matches!(user.mode.as_str(), "basic" | "passkey")
        && !user.via_authorization
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
    !matches!(
        path,
        "/api/config/import-preview"
            | "/api/render-preview"
            | "/api/policy-simulate"
            | "/api/inhibition-rules/test"
    )
}

fn is_sensitive_mutation_path(path: &str) -> bool {
    matches!(
        path,
        "/api/auth-config"
            | "/api/auth/tokens"
            | "/api/auth/tokens/revoke"
            | "/api/auth/passkeys/register/start"
            | "/api/auth/passkeys/register/finish"
            | "/api/auth/passkeys/delete"
            | "/api/auth/totp/start"
            | "/api/auth/totp/enable"
            | "/api/auth/totp/disable"
            | "/api/config/restore"
            | "/api/channel-config"
            | "/api/ntfy-topics"
            | "/api/ingest-auth"
            | "/api/render-config"
            | "/api/cascade-config"
            | "/api/cascade/toggle"
            | "/api/delivery-config"
            | "/api/dedup-config"
            | "/api/inhibition-rules"
            | "/api/schedules"
            | "/api/acks/clear"
            | "/api/inhibitions/clear"
    )
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
    if *method == Method::GET {
        return match path {
            "/auth/me" => "status:read",
            "/api/auth-config" => "auth:read",
            "/api/logs" => "logs:read",
            "/api/audit" => "audit:read",
            "/api/config/backups" => "status:read",
            "/api/config/export" => "admin:*",
            "/api/config/backup" => "config:read",
            "/api/status"
            | "/api/deliveries"
            | "/api/cascade-config"
            | "/api/setup-status"
            | "/api/channel-test-matrix" => "status:read",
            _ => "admin:read",
        };
    }
    match path {
        "/api/auth-config"
        | "/api/auth/tokens"
        | "/api/auth/tokens/revoke"
        | "/api/auth/totp/start"
        | "/api/auth/totp/enable"
        | "/api/auth/totp/disable"
        | "/api/auth/passkeys/register/start"
        | "/api/auth/passkeys/register/finish"
        | "/api/auth/passkeys/delete" => "auth:write",
        "/api/config/import-preview" => "config:read",
        "/api/config/restore" => "config:write",
        "/api/channel-config" | "/api/ntfy-topics" | "/api/ingest-auth" => "routing:write",
        "/api/render-config" | "/api/render-preview" => "render:write",
        "/api/cascade-config" | "/api/cascade/toggle" => "cascade:write",
        "/api/client-log" => "admin:read",
        "/api/policy-simulate" => "status:read",
        "/api/delivery-config" => "delivery:write",
        "/api/dedup-config" => "dedup:write",
        "/api/inhibition-rules"
        | "/api/inhibition-rules/test"
        | "/api/inhibitions/clear"
        | "/api/schedules"
        | "/api/acks/clear" => "inhibitions:write",
        _ if path.starts_with("/api/test/") => "test:write",
        _ => "admin:*",
    }
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

fn authenticate_basic(state: &AppState, cfg: &AuthConfig, headers: &HeaderMap) -> AuthOutcome {
    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(raw) = auth.strip_prefix("Basic ")
        && let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw)
        && let Ok(s) = String::from_utf8(decoded)
        && let Some((user, pwd)) = s.split_once(':')
        && cfg.basic.username == user
        && !cfg.basic.password_hash.is_empty()
        && verify(pwd, &cfg.basic.password_hash).unwrap_or(false)
        && (!cfg.basic.totp_enabled
            || headers
                .get("X-Klaxond-TOTP")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|code| {
                    verify_totp_code(&cfg.basic.totp_secret, code, now_epoch_i64())
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
    login_page(&auth.mode, auth.webauthn.enabled, &return_to)
}

pub async fn local_login(state: &AppState, body: Bytes) -> Response<Body> {
    let cfg = state.cfg().auth;
    if cfg.mode != "basic" {
        return (
            StatusCode::BAD_REQUEST,
            "local login is available only in basic mode",
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
            .unwrap_or("/ui/status"),
    );
    if username != cfg.basic.username
        || cfg.basic.password_hash.is_empty()
        || !verify(password, &cfg.basic.password_hash).unwrap_or(false)
    {
        record_auth_failure(
            state,
            &rate_key,
            "auth.login",
            "invalid username or password",
        );
        return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response();
    }
    if cfg.basic.totp_enabled && !verify_totp_code(&cfg.basic.totp_secret, code, now_epoch_i64()) {
        record_auth_failure(state, &rate_key, "auth.login", "invalid TOTP code");
        return (StatusCode::UNAUTHORIZED, "TOTP code required or invalid").into_response();
    }
    clear_auth_failures(state, &rate_key);
    let mut user = User {
        sub: username.to_string(),
        email: String::new(),
        name: String::new(),
        groups: vec![],
        mode: "basic".into(),
        exp: 0,
        csrf: String::new(),
        sudo_until: 0,
        via_authorization: false,
    };
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
    if user.mode != "basic" {
        return (
            StatusCode::BAD_REQUEST,
            "sudo reauth is available only for local login",
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
    if cfg.basic.password_hash.is_empty()
        || !verify(password, &cfg.basic.password_hash).unwrap_or(false)
    {
        record_auth_failure(state, &rate_key, "auth.sudo", "invalid password");
        return (StatusCode::UNAUTHORIZED, "invalid password").into_response();
    }
    if cfg.basic.totp_enabled && !verify_totp_code(&cfg.basic.totp_secret, code, now_epoch_i64()) {
        record_auth_failure(state, &rate_key, "auth.sudo", "invalid TOTP code");
        return (StatusCode::UNAUTHORIZED, "TOTP code required or invalid").into_response();
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

pub fn totp_start(state: &AppState) -> Response<Body> {
    let cfg = state.cfg().auth;
    let secret = base32_encode(&random_bytes::<20>());
    let label = if cfg.basic.username.trim().is_empty() {
        "klaxond".to_string()
    } else {
        format!("klaxond:{}", cfg.basic.username)
    };
    let issuer = "klaxond";
    let otpauth_uri = format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        urlencoding::encode(&label),
        secret,
        urlencoding::encode(issuer)
    );
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
    if base32_decode(&secret).is_none() {
        return (StatusCode::BAD_REQUEST, "invalid TOTP secret").into_response();
    }
    if !verify_totp_code(&secret, code, now_epoch_i64()) {
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
    let discovery = match oidc_discovery(state, &issuer).await {
        Ok(d) => d,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("OIDC discovery failed: {err}"),
            )
                .into_response();
        }
    };
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
    {
        let mut states = lock_mutex(&state.oidc_states, "oidc states");
        states.insert(state_token.clone(), (crate::util::now_epoch(), return_to));
        let cutoff = crate::util::now_epoch() - 600.0;
        states.retain(|_, (ts, _)| *ts >= cutoff);
    }
    let mut url = Url::parse(
        discovery
            .get("authorization_endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )
    .unwrap();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &cfg.scopes)
        .append_pair("state", &state_token);
    redirect(url.as_str())
}

fn login_return_to(uri: &str) -> String {
    let return_to = Url::parse(&format!("http://localhost{uri}"))
        .ok()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "return_to")
                .map(|(_, v)| v.to_string())
        })
        .unwrap_or_else(|| "/ui/status".into());
    sanitize_return_to(&return_to)
}

fn login_page(mode: &str, passkeys_enabled: bool, return_to: &str) -> Response<Body> {
    let start_url = format!(
        "/auth/login?start=1&return_to={}",
        urlencoding::encode(return_to)
    );
    let start_url = html_attr(&start_url);
    let return_to = html_attr(return_to);
    let primary = match mode {
        "oidc" => format!(r#"<a class="btn primary" href="{start_url}">Continue with SSO</a>"#),
        "basic" => format!(
            r#"<form class="login-form" method="post" action="/auth/login">
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
        r#"<a class="btn" href="/auth/passkey">Use passkey</a>"#
    } else {
        ""
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
<div class="login-actions">{primary}{passkey}</div>
<nav class="login-legal" aria-label="Legal links">
<a href="/ui/privacy">Privacy</a>
<a href="/ui/accessibility">Accessibility</a>
<a href="/ui/terms">Terms</a>
<a href="/ui/cookies">Cookies</a>
<a href="/ui/legal">Legal notice</a>
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
    let now = now_epoch();
    let cutoff = now - AUTH_FAILURE_WINDOW_SECS;
    let mut failures = lock_mutex(&state.auth_failures, "auth failures");
    let entries = failures.entry(key.to_string()).or_default();
    entries.retain(|ts| *ts >= cutoff);
    entries.len() >= AUTH_FAILURE_MAX
}

fn record_auth_failure(state: &AppState, key: &str, action: &'static str, detail: &'static str) {
    let now = now_epoch();
    let cutoff = now - AUTH_FAILURE_WINDOW_SECS;
    {
        let mut failures = lock_mutex(&state.auth_failures, "auth failures");
        let entries = failures.entry(key.to_string()).or_default();
        entries.retain(|ts| *ts >= cutoff);
        entries.push(now);
    }
    crate::audit::record(key.to_string(), action, "error", detail.to_string());
}

fn clear_auth_failures(state: &AppState, key: &str) {
    lock_mutex(&state.auth_failures, "auth failures").remove(key);
}

fn sudo_window_seconds() -> i64 {
    SUDO_WINDOW_SECS
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            let idx = ((buffer >> (bits - 5)) & 0x1f) as usize;
            output.push(BASE32_ALPHABET[idx] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(BASE32_ALPHABET[idx] as char);
    }
    output
}

fn base32_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for ch in value.chars().filter(|ch| !ch.is_whitespace()) {
        if ch == '=' {
            break;
        }
        let ch = ch.to_ascii_uppercase();
        let val = match ch {
            'A'..='Z' => ch as u8 - b'A',
            '2'..='7' => ch as u8 - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(val);
        bits += 5;
        while bits >= 8 {
            output.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    (!output.is_empty()).then_some(output)
}

fn verify_totp_code(secret: &str, code: &str, now: i64) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.as_bytes().iter().all(u8::is_ascii_digit) {
        return false;
    }
    let Ok(expected) = code.parse::<u32>() else {
        return false;
    };
    let Some(secret) = base32_decode(secret) else {
        return false;
    };
    let counter = now.max(0) / 30;
    (-1..=1).any(|skew| {
        let step = counter + skew;
        step >= 0 && hotp(&secret, step as u64).is_some_and(|value| value == expected)
    })
}

fn hotp(secret: &[u8], counter: u64) -> Option<u32> {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret).ok()?;
    mac.update(&counter.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let offset = usize::from(out[19] & 0x0f);
    let binary = (u32::from(out[offset] & 0x7f) << 24)
        | (u32::from(out[offset + 1]) << 16)
        | (u32::from(out[offset + 2]) << 8)
        | u32::from(out[offset + 3]);
    Some(binary % 1_000_000)
}

pub async fn oidc_callback(state: &AppState, headers: HeaderMap, uri: &str) -> Response<Body> {
    let cfg = state.cfg().auth.oidc;
    let issuer = cfg.issuer.trim_end_matches('/').to_string();
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
    let return_to = {
        let mut states = lock_mutex(&state.oidc_states, "oidc states");
        match states.remove(&state_param) {
            Some((_, ret)) => sanitize_return_to(&ret),
            None => return redirect("/"),
        }
    };
    let discovery = match oidc_discovery(state, &issuer).await {
        Ok(d) => d,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("OIDC discovery failed: {err}"),
            )
                .into_response();
        }
    };
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
    let token_endpoint = discovery
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tokens = match state
        .http
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &cfg.client_id),
            ("client_secret", &cfg.client_secret),
        ])
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => v,
            Err(err) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("token exchange failed: {err}"),
                )
                    .into_response();
            }
        },
        Ok(resp) => {
            let code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return (
                StatusCode::BAD_GATEWAY,
                format!(
                    "token exchange failed: {code} {}",
                    &body[..body.len().min(200)]
                ),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("token exchange failed: {err}"),
            )
                .into_response();
        }
    };
    let Some(id_token) = tokens.get("id_token").and_then(|v| v.as_str()) else {
        return (StatusCode::BAD_GATEWAY, "no id_token in response").into_response();
    };
    let claims = match verify_id_token(state, &issuer, &discovery, id_token, &cfg.client_id).await {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::UNAUTHORIZED,
                format!("id_token verify failed: {err}"),
            )
                .into_response();
        }
    };
    if !cfg.required_group.trim().is_empty() {
        let groups = claims
            .get("groups")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if !groups
            .iter()
            .any(|g| g.as_str() == Some(cfg.required_group.as_str()))
        {
            return (
                StatusCode::FORBIDDEN,
                format!("required_group '{}' not in user claims", cfg.required_group),
            )
                .into_response();
        }
    }
    let mut user = User {
        sub: claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        email: claims
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: claims
            .get("name")
            .or_else(|| claims.get("preferred_username"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        groups: claims
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
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

pub fn logout(headers: &HeaderMap) -> Response<Body> {
    let mut resp = redirect("/auth/login?logged_out=1");
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
    let value = value.trim();
    if value.is_empty()
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.starts_with("/\\")
        || value.contains(['\r', '\n'])
        || value == "/auth"
        || value.starts_with("/auth/")
    {
        "/".to_string()
    } else {
        value.to_string()
    }
}

fn expired_session_cookies(headers: &HeaderMap) -> Vec<String> {
    let mut cookies = Vec::new();
    let domains = logout_domain_candidates(headers);
    for path in ["/", "/auth", "/auth/", "/auth/login", "/auth/callback"] {
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

async fn oidc_discovery(state: &AppState, issuer: &str) -> anyhow::Result<Value> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    Ok(state
        .http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?)
}

async fn verify_id_token(
    state: &AppState,
    issuer: &str,
    discovery: &Value,
    id_token: &str,
    client_id: &str,
) -> anyhow::Result<Value> {
    let jwks_uri = discovery
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("issuer discovery missing jwks_uri"))?;
    let jwks = state
        .http
        .get(jwks_uri)
        .send()
        .await?
        .error_for_status()?
        .json::<JwkSet>()
        .await?;
    let header = decode_header(id_token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("missing kid"))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| anyhow::anyhow!("kid not found in JWKS"))?;
    let key = DecodingKey::from_jwk(jwk)?;
    let alg = header.alg;
    let mut validation = Validation::new(match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384 => alg,
        _ => Algorithm::RS256,
    });
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[discovery
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or(issuer)]);
    let data = decode::<Value>(id_token, &key, &validation)?;
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    #[test]
    fn jwt_crypto_provider_is_available() {
        let claims = serde_json::json!({
            "sub": "probe",
            "exp": 4_102_444_800_i64
        });
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("JWT encode should have a crypto provider");
        let data = decode::<Value>(
            &token,
            &DecodingKey::from_secret(b"secret"),
            &Validation::new(Algorithm::HS256),
        )
        .expect("JWT decode should have a crypto provider");

        assert_eq!(
            data.claims.get("sub").and_then(Value::as_str),
            Some("probe")
        );
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
        assert_eq!(sanitize_return_to("/ui/inhibitions"), "/ui/inhibitions");
        assert_eq!(sanitize_return_to("https://example.test/"), "/");
        assert_eq!(sanitize_return_to("//example.test/"), "/");
        assert_eq!(sanitize_return_to("/ui\r\nLocation: //example.test"), "/");
        assert_eq!(sanitize_return_to("/auth/login?return_to=%2F"), "/");
        assert_eq!(sanitize_return_to("/auth"), "/");
        assert_eq!(sanitize_return_to(""), "/");
    }

    #[test]
    fn legal_ui_pages_and_assets_are_public_but_admin_routes_are_not() {
        assert!(is_public("/ui/privacy"));
        assert!(is_public("/ui/accessibility"));
        assert!(is_public("/ui/style.css"));
        assert!(is_public("/ui/meta.js"));
        assert!(is_public("/ui/app.js"));
        assert!(!is_public("/ui/status"));
        assert!(!is_public("/ui/auth"));
    }

    #[test]
    fn ui_fetch_auth_required_is_machine_readable() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Klaxond-Request", HeaderValue::from_static("fetch"));
        assert!(is_ui_fetch(&headers));

        let resp = auth_required("/auth/login?return_to=%2Fui%2Fstatus");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get("X-Klaxond-Login")
                .and_then(|v| v.to_str().ok()),
            Some("/auth/login?return_to=%2Fui%2Fstatus")
        );
        assert_eq!(
            resp.headers()
                .get("Cache-Control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }

    #[test]
    fn logout_clears_host_and_parent_domain_cookie_variants() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("klaxond.example.com"));
        let resp = logout(&headers);
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers().get("Location").and_then(|v| v.to_str().ok()),
            Some("/auth/login?logged_out=1")
        );
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
        assert!(cookies.iter().any(|c| c.contains("Path=/auth/callback;")));
    }
}
