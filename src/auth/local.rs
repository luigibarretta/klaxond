use super::session::sanitize_return_to;
use super::session::{issue_session, set_session_cookie};
use super::step_up::{primary_step_up_response, redirect_location_after_primary};
use super::{
    AuthOutcome, User, auth_rate_key, auth_rate_limited, clear_auth_failures, json_response,
    login_payload, record_auth_failure, redirect, sudo_window_seconds, verify_password,
};
use crate::config::AuthConfig;
use crate::state::AppState;
use crate::totp;
use crate::util::now_epoch_i64;
use auth_modules::errors;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::{Body, Bytes};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use ipnet::IpNet;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};

pub(super) fn authenticate_basic(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
    return_to: &str,
) -> AuthOutcome {
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
            second_factor: if cfg.basic.totp_enabled {
                "totp".into()
            } else {
                String::new()
            },
        };
        if let Some(resp) = primary_step_up_response(
            state,
            cfg,
            &u,
            return_to,
            PrimaryAuthMethod::Password,
            headers,
        ) {
            return AuthOutcome::Rejected(resp);
        }
        let cookie = issue_session(state, cfg, &mut u);
        return AuthOutcome::Authorized(u, Some(cookie));
    }
    AuthOutcome::Rejected(basic_challenge(&cfg.basic.realm))
}

pub(super) async fn authenticate_ldap_basic(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
    return_to: &str,
) -> AuthOutcome {
    let Some((username, password)) = basic_credentials(headers) else {
        return AuthOutcome::Rejected(basic_challenge("klaxond ldap"));
    };
    let rate_key = auth_rate_key("ldap", &username);
    if auth_rate_limited(state, &rate_key) {
        record_auth_failure(state, &rate_key, "auth.ldap", errors::RATE_LIMITED);
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
    if let Some(resp) = primary_step_up_response(
        state,
        cfg,
        &user,
        return_to,
        PrimaryAuthMethod::Ldap,
        headers,
    ) {
        return AuthOutcome::Rejected(resp);
    }
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
    resp.headers_mut()
        .insert(WWW_AUTHENTICATE, basic_challenge_header(realm));
    resp
}

fn basic_challenge_header(realm: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Basic realm=\"{realm}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("Basic realm=\"klaxond\""))
}

pub(super) fn authenticate_trusted_proxy(
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
            second_factor: String::new(),
        },
        None,
    )
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
    let username = payload.username().trim();
    let password = payload.password();
    let code = payload.totp();
    let rate_key = auth_rate_key("login", username);
    if auth_rate_limited(state, &rate_key) {
        record_auth_failure(state, &rate_key, "auth.login", errors::RATE_LIMITED);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many authentication failures",
        )
            .into_response();
    }
    let return_to = sanitize_return_to(payload.return_to_or_status());
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
            second_factor: if cfg.basic.totp_enabled {
                "totp".into()
            } else {
                String::new()
            },
        }
    };
    clear_auth_failures(state, &rate_key);
    let primary = if user.mode == "ldap" {
        PrimaryAuthMethod::Ldap
    } else {
        PrimaryAuthMethod::Password
    };
    if let Some(location) =
        redirect_location_after_primary(state, &cfg, user.clone(), &return_to, primary)
    {
        return if payload.wants_json(&body) {
            json_response(json!({"ok": true, "step_up": true, "return_to": location}))
        } else {
            redirect(&location)
        };
    }
    let cookie = issue_session(state, &cfg, &mut user);
    let mut resp = if payload.wants_json(&body) {
        json_response(json!({"ok": true, "return_to": return_to, "csrf": user.csrf}))
    } else {
        redirect(&return_to)
    };
    set_session_cookie(&mut resp, &cookie);
    resp
}

pub async fn sudo(state: &AppState, body: Bytes, user: Option<&User>) -> Response<Body> {
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
    let password = payload.password();
    let code = payload.totp();
    let rate_key = auth_rate_key("sudo", &user.sub);
    if auth_rate_limited(state, &rate_key) {
        record_auth_failure(state, &rate_key, "auth.sudo", errors::RATE_LIMITED);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many authentication failures",
        )
            .into_response();
    }
    if user.mode == "ldap" {
        if let Err(err) = authenticate_ldap_credentials(&cfg, &user.sub, password).await {
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
    set_session_cookie(&mut resp, &cookie);
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
        second_factor: String::new(),
    }
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
