use super::{ldap_user, rate_limited_response, rate_store_error};
use crate::auth::session::{issue_session_on_worker, sanitize_return_to, set_session_cookie};
use crate::auth::step_up::redirect_location_after_primary;
use crate::auth::totp_replay::consume_basic_totp;
use crate::auth::{
    AuthRateKeys, User, auth_rate_keys, auth_rate_limited_on_worker,
    blocking::{authenticate_ldap, verify_password_on_worker},
    clear_auth_failures_on_worker, json_response, login_payload, record_auth_failure_on_worker,
    redirect,
};
use crate::config::AuthConfig;
use crate::state::AppState;
use auth_modules::errors;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use std::net::SocketAddr;

enum LoginRejection {
    RateLimited,
    InvalidCredentials,
    TotpRequired,
    Store {
        operation: &'static str,
        error: String,
    },
    TotpPersistence(String),
}

impl LoginRejection {
    fn into_response(self) -> Response<Body> {
        match self {
            Self::RateLimited => rate_limited_response(),
            Self::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "invalid username or password").into_response()
            }
            Self::TotpRequired => (
                StatusCode::UNAUTHORIZED,
                "TOTP code required, invalid, or already used",
            )
                .into_response(),
            Self::Store { operation, error } => rate_store_error(operation, error),
            Self::TotpPersistence(error) => {
                tracing::error!("persist login TOTP replay counter failed: {error}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

pub async fn local_login(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: Bytes,
) -> Response<Body> {
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
    let rate_keys = auth_rate_keys(state, "login", username, headers, Some(peer));
    if let Err(rejection) = check_rate_limit(state, &rate_keys).await {
        return rejection.into_response();
    }
    let mut user = match authenticate_login_user(
        state,
        &cfg,
        username,
        payload.password(),
        payload.totp(),
        &rate_keys,
    )
    .await
    {
        Ok(user) => user,
        Err(rejection) => return rejection.into_response(),
    };
    if let Err(error) = clear_auth_failures_on_worker(state, &rate_keys).await {
        return LoginRejection::Store {
            operation: "local login clear",
            error,
        }
        .into_response();
    }
    finish_login(
        state,
        &cfg,
        &mut user,
        &sanitize_return_to(payload.return_to_or_status()),
        payload.wants_json(&body),
    )
    .await
}

async fn check_rate_limit(
    state: &AppState,
    rate_keys: &AuthRateKeys,
) -> Result<(), LoginRejection> {
    match auth_rate_limited_on_worker(state, rate_keys).await {
        Ok(true) => {
            let _ =
                record_auth_failure_on_worker(state, rate_keys, "auth.login", errors::RATE_LIMITED)
                    .await;
            Err(LoginRejection::RateLimited)
        }
        Ok(false) => Ok(()),
        Err(error) => Err(LoginRejection::Store {
            operation: "local login check",
            error,
        }),
    }
}

async fn authenticate_login_user(
    state: &AppState,
    cfg: &AuthConfig,
    username: &str,
    password: &str,
    code: &str,
    rate_keys: &AuthRateKeys,
) -> Result<User, LoginRejection> {
    if cfg.mode == "ldap" {
        return authenticate_ldap_login(state, cfg, username, password, rate_keys).await;
    }
    authenticate_basic_login(state, cfg, username, password, code, rate_keys).await
}

async fn authenticate_ldap_login(
    state: &AppState,
    cfg: &AuthConfig,
    username: &str,
    password: &str,
    rate_keys: &AuthRateKeys,
) -> Result<User, LoginRejection> {
    match authenticate_ldap(state, cfg, username, password).await {
        Ok(identity) => Ok(ldap_user(identity)),
        Err(err) => {
            tracing::warn!(?err, "LDAP login failed");
            record_failure(
                state,
                rate_keys,
                "auth.ldap",
                "ldap authentication failed",
                "LDAP login failure",
            )
            .await?;
            Err(LoginRejection::InvalidCredentials)
        }
    }
}

async fn authenticate_basic_login(
    state: &AppState,
    cfg: &AuthConfig,
    username: &str,
    password: &str,
    code: &str,
    rate_keys: &AuthRateKeys,
) -> Result<User, LoginRejection> {
    let valid = username == cfg.basic.username
        && !cfg.basic.password_hash.is_empty()
        && verify_password_on_worker(state, password, &cfg.basic.password_hash).await;
    if !valid {
        record_failure(
            state,
            rate_keys,
            "auth.login",
            "invalid username or password",
            "local login failure",
        )
        .await?;
        return Err(LoginRejection::InvalidCredentials);
    }
    if cfg.basic.totp_enabled {
        verify_totp(state, code, rate_keys).await?;
    }
    Ok(basic_user(username, cfg.basic.totp_enabled))
}

async fn verify_totp(
    state: &AppState,
    code: &str,
    rate_keys: &AuthRateKeys,
) -> Result<(), LoginRejection> {
    match consume_basic_totp(state, code) {
        Ok(true) => Ok(()),
        Ok(false) => {
            record_failure(
                state,
                rate_keys,
                "auth.login",
                "invalid or replayed TOTP code",
                "local TOTP failure",
            )
            .await?;
            Err(LoginRejection::TotpRequired)
        }
        Err(error) => Err(LoginRejection::TotpPersistence(error.to_string())),
    }
}

async fn record_failure(
    state: &AppState,
    rate_keys: &AuthRateKeys,
    component: &'static str,
    message: &'static str,
    operation: &'static str,
) -> Result<(), LoginRejection> {
    record_auth_failure_on_worker(state, rate_keys, component, message)
        .await
        .map_err(|error| LoginRejection::Store { operation, error })
}

async fn finish_login(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
    return_to: &str,
    wants_json: bool,
) -> Response<Body> {
    let primary = if user.mode == "ldap" {
        PrimaryAuthMethod::Ldap
    } else {
        PrimaryAuthMethod::Password
    };
    if let Some(location) =
        redirect_location_after_primary(state, cfg, user.clone(), return_to, primary)
    {
        return if wants_json {
            json_response(json!({"ok": true, "step_up": true, "return_to": location}))
        } else {
            redirect(&location)
        };
    }
    let cookie = match issue_session_on_worker(state, cfg, user).await {
        Ok(cookie) => cookie,
        Err(error) => {
            tracing::error!("persist local session failed: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut response = if wants_json {
        json_response(json!({"ok": true, "return_to": return_to, "csrf": user.csrf}))
    } else {
        redirect(return_to)
    };
    set_session_cookie(&mut response, &cookie);
    response
}

fn basic_user(username: &str, totp_enabled: bool) -> User {
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
        second_factor: if totp_enabled {
            "totp".into()
        } else {
            String::new()
        },
        session_id_hash: String::new(),
        session_family_hash: String::new(),
        session_created_at: 0,
        provider_issuer: String::new(),
        provider_session_id: String::new(),
    }
}
