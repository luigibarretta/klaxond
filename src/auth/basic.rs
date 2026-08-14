use super::blocking::verify_password_on_worker;
use super::session::issue_session_on_worker;
use super::step_up::primary_step_up_response;
use super::totp_replay::consume_basic_totp;
use super::{
    AuthOutcome, User, auth_rate_keys, auth_rate_limited_on_worker, clear_auth_failures_on_worker,
    record_auth_failure_on_worker, sudo_window_seconds,
};
use crate::config::AuthConfig;
use crate::state::AppState;
use crate::util::now_epoch_i64;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use std::net::SocketAddr;

enum BasicFailure {
    Challenge,
    TooManyRequests,
    ServiceUnavailable,
    InternalServerError,
}

impl BasicFailure {
    fn response(self, realm: &str) -> Response<Body> {
        match self {
            Self::Challenge => challenge(realm),
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS.into_response(),
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            Self::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

pub(super) async fn authenticate_basic(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
    return_to: &str,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    let Some((username, password)) = credentials(headers) else {
        return AuthOutcome::Rejected(challenge(&cfg.basic.realm));
    };
    let rate_keys = auth_rate_keys(state, "basic", &username, headers, peer);
    if let Err(failure) = check_rate_limit(state, &rate_keys).await {
        return AuthOutcome::Rejected(failure.response(&cfg.basic.realm));
    }
    if let Err(failure) = verify_credentials(state, cfg, &username, &password, &rate_keys).await {
        return AuthOutcome::Rejected(failure.response(&cfg.basic.realm));
    }
    if let Err(failure) = verify_totp(state, cfg, headers, &rate_keys).await {
        return AuthOutcome::Rejected(failure.response(&cfg.basic.realm));
    }
    if let Err(err) = clear_auth_failures_on_worker(state, &rate_keys).await {
        tracing::error!("clear persistent Basic authentication failures failed: {err}");
        return AuthOutcome::Rejected(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    let mut user = basic_user(username, cfg.basic.totp_enabled);
    if let Some(response) = primary_step_up_response(
        state,
        cfg,
        &user,
        return_to,
        PrimaryAuthMethod::Password,
        headers,
    ) {
        return AuthOutcome::Rejected(response);
    }
    match issue_session_on_worker(state, cfg, &mut user).await {
        Ok(cookie) => AuthOutcome::Authorized(user, Some(cookie)),
        Err(err) => {
            tracing::error!("persist Basic session failed: {err}");
            AuthOutcome::Rejected(StatusCode::SERVICE_UNAVAILABLE.into_response())
        }
    }
}

async fn check_rate_limit(
    state: &AppState,
    rate_keys: &super::AuthRateKeys,
) -> Result<(), BasicFailure> {
    match auth_rate_limited_on_worker(state, rate_keys).await {
        Ok(true) => {
            let _ = record_auth_failure_on_worker(
                state,
                rate_keys,
                "auth.login",
                auth_modules::errors::RATE_LIMITED,
            )
            .await;
            Err(BasicFailure::TooManyRequests)
        }
        Ok(false) => Ok(()),
        Err(err) => {
            tracing::error!("persistent Basic rate-limit check failed: {err}");
            Err(BasicFailure::ServiceUnavailable)
        }
    }
}

async fn verify_credentials(
    state: &AppState,
    cfg: &AuthConfig,
    username: &str,
    password: &str,
    rate_keys: &super::AuthRateKeys,
) -> Result<(), BasicFailure> {
    let valid = username == cfg.basic.username
        && !cfg.basic.password_hash.is_empty()
        && verify_password_on_worker(state, password, &cfg.basic.password_hash).await;
    if valid {
        return Ok(());
    }
    if let Err(err) = record_auth_failure_on_worker(
        state,
        rate_keys,
        "auth.login",
        "invalid username or password",
    )
    .await
    {
        tracing::error!("persist Basic authentication failure failed: {err}");
        return Err(BasicFailure::ServiceUnavailable);
    }
    Err(BasicFailure::Challenge)
}

async fn verify_totp(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
    rate_keys: &super::AuthRateKeys,
) -> Result<(), BasicFailure> {
    if !cfg.basic.totp_enabled {
        return Ok(());
    }
    let code = headers
        .get("X-Klaxond-TOTP")
        .and_then(|value| value.to_str().ok());
    let (valid, detail) = match code.map(|code| consume_basic_totp(state, code)) {
        None => (false, "missing TOTP code"),
        Some(Ok(valid)) => (valid, "invalid or replayed TOTP code"),
        Some(Err(err)) => {
            tracing::error!("persist Basic TOTP replay counter failed: {err}");
            return Err(BasicFailure::InternalServerError);
        }
    };
    if valid {
        return Ok(());
    }
    if let Err(err) = record_auth_failure_on_worker(state, rate_keys, "auth.login", detail).await {
        tracing::error!("persist Basic TOTP failure failed: {err}");
        return Err(BasicFailure::ServiceUnavailable);
    }
    Err(BasicFailure::Challenge)
}

fn basic_user(username: String, totp_enabled: bool) -> User {
    User {
        sub: username,
        email: String::new(),
        name: String::new(),
        groups: vec![],
        mode: "basic".into(),
        exp: 0,
        csrf: String::new(),
        sudo_until: now_epoch_i64() + sudo_window_seconds(),
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

pub(super) fn credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let raw = auth.strip_prefix("Basic ")?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

pub(super) fn challenge(realm: &str) -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::empty())
        .unwrap();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&format!("Basic realm=\"{realm}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("Basic realm=\"klaxond\"")),
    );
    response
}
