use super::blocking::verify_password_on_worker;
use super::session::issue_session;
use super::step_up::primary_step_up_response;
use super::totp_replay::consume_basic_totp;
use super::{AuthOutcome, User, sudo_window_seconds};
use crate::config::AuthConfig;
use crate::state::AppState;
use crate::util::now_epoch_i64;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;

pub(super) async fn authenticate_basic(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
    return_to: &str,
) -> AuthOutcome {
    let Some((username, password)) = credentials(headers) else {
        return AuthOutcome::Rejected(challenge(&cfg.basic.realm));
    };
    if username != cfg.basic.username
        || cfg.basic.password_hash.is_empty()
        || !verify_password_on_worker(state, &password, &cfg.basic.password_hash).await
    {
        return AuthOutcome::Rejected(challenge(&cfg.basic.realm));
    }
    if cfg.basic.totp_enabled {
        let Some(code) = headers
            .get("X-Klaxond-TOTP")
            .and_then(|value| value.to_str().ok())
        else {
            return AuthOutcome::Rejected(challenge(&cfg.basic.realm));
        };
        match consume_basic_totp(state, code) {
            Ok(true) => {}
            Ok(false) => return AuthOutcome::Rejected(challenge(&cfg.basic.realm)),
            Err(err) => {
                tracing::error!("persist Basic TOTP replay counter failed: {err}");
                return AuthOutcome::Rejected(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        }
    }
    let mut user = User {
        sub: username,
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
    let cookie = issue_session(state, cfg, &mut user);
    AuthOutcome::Authorized(user, Some(cookie))
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
