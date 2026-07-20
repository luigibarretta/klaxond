use super::basic::authenticate_basic;
use super::local::{authenticate_ldap_basic, authenticate_trusted_proxy};
use super::session::{cookie_values, rotate_session_on_worker, verify_session};
use super::step_up::redirect_location_after_primary;
use super::tokens::{authenticate_api_token, bearer_token, required_scope, viewer_allows_scope};
use super::{AUTH_SESSION_COOKIE, AuthOutcome, User, auth_required, is_ui_fetch, redirect};
use crate::config::AuthConfig;
use crate::state::AppState;
use crate::util::token_urlsafe;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::Body;
use axum::http::header::COOKIE;
use axum::http::{HeaderMap, Method, Response, StatusCode};
use axum::response::IntoResponse;
use std::net::SocketAddr;

pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    let cfg = state.cfg().auth;
    if cfg.mode == "none" {
        return AuthOutcome::Authorized(anonymous_user(), None);
    }
    if let Some(token) = bearer_token(headers) {
        return authenticate_api_token(state, &token, method, path);
    }

    match authenticate_session(state, &cfg, headers, method, path).await {
        Ok(Some(outcome)) => return outcome,
        Ok(None) => {}
        Err(err) => {
            tracing::error!("persistent session authentication failed: {err}");
            return AuthOutcome::Rejected(StatusCode::SERVICE_UNAVAILABLE.into_response());
        }
    }

    let outcome = authenticate_interactive_mode(state, &cfg, headers, path, peer).await;
    authorize_authenticated_outcome(outcome, method, path)
}

fn anonymous_user() -> User {
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
        second_factor: String::new(),
        session_id_hash: String::new(),
        session_family_hash: String::new(),
        session_created_at: 0,
        provider_issuer: String::new(),
        provider_session_id: String::new(),
    }
}

async fn authenticate_session(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
) -> Result<Option<AuthOutcome>, String> {
    if let Some(cookie) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        for value in cookie_values(cookie, AUTH_SESSION_COOKIE).into_iter().rev() {
            if let Some(verified) = verify_session(state, value).await? {
                let mut user = verified.user;
                let refresh_cookie = ensure_session_security_fields(
                    state,
                    cfg,
                    &mut user,
                    verified.legacy || verified.should_rotate,
                )
                .await?;
                return Ok(Some(authorize_interactive_user(
                    user,
                    refresh_cookie,
                    method,
                    path,
                )));
            }
        }
    }
    Ok(None)
}

async fn authenticate_interactive_mode(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
    path: &str,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    match cfg.mode.as_str() {
        "basic" => {
            let outcome = authenticate_basic(state, cfg, headers, path, peer).await;
            ui_fetch_login_on_unauthorized(outcome, headers, path)
        }
        "ldap" => {
            let outcome = authenticate_ldap_basic(state, cfg, headers, path, peer).await;
            ui_fetch_login_on_unauthorized(outcome, headers, path)
        }
        "trusted-proxy" => trusted_proxy_with_step_up(state, cfg, headers, path, peer),
        "oidc" => AuthOutcome::Rejected(oidc_login_redirect(headers, path)),
        _ => AuthOutcome::Rejected(StatusCode::FORBIDDEN.into_response()),
    }
}

fn trusted_proxy_with_step_up(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
    path: &str,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    match authenticate_trusted_proxy(cfg, headers, peer) {
        AuthOutcome::Authorized(user, cookie) => {
            if let Some(location) = redirect_location_after_primary(
                state,
                cfg,
                user.clone(),
                path,
                PrimaryAuthMethod::TrustedProxy,
            ) {
                return AuthOutcome::Rejected(if is_ui_fetch(headers) {
                    auth_required(&location)
                } else {
                    redirect(&location)
                });
            }
            AuthOutcome::Authorized(user, cookie)
        }
        rejected => rejected,
    }
}

fn ui_fetch_login_on_unauthorized(
    outcome: AuthOutcome,
    headers: &HeaderMap,
    path: &str,
) -> AuthOutcome {
    match outcome {
        AuthOutcome::Rejected(resp)
            if resp.status() == StatusCode::UNAUTHORIZED && is_ui_fetch(headers) =>
        {
            if resp.headers().contains_key("X-Klaxond-Login") {
                AuthOutcome::Rejected(resp)
            } else {
                AuthOutcome::Rejected(auth_required(&login_location(path)))
            }
        }
        other => other,
    }
}

fn oidc_login_redirect(headers: &HeaderMap, path: &str) -> Response<Body> {
    let location = login_location(path);
    if is_ui_fetch(headers) {
        auth_required(&location)
    } else {
        redirect(&location)
    }
}

fn login_location(path: &str) -> String {
    format!("/api/auth/login?return_to={}", urlencoding::encode(path))
}

fn authorize_authenticated_outcome(
    outcome: AuthOutcome,
    method: &Method,
    path: &str,
) -> AuthOutcome {
    match outcome {
        AuthOutcome::Authorized(user, cookie) => {
            authorize_interactive_user(user, cookie, method, path)
        }
        rejected => rejected,
    }
}

async fn ensure_session_security_fields(
    state: &AppState,
    cfg: &AuthConfig,
    user: &mut User,
    force_rotation: bool,
) -> Result<Option<String>, String> {
    let needs_refresh = force_rotation || user.csrf.is_empty();
    if user.csrf.is_empty() {
        user.csrf = format!("klx_csrf_{}", token_urlsafe(24));
    }
    if needs_refresh {
        rotate_session_on_worker(state, cfg, user).await.map(Some)
    } else {
        Ok(None)
    }
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
