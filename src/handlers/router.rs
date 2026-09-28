use super::auth_admin::revoke_auth_token;
use super::passkeys::passkey_delete;
use crate::auth::{self, AuthOutcome, User};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use std::net::SocketAddr;

mod audit;
mod get;
mod paths;
mod post;

use self::audit::record_admin_mutation_audit;
use self::get::handle_get;
use self::paths::path_id;
use self::post::{PostRequest, handle_post};

pub async fn dispatch(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let path = uri.path().to_string();
    let full_path = uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or(uri.path())
        .to_string();

    if method == Method::GET && path.starts_with("/api/auth/login") {
        return auth::login(&state, headers, &full_path).await;
    }
    if method == Method::GET && path.starts_with("/api/auth/callback") {
        return auth::oidc_callback(&state, headers, &full_path).await;
    }
    if method == Method::POST && path == "/api/auth/logout" {
        return auth::api_logout(&state, &headers).await;
    }
    if method == Method::POST && path == "/api/auth/backchannel-logout" {
        return auth::backchannel_logout(&state, body).await;
    }

    let (authed_user, pending_cookie) =
        match authenticate_request(&state, &headers, &method, &path, peer).await {
            Ok(auth) => auth,
            Err(response) => return *response,
        };
    if let Err(response) = enforce_mutation_security(&headers, &method, &path, authed_user.as_ref())
    {
        return *response;
    }

    let mut resp = match method {
        Method::GET => handle_get(&state, &path, &full_path, &headers, authed_user).await,
        Method::POST => {
            handle_post(
                &state,
                PostRequest {
                    path: &path,
                    full_path: &full_path,
                    headers: &headers,
                    body,
                    peer,
                    authed_user,
                },
            )
            .await
        }
        Method::DELETE => handle_delete(&state, &path, authed_user).await,
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };
    attach_pending_cookie(&mut resp, pending_cookie);
    resp
}

fn attach_pending_cookie(response: &mut Response<Body>, cookie: Option<String>) {
    if let Some(cookie) = cookie
        && let Ok(value) = HeaderValue::from_str(&cookie)
    {
        response.headers_mut().insert(SET_COOKIE, value);
    }
}

async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    peer: SocketAddr,
) -> Result<(Option<User>, Option<String>), Box<Response<Body>>> {
    if auth::is_public(path) {
        return Ok((None, None));
    }
    match auth::authenticate(state, headers, method, path, Some(peer)).await {
        AuthOutcome::Authorized(user, cookie) => Ok((Some(user), cookie)),
        AuthOutcome::Rejected(response) => Err(Box::new(response)),
    }
}

fn enforce_mutation_security(
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    user: Option<&User>,
) -> Result<(), Box<Response<Body>>> {
    if method == Method::GET || auth::is_public(path) {
        return Ok(());
    }
    let Some(user) = user else {
        return Ok(());
    };
    if auth::csrf_required(headers, path, user) && !auth::csrf_valid(headers, user) {
        return Err(Box::new(auth::csrf_rejected()));
    }
    if auth::sudo_required(headers, path, user) && !auth::sudo_valid(user) {
        return Err(Box::new(auth::sudo_required_response()));
    }
    Ok(())
}

async fn handle_delete(state: &AppState, path: &str, authed_user: Option<User>) -> Response<Body> {
    let resp = if let Some(id) = path_id(path, "/api/auth/tokens/") {
        revoke_auth_token(state, &id)
    } else if let Some(id) = path_id(path, "/api/auth/passkey/credentials/") {
        passkey_delete(state, &id, authed_user.as_ref())
    } else {
        StatusCode::METHOD_NOT_ALLOWED.into_response()
    };
    record_admin_mutation_audit(path, resp.status(), authed_user.as_ref(), 0);
    resp
}
