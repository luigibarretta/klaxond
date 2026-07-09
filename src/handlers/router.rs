use super::auth_admin::{create_auth_token, revoke_auth_token, update_auth_config};
use super::config_admin::{config_import_preview_response, restore_config};
use super::config_mutations::{
    cascade_toggle, render_preview, update_cascade_config, update_channel_config,
    update_dedup_config, update_delivery_config, update_ntfy_topics, update_render_config,
};
use super::ingest::{api_test, ingest, update_ingest_auth};
use super::observability::client_log_response;
use super::passkeys::{
    passkey_delete, passkey_login_finish, passkey_login_start, passkey_register_finish,
    passkey_register_start,
};
use super::rules::{
    clear_acks, clear_inhibitions, inhibition_rules_test, policy_simulate, update_inhibition_rules,
    update_schedules,
};
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

use self::audit::record_admin_mutation_audit;
use self::get::handle_get;
use self::paths::path_id;

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
        return auth::api_logout(&headers);
    }

    let mut authed_user: Option<User> = None;
    let mut pending_cookie: Option<String> = None;
    if !auth::is_public(&path) {
        match auth::authenticate(&state, &headers, &method, &path, Some(peer)).await {
            AuthOutcome::Authorized(user, cookie) => {
                authed_user = Some(user);
                pending_cookie = cookie;
            }
            AuthOutcome::Rejected(resp) => return resp,
        }
    }

    if method != Method::GET
        && !auth::is_public(&path)
        && let Some(user) = authed_user.as_ref()
    {
        if auth::csrf_required(&headers, &path, user) && !auth::csrf_valid(&headers, user) {
            return auth::csrf_rejected();
        }
        if auth::sudo_required(&headers, &path, user) && !auth::sudo_valid(user) {
            return auth::sudo_required_response();
        }
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
    if let Some(cookie) = pending_cookie
        && let Ok(v) = HeaderValue::from_str(&cookie)
    {
        resp.headers_mut().insert(SET_COOKIE, v);
    }
    resp
}

struct PostRequest<'a> {
    path: &'a str,
    full_path: &'a str,
    headers: &'a HeaderMap,
    body: Bytes,
    peer: SocketAddr,
    authed_user: Option<User>,
}

async fn handle_post(state: &AppState, req: PostRequest<'_>) -> Response<Body> {
    let PostRequest {
        path,
        full_path,
        headers,
        body,
        peer,
        authed_user,
    } = req;
    let body_len = body.len();
    let resp = match path {
        "/api/auth/local/login" => auth::local_login(state, body).await,
        "/api/auth/reauth" => auth::sudo(state, body, authed_user.as_ref()),
        "/api/auth/magic/request" => auth::magic_link_request(state, headers, peer, body),
        "/api/auth/passkey/login/options" => passkey_login_start(state, headers, peer, body),
        "/api/auth/passkey/login/verify" => passkey_login_finish(state, headers, peer, body),
        "/api/client-log" => client_log_response(body, authed_user.as_ref()),
        "/api/auth/config" => update_auth_config(state, body, authed_user.as_ref(), peer, headers),
        "/api/auth/tokens" => create_auth_token(state, body, authed_user.as_ref()),
        "/api/auth/totp/setup/start" => auth::totp_start(state),
        "/api/auth/totp/setup/confirm" => auth::totp_enable(state, body),
        "/api/auth/totp/disable" => auth::totp_disable(state),
        "/api/auth/passkey/register/options" => {
            passkey_register_start(state, body, authed_user.as_ref())
        }
        "/api/auth/passkey/register/verify" => passkey_register_finish(state, body),
        "/api/cascade/toggle" => cascade_toggle(state, body),
        "/api/render-config" => update_render_config(state, body),
        "/api/cascade-config" => update_cascade_config(state, body),
        "/api/channel-config" => update_channel_config(state, body),
        "/api/delivery-config" => update_delivery_config(state, body),
        "/api/render-preview" => render_preview(state, body),
        "/api/dedup-config" => update_dedup_config(state, body),
        "/api/ntfy-topics" => update_ntfy_topics(state, body),
        "/api/inhibition-rules" => update_inhibition_rules(state, body),
        "/api/config/import-preview" => config_import_preview_response(state, body),
        "/api/config/restore" => restore_config(state, body, authed_user.as_ref()),
        "/api/ingest-auth" => update_ingest_auth(state, body),
        "/api/schedules" => update_schedules(state, body),
        "/api/acks/clear" => clear_acks(state, body),
        "/api/inhibitions/clear" => clear_inhibitions(state, body),
        "/api/inhibition-rules/test" => inhibition_rules_test(state, body),
        "/api/policy-simulate" => policy_simulate(state, body),
        _ if path.starts_with("/api/auth") => StatusCode::NOT_FOUND.into_response(),
        _ if path.starts_with("/api/test/") => api_test(state, path, body).await,
        _ => ingest(state, path, full_path, headers, body, peer).await,
    };
    record_admin_mutation_audit(path, resp.status(), authed_user.as_ref(), body_len);
    resp
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
