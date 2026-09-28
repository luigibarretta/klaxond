use super::record_admin_mutation_audit;
use crate::auth::{self, User};
use crate::handlers::auth_admin::{create_auth_token, update_auth_config};
use crate::handlers::config_admin::{config_import_preview_response, restore_config};
use crate::handlers::config_mutations::{
    cascade_toggle, render_preview, update_cascade_config, update_channel_config,
    update_dedup_config, update_delivery_config, update_emergency_config, update_history_config,
    update_ntfy_topics, update_render_config,
};
use crate::handlers::ingest::{api_test, ingest, update_ingest_auth};
use crate::handlers::observability::client_log_response;
use crate::handlers::passkeys::{
    passkey_login_finish, passkey_login_start, passkey_register_finish, passkey_register_start,
    passkey_step_up_register_start,
};
use crate::handlers::rules::{
    clear_acks, clear_inhibitions, inhibition_regex_validate, inhibition_rules_test,
    policy_simulate, update_inhibition_rules, update_schedules,
};
use crate::handlers::step_up::{
    step_up_totp_setup_confirm, step_up_totp_setup_start, step_up_totp_verify,
};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use std::net::SocketAddr;

pub(super) struct PostRequest<'a> {
    pub(super) path: &'a str,
    pub(super) full_path: &'a str,
    pub(super) headers: &'a HeaderMap,
    pub(super) body: Bytes,
    pub(super) peer: SocketAddr,
    pub(super) authed_user: Option<User>,
}

pub(super) async fn handle_post(state: &AppState, request: PostRequest<'_>) -> Response<Body> {
    let body_len = request.body.len();
    let path = request.path;
    let user = request.authed_user.clone();
    let response = if is_emergency_path(path) {
        handle_emergency_post(state, request).await
    } else if path.starts_with("/api/auth") {
        handle_auth_post(state, request).await
    } else {
        handle_application_post(state, request).await
    };
    record_admin_mutation_audit(path, response.status(), user.as_ref(), body_len);
    response
}

fn is_emergency_path(path: &str) -> bool {
    path.starts_with("/emergency/")
        || path.starts_with("/api/emergency/")
        || path.starts_with("/api/emergencies/")
}

async fn handle_emergency_post(state: &AppState, request: PostRequest<'_>) -> Response<Body> {
    let PostRequest {
        path,
        headers,
        authed_user,
        ..
    } = request;
    if path.starts_with("/api/emergency/") && path.ends_with("/ack") {
        return crate::handlers::emergency::ntfy_ack(state, path, headers).await;
    }
    if path.starts_with("/emergency/") {
        return crate::handlers::emergency::confirmation_ack(state, path).await;
    }
    crate::handlers::emergency::admin_action(state, path, authed_user.as_ref()).await
}

async fn handle_auth_post(state: &AppState, request: PostRequest<'_>) -> Response<Body> {
    let PostRequest {
        path,
        headers,
        body,
        peer,
        authed_user,
        ..
    } = request;
    match path {
        "/api/auth/local/login" => auth::local_login(state, headers, peer, body).await,
        "/api/auth/reauth" => auth::sudo(state, headers, peer, body, authed_user.as_ref()).await,
        "/api/auth/magic/request" => auth::magic_link_request(state, headers, peer, body),
        "/api/auth/config" => update_auth_config(state, body, authed_user.as_ref(), peer, headers),
        "/api/auth/tokens" => create_auth_token(state, body, authed_user.as_ref()),
        "/api/auth/totp/setup/start" => auth::totp_start(state),
        "/api/auth/totp/setup/confirm" => auth::totp_enable(state, body),
        "/api/auth/totp/disable" => auth::totp_disable(state),
        _ if path.starts_with("/api/auth/passkey/") => {
            handle_passkey_post(state, path, headers, peer, body, authed_user).await
        }
        _ if path.starts_with("/api/auth/step-up/") => handle_step_up_post(state, path, body).await,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn handle_passkey_post(
    state: &AppState,
    path: &str,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: Bytes,
    user: Option<User>,
) -> Response<Body> {
    match path {
        "/api/auth/passkey/login/options" => {
            let headers = headers.clone();
            auth_blocking_response(state, move |state| {
                passkey_login_start(state, &headers, peer, body)
            })
            .await
        }
        "/api/auth/passkey/login/verify" => {
            let headers = headers.clone();
            auth_blocking_response(state, move |state| {
                passkey_login_finish(state, &headers, peer, body)
            })
            .await
        }
        "/api/auth/passkey/register/options" => {
            auth_blocking_response(state, move |state| {
                passkey_register_start(state, body, user.as_ref())
            })
            .await
        }
        "/api/auth/passkey/register/verify" => {
            auth_blocking_response(state, move |state| passkey_register_finish(state, body)).await
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn handle_step_up_post(state: &AppState, path: &str, body: Bytes) -> Response<Body> {
    match path {
        "/api/auth/step-up/passkey/register/options" => {
            auth_blocking_response(state, move |state| {
                passkey_step_up_register_start(state, body)
            })
            .await
        }
        "/api/auth/step-up/passkey/register/verify" => {
            auth_blocking_response(state, move |state| passkey_register_finish(state, body)).await
        }
        "/api/auth/step-up/totp/setup/start" => {
            auth_blocking_response(state, move |state| step_up_totp_setup_start(state, body)).await
        }
        "/api/auth/step-up/totp/setup/confirm" => {
            auth_blocking_response(state, move |state| step_up_totp_setup_confirm(state, body))
                .await
        }
        "/api/auth/step-up/totp/verify" => {
            auth_blocking_response(state, move |state| step_up_totp_verify(state, body)).await
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn handle_application_post(state: &AppState, request: PostRequest<'_>) -> Response<Body> {
    let PostRequest {
        path,
        full_path,
        headers,
        body,
        peer,
        authed_user,
    } = request;
    match path {
        "/api/client-log" => client_log_response(body, authed_user.as_ref()),
        "/api/cascade/toggle" => cascade_toggle(state, body),
        "/api/render-config" => update_render_config(state, body),
        "/api/cascade-config" => update_cascade_config(state, body),
        "/api/emergency-config" => update_emergency_config(state, body),
        "/api/history-config" => update_history_config(state, body),
        "/api/channel-config" => update_channel_config(state, body),
        "/api/delivery-config" => update_delivery_config(state, body),
        "/api/render-preview" => render_preview(state, body),
        "/api/dedup-config" => update_dedup_config(state, body),
        "/api/ntfy-topics" => update_ntfy_topics(state, body),
        "/api/inhibition-rules" => update_inhibition_rules(state, body),
        "/api/config/import-preview" => config_import_preview_response(state, body),
        "/api/config/restore" => restore_config(state, body, authed_user.as_ref()).await,
        "/api/ingest-auth" => update_ingest_auth(state, body),
        "/api/schedules" => update_schedules(state, body),
        "/api/acks/clear" => clear_acks(state, body),
        "/api/inhibitions/clear" => clear_inhibitions(state, body),
        "/api/inhibition-rules/test" => inhibition_rules_test(state, body),
        "/api/inhibition-rules/validate-regex" => inhibition_regex_validate(body),
        "/api/policy-simulate" => policy_simulate(state, body),
        _ if path.starts_with("/api/test/") => api_test(state, path, body).await,
        _ => ingest(state, path, full_path, headers, body, peer).await,
    }
}

async fn auth_blocking_response<F>(state: &AppState, task: F) -> Response<Body>
where
    F: FnOnce(&AppState) -> Response<Body> + Send + 'static,
{
    let state_for_task = state.clone();
    match auth::blocking::run_with_timeout(state, auth::blocking::AUTH_STORE_TIMEOUT, move || {
        task(&state_for_task)
    })
    .await
    {
        Ok(response) => response,
        Err(err) => {
            tracing::error!("authentication storage worker failed: {err}");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}
