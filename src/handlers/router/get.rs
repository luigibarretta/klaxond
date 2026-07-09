use super::super::auth_admin::{
    anonymous_user, auth_methods_payload, password_policy_response, redacted_auth_settings,
};
use super::super::config_admin::{
    config_backup_response, config_backups_payload, config_full_export_response,
};
use super::super::ingest::{ack_response, ingest_auth_payload};
use super::super::observability::{
    audit_payload, channel_config_payload, channel_test_matrix_payload, deliveries_response,
    inhibition_rules_payload, logs_payload, metrics_response, setup_status_payload, status_payload,
};
use super::super::passkeys::{passkey_login_page, public_passkey, webauthn_public_config};
use super::super::{json_response, redirect, text};
use super::paths::{
    legacy_legal_redirect, legacy_ui_redirect, legal_tab_from_path, path_id, root_ui_tab_from_path,
};
use crate::auth::{self, User};
use crate::config::{DEDUP_SOURCES, default_dedup, default_tiers};
use crate::inhibition;
use crate::openapi;
use crate::state::AppState;
use crate::static_files;
use crate::util::env_string;
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

pub(super) async fn handle_get(
    state: &AppState,
    path: &str,
    full_path: &str,
    headers: &HeaderMap,
    authed_user: Option<User>,
) -> Response<Body> {
    let authed_user = authed_user.as_ref();
    if let Some(resp) = public_get_response(state, path, headers) {
        return resp;
    }
    if let Some(resp) = auth_get_response(state, path, authed_user) {
        return resp;
    }
    if let Some(resp) = config_get_response(state, path).await {
        return resp;
    }
    if let Some(resp) = observability_get_response(state, path, full_path).await {
        return resp;
    }
    static_get_response(state, path).unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

fn public_get_response(
    state: &AppState,
    path: &str,
    headers: &HeaderMap,
) -> Option<Response<Body>> {
    match path {
        "/healthz" => Some(text(StatusCode::OK, "OK")),
        "/metrics" => Some(metrics_response(state)),
        "/openapi.yaml" | "/api/openapi.yaml" => Some(openapi::response()),
        "/swagger" | "/swagger/" | "/api/docs" | "/api/docs/" | "/api/swagger"
        | "/api/swagger/" | "/api/swagger-ui" | "/api/swagger-ui/" => {
            Some(static_files::ui_response(state, "swagger.html"))
        }
        "/legal" | "/legal/" => Some(redirect("/legal/privacy")),
        _ if legal_tab_from_path(path).is_some() => Some(static_files::index_response(state)),
        _ if legacy_legal_redirect(path).is_some() => Some(redirect(
            legacy_legal_redirect(path).unwrap_or("/legal/privacy"),
        )),
        "/" | "/ui" | "/ui/" => Some(redirect("/status")),
        _ if root_ui_tab_from_path(path, headers).is_some() => {
            Some(static_files::index_response(state))
        }
        _ if legacy_ui_redirect(path).is_some() => {
            Some(redirect(legacy_ui_redirect(path).unwrap_or("/status")))
        }
        _ => None,
    }
}

fn auth_get_response(
    state: &AppState,
    path: &str,
    authed_user: Option<&User>,
) -> Option<Response<Body>> {
    match path {
        "/api/auth/config" => Some(auth_config_response(state, authed_user)),
        "/api/auth/methods" => Some(auth_methods_response(state)),
        _ if path.starts_with("/api/auth/magic/callback/") => {
            let Some(token) = path_id(path, "/api/auth/magic/callback/") else {
                return Some(text(StatusCode::NOT_FOUND, "not found"));
            };
            Some(auth::magic_link_callback(state, &token))
        }
        "/api/auth/password-policy" => Some(password_policy_response()),
        "/api/auth/tokens" => Some(auth_tokens_response(state)),
        "/api/auth/passkey/credentials" => Some(passkey_credentials_response(state)),
        "/api/auth/me" => Some(json_response(
            authed_user.cloned().unwrap_or_else(anonymous_user),
        )),
        "/api/auth/passkey/login" | "/api/auth/passkey/login/" => Some(passkey_login_page()),
        _ => None,
    }
}

async fn config_get_response(state: &AppState, path: &str) -> Option<Response<Body>> {
    match path {
        "/api/render-config" => Some(render_config_response(state)),
        "/api/cascade-config" => Some(cascade_config_response(state)),
        "/api/ntfy-topics" => Some(ntfy_topics_response(state)),
        "/api/dedup-config" => Some(dedup_config_response(state).await),
        "/api/delivery-config" => Some(delivery_config_response(state)),
        "/api/channel-config" => Some(json_response(channel_config_payload(state))),
        "/api/ingest-auth" => Some(json_response(ingest_auth_payload(state))),
        "/api/schedules" => Some(json_response(inhibition::scheduler_status(state))),
        "/api/acks" => Some(json_response(inhibition::ack_status_snapshot(state))),
        "/api/inhibition-rules" => Some(json_response(inhibition_rules_payload(state))),
        "/api/config/backup" => Some(config_backup_response(state)),
        "/api/config/export" => Some(config_full_export_response(state)),
        "/api/config/backups" => Some(json_response(config_backups_payload(state))),
        _ => None,
    }
}

async fn observability_get_response(
    state: &AppState,
    path: &str,
    full_path: &str,
) -> Option<Response<Body>> {
    match path {
        "/inhibitions" | "/api/inhibitions" => {
            Some(json_response(inhibition::inhibition_status(state)))
        }
        "/api/status" => Some(json_response(status_payload(state).await)),
        "/api/deliveries" => Some(deliveries_response(state, full_path)),
        "/api/logs" => Some(json_response(logs_payload(full_path))),
        "/api/audit" => Some(json_response(audit_payload(full_path))),
        "/api/setup-status" => Some(json_response(setup_status_payload(state))),
        "/api/channel-test-matrix" => Some(json_response(channel_test_matrix_payload(state).await)),
        _ => None,
    }
}

fn static_get_response(state: &AppState, path: &str) -> Option<Response<Body>> {
    match path {
        _ if path.starts_with("/img/") => Some(static_files::image_response(state, path)),
        _ if path.starts_with("/ui/") => Some(static_files::ui_response(
            state,
            path.trim_start_matches("/ui/"),
        )),
        _ if path.starts_with("/api/ack/") => Some(ack_response(state, path)),
        _ => None,
    }
}

fn render_config_response(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    json_response(json!({
        "component_dashboards": cfg.component_dashboards,
        "grafana_base": cfg.grafana_base,
        "settings": {
            "grafana_base": cfg.grafana_base,
            "grafana_render_base": cfg.grafana_render_base,
            "grafana_render_token_configured": !cfg.grafana_render_token.is_empty(),
            "render_image_ttl": cfg.render_image_ttl,
            "public_url": cfg.public_url,
            "ack_default_ttl": cfg.ack_default_ttl,
            "from_env": {
                "grafana_base": !env_string("GRAFANA_BASE").is_empty(),
                "grafana_render_base": !env_string("GRAFANA_RENDER_BASE").is_empty(),
                "grafana_render_token": !env_string("GRAFANA_RENDER_TOKEN").is_empty(),
                "render_image_ttl": std::env::var("RENDER_IMAGE_TTL").is_ok(),
                "public_url": std::env::var("KLAXOND_PUBLIC_URL").is_ok(),
                "ack_default_ttl": std::env::var("ACK_DEFAULT_TTL_SECONDS").is_ok(),
            }
        }
    }))
}

fn cascade_config_response(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    json_response(json!({
        "tiers": cfg.tiers,
        "default_enabled_for_webhook": cfg.cascade_default,
        "runtime_enabled": state.cascade_runtime_enabled.load(Ordering::Relaxed),
    }))
}

fn auth_config_response(state: &AppState, authed_user: Option<&User>) -> Response<Body> {
    let cfg = state.cfg();
    json_response(json!({
        "settings": redacted_auth_settings(&cfg.auth),
        "available_modes": ["none", "basic", "ldap", "oidc", "trusted-proxy"],
        "available_token_scopes": auth::TOKEN_SCOPES,
        "argon2_available": true,
        "jwt_available": true,
        "current_user": authed_user.cloned().unwrap_or_else(anonymous_user),
    }))
}

fn auth_methods_response(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    json_response(auth_methods_payload(&cfg.auth))
}

fn auth_tokens_response(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    json_response(json!({
        "tokens": cfg.auth.api_keys.iter().map(auth::public_token).collect::<Vec<_>>(),
        "available_scopes": auth::TOKEN_SCOPES,
    }))
}

fn passkey_credentials_response(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    json_response(json!({
        "webauthn": webauthn_public_config(&cfg),
        "passkeys": cfg.auth.passkeys.iter().map(public_passkey).collect::<Vec<_>>(),
    }))
}

fn ntfy_topics_response(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    let topics = cfg
        .ntfy_topics
        .iter()
        .map(|topic| {
            json!({
                "name": topic.name,
                "handles": topic.handles,
                "token": if topic.token.is_empty() { "" } else { "***SET***" },
            })
        })
        .collect::<Vec<_>>();
    json_response(json!({
        "topics": topics,
        "ntfy_url": cfg.ntfy_url,
        "known_severities": cfg.known_severities(),
        "orphans": [],
        "writeable": true,
        "persisted_at": state.paths.ntfy_topics,
        "note": "Edits saved to /data/ntfy-topics.json supersede TOML + env vars. Delete the file + restart to re-bootstrap from env.",
    }))
}

async fn dedup_config_response(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    let pending_counts = {
        let d = state.dedup.lock().await;
        DEDUP_SOURCES
            .iter()
            .map(|source| {
                (
                    (*source).to_string(),
                    d.queues.get(*source).map(|queue| queue.len()).unwrap_or(0),
                )
            })
            .collect::<HashMap<_, _>>()
    };
    json_response(json!({
        "sources": DEDUP_SOURCES,
        "settings": cfg.dedup,
        "pending_counts": pending_counts,
        "defaults": default_dedup(),
    }))
}

fn delivery_config_response(state: &AppState) -> Response<Body> {
    let cfg = state.cfg();
    json_response(json!({
        "default_policy": cfg.delivery.default_policy,
        "policies": cfg.delivery.policies,
        "rules": cfg.delivery.rules,
        "available_tiers": ["ntfy", "telegram", "smtp"],
        "legacy_cascade_tiers": if cfg.tiers.is_empty() { default_tiers() } else { cfg.tiers },
    }))
}
