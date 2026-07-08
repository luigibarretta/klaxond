use super::auth_admin::{
    anonymous_user, auth_methods_payload, create_auth_token, password_policy_response,
    redacted_auth_settings, revoke_auth_token, update_auth_config,
};
use super::config_admin::{
    config_backup_response, config_backups_payload, config_full_export_response,
    config_import_preview_response, restore_config,
};
use super::config_mutations::{
    cascade_toggle, render_preview, update_cascade_config, update_channel_config,
    update_dedup_config, update_delivery_config, update_ntfy_topics, update_render_config,
};
use super::ingest::{ack_response, api_test, ingest, ingest_auth_payload, update_ingest_auth};
use super::observability::{
    audit_payload, channel_config_payload, channel_test_matrix_payload, client_log_response,
    deliveries_response, inhibition_rules_payload, logs_payload, metrics_response,
    setup_status_payload, status_payload,
};
use super::passkeys::{
    passkey_delete, passkey_login_finish, passkey_login_page, passkey_login_start,
    passkey_register_finish, passkey_register_start, public_passkey, webauthn_public_config,
};
use super::rules::{
    clear_acks, clear_inhibitions, inhibition_rules_test, policy_simulate, update_inhibition_rules,
    update_schedules,
};
use super::{json_response, redirect, text};
use crate::audit;
use crate::auth::{self, AuthOutcome, User};
use crate::config::{DEDUP_SOURCES, default_dedup, default_tiers};
use crate::endpoints;
use crate::inhibition;
use crate::openapi;
use crate::state::AppState;
use crate::static_files;
use crate::util::env_string;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::header::{ACCEPT, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

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
            handle_post(&state, &path, &full_path, &headers, body, peer, authed_user).await
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

async fn handle_get(
    state: &AppState,
    path: &str,
    full_path: &str,
    headers: &HeaderMap,
    authed_user: Option<User>,
) -> Response<Body> {
    match path {
        "/healthz" => text(StatusCode::OK, "OK"),
        "/metrics" => metrics_response(state),
        "/openapi.yaml" | "/api/openapi.yaml" => openapi::response(),
        "/swagger" | "/swagger/" | "/api/docs" | "/api/docs/" | "/api/swagger"
        | "/api/swagger/" | "/api/swagger-ui" | "/api/swagger-ui/" => {
            static_files::ui_response(state, "swagger.html")
        }
        "/legal" | "/legal/" => redirect("/legal/privacy"),
        _ if legal_tab_from_path(path).is_some() => static_files::index_response(state),
        _ if legacy_legal_redirect(path).is_some() => {
            redirect(legacy_legal_redirect(path).unwrap_or("/legal/privacy"))
        }
        "/" | "/ui" | "/ui/" => redirect("/status"),
        _ if root_ui_tab_from_path(path, headers).is_some() => static_files::index_response(state),
        _ if legacy_ui_redirect(path).is_some() => {
            redirect(legacy_ui_redirect(path).unwrap_or("/status"))
        }
        "/inhibitions" | "/api/inhibitions" => json_response(inhibition::inhibition_status(state)),
        "/api/status" => json_response(status_payload(state).await),
        "/api/deliveries" => deliveries_response(state, full_path),
        "/api/logs" => json_response(logs_payload(full_path)),
        "/api/audit" => json_response(audit_payload(full_path)),
        "/api/render-config" => {
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
        "/api/cascade-config" => {
            let cfg = state.cfg();
            json_response(json!({
                "tiers": cfg.tiers,
                "default_enabled_for_webhook": cfg.cascade_default,
                "runtime_enabled": state.cascade_runtime_enabled.load(Ordering::Relaxed),
            }))
        }
        "/api/auth/config" => {
            let cfg = state.cfg();
            let settings = redacted_auth_settings(&cfg.auth);
            json_response(json!({
                "settings": settings,
                "available_modes": ["none", "basic", "ldap", "oidc", "trusted-proxy"],
                "available_token_scopes": auth::TOKEN_SCOPES,
                "argon2_available": true,
                "jwt_available": true,
                "current_user": authed_user.unwrap_or_else(anonymous_user),
            }))
        }
        "/api/auth/methods" => {
            let cfg = state.cfg();
            json_response(auth_methods_payload(&cfg.auth))
        }
        _ if path.starts_with("/api/auth/magic/callback/") => {
            let Some(token) = path_id(path, "/api/auth/magic/callback/") else {
                return text(StatusCode::NOT_FOUND, "not found");
            };
            auth::magic_link_callback(state, &token)
        }
        "/api/auth/password-policy" => password_policy_response(),
        "/api/auth/tokens" => {
            let cfg = state.cfg();
            json_response(json!({
                "tokens": cfg.auth.api_keys.iter().map(auth::public_token).collect::<Vec<_>>(),
                "available_scopes": auth::TOKEN_SCOPES,
            }))
        }
        "/api/auth/passkey/credentials" => {
            let cfg = state.cfg();
            json_response(json!({
                "webauthn": webauthn_public_config(&cfg),
                "passkeys": cfg.auth.passkeys.iter().map(public_passkey).collect::<Vec<_>>(),
            }))
        }
        "/api/ntfy-topics" => {
            let cfg = state.cfg();
            let topics = cfg
                .ntfy_topics
                .iter()
                .map(|t| json!({"name": t.name, "handles": t.handles, "token": if t.token.is_empty() { "" } else { "***SET***" }}))
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
        "/api/dedup-config" => {
            let cfg = state.cfg();
            let pending_counts = {
                let d = state.dedup.lock().await;
                DEDUP_SOURCES
                    .iter()
                    .map(|s| {
                        (
                            (*s).to_string(),
                            d.queues.get(*s).map(|q| q.len()).unwrap_or(0),
                        )
                    })
                    .collect::<HashMap<_, _>>()
            };
            json_response(
                json!({"sources": DEDUP_SOURCES, "settings": cfg.dedup, "pending_counts": pending_counts, "defaults": default_dedup()}),
            )
        }
        "/api/delivery-config" => {
            let cfg = state.cfg();
            json_response(json!({
                "default_policy": cfg.delivery.default_policy,
                "policies": cfg.delivery.policies,
                "rules": cfg.delivery.rules,
                "available_tiers": ["ntfy", "telegram", "smtp"],
                "legacy_cascade_tiers": if cfg.tiers.is_empty() { default_tiers() } else { cfg.tiers },
            }))
        }
        "/api/channel-config" => json_response(channel_config_payload(state)),
        "/api/ingest-auth" => json_response(ingest_auth_payload(state)),
        "/api/schedules" => json_response(inhibition::scheduler_status(state)),
        "/api/acks" => json_response(inhibition::ack_status_snapshot(state)),
        "/api/inhibition-rules" => json_response(inhibition_rules_payload(state)),
        "/api/config/backup" => config_backup_response(state),
        "/api/config/export" => config_full_export_response(state),
        "/api/config/backups" => json_response(config_backups_payload(state)),
        "/api/setup-status" => json_response(setup_status_payload(state)),
        "/api/channel-test-matrix" => json_response(channel_test_matrix_payload(state).await),
        "/api/auth/me" => json_response(authed_user.unwrap_or_else(anonymous_user)),
        "/api/auth/passkey/login" | "/api/auth/passkey/login/" => passkey_login_page(),
        _ if path.starts_with("/img/") => static_files::image_response(state, path),
        _ if path.starts_with("/ui/") => {
            static_files::ui_response(state, path.trim_start_matches("/ui/"))
        }
        _ if path.starts_with("/api/ack/") => ack_response(state, path),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

fn legal_tab_from_path(path: &str) -> Option<&'static str> {
    match path.trim_end_matches('/') {
        "/legal/privacy" => Some("privacy"),
        "/legal/accessibility" => Some("accessibility"),
        "/legal/terms" => Some("terms"),
        "/legal/cookies" => Some("cookies"),
        "/legal/notice" => Some("legal"),
        _ => None,
    }
}

fn legacy_legal_redirect(path: &str) -> Option<&'static str> {
    match path.trim_end_matches('/') {
        "/ui/privacy" => Some("/legal/privacy"),
        "/ui/accessibility" => Some("/legal/accessibility"),
        "/ui/terms" => Some("/legal/terms"),
        "/ui/cookies" => Some("/legal/cookies"),
        "/ui/legal" => Some("/legal/notice"),
        _ => None,
    }
}

fn root_ui_tab_from_path(path: &str, headers: &HeaderMap) -> Option<&'static str> {
    let route = path.trim_matches('/');
    if route == "inhibitions" && !prefers_html(headers) {
        return None;
    }
    static_files::tab_for_root_route(route)
}

fn legacy_ui_redirect(path: &str) -> Option<&'static str> {
    let route = path.strip_prefix("/ui/")?.trim_matches('/');
    if route.is_empty() || route == "index.html" {
        return Some("/status");
    }
    static_files::root_route_for_tab(route).map(|root| match root {
        "authentication" => "/authentication",
        "status" => "/status",
        "flow" => "/flow",
        "inhibitions" => "/inhibitions",
        "deliveries" => "/deliveries",
        "logs" => "/logs",
        "audit" => "/audit",
        "setup" => "/setup",
        "render" => "/render",
        "routing" => "/routing",
        "cascade" => "/cascade",
        "delivery" => "/delivery",
        "grouping" => "/grouping",
        "preview" => "/preview",
        "simulator" => "/simulator",
        "test" => "/test",
        _ => "/status",
    })
}

fn prefers_html(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

async fn handle_post(
    state: &AppState,
    path: &str,
    full_path: &str,
    headers: &HeaderMap,
    body: Bytes,
    peer: SocketAddr,
    authed_user: Option<User>,
) -> Response<Body> {
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

fn path_id(path: &str, prefix: &str) -> Option<String> {
    let raw = path.strip_prefix(prefix)?;
    if raw.is_empty() || raw.contains('/') {
        return None;
    }
    Some(urlencoding::decode(raw).ok()?.into_owned())
}

fn record_admin_mutation_audit(
    path: &str,
    status: StatusCode,
    authed_user: Option<&User>,
    body_len: usize,
) {
    let Some(action) = endpoints::audit_action_for_post(path) else {
        return;
    };
    audit::record(
        audit_actor(authed_user),
        action,
        if status.is_success() { "ok" } else { "error" },
        format!("{} status={} bytes={}", path, status.as_u16(), body_len),
    );
}

fn audit_actor(user: Option<&User>) -> String {
    user.map(|u| {
        let sub = if u.sub.trim().is_empty() {
            "anonymous"
        } else {
            u.sub.as_str()
        };
        format!("{}:{sub}", u.mode)
    })
    .unwrap_or_else(|| "anonymous".into())
}
