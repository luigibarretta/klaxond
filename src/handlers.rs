use crate::audit;
use crate::auth::{self, AuthOutcome, User};
use crate::config::{
    DEDUP_SOURCES, InhibitionRule, NtfyTopic, Schedule, default_dedup, default_tiers,
    load_runtime_config, save_dedup, save_ntfy_topics, save_render_config,
};
use crate::dedup;
use crate::delivery::{deliver, pick_policy};
use crate::endpoints;
use crate::inhibition;
use crate::openapi;
use crate::parsers::{
    Parts, normalize_labels, parse_beszel_payload, parse_grafana_payload,
    parse_healthchecks_payload, parse_source, parse_wud_payload,
};
use crate::state::{AppState, lock_mutex};
use crate::static_files;
use crate::util::{env_string, random_hex, toml_table_mut};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use url::form_urlencoded;

mod auth_admin;
mod config_admin;
mod observability;
mod passkeys;

use auth_admin::{
    anonymous_user, auth_methods_payload, create_auth_token, password_policy_response,
    redacted_auth_settings, revoke_auth_token, update_auth_config,
};
use config_admin::{
    config_backup_response, config_backups_payload, config_full_export_response,
    config_import_preview_response, persist_reload, restore_config,
};
use observability::{
    audit_payload, channel_config_payload, channel_test_matrix_payload, client_log_response,
    deliveries_response, inhibition_rules_payload, logs_payload, metrics_response,
    setup_status_payload, status_payload,
};
use passkeys::{
    passkey_delete, passkey_login_finish, passkey_login_page, passkey_login_start,
    passkey_register_finish, passkey_register_start, public_passkey, webauthn_public_config,
};

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

async fn ingest(
    state: &AppState,
    path: &str,
    full_path: &str,
    headers: &HeaderMap,
    body: Bytes,
    peer: SocketAddr,
) -> Response<Body> {
    let source = if path.starts_with("/webhook/") {
        "grafana"
    } else if path.starts_with("/beszel/") {
        "beszel"
    } else if path.starts_with("/healthchecks/") {
        "healthchecks"
    } else if path.starts_with("/wud/") {
        "wud"
    } else if path.starts_with("/authentik/") {
        "authentik"
    } else if path.starts_with("/shelfmark/") {
        "shelfmark"
    } else if path.starts_with("/prowlarr/") {
        "prowlarr"
    } else if path.starts_with("/decypharr/") {
        "decypharr"
    } else if path.starts_with("/pve/") {
        "pve"
    } else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let severity = path.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    if !state.with_cfg(|cfg| cfg.handles_severity(&severity)) {
        return text(
            StatusCode::BAD_REQUEST,
            &format!("unknown severity {severity} (no topic handles it)"),
        );
    }
    let qs = parse_query(full_path);
    let (auth_ok, auth_reason) = verify_ingest_auth(state, source, headers, &qs);
    if !auth_ok {
        tracing::warn!(
            "[{}/{}] webhook auth rejected: {} (from {})",
            source,
            severity,
            auth_reason,
            peer.ip()
        );
        return text(
            StatusCode::UNAUTHORIZED,
            "unauthorized (per-source secret required)",
        );
    }
    let payload: Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => {
                tracing::error!("invalid JSON: {}", err);
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    };
    let dry_run = qs
        .get("dry_run")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
        || payload
            .get("_klaxond_dry_run")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

    let norm = normalize_labels(source, &payload);
    let (should_send, reason) = inhibition::apply_inhibition(state, source, &norm, dry_run);
    if !should_send {
        let title = norm
            .get("alertname")
            .or_else(|| norm.get("host"))
            .cloned()
            .unwrap_or_else(|| "alert".into());
        let (suppressed_by, ch) = if let Some(rest) = reason.strip_prefix("ack-snoozed-") {
            (
                rest.to_string(),
                if dry_run {
                    "dry-run-ack-snoozed"
                } else {
                    "ack-snoozed"
                },
            )
        } else if let Some(rest) = reason.strip_prefix("scheduled-mute-") {
            (
                rest.to_string(),
                if dry_run {
                    "dry-run-scheduled-mute"
                } else {
                    "scheduled-mute"
                },
            )
        } else if let Some(rest) = reason.strip_prefix("inhibited-by-") {
            (
                rest.to_string(),
                if dry_run {
                    "dry-run-suppressed"
                } else {
                    "suppressed"
                },
            )
        } else {
            (
                reason.clone(),
                if dry_run {
                    "dry-run-suppressed"
                } else {
                    "suppressed"
                },
            )
        };
        state.log_delivery(source, &severity, &title, ch, &suppressed_by);
        if dry_run {
            return json_response(
                json!({"dry_run": true, "would_send": false, "reason": reason, "suppressed_by": suppressed_by, "title": title}),
            );
        }
        return text(StatusCode::OK, &format!("suppressed by {reason}"));
    }

    let (severity2, parts, with_cascade) = state.with_cfg(|cfg| {
        let (severity2, parts) = parse_source(source, &payload, &severity, cfg);
        let with_cascade = if source == "grafana" {
            cfg.cascade_default
        } else {
            true
        };
        (severity2, parts, with_cascade)
    });
    let common_labels = if source == "grafana" {
        payload
            .get("commonLabels")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), crate::parsers::scalar_to_string(v)))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    if dry_run {
        state.log_delivery(source, &severity2, &parts.title, "dry-run", "");
        return json_response(json!({
            "dry_run": true,
            "would_send": true,
            "reason": reason,
            "source": source,
            "severity": severity2,
            "with_cascade": with_cascade,
            "parsed": parts.public_json(),
        }));
    }

    if source != "pve"
        && dedup::submit(
            state,
            source,
            &severity2,
            payload.clone(),
            parts.clone(),
            common_labels.clone(),
            with_cascade,
        )
        .await
    {
        return text(StatusCode::ACCEPTED, "buffered (dedup window)");
    }
    let (ok, channel) = deliver(
        state,
        &severity2,
        parts,
        with_cascade,
        common_labels,
        source,
    )
    .await;
    if ok {
        text(StatusCode::OK, &format!("delivered via {channel}"))
    } else {
        text(
            StatusCode::BAD_GATEWAY,
            &format!("all channels failed ({channel})"),
        )
    }
}

async fn api_test(state: &AppState, path: &str, body: Bytes) -> Response<Body> {
    let severity = path.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    if !state.with_cfg(|cfg| cfg.handles_severity(&severity)) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let title = payload
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let title = if title.is_empty() {
        format!("klaxond test [{severity}]")
    } else {
        title
    };
    let body_txt = payload
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("Synthetic alert from /api/test endpoint")
        .to_string();
    let component = payload
        .get("component")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let host = payload
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let cfg = state.cfg();
    let (parts, labels) = if !component.is_empty() || !host.is_empty() {
        let fake = json!({
            "status": "firing",
            "commonLabels": {"alertname": title, "severity": severity, "component": component, "host": host},
            "commonAnnotations": {"summary": body_txt},
            "alerts": [{"labels": {"alertname": title, "host": host, "component": component}, "annotations": {"summary": body_txt}, "generatorURL": ""}],
        });
        (
            parse_grafana_payload(&fake, &severity, &cfg),
            HashMap::from([("component".into(), component), ("host".into(), host)]),
        )
    } else {
        (
            Parts {
                title,
                body: body_txt,
                tags: vec![severity.clone(), "test".into()],
                actions: vec![],
                priority: cfg.priority(&severity),
                alertname: String::new(),
                skip_snooze: false,
                render_slug: None,
                render_panel: None,
                render_instance: String::new(),
                attach_url: None,
            },
            HashMap::new(),
        )
    };
    let with_cascade = state.cascade_runtime_enabled.load(Ordering::Relaxed);
    let (ok, channel) = deliver(
        state,
        &severity,
        parts.clone(),
        with_cascade,
        labels,
        "api-test",
    )
    .await;
    json_response(json!({"ok": ok, "channel": channel, "title": parts.title}))
}

fn cascade_toggle(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let next = if let Some(v) = payload.get("enabled").and_then(|v| v.as_bool()) {
        v
    } else {
        !state.cascade_runtime_enabled.load(Ordering::Relaxed)
    };
    state.cascade_runtime_enabled.store(next, Ordering::Relaxed);
    json_response(json!({"cascade_enabled_runtime": next}))
}

fn render_preview(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let severity = payload
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("warning")
        .to_string();
    let sample = payload.get("payload").cloned().unwrap_or_else(|| json!({}));
    let (parts, url) = state.with_cfg(|cfg| {
        let parts = if sample.get("alerts").is_some() || sample.get("commonLabels").is_some() {
            parse_grafana_payload(&sample, &severity, cfg)
        } else if sample.get("check").is_some() && sample.get("status").is_some() {
            parse_healthchecks_payload(&sample, &severity, cfg)
        } else if sample.get("title").is_some()
            && sample.get("body").is_some()
            && sample.get("alert").is_none()
        {
            parse_wud_payload(&sample, &severity, cfg)
        } else {
            parse_beszel_payload(&sample, &severity, cfg)
        };
        let url = cfg
            .ntfy_topics
            .iter()
            .find(|t| t.handles.iter().any(|h| h == &severity))
            .map(|t| format!("{}/{}", cfg.ntfy_url, t.name))
            .unwrap_or_else(|| format!("{}/(no topic handles '{}')", cfg.ntfy_url, severity));
        (parts, url)
    });
    let title_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        parts.title.as_bytes(),
    );
    json_response(json!({
        "url": url,
        "headers": {
            "Title (raw)": parts.title,
            "Title (RFC2047)": format!("=?UTF-8?B?{title_b64}?="),
            "Tags": parts.tags.join(","),
            "Priority": parts.priority,
            "Actions": parts.actions.iter().map(|[k,l,t]| format!("{k}, {l}, {t}")).collect::<Vec<_>>().join("; "),
        },
        "body": parts.body,
    }))
}

fn update_render_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let has_dashboards = payload.get("component_dashboards").is_some();
    let mut cleaned: HashMap<String, [String; 2]> = HashMap::new();
    if let Some(obj) = payload
        .get("component_dashboards")
        .and_then(|v| v.as_object())
    {
        for (k, v) in obj {
            if let Some(arr) = v.as_array() {
                let label = arr
                    .first()
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let url = arr
                    .get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !k.is_empty() && !label.is_empty() && !url.is_empty() {
                    cleaned.insert(k.clone(), [label, url]);
                }
            }
        }
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            if has_dashboards {
                if let Err(err) = save_render_config(&state.paths, &cleaned) {
                    return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
                }
                cfg.component_dashboards = cleaned.clone();
                toml_table_mut(&mut cfg.toml, &["render"])
                    .insert("component_dashboards".into(), dashboards_to_toml(&cleaned));
            }
            if let Some(settings) = payload.get("settings").and_then(|v| v.as_object()) {
                {
                    let render = toml_table_mut(&mut cfg.toml, &["render"]);
                    if let Some(v) = settings.get("grafana_base").and_then(|v| v.as_str()) {
                        render.insert(
                            "grafana_base".into(),
                            toml::Value::String(v.trim_end_matches('/').into()),
                        );
                    }
                    if let Some(v) = settings.get("grafana_render_base").and_then(|v| v.as_str()) {
                        render.insert(
                            "grafana_render_base".into(),
                            toml::Value::String(v.trim_end_matches('/').into()),
                        );
                    }
                    if let Some(v) = settings
                        .get("grafana_render_token")
                        .and_then(|v| v.as_str())
                        .filter(|v| *v != "***SET***")
                    {
                        render.insert("grafana_render_token".into(), toml::Value::String(v.into()));
                    }
                    if let Some(v) = settings.get("render_image_ttl").and_then(|v| v.as_u64()) {
                        render.insert(
                            "render_image_ttl".into(),
                            toml::Value::Integer(v.clamp(1, 86_400) as i64),
                        );
                    }
                }
                if let Some(v) = settings.get("public_url").and_then(|v| v.as_str()) {
                    toml_table_mut(&mut cfg.toml, &["server"]).insert(
                        "public_url".into(),
                        toml::Value::String(v.trim_end_matches('/').into()),
                    );
                }
                if let Some(v) = settings.get("ack_default_ttl").and_then(|v| v.as_u64()) {
                    toml_table_mut(&mut cfg.toml, &["acks"]).insert(
                        "default_ttl_seconds".into(),
                        toml::Value::Integer(v.clamp(60, 86_400) as i64),
                    );
                }
                return persist_reload(state, cfg.toml)
                    .map(|_| json_response(json!({"ok": true, "count": cleaned.len()})))
                    .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e));
            }
            if has_dashboards {
                return persist_reload(state, cfg.toml)
                    .map(|_| json_response(json!({"ok": true, "count": cleaned.len()})))
                    .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e));
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true, "count": cleaned.len()}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn dashboards_to_toml(dashboards: &HashMap<String, [String; 2]>) -> toml::Value {
    let mut table = toml::map::Map::new();
    let mut keys = dashboards.keys().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        if let Some([label, url]) = dashboards.get(key) {
            table.insert(
                key.clone(),
                toml::Value::Array(vec![
                    toml::Value::String(label.clone()),
                    toml::Value::String(url.clone()),
                ]),
            );
        }
    }
    toml::Value::Table(table)
}

fn update_ntfy_topics(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(incoming) = payload.get("topics").and_then(|v| v.as_array()) else {
        return text(StatusCode::BAD_REQUEST, "missing 'topics' list");
    };
    state.with_config_write_lock(|| {
        let existing = state
            .cfg()
            .ntfy_topics
            .into_iter()
            .map(|t| (t.name, t.token))
            .collect::<HashMap<_, _>>();
        let mut cleaned = Vec::new();
        let mut names = std::collections::HashSet::new();
        let mut errors = Vec::new();
        for (idx, t) in incoming.iter().enumerate() {
            let name = t
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if name.is_empty() {
                errors.push(format!("topic[{idx}]: empty name"));
                continue;
            }
            if !names.insert(name.clone()) {
                errors.push(format!("topic[{idx}]: duplicate name '{name}'"));
                continue;
            }
            let Some(handles_arr) = t.get("handles").and_then(|v| v.as_array()) else {
                errors.push(format!("topic[{idx}] '{name}': handles must be a list"));
                continue;
            };
            let handles = handles_arr
                .iter()
                .filter_map(|h| h.as_str().map(|s| s.trim().to_ascii_lowercase()))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            if handles.is_empty() {
                errors.push(format!("topic[{idx}] '{name}': handles is empty"));
                continue;
            }
            let token_in = t.get("token").and_then(|v| v.as_str()).unwrap_or("");
            let token = if token_in == "***SET***" {
                existing.get(&name).cloned().unwrap_or_default()
            } else {
                token_in.to_string()
            };
            cleaned.push(NtfyTopic {
                name,
                token,
                handles,
            });
        }
        if !errors.is_empty() {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("validation errors:\n  - {}", errors.join("\n  - ")),
            );
        }
        if cleaned.is_empty() {
            return text(StatusCode::BAD_REQUEST, "need at least one valid topic");
        }
        if let Err(err) = save_ntfy_topics(&state.paths, &cleaned) {
            return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }
        match load_runtime_config(&state.paths) {
            Ok(cfg) => {
                if let Err(err) = state.try_replace_config(cfg) {
                    return text(StatusCode::INTERNAL_SERVER_ERROR, &err);
                }
            }
            Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
        let cfg = state.cfg();
        let redacted = cfg
            .ntfy_topics
            .iter()
            .map(|t| json!({"name": t.name, "token": if t.token.is_empty() { "" } else { "***SET***" }, "handles": t.handles}))
            .collect::<Vec<_>>();
        json_response(
            json!({"ok": true, "topics": redacted, "known_severities": cfg.known_severities(), "persisted_at": state.paths.ntfy_topics}),
        )
    })
    .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn update_dedup_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(new) = payload.get("settings").and_then(|v| v.as_object()) else {
        return text(StatusCode::BAD_REQUEST, "missing 'settings' object");
    };
    let mut cleaned = default_dedup();
    for src in DEDUP_SOURCES {
        if let Some(incoming) = new.get(*src).and_then(|v| v.as_object())
            && let Some(base) = cleaned.get_mut(*src)
        {
            if let Some(v) = incoming.get("enabled").and_then(|v| v.as_bool()) {
                base.enabled = v;
            }
            if let Some(v) = incoming.get("window_s").and_then(|v| v.as_u64()) {
                base.window_s = v.clamp(5, 3600);
            }
            if let Some(v) = incoming.get("strategy").and_then(|v| v.as_str())
                && matches!(v, "none" | "time" | "key")
            {
                base.strategy = v.into();
            }
            if let Some(v) = incoming.get("override_critical").and_then(|v| v.as_bool()) {
                base.override_critical = v;
            }
        }
    }
    state
        .with_config_write_lock(|| {
            if let Err(err) = save_dedup(&state.paths, &cleaned) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            let mut cfg = state.cfg();
            cfg.dedup = cleaned.clone();
            state.replace_config(cfg);
            json_response(json!({"ok": true, "settings": cleaned}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn update_cascade_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(arr) = payload.get("tiers").and_then(|v| v.as_array()) else {
        return text(StatusCode::BAD_REQUEST, "tiers must be a non-empty list");
    };
    let mut tiers = Vec::new();
    for t in arr {
        let name = t
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(name.as_str(), "ntfy" | "telegram" | "smtp") {
            continue;
        }
        tiers.push(json!({"name": name, "timeout_seconds": t.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(5).clamp(1, 60)}));
    }
    if tiers.is_empty() {
        return text(StatusCode::BAD_REQUEST, "no valid tiers");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            {
                let cas = toml_table_mut(&mut cfg.toml, &["cascade"]);
                cas.insert("tiers".into(), json_to_toml(Value::Array(tiers.clone())));
                if let Some(v) = payload
                    .get("default_enabled_for_webhook")
                    .and_then(|v| v.as_bool())
                {
                    cas.insert(
                        "default_enabled_for_webhook".into(),
                        toml::Value::Boolean(v),
                    );
                }
            }
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true, "tiers": state.cfg().tiers})))
                .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn update_channel_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            if let Some(n) = payload.get("ntfy").and_then(|v| v.as_object()) {
                let ntfy = toml_table_mut(&mut cfg.toml, &["ntfy"]);
                if let Some(url) = n.get("url").and_then(|v| v.as_str()) {
                    ntfy.insert(
                        "url".into(),
                        toml::Value::String(url.trim_end_matches('/').into()),
                    );
                }
                if let Some(topics) = n.get("topics").and_then(|v| v.as_object()) {
                    let ntfy_topics = toml_table_mut(&mut cfg.toml, &["ntfy", "topics"]);
                    for sev in ["info", "warning", "critical"] {
                        if let Some(v) = topics.get(sev).and_then(|v| v.as_str()) {
                            ntfy_topics.insert(sev.into(), toml::Value::String(v.into()));
                        }
                    }
                }
            }
            if let Some(t) = payload.get("telegram").and_then(|v| v.as_object()) {
                let tg = toml_table_mut(&mut cfg.toml, &["telegram"]);
                if let Some(v) = t.get("chat_id").and_then(|v| v.as_str()) {
                    tg.insert("chat_id".into(), toml::Value::String(v.into()));
                }
                if let Some(v) = t.get("api_base").and_then(|v| v.as_str()) {
                    tg.insert(
                        "api_base".into(),
                        toml::Value::String(v.trim_end_matches('/').into()),
                    );
                }
                if let Some(v) = t
                    .get("bot_token")
                    .and_then(|v| v.as_str())
                    .filter(|v| *v != "***SET***")
                {
                    tg.insert("bot_token".into(), toml::Value::String(v.into()));
                }
            }
            if let Some(s) = payload.get("smtp").and_then(|v| v.as_object()) {
                let smtp = toml_table_mut(&mut cfg.toml, &["smtp"]);
                for k in ["host", "from_addr", "to_addr"] {
                    if let Some(v) = s.get(k).and_then(|v| v.as_str()) {
                        smtp.insert(k.into(), toml::Value::String(v.into()));
                    }
                }
                if let Some(v) = s.get("user").and_then(|v| v.as_str()) {
                    smtp.insert("user".into(), toml::Value::String(v.into()));
                }
                if let Some(v) = s
                    .get("password")
                    .and_then(|v| v.as_str())
                    .filter(|v| *v != "***SET***")
                {
                    smtp.insert("password".into(), toml::Value::String(v.into()));
                }
                if let Some(p) = s.get("port").and_then(|v| v.as_i64()) {
                    smtp.insert("port".into(), toml::Value::Integer(p));
                }
                if let Some(v) = s.get("starttls").and_then(|v| v.as_bool()) {
                    smtp.insert("starttls".into(), toml::Value::Boolean(v));
                }
            }
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true})))
                .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn update_delivery_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let delivery = toml_table_mut(&mut cfg.toml, &["delivery"]);
            if let Some(v) = payload.get("default_policy").and_then(|v| v.as_str()) {
                delivery.insert("default_policy".into(), toml::Value::String(v.into()));
            }
            if let Some(p) = payload.get("policies") {
                delivery.insert("policies".into(), json_to_toml(p.clone()));
            }
            if let Some(r) = payload.get("rules") {
                delivery.insert("rules".into(), json_to_toml(r.clone()));
            }
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true})))
                .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn update_inhibition_rules(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(arr) = payload.get("rules").and_then(|v| v.as_array()) else {
        return text(StatusCode::BAD_REQUEST, "rules must be a list");
    };
    let mut cleaned = Vec::new();
    let mut errors = Vec::new();
    for (i, r) in arr.iter().enumerate() {
        let source = r
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if source.is_empty() {
            errors.push(format!("rule[{i}]: source is required"));
            continue;
        }
        let ttl = r
            .get("ttl_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(900)
            .clamp(30, 86400);
        let match_types = (r
            .get("match_by")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .is_some() as u8)
            + (r.get("match_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false) as u8)
            + ((r
                .get("match_label")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .is_some()
                && r.get("match_regex")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .is_some()) as u8);
        if match_types == 0 {
            errors.push(format!("rule[{i}] ({source}): one of match_by / match_label+match_regex / match_all is required"));
            continue;
        }
        if match_types > 1 {
            errors.push(format!(
                "rule[{i}] ({source}): only one match type may be set"
            ));
            continue;
        }
        let rule = InhibitionRule {
            source,
            match_by: r
                .get("match_by")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            match_label: r
                .get("match_label")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            match_regex: r
                .get("match_regex")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            match_all: r
                .get("match_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            applies_to: r
                .get("applies_to")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                        .filter(|s| DEDUP_SOURCES.contains(&s.as_str()))
                        .collect()
                })
                .unwrap_or_default(),
            ttl_seconds: ttl,
        };
        if let Err(err) = inhibition::validate_regex(&rule) {
            errors.push(format!("rule[{i}] regex invalid: {err}"));
            continue;
        }
        cleaned.push(rule);
    }
    if !errors.is_empty() {
        return text(StatusCode::BAD_REQUEST, &errors.join("\n"));
    }
    match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        cfg.toml.as_table_mut().unwrap().insert(
            "inhibitions".into(),
            json_to_toml(serde_json::to_value(&cleaned).unwrap()),
        );
        persist_reload(state, cfg.toml)
    }) {
        Ok(Ok(())) => {}
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
    let cleared = {
        let mut s = lock_mutex(&state.suppressions, "suppressions");
        let c = s.len();
        s.clear();
        c
    };
    json_response(json!({"ok": true, "count": cleaned.len(), "cleared_suppressions": cleared}))
}

fn update_ingest_auth(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let src = payload
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let action = payload
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !DEDUP_SOURCES.contains(&src.as_str()) {
        return text(
            StatusCode::BAD_REQUEST,
            &format!("source must be one of {:?}", DEDUP_SOURCES),
        );
    }
    if !matches!(action.as_str(), "set" | "generate" | "clear") {
        return text(
            StatusCode::BAD_REQUEST,
            "action must be one of: set, generate, clear",
        );
    }
    if action == "set" {
        let sec = payload
            .get("secret")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if sec.len() < 16 {
            return text(
                StatusCode::BAD_REQUEST,
                "secret missing or shorter than 16 chars",
            );
        }
    }
    let new_secret = match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        let secrets = toml_table_mut(&mut cfg.toml, &["ingest", "secrets"]);
        let mut new_secret = None;
        match action.as_str() {
            "clear" => {
                secrets.remove(&src);
            }
            "generate" => {
                let sec = random_hex(32);
                secrets.insert(src.clone(), toml::Value::String(sec.clone()));
                new_secret = Some(sec);
            }
            _ => {
                let sec = payload
                    .get("secret")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                secrets.insert(src.clone(), toml::Value::String(sec.into()));
            }
        }
        persist_reload(state, cfg.toml).map(|_| new_secret)
    }) {
        Ok(Ok(new_secret)) => new_secret,
        Ok(Err(err)) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    let mut resp = json!({"ok": true, "source": src, "action": action});
    if let Some(sec) = new_secret {
        resp["secret"] = json!(sec);
    }
    json_response(resp)
}

fn update_schedules(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(arr) = payload.get("schedules").and_then(|v| v.as_array()) else {
        return text(StatusCode::BAD_REQUEST, "schedules must be a list");
    };
    let mut cleaned = Vec::<Schedule>::new();
    let mut errors = Vec::new();
    for (i, s) in arr.iter().enumerate() {
        let name = s
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let cron = s
            .get("cron")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if name.is_empty() {
            errors.push(format!("schedule[{i}]: name required"));
            continue;
        }
        if cron.split_whitespace().count() != 5 {
            errors.push(format!("schedule[{i}] ({name}): cron must have 5 fields"));
            continue;
        }
        let duration = s
            .get("duration_minutes")
            .and_then(|v| v.as_u64())
            .unwrap_or(30);
        if !(1..=1440).contains(&duration) {
            errors.push(format!(
                "schedule[{i}] ({name}): duration_minutes must be 1..1440"
            ));
            continue;
        }
        let m = s
            .get("match")
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| {
                        v.as_str()
                            .filter(|s| !s.is_empty())
                            .map(|s| (k.clone(), s.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let applies_to = s
            .get("applies_to")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .filter(|s| DEDUP_SOURCES.contains(&s.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        cleaned.push(Schedule {
            name,
            cron,
            duration_minutes: duration,
            r#match: m,
            applies_to,
        });
    }
    if !errors.is_empty() {
        return text(StatusCode::BAD_REQUEST, &errors.join("\n"));
    }
    match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        cfg.toml.as_table_mut().unwrap().insert(
            "schedules".into(),
            json_to_toml(serde_json::to_value(&cleaned).unwrap()),
        );
        persist_reload(state, cfg.toml)
    }) {
        Ok(Ok(())) => {}
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
    {
        let mut active = lock_mutex(&state.active_mutes, "active mutes");
        let names = cleaned
            .iter()
            .map(|s| s.name.clone())
            .collect::<std::collections::HashSet<_>>();
        active.retain(|k, _| names.contains(k));
    }
    json_response(json!({"ok": true, "count": cleaned.len()}))
}

fn clear_acks(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let target = payload
        .get("alertname")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let mut acks = lock_mutex(&state.ack_suppressions, "ack suppressions");
    let before = acks.len();
    if target.is_empty() {
        acks.clear();
    } else {
        acks.remove(&target);
    }
    let after = acks.len();
    json_response(json!({"ok": true, "cleared": before - after, "remaining": after}))
}

fn clear_inhibitions(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let clear_all = payload.as_object().map(|o| o.is_empty()).unwrap_or(true)
        || payload
            .get("all")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    let source = payload
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let anchor = payload
        .get("anchor")
        .and_then(|v| v.as_str())
        .map(|s| if s == "*" { None } else { Some(s.to_string()) })
        .unwrap_or(None);
    let cfg = state.cfg();
    let mut suppressions = lock_mutex(&state.suppressions, "suppressions");
    let before = suppressions.len();
    if clear_all {
        suppressions.clear();
    } else {
        if source.is_empty() {
            return text(
                StatusCode::BAD_REQUEST,
                "source is required (or pass {'all': true})",
            );
        }
        suppressions.retain(|s| {
            let rule = cfg.inhibition_rules.get(s.rule_idx);
            !(rule.map(|r| r.source == source).unwrap_or(false)
                && (anchor.is_none() || s.anchor == anchor))
        });
    }
    let after = suppressions.len();
    json_response(json!({"ok": true, "cleared": before - after, "remaining": after}))
}

fn inhibition_rules_test(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let source = payload
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if source.is_empty() {
        return text(StatusCode::BAD_REQUEST, "source is required");
    }
    let labels = payload
        .get("labels")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), crate::parsers::scalar_to_string(v)))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    let cfg = state.cfg();
    let considered = cfg
        .inhibition_rules
        .iter()
        .filter(|r| r.applies_to.is_empty() || r.applies_to.contains(&source))
        .map(|r| r.source.clone())
        .collect::<Vec<_>>();
    let arm_idx = if source == "grafana" {
        inhibition::alert_is_source(&labels, &cfg.inhibition_rules)
    } else {
        None
    };
    let suppressed = inhibition::is_suppressed(state, &labels, &source);
    let (would_send, reason, matched) = if let Some(idx) = arm_idx {
        (
            true,
            "source".to_string(),
            cfg.inhibition_rules.get(idx).map(|r| r.source.clone()),
        )
    } else if let Some(s) = suppressed {
        (false, format!("inhibited-by-{s}"), Some(s))
    } else {
        (true, "ok".to_string(), None)
    };
    json_response(
        json!({"would_send": would_send, "reason": reason, "matched_rule": matched, "would_arm_suppression": arm_idx.is_some(), "considered_rules": considered}),
    )
}

fn policy_simulate(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let source = payload
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("grafana")
        .trim()
        .to_ascii_lowercase();
    if !DEDUP_SOURCES.contains(&source.as_str()) {
        return text(StatusCode::BAD_REQUEST, "unknown source");
    }
    let severity = payload
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("warning")
        .trim()
        .to_ascii_lowercase();
    let mut labels = payload
        .get("payload")
        .map(|body| normalize_labels(&source, body))
        .unwrap_or_else(|| {
            HashMap::from([
                ("source".to_string(), source.clone()),
                ("status".to_string(), "firing".to_string()),
            ])
        });
    if let Some(obj) = payload.get("labels").and_then(Value::as_object) {
        for (key, value) in obj {
            labels.insert(key.clone(), crate::parsers::scalar_to_string(value));
        }
    }
    labels.insert("severity".into(), severity.clone());

    let (would_send, reason) = inhibition::apply_inhibition(state, &source, &labels, true);
    let cfg = state.cfg();
    let considered = cfg
        .inhibition_rules
        .iter()
        .filter(|rule| rule.applies_to.is_empty() || rule.applies_to.contains(&source))
        .map(|rule| rule.source.clone())
        .collect::<Vec<_>>();
    let arm_idx = if source == "grafana" {
        inhibition::alert_is_source(&labels, &cfg.inhibition_rules)
    } else {
        None
    };
    let matched_rule = if let Some(idx) = arm_idx {
        cfg.inhibition_rules
            .get(idx)
            .map(|rule| rule.source.clone())
    } else {
        reason
            .strip_prefix("inhibited-by-")
            .map(ToOwned::to_owned)
            .or_else(|| {
                reason
                    .strip_prefix("scheduled-mute-")
                    .map(ToOwned::to_owned)
            })
            .or_else(|| reason.strip_prefix("ack-snoozed-").map(ToOwned::to_owned))
    };
    let (policy, matched_by) = pick_policy(&cfg, &labels);
    let defaults = default_dedup();
    let dedup = cfg
        .dedup
        .get(&source)
        .or_else(|| defaults.get(&source))
        .cloned();
    json_response(json!({
        "source": source,
        "severity": severity,
        "labels": labels,
        "inhibition": {
            "would_send": would_send,
            "reason": reason,
            "matched_rule": matched_rule,
            "would_arm_suppression": arm_idx.is_some(),
            "considered_rules": considered,
        },
        "delivery": {
            "policy": policy.name,
            "mode": policy.mode,
            "matched_by": matched_by,
            "tiers": policy.tiers,
        },
        "dedup": dedup.map(|d| json!({
            "enabled": d.enabled,
            "window_s": d.window_s,
            "strategy": d.strategy,
            "override_critical": d.override_critical,
        })).unwrap_or_else(|| json!({
            "enabled": false,
            "window_s": 0,
            "strategy": "none",
            "override_critical": false,
        })),
    }))
}

fn verify_ingest_auth(
    state: &AppState,
    source: &str,
    headers: &HeaderMap,
    qs: &HashMap<String, String>,
) -> (bool, String) {
    let secret = ingest_secret_for(state, source);
    if secret.is_empty() {
        return (true, "no-secret".into());
    }
    if let Some(auth) = headers.get("Authorization").and_then(|v| v.to_str().ok())
        && let Some((scheme, tok)) = auth.split_once(char::is_whitespace)
        && scheme.eq_ignore_ascii_case("bearer")
        && constant_time_eq::constant_time_eq(tok.trim().as_bytes(), secret.as_bytes())
    {
        return (true, "bearer".into());
    }
    if let Some(tok) = headers.get("X-Klaxond-Token").and_then(|v| v.to_str().ok())
        && constant_time_eq::constant_time_eq(tok.trim().as_bytes(), secret.as_bytes())
    {
        return (true, "x-klaxond-token".into());
    }
    if let Some(tok) = qs.get("token")
        && constant_time_eq::constant_time_eq(tok.as_bytes(), secret.as_bytes())
    {
        return (true, "query".into());
    }
    (false, "secret-required-but-missing-or-mismatch".into())
}

fn ingest_secret_for(state: &AppState, source: &str) -> String {
    let env_key = format!("KLAXOND_INGEST_SECRET_{}", source.to_ascii_uppercase());
    let env_val = env_string(&env_key);
    if !env_val.trim().is_empty() {
        return env_val.trim().into();
    }
    state
        .cfg()
        .toml
        .get("ingest")
        .and_then(|v| v.get("secrets"))
        .and_then(|v| v.get(source))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn ingest_auth_payload(state: &AppState) -> Value {
    let mut sources = serde_json::Map::new();
    for src in DEDUP_SOURCES {
        let env_val = env_string(&format!(
            "KLAXOND_INGEST_SECRET_{}",
            src.to_ascii_uppercase()
        ));
        let toml_val = state
            .cfg()
            .toml
            .get("ingest")
            .and_then(|v| v.get("secrets"))
            .and_then(|v| v.get(*src))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        sources.insert(
            (*src).into(),
            if !env_val.trim().is_empty() {
                json!({"configured": true, "from": "env"})
            } else if !toml_val.trim().is_empty() {
                json!({"configured": true, "from": "toml"})
            } else {
                json!({"configured": false, "from": ""})
            },
        );
    }
    json!({
        "sources": sources,
        "auth_methods_accepted": ["Authorization: Bearer <secret>", "X-Klaxond-Token: <secret>", "?token=<secret> query param"],
        "note": "Legacy permissive mode (no auth required) is in effect when a source has no secret configured.",
    })
}

fn ack_response(state: &AppState, path: &str) -> Response<Body> {
    let token = path
        .trim_start_matches("/api/ack/")
        .split('?')
        .next()
        .unwrap_or("");
    let (alertname, reason) = inhibition::ack_verify(state, token);
    let Some(alertname) = alertname else {
        return html(
            StatusCode::BAD_REQUEST,
            &format!("<html><body><h2>Ack rejected</h2><p>{reason}</p></body></html>"),
        );
    };
    let ttl = state.cfg().ack_default_ttl;
    inhibition::register_ack_suppression(state, &alertname, ttl);
    html(
        StatusCode::OK,
        &format!(
            "<html><body style='font-family:system-ui,sans-serif;padding:2em;max-width:480px;margin:auto'><h2 style='color:#22c55e'>✓ Snooze armed</h2><p>Alerts with <code style='background:#eee;padding:0.1em 0.4em;border-radius:3px'>alertname={alertname}</code> are silenced for the next <b>{} minutes</b>.</p><p style='color:#666;font-size:0.9em'>This page can be closed. The snooze auto-expires; you'll get the next occurrence when the condition recurs.</p></body></html>",
            ttl / 60
        ),
    )
}

fn json_body(body: &Bytes) -> Result<Value, serde_json::Error> {
    if body.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(body)
    }
}

fn parse_query(full_path: &str) -> HashMap<String, String> {
    let query = full_path.split_once('?').map(|(_, q)| q).unwrap_or("");
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn json_to_toml(v: Value) -> toml::Value {
    match v {
        Value::Null => toml::Value::String(String::new()),
        Value::Bool(b) => toml::Value::Boolean(b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else {
                toml::Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => toml::Value::String(s),
        Value::Array(a) => toml::Value::Array(a.into_iter().map(json_to_toml).collect()),
        Value::Object(o) => {
            toml::Value::Table(o.into_iter().map(|(k, v)| (k, json_to_toml(v))).collect())
        }
    }
}

fn json_response<T: serde::Serialize>(value: T) -> Response<Body> {
    let body = serde_json::to_vec_pretty(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap()
}

fn text(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn html(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn redirect(location: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Body::empty())
        .unwrap()
}
