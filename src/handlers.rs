use crate::auth::{self, AuthOutcome, User};
use crate::config::{
    AuthConfig, AuthToken, DEDUP_SOURCES, DedupSetting, InhibitionRule, NtfyTopic, PasskeyRecord,
    RuntimeConfig, Schedule, default_dedup, default_tiers, load_runtime_config,
    restore_sidecars_from_toml, save_auth, save_dedup, save_ntfy_topics, save_render_config,
    save_toml,
};
use crate::dedup;
use crate::delivery::deliver;
use crate::inhibition;
use crate::log_buffer;
use crate::parsers::{
    Parts, normalize_labels, parse_beszel_payload, parse_grafana_payload,
    parse_healthchecks_payload, parse_source, parse_wud_payload,
};
use crate::state::{
    AppState, PendingPasskeyAuthentication, PendingPasskeyRegistration, esc_label, lock_mutex,
};
use crate::util::{atomic_write, env_string, random_hex, token_urlsafe, toml_table_mut};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, SET_COOKIE,
};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;
use url::{Url, form_urlencoded};
use webauthn_rs::prelude::{
    CredentialID, Passkey, PublicKeyCredential, RegisterPublicKeyCredential, Uuid, Webauthn,
    WebauthnBuilder,
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

    if method == Method::GET && path.starts_with("/auth/login") {
        return auth::login(&state, headers, &full_path).await;
    }
    if method == Method::GET && path.starts_with("/auth/callback") {
        return auth::oidc_callback(&state, headers, &full_path).await;
    }
    if method == Method::GET && path.starts_with("/auth/logout") {
        return auth::logout(&headers);
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

    let mut resp = match method {
        Method::GET => handle_get(&state, &path, &full_path, authed_user).await,
        Method::POST => {
            handle_post(&state, &path, &full_path, &headers, body, peer, authed_user).await
        }
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
    authed_user: Option<User>,
) -> Response<Body> {
    match path {
        "/healthz" => text(StatusCode::OK, "OK"),
        "/metrics" => metrics_response(state),
        "/" | "/ui" | "/ui/" => redirect("/ui/status"),
        "/inhibitions" | "/api/inhibitions" => json_response(inhibition::inhibition_status(state)),
        "/api/status" => json_response(status_payload(state).await),
        "/api/deliveries" => json_response(state.recent_deliveries()),
        "/api/logs" => json_response(logs_payload(full_path)),
        "/api/render-config" => {
            let cfg = state.cfg();
            json_response(
                json!({"component_dashboards": cfg.component_dashboards, "grafana_base": cfg.grafana_base}),
            )
        }
        "/api/cascade-config" => {
            let cfg = state.cfg();
            json_response(json!({
                "tiers": cfg.tiers,
                "default_enabled_for_webhook": cfg.cascade_default,
                "runtime_enabled": state.cascade_runtime_enabled.load(Ordering::Relaxed),
            }))
        }
        "/api/auth-config" => {
            let mut settings = serde_json::to_value(state.cfg().auth).unwrap_or_else(|_| json!({}));
            if !settings
                .get("basic")
                .and_then(|b| b.get("password_hash"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
            {
                settings["basic"]["password_hash"] = json!("***SET***");
            }
            if !settings
                .get("oidc")
                .and_then(|b| b.get("client_secret"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
            {
                settings["oidc"]["client_secret"] = json!("***SET***");
            }
            let cfg = state.cfg();
            settings["api_keys"] = json!(
                cfg.auth
                    .api_keys
                    .iter()
                    .map(auth::public_token)
                    .collect::<Vec<_>>()
            );
            settings["passkeys"] = json!(
                cfg.auth
                    .passkeys
                    .iter()
                    .map(public_passkey)
                    .collect::<Vec<_>>()
            );
            json_response(json!({
                "settings": settings,
                "available_modes": ["none", "basic", "oidc", "trusted-proxy"],
                "available_token_scopes": auth::TOKEN_SCOPES,
                "bcrypt_available": true,
                "jwt_available": true,
                "current_user": authed_user.unwrap_or(User { sub: "anonymous".into(), email: String::new(), name: String::new(), groups: vec![], mode: "none".into(), exp: 0 }),
            }))
        }
        "/api/auth/tokens" => {
            let cfg = state.cfg();
            json_response(json!({
                "tokens": cfg.auth.api_keys.iter().map(auth::public_token).collect::<Vec<_>>(),
                "available_scopes": auth::TOKEN_SCOPES,
            }))
        }
        "/api/auth/passkeys" => {
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
        "/auth/me" => json_response(authed_user.unwrap_or(User {
            sub: "anonymous".into(),
            email: String::new(),
            name: String::new(),
            groups: vec![],
            mode: "none".into(),
            exp: 0,
        })),
        "/auth/passkey" | "/auth/passkey/" => passkey_login_page(),
        _ if path.starts_with("/img/") => image_response(state, path),
        _ if path.starts_with("/ui/") => ui_response(state, path.trim_start_matches("/ui/")),
        _ if path.starts_with("/api/ack/") => ack_response(state, path),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
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
    match path {
        "/auth/passkey/start" => passkey_login_start(state, body),
        "/auth/passkey/finish" => passkey_login_finish(state, body),
        "/api/auth-config" => update_auth_config(state, body, authed_user.as_ref(), peer, headers),
        "/api/auth/tokens" => create_auth_token(state, body),
        "/api/auth/tokens/revoke" => revoke_auth_token(state, body),
        "/api/auth/passkeys/register/start" => {
            passkey_register_start(state, body, authed_user.as_ref())
        }
        "/api/auth/passkeys/register/finish" => passkey_register_finish(state, body),
        "/api/auth/passkeys/delete" => passkey_delete(state, body, authed_user.as_ref()),
        "/api/cascade/toggle" => cascade_toggle(state, body),
        "/api/render-config" => update_render_config(state, body),
        "/api/cascade-config" => update_cascade_config(state, body),
        "/api/channel-config" => update_channel_config(state, body),
        "/api/delivery-config" => update_delivery_config(state, body),
        "/api/render-preview" => render_preview(state, body),
        "/api/dedup-config" => update_dedup_config(state, body),
        "/api/ntfy-topics" => update_ntfy_topics(state, body),
        "/api/inhibition-rules" => update_inhibition_rules(state, body),
        "/api/config/restore" => restore_config(state, body),
        "/api/ingest-auth" => update_ingest_auth(state, body),
        "/api/schedules" => update_schedules(state, body),
        "/api/acks/clear" => clear_acks(state, body),
        "/api/inhibitions/clear" => clear_inhibitions(state, body),
        "/api/inhibition-rules/test" => inhibition_rules_test(state, body),
        _ if path.starts_with("/api/test/") => api_test(state, path, body).await,
        _ => ingest(state, path, full_path, headers, body, peer).await,
    }
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
    state.log_delivery(
        "api-test",
        &severity,
        &parts.title,
        if ok { &channel } else { "all-failed" },
        "",
    );
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
            if let Err(err) = save_render_config(&state.paths, &cleaned) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            let mut cfg = state.cfg();
            cfg.component_dashboards = cleaned.clone();
            state.replace_config(cfg);
            json_response(json!({"ok": true, "count": cleaned.len()}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
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
            Ok(cfg) => state.replace_config(cfg),
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

fn validate_auth_config(
    auth: &AuthConfig,
    current_user: Option<&User>,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), String> {
    match auth.mode.as_str() {
        "none" => Ok(()),
        "basic" => {
            if auth.basic.username.trim().is_empty() {
                return Err("basic auth requires a username".into());
            }
            if auth.basic.password_hash.trim().is_empty() {
                return Err("basic auth requires a password before it can be enabled".into());
            }
            Ok(())
        }
        "oidc" => {
            if auth.oidc.issuer.trim().is_empty() || auth.oidc.client_id.trim().is_empty() {
                return Err("OIDC requires issuer and client_id before it can be enabled".into());
            }
            if auth.oidc.redirect_path != "/auth/callback" {
                return Err("OIDC redirect_path must be /auth/callback".into());
            }
            if let Some(user) = current_user
                && !auth.oidc.required_group.trim().is_empty()
                && user.mode == "oidc"
                && !user.groups.iter().any(|g| g == &auth.oidc.required_group)
            {
                return Err(format!(
                    "current OIDC user is not in required_group '{}'",
                    auth.oidc.required_group
                ));
            }
            Ok(())
        }
        "trusted-proxy" => {
            if auth.trusted_proxy.user_header.trim().is_empty() {
                return Err("trusted-proxy requires a user header".into());
            }
            if auth.trusted_proxy.trusted_cidrs.is_empty() {
                return Err("trusted-proxy requires at least one trusted CIDR".into());
            }
            for cidr in &auth.trusted_proxy.trusted_cidrs {
                cidr.parse::<IpNet>()
                    .map_err(|_| format!("invalid trusted CIDR '{cidr}'"))?;
            }
            if !cidr_match(peer.ip(), &auth.trusted_proxy.trusted_cidrs) {
                return Err(format!(
                    "current peer {} is not covered by trusted_proxy.trusted_cidrs",
                    peer.ip()
                ));
            }
            if headers
                .get(auth.trusted_proxy.user_header.as_str())
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.trim().is_empty())
                .is_none()
            {
                return Err(format!(
                    "current request is missing trusted proxy user header '{}'",
                    auth.trusted_proxy.user_header
                ));
            }
            Ok(())
        }
        _ => Err("invalid mode".into()),
    }
}

fn cidr_match(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}

fn update_auth_config(
    state: &AppState,
    body: Bytes,
    current_user: Option<&User>,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(incoming) = payload.get("settings") else {
        return text(StatusCode::BAD_REQUEST, "missing 'settings' object");
    };
    state
        .with_config_write_lock(|| {
            let mut auth = state.cfg().auth;
            if let Some(mode) = incoming.get("mode").and_then(|v| v.as_str()) {
                if !matches!(mode, "none" | "basic" | "oidc" | "trusted-proxy") {
                    return text(StatusCode::BAD_REQUEST, "invalid mode");
                }
                auth.mode = mode.into();
            }
            if let Some(h) = incoming
                .get("session_timeout_hours")
                .and_then(|v| v.as_u64())
            {
                auth.session_timeout_hours = h.clamp(1, 720);
            }
            if let Some(b) = incoming.get("basic").and_then(|v| v.as_object()) {
                if let Some(v) = b.get("username").and_then(|v| v.as_str()) {
                    auth.basic.username = v.into();
                }
                if let Some(v) = b.get("realm").and_then(|v| v.as_str()) {
                    auth.basic.realm = v.into();
                }
                if let Some(pwd) = b
                    .get("password")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    match bcrypt::hash(pwd, bcrypt::DEFAULT_COST) {
                        Ok(h) => auth.basic.password_hash = h,
                        Err(err) => {
                            return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
                        }
                    }
                } else if let Some(h) = b
                    .get("password_hash")
                    .and_then(|v| v.as_str())
                    .filter(|s| *s != "***SET***" && !s.is_empty())
                {
                    auth.basic.password_hash = h.into();
                }
            }
            if let Some(o) = incoming.get("oidc").and_then(|v| v.as_object()) {
                for (k, slot) in [
                    ("provider", &mut auth.oidc.provider),
                    ("issuer", &mut auth.oidc.issuer),
                    ("client_id", &mut auth.oidc.client_id),
                    ("scopes", &mut auth.oidc.scopes),
                    ("required_group", &mut auth.oidc.required_group),
                    ("redirect_path", &mut auth.oidc.redirect_path),
                ] {
                    if let Some(v) = o.get(k).and_then(|v| v.as_str()) {
                        *slot = v.into();
                    }
                }
                if let Some(v) = o
                    .get("client_secret")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && *s != "***SET***")
                {
                    auth.oidc.client_secret = v.into();
                }
            }
            if let Some(tp) = incoming.get("trusted_proxy").and_then(|v| v.as_object()) {
                if let Some(v) = tp.get("user_header").and_then(|v| v.as_str()) {
                    auth.trusted_proxy.user_header = v.into();
                }
                if let Some(v) = tp.get("email_header").and_then(|v| v.as_str()) {
                    auth.trusted_proxy.email_header = v.into();
                }
                if let Some(v) = tp.get("groups_header").and_then(|v| v.as_str()) {
                    auth.trusted_proxy.groups_header = v.into();
                }
                if let Some(arr) = tp.get("trusted_cidrs").and_then(|v| v.as_array()) {
                    auth.trusted_proxy.trusted_cidrs = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                        .collect();
                }
            }
            if let Some(w) = incoming.get("webauthn").and_then(|v| v.as_object()) {
                if let Some(v) = w.get("enabled").and_then(|v| v.as_bool()) {
                    auth.webauthn.enabled = v;
                }
                if let Some(v) = w.get("rp_id").and_then(|v| v.as_str()) {
                    auth.webauthn.rp_id = v.trim().to_string();
                }
                if let Some(v) = w.get("origin").and_then(|v| v.as_str()) {
                    auth.webauthn.origin = v.trim().trim_end_matches('/').to_string();
                }
            }
            if let Err(err) = validate_auth_config(&auth, current_user, peer, headers) {
                return text(StatusCode::BAD_REQUEST, &err);
            }
            if let Err(err) = save_auth(&state.paths, &auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            let mut cfg = state.cfg();
            cfg.auth = auth;
            let mut redacted = serde_json::to_value(&cfg.auth).unwrap();
            if !redacted["basic"]["password_hash"]
                .as_str()
                .unwrap_or("")
                .is_empty()
            {
                redacted["basic"]["password_hash"] = json!("***SET***");
            }
            if !redacted["oidc"]["client_secret"]
                .as_str()
                .unwrap_or("")
                .is_empty()
            {
                redacted["oidc"]["client_secret"] = json!("***SET***");
            }
            redacted["api_keys"] = json!(
                cfg.auth
                    .api_keys
                    .iter()
                    .map(auth::public_token)
                    .collect::<Vec<_>>()
            );
            redacted["passkeys"] = json!(
                cfg.auth
                    .passkeys
                    .iter()
                    .map(public_passkey)
                    .collect::<Vec<_>>()
            );
            state.replace_config(cfg);
            json_response(json!({"ok": true, "settings": redacted}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn create_auth_token(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return text(StatusCode::BAD_REQUEST, "token name is required");
    }
    let kind = payload
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("api-key")
        .trim();
    if !matches!(kind, "api-key" | "pat") {
        return text(StatusCode::BAD_REQUEST, "kind must be api-key or pat");
    }
    let scopes = payload
        .get("scopes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if scopes.is_empty() {
        return text(StatusCode::BAD_REQUEST, "at least one scope is required");
    }
    for scope in &scopes {
        if !auth::TOKEN_SCOPES.contains(&scope.as_str()) {
            return text(StatusCode::BAD_REQUEST, &format!("invalid scope '{scope}'"));
        }
    }
    let now = crate::util::now_epoch_i64();
    let expires_at = payload
        .get("expires_in_days")
        .and_then(|v| v.as_u64())
        .filter(|days| *days > 0)
        .map(|days| now + (days.min(3650) * 86_400) as i64)
        .or_else(|| {
            payload
                .get("expires_at")
                .and_then(|v| v.as_i64())
                .filter(|v| *v > now)
        });
    let token = format!(
        "klx_{}_{}",
        if kind == "pat" { "pat" } else { "key" },
        token_urlsafe(32)
    );
    let record = AuthToken {
        id: random_hex(8),
        name: name.to_string(),
        kind: kind.to_string(),
        prefix: token.chars().take(18).collect(),
        token_hash: auth::token_hash(&token),
        scopes,
        created_at: now,
        expires_at,
        last_used_at: None,
        enabled: true,
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            cfg.auth.api_keys.push(record.clone());
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({
                "ok": true,
                "token": token,
                "record": auth::public_token(&record),
            }))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn revoke_auth_token(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "token id is required");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let mut changed = false;
            for token in &mut cfg.auth.api_keys {
                if token.id == id {
                    token.enabled = false;
                    changed = true;
                }
            }
            if !changed {
                return text(StatusCode::NOT_FOUND, "token not found");
            }
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn webauthn_for_cfg(cfg: &RuntimeConfig) -> Result<Webauthn, String> {
    if !cfg.auth.webauthn.enabled {
        return Err("WebAuthn/passkeys are disabled".into());
    }
    let origin = if cfg.auth.webauthn.origin.trim().is_empty() {
        cfg.public_url.trim_end_matches('/').to_string()
    } else {
        cfg.auth.webauthn.origin.trim_end_matches('/').to_string()
    };
    let url = Url::parse(&origin).map_err(|err| format!("invalid WebAuthn origin: {err}"))?;
    let rp_id = if cfg.auth.webauthn.rp_id.trim().is_empty() {
        url.domain()
            .ok_or_else(|| "WebAuthn origin must have a domain host".to_string())?
            .to_string()
    } else {
        cfg.auth.webauthn.rp_id.trim().to_string()
    };
    WebauthnBuilder::new(&rp_id, &url)
        .map_err(|err| format!("invalid WebAuthn relying party: {err}"))?
        .rp_name("klaxond")
        .allow_any_port(matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1")
        ))
        .build()
        .map_err(|err| format!("invalid WebAuthn config: {err}"))
}

fn webauthn_public_config(cfg: &RuntimeConfig) -> Value {
    let origin = if cfg.auth.webauthn.origin.trim().is_empty() {
        cfg.public_url.trim_end_matches('/').to_string()
    } else {
        cfg.auth.webauthn.origin.trim_end_matches('/').to_string()
    };
    let rp_id = if cfg.auth.webauthn.rp_id.trim().is_empty() {
        Url::parse(&origin)
            .ok()
            .and_then(|url| url.domain().map(ToOwned::to_owned))
            .unwrap_or_default()
    } else {
        cfg.auth.webauthn.rp_id.clone()
    };
    json!({
        "enabled": cfg.auth.webauthn.enabled,
        "rp_id": rp_id,
        "origin": origin,
    })
}

fn public_passkey(record: &PasskeyRecord) -> Value {
    json!({
        "id": record.id,
        "name": record.name,
        "user_sub": record.user_sub,
        "user_name": record.user_name,
        "user_email": record.user_email,
        "created_at": record.created_at,
        "last_used_at": record.last_used_at,
    })
}

fn passkey_register_start(
    state: &AppState,
    body: Bytes,
    current_user: Option<&User>,
) -> Response<Body> {
    let Some(user) = current_user.filter(|u| u.sub != "anonymous") else {
        return text(
            StatusCode::FORBIDDEN,
            "passkey registration requires a logged-in user",
        );
    };
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let label = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("passkey")
        .trim()
        .chars()
        .take(80)
        .collect::<String>();
    let cfg = state.cfg();
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let excludes = cfg
        .auth
        .passkeys
        .iter()
        .filter(|p| p.user_sub == user.sub)
        .map(|p| p.credential.cred_id().clone())
        .collect::<Vec<CredentialID>>();
    let user_uuid = Uuid::new_v4();
    let display_name = if user.name.is_empty() {
        user.sub.as_str()
    } else {
        user.name.as_str()
    };
    let (challenge, reg_state) = match webauthn.start_passkey_registration(
        user_uuid,
        &user.sub,
        display_name,
        (!excludes.is_empty()).then_some(excludes),
    ) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    let request_id = random_hex(16);
    {
        let mut pending = lock_mutex(&state.passkey_registrations, "passkey registrations");
        let cutoff = crate::util::now_epoch() - 600.0;
        pending.retain(|_, v| v.ts >= cutoff);
        pending.insert(
            request_id.clone(),
            PendingPasskeyRegistration {
                ts: crate::util::now_epoch(),
                user_sub: user.sub.clone(),
                user_name: user.name.clone(),
                user_email: user.email.clone(),
                user_uuid,
                label: if label.is_empty() {
                    "passkey".into()
                } else {
                    label
                },
                state: reg_state,
            },
        );
    }
    json_response(json!({"ok": true, "request_id": request_id, "publicKey": challenge.public_key}))
}

fn passkey_register_finish(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let request_id = payload
        .get("request_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(credential_value) = payload.get("credential") else {
        return text(StatusCode::BAD_REQUEST, "missing credential");
    };
    let credential: RegisterPublicKeyCredential =
        match serde_json::from_value(credential_value.clone()) {
            Ok(v) => v,
            Err(err) => return text(StatusCode::BAD_REQUEST, &format!("bad credential: {err}")),
        };
    let pending = {
        let mut pending = lock_mutex(&state.passkey_registrations, "passkey registrations");
        match pending.remove(request_id) {
            Some(v) => v,
            None => {
                return text(
                    StatusCode::BAD_REQUEST,
                    "unknown or expired passkey request",
                );
            }
        }
    };
    let cfg = state.cfg();
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let passkey = match webauthn.finish_passkey_registration(&credential, &pending.state) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            if cfg
                .auth
                .passkeys
                .iter()
                .any(|record| record.credential.cred_id() == passkey.cred_id())
            {
                return text(StatusCode::CONFLICT, "passkey already registered");
            }
            let record = PasskeyRecord {
                id: random_hex(8),
                name: pending.label,
                user_sub: pending.user_sub,
                user_name: pending.user_name,
                user_email: pending.user_email,
                user_uuid: pending.user_uuid.to_string(),
                created_at: crate::util::now_epoch_i64(),
                last_used_at: None,
                credential: passkey,
            };
            cfg.auth.passkeys.push(record.clone());
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true, "passkey": public_passkey(&record)}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn passkey_login_start(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let user_hint = payload
        .get("user")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if user_hint.is_empty() {
        return text(StatusCode::BAD_REQUEST, "user is required");
    }
    let cfg = state.cfg();
    let matching = cfg
        .auth
        .passkeys
        .iter()
        .filter(|record| {
            [
                record.user_sub.as_str(),
                record.user_name.as_str(),
                record.user_email.as_str(),
            ]
            .iter()
            .any(|v| v.to_ascii_lowercase() == user_hint)
        })
        .cloned()
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return text(StatusCode::NOT_FOUND, "no passkey registered for that user");
    }
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let creds = matching
        .iter()
        .map(|record| record.credential.clone())
        .collect::<Vec<Passkey>>();
    let (challenge, auth_state) = match webauthn.start_passkey_authentication(&creds) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    let request_id = random_hex(16);
    {
        let mut pending = lock_mutex(&state.passkey_authentications, "passkey authentications");
        let cutoff = crate::util::now_epoch() - 600.0;
        pending.retain(|_, v| v.ts >= cutoff);
        pending.insert(
            request_id.clone(),
            PendingPasskeyAuthentication {
                ts: crate::util::now_epoch(),
                user_sub: matching[0].user_sub.clone(),
                state: auth_state,
            },
        );
    }
    json_response(json!({"ok": true, "request_id": request_id, "publicKey": challenge.public_key}))
}

fn passkey_login_finish(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let request_id = payload
        .get("request_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(credential_value) = payload.get("credential") else {
        return text(StatusCode::BAD_REQUEST, "missing credential");
    };
    let credential: PublicKeyCredential = match serde_json::from_value(credential_value.clone()) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &format!("bad credential: {err}")),
    };
    let pending = {
        let mut pending = lock_mutex(&state.passkey_authentications, "passkey authentications");
        match pending.remove(request_id) {
            Some(v) => v,
            None => {
                return text(
                    StatusCode::BAD_REQUEST,
                    "unknown or expired passkey request",
                );
            }
        }
    };
    let cfg = state.cfg();
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let result = match webauthn.finish_passkey_authentication(&credential, &pending.state) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::UNAUTHORIZED, &err.to_string()),
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let now = crate::util::now_epoch_i64();
            let mut matched_idx = None;
            for (idx, record) in cfg.auth.passkeys.iter_mut().enumerate() {
                if record.user_sub == pending.user_sub
                    && record.credential.update_credential(&result).is_some()
                {
                    matched_idx = Some(idx);
                    break;
                }
            }
            let Some(idx) = matched_idx else {
                return text(StatusCode::UNAUTHORIZED, "passkey credential not found");
            };
            let record = &mut cfg.auth.passkeys[idx];
            record.last_used_at = Some(now);
            let mut user = User {
                sub: record.user_sub.clone(),
                email: record.user_email.clone(),
                name: record.user_name.clone(),
                groups: vec!["passkey".into()],
                mode: "passkey".into(),
                exp: 0,
            };
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            let cookie = auth::issue_session_cookie(state, &mut user);
            let mut resp = json_response(json!({"ok": true, "user": user}));
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                resp.headers_mut().insert(SET_COOKIE, value);
            }
            resp
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn passkey_delete(state: &AppState, body: Bytes, current_user: Option<&User>) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "passkey id is required");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let before = cfg.auth.passkeys.len();
            cfg.auth.passkeys.retain(|record| {
                if record.id != id {
                    return true;
                }
                if let Some(user) = current_user
                    && user.mode == "passkey"
                    && user.sub != record.user_sub
                {
                    return true;
                }
                false
            });
            if cfg.auth.passkeys.len() == before {
                return text(StatusCode::NOT_FOUND, "passkey not found");
            }
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn passkey_login_page() -> Response<Body> {
    let html = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>klaxond passkey login</title><link rel="stylesheet" href="/ui/style.css"></head>
<body><main class="passkey-login"><section class="card"><h1>klaxond</h1><h2>Passkey login</h2>
<label>User, email or subject <input id="user" autocomplete="username webauthn"></label>
<button id="login" class="primary">Use passkey</button><p id="status" class="muted"></p>
<p><a href="/ui/status">Back to UI</a></p></section></main>
<script>
const b64uToBuf=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');s+='==='.slice((s.length+3)%4);const b=atob(s);const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer};
const bufToB64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function publicKeyGetOptions(pk){pk.challenge=b64uToBuf(pk.challenge);(pk.allowCredentials||[]).forEach(c=>c.id=b64uToBuf(c.id));return pk}
function credentialGetPayload(c){return {id:c.id,rawId:bufToB64u(c.rawId),type:c.type,response:{authenticatorData:bufToB64u(c.response.authenticatorData),clientDataJSON:bufToB64u(c.response.clientDataJSON),signature:bufToB64u(c.response.signature),userHandle:c.response.userHandle?bufToB64u(c.response.userHandle):null},extensions:c.getClientExtensionResults?c.getClientExtensionResults():{}}}
document.getElementById('login').onclick=async()=>{const s=document.getElementById('status');try{const user=document.getElementById('user').value.trim();const a=await fetch('/auth/passkey/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({user})});if(!a.ok)throw new Error(await a.text());const ch=await a.json();const cred=await navigator.credentials.get({publicKey:publicKeyGetOptions(ch.publicKey)});const f=await fetch('/auth/passkey/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request_id:ch.request_id,credential:credentialGetPayload(cred)})});if(!f.ok)throw new Error(await f.text());location.href='/ui/status'}catch(e){s.textContent=e.message||String(e);s.style.color='var(--red)'}};
</script></body></html>"#;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
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
            }
            if let Some(s) = payload.get("smtp").and_then(|v| v.as_object()) {
                let smtp = toml_table_mut(&mut cfg.toml, &["smtp"]);
                for k in ["host", "from_addr", "to_addr"] {
                    if let Some(v) = s.get(k).and_then(|v| v.as_str()) {
                        smtp.insert(k.into(), toml::Value::String(v.into()));
                    }
                }
                if let Some(p) = s.get("port").and_then(|v| v.as_i64()) {
                    smtp.insert("port".into(), toml::Value::Integer(p));
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

struct RestoreInput {
    source_kind: &'static str,
    toml_text: String,
    parsed: toml::Value,
    sidecars: Vec<BundleSidecar>,
}

struct BundleSidecar {
    name: &'static str,
    text: String,
}

fn restore_config(state: &AppState, body: Bytes) -> Response<Body> {
    if body.is_empty() || body.len() > 5_000_000 {
        return text(StatusCode::BAD_REQUEST, "empty or oversized body");
    }
    let body_len = body.len();
    let input = match parse_restore_input(&body) {
        Ok(input) => input,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    if !["cascade", "delivery", "render", "ntfy", "auth"]
        .iter()
        .any(|k| input.parsed.get(k).is_some())
    {
        return text(
            StatusCode::BAD_REQUEST,
            "no recognised top-level sections; refusing as likely empty",
        );
    }
    let (backup, restored_sidecars) = match state.with_config_write_lock(|| {
        let backup = config_auto_backup(state).ok().flatten();
        if let Err(err) = atomic_write(&state.paths.config, input.toml_text.as_bytes()) {
            return Err(format!("write failed: {err}"));
        }
        let restored_sidecars = if input.sidecars.is_empty() {
            restore_sidecars_from_toml(&state.paths, &input.parsed)
                .map_err(|err| format!("restore sidecars failed: {err}"))?
        } else {
            let mut restored = Vec::new();
            for sidecar in &input.sidecars {
                write_bundle_sidecar(state, sidecar)?;
                restored.push(sidecar.name);
            }
            restored
        };
        match load_runtime_config(&state.paths) {
            Ok(cfg) => state.replace_config(cfg),
            Err(err) => return Err(format!("reload failed: {err}")),
        }
        Ok((backup, restored_sidecars))
    }) {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    json_response(
        json!({"ok": true, "source_kind": input.source_kind, "bytes_written": body_len, "toml_bytes_written": input.toml_text.len(), "pre_restore_backup": backup, "restored_sidecars": restored_sidecars}),
    )
}

fn parse_restore_input(body: &Bytes) -> Result<RestoreInput, String> {
    let text_body = String::from_utf8(body.to_vec()).map_err(|e| format!("invalid UTF-8: {e}"))?;
    if text_body.trim_start().starts_with('{') {
        return parse_restore_bundle(&text_body);
    }
    let parsed: toml::Value =
        toml::from_str(&text_body).map_err(|e| format!("invalid TOML: {e}"))?;
    Ok(RestoreInput {
        source_kind: "toml",
        toml_text: text_body,
        parsed,
        sidecars: Vec::new(),
    })
}

fn parse_restore_bundle(raw: &str) -> Result<RestoreInput, String> {
    let bundle: Value = serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    if bundle.get("kind").and_then(Value::as_str) != Some("klaxond.full-settings") {
        return Err("JSON bundle kind must be klaxond.full-settings".into());
    }
    if bundle
        .get("format_version")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        != 1
    {
        return Err("unsupported config bundle format_version".into());
    }
    let files = bundle
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| "bundle missing files object".to_string())?;
    let allowed_files = [
        "klaxond.toml",
        "render-config.json",
        "ntfy-topics.json",
        "dedup-config.json",
        "auth-config.json",
    ];
    for name in files.keys() {
        if !allowed_files.contains(&name.as_str()) {
            return Err(format!("unsupported sidecar {name}"));
        }
    }
    let toml_text = bundle_file(files, "klaxond.toml")?
        .ok_or_else(|| "bundle missing files.klaxond.toml".to_string())?;
    let parsed: toml::Value =
        toml::from_str(&toml_text).map_err(|e| format!("invalid bundled TOML: {e}"))?;
    let mut sidecars = Vec::new();
    for name in [
        "render-config.json",
        "ntfy-topics.json",
        "dedup-config.json",
        "auth-config.json",
    ] {
        let Some(text) = bundle_file(files, name)? else {
            return Err(format!("bundle missing files.{name}"));
        };
        validate_bundle_sidecar(name, &text)?;
        sidecars.push(BundleSidecar { name, text });
    }
    Ok(RestoreInput {
        source_kind: "full-bundle",
        toml_text,
        parsed,
        sidecars,
    })
}

fn bundle_file(
    files: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<String>, String> {
    files
        .get(name)
        .map(|v| {
            v.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("files.{name} must be a string"))
        })
        .transpose()
}

fn validate_bundle_sidecar(name: &str, raw: &str) -> Result<(), String> {
    match name {
        "render-config.json" => {
            let v: Value = serde_json::from_str(raw).map_err(|e| format!("invalid {name}: {e}"))?;
            if !v
                .get("component_dashboards")
                .and_then(Value::as_object)
                .map(|_| true)
                .unwrap_or(false)
            {
                return Err(format!("{name} must contain component_dashboards object"));
            }
        }
        "ntfy-topics.json" => {
            let v: Value = serde_json::from_str(raw).map_err(|e| format!("invalid {name}: {e}"))?;
            let arr = v
                .get("topics")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{name} must contain topics array"))?;
            for topic in arr {
                serde_json::from_value::<NtfyTopic>(topic.clone())
                    .map_err(|e| format!("invalid topic in {name}: {e}"))?;
            }
        }
        "dedup-config.json" => {
            serde_json::from_str::<HashMap<String, DedupSetting>>(raw)
                .map_err(|e| format!("invalid {name}: {e}"))?;
        }
        "auth-config.json" => {
            serde_json::from_str::<AuthConfig>(raw).map_err(|e| format!("invalid {name}: {e}"))?;
        }
        _ => return Err(format!("unsupported sidecar {name}")),
    }
    Ok(())
}

fn write_bundle_sidecar(state: &AppState, sidecar: &BundleSidecar) -> Result<(), String> {
    let path = match sidecar.name {
        "render-config.json" => &state.paths.render_config,
        "ntfy-topics.json" => &state.paths.ntfy_topics,
        "dedup-config.json" => &state.paths.dedup_config,
        "auth-config.json" => &state.paths.auth_config,
        _ => return Err(format!("unsupported sidecar {}", sidecar.name)),
    };
    atomic_write(path, sidecar.text.as_bytes())
        .map_err(|err| format!("write {} failed: {err}", sidecar.name))
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

async fn status_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    json!({
        "version": crate::config::VERSION,
        "cascade_enabled_runtime": state.cascade_runtime_enabled.load(Ordering::Relaxed),
        "cascade_enabled_default": cfg.cascade_default,
        "channels": check_channel_reachability(state).await,
        "ntfy_url": cfg.ntfy_url,
        "smtp_host": cfg.smtp_host,
        "telegram_configured": !cfg.tg_token.is_empty() && !cfg.tg_chat.is_empty(),
        "logs": log_buffer::stats_global(),
    })
}

async fn check_channel_reachability(state: &AppState) -> Value {
    let cfg = state.cfg();
    let mut ntfy = false;
    let mut telegram = false;
    let mut smtp = false;
    if !cfg.ntfy_url.is_empty() {
        ntfy = state
            .http
            .get(format!("{}/v1/health", cfg.ntfy_url))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
    }
    if !cfg.tg_token.is_empty() {
        let base = cfg.telegram_api_base.trim_end_matches('/');
        telegram = state
            .http
            .get(format!("{base}/bot{}/getMe", cfg.tg_token))
            .timeout(Duration::from_secs(4))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
    }
    if !cfg.smtp_host.is_empty() {
        smtp = tokio::time::timeout(
            Duration::from_secs(4),
            tokio::net::TcpStream::connect(format!("{}:{}", cfg.smtp_host, cfg.smtp_port)),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    }
    json!({"ntfy": ntfy, "telegram": telegram, "smtp": smtp})
}

fn channel_config_payload(state: &AppState) -> Value {
    let cfg = state.cfg();
    let mut legacy_topics = serde_json::Map::new();
    let mut legacy_tokens = serde_json::Map::new();
    for sev in ["info", "warning", "critical"] {
        let matches = cfg.topics_for(sev);
        legacy_topics.insert(
            sev.into(),
            json!(matches.first().map(|t| t.name.clone()).unwrap_or_default()),
        );
        legacy_tokens.insert(
            sev.into(),
            json!(
                matches
                    .first()
                    .map(|t| !t.token.is_empty())
                    .unwrap_or(false)
            ),
        );
    }
    json!({
        "ntfy": {
            "url": cfg.ntfy_url,
            "topics": legacy_topics,
            "url_from_env": !env_string("NTFY_URL").is_empty(),
            "topics_from_env": {
                "info": !env_string("TOPIC_INFO").is_empty(),
                "warning": !env_string("TOPIC_WARN").is_empty(),
                "critical": !env_string("TOPIC_CRIT").is_empty(),
            },
            "tokens_configured": legacy_tokens,
        },
        "telegram": {"chat_id": cfg.tg_chat, "chat_id_from_env": !env_string("TELEGRAM_CHAT_ID").is_empty(), "bot_token_configured": !cfg.tg_token.is_empty()},
        "smtp": {"host": cfg.smtp_host, "port": cfg.smtp_port, "from_addr": cfg.smtp_from, "to_addr": cfg.smtp_to, "host_from_env": !env_string("SMTP_HOST").is_empty(), "user_configured": !cfg.smtp_user.is_empty(), "password_configured": !cfg.smtp_pass.is_empty()},
    })
}

fn inhibition_rules_payload(state: &AppState) -> Value {
    let rules = state
        .cfg()
        .inhibition_rules
        .iter()
        .map(|r| {
            json!({
                "source": r.source,
                "ttl_seconds": r.ttl_seconds,
                "match_by": r.match_by,
                "match_label": r.match_label,
                "match_regex": r.match_regex,
                "match_all": r.match_all,
                "applies_to": r.applies_to,
            })
        })
        .collect::<Vec<_>>();
    json!({"rules": rules, "available_sources": DEDUP_SOURCES})
}

fn image_response(state: &AppState, path: &str) -> Response<Body> {
    let mut token = path
        .trim_start_matches("/img/")
        .split('?')
        .next()
        .unwrap_or("")
        .to_string();
    if let Some(t) = token.strip_suffix(".png") {
        token = t.into();
    }
    let now = crate::util::now_epoch();
    let img = {
        let mut imgs = lock_mutex(&state.rendered_images, "rendered images");
        imgs.retain(|_, img| img.expires_at > now);
        imgs.get(&token).cloned()
    };
    let Some(img) = img else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "image/png")
        .header(CACHE_CONTROL, "private, max-age=900")
        .header(CONTENT_LENGTH, img.bytes.len().to_string())
        .body(Body::from(img.bytes))
        .unwrap()
}

const UI_ROUTES: &[&str] = &[
    "status",
    "flow",
    "inhibitions",
    "deliveries",
    "logs",
    "render",
    "routing",
    "cascade",
    "delivery",
    "grouping",
    "auth",
    "preview",
    "test",
    "privacy",
    "accessibility",
    "terms",
    "cookies",
    "legal",
];

fn sanitize_static_rel(rel: &str) -> String {
    rel.trim_start_matches('/')
        .split('/')
        .filter(|p| *p != "..")
        .collect::<Vec<_>>()
        .join("/")
}

fn ui_response(state: &AppState, rel: &str) -> Response<Body> {
    let safe = sanitize_static_rel(rel);
    let route = safe.trim_matches('/');
    if route == "meta.js" {
        return ui_meta_response();
    }
    if route.is_empty() || route == "index.html" || UI_ROUTES.contains(&route) {
        return static_response(state, "index.html");
    }
    static_response(state, &safe)
}

fn ui_meta_response() -> Response<Body> {
    let body = format!(
        "window.KLAXOND_META=Object.freeze({{version:{},authorName:{},authorUrl:{}}});\n",
        serde_json::to_string(crate::config::VERSION).unwrap_or_else(|_| "\"\"".into()),
        serde_json::to_string(crate::config::AUTHOR_NAME).unwrap_or_else(|_| "\"\"".into()),
        serde_json::to_string(crate::config::AUTHOR_URL).unwrap_or_else(|_| "\"\"".into())
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header(CONTENT_LENGTH, body.len().to_string())
        .header(CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .unwrap()
}

fn static_response(state: &AppState, rel: &str) -> Response<Body> {
    let safe = sanitize_static_rel(rel);
    let full = state
        .paths
        .static_dir
        .join(if safe.is_empty() { "index.html" } else { &safe });
    if !full.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(bytes) = fs::read(&full) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mime = mime_guess::from_path(&full)
        .first_or_octet_stream()
        .to_string();
    let cache = full
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase().contains("mermaid") || n.contains("vendor"))
        .unwrap_or(false);
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, format!("{mime}; charset=utf-8"))
        .header(CONTENT_LENGTH, bytes.len().to_string())
        .header(
            CACHE_CONTROL,
            if cache {
                "public, max-age=86400, immutable"
            } else {
                "no-store"
            },
        )
        .body(Body::from(bytes))
        .unwrap()
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

fn metrics_response(state: &AppState) -> Response<Body> {
    let uptime = state.started.elapsed().as_secs();
    state.metric_set(
        "klaxond_suppressions_active",
        &[],
        lock_mutex(&state.suppressions, "suppressions").len() as f64,
    );
    if let Ok(d) = state.dedup.try_lock() {
        for src in DEDUP_SOURCES {
            state.metric_set(
                "klaxond_dedup_pending",
                &[("source", src)],
                d.queues.get(*src).map(|q| q.len()).unwrap_or(0) as f64,
            );
        }
    }
    let mut lines = vec![
        "# HELP klaxond_info Static info (version, etc).".to_string(),
        "# TYPE klaxond_info gauge".to_string(),
        format!("klaxond_info{{version=\"{}\"}} 1", crate::config::VERSION),
        "# HELP klaxond_uptime_seconds Seconds since klaxond started.".to_string(),
        "# TYPE klaxond_uptime_seconds counter".to_string(),
        format!("klaxond_uptime_seconds {uptime}"),
    ];
    let counters = lock_mutex(&state.metrics.counters, "metrics counters");
    emit_metrics(
        &mut lines,
        "counter",
        &counters,
        &HashMap::from([
            (
                "klaxond_deliveries_total",
                "Cumulative deliveries (or attempts) per source/severity/channel/ok.",
            ),
            (
                "klaxond_suppressions_armed_total",
                "Inhibition source-alerts that armed a suppression.",
            ),
            (
                "klaxond_render_errors_total",
                "Render-time exceptions per source.",
            ),
            (
                "klaxond_dedup_buffered_total",
                "Events queued in the dedup buffer per source.",
            ),
            (
                "klaxond_dedup_flushed_total",
                "Events flushed from the dedup buffer per source.",
            ),
        ]),
    );
    let gauges = lock_mutex(&state.metrics.gauges, "metrics gauges");
    let gauge_i = gauges
        .iter()
        .map(|(k, v)| (k.clone(), *v as i64))
        .collect::<HashMap<_, _>>();
    emit_metrics(
        &mut lines,
        "gauge",
        &gauge_i,
        &HashMap::from([
            (
                "klaxond_suppressions_active",
                "Currently-armed in-memory suppressions.",
            ),
            (
                "klaxond_dedup_pending",
                "Events pending in the dedup buffer per source.",
            ),
        ]),
    );
    let body = lines.join("\n") + "\n";
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

fn emit_metrics(
    lines: &mut Vec<String>,
    kind: &str,
    samples: &HashMap<String, i64>,
    helps: &HashMap<&str, &str>,
) {
    let mut by_name: HashMap<String, Vec<(String, i64)>> = HashMap::new();
    for (key, val) in samples {
        let (name, labels) = key.split_once('|').unwrap_or((key, ""));
        by_name
            .entry(name.into())
            .or_default()
            .push((labels.into(), *val));
    }
    let mut names = by_name.keys().cloned().collect::<Vec<_>>();
    names.sort();
    for name in names {
        lines.push(format!(
            "# HELP {name} {}",
            helps
                .get(name.as_str())
                .copied()
                .unwrap_or("(no description)")
        ));
        lines.push(format!("# TYPE {name} {kind}"));
        for (labels, val) in by_name.remove(&name).unwrap_or_default() {
            let label_render = if labels.is_empty() {
                String::new()
            } else {
                let labels = labels
                    .split(',')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| format!("{k}=\"{}\"", esc_label(v)))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{{{labels}}}")
            };
            lines.push(format!("{name}{label_render} {val}"));
        }
    }
}

fn config_backup_response(state: &AppState) -> Response<Body> {
    let Ok(bytes) = fs::read(&state.paths.config) else {
        return text(StatusCode::NOT_FOUND, "klaxond.toml not found");
    };
    let stamp = Utc::now().format("%Y%m%d-%H%M%S-%f");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/toml")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"klaxond-{stamp}.toml\""),
        )
        .header(CONTENT_LENGTH, bytes.len().to_string())
        .body(Body::from(bytes))
        .unwrap()
}

fn config_full_export_response(state: &AppState) -> Response<Body> {
    let payload = match state.with_config_write_lock(|| config_full_export_payload(state)) {
        Ok(Ok(payload)) => payload,
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    let bytes = match serde_json::to_vec_pretty(&payload) {
        Ok(bytes) => bytes,
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    };
    let stamp = Utc::now().format("%Y%m%d-%H%M%S-%f");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"klaxond-full-settings-{stamp}.json\""),
        )
        .header(CONTENT_LENGTH, bytes.len().to_string())
        .body(Body::from(bytes))
        .unwrap()
}

fn config_full_export_payload(state: &AppState) -> Result<Value, String> {
    let cfg = state.cfg();
    let toml_text = fs::read_to_string(&state.paths.config)
        .map_err(|err| format!("read {} failed: {err}", state.paths.config.display()))?;
    let render_sidecar = json!({ "component_dashboards": &cfg.component_dashboards });
    let ntfy_sidecar = json!({ "topics": &cfg.ntfy_topics });
    let mut files = serde_json::Map::new();
    files.insert("klaxond.toml".into(), json!(toml_text));
    files.insert(
        "render-config.json".into(),
        json!(json_pretty_string(&render_sidecar)?),
    );
    files.insert(
        "ntfy-topics.json".into(),
        json!(json_pretty_string(&ntfy_sidecar)?),
    );
    files.insert(
        "dedup-config.json".into(),
        json!(json_pretty_string(&cfg.dedup)?),
    );
    files.insert(
        "auth-config.json".into(),
        json!(json_pretty_string(&cfg.auth)?),
    );
    Ok(json!({
        "kind": "klaxond.full-settings",
        "format_version": 1,
        "klaxond_version": crate::config::VERSION,
        "exported_at": Utc::now().to_rfc3339(),
        "includes_secrets": true,
        "files_are_effective": true,
        "files": Value::Object(files),
        "source_paths": {
            "klaxond.toml": state.paths.config.to_string_lossy(),
            "render-config.json": state.paths.render_config.to_string_lossy(),
            "ntfy-topics.json": state.paths.ntfy_topics.to_string_lossy(),
            "dedup-config.json": state.paths.dedup_config.to_string_lossy(),
            "auth-config.json": state.paths.auth_config.to_string_lossy(),
        },
        "effective_runtime": {
            "ntfy_url": cfg.ntfy_url,
            "telegram": {
                "api_base": cfg.telegram_api_base,
                "bot_token": cfg.tg_token,
                "chat_id": cfg.tg_chat,
            },
            "smtp": {
                "host": cfg.smtp_host,
                "port": cfg.smtp_port,
                "starttls": cfg.smtp_starttls,
                "from_addr": cfg.smtp_from,
                "to_addr": cfg.smtp_to,
                "user": cfg.smtp_user,
                "password": cfg.smtp_pass,
            },
            "grafana": {
                "base": cfg.grafana_base,
                "render_base": cfg.grafana_render_base,
                "render_token": cfg.grafana_render_token,
            },
            "public_url": cfg.public_url,
            "render_image_ttl": cfg.render_image_ttl,
            "ack_default_ttl": cfg.ack_default_ttl,
            "beszel_db": cfg.beszel_db.to_string_lossy(),
        }
    }))
}

fn json_pretty_string<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|err| err.to_string())
}

fn config_backups_payload(state: &AppState) -> Value {
    let mut backups = Vec::new();
    if let Ok(entries) = fs::read_dir(&state.paths.backup_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !(name.starts_with("klaxond-") && name.ends_with(".toml")) {
                continue;
            }
            if let Ok(meta) = e.metadata() {
                let mtime_iso = meta
                    .modified()
                    .ok()
                    .map(DateTime::<Utc>::from)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default();
                backups.push(json!({"name": name, "size": meta.len(), "mtime_iso": mtime_iso}));
            }
        }
    }
    backups.sort_by(|a, b| {
        b.get("mtime_iso")
            .and_then(|v| v.as_str())
            .cmp(&a.get("mtime_iso").and_then(|v| v.as_str()))
    });
    json!({"backups": backups, "keep_max": 10, "dir": state.paths.backup_dir})
}

fn logs_payload(full_path: &str) -> log_buffer::LogQuery {
    let qs = parse_query(full_path);
    let limit = qs
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200);
    let offset = qs
        .get("offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let query = qs.get("q").map(String::as_str).unwrap_or("");
    let level = qs.get("level").map(String::as_str).unwrap_or("all");
    log_buffer::query_global(query, level, limit, offset)
}

fn config_auto_backup(state: &AppState) -> anyhow::Result<Option<String>> {
    if !state.paths.config.exists() {
        return Ok(None);
    }
    fs::create_dir_all(&state.paths.backup_dir).ok();
    let stamp = Utc::now().format("%Y%m%d-%H%M%S-%f");
    let dest = state.paths.backup_dir.join(format!("klaxond-{stamp}.toml"));
    fs::copy(&state.paths.config, &dest)?;
    let mut files = fs::read_dir(&state.paths.backup_dir)?
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("klaxond-") && name.ends_with(".toml")
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|e| std::cmp::Reverse(e.file_name()));
    for stale in files.into_iter().skip(10) {
        let _ = fs::remove_file(stale.path());
    }
    Ok(Some(dest.to_string_lossy().to_string()))
}

fn persist_reload(state: &AppState, toml_value: toml::Value) -> Result<(), String> {
    config_auto_backup(state).map_err(|e| e.to_string()).ok();
    save_toml(&state.paths, &toml_value).map_err(|e| e.to_string())?;
    let cfg = load_runtime_config(&state.paths).map_err(|e| e.to_string())?;
    state.replace_config(cfg);
    Ok(())
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
