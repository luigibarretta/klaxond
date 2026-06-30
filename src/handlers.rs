use crate::auth::{self, AuthOutcome, User};
use crate::config::{
    DEDUP_SOURCES, InhibitionRule, NtfyTopic, Schedule, default_dedup, default_tiers,
    load_runtime_config, save_auth, save_dedup, save_ntfy_topics, save_render_config, save_toml,
};
use crate::dedup;
use crate::delivery::deliver;
use crate::inhibition;
use crate::log_buffer;
use crate::parsers::{
    Parts, normalize_labels, parse_beszel_payload, parse_grafana_payload,
    parse_healthchecks_payload, parse_source, parse_wud_payload,
};
use crate::state::{AppState, esc_label, lock_mutex};
use crate::util::{atomic_write, env_string, random_hex, toml_table_mut};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, SET_COOKIE,
};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use url::form_urlencoded;

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
        return auth::oidc_login_redirect(&state, headers, &full_path).await;
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
        match auth::authenticate(&state, &headers, &full_path, Some(peer)).await {
            AuthOutcome::Authorized(user, cookie) => {
                authed_user = Some(user);
                pending_cookie = cookie;
            }
            AuthOutcome::Rejected(resp) => return resp,
        }
    }

    let mut resp = match method {
        Method::GET => handle_get(&state, &path, &full_path, authed_user).await,
        Method::POST => handle_post(&state, &path, &full_path, &headers, body, peer).await,
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
        "/" | "/ui" | "/ui/" => redirect("/ui/index.html"),
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
            json_response(json!({
                "settings": settings,
                "available_modes": ["none", "basic", "oidc", "trusted-proxy"],
                "bcrypt_available": true,
                "jwt_available": true,
                "current_user": authed_user.unwrap_or(User { sub: "anonymous".into(), email: String::new(), name: String::new(), groups: vec![], mode: "none".into(), exp: 0 }),
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
        "/api/config/backups" => json_response(config_backups_payload(state)),
        "/auth/me" => json_response(authed_user.unwrap_or(User {
            sub: "anonymous".into(),
            email: String::new(),
            name: String::new(),
            groups: vec![],
            mode: "none".into(),
            exp: 0,
        })),
        _ if path.starts_with("/img/") => image_response(state, path),
        _ if path.starts_with("/ui/") => static_response(state, path.trim_start_matches("/ui/")),
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
) -> Response<Body> {
    match path {
        "/api/auth-config" => update_auth_config(state, body),
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
    if let Err(err) = save_render_config(&state.paths, &cleaned) {
        return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
    }
    let mut cfg = state.cfg();
    cfg.component_dashboards = cleaned.clone();
    state.replace_config(cfg);
    json_response(json!({"ok": true, "count": cleaned.len()}))
}

fn update_ntfy_topics(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(incoming) = payload.get("topics").and_then(|v| v.as_array()) else {
        return text(StatusCode::BAD_REQUEST, "missing 'topics' list");
    };
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
    if let Err(err) = save_dedup(&state.paths, &cleaned) {
        return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
    }
    let mut cfg = state.cfg();
    cfg.dedup = cleaned.clone();
    state.replace_config(cfg);
    json_response(json!({"ok": true, "settings": cleaned}))
}

fn update_auth_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(incoming) = payload.get("settings") else {
        return text(StatusCode::BAD_REQUEST, "missing 'settings' object");
    };
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
                Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
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
    state.replace_config(cfg);
    json_response(json!({"ok": true, "settings": redacted}))
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
}

fn update_channel_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
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
}

fn update_delivery_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
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
    let mut cfg = state.cfg();
    cfg.toml.as_table_mut().unwrap().insert(
        "inhibitions".into(),
        json_to_toml(serde_json::to_value(&cleaned).unwrap()),
    );
    if let Err(err) = persist_reload(state, cfg.toml) {
        return text(StatusCode::INTERNAL_SERVER_ERROR, &err);
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
            if sec.len() < 16 {
                return text(
                    StatusCode::BAD_REQUEST,
                    "secret missing or shorter than 16 chars",
                );
            }
            secrets.insert(src.clone(), toml::Value::String(sec.into()));
        }
    }
    if let Err(err) = persist_reload(state, cfg.toml) {
        return text(StatusCode::INTERNAL_SERVER_ERROR, &err);
    }
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
    let mut cfg = state.cfg();
    cfg.toml.as_table_mut().unwrap().insert(
        "schedules".into(),
        json_to_toml(serde_json::to_value(&cleaned).unwrap()),
    );
    if let Err(err) = persist_reload(state, cfg.toml) {
        return text(StatusCode::INTERNAL_SERVER_ERROR, &err);
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

fn restore_config(state: &AppState, body: Bytes) -> Response<Body> {
    if body.is_empty() || body.len() > 1_000_000 {
        return text(StatusCode::BAD_REQUEST, "empty or oversized body");
    }
    let text_body = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid UTF-8: {e}")),
    };
    let parsed: toml::Value = match toml::from_str(&text_body) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid TOML: {e}")),
    };
    if !["cascade", "delivery", "render", "ntfy", "auth"]
        .iter()
        .any(|k| parsed.get(k).is_some())
    {
        return text(
            StatusCode::BAD_REQUEST,
            "no recognised top-level sections; refusing as likely empty",
        );
    }
    let backup = config_auto_backup(state).ok().flatten();
    if let Err(err) = atomic_write(&state.paths.config, text_body.as_bytes()) {
        return text(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("write failed: {err}"),
        );
    }
    match load_runtime_config(&state.paths) {
        Ok(cfg) => state.replace_config(cfg),
        Err(err) => {
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("reload failed: {err}"),
            );
        }
    }
    json_response(
        json!({"ok": true, "bytes_written": text_body.len(), "pre_restore_backup": backup}),
    )
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
        telegram = state
            .http
            .get(format!(
                "https://api.telegram.org/bot{}/getMe",
                cfg.tg_token
            ))
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

fn static_response(state: &AppState, rel: &str) -> Response<Body> {
    let safe = rel
        .trim_start_matches('/')
        .split('/')
        .filter(|p| *p != "..")
        .collect::<Vec<_>>()
        .join("/");
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
    let stamp = Utc::now().format("%Y%m%d-%H%M%S");
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
    let query = qs.get("q").map(String::as_str).unwrap_or("");
    let level = qs.get("level").map(String::as_str).unwrap_or("all");
    log_buffer::query_global(query, level, limit)
}

fn config_auto_backup(state: &AppState) -> anyhow::Result<Option<String>> {
    if !state.paths.config.exists() {
        return Ok(None);
    }
    fs::create_dir_all(&state.paths.backup_dir).ok();
    let stamp = Utc::now().format("%Y%m%d-%H%M%S");
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
