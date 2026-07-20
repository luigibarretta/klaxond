use super::oidc_client::client_for;
use super::session::{
    cookie_values, issue_session, sanitize_return_to, set_session_cookie, verify_session,
};
use super::step_up::redirect_location_after_primary;
use super::{AUTH_SESSION_COOKIE, User, magic_link_enabled, redirect};
use crate::state::{AppState, PendingOidcState, lock_mutex};
use crate::util::token_urlsafe;
use auth_modules::oidc::OidcClientConfig;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::Body;
use axum::http::header::{COOKIE, HOST};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use url::Url;

pub async fn login(state: &AppState, headers: HeaderMap, uri: &str) -> Response<Body> {
    let return_to = login_return_to(uri);
    let logged_out = Url::parse(&format!("http://localhost{uri}"))
        .ok()
        .is_some_and(|u| u.query_pairs().any(|(k, _)| k == "logged_out"));
    let start = Url::parse(&format!("http://localhost{uri}"))
        .ok()
        .is_some_and(|u| {
            u.query_pairs()
                .any(|(k, v)| (k == "start" || k == "oidc") && v != "0")
        });
    let auth = state.cfg().auth;
    if auth.mode == "none" {
        return redirect(&return_to);
    }
    if !logged_out && let Some(cookie) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        for value in cookie_values(cookie, AUTH_SESSION_COOKIE).into_iter().rev() {
            if verify_session(state, value).is_some() {
                return redirect(&return_to);
            }
        }
    }
    if start && auth.mode == "oidc" {
        return oidc_login_redirect(state, headers, uri).await;
    }
    login_page(
        &auth.mode,
        auth.webauthn.enabled,
        magic_link_enabled(&auth),
        &return_to,
    )
}

async fn oidc_login_redirect(state: &AppState, headers: HeaderMap, uri: &str) -> Response<Body> {
    let cfg = state.cfg().auth.oidc;
    let issuer = exact_oidc_issuer(&cfg.issuer);
    if issuer.is_empty() || cfg.client_id.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "OIDC not configured (set issuer + client_id in Auth tab)",
        )
            .into_response();
    }
    let return_to = login_return_to(uri);
    let redirect_uri = oidc_redirect_uri(state, &headers, &cfg.redirect_path);
    let state_token = token_urlsafe(24);
    let client_config = oidc_client_config(&cfg, &redirect_uri);
    let client = match client_for(state, &client_config).await {
        Ok(client) => client,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("OIDC discovery failed: {err}"),
            )
                .into_response();
        }
    };
    let flow = match client.authorization_url(&client_config, &state_token) {
        Ok(flow) => flow,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("OIDC discovery failed: {err}"),
            )
                .into_response();
        }
    };
    {
        let mut states = lock_mutex(&state.oidc_states, "oidc states");
        let now = crate::util::now_epoch();
        states.insert(
            state_token.clone(),
            PendingOidcState {
                created_at: now,
                return_to,
                nonce: flow.nonce,
                code_verifier: flow.pkce_verifier,
            },
        );
        let cutoff = now - 600.0;
        states.retain(|_, pending| pending.created_at >= cutoff);
    }
    redirect(&flow.authorization_url)
}

fn login_return_to(uri: &str) -> String {
    let return_to = Url::parse(&format!("http://localhost{uri}"))
        .ok()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "return_to")
                .map(|(_, v)| v.to_string())
        })
        .unwrap_or_else(|| "/status".into());
    sanitize_return_to(&return_to)
}

fn login_page(
    mode: &str,
    passkeys_enabled: bool,
    magic_link_enabled: bool,
    return_to: &str,
) -> Response<Body> {
    let start_url = format!(
        "/api/auth/login?start=1&return_to={}",
        urlencoding::encode(return_to)
    );
    let start_url = html_attr(&start_url);
    let return_to = html_attr(return_to);
    let primary = match mode {
        "oidc" => format!(r#"<a class="btn primary" href="{start_url}">Continue with SSO</a>"#),
        "basic" => format!(
            r#"<form class="login-form" method="post" action="/api/auth/local/login">
<input type="hidden" name="return_to" value="{return_to}">
<label><span>Username</span><input name="username" autocomplete="username" required></label>
<label><span>Password</span><input name="password" type="password" autocomplete="current-password" required></label>
<label><span>TOTP code</span><input name="totp" inputmode="numeric" pattern="[0-9]{{6}}" autocomplete="one-time-code" placeholder="000000"></label>
<button class="btn primary" type="submit">Sign in</button>
</form>"#
        ),
        "trusted-proxy" => {
            format!(
                r#"<a class="btn primary" href="{return_to}">Continue through trusted proxy</a>"#
            )
        }
        _ => format!(r#"<a class="btn primary" href="{return_to}">Continue</a>"#),
    };
    let passkey = if passkeys_enabled {
        r#"<a class="btn" href="/api/auth/passkey/login">Use passkey</a>"#
    } else {
        ""
    };
    let magic_link = if magic_link_enabled {
        format!(
            r#"<form class="login-form" method="post" action="/api/auth/magic/request">
<input type="hidden" name="return_to" value="{return_to}">
<label><span>Username</span><input name="username" autocomplete="username" required></label>
<button class="btn" type="submit">Use magic link</button>
</form>"#
        )
    } else {
        String::new()
    };
    let author_link = author_link_html();
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>klaxond login</title><link rel="stylesheet" href="/ui/style.css"></head>
<body><main class="auth-login"><section class="card auth-login-card">
<div class="login-brand">
<img class="login-logo" src="/ui/favicon.svg" alt="" aria-hidden="true">
<div class="login-brand-text"><h1>klaxond</h1><span>notification daemon</span></div>
<span class="login-version">v{version}</span>
</div>
<h2>Sign in</h2>
<p class="login-note">You are signed out locally. If your SSO session is still active, continuing may sign you back in without asking for credentials.</p>
<div class="login-actions">{primary}{passkey}{magic_link}</div>
<nav class="login-legal" aria-label="Legal links">
<a href="/legal/privacy?from=login">Privacy</a>
<a href="/legal/accessibility?from=login">Accessibility</a>
<a href="/legal/terms?from=login">Terms</a>
<a href="/legal/cookies?from=login">Cookies</a>
<a href="/legal/notice?from=login">Legal notice</a>
</nav>
<p class="muted login-byline">by {author_link}</p>
</section></main></body></html>"#,
        version = crate::config::VERSION
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("Cache-Control", "no-store")
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

fn author_link_html() -> String {
    format!(
        r#"<a href="{}" target="_blank" rel="noopener">{}</a>"#,
        html_attr(crate::config::AUTHOR_URL),
        html_attr(crate::config::AUTHOR_NAME)
    )
}

fn html_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub async fn oidc_callback(state: &AppState, headers: HeaderMap, uri: &str) -> Response<Body> {
    let cfg = state.cfg().auth.oidc;
    let parsed = match callback_url(uri) {
        Ok(parsed) => parsed,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad callback uri").into_response(),
    };
    let code = parsed
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string());
    let state_param = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string());
    let (Some(code), Some(state_param)) = (code, state_param) else {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };
    let pending = {
        let mut states = lock_mutex(&state.oidc_states, "oidc states");
        match states.remove(&state_param) {
            Some(pending) => pending,
            None => return redirect("/"),
        }
    };
    let return_to = sanitize_return_to(&pending.return_to);
    let redirect_uri = oidc_redirect_uri(state, &headers, &cfg.redirect_path);
    let client_config = oidc_client_config(&cfg, &redirect_uri);
    let client = match client_for(state, &client_config).await {
        Ok(client) => client,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("OIDC provider unavailable: {err}"),
            )
                .into_response();
        }
    };
    let identity = match client
        .exchange_code(
            &client_config,
            &code,
            &pending.nonce,
            &pending.code_verifier,
        )
        .await
    {
        Ok(identity) => identity,
        Err(err) => {
            return (
                StatusCode::UNAUTHORIZED,
                format!("id_token verify failed: {err}"),
            )
                .into_response();
        }
    };
    if !cfg.required_group.trim().is_empty()
        && !identity
            .groups
            .iter()
            .any(|group| group == cfg.required_group.as_str())
    {
        return (
            StatusCode::FORBIDDEN,
            format!("required_group '{}' not in user claims", cfg.required_group),
        )
            .into_response();
    }
    let mut user = User {
        sub: identity.subject,
        email: identity.email.unwrap_or_default(),
        name: if identity.name.trim().is_empty() {
            identity.username
        } else {
            identity.name
        },
        groups: identity.groups,
        mode: "oidc".into(),
        exp: 0,
        csrf: String::new(),
        sudo_until: 0,
        via_authorization: false,
        second_factor: String::new(),
    };
    let cfg_all = state.cfg().auth;
    if let Some(location) = redirect_location_after_primary(
        state,
        &cfg_all,
        user.clone(),
        &return_to,
        PrimaryAuthMethod::Oidc,
    ) {
        return redirect(&location);
    }
    let cookie = issue_session(state, &cfg_all, &mut user);
    let mut resp = redirect(if return_to.is_empty() {
        "/"
    } else {
        &return_to
    });
    set_session_cookie(&mut resp, &cookie);
    resp
}

pub(super) fn callback_url(uri: &str) -> Result<Url, String> {
    if !uri.starts_with('/') || uri.chars().any(char::is_control) {
        return Err("callback uri must be a local path".into());
    }
    Url::parse(&format!("http://localhost{uri}")).map_err(|err| err.to_string())
}

pub(super) fn oidc_client_config(
    cfg: &crate::config::OidcConfig,
    redirect_uri: &str,
) -> OidcClientConfig {
    OidcClientConfig::new(
        exact_oidc_issuer(&cfg.issuer),
        cfg.client_id.clone(),
        Some(cfg.client_secret.clone()),
        redirect_uri.to_string(),
        cfg.scopes
            .split_whitespace()
            .filter(|scope| !scope.trim().is_empty())
            .map(str::to_string)
            .collect(),
    )
    .with_userinfo(true)
}

fn exact_oidc_issuer(value: &str) -> String {
    value.trim().to_string()
}

pub(super) fn oidc_redirect_uri(
    state: &AppState,
    headers: &HeaderMap,
    redirect_path: &str,
) -> String {
    let public_url = state.with_cfg(|cfg| cfg.public_url.clone());
    if let Ok(url) = Url::parse(&public_url)
        && matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
    {
        return format!("{}{}", public_url.trim_end_matches('/'), redirect_path);
    }

    tracing::warn!("KLAXOND_PUBLIC_URL is not configured; deriving OIDC callback from request");
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let scheme = if headers
        .get("X-Forwarded-Proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("https")
        == "https"
    {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{host}{redirect_path}")
}
