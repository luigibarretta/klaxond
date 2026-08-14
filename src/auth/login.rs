use super::login_page::login_page;
use super::oidc_client::client_for;
use super::session::{
    cookie_values, rotate_session_on_worker, sanitize_return_to, set_session_cookie, verify_session,
};
use super::{AUTH_SESSION_COOKIE, magic_link_enabled, redirect};
use crate::state::{AppState, PendingOidcState, lock_mutex};
use crate::util::token_urlsafe;
use auth_modules::oidc::OidcClientConfig;
use axum::body::Body;
use axum::http::header::{COOKIE, HOST};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use url::Url;

mod callback;

pub use callback::oidc_callback;

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
            match verify_session(state, value).await {
                Ok(Some(mut verified)) => {
                    let mut response = redirect(&return_to);
                    if verified.legacy || verified.should_rotate {
                        let cookie = match rotate_session_on_worker(
                            state,
                            &auth,
                            &mut verified.user,
                        )
                        .await
                        {
                            Ok(cookie) => cookie,
                            Err(err) => {
                                tracing::error!("migrate login session failed: {err}");
                                return StatusCode::SERVICE_UNAVAILABLE.into_response();
                            }
                        };
                        set_session_cookie(&mut response, &cookie);
                    } else if let Some(cookie) = verified.replacement_cookie {
                        set_session_cookie(&mut response, &cookie);
                    }
                    return response;
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::error!("load login session failed: {err}");
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
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
