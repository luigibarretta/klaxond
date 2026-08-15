use super::{cookie_values, persistent_session_hash};
use crate::auth::blocking::{AUTH_STORE_TIMEOUT, run_with_timeout};
use crate::auth::{AUTH_SESSION_COOKIE, json_response};
use crate::state::AppState;
use crate::util::now_epoch_i64;
use axum::body::Body;
use axum::http::header::{COOKIE, HOST, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use serde_json::json;
use std::net::IpAddr;

pub async fn api_logout(state: &AppState, headers: &HeaderMap) -> Response<Body> {
    let hashes = headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|cookie| {
            cookie_values(cookie, AUTH_SESSION_COOKIE)
                .into_iter()
                .filter_map(persistent_session_hash)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let state_for_store = state.clone();
    let now = now_epoch_i64();
    let revoked = run_with_timeout(state, AUTH_STORE_TIMEOUT, move || {
        for hash in hashes {
            state_for_store
                .with_auth_store(|store| store.revoke_auth_session_family(&hash, now))
                .map_err(|err| err.to_string())?;
        }
        Ok::<_, String>(())
    })
    .await
    .and_then(|result| result);
    let mut response = if let Err(err) = revoked {
        tracing::error!("persistent session logout failed: {err}");
        let mut response = json_response(json!({"ok": false}));
        *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        response
    } else {
        json_response(json!({"ok": true}))
    };
    for cookie in expired_session_cookies(headers) {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(SET_COOKIE, value);
        }
    }
    response
}

fn expired_session_cookies(headers: &HeaderMap) -> Vec<String> {
    let mut cookies = Vec::new();
    let domains = logout_domain_candidates(headers);
    for path in ["/", "/api/auth/login", "/api/auth/callback"] {
        cookies.push(expired_session_cookie(path, None));
        for domain in &domains {
            cookies.push(expired_session_cookie(path, Some(domain)));
        }
    }
    cookies
}

fn expired_session_cookie(path: &str, domain: Option<&str>) -> String {
    let mut cookie = format!(
        "{AUTH_SESSION_COOKIE}=; HttpOnly; Path={path}; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
    if let Some(domain) = domain {
        cookie.push_str("; Domain=");
        cookie.push_str(domain);
    }
    cookie
}

fn logout_domain_candidates(headers: &HeaderMap) -> Vec<String> {
    let Some(host) = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(':').next())
        .map(|value| value.trim().trim_end_matches('.'))
        .filter(|value| !value.is_empty())
    else {
        return Vec::new();
    };
    if host.parse::<IpAddr>().is_ok() || host.contains(['/', '\\']) {
        return Vec::new();
    }

    let mut domains = vec![host.to_string(), format!(".{host}")];
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() > 2 {
        let parent = labels[labels.len() - 2..].join(".");
        domains.push(parent.clone());
        domains.push(format!(".{parent}"));
    }
    domains.sort();
    domains.dedup();
    domains
}
