use super::blocking::{AUTH_STORE_TIMEOUT, run_with_timeout};
use super::login::oidc_client_config;
use super::oidc_client::cached_client_for;
use crate::history::OidcLogoutTokenRecord;
use crate::state::AppState;
use crate::util::now_epoch_i64;
use auth_modules::one_time_token::hash_token;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use url::form_urlencoded;

const MAX_FORM_BYTES: usize = 17 * 1024;
const REPLAY_RETENTION_SECONDS: i64 = 10 * 60;

pub async fn backchannel_logout(state: &AppState, body: Bytes) -> Response<Body> {
    let raw_token = match logout_token(&body) {
        Ok(token) => token,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    let runtime = state.cfg();
    if runtime.auth.mode != "oidc" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let redirect_uri = format!(
        "{}{}",
        runtime.public_url.trim_end_matches('/'),
        runtime.auth.oidc.redirect_path
    );
    let config = oidc_client_config(&runtime.auth.oidc, &redirect_uri);
    let client = match cached_client_for(state, &config).await {
        Ok(client) => client,
        Err(err) => {
            tracing::error!("OIDC back-channel logout provider is unavailable: {err}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let logout = match client.validate_backchannel_logout_token(&config, &raw_token) {
        Ok(logout) => logout,
        Err(err) => {
            tracing::warn!("rejected OIDC back-channel logout token: {err}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let now = now_epoch_i64();
    let token_id_hash = hash_token(&format!("{}\0{}", logout.issuer, logout.token_id));
    let record = OidcLogoutTokenRecord {
        issuer: logout.issuer,
        token_id_hash,
        consumed_at: now,
        expires_at: logout
            .expires_at_unix
            .unwrap_or_default()
            .max(now.saturating_add(REPLAY_RETENTION_SECONDS)),
    };
    let provider_session_id = logout.provider_session_id;
    let subject = logout.subject;
    let state_for_store = state.clone();
    let result = run_with_timeout(state, AUTH_STORE_TIMEOUT, move || {
        state_for_store
            .with_auth_store(|store| {
                store.consume_oidc_logout(
                    &record,
                    provider_session_id.as_deref(),
                    subject.as_deref(),
                    now,
                )
            })
            .map_err(|err| err.to_string())
    })
    .await;
    match result {
        Ok(Ok(outcome)) => {
            if outcome.replayed {
                tracing::warn!("ignored replayed OIDC back-channel logout token");
            } else {
                tracing::info!(
                    revoked_sessions = outcome.revoked_sessions,
                    "processed OIDC back-channel logout"
                );
            }
            StatusCode::OK.into_response()
        }
        Ok(Err(err)) | Err(err) => {
            tracing::error!("persist OIDC back-channel logout failed: {err}");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

fn logout_token(body: &[u8]) -> Result<String, &'static str> {
    if body.is_empty() || body.len() > MAX_FORM_BYTES {
        return Err("invalid logout request");
    }
    let mut token = None;
    for (key, value) in form_urlencoded::parse(body) {
        if key == "logout_token" {
            if token.is_some() || value.is_empty() {
                return Err("invalid logout_token");
            }
            token = Some(value.into_owned());
        }
    }
    token.ok_or("logout_token is required")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exactly_one_logout_token() {
        assert_eq!(
            logout_token(b"logout_token=header.payload.signature").unwrap(),
            "header.payload.signature"
        );
        assert!(logout_token(b"other=value").is_err());
        assert!(logout_token(b"logout_token=a&logout_token=b").is_err());
        assert!(logout_token(b"logout_token=").is_err());
    }

    #[test]
    fn bounds_logout_form_size() {
        assert!(logout_token(&vec![b'a'; MAX_FORM_BYTES + 1]).is_err());
    }
}
