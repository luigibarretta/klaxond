use super::{callback_url, oidc_client_config, oidc_redirect_uri};
use crate::auth::oidc_client::client_for;
use crate::auth::session::{issue_session_on_worker, sanitize_return_to, set_session_cookie};
use crate::auth::step_up::redirect_location_after_primary;
use crate::auth::{User, redirect};
use crate::config::OidcConfig;
use crate::state::{AppState, PendingOidcState, lock_mutex};
use auth_modules::oidc::OidcIdentity;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;

enum CallbackError {
    BadUri,
    MissingParameters,
    UnknownState,
    ProviderUnavailable(String),
    InvalidIdentity(String),
    MissingGroup(String),
    SessionPersistence(String),
}

impl CallbackError {
    fn into_response(self) -> Response<Body> {
        match self {
            Self::BadUri => (StatusCode::BAD_REQUEST, "bad callback uri").into_response(),
            Self::MissingParameters => {
                (StatusCode::BAD_REQUEST, "missing code or state").into_response()
            }
            Self::UnknownState => redirect("/"),
            Self::ProviderUnavailable(error) => (
                StatusCode::BAD_GATEWAY,
                format!("OIDC provider unavailable: {error}"),
            )
                .into_response(),
            Self::InvalidIdentity(error) => (
                StatusCode::UNAUTHORIZED,
                format!("id_token verify failed: {error}"),
            )
                .into_response(),
            Self::MissingGroup(group) => (
                StatusCode::FORBIDDEN,
                format!("required_group '{group}' not in user claims"),
            )
                .into_response(),
            Self::SessionPersistence(error) => {
                tracing::error!("persist OIDC session failed: {error}");
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
        }
    }
}

pub async fn oidc_callback(state: &AppState, headers: HeaderMap, uri: &str) -> Response<Body> {
    match complete_oidc_callback(state, &headers, uri).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn complete_oidc_callback(
    state: &AppState,
    headers: &HeaderMap,
    uri: &str,
) -> Result<Response<Body>, CallbackError> {
    let cfg = state.cfg().auth.oidc;
    let (code, state_param) = callback_parameters(uri)?;
    let pending = take_pending_state(state, &state_param)?;
    let identity = exchange_identity(state, headers, &cfg, &code, &pending).await?;
    require_group(&cfg, &identity)?;
    finish_oidc_callback(
        state,
        oidc_user(identity),
        &sanitize_return_to(&pending.return_to),
    )
    .await
}

fn callback_parameters(uri: &str) -> Result<(String, String), CallbackError> {
    let parsed = callback_url(uri).map_err(|_| CallbackError::BadUri)?;
    let code = parsed
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string());
    let state = parsed
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.to_string());
    code.zip(state).ok_or(CallbackError::MissingParameters)
}

fn take_pending_state(
    state: &AppState,
    state_param: &str,
) -> Result<PendingOidcState, CallbackError> {
    lock_mutex(&state.oidc_states, "oidc states")
        .remove(state_param)
        .ok_or(CallbackError::UnknownState)
}

async fn exchange_identity(
    state: &AppState,
    headers: &HeaderMap,
    cfg: &OidcConfig,
    code: &str,
    pending: &PendingOidcState,
) -> Result<OidcIdentity, CallbackError> {
    let redirect_uri = oidc_redirect_uri(state, headers, &cfg.redirect_path);
    let client_config = oidc_client_config(cfg, &redirect_uri);
    let client = client_for(state, &client_config)
        .await
        .map_err(|error| CallbackError::ProviderUnavailable(error.to_string()))?;
    client
        .exchange_code(&client_config, code, &pending.nonce, &pending.code_verifier)
        .await
        .map_err(|error| CallbackError::InvalidIdentity(error.to_string()))
}

fn require_group(cfg: &OidcConfig, identity: &OidcIdentity) -> Result<(), CallbackError> {
    if cfg.required_group.trim().is_empty()
        || identity
            .groups
            .iter()
            .any(|group| group == cfg.required_group.as_str())
    {
        return Ok(());
    }
    Err(CallbackError::MissingGroup(cfg.required_group.clone()))
}

async fn finish_oidc_callback(
    state: &AppState,
    mut user: User,
    return_to: &str,
) -> Result<Response<Body>, CallbackError> {
    let cfg = state.cfg().auth;
    if let Some(location) = redirect_location_after_primary(
        state,
        &cfg,
        user.clone(),
        return_to,
        PrimaryAuthMethod::Oidc,
    ) {
        return Ok(redirect(&location));
    }
    let cookie = issue_session_on_worker(state, &cfg, &mut user)
        .await
        .map_err(|error| CallbackError::SessionPersistence(error.to_string()))?;
    let mut response = redirect(if return_to.is_empty() { "/" } else { return_to });
    set_session_cookie(&mut response, &cookie);
    Ok(response)
}

fn oidc_user(identity: OidcIdentity) -> User {
    User {
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
        session_id_hash: String::new(),
        session_family_hash: String::new(),
        session_created_at: 0,
        provider_issuer: identity.assurance.issuer,
        provider_session_id: identity.assurance.provider_session_id.unwrap_or_default(),
    }
}
