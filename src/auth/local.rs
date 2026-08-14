use super::basic::{challenge as basic_challenge, credentials as basic_credentials};
use super::session::issue_session_on_worker;
use super::step_up::primary_step_up_response;
use super::{
    AuthOutcome, User, auth_rate_keys, auth_rate_limited_on_worker, blocking::authenticate_ldap,
    clear_auth_failures_on_worker, record_auth_failure_on_worker, sudo_window_seconds,
};
use crate::config::AuthConfig;
use crate::state::AppState;
use crate::util::now_epoch_i64;
use auth_modules::errors;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

mod login;
mod sudo;
pub use self::login::local_login;
pub use self::sudo::sudo;

pub(super) async fn authenticate_ldap_basic(
    state: &AppState,
    cfg: &AuthConfig,
    headers: &HeaderMap,
    return_to: &str,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    let Some((username, password)) = basic_credentials(headers) else {
        return AuthOutcome::Rejected(basic_challenge("klaxond ldap"));
    };
    let rate_keys = auth_rate_keys(state, "ldap", &username, headers, peer);
    match auth_rate_limited_on_worker(state, &rate_keys).await {
        Ok(true) => {
            let _ =
                record_auth_failure_on_worker(state, &rate_keys, "auth.ldap", errors::RATE_LIMITED)
                    .await;
            return AuthOutcome::Rejected(rate_limited_response());
        }
        Ok(false) => {}
        Err(err) => return AuthOutcome::Rejected(rate_store_error("LDAP check", err)),
    }
    let identity = match authenticate_ldap(state, cfg, &username, &password).await {
        Ok(identity) => identity,
        Err(err) => {
            tracing::warn!(?err, "LDAP Basic authentication failed");
            if let Err(err) = record_auth_failure_on_worker(
                state,
                &rate_keys,
                "auth.ldap",
                "ldap authentication failed",
            )
            .await
            {
                return AuthOutcome::Rejected(rate_store_error("LDAP failure", err));
            }
            return AuthOutcome::Rejected(basic_challenge("klaxond ldap"));
        }
    };
    if let Err(err) = clear_auth_failures_on_worker(state, &rate_keys).await {
        return AuthOutcome::Rejected(rate_store_error("LDAP clear", err));
    }
    let mut user = ldap_user(identity);
    user.sudo_until = now_epoch_i64() + sudo_window_seconds();
    if let Some(resp) = primary_step_up_response(
        state,
        cfg,
        &user,
        return_to,
        PrimaryAuthMethod::Ldap,
        headers,
    ) {
        return AuthOutcome::Rejected(resp);
    }
    match issue_session_on_worker(state, cfg, &mut user).await {
        Ok(cookie) => AuthOutcome::Authorized(user, Some(cookie)),
        Err(err) => {
            tracing::error!("persist LDAP session failed: {err}");
            AuthOutcome::Rejected(StatusCode::SERVICE_UNAVAILABLE.into_response())
        }
    }
}

pub(super) fn authenticate_trusted_proxy(
    cfg: &AuthConfig,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    let peer_ip = peer.map(|p| p.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
    if !cidr_match(peer_ip, &cfg.trusted_proxy.trusted_cidrs) {
        return AuthOutcome::Rejected(
            (StatusCode::FORBIDDEN, "untrusted peer (trusted-proxy mode)").into_response(),
        );
    }
    let uh = &cfg.trusted_proxy.user_header;
    let Some(user_val) = header_by_name(headers, uh) else {
        return AuthOutcome::Rejected(
            (StatusCode::UNAUTHORIZED, format!("missing {uh} header")).into_response(),
        );
    };
    AuthOutcome::Authorized(
        User {
            sub: user_val,
            email: header_by_name(headers, &cfg.trusted_proxy.email_header).unwrap_or_default(),
            groups: header_by_name(headers, &cfg.trusted_proxy.groups_header)
                .unwrap_or_default()
                .split(',')
                .map(|s| s.to_string())
                .collect(),
            name: String::new(),
            mode: "trusted-proxy".into(),
            exp: 0,
            csrf: String::new(),
            sudo_until: 0,
            via_authorization: false,
            second_factor: String::new(),
            session_id_hash: String::new(),
            session_family_hash: String::new(),
            session_created_at: 0,
            provider_issuer: String::new(),
            provider_session_id: String::new(),
        },
        None,
    )
}

pub fn ldap_login_enabled(cfg: &AuthConfig) -> bool {
    cfg.mode == "ldap" && cfg.ldap.to_auth_modules_config().is_some()
}

fn ldap_user(identity: auth_modules::ldap::LdapIdentity) -> User {
    User {
        sub: identity.username,
        email: identity.email.unwrap_or_default(),
        name: identity.name,
        groups: identity.groups,
        mode: "ldap".into(),
        exp: 0,
        csrf: String::new(),
        sudo_until: 0,
        via_authorization: false,
        second_factor: String::new(),
        session_id_hash: String::new(),
        session_family_hash: String::new(),
        session_created_at: 0,
        provider_issuer: String::new(),
        provider_session_id: String::new(),
    }
}

pub(super) fn rate_limited_response() -> Response<Body> {
    (
        StatusCode::TOO_MANY_REQUESTS,
        "too many authentication failures",
    )
        .into_response()
}

pub(super) fn rate_store_error(operation: &str, err: String) -> Response<Body> {
    tracing::error!("persistent authentication rate-limit {operation} failed: {err}");
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

fn cidr_match(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}

fn header_by_name(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
}
