use super::super::super::auth::User;
use crate::config::AuthConfig;
use auth_modules::methods::{HARDWARE_KEY, PASSKEY};
use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub(super) fn validate_auth_config(
    auth: &AuthConfig,
    current_user: Option<&User>,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), String> {
    validate_step_up(auth)?;
    match auth.mode.as_str() {
        "none" => Ok(()),
        "basic" => validate_basic(auth),
        "ldap" => validate_ldap(auth),
        "oidc" => validate_oidc(auth, current_user),
        "trusted-proxy" => validate_trusted_proxy(auth, peer, headers),
        _ => Err("invalid mode".into()),
    }
}

fn validate_step_up(auth: &AuthConfig) -> Result<(), String> {
    if auth.step_up.required_after_primary
        && matches!(auth.step_up.factor.as_str(), PASSKEY | HARDWARE_KEY)
        && !auth.webauthn.enabled
    {
        return Err("MFA / step-up with passkeys requires WebAuthn/passkeys to be enabled".into());
    }
    Ok(())
}

fn validate_basic(auth: &AuthConfig) -> Result<(), String> {
    if auth.basic.username.trim().is_empty() {
        return Err("basic auth requires a username".into());
    }
    if auth.basic.password_hash.trim().is_empty() {
        return Err("basic auth requires a password before it can be enabled".into());
    }
    if auth.basic.totp_enabled && auth.basic.totp_secret.trim().is_empty() {
        return Err("basic auth TOTP is enabled but no TOTP secret is configured".into());
    }
    Ok(())
}

fn validate_ldap(auth: &AuthConfig) -> Result<(), String> {
    if !(auth.ldap.url.starts_with("ldap://") || auth.ldap.url.starts_with("ldaps://")) {
        return Err("LDAP requires an ldap:// or ldaps:// URL".into());
    }
    if auth_modules::ldap::ldap_scope_from_name(&auth.ldap.scope).is_none() {
        return Err("LDAP scope must be base, one, or subtree".into());
    }
    if auth.ldap.to_auth_modules_config().is_none() {
        return Err("LDAP requires either bind_dn_template or service bind DN/password".into());
    }
    Ok(())
}

fn validate_oidc(auth: &AuthConfig, current_user: Option<&User>) -> Result<(), String> {
    if auth.oidc.issuer.trim().is_empty() || auth.oidc.client_id.trim().is_empty() {
        return Err("OIDC requires issuer and client_id before it can be enabled".into());
    }
    if auth.oidc.redirect_path != "/api/auth/callback" {
        return Err("OIDC redirect_path must be /api/auth/callback".into());
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

fn validate_trusted_proxy(
    auth: &AuthConfig,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), String> {
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

fn cidr_match(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs
        .iter()
        .filter_map(|cidr| cidr.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}
