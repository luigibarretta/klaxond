use std::fmt;

use openidconnect::core::CoreGenderClaim;
use openidconnect::reqwest;
use openidconnect::{AuthorizationCode, Nonce, OAuth2TokenResponse, TokenResponse};

use super::client::{
    build_authorization_flow, build_authorization_flow_with_values, client_from_metadata,
    same_provider_configuration, ReadyClient, SharedTokenResponse,
};
use super::identity::{
    identity_from_id_claims, merge_userinfo, validate_access_token_hash, validate_authorized_party,
    validate_required_authentication_methods, verifier_for_config,
};
use super::logout::{jwks_from_metadata, validate_backchannel_logout_token_with_jwks};
use super::security::{
    issuer_url, pkce_verifier as validate_pkce_verifier, validate_nonce,
    validate_provider_metadata, validate_state,
};
use super::{
    types::OidcProviderMetadata, OidcAdditionalClaims, OidcAuthorizationFlow,
    OidcBackchannelLogout, OidcClientConfig, OidcError, OidcIdentity,
};

/// A blocking OIDC client prepared from one validated discovery document.
///
/// Reuse this handle for login, callback, and back-channel logout so public
/// endpoints do not perform provider discovery for every request.
#[derive(Clone)]
pub struct PreparedBlockingOidcClient {
    config: OidcClientConfig,
    http: reqwest::blocking::Client,
    client: ReadyClient,
    logout_jwks: jsonwebtoken::jwk::JwkSet,
}

impl fmt::Debug for PreparedBlockingOidcClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBlockingOidcClient")
            .field("config", &self.config)
            .field("logout_key_count", &self.logout_jwks.keys.len())
            .finish_non_exhaustive()
    }
}

impl PreparedBlockingOidcClient {
    pub fn discover(config: &OidcClientConfig) -> Result<Self, OidcError> {
        let http = http_client(config)?;
        let metadata = discover(config, &http)?;
        let logout_jwks = jwks_from_metadata(&metadata)?;
        let client = client_from_metadata(config, metadata)?;
        Ok(Self {
            config: config.clone(),
            http,
            client,
            logout_jwks,
        })
    }

    pub fn authorization_url(
        &self,
        config: &OidcClientConfig,
        state: &str,
    ) -> Result<OidcAuthorizationFlow, OidcError> {
        self.ensure_compatible(config)?;
        validate_state(state)?;
        Ok(build_authorization_flow(&self.client, config, state))
    }

    pub fn authorization_url_with_flow(
        &self,
        config: &OidcClientConfig,
        state: &str,
        nonce: &str,
        pkce_verifier: &str,
    ) -> Result<OidcAuthorizationFlow, OidcError> {
        self.ensure_compatible(config)?;
        validate_state(state)?;
        validate_nonce(nonce)?;
        validate_pkce_verifier(pkce_verifier)?;
        Ok(build_authorization_flow_with_values(
            &self.client,
            config,
            state,
            nonce,
            pkce_verifier,
        ))
    }

    pub fn exchange_code(
        &self,
        config: &OidcClientConfig,
        code: &str,
        nonce: &str,
        pkce_verifier: &str,
    ) -> Result<OidcIdentity, OidcError> {
        self.ensure_compatible(config)?;
        validate_nonce(nonce)?;
        let pkce_verifier = validate_pkce_verifier(pkce_verifier)?;
        let token = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|err| OidcError::new(format!("OIDC token endpoint missing: {err}")))?
            .set_pkce_verifier(pkce_verifier)
            .request(&self.http)
            .map_err(|err| OidcError::new(format!("OIDC token exchange failed: {err}")))?;
        verified_identity(&self.client, &self.http, config, &token, nonce)
    }

    pub fn validate_backchannel_logout_token(
        &self,
        config: &OidcClientConfig,
        raw_token: &str,
    ) -> Result<OidcBackchannelLogout, OidcError> {
        self.ensure_compatible(config)?;
        validate_backchannel_logout_token_with_jwks(config, raw_token, &self.logout_jwks)
    }

    fn ensure_compatible(&self, config: &OidcClientConfig) -> Result<(), OidcError> {
        if same_provider_configuration(&self.config, config) {
            Ok(())
        } else {
            Err(OidcError::new(
                "OIDC request configuration does not match the prepared provider",
            ))
        }
    }
}

pub fn authorization_url(
    config: &OidcClientConfig,
    state: &str,
) -> Result<OidcAuthorizationFlow, OidcError> {
    PreparedBlockingOidcClient::discover(config)?.authorization_url(config, state)
}

pub fn authorization_url_with_flow(
    config: &OidcClientConfig,
    state: &str,
    nonce: &str,
    pkce_verifier: &str,
) -> Result<OidcAuthorizationFlow, OidcError> {
    PreparedBlockingOidcClient::discover(config)?.authorization_url_with_flow(
        config,
        state,
        nonce,
        pkce_verifier,
    )
}

pub fn exchange_code(
    config: &OidcClientConfig,
    code: &str,
    nonce: &str,
    pkce_verifier: &str,
) -> Result<OidcIdentity, OidcError> {
    PreparedBlockingOidcClient::discover(config)?.exchange_code(config, code, nonce, pkce_verifier)
}

fn discover(
    config: &OidcClientConfig,
    http: &reqwest::blocking::Client,
) -> Result<OidcProviderMetadata, OidcError> {
    let metadata = OidcProviderMetadata::discover(&issuer_url(config)?, http)
        .map_err(|err| OidcError::new(format!("OIDC discovery failed: {err}")))?;
    validate_provider_metadata(&metadata, config)?;
    Ok(metadata)
}

fn http_client(config: &OidcClientConfig) -> Result<reqwest::blocking::Client, OidcError> {
    reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .build()
        .map_err(|err| OidcError::new(format!("build OIDC HTTP client failed: {err}")))
}

fn verified_identity(
    client: &ReadyClient,
    http: &reqwest::blocking::Client,
    config: &OidcClientConfig,
    token: &SharedTokenResponse,
    nonce: &str,
) -> Result<OidcIdentity, OidcError> {
    let id_token = token
        .id_token()
        .ok_or_else(|| OidcError::new("OIDC provider did not return an id_token"))?;
    let verifier = verifier_for_config(client, config);
    let claims = id_token
        .claims(&verifier, &Nonce::new(nonce.to_string()))
        .map_err(|err| OidcError::new(format!("OIDC id_token validation failed: {err}")))?;
    validate_access_token_hash(claims, id_token, token, &verifier)?;
    validate_authorized_party(claims, config)?;
    validate_required_authentication_methods(claims, config)?;

    let mut identity = identity_from_id_claims(claims);
    if config.fetch_userinfo {
        let request = client.user_info(
            token.access_token().to_owned(),
            Some(claims.subject().to_owned()),
        );
        match request {
            Ok(request) => {
                match request.request::<OidcAdditionalClaims, CoreGenderClaim, _>(http) {
                    Ok(userinfo) => {
                        merge_userinfo(&mut identity, &userinfo, config.require_userinfo);
                    }
                    Err(err) if config.require_userinfo => {
                        return Err(OidcError::new(format!(
                            "OIDC UserInfo request failed: {err}"
                        )));
                    }
                    Err(_) => {}
                }
            }
            Err(err) if config.require_userinfo => {
                return Err(OidcError::new(format!(
                    "OIDC UserInfo endpoint unavailable: {err}"
                )));
            }
            Err(_) => {}
        }
    }
    Ok(identity)
}
