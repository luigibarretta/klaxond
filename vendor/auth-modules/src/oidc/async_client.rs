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

/// A bounded OIDC client prepared from one validated discovery document.
///
/// Reuse this handle for login, callback, and back-channel logout. This avoids
/// unauthenticated request paths performing discovery for every operation.
/// Only the assurance policy may vary between calls, which supports normal
/// login and forced step-up without allowing provider configuration drift.
#[derive(Clone)]
pub struct PreparedAsyncOidcClient {
    config: OidcClientConfig,
    http: reqwest::Client,
    client: ReadyClient,
    logout_jwks: jsonwebtoken::jwk::JwkSet,
}

impl fmt::Debug for PreparedAsyncOidcClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAsyncOidcClient")
            .field("config", &self.config)
            .field("logout_key_count", &self.logout_jwks.keys.len())
            .finish_non_exhaustive()
    }
}

impl PreparedAsyncOidcClient {
    pub async fn discover(config: &OidcClientConfig) -> Result<Self, OidcError> {
        let http = http_client(config)?;
        let metadata = discover(config, &http).await?;
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

    pub async fn exchange_code(
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
            .request_async(&self.http)
            .await
            .map_err(|err| OidcError::new(format!("OIDC token exchange failed: {err}")))?;
        verified_identity(&self.client, &self.http, config, &token, nonce).await
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

pub async fn authorization_url(
    config: &OidcClientConfig,
    state: &str,
) -> Result<OidcAuthorizationFlow, OidcError> {
    PreparedAsyncOidcClient::discover(config)
        .await?
        .authorization_url(config, state)
}

pub async fn authorization_url_with_flow(
    config: &OidcClientConfig,
    state: &str,
    nonce: &str,
    pkce_verifier: &str,
) -> Result<OidcAuthorizationFlow, OidcError> {
    PreparedAsyncOidcClient::discover(config)
        .await?
        .authorization_url_with_flow(config, state, nonce, pkce_verifier)
}

pub async fn exchange_code(
    config: &OidcClientConfig,
    code: &str,
    nonce: &str,
    pkce_verifier: &str,
) -> Result<OidcIdentity, OidcError> {
    PreparedAsyncOidcClient::discover(config)
        .await?
        .exchange_code(config, code, nonce, pkce_verifier)
        .await
}

async fn discover(
    config: &OidcClientConfig,
    http: &reqwest::Client,
) -> Result<OidcProviderMetadata, OidcError> {
    let metadata = OidcProviderMetadata::discover_async(issuer_url(config)?, http)
        .await
        .map_err(|err| OidcError::new(format!("OIDC discovery failed: {err}")))?;
    validate_provider_metadata(&metadata, config)?;
    Ok(metadata)
}

fn http_client(config: &OidcClientConfig) -> Result<reqwest::Client, OidcError> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .build()
        .map_err(|err| OidcError::new(format!("build OIDC HTTP client failed: {err}")))
}

async fn verified_identity(
    client: &ReadyClient,
    http: &reqwest::Client,
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
            Ok(request) => match request
                .request_async::<OidcAdditionalClaims, _, CoreGenderClaim>(http)
                .await
            {
                Ok(userinfo) => {
                    merge_userinfo(&mut identity, &userinfo, config.require_userinfo);
                }
                Err(err) if config.require_userinfo => {
                    return Err(OidcError::new(format!(
                        "OIDC UserInfo request failed: {err}"
                    )));
                }
                Err(_) => {}
            },
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::oidc::OidcAssurancePolicy;

    fn config() -> OidcClientConfig {
        OidcClientConfig::new(
            "https://identity.example.test/application/o/control/",
            "control-client",
            Some("secret".to_string()),
            "https://control.example.test/api/control/auth/callback",
            vec!["openid".to_string(), "studioflow_control".to_string()],
        )
        .with_assurance_policy(
            OidcAssurancePolicy::requiring_context("control-mfa")
                .with_required_authentication_methods(["mfa"]),
        )
        .with_http_timeouts(Duration::from_secs(2), Duration::from_secs(10))
    }

    #[test]
    fn prepared_provider_allows_only_assurance_policy_changes() {
        let baseline = config();
        let step_up = config().with_assurance_policy(
            OidcAssurancePolicy::requiring_context("control-mfa")
                .with_required_authentication_methods(["mfa"])
                .with_maximum_authentication_age(Duration::ZERO)
                .forcing_reauthentication(),
        );
        assert!(same_provider_configuration(&baseline, &step_up));

        let mut different_issuer = step_up.clone();
        different_issuer.issuer_url = "https://other.example.test/".to_string();
        assert!(!same_provider_configuration(&baseline, &different_issuer));

        let mut different_secret = step_up;
        different_secret.client_secret = Some("other-secret".to_string());
        assert!(!same_provider_configuration(&baseline, &different_secret));

        let mut weaker_context = baseline.clone();
        weaker_context
            .assurance_policy
            .required_authentication_context = None;
        assert!(!same_provider_configuration(&baseline, &weaker_context));

        let mut weaker_methods = baseline.clone();
        weaker_methods
            .assurance_policy
            .required_authentication_methods
            .clear();
        assert!(!same_provider_configuration(&baseline, &weaker_methods));

        let mut larger_clock_skew = baseline.clone();
        larger_clock_skew.assurance_policy.clock_skew = Duration::from_secs(120);
        assert!(!same_provider_configuration(&baseline, &larger_clock_skew));
    }
}
