use openidconnect::core::{
    CoreClientAuthMethod, CoreJsonWebKey, CoreJwsSigningAlgorithm, CoreResponseType,
};
use openidconnect::{
    IssuerUrl, JsonWebKey, JsonWebKeyAlgorithm, JsonWebKeyUse, JwsSigningAlgorithm,
    PkceCodeVerifier,
};

use super::{client::signing_algorithm, types::OidcProviderMetadata, OidcClientConfig, OidcError};

pub(crate) fn issuer_url(config: &OidcClientConfig) -> Result<IssuerUrl, OidcError> {
    let issuer = IssuerUrl::new(config.issuer_url.clone())
        .map_err(|err| OidcError::new(format!("invalid OIDC issuer URL: {err}")))?;
    validate_url(issuer.url(), config.allow_insecure_http, true)?;
    Ok(issuer)
}

pub(crate) fn validate_provider_metadata(
    metadata: &OidcProviderMetadata,
    config: &OidcClientConfig,
) -> Result<(), OidcError> {
    validate_url(
        metadata.authorization_endpoint().url(),
        config.allow_insecure_http,
        false,
    )?;
    validate_url(metadata.jwks_uri().url(), config.allow_insecure_http, false)?;
    let token_endpoint = metadata
        .token_endpoint()
        .ok_or_else(|| OidcError::new("OIDC provider has no token endpoint"))?;
    validate_url(token_endpoint.url(), config.allow_insecure_http, false)?;
    if let Some(endpoint) = metadata.userinfo_endpoint() {
        validate_url(endpoint.url(), config.allow_insecure_http, false)?;
    }
    if !metadata
        .response_types_supported()
        .iter()
        .any(|types| types.as_slice() == [CoreResponseType::Code])
    {
        return Err(OidcError::new(
            "OIDC provider does not support the Authorization Code response type",
        ));
    }
    if !supports_client_authentication(metadata, config) {
        return Err(OidcError::new(
            "OIDC provider does not support the configured client authentication method",
        ));
    }
    if !metadata
        .additional_metadata()
        .code_challenge_methods_supported
        .iter()
        .any(|method| method.as_str() == "S256")
    {
        return Err(OidcError::new(
            "OIDC provider does not advertise the S256 PKCE method",
        ));
    }
    let configured_algorithms = config
        .allowed_signing_algorithms
        .iter()
        .copied()
        .map(signing_algorithm)
        .collect::<Vec<_>>();
    if configured_algorithms.is_empty()
        || !metadata
            .id_token_signing_alg_values_supported()
            .iter()
            .any(|algorithm| configured_algorithms.contains(algorithm))
        || !metadata.jwks().keys().iter().any(|key| {
            configured_algorithms
                .iter()
                .any(|algorithm| key_supports_algorithm(key, algorithm))
        })
    {
        return Err(OidcError::new(
            "OIDC provider has no usable configured ID-token signing key",
        ));
    }
    Ok(())
}

fn supports_client_authentication(
    metadata: &OidcProviderMetadata,
    config: &OidcClientConfig,
) -> bool {
    match (
        config.client_secret.is_some(),
        metadata.token_endpoint_auth_methods_supported(),
    ) {
        (true, None) => true,
        (true, Some(methods)) => methods.contains(&CoreClientAuthMethod::ClientSecretBasic),
        (false, Some(methods)) => methods.contains(&CoreClientAuthMethod::None),
        (false, None) => false,
    }
}

fn key_supports_algorithm(key: &CoreJsonWebKey, algorithm: &CoreJwsSigningAlgorithm) -> bool {
    if key.key_use().is_some_and(|usage| !usage.allows_signature())
        || algorithm.key_type().as_ref() != Some(key.key_type())
    {
        return false;
    }
    match key.signing_alg() {
        JsonWebKeyAlgorithm::Unspecified => true,
        JsonWebKeyAlgorithm::Algorithm(key_algorithm) => key_algorithm == algorithm,
        JsonWebKeyAlgorithm::Unsupported => false,
    }
}

pub(crate) fn validate_state(state: &str) -> Result<(), OidcError> {
    if state.trim().is_empty() {
        return Err(OidcError::new("OIDC state must not be empty"));
    }
    Ok(())
}

pub(crate) fn validate_nonce(nonce: &str) -> Result<(), OidcError> {
    if nonce.trim().is_empty() {
        return Err(OidcError::new("OIDC nonce must not be empty"));
    }
    Ok(())
}

pub(crate) fn pkce_verifier(value: &str) -> Result<PkceCodeVerifier, OidcError> {
    if !(43..=128).contains(&value.len())
        || !value.bytes().all(
            |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'),
        )
    {
        return Err(OidcError::new(
            "OIDC PKCE verifier must contain 43-128 RFC 7636 unreserved characters",
        ));
    }
    Ok(PkceCodeVerifier::new(value.to_string()))
}

fn validate_url(
    url: &openidconnect::url::Url,
    allow_insecure_http: bool,
    issuer: bool,
) -> Result<(), OidcError> {
    let secure_scheme = url.scheme() == "https";
    let development_http = allow_insecure_http && url.scheme() == "http";
    if !secure_scheme && !development_http {
        return Err(OidcError::new(
            "OIDC issuer and discovered endpoints must use HTTPS",
        ));
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(OidcError::new(
            "OIDC URLs must have a host and must not contain userinfo",
        ));
    }
    if url.fragment().is_some() || (issuer && url.query().is_some()) {
        return Err(OidcError::new(
            "OIDC URLs must not contain a fragment and issuer URLs must not contain a query",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::types::OidcProviderAdditionalMetadata;
    use openidconnect::core::{CoreJsonCurveType, CoreSubjectIdentifierType};
    use openidconnect::{
        AuthUrl, JsonWebKeyId, JsonWebKeySet, JsonWebKeySetUrl, PkceCodeChallengeMethod,
        ResponseTypes, TokenUrl,
    };

    fn provider_metadata() -> OidcProviderMetadata {
        OidcProviderMetadata::new(
            IssuerUrl::new("https://identity.example.test/".to_string()).expect("issuer"),
            AuthUrl::new("https://identity.example.test/authorize".to_string())
                .expect("authorization URL"),
            JsonWebKeySetUrl::new("https://identity.example.test/jwks".to_string())
                .expect("JWKS URL"),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Public],
            vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256],
            OidcProviderAdditionalMetadata {
                code_challenge_methods_supported: vec![PkceCodeChallengeMethod::new(
                    "S256".to_string(),
                )],
            },
        )
        .set_token_endpoint(Some(
            TokenUrl::new("https://identity.example.test/token".to_string()).expect("token URL"),
        ))
        .set_token_endpoint_auth_methods_supported(Some(vec![
            CoreClientAuthMethod::ClientSecretBasic,
        ]))
        .set_jwks(JsonWebKeySet::new(vec![CoreJsonWebKey::new_ec(
            vec![1; 32],
            vec![2; 32],
            CoreJsonCurveType::P256,
            Some(JsonWebKeyId::new("signing-key".to_string())),
        )]))
    }

    fn code_flow_config() -> OidcClientConfig {
        OidcClientConfig::new(
            "https://identity.example.test/",
            "client",
            Some("secret".to_string()),
            "https://app.example.test/callback",
            vec!["openid".to_string()],
        )
        .with_allowed_signing_algorithms([super::super::OidcSigningAlgorithm::EcdsaP256Sha256])
    }

    #[test]
    fn issuer_requires_https_without_explicit_development_override() {
        let config = OidcClientConfig::new(
            "http://issuer.example",
            "client",
            None,
            "http://app.example/callback",
            vec!["openid".to_string()],
        );
        assert!(issuer_url(&config).is_err());
        assert!(issuer_url(&config.allowing_insecure_http_for_development()).is_ok());
    }

    #[test]
    fn explicit_pkce_verifier_is_validated() {
        assert!(pkce_verifier("short").is_err());
        assert!(pkce_verifier(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc"
        )
        .is_ok());
        assert!(pkce_verifier(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~ab!"
        )
        .is_err());
    }

    #[test]
    fn prepared_code_flow_requires_complete_compatible_provider_metadata() {
        let config = code_flow_config();
        assert!(validate_provider_metadata(&provider_metadata(), &config).is_ok());

        assert!(
            validate_provider_metadata(&provider_metadata().set_token_endpoint(None), &config)
                .is_err()
        );
        assert!(validate_provider_metadata(
            &provider_metadata().set_response_types_supported(vec![ResponseTypes::new(vec![
                CoreResponseType::IdToken
            ])]),
            &config
        )
        .is_err());
        assert!(validate_provider_metadata(
            &provider_metadata().set_token_endpoint_auth_methods_supported(Some(vec![
                CoreClientAuthMethod::PrivateKeyJwt
            ])),
            &config
        )
        .is_err());
        assert!(validate_provider_metadata(
            &provider_metadata().set_jwks(JsonWebKeySet::new(Vec::new())),
            &config
        )
        .is_err());
        let mut missing_pkce = provider_metadata();
        missing_pkce
            .additional_metadata_mut()
            .code_challenge_methods_supported
            .clear();
        assert!(validate_provider_metadata(&missing_pkce, &config).is_err());
    }
}
