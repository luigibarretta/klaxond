use std::time::Duration;

use super::*;
use crate::oidc::types::OidcProviderMetadata;
use crate::oidc::OidcAssurancePolicy;

#[test]
fn assurance_policy_is_added_to_authorization_request() {
    let metadata: OidcProviderMetadata = serde_json::from_value(serde_json::json!({
        "issuer": "https://issuer.example",
        "authorization_endpoint": "https://issuer.example/authorize",
        "jwks_uri": "https://issuer.example/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "code_challenge_methods_supported": ["S256"]
    }))
    .expect("provider metadata");
    let config = OidcClientConfig::new(
        "https://issuer.example",
        "client-id",
        Some("client-secret".to_string()),
        "https://app.example/api/auth/callback",
        vec!["openid".to_string()],
    )
    .with_assurance_policy(
        OidcAssurancePolicy::requiring_context("urn:example:mfa")
            .with_maximum_authentication_age(Duration::ZERO)
            .forcing_reauthentication(),
    );
    let client = client_from_metadata(&config, metadata).expect("OIDC client");

    let flow = build_authorization_flow_with_values(
        &client,
        &config,
        "state",
        "nonce",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc",
    );

    assert!(flow
        .authorization_url
        .contains("acr_values=urn%3Aexample%3Amfa"));
    assert!(flow.authorization_url.contains("max_age=0"));
    assert!(flow.authorization_url.contains("prompt=login"));
}

#[test]
fn signing_algorithm_mapping_excludes_symmetric_and_unsigned_algorithms() {
    let algorithms = [
        OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        OidcSigningAlgorithm::RsaSsaPssSha256,
        OidcSigningAlgorithm::EcdsaP256Sha256,
        OidcSigningAlgorithm::EdDsa,
    ]
    .map(signing_algorithm);

    assert!(algorithms.iter().all(|algorithm| !matches!(
        algorithm,
        CoreJwsSigningAlgorithm::HmacSha256
            | CoreJwsSigningAlgorithm::HmacSha384
            | CoreJwsSigningAlgorithm::HmacSha512
            | CoreJwsSigningAlgorithm::None
    )));
}
