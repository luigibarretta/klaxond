use super::*;
use crate::oidc::identity::{
    identity_from_id_claims, validate_authorized_party, validate_required_authentication_methods,
};

#[test]
fn verified_identity_retains_assurance_claims() {
    let claims: openidconnect::IdTokenClaims<
        OidcAdditionalClaims,
        openidconnect::core::CoreGenderClaim,
    > = serde_json::from_value(serde_json::json!({
        "iss": "https://issuer.example",
        "sub": "operator-subject",
        "aud": "control-client",
        "exp": 2_000_000_000,
        "iat": 1_900_000_000,
        "auth_time": 1_899_999_900,
        "acr": "urn:example:mfa",
        "amr": ["password", "totp"],
        "sid": "provider-session",
        "preferred_username": "operator"
    }))
    .expect("ID-token claims");

    let identity = identity_from_id_claims(&claims);

    assert_eq!(identity.assurance.issuer, "https://issuer.example/");
    assert_eq!(identity.assurance.issued_at_unix, 1_900_000_000);
    assert_eq!(identity.assurance.expires_at_unix, 2_000_000_000);
    assert_eq!(
        identity.assurance.authenticated_at_unix,
        Some(1_899_999_900)
    );
    assert_eq!(
        identity.assurance.authentication_context.as_deref(),
        Some("urn:example:mfa")
    );
    assert_eq!(
        identity.assurance.authentication_methods,
        ["password", "totp"]
    );
    assert_eq!(
        identity.assurance.provider_session_id.as_deref(),
        Some("provider-session")
    );
}

#[test]
fn required_authentication_methods_are_enforced() {
    let claims: openidconnect::IdTokenClaims<
        OidcAdditionalClaims,
        openidconnect::core::CoreGenderClaim,
    > = serde_json::from_value(serde_json::json!({
        "iss": "https://issuer.example",
        "sub": "operator-subject",
        "aud": "control-client",
        "exp": 2_000_000_000,
        "iat": 1_900_000_000,
        "amr": ["password"]
    }))
    .expect("ID-token claims");
    let config = OidcClientConfig::new(
        "https://issuer.example",
        "client-id",
        None,
        "https://app.example/callback",
        vec!["openid".to_string()],
    )
    .with_assurance_policy(
        OidcAssurancePolicy::default().with_required_authentication_methods(["password", "totp"]),
    );

    let error = validate_required_authentication_methods(&claims, &config)
        .expect_err("missing TOTP must fail");

    assert!(error.to_string().contains("totp"));
}

#[test]
fn conflicting_authorized_party_is_rejected() {
    let claims: openidconnect::IdTokenClaims<
        OidcAdditionalClaims,
        openidconnect::core::CoreGenderClaim,
    > = serde_json::from_value(serde_json::json!({
        "iss": "https://issuer.example",
        "sub": "operator-subject",
        "aud": "client-id",
        "azp": "different-client",
        "exp": 2_000_000_000,
        "iat": 1_900_000_000
    }))
    .expect("ID-token claims");
    let config = OidcClientConfig::new(
        "https://issuer.example",
        "client-id",
        None,
        "https://app.example/callback",
        vec!["openid".to_string()],
    );

    assert!(validate_authorized_party(&claims, &config).is_err());
}

#[test]
fn multiple_audiences_require_an_authorized_party() {
    let claims: openidconnect::IdTokenClaims<
        OidcAdditionalClaims,
        openidconnect::core::CoreGenderClaim,
    > = serde_json::from_value(serde_json::json!({
        "iss": "https://issuer.example",
        "sub": "operator-subject",
        "aud": ["client-id", "resource-server"],
        "exp": 2_000_000_000,
        "iat": 1_900_000_000
    }))
    .expect("ID-token claims");
    let config = OidcClientConfig::new(
        "https://issuer.example",
        "client-id",
        None,
        "https://app.example/callback",
        vec!["openid".to_string()],
    );

    assert!(validate_authorized_party(&claims, &config).is_err());
}
