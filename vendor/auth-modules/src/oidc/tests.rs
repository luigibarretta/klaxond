use std::collections::BTreeMap;

use serde_json::Value;

use super::*;
use crate::oidc::identity::{
    identity_from_id_claims, validate_authorized_party, validate_required_authentication_methods,
};

#[test]
fn additional_claims_accept_group_arrays_and_raw_claims() {
    let claims: OidcAdditionalClaims = serde_json::from_value(serde_json::json!({
        "groups": ["admins", "users"],
        "codice_fiscale": "RSSMRA80A01H501U"
    }))
    .unwrap();

    assert_eq!(claims.groups, vec!["admins", "users"]);
    assert_eq!(
        claims.raw.get("codice_fiscale").and_then(Value::as_str),
        Some("RSSMRA80A01H501U")
    );
}

#[test]
fn additional_claims_accept_single_group_string() {
    let claims: OidcAdditionalClaims =
        serde_json::from_value(serde_json::json!({"groups": "admins"})).unwrap();

    assert_eq!(claims.groups, vec!["admins"]);
}

#[test]
fn additional_claims_reject_malformed_group_arrays() {
    let claims = serde_json::from_value::<OidcAdditionalClaims>(serde_json::json!({
        "groups": ["admins", 7]
    }));

    assert!(claims.is_err());
}

#[test]
fn oidc_debug_output_redacts_protocol_secrets() {
    let config = OidcClientConfig::new(
        "https://issuer.example",
        "client-id",
        Some("client-secret".to_string()),
        "https://app.example/api/auth/callback",
        vec!["openid".to_string(), "email".to_string()],
    );
    let config_debug = format!("{config:?}");
    assert!(config_debug.contains("issuer.example"));
    assert!(config_debug.contains("[REDACTED]"));
    assert!(!config_debug.contains("client-secret"));

    let flow = OidcAuthorizationFlow {
        authorization_url: "https://issuer.example/authorize?state=csrf-secret".to_string(),
        state: "csrf-secret".to_string(),
        nonce: "nonce-secret".to_string(),
        pkce_verifier: "pkce-secret".to_string(),
    };
    let flow_debug = format!("{flow:?}");
    assert!(!flow_debug.contains("csrf-secret"));
    assert!(!flow_debug.contains("nonce-secret"));
    assert!(!flow_debug.contains("pkce-secret"));
}

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

#[test]
fn identity_debug_output_redacts_personal_claims() {
    let identity = OidcIdentity {
        subject: "subject-secret".to_string(),
        username: "operator-name".to_string(),
        email: Some("operator@example.test".to_string()),
        email_verified: Some(true),
        name: "Operator Person".to_string(),
        groups: vec!["control-admins".to_string()],
        claims: BTreeMap::from([(
            "private_claim".to_string(),
            Value::String("private-value".to_string()),
        )]),
        assurance: OidcAssurance {
            provider_session_id: Some("provider-session-secret".to_string()),
            ..OidcAssurance::default()
        },
    };

    let debug = format!("{identity:?}");

    for sensitive in [
        "subject-secret",
        "operator-name",
        "operator@example.test",
        "Operator Person",
        "control-admins",
        "private-value",
        "provider-session-secret",
    ] {
        assert!(!debug.contains(sensitive));
    }
}
