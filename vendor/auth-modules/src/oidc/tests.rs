use std::collections::BTreeMap;

use serde_json::Value;

use super::*;
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
