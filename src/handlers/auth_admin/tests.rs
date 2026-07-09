use super::*;

#[test]
fn auth_methods_payload_maps_hardware_key_and_magic_link() {
    let mut auth = AuthConfig {
        mode: "basic".to_string(),
        ..Default::default()
    };
    auth.basic.username = "luigi".to_string();
    auth.basic.password_hash = "$argon2id$configured".to_string();
    auth.basic.totp_enabled = true;
    auth.webauthn.enabled = true;

    let payload = auth_methods_payload(&auth);
    let actual = payload["methods"]
        .as_array()
        .expect("methods")
        .iter()
        .map(|row| {
            (
                row["method"].as_str().expect("method"),
                row["enabled"].as_bool().expect("enabled"),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        vec![
            ("password", true),
            ("oidc", false),
            ("totp", true),
            ("passkey", true),
            ("hardware_key", true),
            ("trusted_proxy", false),
            ("ldap", false),
            ("api_token", true),
            ("magic_link", true),
        ]
    );
}

#[test]
fn auth_methods_payload_enables_configured_ldap() {
    let mut auth = AuthConfig {
        mode: "ldap".to_string(),
        ..Default::default()
    };
    auth.ldap.url = "ldaps://directory.example.com:636".to_string();
    auth.ldap.bind_dn_template = "uid={username},ou=people,dc=example,dc=com".to_string();

    let payload = auth_methods_payload(&auth);
    let methods = payload["methods"].as_array().expect("methods");

    assert!(
        methods
            .iter()
            .any(|row| row["method"] == "ldap" && row["enabled"] == true)
    );
    assert!(
        methods
            .iter()
            .any(|row| row["method"] == "password" && row["enabled"] == false)
    );
}

#[test]
fn auth_settings_patch_preserves_secret_sentinels_and_lenient_fields() {
    let mut auth = AuthConfig {
        mode: "oidc".to_string(),
        session_secret: "existing-session-secret".to_string(),
        session_timeout_hours: 24,
        ..Default::default()
    };
    auth.basic.password_hash = "existing-password-hash".to_string();
    auth.oidc.client_secret = "existing-oidc-secret".to_string();
    auth.ldap.service_bind_password = "existing-ldap-secret".to_string();

    let patch: AuthSettingsPatch = serde_json::from_value(json!({
        "mode": "basic",
        "session_timeout_hours": 9999,
        "session_secret": "***SET***",
        "basic": {
            "username": "luigi",
            "realm": "klaxond-admin",
            "password": "",
            "password_hash": "***SET***"
        },
        "oidc": {
            "issuer": 42,
            "client_secret": "***SET***",
            "required_group": "klaxond-admins"
        },
        "ldap": {
            "url": "  ldaps://directory.example.com  ",
            "service_bind_password": "***SET***",
            "timeout_secs": 999
        },
        "trusted_proxy": {
            "trusted_cidrs": ["127.0.0.1/32", 42, null]
        },
        "webauthn": {
            "enabled": true,
            "origin": " https://klaxond.example.com/ "
        }
    }))
    .expect("patch");

    patch.apply_to(&mut auth).expect("apply patch");

    assert_eq!(auth.mode, "basic");
    assert_eq!(auth.session_timeout_hours, 720);
    assert_eq!(auth.session_secret, "existing-session-secret");
    assert_eq!(auth.basic.username, "luigi");
    assert_eq!(auth.basic.realm, "klaxond-admin");
    assert_eq!(auth.basic.password_hash, "existing-password-hash");
    assert_eq!(auth.oidc.issuer, "");
    assert_eq!(auth.oidc.client_secret, "existing-oidc-secret");
    assert_eq!(auth.oidc.required_group, "klaxond-admins");
    assert_eq!(auth.ldap.url, "ldaps://directory.example.com");
    assert_eq!(auth.ldap.service_bind_password, "existing-ldap-secret");
    assert_eq!(auth.ldap.timeout_secs, 60);
    assert_eq!(auth.trusted_proxy.trusted_cidrs, vec!["127.0.0.1/32"]);
    assert!(auth.webauthn.enabled);
    assert_eq!(auth.webauthn.origin, "https://klaxond.example.com");
}

#[test]
fn auth_settings_patch_rejects_invalid_mode() {
    let mut auth = AuthConfig::default();
    let patch: AuthSettingsPatch =
        serde_json::from_value(json!({ "mode": "invalid" })).expect("patch");

    assert!(matches!(
        patch.apply_to(&mut auth),
        Err(AuthConfigPatchError::InvalidMode)
    ));
}
