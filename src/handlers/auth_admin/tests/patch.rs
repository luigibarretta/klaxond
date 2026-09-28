use super::super::*;

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

    let patch = patch_fixture();

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
    assert!(auth.step_up.required_after_primary);
    assert_eq!(auth.step_up.factor, "totp");
}

fn patch_fixture() -> AuthSettingsPatch {
    serde_json::from_value(json!({
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
        },
        "step_up": {
            "required_after_primary": true,
            "factor": "totp"
        }
    }))
    .expect("patch")
}
