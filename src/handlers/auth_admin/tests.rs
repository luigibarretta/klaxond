use super::*;

mod patch;

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
fn auth_settings_hide_totp_replay_counters() {
    let mut auth = AuthConfig::default();
    auth.basic.totp_last_counter = Some(42);
    auth.totp_factors.push(crate::config::TotpRecord {
        id: "totp-1".to_string(),
        name: "Authenticator".to_string(),
        user_sub: "user-1".to_string(),
        user_name: "User".to_string(),
        user_email: "user@example.test".to_string(),
        secret: "SECRET".to_string(),
        created_at: 1,
        last_used_at: Some(2),
        last_used_counter: Some(42),
    });

    let settings = redacted_auth_settings(&auth);

    assert!(settings["basic"].get("totp_last_counter").is_none());
    assert!(
        settings["totp_factors"][0]
            .get("last_used_counter")
            .is_none()
    );
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
