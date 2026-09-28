use super::super::passkeys::public_passkey;
use crate::auth;
use crate::config::AuthConfig;
use serde_json::{Value, json};

pub(crate) fn redacted_auth_settings(auth_cfg: &AuthConfig) -> Value {
    let mut settings = serde_json::to_value(auth_cfg).unwrap_or_else(|_| json!({}));
    redact_secret(&mut settings, &["session_secret"]);
    redact_secret(&mut settings, &["basic", "password_hash"]);
    redact_secret(&mut settings, &["basic", "totp_secret"]);
    redact_secret(&mut settings, &["oidc", "client_secret"]);
    redact_secret(&mut settings, &["ldap", "service_bind_password"]);
    if let Some(basic) = settings["basic"].as_object_mut() {
        basic.remove("totp_last_counter");
    }
    settings["api_keys"] = json!(
        auth_cfg
            .api_keys
            .iter()
            .map(auth::public_token)
            .collect::<Vec<_>>()
    );
    settings["passkeys"] = json!(
        auth_cfg
            .passkeys
            .iter()
            .map(public_passkey)
            .collect::<Vec<_>>()
    );
    settings["totp_factors"] = json!(
        auth_cfg
            .totp_factors
            .iter()
            .map(|record| json!({
                "id": record.id.as_str(),
                "name": record.name.as_str(),
                "user_sub": record.user_sub.as_str(),
                "user_name": record.user_name.as_str(),
                "user_email": record.user_email.as_str(),
                "created_at": record.created_at,
                "last_used_at": record.last_used_at,
            }))
            .collect::<Vec<_>>()
    );
    settings
}

fn redact_secret(settings: &mut Value, path: &[&str]) {
    let Some(value) = path
        .iter()
        .try_fold(settings, |value, key| value.get_mut(*key))
    else {
        return;
    };
    if !value.as_str().unwrap_or_default().is_empty() {
        *value = json!("***SET***");
    }
}
