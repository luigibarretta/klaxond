use super::{
    AuthConfig, AuthStepUpConfig, BasicAuthConfig, LdapConfig, OidcConfig, TrustedProxyConfig,
    WebauthnConfig,
};

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: "none".to_string(),
            session_secret: String::new(),
            session_timeout_hours: 8,
            basic: BasicAuthConfig {
                username: String::new(),
                password_hash: String::new(),
                realm: "klaxond".to_string(),
                totp_enabled: false,
                totp_secret: String::new(),
                totp_last_counter: None,
            },
            oidc: OidcConfig {
                provider: "authentik".to_string(),
                issuer: String::new(),
                client_id: String::new(),
                client_secret: String::new(),
                scopes: "openid profile email".to_string(),
                required_group: String::new(),
                redirect_path: "/api/auth/callback".to_string(),
            },
            ldap: LdapConfig::default(),
            trusted_proxy: TrustedProxyConfig {
                user_header: "X-Forwarded-User".to_string(),
                email_header: "X-Forwarded-Email".to_string(),
                groups_header: "X-Forwarded-Groups".to_string(),
                trusted_cidrs: vec!["127.0.0.1/32".to_string(), "::1/128".to_string()],
            },
            webauthn: WebauthnConfig::default(),
            step_up: AuthStepUpConfig::default(),
            api_keys: Vec::new(),
            passkeys: Vec::new(),
            totp_factors: Vec::new(),
        }
    }
}
