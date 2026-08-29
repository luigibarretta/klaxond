pub const PASSWORD: &str = "password";
pub const OIDC: &str = "oidc";
pub const TOTP: &str = "totp";
pub const PASSKEY: &str = "passkey";
pub const HARDWARE_KEY: &str = "hardware_key";
pub const TRUSTED_PROXY: &str = "trusted_proxy";
pub const LDAP: &str = "ldap";
pub const API_TOKEN: &str = "api_token";
pub const MAGIC_LINK: &str = "magic_link";

pub const GOLD_AUTH_METHODS: [&str; 9] = [
    PASSWORD,
    OIDC,
    TOTP,
    PASSKEY,
    HARDWARE_KEY,
    TRUSTED_PROXY,
    LDAP,
    API_TOKEN,
    MAGIC_LINK,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthMethodStatus {
    pub method: &'static str,
    pub enabled: bool,
}

pub fn is_gold_auth_method(method: &str) -> bool {
    GOLD_AUTH_METHODS.contains(&method)
}

pub fn canonical_auth_method_statuses<F>(mut enabled: F) -> Vec<AuthMethodStatus>
where
    F: FnMut(&str) -> bool,
{
    GOLD_AUTH_METHODS
        .into_iter()
        .map(|method| AuthMethodStatus {
            method,
            enabled: enabled(method),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_method_order_is_stable() {
        assert_eq!(
            GOLD_AUTH_METHODS,
            [
                "password",
                "oidc",
                "totp",
                "passkey",
                "hardware_key",
                "trusted_proxy",
                "ldap",
                "api_token",
                "magic_link",
            ]
        );
    }

    #[test]
    fn status_builder_preserves_order_and_enabled_flags() {
        let rows = canonical_auth_method_statuses(|method| {
            matches!(method, PASSWORD | API_TOKEN | TRUSTED_PROXY)
        });
        assert_eq!(
            rows,
            vec![
                AuthMethodStatus {
                    method: PASSWORD,
                    enabled: true
                },
                AuthMethodStatus {
                    method: OIDC,
                    enabled: false
                },
                AuthMethodStatus {
                    method: TOTP,
                    enabled: false
                },
                AuthMethodStatus {
                    method: PASSKEY,
                    enabled: false
                },
                AuthMethodStatus {
                    method: HARDWARE_KEY,
                    enabled: false
                },
                AuthMethodStatus {
                    method: TRUSTED_PROXY,
                    enabled: true
                },
                AuthMethodStatus {
                    method: LDAP,
                    enabled: false
                },
                AuthMethodStatus {
                    method: API_TOKEN,
                    enabled: true
                },
                AuthMethodStatus {
                    method: MAGIC_LINK,
                    enabled: false
                },
            ]
        );
    }
}
