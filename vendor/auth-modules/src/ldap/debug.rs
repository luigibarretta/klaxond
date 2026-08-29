use std::fmt;

use super::LdapAuthConfig;

impl fmt::Debug for LdapAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LdapAuthConfig")
            .field("url", &self.url)
            .field("bind_dn_template", &self.bind_dn_template)
            .field("service_bind_dn", &self.service_bind_dn)
            .field(
                "service_bind_password",
                &self.service_bind_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("base_dn", &self.base_dn)
            .field("user_filter", &self.user_filter)
            .field("scope", &self.scope)
            .field("username_attr", &self.username_attr)
            .field("email_attr", &self.email_attr)
            .field("name_attr", &self.name_attr)
            .field("groups_attr", &self.groups_attr)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}
