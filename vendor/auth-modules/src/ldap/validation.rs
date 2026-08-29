use std::env;

use super::{LdapAuthConfig, LdapError};

impl LdapAuthConfig {
    pub fn validate(&self) -> Result<(), LdapError> {
        let url = self.url.trim();
        let insecure_override = insecure_ldap_development_override();
        if url.starts_with("ldap://") && !insecure_override {
            return Err(LdapError::InsecureTransport);
        }
        if !(url.starts_with("ldaps://") || url.starts_with("ldap://") && insecure_override) {
            return Err(LdapError::InvalidConfiguration(
                "URL must use the ldaps:// scheme",
            ));
        }
        if let Some(template) = self.bind_dn_template.as_deref() {
            validate_direct_bind_template(template)?;
        } else if self.service_bind_dn.as_deref().is_none_or(str::is_empty)
            || self
                .service_bind_password
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(LdapError::MissingServiceBind);
        }
        Ok(())
    }
}

fn validate_direct_bind_template(template: &str) -> Result<(), LdapError> {
    let placeholders = template.matches("{username}").count() + template.matches("%s").count();
    if placeholders != 1 {
        return Err(LdapError::InvalidConfiguration(
            "direct-bind DN template must contain exactly one {username} or %s placeholder",
        ));
    }
    Ok(())
}

fn insecure_ldap_development_override() -> bool {
    env::var("AUTH_MODULES_ALLOW_INSECURE_LDAP")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}
