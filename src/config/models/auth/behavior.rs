use super::defaults::default_step_up_factor;
use super::{AuthConfig, AuthStepUpConfig, LdapConfig};
use auth_modules::ldap::{
    default_ldap_email_attr, default_ldap_groups_attr, default_ldap_name_attr, default_ldap_scope,
    default_ldap_user_filter, default_ldap_username_attr, ldap_scope_from_name,
};
use auth_modules::methods::{HARDWARE_KEY, PASSKEY, TOTP};
use auth_modules::step_up::{StepUpFactor, StepUpPolicy};

impl LdapConfig {
    pub fn to_auth_modules_config(&self) -> Option<auth_modules::ldap::LdapAuthConfig> {
        let url = self.url.trim();
        if url.is_empty() {
            return None;
        }
        let bind_dn_template = clean_optional_string(&self.bind_dn_template);
        let service_bind_dn = clean_optional_string(&self.service_bind_dn);
        let service_bind_password = clean_optional_string(&self.service_bind_password);
        if bind_dn_template.is_none()
            && (service_bind_dn.is_none() || service_bind_password.is_none())
        {
            return None;
        }
        Some(auth_modules::ldap::LdapAuthConfig {
            url: url.to_string(),
            bind_dn_template,
            service_bind_dn,
            service_bind_password,
            base_dn: clean_optional_string(&self.base_dn),
            user_filter: clean_optional_string(&self.user_filter)
                .unwrap_or_else(default_ldap_user_filter),
            scope: ldap_scope_from_name(&self.scope).unwrap_or_else(default_ldap_scope),
            username_attr: clean_optional_string(&self.username_attr)
                .unwrap_or_else(default_ldap_username_attr),
            email_attr: clean_optional_string(&self.email_attr)
                .unwrap_or_else(default_ldap_email_attr),
            name_attr: clean_optional_string(&self.name_attr)
                .unwrap_or_else(default_ldap_name_attr),
            groups_attr: clean_optional_string(&self.groups_attr)
                .unwrap_or_else(default_ldap_groups_attr),
            timeout_secs: self.timeout_secs.clamp(1, 60),
        })
    }
}

impl AuthConfig {
    pub fn step_up_policy(&self) -> StepUpPolicy {
        if self.step_up.required_after_primary || self.step_up.oidc_requires_passkey {
            StepUpPolicy {
                required_after_primary: true,
                factor: self.step_up.factor(),
            }
        } else {
            StepUpPolicy::new()
        }
    }
}

impl AuthStepUpConfig {
    pub fn factor(&self) -> StepUpFactor {
        match self.factor.as_str() {
            TOTP => StepUpFactor::Totp,
            HARDWARE_KEY => StepUpFactor::HardwareKey,
            _ => StepUpFactor::Passkey,
        }
    }

    pub fn normalize(&mut self) -> bool {
        let mut changed = false;
        if self.oidc_requires_passkey {
            self.required_after_primary = true;
            self.factor = PASSKEY.to_string();
            self.oidc_requires_passkey = false;
            changed = true;
        }
        if !matches!(self.factor.as_str(), PASSKEY | HARDWARE_KEY | TOTP) {
            self.factor = PASSKEY.to_string();
            changed = true;
        }
        changed
    }
}

impl Default for AuthStepUpConfig {
    fn default() -> Self {
        Self {
            required_after_primary: false,
            factor: default_step_up_factor(),
            oidc_requires_passkey: false,
        }
    }
}

fn clean_optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty() && trimmed != "***SET***").then(|| trimmed.to_string())
}
