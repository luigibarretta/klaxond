use super::{LdapConfig, WebauthnConfig};
use auth_modules::ldap::{
    default_ldap_email_attr, default_ldap_groups_attr, default_ldap_name_attr, default_ldap_scope,
    default_ldap_timeout_secs, default_ldap_user_filter, default_ldap_username_attr,
    ldap_scope_name,
};
use auth_modules::methods::PASSKEY;

impl Default for WebauthnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rp_id: String::new(),
            origin: String::new(),
        }
    }
}

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn is_false(value: &bool) -> bool {
    !*value
}

pub(super) fn default_step_up_factor() -> String {
    PASSKEY.to_string()
}

pub(super) fn default_ldap_scope_name() -> String {
    ldap_scope_name(default_ldap_scope()).to_string()
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            bind_dn_template: String::new(),
            service_bind_dn: String::new(),
            service_bind_password: String::new(),
            base_dn: String::new(),
            user_filter: default_ldap_user_filter(),
            scope: default_ldap_scope_name(),
            username_attr: default_ldap_username_attr(),
            email_attr: default_ldap_email_attr(),
            name_attr: default_ldap_name_attr(),
            groups_attr: default_ldap_groups_attr(),
            timeout_secs: default_ldap_timeout_secs(),
        }
    }
}
