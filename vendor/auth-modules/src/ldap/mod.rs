mod config;
mod debug;
mod defaults;
mod escaping;
mod types;
mod validation;

pub use config::LdapAuthConfig;
pub use defaults::{
    default_ldap_email_attr, default_ldap_groups_attr, default_ldap_name_attr, default_ldap_scope,
    default_ldap_timeout_secs, default_ldap_user_filter, default_ldap_username_attr,
    ldap_scope_from_name, ldap_scope_name, DEFAULT_EMAIL_ATTR, DEFAULT_GROUPS_ATTR,
    DEFAULT_NAME_ATTR, DEFAULT_TIMEOUT_SECS, DEFAULT_USERNAME_ATTR, DEFAULT_USER_FILTER,
};
pub use escaping::{escape_dn_value, escape_filter_value, interpolate_bind_dn};
pub use types::{LdapError, LdapIdentity};

#[cfg(test)]
mod tests;
