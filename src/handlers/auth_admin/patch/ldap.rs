use super::deserialize::{optional_string, optional_u64};
use crate::config::AuthConfig;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub(super) struct LdapPatch {
    #[serde(default, deserialize_with = "optional_string")]
    url: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    bind_dn_template: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    service_bind_dn: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    service_bind_password: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    base_dn: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    user_filter: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    scope: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    username_attr: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    email_attr: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    name_attr: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    groups_attr: Option<String>,
    #[serde(default, deserialize_with = "optional_u64")]
    timeout_secs: Option<u64>,
}

impl LdapPatch {
    pub(super) fn apply_to(self, auth: &mut AuthConfig) {
        apply_trimmed_string(self.url, &mut auth.ldap.url);
        apply_trimmed_string(self.bind_dn_template, &mut auth.ldap.bind_dn_template);
        apply_trimmed_string(self.service_bind_dn, &mut auth.ldap.service_bind_dn);
        apply_trimmed_string(self.base_dn, &mut auth.ldap.base_dn);
        apply_trimmed_string(self.user_filter, &mut auth.ldap.user_filter);
        apply_trimmed_string(self.scope, &mut auth.ldap.scope);
        apply_trimmed_string(self.username_attr, &mut auth.ldap.username_attr);
        apply_trimmed_string(self.email_attr, &mut auth.ldap.email_attr);
        apply_trimmed_string(self.name_attr, &mut auth.ldap.name_attr);
        apply_trimmed_string(self.groups_attr, &mut auth.ldap.groups_attr);
        if let Some(password) = self
            .service_bind_password
            .filter(|password| !password.is_empty() && password != "***SET***")
        {
            auth.ldap.service_bind_password = password;
        }
        if let Some(timeout_secs) = self.timeout_secs {
            auth.ldap.timeout_secs = timeout_secs.clamp(1, 60);
        }
    }
}

fn apply_trimmed_string(value: Option<String>, slot: &mut String) {
    if let Some(value) = value {
        *slot = value.trim().to_string();
    }
}
