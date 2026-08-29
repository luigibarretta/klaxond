use std::env;
use std::time::Duration as StdDuration;

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry, SearchOptions};

use super::defaults::{
    default_ldap_email_attr, default_ldap_groups_attr, default_ldap_name_attr, default_ldap_scope,
    default_ldap_user_filter, default_ldap_username_attr, ldap_scope_from_name,
    DEFAULT_TIMEOUT_SECS,
};
use super::escaping::{escape_filter_value, interpolate_bind_dn};
use super::types::{attr_first, LdapError, LdapIdentity, LdapUserEntry};

#[derive(Clone)]
pub struct LdapAuthConfig {
    pub url: String,
    pub bind_dn_template: Option<String>,
    pub service_bind_dn: Option<String>,
    pub service_bind_password: Option<String>,
    pub base_dn: Option<String>,
    pub user_filter: String,
    pub scope: Scope,
    pub username_attr: String,
    pub email_attr: String,
    pub name_attr: String,
    pub groups_attr: String,
    pub timeout_secs: u64,
}

impl LdapAuthConfig {
    pub fn from_env_prefix(prefix: &str) -> Option<Self> {
        let url = non_empty_env(&format!("{prefix}_URL"))?;
        Some(Self {
            url,
            bind_dn_template: non_empty_env(&format!("{prefix}_BIND_DN_TEMPLATE")),
            service_bind_dn: non_empty_env(&format!("{prefix}_BIND_DN")),
            service_bind_password: non_empty_env(&format!("{prefix}_BIND_PASSWORD")),
            base_dn: non_empty_env(&format!("{prefix}_BASE_DN")),
            user_filter: non_empty_env(&format!("{prefix}_USER_FILTER"))
                .unwrap_or_else(default_ldap_user_filter),
            scope: non_empty_env(&format!("{prefix}_SCOPE"))
                .and_then(|value| ldap_scope_from_name(&value))
                .unwrap_or_else(default_ldap_scope),
            username_attr: non_empty_env(&format!("{prefix}_ATTR_USERNAME"))
                .unwrap_or_else(default_ldap_username_attr),
            email_attr: non_empty_env(&format!("{prefix}_ATTR_EMAIL"))
                .unwrap_or_else(default_ldap_email_attr),
            name_attr: non_empty_env(&format!("{prefix}_ATTR_NAME"))
                .unwrap_or_else(default_ldap_name_attr),
            groups_attr: non_empty_env(&format!("{prefix}_ATTR_GROUPS"))
                .unwrap_or_else(default_ldap_groups_attr),
            timeout_secs: non_empty_env(&format!("{prefix}_TIMEOUT_SECS"))
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(DEFAULT_TIMEOUT_SECS),
        })
    }

    pub fn configured(&self) -> bool {
        !self.url.trim().is_empty()
            && (self.bind_dn_template.is_some()
                || (self.service_bind_dn.is_some() && self.service_bind_password.is_some()))
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Result<LdapIdentity, LdapError> {
        self.validate()?;
        if username.trim().is_empty() || password.is_empty() {
            return Err(LdapError::InvalidCredentials);
        }
        let mut ldap = self.connect()?;
        let entry = self.bind_and_resolve_user(&mut ldap, username.trim(), password)?;
        let _ = ldap.unbind();
        Ok(entry.into_identity())
    }

    fn bind_and_resolve_user(
        &self,
        ldap: &mut LdapConn,
        username: &str,
        password: &str,
    ) -> Result<LdapUserEntry, LdapError> {
        if let Some(template) = self.bind_dn_template.as_deref() {
            return self.bind_direct_user(ldap, template, username, password);
        }

        let bind_dn = self
            .service_bind_dn
            .as_deref()
            .ok_or(LdapError::MissingServiceBind)?;
        let bind_password = self
            .service_bind_password
            .as_deref()
            .ok_or(LdapError::MissingServiceBind)?;
        self.with_timeout(ldap)
            .simple_bind(bind_dn, bind_password)
            .map_err(LdapError::Bind)?
            .success()
            .map_err(LdapError::Bind)?;
        let entry = self
            .search_user(ldap, username)?
            .ok_or(LdapError::UserNotFound)?;
        self.with_timeout(ldap)
            .simple_bind(&entry.dn, password)
            .map_err(LdapError::Bind)?
            .success()
            .map_err(LdapError::Bind)?;
        Ok(entry)
    }

    fn bind_direct_user(
        &self,
        ldap: &mut LdapConn,
        template: &str,
        username: &str,
        password: &str,
    ) -> Result<LdapUserEntry, LdapError> {
        let bind_dn = interpolate_bind_dn(template, username);
        self.with_timeout(ldap)
            .simple_bind(&bind_dn, password)
            .map_err(LdapError::Bind)?
            .success()
            .map_err(LdapError::Bind)?;
        self.search_bound_user(ldap, &bind_dn, username)?
            .ok_or(LdapError::UserNotFound)
    }

    fn connect(&self) -> Result<LdapConn, LdapError> {
        let settings =
            LdapConnSettings::new().set_conn_timeout(StdDuration::from_secs(self.timeout_secs));
        LdapConn::with_settings(settings, &self.url).map_err(LdapError::Connect)
    }

    fn search_user(
        &self,
        ldap: &mut LdapConn,
        username: &str,
    ) -> Result<Option<LdapUserEntry>, LdapError> {
        let Some(base_dn) = self.base_dn.as_deref() else {
            return Ok(None);
        };
        let escaped = escape_filter_value(username.trim());
        let filter = self.user_filter.replace("{username}", &escaped);
        let (entries, _) = self
            .with_search_limits(ldap)
            .search(base_dn, self.scope, &filter, self.attrs())
            .map_err(LdapError::Search)?
            .success()
            .map_err(LdapError::Search)?;
        self.single_user_entry(entries, username)
    }

    fn search_bound_user(
        &self,
        ldap: &mut LdapConn,
        bind_dn: &str,
        username: &str,
    ) -> Result<Option<LdapUserEntry>, LdapError> {
        let (entries, _) = self
            .with_search_limits(ldap)
            .search(bind_dn, Scope::Base, "(objectClass=*)", self.attrs())
            .map_err(LdapError::Search)?
            .success()
            .map_err(LdapError::Search)?;
        self.single_user_entry(entries, username)
    }

    fn attrs(&self) -> Vec<&str> {
        vec![
            self.username_attr.as_str(),
            self.email_attr.as_str(),
            self.name_attr.as_str(),
            self.groups_attr.as_str(),
        ]
    }

    fn user_entry(&self, entry: SearchEntry, fallback_username: &str) -> LdapUserEntry {
        let username = attr_first(&entry, &self.username_attr)
            .or_else(|| attr_first(&entry, "sAMAccountName"))
            .or_else(|| attr_first(&entry, "uid"))
            .unwrap_or_else(|| fallback_username.trim().to_string());
        let email = attr_first(&entry, &self.email_attr)
            .or_else(|| username.contains('@').then(|| username.trim().to_string()));
        let name = attr_first(&entry, &self.name_attr)
            .or_else(|| attr_first(&entry, "displayName"))
            .or_else(|| email.clone())
            .unwrap_or_else(|| username.clone());
        let groups = entry
            .attrs
            .get(&self.groups_attr)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect();
        LdapUserEntry {
            dn: entry.dn,
            username,
            email,
            name,
            groups,
        }
    }

    fn single_user_entry(
        &self,
        entries: Vec<ldap3::ResultEntry>,
        fallback_username: &str,
    ) -> Result<Option<LdapUserEntry>, LdapError> {
        let mut entries = entries.into_iter();
        let first = entries.next().map(SearchEntry::construct);
        if entries.next().is_some() {
            return Err(LdapError::AmbiguousUser);
        }
        Ok(first.map(|entry| self.user_entry(entry, fallback_username)))
    }

    fn with_timeout<'a>(&self, ldap: &'a mut LdapConn) -> &'a mut LdapConn {
        ldap.with_timeout(StdDuration::from_secs(self.timeout_secs))
    }

    fn with_search_limits<'a>(&self, ldap: &'a mut LdapConn) -> &'a mut LdapConn {
        let server_timeout = i32::try_from(self.timeout_secs).unwrap_or(i32::MAX);
        ldap.with_timeout(StdDuration::from_secs(self.timeout_secs))
            .with_search_options(SearchOptions::new().sizelimit(2).timelimit(server_timeout))
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
