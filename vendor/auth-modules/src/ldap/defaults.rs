use ldap3::Scope;

pub const DEFAULT_USER_FILTER: &str =
    "(|(uid={username})(sAMAccountName={username})(mail={username}))";
pub const DEFAULT_USERNAME_ATTR: &str = "uid";
pub const DEFAULT_EMAIL_ATTR: &str = "mail";
pub const DEFAULT_NAME_ATTR: &str = "cn";
pub const DEFAULT_GROUPS_ATTR: &str = "memberOf";
pub const DEFAULT_TIMEOUT_SECS: u64 = 5;

pub fn default_ldap_user_filter() -> String {
    DEFAULT_USER_FILTER.to_string()
}

pub fn default_ldap_scope() -> Scope {
    Scope::Subtree
}

pub fn default_ldap_username_attr() -> String {
    DEFAULT_USERNAME_ATTR.to_string()
}

pub fn default_ldap_email_attr() -> String {
    DEFAULT_EMAIL_ATTR.to_string()
}

pub fn default_ldap_name_attr() -> String {
    DEFAULT_NAME_ATTR.to_string()
}

pub fn default_ldap_groups_attr() -> String {
    DEFAULT_GROUPS_ATTR.to_string()
}

pub fn default_ldap_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

pub fn ldap_scope_from_name(value: &str) -> Option<Scope> {
    match value.trim().to_ascii_lowercase().as_str() {
        "base" => Some(Scope::Base),
        "one" | "onelevel" | "one-level" => Some(Scope::OneLevel),
        "sub" | "subtree" => Some(Scope::Subtree),
        _ => None,
    }
}

pub fn ldap_scope_name(scope: Scope) -> &'static str {
    match scope {
        Scope::Base => "base",
        Scope::OneLevel => "one",
        Scope::Subtree => "subtree",
    }
}
