use ldap3::SearchEntry;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LdapIdentity {
    pub dn: String,
    pub username: String,
    pub email: Option<String>,
    pub name: String,
    pub groups: Vec<String>,
}

#[derive(Debug)]
pub enum LdapError {
    InvalidCredentials,
    InvalidConfiguration(&'static str),
    InsecureTransport,
    MissingServiceBind,
    UserNotFound,
    AmbiguousUser,
    Connect(ldap3::LdapError),
    Bind(ldap3::LdapError),
    Search(ldap3::LdapError),
}

impl std::fmt::Display for LdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCredentials => write!(f, "invalid ldap credentials"),
            Self::InvalidConfiguration(message) => {
                write!(f, "invalid ldap configuration: {message}")
            }
            Self::InsecureTransport => write!(
                f,
                "plaintext ldap transport is disabled; use ldaps:// or explicitly enable the development-only override"
            ),
            Self::MissingServiceBind => write!(f, "ldap service bind is not configured"),
            Self::UserNotFound => write!(f, "ldap user not found"),
            Self::AmbiguousUser => write!(f, "ldap user lookup returned multiple entries"),
            Self::Connect(err) => write!(f, "ldap connect failed: {err}"),
            Self::Bind(err) => write!(f, "ldap bind failed: {err}"),
            Self::Search(err) => write!(f, "ldap search failed: {err}"),
        }
    }
}

impl std::error::Error for LdapError {}

pub(super) struct LdapUserEntry {
    pub(super) dn: String,
    pub(super) username: String,
    pub(super) email: Option<String>,
    pub(super) name: String,
    pub(super) groups: Vec<String>,
}

impl LdapUserEntry {
    pub(super) fn into_identity(self) -> LdapIdentity {
        LdapIdentity {
            dn: self.dn,
            username: self.username,
            email: self.email,
            name: self.name,
            groups: self.groups,
        }
    }
}

pub(super) fn attr_first(entry: &SearchEntry, attr: &str) -> Option<String> {
    entry
        .attrs
        .get(attr)
        .and_then(|values| values.first())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
