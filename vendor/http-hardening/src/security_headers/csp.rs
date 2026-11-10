//! Content-Security-Policy builder.

use super::HeaderPolicyError;

/// Maximum number of directives in one policy.
pub const MAX_CSP_DIRECTIVES: usize = 32;
/// Maximum number of sources in one directive.
pub const MAX_CSP_SOURCES: usize = 64;
const MAX_TOKEN_LEN: usize = 512;

/// Ordered list of CSP directives with validated tokens.
///
/// [`ContentSecurityPolicy::strict`] is a deny-by-default policy for apps
/// that serve their own scripts and styles from the same origin:
///
/// ```text
/// default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
/// font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self';
/// base-uri 'none'; object-src 'none'; frame-ancestors 'none'
/// ```
///
/// `form-action` is deliberately absent: Chrome applies it to every redirect
/// of a form submission, so `form-action 'self'` breaks a login POST that
/// answers 302 to an external identity provider. Apps without such a flow can
/// add it with `.add("form-action", "'self'")` (plus the IdP origin if needed).
///
/// Inline scripts: per-request nonces are not supported. For a fixed inline
/// bootstrap script (e.g. klaxond's theme/language snippet) add its hash,
/// computed with `openssl dgst -sha256 -binary script.js | openssl base64`,
/// as `.add("script-src", "'sha256-<base64>'")`, or move it to a file.
///
/// Per-app needs are expressed with [`ContentSecurityPolicy::set`],
/// [`ContentSecurityPolicy::add`] and [`ContentSecurityPolicy::remove`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentSecurityPolicy {
    directives: Vec<(String, Vec<String>)>,
    upgrade_insecure_requests: bool,
}

const STRICT: [(&str, &[&str]); 11] = [
    ("default-src", &["'none'"]),
    ("script-src", &["'self'"]),
    ("style-src", &["'self'"]),
    ("img-src", &["'self'", "data:"]),
    ("font-src", &["'self'"]),
    ("connect-src", &["'self'"]),
    ("manifest-src", &["'self'"]),
    ("worker-src", &["'self'"]),
    ("base-uri", &["'none'"]),
    ("object-src", &["'none'"]),
    ("frame-ancestors", &["'none'"]),
];

impl Default for ContentSecurityPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

impl ContentSecurityPolicy {
    /// Deny-by-default policy (see the type documentation).
    pub fn strict() -> Self {
        let directives = STRICT
            .iter()
            .map(|(name, sources)| {
                let sources = sources.iter().map(|s| (*s).to_owned()).collect();
                ((*name).to_owned(), sources)
            })
            .collect();
        Self {
            directives,
            upgrade_insecure_requests: false,
        }
    }

    /// Policy without directives.
    pub fn empty() -> Self {
        Self {
            directives: Vec::new(),
            upgrade_insecure_requests: false,
        }
    }

    /// Replaces (or creates) `directive` with exactly `sources`. An empty
    /// source list renders the directive alone (e.g. `sandbox`).
    pub fn set(mut self, directive: &str, sources: &[&str]) -> Result<Self, HeaderPolicyError> {
        let name = directive_name(directive)?;
        if sources.len() > MAX_CSP_SOURCES {
            return Err(HeaderPolicyError::TooManyCspSources(name));
        }
        let sources = sources
            .iter()
            .map(|source| source_token(source))
            .collect::<Result<Vec<_>, _>>()?;
        match self.position(&name) {
            Some(index) => {
                if let Some(entry) = self.directives.get_mut(index) {
                    entry.1 = sources;
                }
            }
            None => self.push(name, sources)?,
        }
        Ok(self)
    }

    /// Appends one source to `directive`, creating it if missing. A lone
    /// `'none'` is replaced, since `'none'` cannot be combined with sources.
    pub fn add(mut self, directive: &str, source: &str) -> Result<Self, HeaderPolicyError> {
        let name = directive_name(directive)?;
        let source = source_token(source)?;
        let Some(index) = self.position(&name) else {
            self.push(name, vec![source])?;
            return Ok(self);
        };
        if let Some((_, sources)) = self.directives.get_mut(index) {
            sources.retain(|existing| existing != "'none'");
            if !sources.contains(&source) {
                if sources.len() >= MAX_CSP_SOURCES {
                    return Err(HeaderPolicyError::TooManyCspSources(name));
                }
                sources.push(source);
            }
        }
        Ok(self)
    }

    /// Removes `directive` if present (names are case-insensitive).
    pub fn remove(mut self, directive: &str) -> Self {
        let name = directive.trim().to_ascii_lowercase();
        self.directives.retain(|(existing, _)| *existing != name);
        self
    }

    /// Adds or removes the `upgrade-insecure-requests` flag.
    pub fn upgrade_insecure_requests(mut self, enabled: bool) -> Self {
        self.upgrade_insecure_requests = enabled;
        self
    }

    /// Sources of `directive`, if present.
    pub fn sources(&self, directive: &str) -> Option<&[String]> {
        let name = directive.trim().to_ascii_lowercase();
        self.position(&name)
            .and_then(|index| self.directives.get(index))
            .map(|(_, sources)| sources.as_slice())
    }

    /// Serialises the policy as a header value.
    pub fn render(&self) -> String {
        let mut parts: Vec<String> = self
            .directives
            .iter()
            .map(|(name, sources)| {
                if sources.is_empty() {
                    name.clone()
                } else {
                    format!("{name} {}", sources.join(" "))
                }
            })
            .collect();
        if self.upgrade_insecure_requests {
            parts.push("upgrade-insecure-requests".to_owned());
        }
        parts.join("; ")
    }

    fn position(&self, name: &str) -> Option<usize> {
        self.directives
            .iter()
            .position(|(existing, _)| existing == name)
    }

    fn push(&mut self, name: String, sources: Vec<String>) -> Result<(), HeaderPolicyError> {
        if self.directives.len() >= MAX_CSP_DIRECTIVES {
            return Err(HeaderPolicyError::TooManyCspDirectives);
        }
        self.directives.push((name, sources));
        Ok(())
    }
}

/// Directive names are lowercase ASCII letters and dashes.
fn directive_name(raw: &str) -> Result<String, HeaderPolicyError> {
    let name = raw.trim().to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
    if valid {
        Ok(name)
    } else {
        Err(HeaderPolicyError::InvalidCspDirective(raw.to_owned()))
    }
}

/// Sources are visible ASCII without the `;` and `,` policy separators, so a
/// source can never inject a directive or a second policy.
pub(super) fn source_token(raw: &str) -> Result<String, HeaderPolicyError> {
    let token = raw.trim();
    let valid = !token.is_empty()
        && token.len() <= MAX_TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b';' && b != b',');
    if valid {
        Ok(token.to_owned())
    } else {
        Err(HeaderPolicyError::InvalidCspSource(raw.to_owned()))
    }
}
