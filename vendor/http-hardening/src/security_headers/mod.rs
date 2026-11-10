//! Framework-agnostic security response headers.
//!
//! [`SecurityHeaders`] is an immutable, validated list of `(name, value)`
//! pairs built once at startup. The core is std-only: [`SecurityHeaders::headers_str`]
//! yields plain strings for hand-written servers. With the `http` feature,
//! `SecurityHeaders::apply` writes them into an `http::HeaderMap`, and with
//! `tower`, `SecurityHeadersLayer` does it for every response.
//!
//! By default the policy value **replaces** whatever the handler or an
//! upstream (e.g. a reverse-proxied service) already set, so attacker-influenced
//! upstream headers cannot weaken the policy. Individual headers can opt into
//! keeping a handler value with [`SecurityHeadersBuilder::keep_if_present`]
//! (e.g. a looser CSP on a preview route).

mod builder;
mod csp;
mod error;
#[cfg(feature = "tower")]
mod layer;
mod options;
mod validate;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_csp;
#[cfg(test)]
#[cfg(feature = "http")]
mod tests_http;
#[cfg(test)]
#[cfg(feature = "tower")]
mod tests_layer;

pub use builder::{SecurityHeadersBuilder, MAX_EXTRA_HEADERS};
pub use csp::{ContentSecurityPolicy, MAX_CSP_DIRECTIVES, MAX_CSP_SOURCES};
pub use error::HeaderPolicyError;
#[cfg(feature = "tower")]
pub use layer::{ResponseFuture, SecurityHeadersLayer, SecurityHeadersService};
pub use options::{
    CrossOriginOpenerPolicy, CrossOriginResourcePolicy, FrameOptions, Hsts, PermissionsPolicy,
    ReferrerPolicy, MAX_PERMISSIONS_FEATURES, MAX_PERMISSIONS_ORIGINS,
};
pub use validate::{is_valid_header_name, is_valid_header_value};

/// What to do when a response already carries one of the policy headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ExistingHeaders {
    /// Replace it with the policy value (default).
    #[default]
    Overwrite,
    /// Keep every value the handler or upstream already set. Prefer
    /// [`SecurityHeadersBuilder::keep_if_present`] for single headers.
    Keep,
}

/// One validated header (lowercase name) and whether a present value wins.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    name: String,
    value: String,
    keep_existing: bool,
}

/// Validated, ready-to-apply security headers.
#[derive(Clone, Debug)]
pub struct SecurityHeaders {
    entries: Vec<Entry>,
    #[cfg(feature = "http")]
    typed: Vec<(http::HeaderName, http::HeaderValue)>,
}

impl SecurityHeaders {
    /// Builder starting from the strict defaults.
    pub fn builder() -> SecurityHeadersBuilder {
        SecurityHeadersBuilder::default()
    }

    /// Strict defaults (same as `SecurityHeaders::builder().build()`).
    pub fn strict() -> Result<Self, HeaderPolicyError> {
        SecurityHeadersBuilder::default().build()
    }

    /// The headers as `(lowercase name, value)` strings, in application order.
    /// For servers without the `http` crate: write every pair, except that a
    /// header for which [`SecurityHeaders::keeps_existing`] is true may be
    /// skipped when the response already has it.
    pub fn headers_str(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry.value.as_str()))
    }

    /// Value configured for `name` (case-insensitive), if any.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entry(name).map(|entry| entry.value.as_str())
    }

    /// True when a value already present on the response wins for `name`.
    pub fn keeps_existing(&self, name: &str) -> bool {
        self.entry(name).is_some_and(|entry| entry.keep_existing)
    }

    /// Number of headers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the policy sends no header.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(name.trim()))
    }
}

#[cfg(feature = "http")]
impl SecurityHeaders {
    /// The headers as typed `http` 1.x values, in application order.
    pub fn headers(&self) -> &[(http::HeaderName, http::HeaderValue)] {
        &self.typed
    }

    /// Writes the headers into `target`: every policy header replaces any
    /// existing value, except those configured to keep a present value.
    pub fn apply(&self, target: &mut http::HeaderMap) {
        for (entry, (name, value)) in self.entries.iter().zip(&self.typed) {
            if entry.keep_existing && target.contains_key(name) {
                continue;
            }
            target.insert(name.clone(), value.clone());
        }
    }

    fn typed_from(
        entries: &[Entry],
    ) -> Result<Vec<(http::HeaderName, http::HeaderValue)>, HeaderPolicyError> {
        entries
            .iter()
            .map(|entry| {
                let invalid = || HeaderPolicyError::InvalidHeader(entry.name.clone());
                let name =
                    http::HeaderName::from_bytes(entry.name.as_bytes()).map_err(|_| invalid())?;
                let value = http::HeaderValue::from_str(&entry.value).map_err(|_| invalid())?;
                Ok((name, value))
            })
            .collect()
    }
}

impl SecurityHeaders {
    /// Assembles the final policy from validated entries.
    fn from_entries(entries: Vec<Entry>) -> Result<Self, HeaderPolicyError> {
        Ok(Self {
            #[cfg(feature = "http")]
            typed: Self::typed_from(&entries)?,
            entries,
        })
    }
}
