//! Error type of the security header builders.

use std::fmt;

use super::{MAX_CSP_DIRECTIVES, MAX_EXTRA_HEADERS};

/// Invalid security header configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderPolicyError {
    /// CSP directive name is not lowercase letters and dashes.
    InvalidCspDirective(String),
    /// CSP source is empty, too long, or contains whitespace, `;` or `,`.
    InvalidCspSource(String),
    /// Too many CSP directives.
    TooManyCspDirectives,
    /// Too many sources in one CSP directive.
    TooManyCspSources(String),
    /// Permissions-Policy feature name is invalid.
    InvalidPermissionsFeature(String),
    /// Too many Permissions-Policy features.
    TooManyPermissionsFeatures,
    /// An origin (Permissions-Policy or frame ancestor) is invalid.
    InvalidOrigin(String),
    /// A rendered value or extra header is not a valid HTTP header.
    InvalidHeader(String),
    /// Too many extra headers.
    TooManyExtraHeaders,
    /// `keep_if_present` names a header the policy does not send (typo or a
    /// header disabled with `None`).
    KeptHeaderNotInPolicy(String),
}

impl fmt::Display for HeaderPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCspDirective(raw) => write!(f, "invalid CSP directive '{raw}'"),
            Self::InvalidCspSource(raw) => write!(f, "invalid CSP source '{raw}'"),
            Self::TooManyCspDirectives => {
                write!(f, "more than {MAX_CSP_DIRECTIVES} CSP directives")
            }
            Self::TooManyCspSources(name) => {
                write!(f, "too many sources in CSP directive '{name}'")
            }
            Self::InvalidPermissionsFeature(raw) => {
                write!(f, "invalid Permissions-Policy feature '{raw}'")
            }
            Self::TooManyPermissionsFeatures => f.write_str("too many Permissions-Policy features"),
            Self::InvalidOrigin(raw) => write!(f, "invalid origin '{raw}'"),
            Self::InvalidHeader(name) => write!(f, "invalid header '{name}'"),
            Self::TooManyExtraHeaders => write!(f, "more than {MAX_EXTRA_HEADERS} extra headers"),
            Self::KeptHeaderNotInPolicy(name) => {
                write!(
                    f,
                    "keep_if_present names '{name}', which the policy does not send"
                )
            }
        }
    }
}

impl std::error::Error for HeaderPolicyError {}
