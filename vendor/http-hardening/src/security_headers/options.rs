//! Typed options for the individual security headers.

use super::csp::source_token;
use super::HeaderPolicyError;

/// Maximum number of features in a Permissions-Policy.
pub const MAX_PERMISSIONS_FEATURES: usize = 48;
/// Maximum number of origins allowed for one Permissions-Policy feature.
pub const MAX_PERMISSIONS_ORIGINS: usize = 16;

/// `Strict-Transport-Security` settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hsts {
    max_age_secs: u64,
    include_subdomains: bool,
    preload: bool,
}

impl Default for Hsts {
    /// Two years, `includeSubDomains`, no `preload`.
    fn default() -> Self {
        Self {
            max_age_secs: 63_072_000,
            include_subdomains: true,
            preload: false,
        }
    }
}

impl Hsts {
    /// Custom max-age with `includeSubDomains` and no `preload`.
    pub const fn new(max_age_secs: u64) -> Self {
        Self {
            max_age_secs,
            include_subdomains: true,
            preload: false,
        }
    }

    /// Sets `includeSubDomains`.
    pub const fn include_subdomains(mut self, enabled: bool) -> Self {
        self.include_subdomains = enabled;
        self
    }

    /// Sets `preload` (only meaningful with a max-age of at least one year
    /// and `includeSubDomains`).
    pub const fn preload(mut self, enabled: bool) -> Self {
        self.preload = enabled;
        self
    }

    /// Header value.
    pub fn render(&self) -> String {
        let mut value = format!("max-age={}", self.max_age_secs);
        if self.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if self.preload {
            value.push_str("; preload");
        }
        value
    }
}

/// `Referrer-Policy` values (`unsafe-url` is intentionally not offered).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ReferrerPolicy {
    /// `no-referrer`
    #[default]
    NoReferrer,
    /// `no-referrer-when-downgrade`
    NoReferrerWhenDowngrade,
    /// `origin`
    Origin,
    /// `origin-when-cross-origin`
    OriginWhenCrossOrigin,
    /// `same-origin`
    SameOrigin,
    /// `strict-origin`
    StrictOrigin,
    /// `strict-origin-when-cross-origin`
    StrictOriginWhenCrossOrigin,
}

impl ReferrerPolicy {
    /// Header value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoReferrer => "no-referrer",
            Self::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Self::Origin => "origin",
            Self::OriginWhenCrossOrigin => "origin-when-cross-origin",
            Self::SameOrigin => "same-origin",
            Self::StrictOrigin => "strict-origin",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
        }
    }
}

/// Who may frame the app. Drives both `X-Frame-Options` and the CSP
/// `frame-ancestors` directive so the two never disagree.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum FrameOptions {
    /// No framing: `X-Frame-Options: DENY`, `frame-ancestors 'none'`.
    #[default]
    Deny,
    /// Same origin only: `SAMEORIGIN`, `frame-ancestors 'self'`.
    SameOrigin,
    /// Listed sources only: `frame-ancestors <sources>`, no `X-Frame-Options`
    /// (it cannot express a list).
    Ancestors(Vec<String>),
}

impl FrameOptions {
    pub(super) fn x_frame_options(&self) -> Option<&'static str> {
        match self {
            Self::Deny => Some("DENY"),
            Self::SameOrigin => Some("SAMEORIGIN"),
            Self::Ancestors(_) => None,
        }
    }

    pub(super) fn ancestors(&self) -> Vec<&str> {
        match self {
            Self::Deny => vec!["'none'"],
            Self::Ancestors(list) if list.is_empty() => vec!["'none'"],
            Self::SameOrigin => vec!["'self'"],
            Self::Ancestors(list) => list.iter().map(String::as_str).collect(),
        }
    }
}

/// `Cross-Origin-Opener-Policy` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CrossOriginOpenerPolicy {
    /// `same-origin`
    #[default]
    SameOrigin,
    /// `same-origin-allow-popups` (needed by some OAuth popup flows)
    SameOriginAllowPopups,
    /// `unsafe-none`
    UnsafeNone,
}

impl CrossOriginOpenerPolicy {
    /// Header value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SameOrigin => "same-origin",
            Self::SameOriginAllowPopups => "same-origin-allow-popups",
            Self::UnsafeNone => "unsafe-none",
        }
    }
}

/// `Cross-Origin-Resource-Policy` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CrossOriginResourcePolicy {
    /// `same-origin`
    #[default]
    SameOrigin,
    /// `same-site`
    SameSite,
    /// `cross-origin` (public assets meant to be embedded elsewhere)
    CrossOrigin,
}

impl CrossOriginResourcePolicy {
    /// Header value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SameOrigin => "same-origin",
            Self::SameSite => "same-site",
            Self::CrossOrigin => "cross-origin",
        }
    }
}

/// `Permissions-Policy` builder. The default denies powerful features that
/// typical web apps never need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionsPolicy {
    features: Vec<(String, String)>,
}

const DENIED_BY_DEFAULT: [&str; 12] = [
    "accelerometer",
    "browsing-topics",
    "camera",
    "display-capture",
    "geolocation",
    "gyroscope",
    "magnetometer",
    "microphone",
    "midi",
    "payment",
    "serial",
    "usb",
];

impl Default for PermissionsPolicy {
    fn default() -> Self {
        let features = DENIED_BY_DEFAULT
            .iter()
            .map(|feature| ((*feature).to_owned(), "()".to_owned()))
            .collect();
        Self { features }
    }
}

impl PermissionsPolicy {
    /// Policy without features.
    pub fn empty() -> Self {
        Self {
            features: Vec::new(),
        }
    }

    /// Denies `feature` everywhere: `feature=()`.
    pub fn deny(self, feature: &str) -> Result<Self, HeaderPolicyError> {
        self.put(feature, "()".to_owned())
    }

    /// Allows `feature` for the same origin: `feature=(self)`.
    pub fn allow_self(self, feature: &str) -> Result<Self, HeaderPolicyError> {
        self.put(feature, "(self)".to_owned())
    }

    /// Allows `feature` for the same origin and the listed origins:
    /// `feature=(self "https://a.example")`.
    pub fn allow_origins(self, feature: &str, origins: &[&str]) -> Result<Self, HeaderPolicyError> {
        if origins.len() > MAX_PERMISSIONS_ORIGINS {
            return Err(HeaderPolicyError::InvalidOrigin(format!(
                "more than {MAX_PERMISSIONS_ORIGINS} origins"
            )));
        }
        let mut list = vec!["self".to_owned()];
        for origin in origins {
            let token = source_token(origin)
                .ok()
                .filter(|token| !token.contains(['"', '\\', '(', ')']))
                .ok_or_else(|| HeaderPolicyError::InvalidOrigin((*origin).to_owned()))?;
            list.push(format!("\"{token}\""));
        }
        self.put(feature, format!("({})", list.join(" ")))
    }

    /// Removes `feature` from the policy.
    pub fn remove(mut self, feature: &str) -> Self {
        let name = feature.trim().to_ascii_lowercase();
        self.features.retain(|(existing, _)| *existing != name);
        self
    }

    /// Header value, e.g. `camera=(), geolocation=(self)`.
    pub fn render(&self) -> String {
        let parts: Vec<String> = self
            .features
            .iter()
            .map(|(name, allowlist)| format!("{name}={allowlist}"))
            .collect();
        parts.join(", ")
    }

    /// True when no feature is configured.
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }

    fn put(mut self, feature: &str, allowlist: String) -> Result<Self, HeaderPolicyError> {
        let name = feature.trim().to_ascii_lowercase();
        let valid = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(HeaderPolicyError::InvalidPermissionsFeature(
                feature.to_owned(),
            ));
        }
        if let Some(entry) = self
            .features
            .iter_mut()
            .find(|(existing, _)| *existing == name)
        {
            entry.1 = allowlist;
            return Ok(self);
        }
        if self.features.len() >= MAX_PERMISSIONS_FEATURES {
            return Err(HeaderPolicyError::TooManyPermissionsFeatures);
        }
        self.features.push((name, allowlist));
        Ok(self)
    }
}
