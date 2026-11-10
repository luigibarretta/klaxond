//! Redirect handling policy.
//!
//! A redirect is a new outbound request chosen by the remote server, so it
//! must pass the same checks as the first one. The default is to not follow
//! redirects at all; `Revalidate` follows a bounded number of hops and checks
//! every hop (scheme, credentials, literal address, port, no downgrade). DNS
//! names of each hop are checked by the resolver adapters at connect time.

use url::Url;

use super::error::NetGuardError;
use super::NetGuard;

/// Hard upper bound on followed redirects, whatever the configuration says.
pub const MAX_REDIRECT_HOPS: u8 = 10;

/// What to do with HTTP redirects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RedirectPolicy {
    /// Never follow redirects (the 3xx response is returned to the caller).
    #[default]
    Disabled,
    /// Follow at most `max_hops` redirects, validating every hop.
    Revalidate {
        /// Maximum number of redirects to follow (clamped to
        /// [`MAX_REDIRECT_HOPS`]).
        max_hops: u8,
    },
}

impl RedirectPolicy {
    /// Bounded revalidating policy; `max_hops` is clamped to
    /// [`MAX_REDIRECT_HOPS`] and zero means [`RedirectPolicy::Disabled`].
    pub fn revalidate(max_hops: u8) -> Self {
        match max_hops.min(MAX_REDIRECT_HOPS) {
            0 => Self::Disabled,
            max_hops => Self::Revalidate { max_hops },
        }
    }

    /// Number of hops that may be followed.
    pub const fn max_hops(self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::Revalidate { max_hops } => max_hops,
        }
    }
}

impl NetGuard {
    /// Validates the redirect from `from` to `to`. `followed` is the number of
    /// redirects already followed before this one (0 for the first).
    pub fn check_redirect(
        &self,
        from: &Url,
        to: &Url,
        followed: usize,
    ) -> Result<(), NetGuardError> {
        let max_hops = match self.redirects {
            RedirectPolicy::Disabled => return Err(NetGuardError::RedirectsDisabled),
            RedirectPolicy::Revalidate { max_hops } => max_hops,
        };
        if followed >= usize::from(max_hops) {
            return Err(NetGuardError::TooManyRedirects(max_hops));
        }
        self.check_url(to)?;
        if is_secure(from.scheme()) && !is_secure(to.scheme()) {
            return Err(NetGuardError::SchemeDowngrade);
        }
        Ok(())
    }
}

fn is_secure(scheme: &str) -> bool {
    matches!(scheme, "https" | "wss")
}
