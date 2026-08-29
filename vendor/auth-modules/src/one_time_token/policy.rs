use std::time::Duration;

pub const DEFAULT_ONE_TIME_TOKEN_BYTES: usize = 32;
pub const MAGIC_LINK_TTL: Duration = Duration::from_secs(10 * 60);
pub const PASSWORD_RESET_TTL: Duration = Duration::from_secs(30 * 60);
pub const EMAIL_VERIFICATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OneTimeTokenPurpose {
    MagicLink,
    PasswordReset,
    EmailVerification,
    Invite,
    MfaChallenge,
    Custom(String),
}

impl OneTimeTokenPurpose {
    pub fn as_str(&self) -> &str {
        match self {
            Self::MagicLink => "magic_link",
            Self::PasswordReset => "password_reset",
            Self::EmailVerification => "email_verification",
            Self::Invite => "invite",
            Self::MfaChallenge => "mfa_challenge",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneTimeTokenPolicy {
    pub token_bytes: usize,
    pub ttl: Duration,
}

impl OneTimeTokenPolicy {
    pub fn new(token_bytes: usize, ttl: Duration) -> Self {
        Self {
            token_bytes: token_bytes.max(16),
            ttl,
        }
    }

    pub fn magic_link() -> Self {
        Self::new(DEFAULT_ONE_TIME_TOKEN_BYTES, MAGIC_LINK_TTL)
    }

    pub fn password_reset() -> Self {
        Self::new(DEFAULT_ONE_TIME_TOKEN_BYTES, PASSWORD_RESET_TTL)
    }

    pub fn email_verification() -> Self {
        Self::new(DEFAULT_ONE_TIME_TOKEN_BYTES, EMAIL_VERIFICATION_TTL)
    }
}

impl Default for OneTimeTokenPolicy {
    fn default() -> Self {
        Self::magic_link()
    }
}
