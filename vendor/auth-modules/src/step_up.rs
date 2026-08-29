use crate::methods::{
    API_TOKEN, HARDWARE_KEY, LDAP, MAGIC_LINK, OIDC, PASSKEY, PASSWORD, TOTP, TRUSTED_PROXY,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimaryAuthMethod {
    None,
    Password,
    Oidc,
    Ldap,
    TrustedProxy,
    MagicLink,
    Passkey,
    ApiToken,
}

impl PrimaryAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Password => PASSWORD,
            Self::Oidc => OIDC,
            Self::Ldap => LDAP,
            Self::TrustedProxy => TRUSTED_PROXY,
            Self::MagicLink => MAGIC_LINK,
            Self::Passkey => PASSKEY,
            Self::ApiToken => API_TOKEN,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "none" | "no_auth" | "no-auth" => Some(Self::None),
            PASSWORD | "local" | "basic" => Some(Self::Password),
            OIDC | "openid" | "openid-connect" => Some(Self::Oidc),
            LDAP | "ad" | "active-directory" => Some(Self::Ldap),
            TRUSTED_PROXY | "trusted-proxy" | "proxy" => Some(Self::TrustedProxy),
            MAGIC_LINK | "magic-link" => Some(Self::MagicLink),
            PASSKEY | HARDWARE_KEY | "hardware-key" | "security-key" => Some(Self::Passkey),
            API_TOKEN | "api-token" | "bearer" | "token" => Some(Self::ApiToken),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepUpFactor {
    Totp,
    Passkey,
    HardwareKey,
}

impl StepUpFactor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => TOTP,
            Self::Passkey => PASSKEY,
            Self::HardwareKey => HARDWARE_KEY,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            TOTP | "otp" | "authenticator" => Some(Self::Totp),
            PASSKEY | "webauthn" => Some(Self::Passkey),
            HARDWARE_KEY | "hardware-key" | "security_key" | "security-key" => {
                Some(Self::HardwareKey)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepUpRequirement {
    pub required: bool,
    pub factor: Option<StepUpFactor>,
    pub reason: &'static str,
}

impl StepUpRequirement {
    pub const fn none() -> Self {
        Self {
            required: false,
            factor: None,
            reason: "not_required",
        }
    }

    pub const fn passkey(reason: &'static str) -> Self {
        Self::factor(StepUpFactor::Passkey, reason)
    }

    pub const fn factor(factor: StepUpFactor, reason: &'static str) -> Self {
        Self {
            required: true,
            factor: Some(factor),
            reason,
        }
    }

    pub const fn unsatisfiable(reason: &'static str) -> Self {
        Self {
            required: true,
            factor: None,
            reason,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepUpPolicy {
    pub required_after_primary: bool,
    pub factor: StepUpFactor,
}

impl Default for StepUpPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl StepUpPolicy {
    pub const fn new() -> Self {
        Self {
            required_after_primary: false,
            factor: StepUpFactor::Passkey,
        }
    }

    pub const fn passkey_required_after_primary() -> Self {
        Self {
            required_after_primary: true,
            factor: StepUpFactor::Passkey,
        }
    }

    pub const fn totp_required_after_primary() -> Self {
        Self {
            required_after_primary: true,
            factor: StepUpFactor::Totp,
        }
    }

    pub const fn required_after_primary(factor: StepUpFactor) -> Self {
        Self {
            required_after_primary: true,
            factor,
        }
    }

    pub fn requirement_after_primary(self, primary: PrimaryAuthMethod) -> StepUpRequirement {
        match primary {
            PrimaryAuthMethod::None | PrimaryAuthMethod::ApiToken
                if self.required_after_primary =>
            {
                StepUpRequirement::unsatisfiable("primary_auth_cannot_satisfy_step_up")
            }
            PrimaryAuthMethod::Passkey if self.factor == StepUpFactor::Passkey => {
                StepUpRequirement::none()
            }
            PrimaryAuthMethod::Passkey if self.factor == StepUpFactor::HardwareKey => {
                StepUpRequirement::none()
            }
            _ if self.required_after_primary => {
                StepUpRequirement::factor(self.factor, "primary_auth_step_up")
            }
            _ => StepUpRequirement::none(),
        }
    }
}

#[cfg(test)]
mod tests;
