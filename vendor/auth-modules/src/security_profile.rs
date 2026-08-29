use crate::password::PasswordPolicy;
use crate::rate_limit::{
    gold_auth_account_failure_policy, PersistentRateLimitPolicy, GOLD_AUTH_IP_BURST_MAX,
    GOLD_AUTH_IP_BURST_WINDOW, GOLD_AUTH_SHORT_BURST_MAX, GOLD_AUTH_SHORT_BURST_WINDOW,
};
use crate::session_policy::SessionPolicy;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoldAuthProfileKind {
    PersonalDefault,
    HighSecurity,
}

impl GoldAuthProfileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PersonalDefault => "personal_default",
            Self::HighSecurity => "high_security",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoldAuthProfile {
    pub kind: GoldAuthProfileKind,
    pub password_policy: PasswordPolicy,
    pub account_failure_policy: PersistentRateLimitPolicy,
    pub session_policy: SessionPolicy,
    pub ip_burst_max: usize,
    pub ip_burst_window_seconds: u64,
    pub short_burst_max: usize,
    pub short_burst_window_seconds: u64,
    pub require_argon2id: bool,
    pub require_oidc_wrapper: bool,
    pub require_dynamic_password_policy_endpoint: bool,
    pub require_auth_methods_endpoint: bool,
}

impl GoldAuthProfile {
    pub fn personal_default() -> Self {
        Self {
            kind: GoldAuthProfileKind::PersonalDefault,
            password_policy: PasswordPolicy::gold_standard(),
            account_failure_policy: gold_auth_account_failure_policy(),
            session_policy: SessionPolicy::gold_standard(),
            ip_burst_max: GOLD_AUTH_IP_BURST_MAX,
            ip_burst_window_seconds: GOLD_AUTH_IP_BURST_WINDOW.as_secs(),
            short_burst_max: GOLD_AUTH_SHORT_BURST_MAX,
            short_burst_window_seconds: GOLD_AUTH_SHORT_BURST_WINDOW.as_secs(),
            require_argon2id: true,
            require_oidc_wrapper: true,
            require_dynamic_password_policy_endpoint: true,
            require_auth_methods_endpoint: true,
        }
    }

    pub fn high_security() -> Self {
        Self {
            kind: GoldAuthProfileKind::HighSecurity,
            password_policy: PasswordPolicy {
                min_length: 16,
                ..PasswordPolicy::gold_standard()
            },
            account_failure_policy: PersistentRateLimitPolicy::new(
                5,
                std::time::Duration::from_secs(5 * 60),
                std::time::Duration::from_secs(30 * 60),
            ),
            session_policy: SessionPolicy::high_security(),
            ip_burst_max: 20,
            ip_burst_window_seconds: 60,
            short_burst_max: 5,
            short_burst_window_seconds: 60,
            require_argon2id: true,
            require_oidc_wrapper: true,
            require_dynamic_password_policy_endpoint: true,
            require_auth_methods_endpoint: true,
        }
    }
}

impl Default for GoldAuthProfile {
    fn default() -> Self {
        Self::personal_default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoldAuthProfileSummary {
    pub profile: &'static str,
    pub min_password_length: usize,
    pub max_password_length: Option<usize>,
    pub account_failures: usize,
    pub account_failure_window_seconds: u64,
    pub account_lockout_seconds: u64,
    pub session_max_lifetime_seconds: u64,
    pub session_idle_timeout_seconds: u64,
    pub session_rotation_seconds: u64,
}

impl From<&GoldAuthProfile> for GoldAuthProfileSummary {
    fn from(profile: &GoldAuthProfile) -> Self {
        Self {
            profile: profile.kind.as_str(),
            min_password_length: profile.password_policy.min_length,
            max_password_length: profile.password_policy.max_length,
            account_failures: profile.account_failure_policy.max_failures,
            account_failure_window_seconds: profile.account_failure_policy.failure_window.as_secs(),
            account_lockout_seconds: profile.account_failure_policy.lockout_window.as_secs(),
            session_max_lifetime_seconds: profile.session_policy.max_lifetime.as_secs(),
            session_idle_timeout_seconds: profile.session_policy.idle_timeout.as_secs(),
            session_rotation_seconds: profile.session_policy.rotation_interval.as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_default_matches_gold_password_and_session_policy() {
        let profile = GoldAuthProfile::personal_default();
        let summary = GoldAuthProfileSummary::from(&profile);

        assert_eq!(profile.kind, GoldAuthProfileKind::PersonalDefault);
        assert!(profile.require_argon2id);
        assert!(profile.require_oidc_wrapper);
        assert_eq!(summary.min_password_length, 12);
        assert_eq!(summary.account_failures, 10);
        assert_eq!(summary.session_idle_timeout_seconds, 30 * 60);
    }

    #[test]
    fn high_security_tightens_password_and_account_failure_thresholds() {
        let personal = GoldAuthProfile::personal_default();
        let high = GoldAuthProfile::high_security();

        assert!(high.password_policy.min_length > personal.password_policy.min_length);
        assert!(
            high.account_failure_policy.max_failures < personal.account_failure_policy.max_failures
        );
        assert!(high.session_policy.max_lifetime < personal.session_policy.max_lifetime);
    }
}
