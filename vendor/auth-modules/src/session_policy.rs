use std::time::Duration;

pub const GOLD_SESSION_MAX_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
pub const GOLD_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const GOLD_SESSION_ROTATION_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub const GOLD_SESSION_MAX_CONCURRENT: u32 = 3;
pub const HIGH_SECURITY_SESSION_MAX_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
pub const HIGH_SECURITY_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const HIGH_SECURITY_SESSION_ROTATION_INTERVAL: Duration = Duration::from_secs(15 * 60);
pub const SESSION_CLOCK_SKEW: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SameSitePolicy {
    Lax,
    Strict,
    None,
}

impl SameSitePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lax => "lax",
            Self::Strict => "strict",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CookiePolicy {
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSitePolicy,
    pub path: &'static str,
}

impl CookiePolicy {
    pub fn gold_standard() -> Self {
        Self {
            secure: true,
            http_only: true,
            same_site: SameSitePolicy::Lax,
            path: "/",
        }
    }

    pub fn high_security() -> Self {
        Self {
            same_site: SameSitePolicy::Strict,
            ..Self::gold_standard()
        }
    }
}

impl Default for CookiePolicy {
    fn default() -> Self {
        Self::gold_standard()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionPolicy {
    pub max_lifetime: Duration,
    pub idle_timeout: Duration,
    pub rotation_interval: Duration,
    pub max_concurrent_sessions: u32,
    pub require_secure_transport: bool,
    pub validate_ip_address: bool,
    pub max_ip_changes: u32,
    pub cookie: CookiePolicy,
}

impl SessionPolicy {
    pub fn gold_standard() -> Self {
        Self {
            max_lifetime: GOLD_SESSION_MAX_LIFETIME,
            idle_timeout: GOLD_SESSION_IDLE_TIMEOUT,
            rotation_interval: GOLD_SESSION_ROTATION_INTERVAL,
            max_concurrent_sessions: GOLD_SESSION_MAX_CONCURRENT,
            require_secure_transport: true,
            validate_ip_address: false,
            max_ip_changes: 3,
            cookie: CookiePolicy::gold_standard(),
        }
    }

    pub fn high_security() -> Self {
        Self {
            max_lifetime: HIGH_SECURITY_SESSION_MAX_LIFETIME,
            idle_timeout: HIGH_SECURITY_SESSION_IDLE_TIMEOUT,
            rotation_interval: HIGH_SECURITY_SESSION_ROTATION_INTERVAL,
            max_concurrent_sessions: 1,
            require_secure_transport: true,
            validate_ip_address: true,
            max_ip_changes: 1,
            cookie: CookiePolicy::high_security(),
        }
    }

    pub fn mobile() -> Self {
        Self {
            max_lifetime: Duration::from_secs(30 * 24 * 60 * 60),
            idle_timeout: Duration::from_secs(7 * 24 * 60 * 60),
            rotation_interval: Duration::from_secs(24 * 60 * 60),
            max_concurrent_sessions: 5,
            require_secure_transport: true,
            validate_ip_address: false,
            max_ip_changes: 50,
            cookie: CookiePolicy::gold_standard(),
        }
    }

    pub fn is_expired(&self, created_at_epoch: i64, last_seen_epoch: i64, now_epoch: i64) -> bool {
        timestamp_too_far_in_future(created_at_epoch, now_epoch)
            || timestamp_too_far_in_future(last_seen_epoch, now_epoch)
            || elapsed(now_epoch, created_at_epoch) >= duration_secs_i64(self.max_lifetime)
            || elapsed(now_epoch, last_seen_epoch) >= duration_secs_i64(self.idle_timeout)
    }

    pub fn should_rotate(&self, last_rotated_epoch: i64, now_epoch: i64) -> bool {
        timestamp_too_far_in_future(last_rotated_epoch, now_epoch)
            || elapsed(now_epoch, last_rotated_epoch) >= duration_secs_i64(self.rotation_interval)
    }

    pub fn transport_allowed(&self, is_secure_transport: bool) -> bool {
        !self.require_secure_transport || is_secure_transport
    }

    pub fn ip_change_allowed(&self, observed_changes: u32) -> bool {
        !self.validate_ip_address || observed_changes <= self.max_ip_changes
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::gold_standard()
    }
}

fn elapsed(now_epoch: i64, then_epoch: i64) -> i64 {
    now_epoch.saturating_sub(then_epoch)
}

fn duration_secs_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

fn timestamp_too_far_in_future(timestamp: i64, now_epoch: i64) -> bool {
    timestamp > now_epoch.saturating_add(duration_secs_i64(SESSION_CLOCK_SKEW))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gold_policy_uses_expected_timeouts() {
        let policy = SessionPolicy::gold_standard();

        assert_eq!(policy.max_lifetime, Duration::from_secs(8 * 60 * 60));
        assert_eq!(policy.idle_timeout, Duration::from_secs(30 * 60));
        assert_eq!(policy.rotation_interval, Duration::from_secs(60 * 60));
        assert_eq!(policy.max_concurrent_sessions, 3);
        assert!(policy.cookie.secure);
        assert!(policy.cookie.http_only);
    }

    #[test]
    fn expiry_checks_lifetime_and_idle_timeout() {
        let policy = SessionPolicy::gold_standard();

        assert!(!policy.is_expired(1_000, 1_100, 1_200));
        assert!(policy.is_expired(1_000, 1_100, 1_000 + (8 * 60 * 60)));
        assert!(policy.is_expired(1_000, 1_100, 1_100 + (30 * 60)));
        assert!(policy.is_expired(2_000, 1_100, 1_200));
    }

    #[test]
    fn high_security_enforces_stricter_cookie_and_ip_policy() {
        let policy = SessionPolicy::high_security();

        assert_eq!(policy.cookie.same_site, SameSitePolicy::Strict);
        assert!(policy.validate_ip_address);
        assert!(policy.ip_change_allowed(1));
        assert!(!policy.ip_change_allowed(2));
    }
}
