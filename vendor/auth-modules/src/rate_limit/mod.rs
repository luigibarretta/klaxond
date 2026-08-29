mod memory;
mod types;

pub use memory::InMemoryRateLimiter;
pub use types::{
    PersistentRateLimitPolicy, PersistentRateLimitRecord, RateLimitBucket, RateLimitDecision,
    RateLimitOutcome,
};

use std::time::Duration;

pub const GOLD_AUTH_ACCOUNT_FAILURE_MAX: usize = 10;
pub const GOLD_AUTH_ACCOUNT_FAILURE_WINDOW: Duration = Duration::from_secs(5 * 60);
pub const GOLD_AUTH_ACCOUNT_LOCKOUT_WINDOW: Duration = Duration::from_secs(10 * 60);
pub const GOLD_AUTH_IP_BURST_MAX: usize = 50;
pub const GOLD_AUTH_IP_BURST_WINDOW: Duration = Duration::from_secs(60);
pub const GOLD_AUTH_SHORT_BURST_MAX: usize = 10;
pub const GOLD_AUTH_SHORT_BURST_WINDOW: Duration = Duration::from_secs(60);

pub fn gold_auth_account_failure_policy() -> PersistentRateLimitPolicy {
    PersistentRateLimitPolicy::new(
        GOLD_AUTH_ACCOUNT_FAILURE_MAX,
        GOLD_AUTH_ACCOUNT_FAILURE_WINDOW,
        GOLD_AUTH_ACCOUNT_LOCKOUT_WINDOW,
    )
}

#[cfg(test)]
mod tests;
