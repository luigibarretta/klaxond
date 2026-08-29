use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, OnceLock};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub struct TestEnvironmentGuard {
    original_vars: HashMap<String, Option<OsString>>,
    _lock: MutexGuard<'static, ()>,
}

impl TestEnvironmentGuard {
    pub fn new() -> Self {
        let lock = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self {
            original_vars: HashMap::new(),
            _lock: lock,
        }
    }

    pub fn with_var(mut self, key: &str, value: &str) -> Self {
        self.set_var(key, value);
        self
    }

    pub fn with_auth_gold_env(self) -> Self {
        self.with_var("AUTH_PASSWORD_MIN_LENGTH", "12")
            .with_var("AUTH_PASSWORD_HASH", "argon2id")
            .with_var("AUTH_RATE_LIMIT_ACCOUNT_MAX", "10")
            .with_var("AUTH_SESSION_IDLE_TIMEOUT_SECONDS", "1800")
    }

    pub fn set_var(&mut self, key: &str, value: &str) {
        if !self.original_vars.contains_key(key) {
            self.original_vars.insert(key.to_string(), env::var_os(key));
        }
        env::set_var(key, value);
    }

    pub fn remove_var(&mut self, key: &str) {
        if !self.original_vars.contains_key(key) {
            self.original_vars.insert(key.to_string(), env::var_os(key));
        }
        env::remove_var(key);
    }
}

impl Default for TestEnvironmentGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TestEnvironmentGuard {
    fn drop(&mut self) {
        for (key, original_value) in &self.original_vars {
            match original_value {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedClock {
    now_epoch: i64,
}

impl FixedClock {
    pub fn new(now_epoch: i64) -> Self {
        Self { now_epoch }
    }

    pub fn now_epoch(&self) -> i64 {
        self.now_epoch
    }

    pub fn advance_seconds(&mut self, seconds: i64) {
        self.now_epoch = self.now_epoch.saturating_add(seconds);
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapturedEvents<T> {
    events: Vec<T>,
}

impl<T> CapturedEvents<T> {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn push(&mut self, event: T) {
        self.events.push(event);
    }

    pub fn as_slice(&self) -> &[T] {
        &self.events
    }

    pub fn into_vec(self) -> Vec<T> {
        self.events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_guard_restores_original_value() {
        env::set_var("AUTH_MODULES_TEST_ENV_GUARD", "original");
        {
            let _guard =
                TestEnvironmentGuard::new().with_var("AUTH_MODULES_TEST_ENV_GUARD", "changed");
            assert_eq!(
                env::var("AUTH_MODULES_TEST_ENV_GUARD").as_deref(),
                Ok("changed")
            );
        }
        assert_eq!(
            env::var("AUTH_MODULES_TEST_ENV_GUARD").as_deref(),
            Ok("original")
        );
        env::remove_var("AUTH_MODULES_TEST_ENV_GUARD");
    }

    #[test]
    fn fixed_clock_advances_by_seconds() {
        let mut clock = FixedClock::new(1_000);

        clock.advance_seconds(30);

        assert_eq!(clock.now_epoch(), 1_030);
    }

    #[test]
    fn captured_events_preserves_order() {
        let mut events = CapturedEvents::new();

        events.push("first");
        events.push("second");

        assert_eq!(events.as_slice(), ["first", "second"]);
    }
}
