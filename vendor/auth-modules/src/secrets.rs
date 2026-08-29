//! Small, dependency-free primitives for handling secret values consistently.
//!
//! This module deliberately does not own persistence, serialization, token
//! semantics, or application error responses. It only provides operations
//! whose security properties should not be reimplemented by every consumer.

use std::fmt;

/// Compares two byte strings without returning early on a mismatched byte or
/// length.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();

    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }

    difference == 0
}

/// Owns a value whose `Debug` output must never reveal the inner value.
#[derive(Clone, Eq, PartialEq)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_comparison_handles_equal_and_different_lengths() {
        assert!(constant_time_eq(b"same-secret", b"same-secret"));
        assert!(!constant_time_eq(b"same-secret", b"same-secreu"));
        assert!(!constant_time_eq(b"same-secret", b"same-secret-longer"));
        assert!(!constant_time_eq(b"same-secret-longer", b"same-secret"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn redacted_debug_never_formats_the_inner_value() {
        let secret = Redacted::new("top-secret".to_owned());

        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(secret.expose_secret(), "top-secret");
        assert_eq!(secret.into_inner(), "top-secret");
    }
}
