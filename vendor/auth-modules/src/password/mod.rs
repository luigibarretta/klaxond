mod hashing;
mod policy;

pub use hashing::{hash_password, is_argon2_hash, verify_password, HashError};
pub use policy::{
    contains_username, is_common_password, validate_gold_standard, PasswordPolicy, PolicyError,
    DEFAULT_MIN_PASSWORD_LENGTH, GOLD_STANDARD_MAX_PASSWORD_LENGTH,
};

#[cfg(test)]
mod tests;
