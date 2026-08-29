use argon2::Argon2;
use password_hash::{
    rand_core::OsRng, Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier,
    SaltString,
};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct HashError(PasswordHashError);

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to hash password: {}", self.0)
    }
}

impl Error for HashError {}

pub fn hash_password(password: &str) -> Result<String, HashError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(HashError)
}

pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    if is_argon2_hash(stored_hash) {
        return verify_argon2(password, stored_hash);
    }
    false
}

pub fn is_argon2_hash(stored_hash: &str) -> bool {
    stored_hash.starts_with("$argon2id$")
}

fn verify_argon2(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}
