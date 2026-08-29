use std::error::Error;
use std::fmt;

pub const DEFAULT_MIN_PASSWORD_LENGTH: usize = 12;
pub const GOLD_STANDARD_MAX_PASSWORD_LENGTH: usize = 1024;

const COMMON_PASSWORDS: &[&str] = &[
    "12345678",
    "123456789",
    "1234567890",
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "welcome123",
    "welcome12345",
    "changeme",
    "changeme123",
    "adminadmin",
    "letmein123",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: Option<usize>,
    pub reject_common_passwords: bool,
    pub reject_username_substring: bool,
}

impl PasswordPolicy {
    pub fn minimum_length(min_length: usize) -> Self {
        Self {
            min_length,
            max_length: None,
            reject_common_passwords: false,
            reject_username_substring: false,
        }
    }

    pub fn gold_standard() -> Self {
        Self {
            min_length: DEFAULT_MIN_PASSWORD_LENGTH,
            max_length: Some(GOLD_STANDARD_MAX_PASSWORD_LENGTH),
            reject_common_passwords: true,
            reject_username_substring: true,
        }
    }

    pub fn validate(&self, password: &str, username: Option<&str>) -> Result<(), PolicyError> {
        let length = password.chars().count();
        if length < self.min_length {
            return Err(PolicyError::TooShort {
                min: self.min_length,
                actual: length,
            });
        }
        if let Some(max) = self.max_length {
            if length > max {
                return Err(PolicyError::TooLong {
                    max,
                    actual: length,
                });
            }
        }
        if self.reject_common_passwords && is_common_password(password) {
            return Err(PolicyError::CommonPassword);
        }
        if self.reject_username_substring
            && username
                .map(|value| contains_username(password, value))
                .unwrap_or(false)
        {
            return Err(PolicyError::ContainsUsername);
        }
        Ok(())
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self::minimum_length(DEFAULT_MIN_PASSWORD_LENGTH)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyError {
    TooShort { min: usize, actual: usize },
    TooLong { max: usize, actual: usize },
    CommonPassword,
    ContainsUsername,
}

impl PolicyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooShort { .. } => "password_too_short",
            Self::TooLong { .. } => "password_too_long",
            Self::CommonPassword => "password_too_common",
            Self::ContainsUsername => "password_contains_username",
        }
    }

    pub fn message(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { min, .. } => write!(f, "password must be at least {min} characters"),
            Self::TooLong { max, .. } => write!(f, "password must be at most {max} characters"),
            Self::CommonPassword => write!(f, "password is too common"),
            Self::ContainsUsername => write!(f, "password must not contain the username"),
        }
    }
}

impl Error for PolicyError {}

pub fn validate_gold_standard(password: &str, username: Option<&str>) -> Result<(), PolicyError> {
    PasswordPolicy::gold_standard().validate(password, username)
}

pub fn is_common_password(password: &str) -> bool {
    let normalized = normalize_common_password_candidate(password);
    COMMON_PASSWORDS
        .iter()
        .any(|candidate| normalized == *candidate)
}

pub fn contains_username(password: &str, username: &str) -> bool {
    let username = username.trim().to_ascii_lowercase();
    username.len() >= 3 && password.to_ascii_lowercase().contains(&username)
}

fn normalize_common_password_candidate(password: &str) -> String {
    password
        .trim()
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}
