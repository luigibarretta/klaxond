pub const INVALID_CREDENTIALS: &str = "invalid_credentials";
pub const UNAUTHORIZED: &str = "unauthorized";
pub const FORBIDDEN: &str = "forbidden";
pub const AUTH_METHOD_DISABLED: &str = "auth_method_disabled";
pub const ACCOUNT_LOCKED: &str = "account_locked";
pub const RATE_LIMITED: &str = "rate_limited";
pub const MFA_REQUIRED: &str = "mfa_required";
pub const MFA_INVALID: &str = "mfa_invalid";
pub const PASSWORD_POLICY_VIOLATION: &str = "password_policy_violation";
pub const PASSWORD_TOO_SHORT: &str = "password_too_short";
pub const PASSWORD_TOO_LONG: &str = "password_too_long";
pub const PASSWORD_TOO_COMMON: &str = "password_too_common";
pub const PASSWORD_CONTAINS_USERNAME: &str = "password_contains_username";
pub const OIDC_UNAVAILABLE: &str = "oidc_unavailable";
pub const OIDC_CALLBACK_INVALID: &str = "oidc_callback_invalid";
pub const PASSKEY_UNAVAILABLE: &str = "passkey_unavailable";
pub const PASSKEY_REGISTRATION_FAILED: &str = "passkey_registration_failed";
pub const PASSKEY_LOGIN_FAILED: &str = "passkey_login_failed";
pub const MAGIC_LINK_UNAVAILABLE: &str = "magic_link_unavailable";
pub const MAGIC_LINK_SENT: &str = "magic_link_sent";
pub const MAGIC_LINK_INVALID: &str = "magic_link_invalid";
pub const LDAP_UNAVAILABLE: &str = "ldap_unavailable";
pub const LDAP_INVALID_CREDENTIALS: &str = "ldap_invalid_credentials";
pub const RECOVERY_CODE_INVALID: &str = "recovery_code_invalid";
pub const SESSION_EXPIRED: &str = "session_expired";
pub const SESSION_INVALID: &str = "session_invalid";
pub const TOKEN_EXPIRED: &str = "token_expired";
pub const TOKEN_INVALID: &str = "token_invalid";
pub const VALIDATION_ERROR: &str = "validation_error";
pub const INTERNAL_ERROR: &str = "internal_error";

pub const GOLD_AUTH_ERROR_CODES: [&str; 30] = [
    INVALID_CREDENTIALS,
    UNAUTHORIZED,
    FORBIDDEN,
    AUTH_METHOD_DISABLED,
    ACCOUNT_LOCKED,
    RATE_LIMITED,
    MFA_REQUIRED,
    MFA_INVALID,
    PASSWORD_POLICY_VIOLATION,
    PASSWORD_TOO_SHORT,
    PASSWORD_TOO_LONG,
    PASSWORD_TOO_COMMON,
    PASSWORD_CONTAINS_USERNAME,
    OIDC_UNAVAILABLE,
    OIDC_CALLBACK_INVALID,
    PASSKEY_UNAVAILABLE,
    PASSKEY_REGISTRATION_FAILED,
    PASSKEY_LOGIN_FAILED,
    MAGIC_LINK_UNAVAILABLE,
    MAGIC_LINK_SENT,
    MAGIC_LINK_INVALID,
    LDAP_UNAVAILABLE,
    LDAP_INVALID_CREDENTIALS,
    RECOVERY_CODE_INVALID,
    SESSION_EXPIRED,
    SESSION_INVALID,
    TOKEN_EXPIRED,
    TOKEN_INVALID,
    VALIDATION_ERROR,
    INTERNAL_ERROR,
];

pub fn is_gold_auth_error_code(code: &str) -> bool {
    GOLD_AUTH_ERROR_CODES.contains(&code)
}
