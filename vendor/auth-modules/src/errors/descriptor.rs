use super::codes::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorDescriptor {
    pub code: &'static str,
    pub http_status: u16,
    pub retryable: bool,
    pub public_message: &'static str,
}

pub fn describe(code: &str) -> ErrorDescriptor {
    match code {
        INVALID_CREDENTIALS => ErrorDescriptor {
            code: INVALID_CREDENTIALS,
            http_status: 401,
            retryable: false,
            public_message: "Invalid credentials.",
        },
        UNAUTHORIZED => ErrorDescriptor {
            code: UNAUTHORIZED,
            http_status: 401,
            retryable: false,
            public_message: "Authentication is required.",
        },
        FORBIDDEN => ErrorDescriptor {
            code: FORBIDDEN,
            http_status: 403,
            retryable: false,
            public_message: "Access denied.",
        },
        AUTH_METHOD_DISABLED => ErrorDescriptor {
            code: AUTH_METHOD_DISABLED,
            http_status: 403,
            retryable: false,
            public_message: "This authentication method is disabled.",
        },
        ACCOUNT_LOCKED => ErrorDescriptor {
            code: ACCOUNT_LOCKED,
            http_status: 423,
            retryable: true,
            public_message: "Account temporarily locked.",
        },
        RATE_LIMITED => ErrorDescriptor {
            code: RATE_LIMITED,
            http_status: 429,
            retryable: true,
            public_message: "Too many attempts. Try again later.",
        },
        MFA_REQUIRED => ErrorDescriptor {
            code: MFA_REQUIRED,
            http_status: 401,
            retryable: false,
            public_message: "Multi-factor authentication is required.",
        },
        MFA_INVALID => ErrorDescriptor {
            code: MFA_INVALID,
            http_status: 401,
            retryable: false,
            public_message: "The verification code is invalid.",
        },
        PASSWORD_POLICY_VIOLATION => ErrorDescriptor {
            code: PASSWORD_POLICY_VIOLATION,
            http_status: 400,
            retryable: false,
            public_message: "Password does not satisfy the policy.",
        },
        PASSWORD_TOO_SHORT => ErrorDescriptor {
            code: PASSWORD_TOO_SHORT,
            http_status: 400,
            retryable: false,
            public_message: "Password is too short.",
        },
        PASSWORD_TOO_LONG => ErrorDescriptor {
            code: PASSWORD_TOO_LONG,
            http_status: 400,
            retryable: false,
            public_message: "Password is too long.",
        },
        PASSWORD_TOO_COMMON => ErrorDescriptor {
            code: PASSWORD_TOO_COMMON,
            http_status: 400,
            retryable: false,
            public_message: "Password is too common.",
        },
        PASSWORD_CONTAINS_USERNAME => ErrorDescriptor {
            code: PASSWORD_CONTAINS_USERNAME,
            http_status: 400,
            retryable: false,
            public_message: "Password must not contain the username.",
        },
        OIDC_UNAVAILABLE => ErrorDescriptor {
            code: OIDC_UNAVAILABLE,
            http_status: 503,
            retryable: true,
            public_message: "OIDC sign-in is temporarily unavailable.",
        },
        OIDC_CALLBACK_INVALID => ErrorDescriptor {
            code: OIDC_CALLBACK_INVALID,
            http_status: 400,
            retryable: false,
            public_message: "OIDC callback could not be verified.",
        },
        PASSKEY_UNAVAILABLE => ErrorDescriptor {
            code: PASSKEY_UNAVAILABLE,
            http_status: 503,
            retryable: true,
            public_message: "Passkey sign-in is temporarily unavailable.",
        },
        PASSKEY_REGISTRATION_FAILED => ErrorDescriptor {
            code: PASSKEY_REGISTRATION_FAILED,
            http_status: 400,
            retryable: false,
            public_message: "Passkey registration failed.",
        },
        PASSKEY_LOGIN_FAILED => ErrorDescriptor {
            code: PASSKEY_LOGIN_FAILED,
            http_status: 401,
            retryable: false,
            public_message: "Passkey sign-in failed.",
        },
        MAGIC_LINK_UNAVAILABLE => ErrorDescriptor {
            code: MAGIC_LINK_UNAVAILABLE,
            http_status: 503,
            retryable: true,
            public_message: "Magic link sign-in is temporarily unavailable.",
        },
        MAGIC_LINK_SENT => ErrorDescriptor {
            code: MAGIC_LINK_SENT,
            http_status: 202,
            retryable: false,
            public_message: "If the account exists, a sign-in link has been sent.",
        },
        MAGIC_LINK_INVALID => ErrorDescriptor {
            code: MAGIC_LINK_INVALID,
            http_status: 400,
            retryable: false,
            public_message: "Magic link is invalid or expired.",
        },
        LDAP_UNAVAILABLE => ErrorDescriptor {
            code: LDAP_UNAVAILABLE,
            http_status: 503,
            retryable: true,
            public_message: "Directory sign-in is temporarily unavailable.",
        },
        LDAP_INVALID_CREDENTIALS => ErrorDescriptor {
            code: LDAP_INVALID_CREDENTIALS,
            http_status: 401,
            retryable: false,
            public_message: "Invalid credentials.",
        },
        RECOVERY_CODE_INVALID => ErrorDescriptor {
            code: RECOVERY_CODE_INVALID,
            http_status: 401,
            retryable: false,
            public_message: "Recovery code is invalid or already used.",
        },
        SESSION_EXPIRED => ErrorDescriptor {
            code: SESSION_EXPIRED,
            http_status: 401,
            retryable: false,
            public_message: "Session expired.",
        },
        SESSION_INVALID => ErrorDescriptor {
            code: SESSION_INVALID,
            http_status: 401,
            retryable: false,
            public_message: "Session is invalid.",
        },
        TOKEN_EXPIRED => ErrorDescriptor {
            code: TOKEN_EXPIRED,
            http_status: 401,
            retryable: false,
            public_message: "Token expired.",
        },
        TOKEN_INVALID => ErrorDescriptor {
            code: TOKEN_INVALID,
            http_status: 401,
            retryable: false,
            public_message: "Token is invalid.",
        },
        VALIDATION_ERROR => ErrorDescriptor {
            code: VALIDATION_ERROR,
            http_status: 400,
            retryable: false,
            public_message: "Request validation failed.",
        },
        _ => ErrorDescriptor {
            code: INTERNAL_ERROR,
            http_status: 500,
            retryable: true,
            public_message: "Internal error.",
        },
    }
}
