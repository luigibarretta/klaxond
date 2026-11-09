//! Authorization Code callback input with mandatory `state` verification
//! (audit finding AM-03).

use std::fmt;

use super::security::validate_state;
use super::OidcError;
use crate::secrets::constant_time_eq;

/// Everything needed to finish an Authorization Code callback.
///
/// `state` is the value returned by the provider in the redirect query;
/// `expected_state`, `nonce` and `pkce_verifier` come from the pending flow
/// the application stored when it built the authorization URL. The exchange
/// functions compare the two states in constant time and fail before any
/// network request when they differ. Binding the pending flow to the browser
/// and consuming it exactly once remain application responsibilities.
#[derive(Clone, Copy)]
pub struct CallbackParams<'a> {
    pub code: &'a str,
    pub state: &'a str,
    pub expected_state: &'a str,
    pub nonce: &'a str,
    pub pkce_verifier: &'a str,
}

impl fmt::Debug for CallbackParams<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackParams")
            .field("code", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .field("expected_state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .finish()
    }
}

/// Rejects an empty code, an empty expected state, and any returned state
/// that differs from the expected one.
pub(crate) fn verify_callback_state(params: &CallbackParams<'_>) -> Result<(), OidcError> {
    validate_state(params.expected_state)?;
    if !constant_time_eq(params.state.as_bytes(), params.expected_state.as_bytes()) {
        return Err(OidcError::new(
            "OIDC callback state does not match the pending authorization flow",
        ));
    }
    if params.code.trim().is_empty() {
        return Err(OidcError::new("OIDC authorization code must not be empty"));
    }
    Ok(())
}
