//! Unit tests for the outbound network guard.

mod cidr;
mod ip;
mod redirect;
#[cfg(feature = "reqwest")]
mod reqwest_adapter;
#[cfg(feature = "reqwest")]
mod reqwest_request;
mod resolve;
#[cfg(feature = "ureq")]
mod ureq_adapter;
#[cfg(feature = "ureq")]
mod ureq_redirects;
mod urls;

use super::{AddressClass, NetGuard, NetGuardError};

/// Asserts that `result` is a `BlockedAddress` refusal with `class`.
pub(super) fn assert_blocked<T: std::fmt::Debug>(
    result: Result<T, NetGuardError>,
    class: AddressClass,
    case: &str,
) {
    match result {
        Err(NetGuardError::BlockedAddress { class: got, .. }) => {
            assert_eq!(got, class, "wrong class for {case}");
        }
        other => panic!("{case}: expected BlockedAddress({class:?}), got {other:?}"),
    }
}

/// Guard admitting plain HTTP, used by most URL tables.
pub(super) fn http_guard() -> NetGuard {
    NetGuard::builder()
        .allow_scheme(super::Scheme::Http)
        .build()
}
