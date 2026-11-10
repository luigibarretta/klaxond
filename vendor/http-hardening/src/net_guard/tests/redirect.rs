//! Redirect policy.

use url::Url;

use super::assert_blocked;
use crate::net_guard::{
    AddressClass as C, NetGuard, NetGuardError, RedirectPolicy, Scheme, MAX_REDIRECT_HOPS,
};

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

fn revalidating(max_hops: u8) -> NetGuard {
    NetGuard::builder()
        .allow_scheme(Scheme::Http)
        .redirects(RedirectPolicy::revalidate(max_hops))
        .build()
}

#[test]
fn redirects_are_disabled_by_default() {
    let guard = NetGuard::strict();
    assert_eq!(guard.redirect_policy(), RedirectPolicy::Disabled);
    assert!(matches!(
        guard.check_redirect(&url("https://a.example/"), &url("https://b.example/"), 0),
        Err(NetGuardError::RedirectsDisabled)
    ));
}

#[test]
fn hop_count_is_bounded() {
    let guard = revalidating(2);
    let from = url("https://a.example/");
    let to = url("https://b.example/");
    assert!(guard.check_redirect(&from, &to, 0).is_ok());
    assert!(guard.check_redirect(&from, &to, 1).is_ok());
    assert!(matches!(
        guard.check_redirect(&from, &to, 2),
        Err(NetGuardError::TooManyRedirects(2))
    ));
}

#[test]
fn every_hop_is_revalidated() {
    let guard = revalidating(5);
    let from = url("https://a.example/");
    assert_blocked(
        guard.check_redirect(&from, &url("https://169.254.169.254/"), 0),
        C::LinkLocal,
        "metadata",
    );
    assert_blocked(
        guard.check_redirect(&from, &url("https://0x7f.1/"), 0),
        C::Loopback,
        "hex loopback",
    );
    assert_blocked(
        guard.check_redirect(&from, &url("https://[::ffff:10.0.0.1]/"), 0),
        C::Private,
        "mapped",
    );
    assert!(matches!(
        guard.check_redirect(&from, &url("file:///etc/passwd"), 0),
        Err(NetGuardError::SchemeNotAllowed(_))
    ));
    assert!(matches!(
        guard.check_redirect(&from, &url("https://u:p@b.example/"), 0),
        Err(NetGuardError::CredentialsInUrl)
    ));
}

#[test]
fn secure_to_plaintext_downgrade_is_refused() {
    let guard = revalidating(3);
    assert!(matches!(
        guard.check_redirect(&url("https://a.example/"), &url("http://a.example/"), 0),
        Err(NetGuardError::SchemeDowngrade)
    ));
    assert!(guard
        .check_redirect(&url("http://a.example/"), &url("https://a.example/"), 0)
        .is_ok());
}

#[test]
fn policy_constructor_clamps_and_maps_zero_to_disabled() {
    assert_eq!(RedirectPolicy::revalidate(0), RedirectPolicy::Disabled);
    assert_eq!(
        RedirectPolicy::revalidate(200).max_hops(),
        MAX_REDIRECT_HOPS
    );
    let guard = NetGuard::builder()
        .redirects(RedirectPolicy::Revalidate { max_hops: 99 })
        .build();
    assert_eq!(guard.redirect_policy().max_hops(), MAX_REDIRECT_HOPS);
    let guard = NetGuard::builder()
        .redirects(RedirectPolicy::Revalidate { max_hops: 0 })
        .build();
    assert_eq!(guard.redirect_policy(), RedirectPolicy::Disabled);
}
