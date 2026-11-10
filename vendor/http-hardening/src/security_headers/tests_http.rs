//! Typed `http` view and conflict handling (feature `http`).

use http::header::{HeaderMap, HeaderValue, CONTENT_SECURITY_POLICY, REFERRER_POLICY};

use super::{ExistingHeaders, SecurityHeaders};

fn upstream_headers() -> HeaderMap {
    let mut target = HeaderMap::new();
    target.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src *"),
    );
    target.insert(REFERRER_POLICY, HeaderValue::from_static("unsafe-url"));
    target.insert("x-frame-options", HeaderValue::from_static("ALLOWALL"));
    target
}

#[test]
fn typed_headers_mirror_the_string_view() {
    let policy = SecurityHeaders::strict().unwrap();
    assert_eq!(policy.headers().len(), policy.len());
    for ((name, value), (typed_name, typed_value)) in policy.headers_str().zip(policy.headers()) {
        assert_eq!(name, typed_name.as_str());
        assert_eq!(value, typed_value.to_str().unwrap());
    }
}

#[test]
fn default_overwrites_upstream_values() {
    let mut target = upstream_headers();
    SecurityHeaders::strict().unwrap().apply(&mut target);
    assert!(target[CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .starts_with("default-src 'none'"));
    assert_eq!(target[REFERRER_POLICY], "no-referrer");
    assert_eq!(target["x-frame-options"], "DENY");
    assert_eq!(target.get_all(CONTENT_SECURITY_POLICY).iter().count(), 1);
}

#[test]
fn keep_if_present_is_per_header() {
    let policy = SecurityHeaders::builder()
        .keep_if_present(&["Referrer-Policy"])
        .build()
        .unwrap();
    assert!(policy.keeps_existing("referrer-policy"));
    assert!(!policy.keeps_existing("content-security-policy"));
    let mut target = upstream_headers();
    policy.apply(&mut target);
    assert_eq!(target[REFERRER_POLICY], "unsafe-url");
    assert_eq!(target["x-frame-options"], "DENY");
    // Absent headers are still added.
    let mut empty = HeaderMap::new();
    policy.apply(&mut empty);
    assert_eq!(empty[REFERRER_POLICY], "no-referrer");
    assert!(SecurityHeaders::builder()
        .keep_if_present(&["bad name"])
        .build()
        .is_err());
}

#[test]
fn keep_mode_keeps_everything_present() {
    let policy = SecurityHeaders::builder()
        .existing_headers(ExistingHeaders::Keep)
        .build()
        .unwrap();
    let mut target = upstream_headers();
    policy.apply(&mut target);
    assert_eq!(target[CONTENT_SECURITY_POLICY], "default-src *");
    assert_eq!(target["x-content-type-options"], "nosniff");
}

#[test]
fn keep_if_present_must_name_a_policy_header() {
    let typo = SecurityHeaders::builder()
        .keep_if_present(&["content-security-polcy"])
        .build();
    assert!(matches!(
        typo,
        Err(super::HeaderPolicyError::KeptHeaderNotInPolicy(name)) if name == "content-security-polcy"
    ));
    let disabled = SecurityHeaders::builder()
        .hsts(None)
        .keep_if_present(&["strict-transport-security"])
        .build();
    assert!(disabled.is_err());
    let extra = SecurityHeaders::builder()
        .header("Cache-Control", "no-store")
        .keep_if_present(&["cache-control"])
        .build()
        .unwrap();
    assert!(extra.keeps_existing("cache-control"));
}
