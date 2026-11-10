//! Unit tests for the assembled security headers.

use super::{
    ContentSecurityPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy, FrameOptions,
    HeaderPolicyError, Hsts, ReferrerPolicy, SecurityHeaders, MAX_EXTRA_HEADERS,
};

const STRICT_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; \
worker-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'";

fn value<'a>(headers: &'a SecurityHeaders, name: &str) -> Option<&'a str> {
    headers.get(name)
}

#[test]
fn strict_defaults_cover_every_header() {
    let headers = SecurityHeaders::strict().unwrap();
    let expected = [
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
        ("content-security-policy", STRICT_CSP),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ];
    for (name, want) in expected {
        assert_eq!(value(&headers, name), Some(want), "{name}");
    }
    let permissions = value(&headers, "permissions-policy").unwrap();
    assert!(permissions.contains("camera=()") && permissions.contains("geolocation=()"));
    assert_eq!(headers.len(), 8);
    assert!(headers
        .headers_str()
        .all(|(name, _)| !headers.keeps_existing(name)));
}

#[test]
fn frame_options_drive_both_headers() {
    let same = SecurityHeaders::builder()
        .frame_options(FrameOptions::SameOrigin)
        .build()
        .unwrap();
    assert_eq!(value(&same, "x-frame-options"), Some("SAMEORIGIN"));
    assert!(value(&same, "content-security-policy")
        .unwrap()
        .ends_with("frame-ancestors 'self'"));

    let list = FrameOptions::Ancestors(vec!["'self'".into(), "https://ha.example".into()]);
    let ancestors = SecurityHeaders::builder()
        .frame_options(list)
        .build()
        .unwrap();
    assert_eq!(value(&ancestors, "x-frame-options"), None);
    assert!(value(&ancestors, "content-security-policy")
        .unwrap()
        .ends_with("frame-ancestors 'self' https://ha.example"));

    let empty = SecurityHeaders::builder()
        .frame_options(FrameOptions::Ancestors(Vec::new()))
        .build()
        .unwrap();
    assert!(value(&empty, "content-security-policy")
        .unwrap()
        .ends_with("frame-ancestors 'none'"));

    let bad = FrameOptions::Ancestors(vec!["https://a.example; script-src *".into()]);
    assert!(matches!(
        SecurityHeaders::builder().frame_options(bad).build(),
        Err(HeaderPolicyError::InvalidCspSource(_))
    ));
}

#[test]
fn disabling_csp_still_sends_frame_ancestors() {
    let headers = SecurityHeaders::builder().csp(None).build().unwrap();
    assert_eq!(
        value(&headers, "content-security-policy"),
        Some("frame-ancestors 'none'")
    );
}

#[test]
fn optional_headers_can_be_dropped_or_tuned() {
    let headers = SecurityHeaders::builder()
        .hsts(Some(
            Hsts::new(31_536_000)
                .include_subdomains(false)
                .preload(true),
        ))
        .referrer_policy(Some(ReferrerPolicy::StrictOriginWhenCrossOrigin))
        .cross_origin_opener_policy(Some(CrossOriginOpenerPolicy::SameOriginAllowPopups))
        .cross_origin_resource_policy(Some(CrossOriginResourcePolicy::CrossOrigin))
        .permissions_policy(None)
        .nosniff(false)
        .build()
        .unwrap();
    assert_eq!(
        value(&headers, "strict-transport-security"),
        Some("max-age=31536000; preload")
    );
    assert_eq!(
        value(&headers, "referrer-policy"),
        Some("strict-origin-when-cross-origin")
    );
    assert_eq!(
        value(&headers, "cross-origin-opener-policy"),
        Some("same-origin-allow-popups")
    );
    assert_eq!(
        value(&headers, "cross-origin-resource-policy"),
        Some("cross-origin")
    );
    assert_eq!(value(&headers, "permissions-policy"), None);
    assert_eq!(value(&headers, "x-content-type-options"), None);

    let minimal = SecurityHeaders::builder()
        .hsts(None)
        .referrer_policy(None)
        .cross_origin_opener_policy(None)
        .cross_origin_resource_policy(None)
        .build()
        .unwrap();
    assert_eq!(value(&minimal, "strict-transport-security"), None);
    assert_eq!(value(&minimal, "referrer-policy"), None);
}

#[test]
fn report_only_and_extra_headers() {
    let trial = ContentSecurityPolicy::strict()
        .set("script-src", &["'self'", "'strict-dynamic'"])
        .unwrap();
    let headers = SecurityHeaders::builder()
        .csp_report_only(Some(trial))
        .header("Cache-Control", "no-store")
        .header("X-Robots-Tag", "noindex, nofollow")
        .build()
        .unwrap();
    assert!(value(&headers, "content-security-policy-report-only")
        .unwrap()
        .contains("script-src 'self' 'strict-dynamic'"));
    assert_eq!(value(&headers, "cache-control"), Some("no-store"));
    assert_eq!(value(&headers, "x-robots-tag"), Some("noindex, nofollow"));

    for (name, val) in [
        ("bad header", "x"),
        ("x-ok", "line\nbreak"),
        ("x-ok", " leading"),
        ("x-ok", "caf\u{e9}"),
        ("", "x"),
    ] {
        let result = SecurityHeaders::builder().header(name, val).build();
        assert!(
            matches!(result, Err(HeaderPolicyError::InvalidHeader(_))),
            "{name}"
        );
    }
    let mut many = SecurityHeaders::builder();
    for i in 0..=MAX_EXTRA_HEADERS {
        many = many.header(&format!("x-extra-{i}"), "1");
    }
    assert_eq!(
        many.build().unwrap_err(),
        HeaderPolicyError::TooManyExtraHeaders
    );
}
