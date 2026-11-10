//! Unit tests for the CSP and Permissions-Policy builders.

use super::{
    ContentSecurityPolicy, HeaderPolicyError, PermissionsPolicy, ReferrerPolicy, MAX_CSP_DIRECTIVES,
};

#[test]
fn csp_builder_set_add_remove() {
    let csp = ContentSecurityPolicy::strict()
        .add("connect-src", "wss://push.example")
        .unwrap()
        .add("default-src", "'self'")
        .unwrap()
        .add("img-src", "data:")
        .unwrap()
        .set("Style-Src", &["'self'", "'sha256-abc='"])
        .unwrap()
        .remove("worker-src")
        .add("report-to", "csp")
        .unwrap()
        .upgrade_insecure_requests(true);
    let rendered = csp.render();
    assert!(rendered.starts_with("default-src 'self'; "), "{rendered}");
    assert!(rendered.contains("connect-src 'self' wss://push.example"));
    assert!(rendered.contains("img-src 'self' data:;"));
    assert!(rendered.contains("style-src 'self' 'sha256-abc='"));
    assert!(!rendered.contains("worker-src"));
    assert!(rendered.ends_with("report-to csp; upgrade-insecure-requests"));
    assert_eq!(csp.sources("CONNECT-SRC").unwrap().len(), 2);
    let sandbox = ContentSecurityPolicy::empty().set("sandbox", &[]).unwrap();
    assert_eq!(sandbox.render(), "sandbox");
}

#[test]
fn csp_builder_rejects_injection_and_bounds() {
    for source in [
        "",
        " ",
        "a b",
        "'self'; script-src *",
        "x,y",
        "\u{e9}",
        "a\tb",
    ] {
        assert!(
            matches!(
                ContentSecurityPolicy::strict().add("img-src", source),
                Err(HeaderPolicyError::InvalidCspSource(_))
            ),
            "{source:?}"
        );
    }
    for directive in [
        "",
        "img src",
        "img_src",
        "-x",
        "img-src;",
        "x".repeat(65).as_str(),
    ] {
        assert!(
            matches!(
                ContentSecurityPolicy::empty().add(directive, "'self'"),
                Err(HeaderPolicyError::InvalidCspDirective(_))
            ),
            "{directive:?}"
        );
    }
    let mut csp = ContentSecurityPolicy::empty();
    for i in 0..MAX_CSP_DIRECTIVES {
        let name =
            format!("x-{}", char::from(b'a' + u8::try_from(i % 26).unwrap())).repeat(1 + i / 26);
        csp = csp.add(&name, "'self'").unwrap();
    }
    assert_eq!(
        csp.add("one-more", "'self'").unwrap_err(),
        HeaderPolicyError::TooManyCspDirectives
    );
    let sources: Vec<String> = (0..=super::MAX_CSP_SOURCES)
        .map(|i| format!("https://h{i}.example"))
        .collect();
    let refs: Vec<&str> = sources.iter().map(String::as_str).collect();
    assert!(matches!(
        ContentSecurityPolicy::empty().set("img-src", &refs),
        Err(HeaderPolicyError::TooManyCspSources(_))
    ));
}

#[test]
fn permissions_policy_builder() {
    let policy = PermissionsPolicy::empty()
        .deny("camera")
        .unwrap()
        .allow_self("fullscreen")
        .unwrap()
        .allow_origins("geolocation", &["https://maps.example"])
        .unwrap()
        .deny("Camera")
        .unwrap();
    assert_eq!(
        policy.render(),
        "camera=(), fullscreen=(self), geolocation=(self \"https://maps.example\")"
    );
    assert!(!policy.clone().remove("camera").render().contains("camera"));
    assert!(PermissionsPolicy::empty().is_empty());
    assert!(matches!(
        PermissionsPolicy::empty().deny("bad feature"),
        Err(HeaderPolicyError::InvalidPermissionsFeature(_))
    ));
    for origin in [
        "https://a\"b",
        "https://a b",
        "x;y",
        "https://a\\b",
        "https://a(b",
        "https://a)b",
    ] {
        assert!(matches!(
            PermissionsPolicy::empty().allow_origins("camera", &[origin]),
            Err(HeaderPolicyError::InvalidOrigin(_))
        ));
    }
    let many = vec!["https://a.example"; super::MAX_PERMISSIONS_ORIGINS + 1];
    assert!(PermissionsPolicy::empty()
        .allow_origins("camera", &many)
        .is_err());
}

#[test]
fn errors_render() {
    assert_eq!(
        HeaderPolicyError::InvalidCspSource("a;b".into()).to_string(),
        "invalid CSP source 'a;b'"
    );
    assert_eq!(ReferrerPolicy::default().as_str(), "no-referrer");
}
