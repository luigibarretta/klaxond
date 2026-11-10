//! URL-level checks: obscure literal encodings, schemes, credentials, ports.

use super::{assert_blocked, http_guard};
use crate::net_guard::{AddressClass as C, NetGuard, NetGuardError, Scheme};

/// Literal-host bypass encodings. The WHATWG parser canonicalises every
/// IPv4 form, so all of these must be refused with the right class.
const BYPASSES: &[(&str, C)] = &[
    ("http://127.0.0.1/", C::Loopback),
    ("http://127.0.0.1./", C::Loopback),
    ("http://2130706433/", C::Loopback),
    ("http://0x7f000001/", C::Loopback),
    ("http://0X7F000001/", C::Loopback),
    ("http://017700000001/", C::Loopback),
    ("http://0177.0.0.1/", C::Loopback),
    ("http://0177.0000.0000.0001/", C::Loopback),
    ("http://0x7f.0x0.0x0.0x1/", C::Loopback),
    ("http://0x7f.1/", C::Loopback),
    ("http://127.1/", C::Loopback),
    ("http://127.0.1/", C::Loopback),
    ("http://127.000.000.001/", C::Loopback),
    ("http://%31%32%37.0.0.1/", C::Loopback),
    ("http://\u{ff11}\u{ff12}\u{ff17}.0.0.1/", C::Loopback),
    ("http://0/", C::Unspecified),
    ("http://0.0.0.0:8080/", C::Unspecified),
    ("http://10.1/", C::Private),
    ("http://167772161/", C::Private),
    ("http://0xa9fea9fe/", C::LinkLocal),
    ("http://2852039166/", C::LinkLocal),
    ("http://169.254.169.254/latest/meta-data/", C::LinkLocal),
    ("http://0251.0376.0251.0376/", C::LinkLocal),
    ("http://100.64.0.1/", C::SharedCgnat),
    ("http://[::1]/", C::Loopback),
    ("http://[0:0:0:0:0:0:0:1]/", C::Loopback),
    ("http://[::]/", C::Unspecified),
    ("http://[::ffff:127.0.0.1]/", C::Loopback),
    ("http://[::ffff:7f00:1]/", C::Loopback),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]/", C::Loopback),
    ("http://[::ffff:a9fe:a9fe]/", C::LinkLocal),
    ("http://[::127.0.0.1]/", C::Ipv4Compatible),
    ("http://[64:ff9b::127.0.0.1]/", C::Loopback),
    ("http://[64:ff9b::10.0.0.1]/", C::Private),
    ("http://[64:ff9b:1::a00:1]/", C::Nat64LocalUse),
    ("http://[2002:7f00:1::]/", C::SixToFour),
    ("http://[2002:a9fe:a9fe::]/", C::SixToFour),
    ("http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/", C::Teredo),
    ("http://[fd00::1]/", C::UniqueLocal),
    ("http://[fe80::1]/", C::LinkLocal),
    ("http://[fec0::1]/", C::SiteLocal),
    ("http://[ff02::1]/", C::Multicast),
    ("http://224.0.0.1/", C::Multicast),
    ("http://255.255.255.255/", C::Broadcast),
    ("http://localhost/", C::Loopback),
    ("http://LOCALHOST./", C::Loopback),
    ("http://api.localhost:9000/", C::Loopback),
];

#[test]
fn literal_host_bypass_encodings_are_refused() {
    let guard = http_guard();
    for (raw, class) in BYPASSES {
        assert_blocked(guard.parse_url(raw), *class, raw);
    }
}

#[test]
fn public_targets_pass() {
    let guard = http_guard();
    for raw in [
        "https://example.com/hook",
        "https://example.com./",
        "https://ntfy.sh/topic?x=1#frag",
        "https://93.184.215.14/",
        "http://1.1.1.1:8080/",
        "https://[2606:4700:4700::1111]/",
        "https://[::ffff:8.8.8.8]/",
        "https://[64:ff9b::8.8.8.8]/",
        "https://xn--bcher-kva.example/",
        "https://bücher.example/",
    ] {
        assert!(guard.parse_url(raw).is_ok(), "{raw} must pass");
    }
}

#[test]
fn malformed_hosts_are_parse_errors() {
    let guard = http_guard();
    for raw in [
        "http://1.2.3.4.5/",
        "http://256.0.0.1/",
        "http://0x100000000/",
        "http://[fe80::1%25eth0]/",
        "http://[::1/",
        "not a url",
    ] {
        assert!(
            matches!(guard.parse_url(raw), Err(NetGuardError::InvalidUrl(_))),
            "{raw} must be a parse error"
        );
    }
}

#[test]
fn schemes_follow_the_allowlist() {
    let strict = NetGuard::strict();
    assert!(matches!(
        strict.parse_url("http://example.com/"),
        Err(NetGuardError::SchemeNotAllowed(s)) if s == "http"
    ));
    for raw in [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/",
        "dict://example.com:11211/",
        "ws://example.com/",
        "data:text/plain,hi",
        "javascript:alert(1)",
    ] {
        assert!(
            matches!(
                http_guard().parse_url(raw),
                Err(NetGuardError::SchemeNotAllowed(_))
            ),
            "{raw}"
        );
    }
    let ws = NetGuard::builder().allow_scheme(Scheme::Wss).build();
    assert!(ws.parse_url("wss://example.com/socket").is_ok());
    assert!(ws.allows_scheme(Scheme::Https) && !ws.allows_scheme(Scheme::Ws));
}

#[test]
fn credentials_in_url_are_refused() {
    let guard = http_guard();
    for raw in [
        "https://user:pass@example.com/",
        "https://user@example.com/",
        "https://:pass@example.com/",
        "http://127.0.0.1:80@example.com/",
    ] {
        assert!(
            matches!(guard.parse_url(raw), Err(NetGuardError::CredentialsInUrl)),
            "{raw}"
        );
    }
    // A fragment that looks like userinfo does not change the host.
    assert!(guard.parse_url("https://example.com#@127.0.0.1/").is_ok());
}

#[test]
fn ports_follow_the_allowlist_and_zero_is_refused() {
    let guard = NetGuard::builder().allowed_ports(&[443, 8443]).build();
    assert!(guard.parse_url("https://example.com/").is_ok());
    assert!(guard.parse_url("https://example.com:8443/").is_ok());
    assert!(matches!(
        guard.parse_url("https://example.com:22/"),
        Err(NetGuardError::PortNotAllowed(22))
    ));
    assert!(matches!(
        NetGuard::strict().parse_url("https://example.com:0/"),
        Err(NetGuardError::PortNotAllowed(0))
    ));
}

#[test]
fn allowlist_admits_intended_internal_targets_only() {
    let guard = NetGuard::builder()
        .allow_scheme(Scheme::Http)
        .allow_cidr_list("192.168.1.0/24, fd00:1::/64")
        .unwrap()
        .build();
    for raw in [
        "http://192.168.1.10/",
        "http://[::ffff:192.168.1.10]/",
        "http://3232235786/",
        "http://[fd00:1::5]/",
    ] {
        assert!(guard.parse_url(raw).is_ok(), "{raw} must be allowlisted");
    }
    assert_blocked(
        guard.parse_url("http://192.168.2.1/"),
        C::Private,
        "other LAN",
    );
    assert_blocked(
        guard.parse_url("http://[fd00:2::5]/"),
        C::UniqueLocal,
        "other ULA",
    );
    assert_blocked(
        guard.parse_url("http://localhost/"),
        C::Loopback,
        "loopback",
    );
    // NAT64 encodings of an allowlisted host go through a translator: refused.
    assert_blocked(
        guard.parse_url("http://[64:ff9b::192.168.1.10]/"),
        C::Private,
        "nat64",
    );
}

#[test]
fn allowlist_never_admits_unspecified_multicast_or_broadcast() {
    let guard = NetGuard::builder()
        .allow_scheme(Scheme::Http)
        .allow_wide_cidr("0.0.0.0/0")
        .unwrap()
        .allow_wide_cidr("::/0")
        .unwrap()
        .build();
    assert!(guard.parse_url("http://127.0.0.1/").is_ok());
    assert!(guard.parse_url("http://localhost/").is_ok());
    assert_blocked(
        guard.parse_url("http://0.0.0.0/"),
        C::Unspecified,
        "0.0.0.0",
    );
    assert_blocked(guard.parse_url("http://[::]/"), C::Unspecified, "::");
    assert_blocked(guard.parse_url("http://224.0.0.251/"), C::Multicast, "mdns");
    assert_blocked(guard.parse_url("http://[ff02::fb]/"), C::Multicast, "ff02");
    assert_blocked(
        guard.parse_url("http://255.255.255.255/"),
        C::Broadcast,
        "bcast",
    );
}

#[test]
fn wide_allowlist_entries_need_explicit_opt_in() {
    use crate::net_guard::CidrError;
    let refused = NetGuard::builder().allow_cidr_list("0.0.0.0/0");
    assert!(matches!(refused, Err(CidrError::TooWide(_))));
    let refused = NetGuard::builder().allow_cidr_list("fc00::/7");
    assert!(matches!(refused, Err(CidrError::TooWide(_))));
    assert!(NetGuard::builder().allow_wide_cidr("fc00::/7").is_ok());
}

#[test]
fn allowlist_overflow_is_an_error_not_a_silent_drop() {
    use crate::net_guard::{Cidr, CidrError, MAX_CIDR_ENTRIES};
    let mut builder = NetGuard::builder();
    for i in 0..MAX_CIDR_ENTRIES {
        let ip = std::net::Ipv4Addr::from(0x0a00_0000_u32 + u32::try_from(i).unwrap());
        builder = builder.allow_cidr(Cidr::host(ip.into())).unwrap();
    }
    // Duplicates are idempotent even when full.
    let builder = builder.allow_cidr("10.0.0.0/32".parse().unwrap()).unwrap();
    let overflow = builder.allow_cidr("10.1.0.0/32".parse().unwrap());
    assert!(matches!(overflow, Err(CidrError::TooManyEntries)));
}
