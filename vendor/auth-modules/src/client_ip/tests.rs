use std::net::IpAddr;

use super::*;

fn ip(value: &str) -> IpAddr {
    value.parse().expect("test IP literal")
}

fn traefik() -> TrustedProxies {
    TrustedProxies::new(["10.0.0.0/8", "fd00::/8"], ForwardingHeader::XForwardedFor)
        .expect("valid trusted proxies")
}

fn xff<'a>(values: &[&'a str]) -> ForwardingHeaders<'a> {
    let mut headers = ForwardingHeaders::new();
    for value in values {
        headers.push_x_forwarded_for(value);
    }
    headers
}

#[test]
fn trusted_proxies_reject_invalid_cidrs() {
    for invalid in [
        "",
        "10.0.0.0/33",
        "fd00::/129",
        "10.0.0.0/",
        "not-an-ip/8",
        "10.0.0.1/8",
        "::ffff:10.0.0.0/104",
        "10.0.0.0/8/1",
    ] {
        let result = TrustedProxies::new([invalid], ForwardingHeader::XForwardedFor);
        assert!(result.is_err(), "{invalid:?} must be rejected");
    }
}

#[test]
fn trusted_proxies_accept_bare_addresses_and_report_membership() {
    let trusted = TrustedProxies::new(
        ["192.0.2.10", "2001:db8::1", "172.16.0.0/12", "0.0.0.0/0"],
        ForwardingHeader::XForwardedFor,
    );
    let trusted = trusted.expect("valid list");
    assert!(trusted.contains(ip("192.0.2.10")));
    assert!(trusted.contains(ip("172.31.255.255")));
    assert!(trusted.contains(ip("::ffff:172.16.0.1")));
    assert!(trusted.contains(ip("2001:db8::1")));
    assert!(!trusted.contains(ip("2001:db8::2")));
    assert!(TrustedProxies::none().is_empty());
    assert!(!TrustedProxies::none().contains(ip("127.0.0.1")));
}

#[test]
fn untrusted_peer_is_returned_even_with_forwarding_headers() {
    let headers = xff(&["198.51.100.7"]);
    let resolved = traefik().resolve(ip("203.0.113.9"), &headers);
    assert_eq!(resolved, ip("203.0.113.9"));
    assert_eq!(
        traefik().resolve_with_source(ip("203.0.113.9"), &headers),
        (ip("203.0.113.9"), ClientIpSource::Peer)
    );
}

#[test]
fn spoofed_left_entries_are_ignored() {
    // The attacker sends "1.1.1.1"; Traefik appends the real address.
    let headers = xff(&["1.1.1.1, 203.0.113.50"]);
    let resolved = traefik().resolve_with_source(ip("10.0.0.2"), &headers);
    assert_eq!(resolved, (ip("203.0.113.50"), ClientIpSource::Header));
}

#[test]
fn multiple_trusted_hops_are_skipped_from_the_right() {
    let headers = xff(&["1.1.1.1, 203.0.113.50, 10.1.2.3", "10.9.9.9"]);
    assert_eq!(
        traefik().resolve(ip("10.0.0.2"), &headers),
        ip("203.0.113.50")
    );
}

#[test]
fn garbage_left_of_the_client_does_not_force_peer_fallback() {
    let headers = xff(&["garbage, , 203.0.113.50"]);
    assert_eq!(
        traefik().resolve(ip("10.0.0.2"), &headers),
        ip("203.0.113.50")
    );
}

#[test]
fn malformed_trusted_portion_falls_back_to_peer() {
    for value in [
        "203.0.113.50, garbage",
        "203.0.113.50,",
        "203.0.113.50, 10.0.0.3 10.0.0.4",
        "unknown",
    ] {
        let headers = xff(&[value]);
        assert_eq!(
            traefik().resolve_with_source(ip("10.0.0.2"), &headers),
            (ip("10.0.0.2"), ClientIpSource::Peer),
            "{value:?}"
        );
    }
}

#[test]
fn absent_or_blank_headers_return_the_peer() {
    for headers in [ForwardingHeaders::new(), xff(&[""]), xff(&["   "])] {
        assert_eq!(
            traefik().resolve_with_source(ip("10.0.0.2"), &headers),
            (ip("10.0.0.2"), ClientIpSource::Peer)
        );
    }
}

#[test]
fn non_utf8_header_values_fall_back_to_peer() {
    let mut headers = xff(&["203.0.113.50"]);
    headers.push_x_forwarded_for_bytes(b"\xff\xfe");
    assert_eq!(traefik().resolve(ip("10.0.0.2"), &headers), ip("10.0.0.2"));
}

#[test]
fn fully_trusted_chain_returns_the_leftmost_hop() {
    let headers = xff(&["10.5.5.5, 10.1.1.1"]);
    assert_eq!(traefik().resolve(ip("10.0.0.2"), &headers), ip("10.5.5.5"));
}

#[test]
fn ipv6_and_ipv4_mapped_addresses_are_normalized() {
    let headers = xff(&["2001:db8::abcd, ::ffff:203.0.113.50"]);
    assert_eq!(
        traefik().resolve(ip("::ffff:10.0.0.2"), &headers),
        ip("203.0.113.50")
    );
    let headers = xff(&["2001:db8::abcd, fd00::1"]);
    assert_eq!(
        traefik().resolve(ip("fd00::2"), &headers),
        ip("2001:db8::abcd")
    );
    assert_eq!(
        TrustedProxies::none().resolve(ip("::ffff:192.0.2.1"), &ForwardingHeaders::new()),
        ip("192.0.2.1")
    );
}

#[test]
fn ports_and_brackets_are_accepted_in_x_forwarded_for() {
    let headers = xff(&["198.51.100.1:4711, [2001:db8::5]:443"]);
    assert_eq!(
        traefik().resolve(ip("10.0.0.2"), &headers),
        ip("2001:db8::5")
    );
}

#[test]
fn only_the_configured_header_is_consulted() {
    let mut headers = ForwardingHeaders::new();
    headers.push_forwarded("for=198.51.100.66");
    headers.push_x_real_ip("198.51.100.67");
    // XFF is configured but absent: the injected Forwarded/X-Real-IP values
    // must not be trusted.
    assert_eq!(traefik().resolve(ip("10.0.0.2"), &headers), ip("10.0.0.2"));
}

#[test]
fn forwarded_header_is_parsed_from_the_right() {
    let trusted = TrustedProxies::new(["10.0.0.0/8"], ForwardingHeader::Forwarded).unwrap();
    let mut headers = ForwardingHeaders::new();
    headers.push_forwarded("for=1.1.1.1;proto=https, For=\"[2001:db8::7]:4711\"");
    headers.push_forwarded("for=10.0.0.9;by=10.0.0.2;host=example.test");
    assert_eq!(trusted.resolve(ip("10.0.0.2"), &headers), ip("2001:db8::7"));

    let mut obfuscated = ForwardingHeaders::new();
    obfuscated.push_forwarded("for=203.0.113.4, for=_hidden");
    assert_eq!(trusted.resolve(ip("10.0.0.2"), &obfuscated), ip("10.0.0.2"));

    let mut missing_for = ForwardingHeaders::new();
    missing_for.push_forwarded("proto=https");
    assert_eq!(
        trusted.resolve(ip("10.0.0.2"), &missing_for),
        ip("10.0.0.2")
    );
}

#[test]
fn x_real_ip_accepts_exactly_one_address() {
    let trusted = TrustedProxies::new(["10.0.0.0/8"], ForwardingHeader::XRealIp).unwrap();
    let mut single = ForwardingHeaders::new();
    single.push_x_real_ip(" 203.0.113.8 ");
    assert_eq!(trusted.resolve(ip("10.0.0.2"), &single), ip("203.0.113.8"));

    let mut list = ForwardingHeaders::new();
    list.push_x_real_ip("203.0.113.8, 203.0.113.9");
    assert_eq!(trusted.resolve(ip("10.0.0.2"), &list), ip("10.0.0.2"));

    let mut repeated = ForwardingHeaders::new();
    repeated.push_x_real_ip("203.0.113.8");
    repeated.push_x_real_ip("203.0.113.9");
    assert_eq!(trusted.resolve(ip("10.0.0.2"), &repeated), ip("10.0.0.2"));
}

#[test]
fn oversized_chains_fall_back_to_peer() {
    let long = vec!["10.0.0.7"; MAX_FORWARDED_HOPS + 1].join(",");
    let headers = xff(&[long.as_str()]);
    assert_eq!(traefik().resolve(ip("10.0.0.2"), &headers), ip("10.0.0.2"));
}

#[test]
fn errors_name_the_rejected_entry_without_panicking() {
    let error = TrustedProxies::new(["10.0.0.1/8"], ForwardingHeader::XForwardedFor)
        .expect_err("host bits set");
    assert!(error.to_string().contains("10.0.0.1/8"));
}

#[test]
fn trusted_hop_budget_boundaries_are_exact() {
    let chain = |trusted: usize, client: Option<&str>| {
        let mut hops: Vec<String> = client.into_iter().map(str::to_string).collect();
        hops.extend((0..trusted).map(|index| format!("10.0.1.{index}")));
        hops.join(",")
    };
    let resolve = |value: &str| traefik().resolve(ip("10.0.0.2"), &xff(&[value]));

    let within = chain(MAX_FORWARDED_HOPS - 1, Some("203.0.113.50"));
    assert_eq!(resolve(&within), ip("203.0.113.50"));
    let exact = chain(MAX_FORWARDED_HOPS, Some("203.0.113.50"));
    assert_eq!(resolve(&exact), ip("10.0.0.2"));
    let all_trusted = chain(MAX_FORWARDED_HOPS, None);
    assert_eq!(resolve(&all_trusted), ip("10.0.1.0"));
}
