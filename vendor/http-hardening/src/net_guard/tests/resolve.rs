//! Resolve-once-and-pin with injected DNS answers.

use std::io;
use std::net::{IpAddr, SocketAddr};

use url::Url;

use super::{assert_blocked, http_guard};
use crate::net_guard::{AddressClass as C, NetGuard, NetGuardError, MAX_RESOLVED_ADDRESSES};

fn sock(raw: &str) -> SocketAddr {
    SocketAddr::new(raw.parse::<IpAddr>().unwrap(), 0)
}

fn answer(ips: &[&str]) -> impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = ips.iter().map(|ip| sock(ip)).collect();
    move |_host, _port| Ok(addrs.clone())
}

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

#[test]
fn public_answer_is_pinned_with_the_url_port() {
    let guard = NetGuard::strict();
    let target = guard
        .resolve_with(
            &url("https://hooks.example/x"),
            &answer(&["93.184.215.14", "2606:4700::1"]),
        )
        .unwrap();
    assert_eq!(target.host(), "hooks.example");
    assert_eq!(target.port(), 443);
    assert_eq!(
        target.addrs(),
        &[
            "93.184.215.14:443".parse().unwrap(),
            "[2606:4700::1]:443".parse().unwrap()
        ]
    );
    assert_eq!(target.url().as_str(), "https://hooks.example/x");
}

#[test]
fn any_non_public_address_in_the_answer_refuses_the_whole_answer() {
    let guard = NetGuard::strict();
    let target = url("https://rebind.example/");
    let cases: &[(&[&str], C)] = &[
        (&["127.0.0.1"], C::Loopback),
        (&["93.184.215.14", "10.0.0.1"], C::Private),
        (&["2606:4700::1", "::1"], C::Loopback),
        (&["::ffff:169.254.169.254"], C::LinkLocal),
        (&["64:ff9b::a00:1"], C::Private),
        (&["2002:a00:1::1"], C::SixToFour),
        (&["fd00::1"], C::UniqueLocal),
        (&["0.0.0.0"], C::Unspecified),
    ];
    for (ips, class) in cases {
        assert_blocked(
            guard.resolve_with(&target, &answer(ips)),
            *class,
            &format!("{ips:?}"),
        );
    }
}

#[test]
fn mapped_answers_are_canonicalised_and_duplicates_dropped() {
    let guard = http_guard();
    let target = guard
        .resolve_with(
            &url("http://dual.example:8080/"),
            &answer(&["::ffff:8.8.8.8", "8.8.8.8"]),
        )
        .unwrap();
    assert_eq!(target.addrs(), &["8.8.8.8:8080".parse().unwrap()]);
}

#[test]
fn empty_oversized_and_failed_answers_are_errors() {
    let guard = NetGuard::strict();
    let target = url("https://x.example/");
    assert!(matches!(
        guard.resolve_with(&target, &answer(&[])),
        Err(NetGuardError::NoAddresses(h)) if h == "x.example"
    ));
    let failing = |_: &str, _: u16| Err(io::Error::new(io::ErrorKind::NotFound, "nxdomain"));
    let error = guard.resolve_with(&target, &failing).unwrap_err();
    assert!(matches!(error, NetGuardError::Dns { .. }));
    assert_eq!(
        error.to_string(),
        "DNS lookup for 'x.example' failed: nxdomain"
    );
    let many = |_: &str, _: u16| {
        let ips =
            (0..=MAX_RESOLVED_ADDRESSES).map(|i| sock(&format!("8.8.{}.{}", i / 250, i % 250 + 1)));
        Ok(ips.collect())
    };
    assert!(matches!(
        guard.resolve_with(&target, &many),
        Err(NetGuardError::TooManyAddresses {
            limit: MAX_RESOLVED_ADDRESSES,
            ..
        })
    ));
    let small = NetGuard::builder().max_addresses(1).build();
    assert!(matches!(
        small.resolve_with(&target, &answer(&["8.8.8.8", "1.1.1.1"])),
        Err(NetGuardError::TooManyAddresses { limit: 1, .. })
    ));
}

#[test]
fn literal_hosts_are_not_sent_to_dns() {
    let guard = NetGuard::strict();
    let never = |_: &str, _: u16| -> io::Result<Vec<SocketAddr>> {
        Err(io::Error::other("DNS must not be called"))
    };
    let target = guard
        .resolve_with(&url("https://8.8.8.8/"), &never)
        .unwrap();
    assert_eq!(target.addrs(), &["8.8.8.8:443".parse().unwrap()]);
    let target = guard
        .resolve_with(&url("https://[2606:4700::1]:8443/"), &never)
        .unwrap();
    assert_eq!(target.host(), "2606:4700::1");
    assert_eq!(target.addrs(), &["[2606:4700::1]:8443".parse().unwrap()]);
    assert_blocked(
        guard.resolve_with(&url("https://0x7f.1/"), &never),
        C::Loopback,
        "hex",
    );
}

#[test]
fn static_checks_run_before_dns() {
    let guard = NetGuard::strict();
    let never = |_: &str, _: u16| -> io::Result<Vec<SocketAddr>> {
        Err(io::Error::other("DNS must not be called"))
    };
    assert!(matches!(
        guard.resolve_with(&url("http://example.com/"), &never),
        Err(NetGuardError::SchemeNotAllowed(_))
    ));
    assert_blocked(
        guard.resolve_with(&url("https://localhost/"), &never),
        C::Loopback,
        "localhost",
    );
}

#[test]
fn allowlisted_lan_target_resolves() {
    let guard = NetGuard::builder()
        .allow_scheme(crate::net_guard::Scheme::Http)
        .allow_cidr("192.168.1.0/24".parse().unwrap())
        .unwrap()
        .build();
    let target = guard
        .resolve_with(&url("http://ntfy.lan/topic"), &answer(&["192.168.1.20"]))
        .unwrap();
    assert_eq!(target.addrs(), &["192.168.1.20:80".parse().unwrap()]);
    let (url_back, addrs) = target.into_parts();
    assert_eq!(url_back.host_str(), Some("ntfy.lan"));
    assert_eq!(addrs.len(), 1);
    assert_blocked(
        guard.resolve_with(
            &url("http://ntfy.lan/"),
            &answer(&["192.168.1.20", "10.0.0.1"]),
        ),
        C::Private,
        "mixed LAN answer",
    );
}

#[test]
fn system_dns_resolves_localhost_and_the_guard_refuses_it() {
    let guard = NetGuard::builder()
        .allow_cidr_list("127.0.0.0/8 ::1")
        .unwrap()
        .build();
    let target = guard.resolve(&url("https://localhost:9443/")).unwrap();
    assert!(target
        .addrs()
        .iter()
        .all(|a| a.ip().is_loopback() && a.port() == 9443));
    assert_blocked(
        NetGuard::strict().resolve(&url("https://localhost/")),
        C::Loopback,
        "sys",
    );
}
