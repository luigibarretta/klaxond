//! CIDR parsing and matching.

use std::net::IpAddr;

use crate::net_guard::{parse_cidr_list, Cidr, CidrError, MAX_CIDR_ENTRIES};

#[test]
fn parses_valid_networks() {
    for (raw, display) in [
        ("192.168.1.0/24", "192.168.1.0/24"),
        (" 10.0.0.0/8 ", "10.0.0.0/8"),
        ("10.0.0.7", "10.0.0.7/32"),
        ("fd00:1::/64", "fd00:1::/64"),
        ("::1", "::1/128"),
        ("2001:db8::/32", "2001:db8::/32"),
    ] {
        let cidr: Cidr = raw.parse().unwrap_or_else(|e| panic!("{raw}: {e}"));
        assert_eq!(cidr.to_string(), display);
    }
}

type ErrorCheck = fn(&CidrError) -> bool;

#[test]
fn rejects_invalid_networks() {
    let cases: &[(&str, ErrorCheck)] = &[
        ("", |e| matches!(e, CidrError::Empty)),
        ("   ", |e| matches!(e, CidrError::Empty)),
        ("abc", |e| matches!(e, CidrError::InvalidAddress(_))),
        ("0177.0.0.1/32", |e| {
            matches!(e, CidrError::InvalidAddress(_))
        }),
        ("0x7f.0.0.1", |e| matches!(e, CidrError::InvalidAddress(_))),
        ("127.1", |e| matches!(e, CidrError::InvalidAddress(_))),
        ("fe80::1%eth0", |e| {
            matches!(e, CidrError::InvalidAddress(_))
        }),
        ("/8", |e| matches!(e, CidrError::InvalidAddress(_))),
        ("10.0.0.0/", |e| matches!(e, CidrError::InvalidPrefix(_))),
        ("10.0.0.0/33", |e| matches!(e, CidrError::InvalidPrefix(_))),
        ("10.0.0.0/+8", |e| matches!(e, CidrError::InvalidPrefix(_))),
        ("10.0.0.0/0008", |e| {
            matches!(e, CidrError::InvalidPrefix(_))
        }),
        ("fe80::/129", |e| matches!(e, CidrError::InvalidPrefix(_))),
        ("10.0.0.1/8", |e| matches!(e, CidrError::HostBitsSet(_))),
        ("192.168.1.5/24", |e| matches!(e, CidrError::HostBitsSet(_))),
        ("fd00::1/8", |e| matches!(e, CidrError::HostBitsSet(_))),
    ];
    for (raw, check) in cases {
        match raw.parse::<Cidr>() {
            Err(error) => assert!(check(&error), "{raw}: unexpected {error:?}"),
            Ok(cidr) => panic!("{raw} parsed as {cidr}"),
        }
    }
}

#[test]
fn contains_matches_prefix_and_canonicalises_mapped() {
    let lan: Cidr = "192.168.1.0/24".parse().unwrap();
    let ip = |raw: &str| raw.parse::<IpAddr>().unwrap();
    assert!(lan.contains(ip("192.168.1.0")));
    assert!(lan.contains(ip("192.168.1.255")));
    assert!(lan.contains(ip("::ffff:192.168.1.9")));
    assert!(!lan.contains(ip("192.168.2.1")));
    assert!(!lan.contains(ip("::192.168.1.9")));
    let ula: Cidr = "fd00:1::/64".parse().unwrap();
    assert!(ula.contains(ip("fd00:1::ffff")));
    assert!(!ula.contains(ip("fd00:1:0:1::1")));
    assert!(!ula.contains(ip("192.168.1.1")));
    let all = Cidr::parse_wide("0.0.0.0/0").unwrap();
    assert!(all.contains(ip("8.8.8.8")) && !all.contains(ip("::1")));
    assert_eq!(all.prefix(), 0);
    assert_eq!(lan.network(), ip("192.168.1.0"));
}

#[test]
fn list_parsing_is_bounded_and_strict() {
    let list = parse_cidr_list("10.0.0.0/8,192.168.1.0/24  fd00:1::/64\n").unwrap();
    assert_eq!(list.len(), 3);
    assert!(parse_cidr_list("").unwrap().is_empty());
    assert!(parse_cidr_list(" , ,").unwrap().is_empty());
    assert!(matches!(
        parse_cidr_list("10.0.0.0/8, 10.0.0.1/8"),
        Err(CidrError::HostBitsSet(_))
    ));
    let many = vec!["10.0.0.1"; MAX_CIDR_ENTRIES + 1].join(",");
    assert_eq!(parse_cidr_list(&many), Err(CidrError::TooManyEntries));
    let max = vec!["10.0.0.1"; MAX_CIDR_ENTRIES].join(",");
    assert_eq!(parse_cidr_list(&max).unwrap().len(), MAX_CIDR_ENTRIES);
}

#[test]
fn errors_render_their_input() {
    let error = "10.0.0.1/8".parse::<Cidr>().unwrap_err();
    assert_eq!(error.to_string(), "CIDR has host bits set: 10.0.0.1/8");
    assert!(Cidr::new("10.0.0.0".parse().unwrap(), 40).is_err());
    assert!(Cidr::new("::".parse().unwrap(), 128).is_ok());
}

#[test]
fn mapped_networks_are_refused_or_canonicalised() {
    for raw in [
        "::ffff:10.0.0.0/104",
        "::ffff:0:0/96",
        "::ffff:192.168.1.0/120",
    ] {
        assert!(
            matches!(raw.parse::<Cidr>(), Err(CidrError::Ipv4MappedNetwork(_))),
            "{raw}"
        );
    }
    let host: Cidr = "::ffff:192.168.1.9".parse().unwrap();
    assert_eq!(host.to_string(), "192.168.1.9/32");
    let explicit: Cidr = "::ffff:192.168.1.9/128".parse().unwrap();
    assert_eq!(explicit, host);
    let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    assert_eq!(
        Cidr::host(ip).network(),
        "10.0.0.1".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn wide_prefixes_need_parse_wide() {
    for raw in [
        "0.0.0.0/0",
        "10.0.0.0/7",
        "::/0",
        "fc00::/7",
        "2000::/3",
        "2001:db8::/31",
    ] {
        assert!(
            matches!(raw.parse::<Cidr>(), Err(CidrError::TooWide(_))),
            "{raw}"
        );
        assert!(Cidr::parse_wide(raw).is_ok(), "{raw}");
    }
    for raw in ["10.0.0.0/8", "2001:db8::/32"] {
        assert!(raw.parse::<Cidr>().is_ok(), "{raw}");
    }
    assert!(matches!(
        Cidr::parse_wide("::ffff:0.0.0.0/96"),
        Err(CidrError::Ipv4MappedNetwork(_))
    ));
}
