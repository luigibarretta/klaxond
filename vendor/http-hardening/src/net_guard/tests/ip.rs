//! Table-driven classification of IPv4 and IPv6 addresses.

use std::net::IpAddr;

use crate::net_guard::{canonical_ip, classify, nat64_embedded_ipv4, AddressClass as C};

const V4_CASES: &[(&str, C)] = &[
    ("0.0.0.0", C::Unspecified),
    ("0.1.2.3", C::Reserved),
    ("10.0.0.1", C::Private),
    ("10.255.255.255", C::Private),
    ("100.63.255.255", C::Public),
    ("100.64.0.1", C::SharedCgnat),
    ("100.127.255.255", C::SharedCgnat),
    ("100.128.0.1", C::Public),
    ("100.100.100.200", C::SharedCgnat),
    ("127.0.0.1", C::Loopback),
    ("127.255.255.254", C::Loopback),
    ("169.254.169.254", C::LinkLocal),
    ("172.15.255.255", C::Public),
    ("172.16.0.1", C::Private),
    ("172.31.255.255", C::Private),
    ("172.32.0.1", C::Public),
    ("192.0.0.1", C::ProtocolAssignment),
    ("192.0.0.192", C::ProtocolAssignment),
    ("192.0.2.1", C::Documentation),
    ("192.88.99.1", C::Reserved),
    ("192.168.1.1", C::Private),
    ("198.17.255.255", C::Public),
    ("198.18.0.1", C::Benchmarking),
    ("198.19.255.255", C::Benchmarking),
    ("198.20.0.1", C::Public),
    ("198.51.100.1", C::Documentation),
    ("203.0.113.1", C::Documentation),
    ("224.0.0.1", C::Multicast),
    ("239.255.255.250", C::Multicast),
    ("240.0.0.1", C::Reserved),
    ("255.255.255.254", C::Reserved),
    ("255.255.255.255", C::Broadcast),
    ("1.1.1.1", C::Public),
    ("8.8.8.8", C::Public),
    ("93.184.215.14", C::Public),
];

const V6_CASES: &[(&str, C)] = &[
    ("::", C::Unspecified),
    ("::1", C::Loopback),
    // IPv4-mapped: canonicalised to IPv4 first.
    ("::ffff:127.0.0.1", C::Loopback),
    ("::ffff:7f00:1", C::Loopback),
    ("0:0:0:0:0:ffff:10.0.0.1", C::Private),
    ("::ffff:169.254.169.254", C::LinkLocal),
    ("::ffff:0.0.0.0", C::Unspecified),
    ("::ffff:8.8.8.8", C::Public),
    // IPv4-compatible (deprecated): whole range refused.
    ("::127.0.0.1", C::Ipv4Compatible),
    ("::7f00:1", C::Ipv4Compatible),
    ("::8.8.8.8", C::Ipv4Compatible),
    ("::2", C::Ipv4Compatible),
    // IPv4-translated (SIIT) is outside 2000::/3.
    ("::ffff:0:7f00:1", C::Reserved),
    // Well-known NAT64: judged by the embedded IPv4 address.
    ("64:ff9b::127.0.0.1", C::Loopback),
    ("64:ff9b::7f00:1", C::Loopback),
    ("64:ff9b::10.1.2.3", C::Private),
    ("64:ff9b::a9fe:a9fe", C::LinkLocal),
    ("64:ff9b::c0a8:101", C::Private),
    ("64:ff9b::0.0.0.0", C::Unspecified),
    ("64:ff9b::8.8.8.8", C::Public),
    // Local-use NAT64 and other NAT64-adjacent space.
    ("64:ff9b:1::1", C::Nat64LocalUse),
    ("64:ff9b:1::a00:1", C::Nat64LocalUse),
    ("64:ff9b:0:1::7f00:1", C::Reserved),
    ("100::1", C::Discard),
    // Teredo, benchmarking, ORCHID and other 2001::/23 assignments.
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2", C::Teredo),
    ("2001::1", C::Teredo),
    ("2001:2::1", C::Benchmarking),
    ("2001:10::1", C::ProtocolAssignment),
    ("2001:1ff::1", C::ProtocolAssignment),
    ("2001:200::1", C::Public),
    ("2001:db8::1", C::Documentation),
    ("2001:db8:ffff::1", C::Documentation),
    // 6to4 can embed any IPv4 address, public or not.
    ("2002:7f00:1::1", C::SixToFour),
    ("2002:a9fe:a9fe::", C::SixToFour),
    ("2002:808:808::1", C::SixToFour),
    ("3fff::1", C::Documentation),
    ("3fff:fff::1", C::Documentation),
    ("3fff:1000::1", C::Public),
    ("fc00::1", C::UniqueLocal),
    ("fd00:ec2::254", C::UniqueLocal),
    ("fdff:ffff::1", C::UniqueLocal),
    ("fe80::1", C::LinkLocal),
    ("febf::1", C::LinkLocal),
    ("fec0::1", C::SiteLocal),
    ("feff::1", C::SiteLocal),
    ("ff02::1", C::Multicast),
    ("ff05::1:3", C::Multicast),
    ("4000::1", C::Reserved),
    ("5f00::1", C::Reserved),
    ("1fff::1", C::Reserved),
    ("e000::1", C::Reserved),
    ("2606:4700:4700::1111", C::Public),
    ("2a00:1450:4001::200e", C::Public),
    ("3ffe::1", C::Public),
];

fn run(cases: &[(&str, C)]) {
    for (raw, expected) in cases {
        let ip: IpAddr = raw.parse().unwrap_or_else(|_| panic!("bad fixture {raw}"));
        assert_eq!(classify(ip), *expected, "classify({raw})");
        assert_eq!(
            classify(ip).is_public(),
            *expected == C::Public,
            "is_public({raw})"
        );
    }
}

#[test]
fn classifies_ipv4_special_purpose_ranges() {
    run(V4_CASES);
}

#[test]
fn classifies_ipv6_special_purpose_ranges_and_ipv4_encodings() {
    run(V6_CASES);
}

#[test]
fn canonical_ip_unwraps_only_ipv4_mapped() {
    let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    assert_eq!(canonical_ip(mapped), "10.0.0.1".parse::<IpAddr>().unwrap());
    for raw in ["::10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::", "10.0.0.1"] {
        let ip: IpAddr = raw.parse().unwrap();
        assert_eq!(canonical_ip(ip), ip, "{raw} must stay unchanged");
    }
}

#[test]
fn nat64_embedded_ipv4_extracts_only_the_well_known_prefix() {
    let wkp = "64:ff9b::c0a8:101".parse().unwrap();
    assert_eq!(
        nat64_embedded_ipv4(wkp),
        Some("192.168.1.1".parse().unwrap())
    );
    for raw in ["64:ff9b:1::c0a8:101", "64:ff9a::1", "::c0a8:101"] {
        assert_eq!(nat64_embedded_ipv4(raw.parse().unwrap()), None, "{raw}");
    }
}

#[test]
fn class_labels_and_never_allowed_set_are_stable() {
    assert_eq!(C::SixToFour.as_str(), "6to4");
    assert_eq!(C::SharedCgnat.as_str(), "shared-cgnat");
    for class in [C::Unspecified, C::Multicast, C::Broadcast] {
        assert!(class.is_never_allowed(), "{class:?}");
    }
    for class in [C::Loopback, C::Private, C::LinkLocal, C::Public] {
        assert!(!class.is_never_allowed(), "{class:?}");
    }
}
