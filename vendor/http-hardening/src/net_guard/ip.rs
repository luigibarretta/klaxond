//! Classification of IP addresses for outbound requests.
//!
//! Only globally routable unicast addresses are [`AddressClass::Public`].
//! Every special-purpose range (IANA IPv4/IPv6 special-purpose registries)
//! gets its own class so errors explain why a target was refused. IPv6
//! encodings of IPv4 addresses are handled explicitly:
//!
//! - IPv4-mapped (`::ffff:a.b.c.d`) is canonicalised to IPv4 first, because
//!   dual-stack sockets dial the embedded IPv4 address;
//! - well-known NAT64 (`64:ff9b::/96`, RFC 6052) is judged by the embedded
//!   IPv4 address, so a NAT64 encoding of a private host stays private;
//! - IPv4-compatible (`::a.b.c.d`), local-use NAT64 (`64:ff9b:1::/48`), 6to4
//!   (`2002::/16`) and Teredo (`2001::/32`) are refused as whole ranges.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::cidr::{prefix_mask_v4, prefix_mask_v6};

/// Why an address is (or is not) eligible as an outbound target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddressClass {
    /// Globally routable unicast address.
    Public,
    /// `0.0.0.0` or `::`.
    Unspecified,
    /// `127.0.0.0/8` or `::1`.
    Loopback,
    /// RFC 1918 private IPv4 space.
    Private,
    /// `100.64.0.0/10` shared address space (carrier-grade NAT).
    SharedCgnat,
    /// `169.254.0.0/16` or `fe80::/10`, including cloud metadata endpoints.
    LinkLocal,
    /// `192.0.0.0/24` or `2001::/23` IETF protocol assignments.
    ProtocolAssignment,
    /// TEST-NET-1/2/3, `2001:db8::/32` and `3fff::/20`.
    Documentation,
    /// `198.18.0.0/15` or `2001:2::/48` benchmarking.
    Benchmarking,
    /// `224.0.0.0/4` or `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// Reserved or otherwise not globally routable space.
    Reserved,
    /// `fc00::/7` unique local addresses.
    UniqueLocal,
    /// `fec0::/10` deprecated site-local addresses.
    SiteLocal,
    /// `100::/64` discard-only prefix.
    Discard,
    /// Deprecated IPv4-compatible IPv6 (`::a.b.c.d`).
    Ipv4Compatible,
    /// `64:ff9b:1::/48` local-use NAT64 (the translator may reach private space).
    Nat64LocalUse,
    /// `2002::/16` 6to4, which can embed any IPv4 address.
    SixToFour,
    /// `2001::/32` Teredo, which embeds IPv4 server and client addresses.
    Teredo,
}

impl AddressClass {
    /// True only for globally routable unicast addresses.
    pub const fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }

    /// Classes that no allowlist can enable: they are never a valid unicast
    /// destination for an outbound HTTP request.
    pub const fn is_never_allowed(self) -> bool {
        matches!(self, Self::Unspecified | Self::Multicast | Self::Broadcast)
    }

    /// Stable lowercase label, suitable for logs and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::SharedCgnat => "shared-cgnat",
            Self::LinkLocal => "link-local",
            Self::ProtocolAssignment => "protocol-assignment",
            Self::Documentation => "documentation",
            Self::Benchmarking => "benchmarking",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Reserved => "reserved",
            Self::UniqueLocal => "unique-local",
            Self::SiteLocal => "site-local",
            Self::Discard => "discard",
            Self::Ipv4Compatible => "ipv4-compatible",
            Self::Nat64LocalUse => "nat64-local-use",
            Self::SixToFour => "6to4",
            Self::Teredo => "teredo",
        }
    }
}

/// IPv4 special-purpose ranges, most specific first; the first match wins.
const V4_RANGES: [(u32, u8, AddressClass); 17] = [
    (0x0000_0000, 32, AddressClass::Unspecified),
    (0x0000_0000, 8, AddressClass::Reserved),
    (0x0a00_0000, 8, AddressClass::Private),
    (0x6440_0000, 10, AddressClass::SharedCgnat),
    (0x7f00_0000, 8, AddressClass::Loopback),
    (0xa9fe_0000, 16, AddressClass::LinkLocal),
    (0xac10_0000, 12, AddressClass::Private),
    (0xc000_0000, 24, AddressClass::ProtocolAssignment),
    (0xc000_0200, 24, AddressClass::Documentation),
    (0xc058_6300, 24, AddressClass::Reserved),
    (0xc0a8_0000, 16, AddressClass::Private),
    (0xc612_0000, 15, AddressClass::Benchmarking),
    (0xc633_6400, 24, AddressClass::Documentation),
    (0xcb00_7100, 24, AddressClass::Documentation),
    (0xe000_0000, 4, AddressClass::Multicast),
    (0xffff_ffff, 32, AddressClass::Broadcast),
    (0xf000_0000, 4, AddressClass::Reserved),
];

/// IPv6 special-purpose ranges inside or next to `2000::/3`, most specific
/// first. `::`, `::1`, mapped and well-known NAT64 are handled before.
const V6_RANGES: [(u128, u8, AddressClass); 13] = [
    (0, 96, AddressClass::Ipv4Compatible),
    (0x0064_ff9b_0001_u128 << 80, 48, AddressClass::Nat64LocalUse),
    (0x0100_u128 << 112, 64, AddressClass::Discard),
    (0x2001_0000_u128 << 96, 32, AddressClass::Teredo),
    (0x2001_0002_0000_u128 << 80, 48, AddressClass::Benchmarking),
    (0x2001_0db8_u128 << 96, 32, AddressClass::Documentation),
    (0x2001_u128 << 112, 23, AddressClass::ProtocolAssignment),
    (0x2002_u128 << 112, 16, AddressClass::SixToFour),
    (0x3fff_u128 << 112, 20, AddressClass::Documentation),
    (0xfc00_u128 << 112, 7, AddressClass::UniqueLocal),
    (0xfe80_u128 << 112, 10, AddressClass::LinkLocal),
    (0xfec0_u128 << 112, 10, AddressClass::SiteLocal),
    (0xff00_u128 << 112, 8, AddressClass::Multicast),
];

/// Unwraps IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4; any other address is
/// returned unchanged. The OS dials the embedded IPv4 address for mapped
/// destinations, so policy and allowlists must see the IPv4 form.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Classifies `ip` after canonicalisation. Fails closed: anything that is not
/// known global unicast space is reported as a non-public class.
pub fn classify(ip: IpAddr) -> AddressClass {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// IPv4 address embedded in a well-known-prefix NAT64 address (`64:ff9b::/96`).
pub fn nat64_embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let bits = u128::from(ip);
    let prefix = 0x0064_ff9b_u128 << 96;
    if bits & prefix_mask_v6(96) != prefix {
        return None;
    }
    u32::try_from(bits & u128::from(u32::MAX))
        .ok()
        .map(Ipv4Addr::from)
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let bits = u32::from(ip);
    V4_RANGES
        .iter()
        .find(|(network, prefix, _)| bits & prefix_mask_v4(*prefix) == *network)
        .map_or(AddressClass::Public, |(_, _, class)| *class)
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    if ip.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if ip.is_loopback() {
        return AddressClass::Loopback;
    }
    if let Some(embedded) = nat64_embedded_ipv4(ip) {
        return classify_v4(embedded);
    }
    let bits = u128::from(ip);
    if let Some((_, _, class)) = V6_RANGES
        .iter()
        .find(|(network, prefix, _)| bits & prefix_mask_v6(*prefix) == *network)
    {
        return *class;
    }
    // Only 2000::/3 is allocated global unicast; everything else is reserved.
    if bits & prefix_mask_v6(3) == 0x2000_u128 << 112 {
        AddressClass::Public
    } else {
        AddressClass::Reserved
    }
}
