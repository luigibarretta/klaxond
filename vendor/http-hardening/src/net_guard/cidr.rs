//! Minimal CIDR type for explicit allowlists (no external dependency).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use super::ip::canonical_ip;

/// Upper bound on entries accepted by [`parse_cidr_list`].
pub const MAX_CIDR_ENTRIES: usize = 256;

/// An IPv4 or IPv6 network in CIDR notation, e.g. `192.168.1.0/24`.
///
/// The network address must have no host bits set: `192.168.1.5/24` is
/// rejected instead of silently widened, so a typo cannot open a range the
/// operator did not intend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

/// Shortest IPv4 prefix accepted without [`Cidr::new_wide`].
pub const MIN_IPV4_PREFIX: u8 = 8;
/// Shortest IPv6 prefix accepted without [`Cidr::new_wide`].
pub const MIN_IPV6_PREFIX: u8 = 32;

/// Errors returned while parsing a [`Cidr`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CidrError {
    /// The input was empty.
    Empty,
    /// The address part is not a strict dotted-quad IPv4 or IPv6 literal.
    InvalidAddress(String),
    /// The prefix length is missing, not a number or too long.
    InvalidPrefix(String),
    /// The address has bits set beyond the prefix length.
    HostBitsSet(String),
    /// IPv4-mapped IPv6 networks (`::ffff:a.b.c.d/n`) are refused: write the
    /// IPv4 network instead, which also matches mapped addresses.
    Ipv4MappedNetwork(String),
    /// Prefix shorter than /8 (IPv4) or /32 (IPv6) without an explicit
    /// [`Cidr::new_wide`] / [`Cidr::parse_wide`].
    TooWide(String),
    /// More than [`MAX_CIDR_ENTRIES`] entries were supplied.
    TooManyEntries,
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty CIDR"),
            Self::InvalidAddress(raw) => write!(f, "invalid CIDR address: {raw}"),
            Self::InvalidPrefix(raw) => write!(f, "invalid CIDR prefix length: {raw}"),
            Self::HostBitsSet(raw) => write!(f, "CIDR has host bits set: {raw}"),
            Self::Ipv4MappedNetwork(raw) => write!(f, "IPv4-mapped CIDR is not allowed: {raw}"),
            Self::TooWide(raw) => write!(f, "CIDR is wider than allowed without opt-in: {raw}"),
            Self::TooManyEntries => {
                write!(f, "CIDR list exceeds {MAX_CIDR_ENTRIES} entries")
            }
        }
    }
}

impl std::error::Error for CidrError {}

impl Cidr {
    /// Builds a network from an address and a prefix length. Refuses host
    /// bits, IPv4-mapped networks (a mapped `/128` is canonicalised to the
    /// IPv4 `/32`) and prefixes shorter than [`MIN_IPV4_PREFIX`] /
    /// [`MIN_IPV6_PREFIX`].
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, CidrError> {
        let cidr = Self::new_wide(network, prefix)?;
        let min = if cidr.network.is_ipv4() {
            MIN_IPV4_PREFIX
        } else {
            MIN_IPV6_PREFIX
        };
        if cidr.prefix < min {
            return Err(CidrError::TooWide(format!("{network}/{prefix}")));
        }
        Ok(cidr)
    }

    /// Like [`Cidr::new`] but accepts any prefix length, e.g. `0.0.0.0/0`.
    /// Use only for deliberate, reviewed wide allowlists.
    pub fn new_wide(network: IpAddr, prefix: u8) -> Result<Self, CidrError> {
        let raw = || format!("{network}/{prefix}");
        let (network, prefix) = match network {
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => {
                if prefix != 128 {
                    return Err(CidrError::Ipv4MappedNetwork(raw()));
                }
                (canonical_ip(network), 32)
            }
            other => (other, prefix),
        };
        let host_bits = match network {
            IpAddr::V4(v4) if prefix <= 32 => u32::from(v4) & !prefix_mask_v4(prefix) != 0,
            IpAddr::V6(v6) if prefix <= 128 => u128::from(v6) & !prefix_mask_v6(prefix) != 0,
            _ => return Err(CidrError::InvalidPrefix(raw())),
        };
        if host_bits {
            return Err(CidrError::HostBitsSet(raw()));
        }
        Ok(Self { network, prefix })
    }

    /// Single-address network (`/32` or `/128`); IPv4-mapped addresses are
    /// canonicalised to IPv4.
    pub fn host(ip: IpAddr) -> Self {
        let network = canonical_ip(ip);
        let prefix = if network.is_ipv4() { 32 } else { 128 };
        Self { network, prefix }
    }

    /// Parses like [`FromStr`] but accepts any prefix length.
    pub fn parse_wide(raw: &str) -> Result<Self, CidrError> {
        parse(raw, Self::new_wide)
    }

    /// Network address.
    pub const fn network(&self) -> IpAddr {
        self.network
    }

    /// Prefix length.
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// True when `ip` (after IPv4-mapped canonicalisation) is inside the network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, canonical_ip(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                u32::from(ip) & prefix_mask_v4(self.prefix) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(ip) & prefix_mask_v6(self.prefix) == u128::from(net)
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    /// Parses `addr/prefix` or a bare address (host network) with the rules
    /// of [`Cidr::new`]. Only strict literals are accepted: std rejects
    /// octal, hex and short IPv4 forms and IPv6 zone identifiers.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        parse(raw, Self::new)
    }
}

fn parse(raw: &str, build: fn(IpAddr, u8) -> Result<Cidr, CidrError>) -> Result<Cidr, CidrError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(CidrError::Empty);
    }
    let (addr, prefix) = match raw.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (raw, None),
    };
    let network = IpAddr::from_str(addr).map_err(|_| CidrError::InvalidAddress(raw.to_owned()))?;
    let Some(prefix) = prefix else {
        return Ok(Cidr::host(network));
    };
    let digits_only =
        !prefix.is_empty() && prefix.len() <= 3 && prefix.bytes().all(|b| b.is_ascii_digit());
    let len = digits_only
        .then(|| prefix.parse::<u8>().ok())
        .flatten()
        .ok_or_else(|| CidrError::InvalidPrefix(raw.to_owned()))?;
    build(network, len)
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Parses a comma- and/or whitespace-separated CIDR list, e.g. the value of a
/// `NTFY_ALLOWED_CIDRS=192.168.1.0/24, fd00:1::/64` setting. Empty input
/// yields an empty list.
pub fn parse_cidr_list(raw: &str) -> Result<Vec<Cidr>, CidrError> {
    let mut out = Vec::new();
    for item in raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|item| !item.is_empty())
        .take(MAX_CIDR_ENTRIES + 1)
    {
        if out.len() == MAX_CIDR_ENTRIES {
            return Err(CidrError::TooManyEntries);
        }
        out.push(item.parse()?);
    }
    Ok(out)
}

/// Network mask for an IPv4 prefix length (lengths above 32 saturate).
pub(crate) fn prefix_mask_v4(prefix: u8) -> u32 {
    let host_bits = 32_u32.saturating_sub(u32::from(prefix));
    u32::MAX.checked_shl(host_bits).unwrap_or(0)
}

/// Network mask for an IPv6 prefix length (lengths above 128 saturate).
pub(crate) fn prefix_mask_v6(prefix: u8) -> u128 {
    let host_bits = 128_u32.saturating_sub(u32::from(prefix));
    u128::MAX.checked_shl(host_bits).unwrap_or(0)
}
