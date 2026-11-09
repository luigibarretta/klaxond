use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ClientIpError;

/// One validated CIDR block. IPv4-mapped IPv6 networks are rejected so every
/// IPv4 range has exactly one spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpNetwork {
    pub(super) fn parse(raw: &str) -> Result<Self, ClientIpError> {
        let invalid = || ClientIpError::invalid_network(raw);
        let trimmed = raw.trim();
        let (address, prefix) = match trimmed.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (trimmed, None),
        };
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        if is_ipv4_mapped(address) {
            return Err(invalid());
        }
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) if prefix.bytes().all(|byte| byte.is_ascii_digit()) => {
                prefix.parse::<u8>().map_err(|_| invalid())?
            }
            Some(_) => return Err(invalid()),
            None => max_prefix,
        };
        if prefix > max_prefix {
            return Err(invalid());
        }
        let network = match address {
            IpAddr::V4(v4) => Self::V4 {
                network: u32::from(v4),
                prefix,
            },
            IpAddr::V6(v6) => Self::V6 {
                network: u128::from(v6),
                prefix,
            },
        };
        if network.has_host_bits() {
            return Err(invalid());
        }
        Ok(network)
    }

    pub(super) fn contains(&self, address: IpAddr) -> bool {
        match (*self, normalize(address)) {
            (Self::V4 { network, prefix }, IpAddr::V4(v4)) => {
                u32::from(v4) & mask_v4(prefix) == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(v6)) => {
                u128::from(v6) & mask_v6(prefix) == network
            }
            _ => false,
        }
    }

    fn has_host_bits(&self) -> bool {
        match *self {
            Self::V4 { network, prefix } => network & !mask_v4(prefix) != 0,
            Self::V6 { network, prefix } => network & !mask_v6(prefix) != 0,
        }
    }
}

/// Converts IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to plain IPv4 so
/// dual-stack listeners and IPv4 CIDRs agree.
pub fn normalize(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => address,
    }
}

fn is_ipv4_mapped(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
}

fn mask_v4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask_v6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

/// Parses one hop: a bare address, `v4:port`, `[v6]` or `[v6]:port`.
pub(super) fn parse_node(raw: &str) -> Option<IpAddr> {
    if let Ok(address) = raw.parse::<IpAddr>() {
        return Some(normalize(address));
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let address = inside.parse::<Ipv6Addr>().ok()?;
        let valid_suffix = after.is_empty() || valid_port(after.strip_prefix(':')?);
        return valid_suffix.then(|| normalize(IpAddr::V6(address)));
    }
    let (address, port) = raw.split_once(':')?;
    let address = address.parse::<Ipv4Addr>().ok()?;
    valid_port(port).then_some(IpAddr::V4(address))
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}
