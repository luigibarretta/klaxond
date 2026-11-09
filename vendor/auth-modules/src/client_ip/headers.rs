use std::net::IpAddr;

use super::network::parse_node;
use super::{ForwardingHeader, MAX_FORWARDED_HOPS};

/// Raw forwarding header values exactly as received, one entry per header
/// line, in arrival order. The resolver only reads the header selected by
/// [`super::TrustedProxies`]; the others are ignored.
#[derive(Clone, Debug, Default)]
pub struct ForwardingHeaders<'a> {
    x_forwarded_for: HeaderLines<'a>,
    forwarded: HeaderLines<'a>,
    x_real_ip: HeaderLines<'a>,
}

#[derive(Clone, Debug, Default)]
struct HeaderLines<'a> {
    values: Vec<&'a str>,
    invalid: bool,
}

impl<'a> HeaderLines<'a> {
    fn push_bytes(&mut self, value: &'a [u8]) {
        match std::str::from_utf8(value) {
            Ok(value) => self.values.push(value),
            Err(_) => self.invalid = true,
        }
    }

    fn non_blank(&self) -> impl DoubleEndedIterator<Item = &'a str> + '_ {
        self.values
            .iter()
            .copied()
            .filter(|value| !value.trim().is_empty())
    }
}

/// A hop that could not be parsed is represented as `None`.
pub(super) type Hop = Option<IpAddr>;

impl<'a> ForwardingHeaders<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_x_forwarded_for(&mut self, value: &'a str) -> &mut Self {
        self.x_forwarded_for.values.push(value);
        self
    }

    /// Adds a raw header value; non-UTF-8 bytes make the header malformed.
    pub fn push_x_forwarded_for_bytes(&mut self, value: &'a [u8]) -> &mut Self {
        self.x_forwarded_for.push_bytes(value);
        self
    }

    pub fn push_forwarded(&mut self, value: &'a str) -> &mut Self {
        self.forwarded.values.push(value);
        self
    }

    pub fn push_forwarded_bytes(&mut self, value: &'a [u8]) -> &mut Self {
        self.forwarded.push_bytes(value);
        self
    }

    pub fn push_x_real_ip(&mut self, value: &'a str) -> &mut Self {
        self.x_real_ip.values.push(value);
        self
    }

    pub fn push_x_real_ip_bytes(&mut self, value: &'a [u8]) -> &mut Self {
        self.x_real_ip.push_bytes(value);
        self
    }

    /// Returns the hops of the selected header from right (closest to this
    /// service) to left, bounded to `MAX_FORWARDED_HOPS + 1` entries.
    /// `None` means the header as a whole is unusable.
    pub(super) fn hops_from_right(&self, header: ForwardingHeader) -> Option<Vec<Hop>> {
        let lines = match header {
            ForwardingHeader::XForwardedFor => &self.x_forwarded_for,
            ForwardingHeader::Forwarded => &self.forwarded,
            ForwardingHeader::XRealIp => &self.x_real_ip,
        };
        if lines.invalid {
            return None;
        }
        match header {
            ForwardingHeader::XForwardedFor => Some(list_hops(lines, parse_node)),
            ForwardingHeader::Forwarded => Some(list_hops(lines, forwarded_node)),
            ForwardingHeader::XRealIp => single_hop(lines),
        }
    }
}

fn list_hops(lines: &HeaderLines<'_>, parse: fn(&str) -> Hop) -> Vec<Hop> {
    lines
        .non_blank()
        .rev()
        .flat_map(|line| line.rsplit(','))
        .map(|element| parse(element.trim()))
        .take(MAX_FORWARDED_HOPS + 1)
        .collect()
}

fn single_hop(lines: &HeaderLines<'_>) -> Option<Vec<Hop>> {
    let mut values = lines.non_blank();
    let Some(value) = values.next() else {
        return Some(Vec::new());
    };
    if values.next().is_some() || value.contains(',') {
        return None;
    }
    Some(vec![parse_node(value.trim())])
}

/// Extracts the `for=` node of one RFC 7239 element. Obfuscated identifiers
/// and `unknown` are not addresses and therefore unusable.
fn forwarded_node(element: &str) -> Hop {
    let mut found = None;
    for pair in element.split(';') {
        let (key, value) = pair.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("for") {
            if found.is_some() {
                return None;
            }
            found = Some(value.trim());
        }
    }
    let value = found?;
    let value = match value.strip_prefix('"') {
        Some(quoted) => quoted.strip_suffix('"')?,
        None => value,
    };
    parse_node(value)
}
