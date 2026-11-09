//! Client address for rate limits and logs, resolved with
//! `auth_modules::client_ip::TrustedProxies`.
//!
//! The trusted proxies are `auth.trusted_proxy.trusted_cidrs` (environment
//! override `AUTH_TRUSTED_PROXY_CIDRS`). Only `X-Forwarded-For` is read, from
//! the right; an untrusted peer is always the client, and a malformed hop
//! before the client makes the peer the answer.

use crate::state::AppState;
use auth_modules::client_ip::{ForwardingHeader, ForwardingHeaders, TrustedProxies};
use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub(crate) fn client_ip(state: &AppState, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    let Some(peer_ip) = peer.map(|peer| peer.ip()) else {
        return "unknown".to_string();
    };
    let trusted = state.with_cfg(|cfg| trusted_proxies(&cfg.auth.trusted_proxy.trusted_cidrs));
    resolve(&trusted, headers, peer_ip).to_string()
}

pub(crate) fn resolve(trusted: &TrustedProxies, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    let mut forwarded = ForwardingHeaders::new();
    for value in headers.get_all("x-forwarded-for") {
        forwarded.push_x_forwarded_for_bytes(value.as_bytes());
    }
    trusted.resolve(peer, &forwarded)
}

/// Builds the resolver from the configured list. The same list also gates
/// the trusted-proxy login mode, which historically accepted host bits
/// (`10.0.0.1/8`) and skipped unparsable entries; both behaviours are kept
/// here (host bits are truncated, invalid entries are ignored with a warning)
/// so a configuration that loaded before keeps loading.
pub(crate) fn trusted_proxies(cidrs: &[String]) -> TrustedProxies {
    let networks = cidrs
        .iter()
        .filter_map(|cidr| {
            let normalized = normalize_network(cidr);
            if normalized.is_none() {
                tracing::warn!(entry = %cidr, "ignoring invalid trusted proxy CIDR");
            }
            normalized
        })
        .collect::<Vec<_>>();
    TrustedProxies::new(networks, ForwardingHeader::XForwardedFor)
        .unwrap_or_else(|_| TrustedProxies::none())
}

fn normalize_network(cidr: &str) -> Option<String> {
    let cidr = cidr.trim();
    let candidate = match cidr.parse::<IpNet>() {
        Ok(network) => network.trunc().to_string(),
        Err(_) => cidr.parse::<IpAddr>().ok()?.to_string(),
    };
    TrustedProxies::new([candidate.as_str()], ForwardingHeader::XForwardedFor)
        .is_ok()
        .then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(values: &[&'static str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", HeaderValue::from_static(value));
        }
        headers
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn untrusted_peers_are_the_client() {
        let trusted = trusted_proxies(&["192.168.50.100/32".into()]);
        let resolved = resolve(&trusted, &headers(&["203.0.113.7"]), ip("192.168.50.42"));
        assert_eq!(resolved, ip("192.168.50.42"));
    }

    #[test]
    fn injected_garbage_left_of_the_client_is_ignored() {
        let trusted = trusted_proxies(&["192.168.50.100/32".into()]);
        let resolved = resolve(
            &trusted,
            &headers(&["not-an-ip, 198.51.100.66, 203.0.113.7"]),
            ip("192.168.50.100"),
        );
        assert_eq!(resolved, ip("203.0.113.7"));
    }

    #[test]
    fn a_malformed_hop_before_the_client_falls_back_to_the_peer() {
        // The old resolver skipped unparsable hops and trusted the next one.
        let trusted = trusted_proxies(&["192.168.50.100/32".into()]);
        let resolved = resolve(
            &trusted,
            &headers(&["198.51.100.66, garbage"]),
            ip("192.168.50.100"),
        );
        assert_eq!(resolved, ip("192.168.50.100"));
    }

    #[test]
    fn x_real_ip_is_not_trusted() {
        let trusted = trusted_proxies(&["192.168.50.100/32".into()]);
        let mut map = HeaderMap::new();
        map.insert("x-real-ip", HeaderValue::from_static("198.51.100.66"));
        assert_eq!(
            resolve(&trusted, &map, ip("192.168.50.100")),
            ip("192.168.50.100")
        );
    }

    #[test]
    fn legacy_entries_keep_loading() {
        let trusted = trusted_proxies(&[
            "10.0.0.1/8".into(),
            "192.0.2.1".into(),
            "nonsense".into(),
            "::ffff:0:0/96".into(),
        ]);
        assert!(trusted.contains(ip("10.9.9.9")));
        assert!(trusted.contains(ip("192.0.2.1")));
        assert!(!trusted.contains(ip("192.0.2.2")));
        assert!(trusted_proxies(&[]).is_empty());
    }
}
