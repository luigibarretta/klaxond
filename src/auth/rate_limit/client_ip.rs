use crate::state::AppState;
use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub(in crate::auth) fn client_ip(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> String {
    let Some(peer_ip) = peer.map(|peer| peer.ip()) else {
        return "unknown".to_string();
    };
    if !trusted_proxy_ip(state, peer_ip) {
        return peer_ip.to_string();
    }

    let mut current = peer_ip;
    let forwarded = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| value.trim().parse::<IpAddr>().ok())
        .collect::<Vec<_>>();
    if forwarded.is_empty()
        && let Some(real_ip) = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
    {
        return real_ip.to_string();
    }
    for forwarded_ip in forwarded.into_iter().rev() {
        if !trusted_proxy_ip(state, current) {
            break;
        }
        current = forwarded_ip;
    }
    current.to_string()
}

fn trusted_proxy_ip(state: &AppState, ip: IpAddr) -> bool {
    state.with_cfg(|cfg| {
        cfg.auth
            .trusted_proxy
            .trusted_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .any(|network| network.contains(&ip))
    })
}
