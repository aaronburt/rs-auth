//! Working out who is on the other end of a request.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use ipnet::IpNet;

/// Turn `::ffff:1.2.3.4` into `1.2.3.4` so IPv4 CIDRs match dual-stack peers.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

pub fn is_trusted(trusted: &[IpNet], ip: IpAddr) -> bool {
    let ip = canonical(ip);
    trusted.iter().any(|n| n.contains(&ip))
}

/// The client's IP. `X-Forwarded-For` is only believed when the direct peer
/// is a trusted proxy, and then we walk it from the right, skipping trusted
/// hops, so a client cannot spoof its address by sending its own header.
pub fn client_ip(trusted: &[IpNet], peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = canonical(peer.ip());
    if !is_trusted(trusted, peer_ip) {
        return peer_ip;
    }
    let mut hops: Vec<IpAddr> = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(s) = value.to_str() else {
            return peer_ip;
        };
        for part in s.split(',') {
            match parse_hop(part) {
                Some(ip) => hops.push(canonical(ip)),
                None => return peer_ip,
            }
        }
    }
    for ip in hops.iter().rev() {
        if !is_trusted(trusted, *ip) {
            return *ip;
        }
    }
    // Every hop is trusted: use the left-most one, else the peer.
    hops.first().copied().unwrap_or(peer_ip)
}

fn parse_hop(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    // Some proxies add a port: 1.2.3.4:5678 or [::1]:5678.
    s.parse::<SocketAddr>().ok().map(|a| a.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn nets() -> Vec<IpNet> {
        vec![
            "172.18.0.0/16".parse().unwrap(),
            "fd00::/8".parse().unwrap(),
        ]
    }

    fn hdrs(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
        h
    }

    #[test]
    fn untrusted_peer_ignores_header() {
        let peer: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        assert_eq!(client_ip(&nets(), peer, &hdrs("1.1.1.1")), peer.ip());
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted() {
        let peer: SocketAddr = "172.18.0.2:1234".parse().unwrap();
        let ip = client_ip(&nets(), peer, &hdrs("6.6.6.6, 198.51.100.7, 172.18.0.5"));
        assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_peer_without_header_is_peer() {
        let peer: SocketAddr = "172.18.0.2:1234".parse().unwrap();
        assert_eq!(client_ip(&nets(), peer, &HeaderMap::new()), peer.ip());
    }

    #[test]
    fn garbage_header_falls_back_to_peer() {
        let peer: SocketAddr = "172.18.0.2:1234".parse().unwrap();
        assert_eq!(client_ip(&nets(), peer, &hdrs("not-an-ip")), peer.ip());
    }

    #[test]
    fn ports_and_mapped_addresses() {
        let peer: SocketAddr = "[::ffff:172.18.0.2]:1234".parse().unwrap();
        assert!(is_trusted(&nets(), peer.ip()));
        let ip = client_ip(&nets(), peer, &hdrs("198.51.100.7:4444"));
        assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    }
}
