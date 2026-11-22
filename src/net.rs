use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use ipnet::IpNet;

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

pub fn client_ip(trusted: &[IpNet], peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = canonical(peer.ip());
    if !is_trusted(trusted, peer_ip) {
        return peer_ip;
    }
    let values: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
    let mut leftmost = None;
    for value in values.into_iter().rev() {
        let Ok(s) = value.to_str() else {
            return leftmost.unwrap_or(peer_ip);
        };
        for part in s.rsplit(',') {
            let Some(ip) = parse_hop(part) else {
                return leftmost.unwrap_or(peer_ip);
            };
            let ip = canonical(ip);
            if !is_trusted(trusted, ip) {
                return ip;
            }
            leftmost = Some(ip);
        }
    }
    leftmost.unwrap_or(peer_ip)
}

fn parse_hop(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    let bare = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Some(ip);
    }
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
    fn garbage_left_of_the_real_client_is_ignored() {
        let peer: SocketAddr = "172.18.0.2:1234".parse().unwrap();
        let ip = client_ip(&nets(), peer, &hdrs("not-an-ip, 198.51.100.7"));
        assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn several_headers_are_read_right_to_left() {
        let peer: SocketAddr = "172.18.0.2:1234".parse().unwrap();
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
        h.append(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.7, 172.18.0.9"),
        );
        assert_eq!(
            client_ip(&nets(), peer, &h),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn all_trusted_hops_use_the_leftmost() {
        let peer: SocketAddr = "172.18.0.2:1234".parse().unwrap();
        let ip = client_ip(&nets(), peer, &hdrs("172.18.0.50, 172.18.0.9"));
        assert_eq!(ip, "172.18.0.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn bracketed_ipv6_hops() {
        let peer: SocketAddr = "172.18.0.2:1234".parse().unwrap();
        assert_eq!(
            client_ip(&nets(), peer, &hdrs("[2001:db8::1]")),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip(&nets(), peer, &hdrs("[2001:db8::1]:443")),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ports_and_mapped_addresses() {
        let peer: SocketAddr = "[::ffff:172.18.0.2]:1234".parse().unwrap();
        assert!(is_trusted(&nets(), peer.ip()));
        let ip = client_ip(&nets(), peer, &hdrs("198.51.100.7:4444"));
        assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    }
}
