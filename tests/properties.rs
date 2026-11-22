#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::http::{HeaderMap, HeaderValue};
use common::*;
use ipnet::IpNet;
use proptest::prelude::*;
use rs_auth::config::host_in_domain;
use rs_auth::cookie::{Cookie, CookieJar};
use rs_auth::net::client_ip;
use rs_auth::redirect::validate_rd;

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?"
}

proptest! {
    #[test]
    fn subdomains_are_inside_the_domain(sub in prop::collection::vec(label(), 1..4)) {
        let host = format!("{}.example.com", sub.join("."));
        prop_assert!(host_in_domain(&host, "example.com"));
    }

    #[test]
    fn lookalike_hosts_are_outside(prefix in label(), tld in "(com|net|org|evil)") {
        for host in [
            format!("{prefix}example.com"),
            format!("example.com.{prefix}.{tld}"),
            format!("{prefix}.example.co"),
            format!("{prefix}-example.com"),
        ] {
            prop_assert!(!host_in_domain(&host, "example.com"), "{host}");
        }
    }

    #[test]
    fn redirects_never_leave_the_domain(s in "\\PC{0,80}") {
        let config = config_from(&yaml(1, "[admins]", false));
        if let Some(u) = validate_rd(&config, &s) {
            prop_assert_eq!(u.scheme(), "https");
            prop_assert!(u.username().is_empty() && u.password().is_none());
            let host = u.host_str().unwrap().to_ascii_lowercase();
            prop_assert!(host_in_domain(&host, "example.com"), "{s:?} -> {u}");
        }
    }

    #[test]
    fn redirect_tricks_are_rejected(prefix in label(), path in "[a-z/]{0,10}") {
        let config = config_from(&yaml(1, "[admins]", false));
        for rd in [
            format!("https://{prefix}example.com/{path}"),
            format!("https://example.com.{prefix}.net/{path}"),
            format!("https://example.com@{prefix}.net/{path}"),
            format!("http://{prefix}.example.com/{path}"),
            format!("javascript://{prefix}.example.com/%0aalert(1)"),
            format!("//{prefix}.net/{path}"),
            format!("https://{prefix}.net\\.example.com/{path}"),
        ] {
            prop_assert!(validate_rd(&config, &rd).is_none(), "{rd} was accepted");
        }
    }

    #[test]
    fn cookie_values_round_trip(name in "[A-Za-z0-9_-]{1,20}", value in "[A-Za-z0-9._~=-]{0,200}") {
        let set = Cookie::new(name.clone(), value.clone()).header_value().unwrap();
        let pair = set.to_str().unwrap().split(';').next().unwrap().to_owned();
        let jar = CookieJar::parse(std::iter::once(pair.as_str()));
        prop_assert_eq!(jar.get(&name), Some(value.as_str()));
    }

    #[test]
    fn untrusted_peers_cannot_choose_their_ip(xff in "\\PC{0,60}", a in any::<u8>(), b in any::<u8>()) {
        let trusted: Vec<IpNet> = vec!["172.18.0.0/16".parse().unwrap()];
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, a, b)), 1000);
        let mut h = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&xff) {
            h.insert("x-forwarded-for", v);
        }
        prop_assert_eq!(client_ip(&trusted, peer, &h), peer.ip());
    }

    #[test]
    fn trusted_proxy_picks_the_rightmost_untrusted_hop(
        hops in prop::collection::vec((1u8..=223, any::<u8>(), any::<u8>(), 1u8..=254), 1..5),
    ) {
        let trusted: Vec<IpNet> = vec!["172.18.0.0/16".parse().unwrap()];
        let peer: SocketAddr = "172.18.0.2:1000".parse().unwrap();
        let ips: Vec<IpAddr> = hops
            .iter()
            .map(|(a, b, c, d)| IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)))
            .collect();
        let header = ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(&header).unwrap());
        let expected = ips
            .iter()
            .rev()
            .find(|ip| !trusted[0].contains(*ip))
            .copied()
            .unwrap_or(ips[0]);
        prop_assert_eq!(client_ip(&trusted, peer, &h), expected);
    }
}
