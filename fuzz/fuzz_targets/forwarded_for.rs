#![no_main]
use std::net::{IpAddr, SocketAddr};

use axum::http::{HeaderMap, HeaderValue};
use ipnet::IpNet;
use libfuzzer_sys::fuzz_target;
use rs_auth::net::{canonical, client_ip, is_trusted};

fuzz_target!(|data: &[u8]| {
    let trusted: Vec<IpNet> = vec![
        "172.18.0.0/16".parse().unwrap(),
        "fd00::/8".parse().unwrap(),
    ];
    let (first, rest) = data.split_first().map_or((0, data), |(f, r)| (*f, r));
    let peer: SocketAddr = if first & 1 == 0 {
        "172.18.0.2:1000".parse().unwrap()
    } else {
        "203.0.113.9:1000".parse().unwrap()
    };
    let mut h = HeaderMap::new();
    for chunk in rest.split(|b| *b == b'\n') {
        if let Ok(v) = HeaderValue::from_bytes(chunk) {
            h.append("x-forwarded-for", v);
        }
    }
    let ip = client_ip(&trusted, peer, &h);
    if !is_trusted(&trusted, peer.ip()) {
        assert_eq!(
            ip,
            canonical(peer.ip()),
            "an untrusted peer must never pick its own address"
        );
    }
    assert_eq!(ip, canonical(ip));
    let _: IpAddr = ip;
});
