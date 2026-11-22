#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
mod common;

use axum::http::{HeaderMap, HeaderValue};
use common::*;
use rs_auth::redirect::{login_url, original_url, target, validate_rd};

#[test]
fn allowed_targets() {
    let c = config_from(&yaml(1, "[admins]", false));
    for ok in [
        "https://example.com/",
        "https://grafana.example.com/d/abc?x=1#y",
        "https://a.b.example.com:8443/",
        "https://GRAFANA.EXAMPLE.COM/",
    ] {
        assert!(validate_rd(&c, ok).is_some(), "{ok} should be allowed");
    }
}

#[test]
fn denied_targets() {
    let c = config_from(&yaml(1, "[admins]", false));
    for bad in [
        "",
        "/relative",
        "//evil.net/",
        "http://grafana.example.com/",
        "https://evil.net/",
        "https://example.com.evil.net/",
        "https://evilexample.com/",
        "https://user@grafana.example.com/",
        "javascript:alert(1)",
        "data:text/html,hi",
        "https:/\\evil.net",
        "https://evil.net\\@grafana.example.com/",
    ] {
        assert!(validate_rd(&c, bad).is_none(), "{bad:?} should be denied");
    }
    assert!(validate_rd(&c, &format!("https://example.com/{}", "a".repeat(5000))).is_none());
    assert_eq!(
        target(&c, Some("https://evil.net/")),
        c.server.default_redirect_url
    );
    assert_eq!(target(&c, None), c.server.default_redirect_url);
}

#[test]
fn rebuilds_original_url() {
    let mut h = HeaderMap::new();
    h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    h.insert(
        "x-forwarded-host",
        HeaderValue::from_static("grafana.example.com"),
    );
    h.insert("x-forwarded-uri", HeaderValue::from_static("/d/abc?x=1"));
    assert_eq!(
        original_url(&h).unwrap().as_str(),
        "https://grafana.example.com/d/abc?x=1"
    );

    h.remove("x-forwarded-uri");
    assert_eq!(
        original_url(&h).unwrap().as_str(),
        "https://grafana.example.com/"
    );

    h.insert("x-forwarded-uri", HeaderValue::from_static("//evil.net/x"));
    assert_eq!(
        original_url(&h).unwrap().host_str(),
        Some("grafana.example.com")
    );
    h.insert("x-forwarded-uri", HeaderValue::from_static("@evil.net/x"));
    assert_eq!(
        original_url(&h).unwrap().host_str(),
        Some("grafana.example.com")
    );

    h.insert(
        "x-forwarded-host",
        HeaderValue::from_static("evil.net/@grafana.example.com"),
    );
    assert!(original_url(&h).is_none());

    h.insert(
        "x-forwarded-host",
        HeaderValue::from_static("grafana.example.com"),
    );
    h.insert("x-forwarded-proto", HeaderValue::from_static("ftp"));
    assert!(original_url(&h).is_none());
}

#[test]
fn login_url_encodes_rd() {
    let c = config_from(&yaml(1, "[admins]", false));
    let rd = url::Url::parse("https://grafana.example.com/a?b=c&d=e").unwrap();
    let u = login_url(&c, Some(&rd));
    assert_eq!(
        u.as_str(),
        "https://auth.example.com/login?rd=https%3A%2F%2Fgrafana.example.com%2Fa%3Fb%3Dc%26d%3De"
    );
    assert_eq!(
        login_url(&c, None).as_str(),
        "https://auth.example.com/login"
    );
}

#[test]
fn uses_the_rightmost_forwarded_values() {
    let mut h = HeaderMap::new();
    h.insert("x-forwarded-proto", HeaderValue::from_static("http, https"));
    h.insert(
        "x-forwarded-host",
        HeaderValue::from_static("evil.net, grafana.example.com"),
    );
    h.insert("x-forwarded-uri", HeaderValue::from_static("/"));
    assert_eq!(
        original_url(&h).unwrap().as_str(),
        "https://grafana.example.com/"
    );
}
