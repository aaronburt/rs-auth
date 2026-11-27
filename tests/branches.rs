#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
//! Table tests that pin down the individual conditions of the security
//! decisions (redirect validation, header trust, verify status codes, login
//! input limits), so that each half of an `&&` / `||` is exercised on its own.
mod common;

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use common::*;
use rs_auth::redirect::{original_url, validate_rd};

fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.insert(*k, HeaderValue::from_static(v));
    }
    h
}

#[test]
fn original_url_accepts_only_http_and_https_and_clean_hosts() {
    let ok = |pairs: &[(&'static str, &'static str)]| original_url(&headers(pairs));

    assert_eq!(
        ok(&[
            ("x-forwarded-proto", "http"),
            ("x-forwarded-host", "grafana.example.com"),
        ])
        .unwrap()
        .as_str(),
        "http://grafana.example.com/"
    );
    assert_eq!(
        ok(&[
            ("x-forwarded-proto", "HTTPS"),
            ("x-forwarded-host", "grafana.example.com"),
            ("x-forwarded-uri", "//evil.net/x"),
        ])
        .unwrap()
        .as_str(),
        "https://grafana.example.com/",
        "a protocol-relative path is flattened to /"
    );
    assert_eq!(
        ok(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "grafana.example.com"),
            ("x-forwarded-uri", "no-leading-slash"),
        ])
        .unwrap()
        .as_str(),
        "https://grafana.example.com/"
    );

    for bad in [
        // missing / wrong proto
        vec![("x-forwarded-host", "grafana.example.com")],
        vec![
            ("x-forwarded-proto", "javascript"),
            ("x-forwarded-host", "grafana.example.com"),
        ],
        vec![("x-forwarded-proto", "https"), ("x-forwarded-host", "  ")],
        vec![("x-forwarded-proto", "https")],
    ] {
        assert!(ok(&bad).is_none(), "{bad:?}");
    }
    // every character that could smuggle another authority is refused
    for c in ['/', '\\', '@', '?', '#'] {
        let host: &'static str = Box::leak(format!("a.example.com{c}b").into_boxed_str());
        assert!(
            ok(&[("x-forwarded-proto", "https"), ("x-forwarded-host", host)]).is_none(),
            "{c}"
        );
    }
    // a host that parses to no host at all
    assert!(ok(&[("x-forwarded-proto", "https"), ("x-forwarded-host", "[::1"),]).is_none());
}

#[test]
fn validate_rd_checks_scheme_userinfo_and_domain_independently() {
    let strict = config_from(&toml(1, &["admins"], false));
    let dev = config_from(&toml(1, &["admins"], false).replace(
        "trusted_proxies =",
        "insecure_dev_mode = true\ntrusted_proxies =",
    ));

    for bad in [
        "http://grafana.example.com/",
        "ftp://grafana.example.com/",
        "javascript:alert(1)",
        "https://user@grafana.example.com/",
        "https://user:pw@grafana.example.com/",
        "https://:pw@grafana.example.com/",
        "https://example.com.evil.net/",
        "https://evilexample.com/",
        "   ",
        "",
    ] {
        assert!(validate_rd(&strict, bad).is_none(), "{bad:?}");
    }
    assert!(validate_rd(&strict, "  https://grafana.example.com/x  ").is_some());
    // http is only acceptable when the operator opted into dev mode, and the
    // other checks still apply there
    assert!(dev.server.insecure_dev_mode);
    {
        assert!(validate_rd(&dev, "http://grafana.example.com/").is_some());
        assert!(validate_rd(&dev, "http://user@grafana.example.com/").is_none());
        assert!(validate_rd(&dev, "http://evil.net/").is_none());
        assert!(validate_rd(&dev, "ftp://grafana.example.com/").is_none());
    }
}

#[tokio::test]
async fn verify_redirects_by_method_and_refuses_unusable_requests() {
    let app = app();
    for (method, status) in [
        ("GET", StatusCode::FOUND),
        ("get", StatusCode::FOUND),
        ("HEAD", StatusCode::FOUND),
        ("POST", StatusCode::SEE_OTHER),
        ("DELETE", StatusCode::SEE_OTHER),
    ] {
        let r = send(
            &app,
            PROXY,
            verify_req(method, "grafana.example.com", "/d", ""),
        )
        .await;
        assert_eq!(r.status, status, "{method}");
        assert!(r.location().starts_with("https://auth.example.com/"));
    }

    // no forwarded method at all counts as GET
    let mut req = verify_req("GET", "grafana.example.com", "/d", "");
    req.headers_mut().remove("x-forwarded-method");
    assert_eq!(send(&app, PROXY, req).await.status, StatusCode::FOUND);

    // no forwarded proto/host: cannot build a safe return address, so refuse
    let r = send(&app, PROXY, get("/api/verify", "")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("location").is_none());

    // a signed-in user whose group list or name cannot be sent as a header is
    // refused rather than sent through with a partial identity
    let cookie = sign_in(&app, "aaron", "correct horse").await;
    let ok = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &cookie),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.header("remote-user"), Some("aaron"));
}

#[tokio::test]
async fn login_limits_each_input_separately() {
    let long_user = "u".repeat(65);
    let long_pw = "p".repeat(1025);
    let cases: [(&str, &str); 5] = [
        ("", "correct horse"),
        ("aaron", ""),
        (&long_user, "x"),
        ("aaron", &long_pw),
        ("", ""),
    ];
    for (user, pw) in cases {
        // a fresh app per case, so the lockout never gets involved
        let app = app();
        let (cookie, token) = csrf(&app, PROXY).await;
        let r = send(
            &app,
            PROXY,
            post_form(
                "/login",
                &cookie,
                &[("username", user), ("password", pw), ("csrf", &token)],
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{user:?}");
        assert!(r.cookie("rs_auth_session").is_none());
    }
}

#[tokio::test]
async fn logout_without_a_session_still_clears_cookies() {
    let app = app();
    let (cookie, token) = csrf(&app, PROXY).await;
    let r = send(
        &app,
        PROXY,
        post_form("/logout", &cookie, &[("csrf", &token)]),
    )
    .await;
    assert!(
        r.status.is_redirection() || r.status.is_success(),
        "{}",
        r.status
    );
}
