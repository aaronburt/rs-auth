#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;

const LOGIN_FOR_GRAFANA: &str =
    "https://auth.example.com/login?rd=https%3A%2F%2Fgrafana.example.com%2Fd%2Fabc%3Fx%3D1";

fn nginx_req(method: &str, host: &str, uri: &str, cookies: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri("/api/verify/nginx")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", host)
        .header("x-forwarded-uri", uri)
        .header("x-forwarded-method", "POST");
    if !cookies.is_empty() {
        b = b.header(header::COOKIE, cookies);
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn not_signed_in_gets_401_with_the_login_address() {
    let app = app();
    for method in ["GET", "HEAD"] {
        let r = send(
            &app,
            PROXY,
            nginx_req(method, "grafana.example.com", "/d/abc?x=1", ""),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{method}");
        assert_eq!(r.location(), LOGIN_FOR_GRAFANA, "{method}");
        assert!(r.header("remote-user").is_none());
    }

    let plain = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/d/abc?x=1", ""),
    )
    .await;
    assert_eq!(plain.status, StatusCode::FOUND);
    assert_eq!(plain.location(), LOGIN_FOR_GRAFANA);
}

#[tokio::test]
async fn signed_in_gets_the_same_headers_as_the_redirect_style() {
    let app = app();
    let session = sign_in(&app, "aaron", "correct horse").await;
    let cookies = format!("pref=keep; {session}; other=2");
    let r = send(
        &app,
        PROXY,
        nginx_req("GET", "grafana.example.com", "/", &cookies),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("remote-user"), Some("aaron"));
    assert_eq!(r.header("remote-groups"), Some("admins,family"));
    assert_eq!(r.header("remote-name"), Some("Aaron Example"));
    assert_eq!(r.header("remote-email"), Some("aaron@example.com"));
    assert_eq!(r.header("cookie"), Some("pref=keep; other=2"));

    let only = send(
        &app,
        PROXY,
        nginx_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(only.status, StatusCode::OK);
    assert!(only.header("cookie").is_none());
}

#[tokio::test]
async fn a_bad_or_revoked_session_is_sent_to_sign_in() {
    let app = app();
    let r = send(
        &app,
        PROXY,
        nginx_req(
            "GET",
            "grafana.example.com",
            "/",
            "rs_auth_session=not.a.token",
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.location().starts_with("https://auth.example.com/login"));

    let session = sign_in(&app, "aaron", "correct horse").await;
    let (csrf_cookie, token) = csrf(&app, PROXY).await;
    let out = send(
        &app,
        PROXY,
        post_form(
            "/logout",
            &format!("{session}; {csrf_cookie}"),
            &[("csrf", &token)],
        ),
    )
    .await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    let r = send(
        &app,
        PROXY,
        nginx_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("remote-user").is_none());
}

#[tokio::test]
async fn a_host_with_no_rule_is_403_for_everyone_with_the_page() {
    let app = app();
    let session = sign_in(&app, "aaron", "correct horse").await;
    for cookies in ["", session.as_str()] {
        let r = send(
            &app,
            PROXY,
            nginx_req("GET", "evil.example.net", "/", cookies),
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert!(r.header("location").is_none());
        assert!(r.header("remote-user").is_none());
        assert!(r.body.contains("evil.example.net"));
        assert!(r.header("content-security-policy").is_some());
    }
}

#[tokio::test]
async fn a_user_outside_the_hosts_groups_is_403() {
    let text = toml(1, &["family"], false).replace(
        "[access.\"*.example.com\"]\ngroups = [\"admins\", \"family\", \"viewers\"]",
        "[access.\"*.example.com\"]\ngroups = [\"admins\"]",
    );
    let app = app_with(&text);
    let session = sign_in(&app, "aaron", "correct horse").await;
    let r = send(
        &app,
        PROXY,
        nginx_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(r.header("remote-user").is_none());
    assert!(r.header("cookie").is_none());
    assert!(
        r.body
            .contains("does not have access to <strong>grafana.example.com</strong>")
    );
}

#[tokio::test]
async fn refuses_what_the_redirect_style_refuses() {
    let app = app();
    let session = sign_in(&app, "aaron", "correct horse").await;

    let r = send(
        &app,
        OUTSIDE,
        nginx_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("location").is_none());
    assert!(r.header("remote-user").is_none());

    let r = send(&app, PROXY, get("/api/verify/nginx", &session)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("location").is_none());

    let planted = format!("{session}; rs_auth_session=planted.by.a.sibling");
    let r = send(
        &app,
        PROXY,
        nginx_req("GET", "grafana.example.com", "/", &planted),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.header("remote-user").is_none());

    let r = send(
        &app,
        PROXY,
        nginx_req("GET", "grafana.example.com", "//evil.net/x", ""),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.location(),
        "https://auth.example.com/login?rd=https%3A%2F%2Fgrafana.example.com%2F"
    );
}
