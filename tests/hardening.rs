#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]

mod common;

use std::path::{Path, PathBuf};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use rs_auth::AppState;

fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rs-auth-hard-{name}-{}", rs_auth::token::new_jti()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn with_revocation_file(file: &Path) -> String {
    toml(1, &["admins"], true).replace(
        "expiry = \"12h\"\n",
        &format!(
            "expiry = \"12h\"\nrevocation_file = {:?}\n",
            file.display().to_string()
        ),
    )
}

fn with_attempts(n: u32) -> String {
    toml(1, &["admins"], true).replace("max_attempts = 5", &format!("max_attempts = {n}"))
}

async fn verify_status(app: &Router, session: &str) -> StatusCode {
    send(
        app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", session),
    )
    .await
    .status
}

async fn logout_page(app: &Router, session: &str) -> Resp {
    send(app, PROXY, get("/logout", session)).await
}

async fn post_logout(app: &Router, session: &str, page: &Resp) -> Resp {
    let csrf = page.cookie("__Host-rs_auth_csrf").unwrap();
    let token = page.csrf_field();
    let cookies = format!("{session}; __Host-rs_auth_csrf={csrf}");
    send(
        app,
        PROXY,
        post_form("/logout", &cookies, &[("csrf", &token)]),
    )
    .await
}

#[tokio::test]
async fn startup_fails_when_the_revocation_file_cannot_be_written() {
    let dir = temp_dir("nostart");
    let cfg = with_revocation_file(&dir.join("missing").join("revoked.txt"));
    let e = AppState::try_new(config_from(&cfg)).err().unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_failed_revocation_write_is_an_error_until_a_retry_saves_it() {
    let dir = temp_dir("logout");
    let data = dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let file = data.join("revoked.txt");
    let cfg = with_revocation_file(&file);
    let app = app_with(&cfg);
    let session = sign_in(&app, "aaron", "correct horse").await;
    assert_eq!(verify_status(&app, &session).await, StatusCode::OK);

    std::fs::remove_dir_all(&data).unwrap();
    let page = logout_page(&app, &session).await;
    assert_eq!(page.status, StatusCode::OK);
    let r = post_logout(&app, &session, &page).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(r.body.contains("Sign-out could not be saved"), "{}", r.body);
    assert!(
        r.cookie("rs_auth_session").is_none(),
        "the browser keeps its cookie so it can retry"
    );
    assert_eq!(
        verify_status(&app, &session).await,
        StatusCode::FOUND,
        "the session is already refused in memory"
    );

    let page = logout_page(&app, &session).await;
    assert_eq!(
        page.status,
        StatusCode::OK,
        "the confirm page is still offered while the sign-out is unsaved"
    );
    assert!(page.body.contains("aaron"));
    let r = post_logout(&app, &session, &page).await;
    assert_eq!(
        r.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a repeated sign-out must not report success while nothing is saved"
    );

    let other = sign_in(&app, "guest", "guest pass").await;
    let other_page = logout_page(&app, &other).await;
    assert_eq!(
        post_logout(&app, &other, &other_page).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );

    std::fs::create_dir_all(&data).unwrap();
    let r = post_logout(&app, &session, &r).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(r.location(), "/login");
    assert_eq!(r.cookie("rs_auth_session").as_deref(), Some(""));
    let saved = std::fs::read_to_string(&file).unwrap();
    assert_eq!(saved.lines().count(), 2, "both pending sign-outs: {saved}");

    let page = logout_page(&app, &session).await;
    assert_eq!(
        page.status,
        StatusCode::SEE_OTHER,
        "once saved, the old cookie no longer gets a confirm page"
    );

    let restarted = app_with(&cfg);
    assert_eq!(verify_status(&restarted, &session).await, StatusCode::FOUND);
    assert_eq!(verify_status(&restarted, &other).await, StatusCode::FOUND);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn without_a_retry_a_failed_sign_out_does_not_survive_a_restart() {
    let dir = temp_dir("noretry");
    let data = dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let cfg = with_revocation_file(&data.join("revoked.txt"));
    let app = app_with(&cfg);
    let session = sign_in(&app, "aaron", "correct horse").await;
    std::fs::remove_dir_all(&data).unwrap();
    let page = logout_page(&app, &session).await;
    assert_eq!(
        post_logout(&app, &session, &page).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    std::fs::create_dir_all(&data).unwrap();
    let restarted = app_with(&cfg);
    assert_eq!(
        verify_status(&restarted, &session).await,
        StatusCode::OK,
        "this is why the failure is reported instead of hidden"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn sign_out_without_a_session_still_clears_cookies() {
    let app = app();
    let (cookie, token) = csrf(&app, PROXY).await;
    let r = send(
        &app,
        PROXY,
        post_form("/logout", &cookie, &[("csrf", &token)]),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/login");
}

#[tokio::test]
async fn duplicate_session_cookies_with_different_values_are_refused() {
    let app = app();
    let aaron = sign_in(&app, "aaron", "correct horse").await;
    let guest = sign_in(&app, "guest", "guest pass").await;

    let both = format!("{aaron}; {guest}");
    let r = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &both),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.header("remote-user").is_none());

    let planted = format!("rs_auth_session=planted; {aaron}");
    assert_eq!(verify_status(&app, &planted).await, StatusCode::BAD_REQUEST);

    let split = Request::get("/api/verify")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", "grafana.example.com")
        .header("x-forwarded-uri", "/")
        .header(header::COOKIE, &aaron)
        .header(header::COOKIE, &guest)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(&app, PROXY, split).await.status,
        StatusCode::BAD_REQUEST
    );

    let same = format!("{aaron}; {aaron}");
    assert_eq!(verify_status(&app, &same).await, StatusCode::OK);

    let r = send(&app, PROXY, get("/logged-in", &both)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "no session is picked");
}

#[tokio::test]
async fn verify_returns_the_app_cookies_without_the_session_cookie() {
    let app = app();
    let session = sign_in(&app, "aaron", "correct horse").await;
    let cookies = format!("grafana_session=g1; {session}; theme=dark");
    let r = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &cookies),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("cookie"), Some("grafana_session=g1; theme=dark"));
    assert_eq!(r.header("remote-user"), Some("aaron"));

    let r = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        r.header("cookie").is_none(),
        "no Cookie header when the session was the only cookie"
    );
}

fn login_from(client: &str, cookie: &str, user: &str, pw: &str, token: &str) -> Request<Body> {
    let mut r = post_form(
        "/login",
        cookie,
        &[("username", user), ("password", pw), ("csrf", token)],
    );
    r.headers_mut()
        .insert("x-forwarded-for", client.parse().unwrap());
    r
}

#[tokio::test]
async fn failures_for_one_username_from_many_addresses_lock_that_account() {
    let app = app_with(&with_attempts(3));
    let (cookie, token) = csrf(&app, PROXY).await;
    for n in 1..=2 {
        let r = send(
            &app,
            PROXY,
            login_from(&format!("198.51.100.{n}"), &cookie, "aaron", "nope", &token),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = send(
        &app,
        PROXY,
        login_from("198.51.100.3", &cookie, "aaron", "nope", &token),
    )
    .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.body.contains("Too many sign-in attempts"));

    let r = send(
        &app,
        PROXY,
        login_from("198.51.100.4", &cookie, "aaron", "correct horse", &token),
    )
    .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.cookie("rs_auth_session").is_none());
    assert!(r.header("retry-after").is_none());

    let r = send(
        &app,
        PROXY,
        login_from("198.51.100.5", &cookie, "guest", "guest pass", &token),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::SEE_OTHER,
        "other accounts are unaffected"
    );
}

#[tokio::test]
async fn unknown_usernames_lock_the_same_way_as_real_ones() {
    let app = app_with(&with_attempts(2));
    let (cookie, token) = csrf(&app, PROXY).await;
    let mut statuses = Vec::new();
    for n in 1..=3 {
        statuses.push(
            send(
                &app,
                PROXY,
                login_from(&format!("198.51.100.{n}"), &cookie, "nobody", "x", &token),
            )
            .await
            .status,
        );
    }
    assert_eq!(
        statuses,
        [
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS
        ]
    );
}

#[tokio::test]
async fn a_successful_sign_in_does_not_count_against_the_account() {
    let app = app_with(&with_attempts(2));
    let (cookie, token) = csrf(&app, PROXY).await;
    for n in 1..=3 {
        let r = send(
            &app,
            PROXY,
            login_from(
                &format!("198.51.100.{n}"),
                &cookie,
                "aaron",
                "correct horse",
                &token,
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
    }
}

#[tokio::test]
async fn one_address_is_never_limited_across_different_accounts() {
    let app = app_with(&with_attempts(2));
    let (cookie, token) = csrf(&app, PROXY).await;
    for n in 0..40 {
        let r = send(
            &app,
            PROXY,
            login_from("198.51.100.1", &cookie, &format!("user{n}"), "nope", &token),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "attempt {n}");
    }
}
