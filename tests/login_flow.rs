//! End-to-end checks of the whole loop through the real router: verify,
//! login, cookie, verify again, logout.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use common::*;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn healthz() {
    let r = send(&app(), OUTSIDE, get("/healthz", "")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, "ok");
}

#[tokio::test]
async fn verify_without_cookie_redirects_to_login_with_rd() {
    let r = send(
        &app(),
        PROXY,
        verify_req("GET", "grafana.example.com", "/d/abc?x=1", ""),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
    let loc = url::Url::parse(r.location()).unwrap();
    assert_eq!(loc.host_str(), Some("auth.example.com"));
    assert_eq!(loc.path(), "/login");
    let rd: Vec<_> = loc
        .query_pairs()
        .filter(|(k, _)| k == "rd")
        .map(|(_, v)| v.into_owned())
        .collect();
    assert_eq!(
        rd,
        vec!["https://grafana.example.com/d/abc?x=1".to_string()]
    );
}

#[tokio::test]
async fn verify_non_get_uses_303() {
    let r = send(
        &app(),
        PROXY,
        verify_req("POST", "grafana.example.com", "/api", ""),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn verify_from_outside_trusted_proxies_is_401_even_with_a_session() {
    let app = app();
    let session = sign_in(&app, "aaron", "correct horse").await;
    let r = send(
        &app,
        OUTSIDE,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("remote-user").is_none());
}

#[tokio::test]
async fn verify_trusts_ipv6_proxy_entry() {
    let r = send(
        &app(),
        "[::1]:5000",
        verify_req("GET", "grafana.example.com", "/", ""),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
}

#[tokio::test]
async fn verify_without_forwarded_headers_fails_closed() {
    let r = send(&app(), PROXY, get("/api/verify", "")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_for_host_outside_domain_drops_rd() {
    let r = send(&app(), PROXY, verify_req("GET", "evil.net", "/", "")).await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.location(), "https://auth.example.com/login");
}

#[tokio::test]
async fn login_page_basics() {
    let r = send(
        &app(),
        PROXY,
        get("/login?rd=https%3A%2F%2Fgrafana.example.com%2F", ""),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("<h1>Sign in</h1>"));
    assert!(
        r.body
            .contains("to continue to <strong>grafana.example.com</strong>")
    );
    assert!(r.body.contains(r#"autocomplete="username""#));
    assert!(r.body.contains(r#"autocomplete="current-password""#));
    assert!(r.body.contains("<title>Sign in · rs-auth</title>"));
    assert!(r.body.contains(r#"<html lang="en">"#));
    assert!(r.body.contains("prefers-color-scheme:dark"));
    assert!(!r.body.contains("role=\"alert\""));
    assert!(r.body.len() < 10 * 1024, "page is {} bytes", r.body.len());

    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
    let csrf = r
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("rs_auth_csrf="))
        .unwrap();
    assert!(
        csrf.contains("HttpOnly") && csrf.contains("Secure") && csrf.contains("SameSite=Strict")
    );
}

#[tokio::test]
async fn csp_hashes_match_the_inline_style_and_script() {
    let r = send(&app(), PROXY, get("/login", "")).await;
    let csp = r.header("content-security-policy").unwrap().to_owned();
    assert!(csp.starts_with("default-src 'none'"));
    for (open, close) in [("<style>", "</style>"), ("<script>", "</script>")] {
        let a = r.body.find(open).unwrap() + open.len();
        let b = r.body[a..].find(close).unwrap() + a;
        let hash = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(&r.body.as_bytes()[a..b]));
        assert!(
            csp.contains(&format!("'sha256-{hash}'")),
            "{open} hash missing from CSP"
        );
    }
    assert!(
        !r.body.contains("style=\""),
        "inline style attributes would be blocked by CSP"
    );
}

#[tokio::test]
async fn full_loop() {
    let app = app();

    // 1. Not signed in: verify sends the browser to login.
    let r = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", ""),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);

    // 2. Sign in with an rd.
    let (cookie, token) = csrf(&app, PROXY).await;
    let r = send(
        &app,
        PROXY,
        post_form(
            "/login",
            &cookie,
            &[
                ("username", "aaron"),
                ("password", "correct horse"),
                ("csrf", &token),
                ("rd", "https://grafana.example.com/d/abc"),
            ],
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "https://grafana.example.com/d/abc");
    let set = r
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("rs_auth_session="))
        .unwrap();
    for attr in [
        "Domain=example.com",
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Max-Age=43200",
    ] {
        assert!(set.contains(attr), "{attr} missing from {set}");
    }
    let session = format!("rs_auth_session={}", r.cookie("rs_auth_session").unwrap());

    // 3. Two different apps go straight through.
    for host in ["grafana.example.com", "photos.example.com"] {
        let r = send(&app, PROXY, verify_req("GET", host, "/", &session)).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.header("remote-user"), Some("aaron"));
        assert_eq!(r.header("remote-groups"), Some("admins,family"));
        assert_eq!(r.header("remote-email"), Some("aaron@example.com"));
        assert_eq!(r.header("remote-name"), Some("Aaron Example"));
    }

    // 4. The login page skips itself when already signed in.
    let r = send(
        &app,
        PROXY,
        get("/login?rd=https%3A%2F%2Fphotos.example.com%2F", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.location(), "https://photos.example.com/");

    // 5. GET /logout only asks.
    let r = send(&app, PROXY, get("/logout", &session)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Sign out?"));
    assert!(r.body.contains("<strong>aaron</strong>"));
    let still = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(still.status, StatusCode::OK);

    // 6. POST /logout without a token is refused.
    let r2 = send(&app, PROXY, post_form("/logout", &session, &[("csrf", "")])).await;
    assert_eq!(r2.status, StatusCode::FORBIDDEN);
    assert!(r2.cookie("rs_auth_session").is_none());

    // 7. POST /logout with the token clears the cookie.
    let token = r.csrf_field();
    let cookies = format!(
        "{session}; rs_auth_csrf={}",
        r.cookie("rs_auth_csrf").unwrap()
    );
    let r = send(
        &app,
        PROXY,
        post_form("/logout", &cookies, &[("csrf", &token)]),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/login");
    let cleared = r
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("rs_auth_session="))
        .unwrap();
    assert!(cleared.contains("Max-Age=0") && cleared.contains("Domain=example.com"));
}

#[tokio::test]
async fn sign_in_without_rd_lands_on_signed_in_page() {
    let app = app();
    let (cookie, token) = csrf(&app, PROXY).await;
    let r = send(
        &app,
        PROXY,
        post_form(
            "/login",
            &cookie,
            &[
                ("username", "aaron"),
                ("password", "correct horse"),
                ("csrf", &token),
            ],
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "https://auth.example.com/logged-in");
    let session = format!("rs_auth_session={}", r.cookie("rs_auth_session").unwrap());
    let r = send(&app, PROXY, get("/logged-in", &session)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Aaron Example"));
    let r = send(&app, PROXY, get("/logged-in", "")).await;
    assert_eq!(r.location(), "/login");
}

#[tokio::test]
async fn open_redirects_are_refused() {
    let app = app();
    for bad in [
        "https://evil.net/",
        "http://grafana.example.com/",
        "https://example.com.evil.net/",
        "//evil.net/",
        "javascript:alert(1)",
        "https://user:pw@grafana.example.com/",
    ] {
        let (cookie, token) = csrf(&app, PROXY).await;
        let r = send(
            &app,
            PROXY,
            post_form(
                "/login",
                &cookie,
                &[
                    ("username", "aaron"),
                    ("password", "correct horse"),
                    ("csrf", &token),
                    ("rd", bad),
                ],
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
        assert_eq!(
            r.location(),
            "https://auth.example.com/logged-in",
            "rd {bad:?} was followed"
        );
    }
}

#[tokio::test]
async fn wrong_password_is_amber_and_generic() {
    let app = app();
    let (cookie, token) = csrf(&app, PROXY).await;
    let r = send(
        &app,
        PROXY,
        post_form(
            "/login",
            &cookie,
            &[
                ("username", "aaron"),
                ("password", "nope"),
                ("csrf", &token),
            ],
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.body.contains(r#"class="alert warn" role="alert""#));
    assert!(r.body.contains("Invalid username or password."));
    assert!(r.body.contains(r#"aria-invalid="true""#));
    assert!(r.body.contains(r#"value="aaron""#), "username is kept");
    assert!(r.cookie("rs_auth_session").is_none());

    // An unknown user gets exactly the same page.
    let r2 = send(
        &app,
        PROXY,
        post_form(
            "/login",
            &cookie,
            &[
                ("username", "nobody"),
                ("password", "nope"),
                ("csrf", &token),
            ],
        ),
    )
    .await;
    assert_eq!(r2.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.body.replace("aaron", "X"),
        r2.body.replace("nobody", "X"),
        "unknown users must look the same as wrong passwords"
    );
}

#[tokio::test]
async fn missing_csrf_is_refused_without_counting_an_attempt() {
    let app = app();
    for _ in 0..10 {
        let r = send(
            &app,
            PROXY,
            post_form(
                "/login",
                "",
                &[
                    ("username", "aaron"),
                    ("password", "correct horse"),
                    ("csrf", ""),
                ],
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert!(r.body.contains("This sign-in form expired"));
        assert!(r.cookie("rs_auth_session").is_none());
    }
    sign_in(&app, "aaron", "correct horse").await;
}

#[tokio::test]
async fn rate_limit_locks_out_per_ip_and_says_nothing_about_duration() {
    let app = app();
    let (cookie, token) = csrf(&app, PROXY).await;
    let attempt = |pw: &'static str, ip: &'static str| {
        let app = app.clone();
        let cookie = cookie.clone();
        let token = token.clone();
        async move {
            let mut req = post_form(
                "/login",
                &cookie,
                &[("username", "aaron"), ("password", pw), ("csrf", &token)],
            );
            req.headers_mut()
                .insert("x-forwarded-for", ip.parse().unwrap());
            send(&app, PROXY, req).await
        }
    };

    for _ in 0..4 {
        assert_eq!(
            attempt("bad", "198.51.100.1").await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    let locked = attempt("bad", "198.51.100.1").await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);

    // Even the right password is refused while locked.
    let r = attempt("correct horse", "198.51.100.1").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.cookie("rs_auth_session").is_none());

    for page in [&locked, &r] {
        assert!(page.body.contains(r#"class="alert error" role="alert""#));
        assert!(page.body.contains("Too many sign-in attempts"));
        assert!(page.body.contains("<fieldset disabled>"));
        assert!(page.header("retry-after").is_none());
        // Only the visible markup, not the stylesheet.
        let lower = page.body[page.body.find("</style>").unwrap()..].to_lowercase();
        for leak in [
            "minute",
            "second",
            "remaining",
            "try again in",
            "attempts left",
        ] {
            assert!(!lower.contains(leak), "locked page mentions {leak:?}");
        }
    }

    // GET /login from that IP shows the locked state too.
    let mut req = get("/login", "");
    req.headers_mut()
        .insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
    let r = send(&app, PROXY, req).await;
    assert!(r.body.contains("Too many sign-in attempts"));

    // Another client behind the same proxy is unaffected.
    let r = attempt("correct horse", "198.51.100.2").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn spoofed_forwarded_for_from_untrusted_peer_is_ignored() {
    let app = app();
    let (cookie, token) = csrf(&app, OUTSIDE).await;
    for i in 0..5 {
        let mut req = post_form(
            "/login",
            &cookie,
            &[("username", "aaron"), ("password", "bad"), ("csrf", &token)],
        );
        // A new fake address every time must not dodge the limit.
        req.headers_mut()
            .insert("x-forwarded-for", format!("10.9.9.{i}").parse().unwrap());
        send(&app, OUTSIDE, req).await;
    }
    let r = send(
        &app,
        OUTSIDE,
        post_form(
            "/login",
            &cookie,
            &[
                ("username", "aaron"),
                ("password", "correct horse"),
                ("csrf", &token),
            ],
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn groups_are_read_live_from_config() {
    let old = app_with(&yaml(1, "[admins]", false));
    let session = sign_in(&old, "aaron", "correct horse").await;

    // Same secret, groups edited and the server restarted.
    let new = app_with(&yaml(1, "[viewers]", false));
    let r = send(
        &new,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("remote-groups"), Some("viewers"));
}

#[tokio::test]
async fn removed_user_is_rejected() {
    let both = app();
    let session = sign_in(&both, "guest", "guest pass").await;
    let r = send(
        &both,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("remote-name"), Some("Guest"));
    assert!(r.header("remote-email").is_none());

    let without_guest = app_with(&yaml(1, "[admins]", false));
    let r = send(
        &without_guest,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
}

#[tokio::test]
async fn bumping_session_version_logs_everyone_out() {
    let v1 = app_with(&yaml(1, "[admins]", false));
    let session = sign_in(&v1, "aaron", "correct horse").await;
    let v2 = app_with(&yaml(2, "[admins]", false));
    let r = send(
        &v2,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
    // And a fresh sign-in on v2 works.
    let s2 = sign_in(&v2, "aaron", "correct horse").await;
    let r = send(
        &v2,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &s2),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn tampered_and_foreign_cookies_are_rejected() {
    let app = app();
    let session = sign_in(&app, "aaron", "correct horse").await;
    // Flip a character in the middle of the signature.
    let mut chars: Vec<char> = session.chars().collect();
    let i = chars.len() - 10;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    for c in [
        tampered.as_str(),
        "rs_auth_session=",
        "rs_auth_session=garbage",
        "other=1",
    ] {
        let r = send(
            &app,
            PROXY,
            verify_req("GET", "grafana.example.com", "/", c),
        )
        .await;
        assert_eq!(r.status, StatusCode::FOUND, "cookie {c:?} was accepted");
    }

    // A token signed with a different secret.
    let other =
        yaml(1, "[admins]", false).replace(SECRET, "another-secret-another-secret-another!!");
    let other_session = sign_in(&app_with(&other), "aaron", "correct horse").await;
    let r = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &other_session),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
}

#[tokio::test]
async fn logout_without_session_goes_to_login() {
    let r = send(&app(), PROXY, get("/logout", "")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/login");
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let big = "a".repeat(64 * 1024);
    let r = send(
        &app(),
        PROXY,
        post_form(
            "/login",
            "",
            &[("username", "aaron"), ("password", &big), ("csrf", "")],
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn html_in_inputs_is_escaped() {
    let app = app();
    let (cookie, token) = csrf(&app, PROXY).await;
    let r = send(
        &app,
        PROXY,
        post_form(
            "/login",
            &cookie,
            &[
                ("username", "<script>x</script>"),
                ("password", "x"),
                ("csrf", &token),
            ],
        ),
    )
    .await;
    assert!(!r.body.contains("<script>x</script>"));
    assert!(r.body.contains("&#60;script&#62;") || r.body.contains("&lt;script&gt;"));
}
