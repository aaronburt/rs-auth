#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
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
        .find(|c| c.starts_with("__Host-rs_auth_csrf="))
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

    let r = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", ""),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);

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

    for host in ["grafana.example.com", "photos.example.com"] {
        let r = send(&app, PROXY, verify_req("GET", host, "/", &session)).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.header("remote-user"), Some("aaron"));
        assert_eq!(r.header("remote-groups"), Some("admins,family"));
        assert_eq!(r.header("remote-email"), Some("aaron@example.com"));
        assert_eq!(r.header("remote-name"), Some("Aaron Example"));
    }

    let r = send(
        &app,
        PROXY,
        get("/login?rd=https%3A%2F%2Fphotos.example.com%2F", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.location(), "https://photos.example.com/");

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

    let r2 = send(&app, PROXY, post_form("/logout", &session, &[("csrf", "")])).await;
    assert_eq!(r2.status, StatusCode::FORBIDDEN);
    assert!(r2.cookie("rs_auth_session").is_none());

    let token = r.csrf_field();
    let cookies = format!(
        "{session}; __Host-rs_auth_csrf={}",
        r.cookie("__Host-rs_auth_csrf").unwrap()
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

    let replayed = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(
        replayed.status,
        StatusCode::FOUND,
        "a signed-out cookie must not work again"
    );
}

async fn sign_out(app: &axum::Router, session: &str) {
    let r = send(app, PROXY, get("/logout", session)).await;
    let cookies = format!(
        "{session}; __Host-rs_auth_csrf={}",
        r.cookie("__Host-rs_auth_csrf").unwrap()
    );
    let r = send(
        app,
        PROXY,
        post_form("/logout", &cookies, &[("csrf", &r.csrf_field())]),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn signing_out_ends_only_that_session() {
    let app = app();
    let laptop = sign_in(&app, "aaron", "correct horse").await;
    let phone = sign_in(&app, "aaron", "correct horse").await;
    sign_out(&app, &laptop).await;
    let r = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &laptop),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
    let r = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &phone),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn password_change_ends_old_sessions() {
    let old = app_with(&toml(1, &["admins"], false));
    let session = sign_in(&old, "aaron", "correct horse").await;
    let changed = toml(1, &["admins"], false).replace(aaron_hash(), &quick_hash("correct horse"));
    let new = app_with(&changed);
    let r = send(
        &new,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
}

#[tokio::test]
async fn sign_out_survives_a_restart_with_revocation_file() {
    let dir = std::env::temp_dir().join(format!("rs-auth-it-{}", rs_auth::token::new_jti()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("revoked.txt");
    let cfg = toml(1, &["admins"], false).replace(
        "expiry = \"12h\"\n",
        &format!(
            "expiry = \"12h\"\nrevocation_file = {:?}\n",
            file.display().to_string()
        ),
    );
    assert!(cfg.contains("revocation_file"));
    let first = app_with(&cfg);
    let session = sign_in(&first, "aaron", "correct horse").await;
    sign_out(&first, &session).await;
    assert!(std::fs::read_to_string(&file).unwrap().contains(' '));

    let restarted = app_with(&cfg);
    let r = send(
        &restarted,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
    std::fs::remove_dir_all(&dir).unwrap();
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

    let r = attempt("correct horse", "198.51.100.1").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.cookie("rs_auth_session").is_none());

    for page in [&locked, &r] {
        assert!(page.body.contains(r#"class="alert error" role="alert""#));
        assert!(page.body.contains("Too many sign-in attempts"));
        assert!(page.body.contains("<fieldset disabled>"));
        assert!(page.header("retry-after").is_none());
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

    let mut req = get("/login", "");
    req.headers_mut()
        .insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
    let r = send(&app, PROXY, req).await;
    assert!(r.body.contains("Too many sign-in attempts"));

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
    let old = app_with(&toml(1, &["admins"], false));
    let session = sign_in(&old, "aaron", "correct horse").await;

    let new = app_with(&toml(1, &["viewers"], false));
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
    assert_eq!(r.header("remote-email"), Some(""));

    let without_guest = app_with(&toml(1, &["admins"], false));
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
    let v1 = app_with(&toml(1, &["admins"], false));
    let session = sign_in(&v1, "aaron", "correct horse").await;
    let v2 = app_with(&toml(2, &["admins"], false));
    let r = send(
        &v2,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
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

    let other =
        toml(1, &["admins"], false).replace(SECRET, "another-secret-another-secret-another!!");
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

async fn attempt(app: &axum::Router, cookie: &str, token: &str, user: &str, pw: &str) -> Resp {
    send(
        app,
        PROXY,
        post_form(
            "/login",
            cookie,
            &[("username", user), ("password", pw), ("csrf", token)],
        ),
    )
    .await
}

#[tokio::test]
async fn signing_in_does_not_reset_failed_attempts() {
    let app = app();
    let (cookie, token) = csrf(&app, PROXY).await;
    for _ in 0..4 {
        let r = attempt(&app, &cookie, &token, "aaron", "guess").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = attempt(&app, &cookie, &token, "guest", "guest pass").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "own account still works");
    let (cookie, token) = csrf(&app, PROXY).await;
    let r = attempt(&app, &cookie, &token, "aaron", "guess").await;
    assert_eq!(
        r.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the fifth failure must lock, even after a successful sign-in"
    );
}

#[tokio::test]
async fn successful_sign_ins_do_not_count_towards_the_limit() {
    let app = app();
    for _ in 0..8 {
        sign_in(&app, "aaron", "correct horse").await;
    }
}

#[tokio::test]
async fn concurrent_burst_gets_no_more_than_the_limit() {
    let app = app();
    let (cookie, token) = csrf(&app, PROXY).await;
    let mut tasks = Vec::new();
    for i in 0..20 {
        let (app, cookie, token) = (app.clone(), cookie.clone(), token.clone());
        tasks.push(tokio::spawn(async move {
            attempt(&app, &cookie, &token, "aaron", &format!("guess-{i}"))
                .await
                .status
        }));
    }
    let mut unauthorized = 0;
    let mut limited = 0;
    for t in tasks {
        match t.await.unwrap() {
            StatusCode::UNAUTHORIZED => unauthorized += 1,
            StatusCode::TOO_MANY_REQUESTS => limited += 1,
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!(unauthorized + limited, 20);
    assert!(unauthorized <= 4, "{unauthorized} guesses got a plain 401");
    assert!(limited >= 16);
}

#[tokio::test]
async fn overlong_usernames_are_rejected_not_truncated() {
    let y = toml(1, &["admins"], false)
        .replace("[users.aaron]\n", &format!("[users.{}]\n", "a".repeat(64)));
    let app = app_with(&y);
    let (cookie, token) = csrf(&app, PROXY).await;
    let long = "a".repeat(65);
    let r = attempt(&app, &cookie, &token, &long, "correct horse").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let exact = "a".repeat(64);
    let r = attempt(&app, &cookie, &token, &exact, "correct horse").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn csrf_cookie_is_host_only_and_rotated_after_sign_in() {
    let app = app();
    let r = send(&app, PROXY, get("/login", "")).await;
    let set = r
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-rs_auth_csrf="))
        .unwrap();
    assert!(set.contains("Secure") && set.contains("Path=/") && !set.contains("Domain"));

    let (cookie, token) = csrf(&app, PROXY).await;
    let r = attempt(&app, &cookie, &token, "aaron", "correct horse").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let cleared = r
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-rs_auth_csrf="))
        .expect("csrf cookie cleared");
    assert!(cleared.contains("Max-Age=0"));
}

#[tokio::test]
async fn planted_unprefixed_csrf_cookie_is_not_accepted() {
    let app = app();
    let planted = "ab".repeat(32);
    let r = attempt(
        &app,
        &format!("rs_auth_csrf={planted}"),
        &planted,
        "aaron",
        "correct horse",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn hash_permit_is_held_until_argon2_finishes() {
    let heavy = rs_auth::password::hash("slow password").unwrap();
    let y = toml(1, &["admins"], false).replace(aaron_hash(), &heavy);
    let state = rs_auth::AppState::new(config_from(&y));
    let total = state.hash_permits.available_permits();
    let s2 = state.clone();
    let task = tokio::spawn(async move { s2.check_password("aaron", "x".into()).await.is_some() });
    let mut waited = 0;
    while state.hash_permits.available_permits() == total {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        waited += 1;
        assert!(waited < 2000, "hash never started");
    }
    task.abort();
    let _ = task.await;
    assert_eq!(
        state.hash_permits.available_permits(),
        total - 1,
        "a dropped request must not free its permit while Argon2 is still running"
    );
    let mut waited = 0;
    while state.hash_permits.available_permits() < total {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        waited += 1;
        assert!(waited < 2000, "permit never came back");
    }
    assert!(total <= rs_auth::state::MAX_CONCURRENT_HASHES);
}
