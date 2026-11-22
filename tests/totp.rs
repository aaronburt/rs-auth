#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use common::*;
use rs_auth::state::SharedState;
use rs_auth::totp::{self, code_at, step_at};
use rs_auth::{AppState, token};

const SECRET_TEXT: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SECRET: &[u8] = b"12345678901234567890";

fn totp_toml() -> String {
    let plain = format!("password = '{}'", aaron_hash());
    toml(1, &["admins", "family"], true)
        .replace(&plain, &format!("{plain}\ntotp_secret = \"{SECRET_TEXT}\""))
}

fn code(step_offset: i64) -> String {
    let step = step_at(token::now())
        .checked_add_signed(step_offset)
        .unwrap();
    format!("{:06}", code_at(SECRET, step))
}

fn built() -> (Router, SharedState) {
    let state = AppState::new(config_from(&totp_toml()));
    (rs_auth::router(Arc::clone(&state)), state)
}

static CLIENT: AtomicU32 = AtomicU32::new(1);

async fn login(app: &Router, user: &str, pw: &str, totp: &str) -> Resp {
    let n = CLIENT.fetch_add(1, Ordering::Relaxed);
    login_from(
        app,
        &format!("198.51.{}.{}", n / 250, n % 250 + 1),
        user,
        pw,
        totp,
    )
    .await
}

async fn login_from(app: &Router, client: &str, user: &str, pw: &str, totp: &str) -> Resp {
    let (cookie, token) = csrf(app, PROXY).await;
    let mut req = post_form(
        "/login",
        &cookie,
        &[
            ("username", user),
            ("password", pw),
            ("totp", totp),
            ("csrf", &token),
        ],
    );
    req.headers_mut()
        .insert("x-forwarded-for", client.parse().unwrap());
    send(app, PROXY, req).await
}

#[tokio::test]
async fn the_code_field_appears_only_when_a_user_has_a_secret() {
    let r = send(&app(), PROXY, get("/login", "")).await;
    assert!(!r.body.contains(r#"name="totp""#));
    assert!(
        r.body.contains("Invalid username or password.")
            || !r.body.contains("Invalid username, password or code.")
    );

    let (with, _) = built();
    let r = send(&with, PROXY, get("/login", "")).await;
    assert!(r.body.contains(r#"name="totp""#));
    assert!(r.body.contains(r#"autocomplete="one-time-code""#));
    assert!(r.body.contains("Leave empty if your account has no code."));
}

#[tokio::test]
async fn failures_say_the_same_thing_whichever_check_failed() {
    let (app, _) = built();
    let good = code(0);
    let bodies = [
        login(&app, "aaron", "correct horse", "").await,
        login(&app, "aaron", "correct horse", "000000x").await,
        login(&app, "aaron", "wrong", &code(0)).await,
        login(&app, "nobody", "correct horse", &good).await,
        login(&app, "aaron", "", &good).await,
    ];
    let first = &bodies[0];
    for r in &bodies {
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(r.body.contains("Invalid username, password or code."));
        assert!(r.cookie("rs_auth_session").is_none());
        assert!(!r.body.contains("attempt"));
        assert!(r.header("retry-after").is_none());
        let strip = |b: &str| {
            let a = b.find(r#"name="csrf" value=""#).unwrap();
            let rest = &b[a + 19 + 64..];
            rest.replace("value=\"nobody\"", "value=\"aaron\"")
        };
        assert_eq!(strip(&r.body).len(), strip(&first.body).len());
    }
}

#[tokio::test]
async fn password_and_code_together_sign_in() {
    let (app, _) = built();
    let r = login(&app, "aaron", "correct horse", &code(0)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert!(r.cookie("rs_auth_session").is_some());
}

#[tokio::test]
async fn a_code_with_spaces_and_the_neighbouring_steps_are_accepted() {
    let (app, _) = built();
    let spaced = {
        let c = code(0);
        format!(" {} {} ", &c[..3], &c[3..])
    };
    assert_eq!(
        login(&app, "aaron", "correct horse", &spaced).await.status,
        StatusCode::SEE_OTHER
    );
    let (app, _) = built();
    assert_eq!(
        login(&app, "aaron", "correct horse", &code(-1))
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    let (app, _) = built();
    assert_eq!(
        login(&app, "aaron", "correct horse", &code(1)).await.status,
        StatusCode::SEE_OTHER
    );
    let (app, _) = built();
    for off in [-2, 2] {
        assert_eq!(
            login(&app, "aaron", "correct horse", &code(off))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn a_used_code_cannot_sign_in_again() {
    let (app, _) = built();
    let c = code(0);
    assert_eq!(
        login(&app, "aaron", "correct horse", &c).await.status,
        StatusCode::SEE_OTHER
    );
    let again = login(&app, "aaron", "correct horse", &c).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert!(again.cookie("rs_auth_session").is_none());
    let earlier = login(&app, "aaron", "correct horse", &code(-1)).await;
    assert_eq!(earlier.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_typo_in_the_password_does_not_burn_the_code() {
    let (app, _) = built();
    let c = code(0);
    assert_eq!(
        login(&app, "aaron", "correct hors", &c).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&app, "aaron", "correct horse", &c).await.status,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn users_without_a_secret_ignore_the_code_field() {
    let (app, _) = built();
    for c in ["", "123456", "garbage"] {
        let r = login(&app, "guest", "guest pass", c).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "code {c:?}");
    }
    let r = login(&app, "guest", "wrong", "").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

async fn finishes_fast(app: &Router, user: &str, pw: &str, c: &str) -> Resp {
    tokio::time::timeout(Duration::from_secs(2), login(app, user, pw, c))
        .await
        .expect("this failure should not wait for Argon2")
}

#[tokio::test]
async fn cheap_failures_never_reach_argon2() {
    let (app, state) = built();
    let hold = state.hash_permits.available_permits();
    let _held = Arc::clone(&state.hash_permits)
        .acquire_many_owned(u32::try_from(hold).unwrap())
        .await
        .unwrap();
    let slots = state.login_slots.available_permits();

    for (user, pw, c) in [
        ("nobody", "correct horse", code(0)),
        ("aaron", "correct horse", String::new()),
        ("aaron", "correct horse", "123456".to_string()),
        ("aaron", "correct horse", "12345".to_string()),
        ("", "correct horse", code(0)),
        ("aaron", "", code(0)),
    ] {
        let r = finishes_fast(&app, user, pw, &c).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{user} {c}");
    }
    assert_eq!(state.login_slots.available_permits(), slots);
    assert_eq!(state.hash_permits.available_permits(), 0);
}

#[tokio::test]
async fn a_right_code_does_go_on_to_the_password_check() {
    let (app, state) = built();
    let hold = state.hash_permits.available_permits();
    let held = Arc::clone(&state.hash_permits)
        .acquire_many_owned(u32::try_from(hold).unwrap())
        .await
        .unwrap();
    let c = code(0);
    let pending = tokio::time::timeout(
        Duration::from_millis(300),
        login(&app, "aaron", "correct horse", &c),
    )
    .await;
    assert!(pending.is_err(), "it should be waiting for a hash slot");
    drop(held);
}

#[tokio::test]
async fn a_busy_server_does_not_burn_the_code_or_an_attempt() {
    let (app, state) = built();
    let slots = state.login_slots.available_permits();
    let held = Arc::clone(&state.login_slots)
        .try_acquire_many_owned(u32::try_from(slots).unwrap())
        .unwrap();
    let c = code(0);
    let r = login_from(&app, "198.51.100.77", "aaron", "correct horse", &c).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(r.body.contains("Sign-in is busy"));
    drop(held);
    let r = login_from(&app, "198.51.100.77", "aaron", "correct horse", &c).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn busy_does_not_apply_to_cheap_failures() {
    let (app, state) = built();
    let slots = state.login_slots.available_permits();
    let _held = Arc::clone(&state.login_slots)
        .try_acquire_many_owned(u32::try_from(slots).unwrap())
        .unwrap();
    let r = login(&app, "aaron", "correct horse", "").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_codes_use_up_the_clients_attempts() {
    let (app, _) = built();
    for _ in 0..4 {
        let r = login_from(&app, "198.51.100.5", "aaron", "correct horse", "000000").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = login_from(&app, "198.51.100.5", "aaron", "correct horse", "000000").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let r = login_from(&app, "198.51.100.5", "aaron", "correct horse", &code(0)).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.cookie("rs_auth_session").is_none());
}

#[tokio::test]
async fn a_new_or_changed_secret_ends_existing_sessions() {
    let with_text = totp_toml();
    let plain_text = with_text.replace(&format!("\ntotp_secret = \"{SECRET_TEXT}\""), "");
    let other_text = with_text.replace(SECRET_TEXT, "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U");
    let plain = AppState::new(config_from(&plain_text));
    let with = AppState::new(config_from(&with_text));
    let other = AppState::new(config_from(&other_text));
    let aaron = |s: &SharedState| s.fingerprint(&s.config.users["aaron"]);
    assert_ne!(aaron(&plain), aaron(&with));
    assert_ne!(aaron(&with), aaron(&other));
    assert_eq!(aaron(&with), aaron(&AppState::new(config_from(&with_text))));
    let guest = |s: &SharedState| s.fingerprint(&s.config.users["guest"]);
    assert_eq!(guest(&plain), guest(&with));
}

async fn verify_status(app: &Router, cookie: &str) -> StatusCode {
    send(
        app,
        PROXY,
        verify_req("GET", "photos.example.com", "/", cookie),
    )
    .await
    .status
}

#[tokio::test]
async fn a_cookie_from_before_the_secret_was_added_is_refused() {
    let before = AppState::new(config_from(&toml(1, &["admins", "family"], true)));
    let now = token::now();
    let claims = token::Claims {
        iss: before.config.issuer(),
        sub: "aaron".into(),
        iat: now,
        exp: now + 3600,
        jti: token::new_jti(),
        pwh: before.fingerprint(&before.config.users["aaron"]),
        ver: 1,
    };
    let cookie = format!("rs_auth_session={}", before.signer.sign(&claims).unwrap());
    assert_eq!(
        verify_status(&rs_auth::router(before), &cookie).await,
        StatusCode::OK
    );
    let (after, _) = built();
    assert_eq!(verify_status(&after, &cookie).await, StatusCode::FOUND);
}

#[test]
fn config_checks_the_secret() {
    let parse = |text: &str| rs_auth::Config::from_toml(text, &NoEnv);
    assert!(parse(&totp_toml()).is_ok());
    let bad = totp_toml().replace(SECRET_TEXT, "NOT-BASE32-1!");
    let e = parse(&bad).unwrap_err().to_string();
    assert!(e.contains("users.aaron.totp_secret"), "{e}");
    assert!(e.contains("not a base32 character"), "{e}");
    let short = totp_toml().replace(SECRET_TEXT, "MZXW6YTBOI");
    let e = parse(&short).unwrap_err().to_string();
    assert!(e.contains("users.aaron.totp_secret"), "{e}");
    assert!(e.contains("at least"), "{e}");
    let loaded = parse(&totp_toml()).unwrap().config;
    assert!(loaded.totp_enabled());
    assert!(!config_from(&toml(1, &["admins"], true)).totp_enabled());
    let shown = format!("{:?}", loaded.users["aaron"]);
    assert!(shown.contains("<redacted>"));
    assert!(!shown.contains(SECRET_TEXT));
    assert!(!shown.contains("12345678901234567890"));
}

#[test]
fn totp_secret_command_makes_a_usable_secret() {
    let made = rs_auth::commands::new_totp_secret(None);
    assert_eq!(
        totp::decode_secret(&made.secret).unwrap().len(),
        totp::SECRET_BYTES
    );
    assert!(made.uri.is_none());
    let made = rs_auth::commands::new_totp_secret(Some("aaron"));
    let uri = made.uri.unwrap();
    assert!(uri.starts_with("otpauth://totp/rs-auth:aaron?secret="));
    assert!(uri.contains(&made.secret));
    assert_ne!(made.secret, rs_auth::commands::new_totp_secret(None).secret);
}
