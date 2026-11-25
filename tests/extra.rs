#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::*;
use rs_auth::revoke::Revocations;
use rs_auth::state::{AppState, SharedState};
use rs_auth::token::{self, Claims, TokenError, TokenSigner};
use tokio::sync::Semaphore;

fn state_with(
    config: rs_auth::Config,
    signer: Box<dyn TokenSigner>,
    revocations: Revocations,
) -> SharedState {
    Arc::new(AppState {
        totp: rs_auth::totp::Replay::default(),
        lockout: rs_auth::lockout::Lockout::new(
            config.login.max_attempts,
            config.login.window,
            &config.session.secret,
        ),
        hash_permits: Arc::new(Semaphore::new(2)),
        revocations: Arc::new(revocations),
        signer,
        config,
    })
}

fn default_state() -> SharedState {
    AppState::new(config_from(&toml(1, &["admins"], false)))
}

fn claims_for(state: &SharedState, iat: u64, exp: u64) -> Claims {
    Claims {
        iss: state.config.issuer(),
        sub: "aaron".into(),
        iat,
        exp,
        jti: token::new_jti(),
        pwh: state.fingerprint(&state.config.users["aaron"]),
        ver: 1,
    }
}

struct FailingSigner;

impl TokenSigner for FailingSigner {
    fn sign(&self, _: &Claims) -> Result<String, TokenError> {
        Err(TokenError::Sign)
    }
    fn verify(&self, _: &str) -> Result<Claims, TokenError> {
        Err(TokenError::Invalid)
    }
}

#[tokio::test]
async fn user_data_that_cannot_be_a_header_fails_closed() {
    let mut config = config_from(&toml(1, &["admins"], false));
    config.users.get_mut("aaron").unwrap().display_name = "Aaron\nInjected: yes".into();
    let app = rs_auth::router(AppState::new(config));
    let session = sign_in(&app, "aaron", "correct horse").await;
    let r = send(
        &app,
        PROXY,
        verify_req("GET", "grafana.example.com", "/", &session),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("remote-user").is_none());
    assert!(r.header("remote-name").is_none());
    assert!(r.header("injected").is_none());
}

#[tokio::test]
async fn a_signing_failure_is_a_500_with_no_cookie() {
    let config = config_from(&toml(1, &["admins"], false));
    let app = rs_auth::router(state_with(
        config,
        Box::new(FailingSigner),
        Revocations::in_memory(),
    ));
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
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(r.cookie("rs_auth_session").is_none());
    assert!(!r.body.contains("Hs256"));
}

#[tokio::test]
async fn an_expired_session_cookie_is_treated_as_signed_out() {
    let state = default_state();
    let app = rs_auth::router(state.clone());
    let now = token::now();
    let old = state
        .signer
        .sign(&claims_for(&state, now - 7200, now - 3600))
        .unwrap();
    let r = send(
        &app,
        PROXY,
        verify_req(
            "GET",
            "grafana.example.com",
            "/",
            &format!("rs_auth_session={old}"),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert!(r.header("remote-user").is_none());

    let live = state
        .signer
        .sign(&claims_for(&state, now, now + 3600))
        .unwrap();
    let r = send(
        &app,
        PROXY,
        verify_req(
            "GET",
            "grafana.example.com",
            "/",
            &format!("rs_auth_session={live}"),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn overflowing_the_revocation_list_ends_older_sessions_but_not_new_ones() {
    let config = config_from(&toml(1, &["admins"], false));
    let signer = Box::new(token::Hs256Signer::new(
        &config.session.secret,
        &config.issuer(),
    ));
    let revocations = Revocations::load_with_capacity(None, 0, 2).unwrap();
    let state = state_with(config, signer, revocations);
    let app = rs_auth::router(state.clone());
    let now = token::now();

    let old = state
        .signer
        .sign(&claims_for(&state, now - 10_000, now + 3600))
        .unwrap();
    let old_cookie = format!("rs_auth_session={old}");
    let check = |cookie: String| {
        let app = app.clone();
        async move {
            send(
                &app,
                PROXY,
                verify_req("GET", "grafana.example.com", "/", &cookie),
            )
            .await
            .status
        }
    };
    assert_eq!(check(old_cookie.clone()).await, StatusCode::OK);

    for (n, age) in [(1u32, 5_000u64), (2, 4_000), (3, 3_000)] {
        state
            .revocations
            .revoke(&format!("{n:032x}"), now - age, now + 3600, now)
            .await
            .unwrap();
    }
    assert_eq!(state.revocations.floor(), now - 5_000);
    assert_eq!(
        check(old_cookie).await,
        StatusCode::FOUND,
        "a session started before the floor is refused"
    );

    let fresh = sign_in(&app, "aaron", "correct horse").await;
    assert_eq!(
        check(fresh).await,
        StatusCode::OK,
        "a session started after the floor still works"
    );
}
