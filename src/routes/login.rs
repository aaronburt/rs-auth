use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use super::{redirect, render};
use crate::ratelimit::Attempt;
use crate::state::SharedState;
use crate::token::{self, Claims};
use crate::ui::{self, LoginState};
use crate::{cookie, csrf, net, password, redirect as rd};

const MAX_USERNAME_LEN: usize = 64;

#[derive(Debug, Deserialize)]
pub struct RdQuery {
    #[serde(default)]
    rd: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    rd: String,
}

fn rd_parts(state: &SharedState, rd: Option<&str>) -> (String, Option<String>) {
    match rd.and_then(|r| rd::validate_rd(&state.config, r)) {
        Some(u) => {
            let host = u.host_str().map(str::to_owned);
            (u.into(), host)
        }
        None => (String::new(), None),
    }
}

fn page(
    state: &SharedState,
    jar: CookieJar,
    status: StatusCode,
    login_state: LoginState,
    rd: Option<&str>,
    username: String,
) -> Response {
    let (jar, token) = csrf::issue(jar, !state.config.server.insecure_dev_mode);
    let (rd, host) = rd_parts(state, rd);
    let p = ui::login_page(login_state, host, rd, token, username);
    (jar, render(status, &p)).into_response()
}

pub async fn show(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<RdQuery>,
    jar: CookieJar,
) -> Response {
    if state.session_user(&jar).is_some() {
        let to = rd::target(&state.config, q.rd.as_deref());
        return redirect(StatusCode::FOUND, to.as_str());
    }
    let ip = net::client_ip(&state.config.server.trusted_proxies, peer, &headers);
    let login_state = if state.limiter.is_locked(ip) {
        LoginState::LockedOut
    } else {
        LoginState::Normal
    };
    page(
        &state,
        jar,
        StatusCode::OK,
        login_state,
        q.rd.as_deref(),
        String::new(),
    )
}

pub async fn submit(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let config = &state.config;
    let secure = !config.server.insecure_dev_mode;
    let ip = net::client_ip(&config.server.trusted_proxies, peer, &headers);
    let rd = Some(form.rd.as_str()).filter(|r| !r.is_empty());
    let raw_username = form.username.trim();
    let shown: String = raw_username.chars().take(MAX_USERNAME_LEN).collect();

    if state.limiter.is_locked(ip) {
        tracing::warn!(%ip, user = %shown, "sign-in refused: rate limit");
        return page(
            &state,
            jar,
            StatusCode::TOO_MANY_REQUESTS,
            LoginState::LockedOut,
            rd,
            String::new(),
        );
    }

    if !csrf::check(&jar, &form.csrf, secure) {
        tracing::info!(%ip, "sign-in form had a missing or stale CSRF token");
        return page(
            &state,
            jar,
            StatusCode::FORBIDDEN,
            LoginState::FormExpired,
            rd,
            shown,
        );
    }

    let (at, locked_after) = match state.limiter.try_attempt(ip) {
        Attempt::Allowed { at, locked_after } => (at, locked_after),
        Attempt::Locked => {
            tracing::warn!(%ip, user = %shown, "sign-in refused: rate limit");
            return page(
                &state,
                jar,
                StatusCode::TOO_MANY_REQUESTS,
                LoginState::LockedOut,
                rd,
                String::new(),
            );
        }
    };

    let well_formed = !raw_username.is_empty()
        && raw_username.len() <= MAX_USERNAME_LEN
        && !form.password.is_empty()
        && form.password.len() <= password::MAX_PASSWORD_LEN;
    let user = if well_formed {
        state.check_password(raw_username, form.password).await
    } else {
        None
    };

    let Some(user) = user else {
        if locked_after {
            tracing::warn!(%ip, user = %shown, "sign-in failed; IP is now rate limited");
            return page(
                &state,
                jar,
                StatusCode::TOO_MANY_REQUESTS,
                LoginState::LockedOut,
                rd,
                String::new(),
            );
        }
        tracing::warn!(%ip, user = %shown, "sign-in failed");
        return page(
            &state,
            jar,
            StatusCode::UNAUTHORIZED,
            LoginState::WrongPassword,
            rd,
            shown,
        );
    };

    state.limiter.refund(ip, at);
    let username = raw_username.to_owned();
    let now = token::now();
    let claims = Claims {
        iss: config.issuer(),
        sub: username.clone(),
        groups: user.groups.clone(),
        iat: now,
        exp: now + config.session.expiry.as_secs(),
        ver: config.session.version,
    };
    let token = match state.signer.sign(&claims) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "could not sign session token");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    tracing::info!(%ip, user = %username, "signed in");
    let to = rd::target(config, rd);
    let jar = csrf::clear(jar, secure).add(cookie::session(config, token));
    (jar, redirect(StatusCode::SEE_OTHER, to.as_str())).into_response()
}

pub async fn signed_in(State(state): State<SharedState>, jar: CookieJar) -> Response {
    let Some(s) = state.session_user(&jar) else {
        return Redirect::to("/login").into_response();
    };
    let p = ui::SignedInPage {
        css: ui::CSS,
        display_name: s.user.display_name.clone(),
        username: s.username.to_owned(),
    };
    render(StatusCode::OK, &p)
}
