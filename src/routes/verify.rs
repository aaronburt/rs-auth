use std::net::SocketAddr;

use crate::cookie::CookieJar;
use axum::extract::{ConnectInfo, State};
use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use super::{redirect, render};
use crate::redirect as rd;
use crate::state::{AppState, SharedState};
use crate::{access, cookie, net, ui};

#[derive(Clone, Copy)]
enum Style {
    Redirect,
    Status,
}

pub async fn verify(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    check(&state, peer, &headers, &jar, Style::Redirect)
}

pub async fn verify_nginx(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    check(&state, peer, &headers, &jar, Style::Status)
}

fn check(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
    jar: &CookieJar,
    style: Style,
) -> Response {
    let config = &state.config;

    if !net::is_trusted(&config.server.trusted_proxies, peer.ip()) {
        tracing::warn!(peer = %peer.ip(), "verify called from an address outside server.trusted_proxies");
        return unauthorized();
    }

    if jar.is_ambiguous(&config.session.cookie_name) {
        tracing::warn!("verify refused: more than one session cookie with different values");
        return (StatusCode::BAD_REQUEST, "ambiguous session cookie").into_response();
    }

    let Some(original) = rd::original_url(headers) else {
        tracing::warn!("verify called without X-Forwarded-Proto/Host headers");
        return unauthorized();
    };
    let host = original.host_str().unwrap_or_default();
    let session = state.session_user(jar);

    let Some(rule) = config.access.groups_for(host) else {
        tracing::info!(%host, "no access rule for this host");
        return forbidden(state, host, session.as_ref().map(|s| s.username));
    };

    let Some(s) = session else {
        let back = rd::validate_rd(config, original.as_str());
        let login = rd::login_url(config, back.as_ref());
        let status = match style {
            Style::Status => StatusCode::UNAUTHORIZED,
            Style::Redirect => {
                let method = headers
                    .get("x-forwarded-method")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("GET");
                if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
                    StatusCode::FOUND
                } else {
                    StatusCode::SEE_OTHER
                }
            }
        };
        return redirect(status, login.as_str());
    };

    if !access::allows(rule, &s.user.groups) {
        tracing::info!(user = %s.username, %host, "user is not in a group allowed on this host");
        return forbidden(state, host, Some(s.username));
    }

    let groups = s.user.groups.join(",");
    let mut out = HeaderMap::new();
    let mut add = |name: &'static str, value: &str| match HeaderValue::from_bytes(value.as_bytes())
    {
        Ok(v) => {
            out.insert(HeaderName::from_static(name), v);
            true
        }
        Err(_) => false,
    };
    let ok = add("remote-user", s.username)
        && add("remote-groups", &groups)
        && add("remote-name", &s.user.display_name)
        && add("remote-email", s.user.email.as_deref().unwrap_or(""));
    if !ok {
        tracing::error!(user = %s.username, "user data cannot be sent as headers");
        return unauthorized();
    }
    let rest = cookie::without(
        headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok()),
        &config.session.cookie_name,
    );
    if let Some(v) = rest.and_then(|r| HeaderValue::from_str(&r).ok()) {
        out.insert(COOKIE, v);
    }
    (StatusCode::OK, out).into_response()
}

fn forbidden(state: &AppState, host: &str, username: Option<&str>) -> Response {
    let page = ui::ForbiddenPage {
        css: ui::CSS,
        host: host.to_owned(),
        username: username.map(str::to_owned),
        logout_url: state
            .config
            .server
            .portal_url
            .join("logout")
            .expect("static path")
            .to_string(),
    };
    render(StatusCode::FORBIDDEN, &page)
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}
