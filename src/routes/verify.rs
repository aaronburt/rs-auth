use std::net::SocketAddr;

use crate::cookie::CookieJar;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use super::redirect;
use crate::net;
use crate::redirect as rd;
use crate::state::SharedState;

pub async fn verify(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let config = &state.config;

    if !net::is_trusted(&config.server.trusted_proxies, peer.ip()) {
        tracing::warn!(peer = %peer.ip(), "verify called from an address outside server.trusted_proxies");
        return unauthorized();
    }

    if let Some(s) = state.session_user(&jar) {
        let groups = s.user.groups.join(",");
        let mut out = HeaderMap::new();
        let mut add =
            |name: &'static str, value: &str| match HeaderValue::from_bytes(value.as_bytes()) {
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
        return (StatusCode::OK, out).into_response();
    }

    let Some(original) = rd::original_url(&headers) else {
        tracing::warn!("verify called without X-Forwarded-Proto/Host headers");
        return unauthorized();
    };
    let back = rd::validate_rd(config, original.as_str());
    let login = rd::login_url(config, back.as_ref());

    let method = headers
        .get("x-forwarded-method")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("GET");
    let status = if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        StatusCode::FOUND
    } else {
        StatusCode::SEE_OTHER
    };
    redirect(status, login.as_str())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}
