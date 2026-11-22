//! HTTP routes.

mod health;
mod login;
mod logout;
mod verify;

use std::time::Duration;

use askama::Template;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::state::SharedState;
use crate::ui;

/// Largest request body accepted. Login and logout forms are tiny.
const BODY_LIMIT: usize = 16 * 1024;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/login") }))
        .route("/healthz", get(health::healthz))
        .route("/api/verify", get(verify::verify).head(verify::verify))
        .route("/login", get(login::show).post(login::submit))
        .route("/logout", get(logout::show).post(logout::submit))
        .route("/logged-in", get(login::signed_in))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::map_response(security_headers))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k, v: &str| {
        if !h.contains_key(&k) {
            h.insert(k, HeaderValue::from_str(v).expect("static header"));
        }
    };
    set(h, header::CONTENT_SECURITY_POLICY, ui::CSP.as_str());
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::CACHE_CONTROL, "no-store");
    set(
        h,
        header::HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    res
}

/// Render a template, or answer 500 if that somehow fails.
fn render(status: StatusCode, t: &impl Template) -> Response {
    match t.render() {
        Ok(body) => (status, Html(body)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// A redirect with the given status code (302, 303).
fn redirect(status: StatusCode, location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(v) => (status, [(header::LOCATION, v)]).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "bad redirect").into_response(),
    }
}
