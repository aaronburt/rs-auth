mod health;
mod login;
mod logout;
mod verify;

use std::time::Duration;

use askama::Template;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;

use crate::state::SharedState;
use crate::ui;

const BODY_LIMIT: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/login") }))
        .route("/healthz", get(health::healthz))
        .route("/api/verify", get(verify::verify).head(verify::verify))
        .route(
            "/api/verify/nginx",
            get(verify::verify_nginx).head(verify::verify_nginx),
        )
        .route("/login", get(login::show).post(login::submit))
        .route("/logout", get(logout::show).post(logout::submit))
        .route("/logged-in", get(login::signed_in))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::map_response(security_headers))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(axum::middleware::from_fn(|req, next| {
            guard(REQUEST_TIMEOUT, req, next)
        }))
        .with_state(state)
}

async fn guard(limit: Duration, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let started = std::time::Instant::now();
    let res = match tokio::time::timeout(limit, next.run(req)).await {
        Ok(res) => res,
        Err(_) => {
            tracing::warn!(%method, %path, "request timed out");
            return StatusCode::REQUEST_TIMEOUT.into_response();
        }
    };
    tracing::debug!(%method, %path, status = res.status().as_u16(), ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), "request");
    res
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

fn render(status: StatusCode, t: &impl Template) -> Response {
    match t.render() {
        Ok(body) => (status, Html(body)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

fn redirect(status: StatusCode, location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(v) => (status, [(header::LOCATION, v)]).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "bad redirect").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn slow_handlers_get_408() {
        use tower::ServiceExt;
        let app = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    "late"
                }),
            )
            .route("/fast", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(|req, next| {
                guard(Duration::from_millis(50), req, next)
            }));
        let get_req = |p: &str| {
            axum::http::Request::get(p)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let slow = app.clone().oneshot(get_req("/slow")).await.unwrap();
        assert_eq!(slow.status(), StatusCode::REQUEST_TIMEOUT);
        let fast = app.oneshot(get_req("/fast")).await.unwrap();
        assert_eq!(fast.status(), StatusCode::OK);
    }
}
