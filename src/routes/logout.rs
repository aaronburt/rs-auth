//! `GET /logout` shows a "Sign out?" page; `POST /logout` signs out.
//!
//! Signing out needs a POST with a CSRF token, so a stray link or image
//! cannot log anyone out.

use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use super::{redirect, render};
use crate::state::SharedState;
use crate::ui;
use crate::{cookie, csrf, redirect as rd};

#[derive(Debug, Deserialize)]
pub struct RdQuery {
    #[serde(default)]
    rd: Option<String>,
}

#[derive(Deserialize)]
pub struct LogoutForm {
    #[serde(default)]
    csrf: String,
}

fn confirm_page(
    state: &SharedState,
    jar: CookieJar,
    status: StatusCode,
    stay: String,
    expired: bool,
) -> Response {
    let Some(s) = state.session_user(&jar) else {
        return Redirect::to("/login").into_response();
    };
    let username = s.username.to_owned();
    let (jar, token) = csrf::issue(jar, !state.config.server.insecure_dev_mode);
    let p = ui::LogoutPage {
        css: ui::CSS,
        username,
        csrf: token,
        stay_url: stay,
        expired,
    };
    (jar, render(status, &p)).into_response()
}

pub async fn show(
    State(state): State<SharedState>,
    Query(q): Query<RdQuery>,
    jar: CookieJar,
) -> Response {
    let stay = rd::target(&state.config, q.rd.as_deref()).to_string();
    confirm_page(&state, jar, StatusCode::OK, stay, false)
}

pub async fn submit(
    State(state): State<SharedState>,
    jar: CookieJar,
    Form(form): Form<LogoutForm>,
) -> Response {
    if !csrf::check(&jar, &form.csrf) {
        let stay = state.config.server.default_redirect_url.to_string();
        return confirm_page(&state, jar, StatusCode::FORBIDDEN, stay, true);
    }
    if let Some(s) = state.session_user(&jar) {
        tracing::info!(user = %s.username, "signed out");
    }
    let jar = jar.add(cookie::clear_session(&state.config));
    (jar, redirect(StatusCode::SEE_OTHER, "/login")).into_response()
}
