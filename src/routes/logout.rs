use crate::cookie::CookieJar;
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
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
    let secure = !state.config.server.insecure_dev_mode;
    if !csrf::check(&jar, &form.csrf, secure) {
        let stay = state.config.server.default_redirect_url.to_string();
        return confirm_page(&state, jar, StatusCode::FORBIDDEN, stay, true);
    }
    if let Some(s) = state.session_user(&jar) {
        tracing::info!(user = %s.username, "signed out");
        let until = state.session_until(&s.claims);
        let jti = s.claims.jti.clone();
        state
            .revocations
            .revoke(&jti, until, crate::token::now())
            .await;
    }
    let jar = csrf::clear(jar, secure).with(cookie::clear_session(&state.config));
    (jar, redirect(StatusCode::SEE_OTHER, "/login")).into_response()
}
