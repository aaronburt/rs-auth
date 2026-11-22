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
    notice: ui::LogoutNotice,
) -> Response {
    let username = match state.session_user(&jar) {
        Some(s) => s.username.to_owned(),
        None => match state.unsaved_sign_out(&jar) {
            Some(c) => c.sub,
            None => return Redirect::to("/login").into_response(),
        },
    };
    let (jar, token) = csrf::issue(jar, !state.config.server.insecure_dev_mode);
    let p = ui::LogoutPage {
        css: ui::CSS,
        username,
        csrf: token,
        stay_url: stay,
        notice,
    };
    (jar, render(status, &p)).into_response()
}

pub async fn show(
    State(state): State<SharedState>,
    Query(q): Query<RdQuery>,
    jar: CookieJar,
) -> Response {
    let stay = rd::target(&state.config, q.rd.as_deref()).to_string();
    confirm_page(&state, jar, StatusCode::OK, stay, ui::LogoutNotice::None)
}

pub async fn submit(
    State(state): State<SharedState>,
    jar: CookieJar,
    Form(form): Form<LogoutForm>,
) -> Response {
    let secure = !state.config.server.insecure_dev_mode;
    if !csrf::check(&jar, &form.csrf, secure) {
        let stay = state.config.server.default_redirect_url.to_string();
        return confirm_page(
            &state,
            jar,
            StatusCode::FORBIDDEN,
            stay,
            ui::LogoutNotice::Expired,
        );
    }
    if let Some(claims) = state.signed_claims(&jar) {
        let until = state.session_until(&claims);
        if let Err(e) = state
            .revocations
            .revoke(&claims.jti, claims.iat, until, crate::token::now())
            .await
        {
            tracing::error!(user = %claims.sub, error = %e, "sign-out could not be saved");
            let stay = state.config.server.default_redirect_url.to_string();
            return confirm_page(
                &state,
                jar,
                StatusCode::SERVICE_UNAVAILABLE,
                stay,
                ui::LogoutNotice::NotSaved,
            );
        }
        tracing::info!(user = %claims.sub, "signed out");
    }
    let jar = csrf::clear(jar, secure).with(cookie::clear_session(&state.config));
    (jar, redirect(StatusCode::SEE_OTHER, "/login")).into_response()
}
