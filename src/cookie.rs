//! Building and clearing the session cookie.

use axum_extra::extract::cookie::{Cookie, SameSite};

use crate::config::Config;

/// The session cookie carrying `token`, shared across `session.domain`.
pub fn session(config: &Config, token: String) -> Cookie<'static> {
    Cookie::build((config.session.cookie_name.clone(), token))
        .domain(config.session.domain.clone())
        .path("/")
        .http_only(true)
        .secure(!config.server.insecure_dev_mode)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(
            config.session.expiry.as_secs() as i64
        ))
        .build()
}

/// A cookie that tells the browser to drop the session cookie. It must carry
/// the same name, domain and path as the one that was set.
pub fn clear_session(config: &Config) -> Cookie<'static> {
    Cookie::build((config.session.cookie_name.clone(), ""))
        .domain(config.session.domain.clone())
        .path("/")
        .http_only(true)
        .secure(!config.server.insecure_dev_mode)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::ZERO)
        .build()
}
