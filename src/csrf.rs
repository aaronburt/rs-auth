//! Double-submit CSRF tokens for the login and logout forms.
//!
//! A random token goes in a short-lived, host-only cookie and in a hidden
//! form field. A POST is accepted only when the two match. This sits on top
//! of `SameSite=Lax` on the session cookie.

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use subtle::ConstantTimeEq;

pub const COOKIE_NAME: &str = "rs_auth_csrf";
const TOKEN_HEX_LEN: usize = 64;
const MAX_AGE_SECS: i64 = 3600;

fn is_well_formed(t: &str) -> bool {
    t.len() == TOKEN_HEX_LEN && t.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn new_token() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The token to put in a form: the one already in the browser's cookie if it
/// looks valid (so several tabs keep working), otherwise a fresh one.
/// Returns the jar with the cookie (re)set.
pub fn issue(jar: CookieJar, secure: bool) -> (CookieJar, String) {
    let token = jar
        .get(COOKIE_NAME)
        .map(|c| c.value().to_owned())
        .filter(|t| is_well_formed(t))
        .unwrap_or_else(new_token);
    let cookie = Cookie::build((COOKIE_NAME, token.clone()))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(MAX_AGE_SECS))
        .build();
    (jar.add(cookie), token)
}

/// True when the form token matches the cookie token.
pub fn check(jar: &CookieJar, form_token: &str) -> bool {
    let Some(cookie) = jar.get(COOKIE_NAME) else {
        return false;
    };
    let c = cookie.value();
    is_well_formed(c)
        && is_well_formed(form_token)
        && bool::from(c.as_bytes().ct_eq(form_token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_check() {
        let (jar, t) = issue(CookieJar::new(), true);
        assert!(check(&jar, &t));
        assert!(!check(&jar, &new_token()));
        assert!(!check(&jar, ""));
        assert!(!check(&CookieJar::new(), &t));
    }

    #[test]
    fn reuses_existing_token() {
        let (jar, t1) = issue(CookieJar::new(), true);
        let (_, t2) = issue(jar, true);
        assert_eq!(t1, t2);
    }

    #[test]
    fn replaces_malformed_cookie() {
        let jar = CookieJar::new().add(Cookie::new(COOKIE_NAME, "short"));
        let (jar, t) = issue(jar, true);
        assert_ne!(t, "short");
        assert!(check(&jar, &t));
    }
}
