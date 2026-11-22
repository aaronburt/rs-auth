use crate::cookie::{Cookie, CookieJar, SameSite};
use subtle::ConstantTimeEq;

pub const SECURE_COOKIE_NAME: &str = "__Host-rs_auth_csrf";
pub const DEV_COOKIE_NAME: &str = "rs_auth_csrf";
const TOKEN_HEX_LEN: usize = 64;
const MAX_AGE_SECS: u64 = 3600;

pub fn cookie_name(secure: bool) -> &'static str {
    if secure {
        SECURE_COOKIE_NAME
    } else {
        DEV_COOKIE_NAME
    }
}

fn is_well_formed(t: &str) -> bool {
    t.len() == TOKEN_HEX_LEN && t.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn new_token() -> String {
    crate::random::hex::<32>()
}

fn build(secure: bool, value: String, max_age: u64) -> Cookie {
    Cookie::new(cookie_name(secure), value)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(max_age)
}

pub fn issue(jar: CookieJar, secure: bool) -> (CookieJar, String) {
    let token = jar
        .get(cookie_name(secure))
        .map(str::to_owned)
        .filter(|t| is_well_formed(t))
        .unwrap_or_else(new_token);
    let cookie = build(secure, token.clone(), MAX_AGE_SECS);
    (jar.with(cookie), token)
}

pub fn clear(jar: CookieJar, secure: bool) -> CookieJar {
    jar.with(build(secure, String::new(), 0))
}

pub fn check(jar: &CookieJar, form_token: &str, secure: bool) -> bool {
    let Some(c) = jar.get(cookie_name(secure)) else {
        return false;
    };
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
        assert!(check(&jar, &t, true));
        assert!(!check(&jar, &new_token(), true));
        assert!(!check(&jar, "", true));
        assert!(!check(&CookieJar::new(), &t, true));
    }

    #[test]
    fn secure_cookie_uses_host_prefix() {
        let (jar, t) = issue(CookieJar::new(), true);
        assert_eq!(jar.get(SECURE_COOKIE_NAME), Some(t.as_str()));
        let h = build(true, t.clone(), 60).header_value().unwrap();
        let h = h.to_str().unwrap();
        assert!(h.starts_with("__Host-rs_auth_csrf="));
        for part in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
            assert!(h.contains(part), "{part} missing from {h}");
        }
        assert!(!h.contains("Domain"), "__Host- cookies must not set Domain");
        assert!(
            !check(&jar, &t, false),
            "dev name is not read in secure mode"
        );
        let (dev, t2) = issue(CookieJar::new(), false);
        assert!(dev.get(DEV_COOKIE_NAME).is_some());
        assert!(check(&dev, &t2, false));
    }

    #[test]
    fn a_planted_unprefixed_cookie_is_ignored() {
        let planted = new_token();
        let jar = CookieJar::new().with(Cookie::new(DEV_COOKIE_NAME, planted.clone()));
        assert!(!check(&jar, &planted, true));
    }

    #[test]
    fn reuses_existing_token() {
        let (jar, t1) = issue(CookieJar::new(), true);
        let (_, t2) = issue(jar, true);
        assert_eq!(t1, t2);
    }

    #[test]
    fn replaces_malformed_cookie() {
        let jar = CookieJar::new().with(Cookie::new(SECURE_COOKIE_NAME, "short"));
        let (jar, t) = issue(jar, true);
        assert_ne!(t, "short");
        assert!(check(&jar, &t, true));
    }

    #[test]
    fn clear_removes_token() {
        let (jar, t) = issue(CookieJar::new(), true);
        let jar = clear(jar, true);
        assert!(!check(&jar, &t, true));
    }
}
