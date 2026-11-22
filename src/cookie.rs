use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::HeaderValue;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::request::Parts;
use axum::response::{IntoResponseParts, ResponseParts};

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Lax,
    Strict,
}

#[derive(Debug, Clone)]
pub struct Cookie {
    name: String,
    value: String,
    domain: Option<String>,
    secure: bool,
    same_site: SameSite,
    max_age: u64,
}

impl Cookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: None,
            secure: false,
            same_site: SameSite::Lax,
            max_age: 0,
        }
    }

    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    pub fn max_age(mut self, secs: u64) -> Self {
        self.max_age = secs;
        self
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn get_domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    pub fn is_secure(&self) -> bool {
        self.secure
    }

    pub fn header_value(&self) -> Option<HeaderValue> {
        let mut s = format!("{}={}; Path=/; HttpOnly", self.name, self.value);
        if let Some(d) = &self.domain {
            s.push_str("; Domain=");
            s.push_str(d);
        }
        if self.secure {
            s.push_str("; Secure");
        }
        s.push_str(match self.same_site {
            SameSite::Lax => "; SameSite=Lax",
            SameSite::Strict => "; SameSite=Strict",
        });
        s.push_str(&format!("; Max-Age={}", self.max_age));
        HeaderValue::from_str(&s).ok()
    }
}

#[derive(Debug, Clone)]
struct Seen {
    name: String,
    value: String,
    ambiguous: bool,
}

#[derive(Debug, Default, Clone)]
pub struct CookieJar {
    seen: Vec<Seen>,
    added: Vec<Cookie>,
}

fn pairs<'a>(values: impl Iterator<Item = &'a str>) -> impl Iterator<Item = (&'a str, &'a str)> {
    values
        .flat_map(|header| header.split(';'))
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            let (name, value) = (name.trim(), value.trim());
            (!name.is_empty()).then_some((name, value))
        })
}

pub fn without<'a>(values: impl Iterator<Item = &'a str>, name: &str) -> Option<String> {
    let kept: Vec<&str> = values
        .flat_map(|header| header.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| pair.split_once('=').map_or(*pair, |(n, _)| n).trim() != name)
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse<'a>(values: impl Iterator<Item = &'a str>) -> Self {
        let mut seen: Vec<Seen> = Vec::new();
        for (name, value) in pairs(values) {
            match seen.iter_mut().find(|s| s.name == name) {
                Some(slot) => slot.ambiguous |= slot.value != value,
                None => seen.push(Seen {
                    name: name.to_owned(),
                    value: value.to_owned(),
                    ambiguous: false,
                }),
            }
        }
        Self {
            seen,
            added: Vec::new(),
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        if let Some(c) = self.added.iter().rev().find(|c| c.name == name) {
            return Some(c.value());
        }
        self.seen
            .iter()
            .find(|s| s.name == name && !s.ambiguous)
            .map(|s| s.value.as_str())
    }

    pub fn is_ambiguous(&self, name: &str) -> bool {
        self.seen.iter().any(|s| s.name == name && s.ambiguous)
    }

    pub fn with(mut self, cookie: Cookie) -> Self {
        self.added.push(cookie);
        self
    }
}

impl<S: Send + Sync> FromRequestParts<S> for CookieJar {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::parse(
            parts
                .headers
                .get_all(COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok()),
        ))
    }
}

impl IntoResponseParts for CookieJar {
    type Error = Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        for c in &self.added {
            if let Some(v) = c.header_value() {
                res.headers_mut().append(SET_COOKIE, v);
            }
        }
        Ok(res)
    }
}

pub fn session(config: &Config, token: String) -> Cookie {
    Cookie::new(config.session.cookie_name.clone(), token)
        .domain(config.session.domain.clone())
        .secure(!config.server.insecure_dev_mode)
        .same_site(SameSite::Lax)
        .max_age(config.session.expiry.as_secs())
}

pub fn clear_session(config: &Config) -> Cookie {
    Cookie::new(config.session.cookie_name.clone(), "")
        .domain(config.session.domain.clone())
        .secure(!config.server.insecure_dev_mode)
        .same_site(SameSite::Lax)
        .max_age(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jar(h: &[&str]) -> CookieJar {
        CookieJar::parse(h.iter().copied())
    }

    #[test]
    fn parses_pairs_across_and_within_headers() {
        let j = jar(&["a=1; b=2", "c=3"]);
        assert_eq!(j.get("a"), Some("1"));
        assert_eq!(j.get("b"), Some("2"));
        assert_eq!(j.get("c"), Some("3"));
        assert_eq!(j.get("d"), None);
    }

    #[test]
    fn values_may_contain_equals_and_dots() {
        let j = jar(&["rs_auth_session=aaa.bbb.ccc==; x=y"]);
        assert_eq!(j.get("rs_auth_session"), Some("aaa.bbb.ccc=="));
    }

    #[test]
    fn junk_is_skipped() {
        let j = jar(&["; =novalue; justname; ok=1;;"]);
        assert_eq!(j.get("ok"), Some("1"));
        assert_eq!(j.get("justname"), None);
        assert_eq!(j.get(""), None);
    }

    #[test]
    fn names_are_case_sensitive_and_exact() {
        let j = jar(&["rs_auth_session=1"]);
        assert_eq!(j.get("RS_AUTH_SESSION"), None);
        assert_eq!(j.get("rs_auth_session "), None);
    }

    #[test]
    fn a_repeated_name_with_different_values_is_ambiguous() {
        let j = jar(&["a=1; b=3", "a=2"]);
        assert_eq!(j.get("a"), None);
        assert!(j.is_ambiguous("a"));
        assert_eq!(j.get("b"), Some("3"));
        assert!(!j.is_ambiguous("b"));
        assert!(!j.is_ambiguous("missing"));
    }

    #[test]
    fn a_repeated_name_with_the_same_value_is_not_ambiguous() {
        let j = jar(&["a=1; a=1"]);
        assert_eq!(j.get("a"), Some("1"));
        assert!(!j.is_ambiguous("a"));
    }

    #[test]
    fn without_drops_only_the_named_cookie() {
        let h = [
            "theme=dark; rs_auth_session=abc.def; app_session=xyz",
            "rs_auth_session=zzz; lang=en",
        ];
        assert_eq!(
            without(h.iter().copied(), "rs_auth_session").as_deref(),
            Some("theme=dark; app_session=xyz; lang=en")
        );
        assert_eq!(
            without(["rs_auth_session=abc"].into_iter(), "rs_auth_session"),
            None
        );
        assert_eq!(without(["; ;"].into_iter(), "x"), None);
        assert_eq!(
            without(
                ["rs_auth_session_extra=1; xrs_auth_session=2; flag"].into_iter(),
                "rs_auth_session"
            )
            .as_deref(),
            Some("rs_auth_session_extra=1; xrs_auth_session=2; flag")
        );
        assert_eq!(
            without([" rs_auth_session =1; a=2"].into_iter(), "rs_auth_session").as_deref(),
            Some("a=2")
        );
    }

    #[test]
    fn added_cookies_shadow_incoming_ones() {
        let j = jar(&["a=old"]).with(Cookie::new("a", "new"));
        assert_eq!(j.get("a"), Some("new"));
    }

    #[test]
    fn set_cookie_has_every_attribute() {
        let c = Cookie::new("n", "v")
            .domain("example.com")
            .secure(true)
            .same_site(SameSite::Strict)
            .max_age(60);
        let h = c.header_value().unwrap();
        let s = h.to_str().unwrap();
        for part in [
            "n=v",
            "Path=/",
            "HttpOnly",
            "Domain=example.com",
            "Secure",
            "SameSite=Strict",
            "Max-Age=60",
        ] {
            assert!(s.contains(part), "{part} missing from {s}");
        }
    }

    #[test]
    fn a_value_that_cannot_be_a_header_is_not_sent() {
        assert!(Cookie::new("n", "bad\nvalue").header_value().is_none());
    }
}
