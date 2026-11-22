#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::OnceLock;

use argon2::password_hash::PasswordHasher;
use argon2::{Algorithm, Argon2, Params, Version};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use rs_auth::config::{Config, Environment};
use tower::ServiceExt;

pub const SECRET: &str = "test-secret-test-secret-test-secret!!";
pub const PROXY: &str = "172.18.0.2:40000";
pub const OUTSIDE: &str = "203.0.113.50:40000";

pub fn quick_hash(pw: &str) -> String {
    let params = Params::new(256, 1, 1, None).unwrap();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(pw.as_bytes())
        .unwrap()
        .to_string()
}

pub fn aaron_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| quick_hash("correct horse"))
}

pub struct NoEnv;
impl Environment for NoEnv {
    fn var(&self, _: &str) -> Option<String> {
        None
    }
    fn read_file(&self, p: &Path) -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            p.display().to_string(),
        ))
    }
}

pub fn yaml(version: u32, aaron_groups: &str, include_guest: bool) -> String {
    let guest = if include_guest {
        format!(
            "  guest:\n    display_name: Guest\n    groups: [family]\n    password: \"{}\"\n",
            quick_hash("guest pass")
        )
    } else {
        String::new()
    };
    format!(
        r#"
server:
  address: 127.0.0.1:9091
  portal_url: https://auth.example.com
  trusted_proxies: [172.18.0.0/16, "::1"]
session:
  domain: example.com
  version: {version}
  expiry: 12h
  jwt_secret: "{SECRET}"
login:
  max_attempts: 5
  window: 5m
users:
  aaron:
    display_name: Aaron Example
    email: aaron@example.com
    groups: {aaron_groups}
    password: "{hash}"
{guest}"#,
        hash = aaron_hash()
    )
}

pub fn config_from(yaml: &str) -> Config {
    Config::from_yaml(yaml, &NoEnv)
        .expect("valid test config")
        .config
}

pub fn app_with(yaml: &str) -> Router {
    rs_auth::router(rs_auth::AppState::new(config_from(yaml)))
}

pub fn app() -> Router {
    app_with(&yaml(1, "[admins, family]", true))
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
    pub fn location(&self) -> &str {
        self.header("location").expect("location header")
    }
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies().iter().find_map(|c| {
            let first = c.split(';').next()?;
            let (k, v) = first.split_once('=')?;
            (k == name).then(|| v.to_owned())
        })
    }
    pub fn csrf_field(&self) -> String {
        let i = self
            .body
            .find(r#"name="csrf" value=""#)
            .expect("csrf field")
            + r#"name="csrf" value=""#.len();
        self.body[i..i + 64].to_owned()
    }
}

pub async fn send(app: &Router, peer: &str, req: Request<Body>) -> Resp {
    let mut req = req;
    let peer: SocketAddr = peer.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    let res: Response<Body> = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

pub fn get(uri: &str, cookies: &str) -> Request<Body> {
    let mut b = Request::get(uri);
    if !cookies.is_empty() {
        b = b.header(header::COOKIE, cookies);
    }
    b.body(Body::empty()).unwrap()
}

pub fn post_form(uri: &str, cookies: &str, form: &[(&str, &str)]) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let mut b =
        Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookies.is_empty() {
        b = b.header(header::COOKIE, cookies);
    }
    b.body(Body::from(body)).unwrap()
}

pub fn verify_req(method: &str, host: &str, uri: &str, cookies: &str) -> Request<Body> {
    let mut b = Request::get("/api/verify")
        .header("x-forwarded-method", method)
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", host)
        .header("x-forwarded-uri", uri)
        .header("x-forwarded-for", "198.51.100.7");
    if !cookies.is_empty() {
        b = b.header(header::COOKIE, cookies);
    }
    b.body(Body::empty()).unwrap()
}

pub async fn csrf(app: &Router, peer: &str) -> (String, String) {
    let r = send(app, peer, get("/login", "")).await;
    let cookie = r.cookie("__Host-rs_auth_csrf").expect("csrf cookie");
    let field = r.csrf_field();
    assert_eq!(cookie, field);
    (format!("__Host-rs_auth_csrf={cookie}"), field)
}

pub async fn sign_in(app: &Router, user: &str, pw: &str) -> String {
    let (cookie, token) = csrf(app, PROXY).await;
    let r = send(
        app,
        PROXY,
        post_form(
            "/login",
            &cookie,
            &[
                ("username", user),
                ("password", pw),
                ("csrf", &token),
                ("rd", ""),
            ],
        ),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::SEE_OTHER,
        "sign-in failed: {}",
        r.body
    );
    format!("rs_auth_session={}", r.cookie("rs_auth_session").unwrap())
}
