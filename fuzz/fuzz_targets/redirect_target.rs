#![no_main]
use std::sync::OnceLock;

use axum::http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use rs_auth::config::{Config, host_in_domain};
use rs_auth::redirect::{original_url, validate_rd};

fn config() -> &'static Config {
    static C: OnceLock<Config> = OnceLock::new();
    C.get_or_init(|| {
        let text = r#"
[server]
portal_url = "https://auth.example.com"
trusted_proxies = ["172.18.0.0/16"]

[session]
domain = "example.com"
jwt_secret = "fuzz-secret-fuzz-secret-fuzz-secret!!"

[users.a]
password = '$argon2id$v=19$m=256,t=1,p=1$c2FsdHNhbHRzYWx0$J0nN0gBOIJPj9TKkNcWXwOGg3jBDAGx2fgDJ5Q1kJpQ'
"#;
        struct NoEnv;
        impl rs_auth::config::Environment for NoEnv {
            fn var(&self, _: &str) -> Option<String> {
                None
            }
            fn read_file(&self, _: &std::path::Path) -> std::io::Result<Vec<u8>> {
                Err(std::io::ErrorKind::NotFound.into())
            }
        }
        Config::from_toml(text, &NoEnv).expect("fuzz config").config
    })
}

fuzz_target!(|data: &[u8]| {
    let c = config();
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(u) = validate_rd(c, s) {
            assert_eq!(u.scheme(), "https");
            assert!(u.username().is_empty() && u.password().is_none());
            let host = u.host_str().expect("validated url has a host");
            assert!(
                host_in_domain(&host.to_ascii_lowercase(), "example.com"),
                "{s:?} -> {u}"
            );
        }
    }
    let parts: Vec<&[u8]> = data.splitn(3, |b| *b == 0).collect();
    if let [proto, host, uri] = parts.as_slice() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("x-forwarded-proto", proto),
            ("x-forwarded-host", host),
            ("x-forwarded-uri", uri),
        ] {
            if let Ok(v) = HeaderValue::from_bytes(v) {
                h.insert(k, v);
            }
        }
        if let Some(u) = original_url(&h) {
            assert!(u.scheme() == "https" || u.scheme() == "http");
            assert!(u.username().is_empty() && u.password().is_none());
        }
    }
});
