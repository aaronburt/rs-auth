#![no_main]
use libfuzzer_sys::fuzz_target;
use rs_auth::config::{Config, Environment};

struct NoEnv;
impl Environment for NoEnv {
    fn var(&self, _: &str) -> Option<String> {
        None
    }
    fn read_file(&self, _: &std::path::Path) -> std::io::Result<Vec<u8>> {
        Err(std::io::ErrorKind::NotFound.into())
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(loaded) = Config::from_toml(s, &NoEnv)
    {
        let c = loaded.config;
        assert!(c.session.secret.len() >= rs_auth::config::MIN_SECRET_LEN);
        assert!(!c.users.is_empty());
        assert!(!c.server.trusted_proxies.is_empty());
        assert_eq!(c.server.portal_url.path(), "/");
    }
});
