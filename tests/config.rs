//! Bad configs are rejected with a useful message; good ones load.

mod common;

use std::path::Path;

use common::*;
use rs_auth::config::{Config, ConfigError, Environment};

fn err(yaml: &str) -> String {
    match Config::from_yaml(yaml, &NoEnv) {
        Ok(_) => panic!("config should have been rejected"),
        Err(e) => e.to_string(),
    }
}

fn base() -> String {
    yaml(1, "[admins]", false)
}

#[test]
fn example_loads() {
    let loaded = Config::from_yaml(&base(), &NoEnv).unwrap();
    let c = loaded.config;
    assert_eq!(c.session.domain, "example.com");
    assert_eq!(c.session.cookie_name, "rs_auth_session");
    assert_eq!(c.session.expiry.as_secs(), 12 * 3600);
    assert_eq!(c.login.max_attempts, 5);
    assert_eq!(c.issuer(), "https://auth.example.com");
    assert_eq!(
        c.server.default_redirect_url.as_str(),
        "https://auth.example.com/logged-in"
    );
    // An inline secret works but warns.
    assert!(loaded.warnings.iter().any(|w| w.contains("jwt_secret")));
}

#[test]
fn debug_output_hides_secrets() {
    let c = config_from(&base());
    let dbg = format!("{c:?}");
    assert!(!dbg.contains(SECRET));
    assert!(!dbg.contains("$argon2id"));
}

#[test]
fn plain_text_password_is_rejected() {
    let y = base().replace(aaron_hash(), "hunter2");
    assert!(err(&y).contains("users.aaron.password"));
}

#[test]
fn non_argon2id_hash_is_rejected() {
    let argon2i = aaron_hash().replacen("$argon2id$", "$argon2i$", 1);
    assert!(err(&base().replace(aaron_hash(), &argon2i)).contains("argon2id"));
}

#[test]
fn short_secret_is_rejected() {
    let e = err(&base().replace(SECRET, "too-short"));
    assert!(e.contains("at least 32"), "{e}");
}

#[test]
fn missing_secret_is_rejected() {
    let y = base().replace(&format!("  jwt_secret: \"{SECRET}\"\n"), "");
    assert!(err(&y).contains("no JWT secret"));
}

struct FakeEnv {
    var: Option<&'static str>,
    file: Option<&'static str>,
}
impl Environment for FakeEnv {
    fn var(&self, name: &str) -> Option<String> {
        assert_eq!(name, "RS_AUTH_JWT_SECRET");
        self.var.map(str::to_owned)
    }
    fn read_file(&self, p: &Path) -> std::io::Result<Vec<u8>> {
        assert_eq!(p, Path::new("/run/secrets/jwt"));
        self.file
            .map(|s| s.as_bytes().to_vec())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "nope"))
    }
}

#[test]
fn secret_sources_in_order_file_env_inline() {
    let file_secret = "file-secret-file-secret-file-secret!!\n";
    let env_secret = "env-secret-env-secret-env-secret-env!!";
    let with_file = base().replace(
        &format!("  jwt_secret: \"{SECRET}\"\n"),
        &format!("  jwt_secret_file: /run/secrets/jwt\n  jwt_secret: \"{SECRET}\"\n"),
    );

    let c = Config::from_yaml(
        &with_file,
        &FakeEnv {
            var: Some(env_secret),
            file: Some(file_secret),
        },
    )
    .unwrap();
    assert_eq!(
        c.config.session.secret,
        file_secret.trim_end().as_bytes(),
        "file wins, newline trimmed"
    );

    let c = Config::from_yaml(
        &base(),
        &FakeEnv {
            var: Some(env_secret),
            file: None,
        },
    )
    .unwrap();
    assert_eq!(
        c.config.session.secret,
        env_secret.as_bytes(),
        "env beats inline"
    );
    assert!(c.warnings.is_empty(), "no inline warning when env is used");

    // A secret file that cannot be read is an error, not a silent fallback.
    let e = Config::from_yaml(
        &with_file,
        &FakeEnv {
            var: Some(env_secret),
            file: None,
        },
    )
    .unwrap_err();
    assert!(matches!(e, ConfigError::Read { .. }));
}

#[test]
fn portal_must_be_inside_cookie_domain() {
    let e = err(&base().replace("https://auth.example.com", "https://auth.other.org"));
    assert!(e.contains("subdomain"), "{e}");
}

#[test]
fn portal_must_be_https_unless_dev_mode() {
    let y = base().replace("https://auth.example.com", "http://auth.example.com");
    assert!(err(&y).contains("https"));
    let dev = y.replace("server:\n", "server:\n  insecure_dev_mode: true\n");
    let loaded = Config::from_yaml(&dev, &NoEnv).unwrap();
    assert!(
        loaded
            .warnings
            .iter()
            .any(|w| w.contains("insecure_dev_mode"))
    );
}

#[test]
fn portal_must_be_host_root() {
    let e = err(&base().replace("https://auth.example.com", "https://example.com/auth"));
    assert!(e.contains("root"), "{e}");
}

#[test]
fn trusted_proxies_are_required_and_parsed() {
    let none = base().replace("  trusted_proxies: [172.18.0.0/16, \"::1\"]\n", "");
    assert!(err(&none).contains("trusted_proxies"));
    let bad = base().replace("172.18.0.0/16", "not-a-cidr");
    assert!(err(&bad).contains("not-a-cidr"));
}

#[test]
fn unknown_fields_are_rejected() {
    let y = base().replace("login:\n", "login:\n  max_attempt: 3\n");
    assert!(err(&y).contains("max_attempt"));
}

#[test]
fn bad_durations_are_rejected() {
    assert!(err(&base().replace("expiry: 12h", "expiry: 12")).contains("unit"));
    assert!(err(&base().replace("expiry: 12h", "expiry: 30s")).contains("at least 1m"));
    assert!(err(&base().replace("window: 5m", "window: 5 minutes")).contains("unit"));
}

#[test]
fn bad_usernames_and_groups_are_rejected() {
    assert!(err(&base().replace("  aaron:\n", "  \"aa ron\":\n")).contains("username"));
    assert!(err(&base().replace("[admins]", "[\"a,b\"]")).contains("commas"));
}

#[test]
fn zero_attempts_and_no_users_are_rejected() {
    assert!(err(&base().replace("max_attempts: 5", "max_attempts: 0")).contains("max_attempts"));
    let i = base().find("users:").unwrap();
    let no_users = format!("{}users: {{}}\n", &base()[..i]);
    assert!(err(&no_users).contains("at least one user"));
}

#[test]
fn cookie_name_cannot_clash_with_csrf_cookie() {
    let y = base().replace("session:\n", "session:\n  cookie_name: rs_auth_csrf\n");
    assert!(err(&y).contains("CSRF"));
}

#[test]
fn default_redirect_must_be_inside_domain() {
    let y = base().replace(
        "server:\n",
        "server:\n  default_redirect_url: https://evil.net/\n",
    );
    assert!(err(&y).contains("default_redirect_url"));
}

#[test]
fn shipped_example_config_parses_apart_from_placeholder_hashes() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.yaml"))
        .unwrap();
    // The example carries placeholder hashes; swap in real ones to check the rest.
    let re_hash = |s: &str| {
        s.lines()
            .map(|l| {
                if l.trim_start().starts_with("password:") {
                    format!("    password: \"{}\"", aaron_hash())
                } else {
                    l.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let text = re_hash(&text).replace("  jwt_secret_file: /run/secrets/rs_auth_jwt\n", "");
    let loaded = Config::from_yaml(&text, &FakeEnvSecret).unwrap();
    assert_eq!(loaded.config.users.len(), 2);
}

struct FakeEnvSecret;
impl Environment for FakeEnvSecret {
    fn var(&self, _: &str) -> Option<String> {
        Some("x".repeat(32))
    }
    fn read_file(&self, _: &Path) -> std::io::Result<Vec<u8>> {
        unreachable!()
    }
}
