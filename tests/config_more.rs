#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
mod common;

use std::time::Duration;

use common::*;
use rs_auth::config::{Config, ConfigError, HumanDuration};

fn base() -> String {
    yaml(1, "[admins]", false)
}

fn err(y: &str) -> String {
    match Config::from_yaml(y, &NoEnv) {
        Ok(_) => panic!("config should have been rejected:\n{y}"),
        Err(e) => e.to_string(),
    }
}

fn swap(find: &str, with: &str) -> String {
    let y = base();
    assert!(y.contains(find), "{find:?} is not in the base config");
    y.replacen(find, with, 1)
}

#[test]
fn rejected_values_name_the_problem() {
    let cases: Vec<(String, &str)> = vec![
        (
            swap(
                "portal_url: https://auth.example.com",
                "portal_url: https://auth.example.com/?a=1",
            ),
            "query or fragment",
        ),
        (
            swap(
                "portal_url: https://auth.example.com",
                "portal_url: https://auth.example.com/#top",
            ),
            "query or fragment",
        ),
        (
            swap(
                "portal_url: https://auth.example.com",
                "portal_url: https://auth.example.com/app",
            ),
            "root of its own host",
        ),
        (
            swap(
                "portal_url: https://auth.example.com",
                "portal_url: https://auth.other.net",
            ),
            "or a subdomain of it",
        ),
        (
            swap(
                "portal_url: https://auth.example.com",
                "portal_url: ftp://auth.example.com",
            ),
            "unsupported scheme",
        ),
        (
            swap(
                "portal_url: https://auth.example.com",
                "portal_url: \"https://u:p@auth.example.com\"",
            ),
            "username or password",
        ),
        (
            swap(
                "portal_url: https://auth.example.com",
                "portal_url: \"not a url\"",
            ),
            "is not a URL",
        ),
        (
            swap(
                "trusted_proxies: [172.18.0.0/16, \"::1\"]",
                "trusted_proxies: []",
            ),
            "at least one",
        ),
        (
            swap(
                "trusted_proxies: [172.18.0.0/16, \"::1\"]",
                "trusted_proxies: [\"not-an-ip\"]",
            ),
            "not an IP address or CIDR",
        ),
        (
            swap("domain: example.com", "domain: com"),
            "must be a domain like",
        ),
        (
            swap("domain: example.com", "domain: \"\""),
            "must be a domain like",
        ),
        (
            swap("domain: example.com", "domain: 10.0.0.1"),
            "not an IP address",
        ),
        (
            swap("domain: example.com", "domain: exa_mple.com"),
            "not allowed",
        ),
        (
            swap("domain: example.com", "domain: -a.example.com"),
            "not allowed",
        ),
        (
            swap("domain: example.com", "domain: a..example.com"),
            "not allowed",
        ),
        (swap("  expiry: 12h", "  expiry: 30s"), "at least 1m"),
        (swap("  expiry: 12h", "  expiry: 500d"), "at most 400d"),
        (
            swap(
                "  version: 1\n",
                "  version: 1\n  cookie_name: \"bad name\"\n",
            ),
            "may only use letters",
        ),
        (
            swap("  version: 1\n", "  version: 1\n  cookie_name: \"\"\n"),
            "may only use letters",
        ),
        (
            swap(
                "  version: 1\n",
                "  version: 1\n  cookie_name: rs_auth_csrf\n",
            ),
            "CSRF cookie",
        ),
        (
            swap(
                "portal_url: https://auth.example.com",
                "portal_url: https://auth.example.com\n  default_redirect_url: https://evil.net",
            ),
            "default_redirect_url host",
        ),
        (
            swap("groups: [admins]", "groups: [\"a,b\"]"),
            "no commas or spaces",
        ),
        (
            swap("groups: [admins]", "groups: [\"\"]"),
            "must be non-empty",
        ),
        (
            swap("groups: [admins]", "groups: [\"a b\"]"),
            "no commas or spaces",
        ),
        (
            swap("display_name: Aaron Example", "display_name: \"A\\x07\""),
            "control characters",
        ),
        (
            swap("email: aaron@example.com", "email: \"a b@example.com\""),
            "does not look like an email",
        ),
        (
            swap("email: aaron@example.com", "email: \"@example.com\""),
            "does not look like an email",
        ),
        (
            swap("email: aaron@example.com", "email: \"a@b@c\""),
            "does not look like an email",
        ),
        (swap("  aaron:\n", "  \"bad name\":\n"), "may only use"),
        (swap("  max_attempts: 5", "  max_attempts: 0"), "at least 1"),
    ];
    for (y, want) in cases {
        let e = err(&y);
        assert!(e.contains(want), "expected {want:?} in {e:?}");
    }
}

#[test]
fn http_needs_dev_mode_and_dev_mode_warns() {
    let http = swap(
        "portal_url: https://auth.example.com",
        "portal_url: http://auth.example.com",
    );
    assert!(err(&http).contains("insecure_dev_mode"));
    let dev = swap(
        "portal_url: https://auth.example.com",
        "portal_url: http://auth.example.com\n  insecure_dev_mode: true",
    );
    let loaded = Config::from_yaml(&dev, &NoEnv).unwrap();
    assert!(
        loaded
            .warnings
            .iter()
            .any(|w| w.contains("insecure_dev_mode"))
    );
    assert!(loaded.config.server.insecure_dev_mode);
}

#[test]
fn omitted_options_get_their_defaults() {
    let y = format!(
        r#"
server:
  portal_url: https://auth.example.com
  trusted_proxies: [172.18.0.0/16]
session:
  domain: example.com
  jwt_secret: "{SECRET}"
users:
  aaron:
    password: "{}"
"#,
        aaron_hash()
    );
    let c = Config::from_yaml(&y, &NoEnv).unwrap().config;
    assert_eq!(c.server.address.to_string(), "0.0.0.0:9091");
    assert_eq!(c.session.version, 1);
    assert_eq!(c.session.expiry, Duration::from_secs(12 * 3600));
    assert_eq!(c.session.cookie_name, "rs_auth_session");
    assert_eq!(c.login.max_attempts, 5);
    assert_eq!(c.login.window, Duration::from_secs(300));
    assert!(c.session.revocation_file.is_none());
    assert_eq!(c.users["aaron"].display_name, "aaron");
}

#[test]
fn durations_print_in_seconds() {
    assert_eq!(
        format!("{:?}", HumanDuration(Duration::from_secs(90))),
        "90s"
    );
}

#[test]
fn load_file_reads_warns_and_fails_clearly() {
    let dir = std::env::temp_dir().join(format!("rs-auth-cfg-{}", rs_auth::token::new_jti()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(&path, base()).unwrap();

    let loaded = Config::load_file(&path).unwrap();
    assert_eq!(loaded.config.users.len(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let w = Config::load_file(&path).unwrap().warnings;
        assert!(w.iter().any(|w| w.contains("world-readable")), "{w:?}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let w = Config::load_file(&path).unwrap().warnings;
        assert!(!w.iter().any(|w| w.contains("world-readable")), "{w:?}");
    }

    let missing = Config::load_file(&dir.join("nope.yaml")).err().unwrap();
    assert!(matches!(missing, ConfigError::Read { .. }));
    assert!(missing.to_string().contains("could not read"));

    std::fs::write(&path, "server: [unclosed").unwrap();
    let bad = Config::load_file(&path).err().unwrap();
    assert!(bad.to_string().contains("not valid YAML"), "{bad}");

    let secret_file = dir.join("secret");
    std::fs::write(&secret_file, format!("{SECRET}\n")).unwrap();
    std::fs::write(
        &path,
        base().replace(
            &format!("jwt_secret: \"{SECRET}\""),
            &format!("jwt_secret_file: {}", secret_file.display()),
        ),
    )
    .unwrap();
    let c = Config::load_file(&path).unwrap().config;
    assert_eq!(c.session.secret, SECRET.as_bytes());
    std::fs::remove_dir_all(&dir).unwrap();
}
