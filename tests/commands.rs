#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use common::*;
use rs_auth::cli::{Command, USAGE, parse_args};
use rs_auth::commands::{check_config, hash_for, healthcheck, load_config, log_level, serve_on};
use tracing::level_filters::LevelFilter;

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rs-auth-{name}-{}", rs_auth::token::new_jti()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn check_config_summarises_and_passes_warnings_on() {
    let dir = temp_dir("check");
    let path = dir.join("config.toml");
    std::fs::write(&path, toml(1, &["admins"], true)).unwrap();
    let c = check_config(&path).unwrap();
    assert!(
        c.summary.contains("is valid: 2 user(s), 1 access rule(s)"),
        "{}",
        c.summary
    );
    assert!(c.summary.contains("auth.example.com"));
    assert!(c.summary.contains("cookie domain example.com"));
    assert!(c.summary.contains("43200s"));
    assert!(c.warnings.iter().any(|w| w.contains("jwt_secret")));

    assert!(load_config(&path).is_ok());
    let e = check_config(&dir.join("missing.toml")).err().unwrap();
    assert!(
        e.to_string().starts_with("loading config: could not read"),
        "{e}"
    );
    assert!(load_config(&dir.join("missing.toml")).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn hashing_warns_about_short_passwords_only() {
    let (h, w) = hash_for("short").unwrap();
    assert!(h.starts_with("$argon2id$"));
    assert!(w.unwrap().contains("shorter than 8"));
    let (_, w) = hash_for("long enough password").unwrap();
    assert!(w.is_none());
    assert!(hash_for("").is_err(), "an empty password cannot be hashed");
}

#[test]
fn log_levels() {
    assert_eq!(log_level(None), LevelFilter::INFO);
    assert_eq!(log_level(Some("debug")), LevelFilter::DEBUG);
    assert_eq!(log_level(Some(" WARN ")), LevelFilter::WARN);
    assert_eq!(log_level(Some("rs_auth=trace")), LevelFilter::INFO);
    assert_eq!(log_level(Some("")), LevelFilter::INFO);
}

#[tokio::test]
async fn server_starts_answers_healthchecks_and_stops_on_signal() {
    let config = config_from(&toml(1, &["admins"], false));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_on(config, listener, async {
        let _ = stopped.await;
    }));

    let ok = tokio::task::spawn_blocking(move || healthcheck(addr))
        .await
        .unwrap();
    assert!(ok.is_ok(), "{:?}", ok.err().map(|e| e.to_string()));

    stop.send(()).unwrap();
    let done = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the server stops when told to")
        .unwrap();
    assert!(done.is_ok());
}

#[tokio::test]
async fn a_bad_revocation_file_stops_startup() {
    let dir = temp_dir("badrev");
    let y = toml(1, &["admins"], false).replace(
        "expiry = \"12h\"\n",
        &format!(
            "expiry = \"12h\"\nrevocation_file = {:?}\n",
            dir.display().to_string()
        ),
    );
    let config = config_from(&y);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let e = serve_on(config, listener, std::future::pending())
        .await
        .err()
        .unwrap();
    assert!(e.to_string().contains("revocation_file"), "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn healthcheck_fails_when_nothing_listens_or_the_answer_is_wrong() {
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    assert!(healthcheck(closed).is_err());

    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let t = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf).unwrap();
        s.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
            .unwrap();
    });
    let e = healthcheck(addr).err().unwrap();
    assert!(e.to_string().starts_with("unhealthy: HTTP/1.1 503"), "{e}");
    t.join().unwrap();
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn cli_covers_the_remaining_forms() {
    assert!(matches!(
        parse_args(args(&["--version"])).unwrap(),
        Some(Command::Version)
    ));
    assert!(matches!(
        parse_args(args(&["-V"])).unwrap(),
        Some(Command::Version)
    ));
    for h in ["-h", "--help", "help"] {
        assert!(parse_args(args(&[h])).unwrap().is_none());
    }
    match parse_args(args(&["healthcheck"])).unwrap().unwrap() {
        Command::Healthcheck { address } => assert_eq!(address.to_string(), "127.0.0.1:9091"),
        _ => panic!("expected healthcheck"),
    }
    assert!(parse_args(args(&["healthcheck", "127.0.0.1:1", "extra"])).is_err());
    assert!(parse_args(args(&["hash-password", "--stdin", "x"])).is_err());
    let e = parse_args(args(&["serve", "stray"])).err().unwrap();
    assert!(e.contains("unexpected argument"), "{e}");
    assert!(USAGE.contains("rs-auth serve"));

    let from_env = std::env::var_os("RS_AUTH_CONFIG")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("config.toml"), PathBuf::from);
    match parse_args(args(&["serve"])).unwrap().unwrap() {
        Command::Serve { config } => assert_eq!(config, from_env),
        _ => panic!("expected serve"),
    }
    match parse_args(args(&[
        "check-config",
        "-c",
        "x.toml",
        "--config",
        "y.toml",
    ]))
    .unwrap()
    .unwrap()
    {
        Command::CheckConfig { config } => assert_eq!(config, PathBuf::from("y.toml")),
        _ => panic!("expected check-config"),
    }
}
