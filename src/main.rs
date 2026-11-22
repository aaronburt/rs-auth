#![forbid(unsafe_code)]

use std::error::Error;
use std::io::{BufRead, IsTerminal};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use rs_auth::{AppState, Config, password};
use tracing::level_filters::LevelFilter;

type Res<T> = Result<T, Box<dyn Error>>;

const USAGE: &str = "\
rs-auth: a small forward-auth login portal for Traefik and Caddy

Usage:
  rs-auth serve [-c, --config <file>]    Run the portal
  rs-auth hash-password [--stdin]        Print an Argon2id hash for a password
  rs-auth check-config [-c <file>]       Validate the config without starting
  rs-auth healthcheck [address]          Exit 0 if /healthz answers (default 127.0.0.1:9091)
  rs-auth --version | --help

The config file defaults to $RS_AUTH_CONFIG, then config.yaml.
The log level comes from RUST_LOG (error, warn, info, debug or trace; default info).";

enum Command {
    Serve { config: PathBuf },
    HashPassword { stdin: bool },
    CheckConfig { config: PathBuf },
    Healthcheck { address: SocketAddr },
    Version,
}

fn parse_args(args: Vec<String>) -> Result<Option<Command>, String> {
    let default_config = || {
        std::env::var_os("RS_AUTH_CONFIG")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("config.yaml"))
    };
    let mut args = args.into_iter();
    let Some(cmd) = args.next() else {
        return Err("a command is required".into());
    };
    match cmd.as_str() {
        "-h" | "--help" | "help" => return Ok(None),
        "-V" | "--version" => {
            return Ok(Some(Command::Version));
        }
        _ => {}
    }
    let rest: Vec<String> = args.collect();
    let config_flag = |rest: &[String]| -> Result<PathBuf, String> {
        let mut config = None;
        let mut it = rest.iter();
        while let Some(a) = it.next() {
            let value = if a == "-c" || a == "--config" {
                it.next()
                    .cloned()
                    .ok_or_else(|| format!("{a} needs a file name"))?
            } else if let Some(v) = a.strip_prefix("--config=") {
                v.to_owned()
            } else {
                return Err(format!("unexpected argument {a:?}"));
            };
            config = Some(PathBuf::from(value));
        }
        Ok(config.unwrap_or_else(default_config))
    };
    match cmd.as_str() {
        "serve" => Ok(Some(Command::Serve {
            config: config_flag(&rest)?,
        })),
        "check-config" => Ok(Some(Command::CheckConfig {
            config: config_flag(&rest)?,
        })),
        "hash-password" => match rest.as_slice() {
            [] => Ok(Some(Command::HashPassword { stdin: false })),
            [f] if f == "--stdin" => Ok(Some(Command::HashPassword { stdin: true })),
            [other, ..] => Err(format!("unexpected argument {other:?}")),
        },
        "healthcheck" => match rest.as_slice() {
            [] => Ok(Some(Command::Healthcheck {
                address: "127.0.0.1:9091".parse().expect("static address"),
            })),
            [a] => a
                .parse()
                .map(|address| Some(Command::Healthcheck { address }))
                .map_err(|_| format!("{a:?} is not an address like 127.0.0.1:9091")),
            [_, other, ..] => Err(format!("unexpected argument {other:?}")),
        },
        other => Err(format!("unknown command {other:?}")),
    }
}

fn main() -> ExitCode {
    let command = match parse_args(std::env::args().skip(1).collect()) {
        Ok(Some(c)) => c,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match command {
        Command::Serve { config } => serve(config),
        Command::HashPassword { stdin } => hash_password(stdin),
        Command::CheckConfig { config } => check_config(config),
        Command::Healthcheck { address } => healthcheck(address),
        Command::Version => {
            println!("rs-auth {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn load(path: &std::path::Path) -> Res<Config> {
    let loaded = Config::load_file(path).map_err(|e| format!("loading config: {e}"))?;
    for w in &loaded.warnings {
        tracing::warn!("{w}");
    }
    Ok(loaded.config)
}

fn check_config(path: PathBuf) -> Res<()> {
    let loaded = Config::load_file(&path).map_err(|e| format!("loading config: {e}"))?;
    for w in &loaded.warnings {
        eprintln!("warning: {w}");
    }
    let c = &loaded.config;
    println!(
        "{} is valid: {} user(s), portal {}, cookie domain {}, sessions last {}s.",
        path.display(),
        c.users.len(),
        c.server.portal_url,
        c.session.domain,
        c.session.expiry.as_secs()
    );
    Ok(())
}

fn healthcheck(addr: SocketAddr) -> Res<()> {
    use std::io::{Read, Write};
    use std::time::Duration;
    let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.set_write_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = [0u8; 12];
    s.read_exact(&mut buf)?;
    if buf.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err(format!("unhealthy: {}", String::from_utf8_lossy(&buf)).into())
    }
}

fn hash_password(from_stdin: bool) -> Res<()> {
    let pw = if from_stdin || !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\n', '\r']).to_owned()
    } else {
        let a = rpassword::prompt_password("Password: ")?;
        let b = rpassword::prompt_password("Again: ")?;
        if a != b {
            return Err("the passwords did not match".into());
        }
        a
    };
    if !pw.is_empty() && pw.chars().count() < 8 {
        eprintln!("warning: that password is shorter than 8 characters");
    }
    println!("{}", password::hash(&pw)?);
    Ok(())
}

fn log_level() -> LevelFilter {
    std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(LevelFilter::INFO)
}

fn serve(path: PathBuf) -> Res<()> {
    tracing_subscriber::fmt()
        .with_max_level(log_level())
        .with_ansi(false)
        .init();
    let config = load(&path)?;
    let addr = config.server.address;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(config, addr))
}

async fn run(config: Config, addr: SocketAddr) -> Res<()> {
    let portal = config.server.portal_url.clone();
    let users = config.users.len();
    let state =
        AppState::try_new(config).map_err(|e| format!("loading session.revocation_file: {e}"))?;
    let app = rs_auth::router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("binding {addr}: {e}"))?;
    tracing::info!(%addr, %portal, users, "rs-auth listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    tracing::info!("rs-auth stopped");
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn cfg(a: &[&str]) -> PathBuf {
        match parse_args(args(a)).unwrap().unwrap() {
            Command::Serve { config } | Command::CheckConfig { config } => config,
            _ => panic!("not a config command"),
        }
    }

    #[test]
    fn config_flag_forms() {
        assert_eq!(cfg(&["serve", "-c", "a.yaml"]), PathBuf::from("a.yaml"));
        assert_eq!(
            cfg(&["serve", "--config", "b.yaml"]),
            PathBuf::from("b.yaml")
        );
        assert_eq!(
            cfg(&["check-config", "--config=c.yaml"]),
            PathBuf::from("c.yaml")
        );
    }

    #[test]
    fn bad_input_is_an_error() {
        assert!(parse_args(args(&[])).is_err());
        assert!(parse_args(args(&["nope"])).is_err());
        assert!(parse_args(args(&["serve", "-c"])).is_err());
        assert!(parse_args(args(&["serve", "--wat"])).is_err());
        assert!(parse_args(args(&["hash-password", "--wat"])).is_err());
        assert!(parse_args(args(&["healthcheck", "not-an-address"])).is_err());
    }

    #[test]
    fn simple_commands() {
        assert!(matches!(
            parse_args(args(&["hash-password", "--stdin"])).unwrap(),
            Some(Command::HashPassword { stdin: true })
        ));
        assert!(matches!(
            parse_args(args(&["healthcheck", "127.0.0.1:1234"])).unwrap(),
            Some(Command::Healthcheck { .. })
        ));
        assert!(parse_args(args(&["--help"])).unwrap().is_none());
    }
}
