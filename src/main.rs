#![forbid(unsafe_code)]

use std::error::Error;
use std::io::{BufRead, IsTerminal};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use rs_auth::cli::{Command, USAGE, parse_args};
use rs_auth::{AppState, Config, password};
use tracing::level_filters::LevelFilter;

type Res<T> = Result<T, Box<dyn Error>>;

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
