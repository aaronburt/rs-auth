#![forbid(unsafe_code)]

use std::io::{BufRead, IsTerminal};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use rs_auth::{AppState, Config, password};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "rs-auth",
    version,
    about = "A small forward-auth login portal for Traefik and Caddy"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(short, long, env = "RS_AUTH_CONFIG", default_value = "config.yaml")]
        config: PathBuf,
    },
    HashPassword {
        #[arg(long)]
        stdin: bool,
    },
    CheckConfig {
        #[arg(short, long, env = "RS_AUTH_CONFIG", default_value = "config.yaml")]
        config: PathBuf,
    },
    Healthcheck {
        #[arg(default_value = "127.0.0.1:9091")]
        address: SocketAddr,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve { config } => serve(config),
        Command::HashPassword { stdin } => hash_password(stdin),
        Command::CheckConfig { config } => check_config(config),
        Command::Healthcheck { address } => healthcheck(address),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn load(path: &std::path::Path) -> anyhow::Result<Config> {
    let loaded = Config::load_file(path).context("loading config")?;
    for w in &loaded.warnings {
        tracing::warn!("{w}");
        if !tracing::enabled!(tracing::Level::WARN) {
            eprintln!("warning: {w}");
        }
    }
    Ok(loaded.config)
}

fn check_config(path: PathBuf) -> anyhow::Result<()> {
    let loaded = Config::load_file(&path).context("loading config")?;
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

fn healthcheck(addr: SocketAddr) -> anyhow::Result<()> {
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
        bail!("unhealthy: {}", String::from_utf8_lossy(&buf))
    }
}

fn hash_password(from_stdin: bool) -> anyhow::Result<()> {
    let pw = if from_stdin || !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\n', '\r']).to_owned()
    } else {
        let a = rpassword::prompt_password("Password: ")?;
        let b = rpassword::prompt_password("Again: ")?;
        if a != b {
            bail!("the passwords did not match");
        }
        a
    };
    if !pw.is_empty() && pw.chars().count() < 8 {
        eprintln!("warning: that password is shorter than 8 characters");
    }
    let h = password::hash(&pw).map_err(anyhow::Error::msg)?;
    println!("{h}");
    Ok(())
}

fn serve(path: PathBuf) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let config = load(&path)?;
    let addr = config.server.address;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(config, addr))
}

async fn run(config: Config, addr: SocketAddr) -> anyhow::Result<()> {
    let portal = config.server.portal_url.clone();
    let users = config.users.len();
    let state = AppState::new(config);
    let app = rs_auth::router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
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
