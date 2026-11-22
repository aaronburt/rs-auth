use std::error::Error;
use std::future::Future;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use tracing::level_filters::LevelFilter;

use crate::{AppState, Config, password};

pub type Res<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub struct Checked {
    pub warnings: Vec<String>,
    pub summary: String,
}

pub fn load_config(path: &Path) -> Res<Config> {
    let loaded = Config::load_file(path).map_err(|e| format!("loading config: {e}"))?;
    for w in &loaded.warnings {
        tracing::warn!("{w}");
    }
    Ok(loaded.config)
}

pub fn check_config(path: &Path) -> Res<Checked> {
    let loaded = Config::load_file(path).map_err(|e| format!("loading config: {e}"))?;
    let c = &loaded.config;
    let summary = format!(
        "{} is valid: {} user(s), portal {}, cookie domain {}, sessions last {}s.",
        path.display(),
        c.users.len(),
        c.server.portal_url,
        c.session.domain,
        c.session.expiry.as_secs()
    );
    Ok(Checked {
        warnings: loaded.warnings,
        summary,
    })
}

pub fn healthcheck(addr: SocketAddr) -> Res<()> {
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

pub fn hash_for(pw: &str) -> Res<(String, Option<&'static str>)> {
    let warning = (!pw.is_empty() && pw.chars().count() < 8)
        .then_some("that password is shorter than 8 characters");
    Ok((password::hash(pw)?, warning))
}

pub fn log_level(rust_log: Option<&str>) -> LevelFilter {
    rust_log
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse().ok())
        .unwrap_or(LevelFilter::INFO)
}

pub async fn serve_on(
    config: Config,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Res<()> {
    let portal = config.server.portal_url.clone();
    let users = config.users.len();
    let state =
        AppState::try_new(config).map_err(|e| format!("loading session.revocation_file: {e}"))?;
    let app = crate::router(state);
    tracing::info!(addr = ?listener.local_addr().ok(), %portal, users, "rs-auth listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    tracing::info!("rs-auth stopped");
    Ok(())
}
