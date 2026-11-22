#![forbid(unsafe_code)]

use std::io::{BufRead, IsTerminal};
use std::path::Path;
use std::process::ExitCode;

use rs_auth::cli::{Command, USAGE, parse_args};
use rs_auth::commands::{self, Res};

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
        Command::Serve { config } => serve(&config),
        Command::HashPassword { stdin } => hash_password(stdin),
        Command::CheckConfig { config } => check_config(&config),
        Command::Healthcheck { address } => commands::healthcheck(address),
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

fn check_config(path: &Path) -> Res<()> {
    let checked = commands::check_config(path)?;
    for w in &checked.warnings {
        eprintln!("warning: {w}");
    }
    println!("{}", checked.summary);
    Ok(())
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
    let (hash, warning) = commands::hash_for(&pw)?;
    if let Some(w) = warning {
        eprintln!("warning: {w}");
    }
    println!("{hash}");
    Ok(())
}

fn serve(path: &Path) -> Res<()> {
    tracing_subscriber::fmt()
        .with_max_level(commands::log_level(
            std::env::var("RUST_LOG").ok().as_deref(),
        ))
        .with_ansi(false)
        .init();
    let config = commands::load_config(path)?;
    let addr = config.server.address;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| format!("binding {addr}: {e}"))?;
            commands::serve_on(config, listener, shutdown()).await
        })
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
