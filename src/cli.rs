use std::net::SocketAddr;
use std::path::PathBuf;

pub const USAGE: &str = "\
rs-auth: a small forward-auth login portal for Traefik and Caddy

Usage:
  rs-auth serve [-c, --config <file>]    Run the portal
  rs-auth hash-password [--stdin]        Print an Argon2id hash for a password
  rs-auth totp-secret [username]         Print a new TOTP secret (and an otpauth:// link for the user)
  rs-auth check-config [-c <file>]       Validate the config without starting
  rs-auth healthcheck [address]          Exit 0 if /healthz answers (default 127.0.0.1:9091)
  rs-auth --version | --help

The config file defaults to $RS_AUTH_CONFIG, then config.toml.
The log level comes from RUST_LOG (error, warn, info, debug or trace; default info).";

pub enum Command {
    Serve { config: PathBuf },
    HashPassword { stdin: bool },
    TotpSecret { account: Option<String> },
    CheckConfig { config: PathBuf },
    Healthcheck { address: SocketAddr },
    Version,
}

pub fn parse_args(args: Vec<String>) -> Result<Option<Command>, String> {
    let default_config = || {
        std::env::var_os("RS_AUTH_CONFIG")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("config.toml"))
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
        "totp-secret" => match rest.as_slice() {
            [] => Ok(Some(Command::TotpSecret { account: None })),
            [a] if !a.starts_with('-') => Ok(Some(Command::TotpSecret {
                account: Some(a.clone()),
            })),
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
        assert_eq!(cfg(&["serve", "-c", "a.toml"]), PathBuf::from("a.toml"));
        assert_eq!(
            cfg(&["serve", "--config", "b.toml"]),
            PathBuf::from("b.toml")
        );
        assert_eq!(
            cfg(&["check-config", "--config=c.toml"]),
            PathBuf::from("c.toml")
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
