use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

use crate::password;

pub const MIN_SECRET_LEN: usize = 32;
pub const SECRET_ENV: &str = "RS_AUTH_JWT_SECRET";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read {}: {error}", path.display())]
    Read {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("config is not valid YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(msg.into()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HumanDuration(pub Duration);

impl fmt::Debug for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0.as_secs())
    }
}

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("duration {s:?} needs a unit: s, m, h or d"))?;
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("duration {s:?} must start with a whole number"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => {
            return Err(format!(
                "duration {s:?} has unknown unit {unit:?}; use s, m, h or d"
            ));
        }
    };
    let secs = n
        .checked_mul(mult)
        .ok_or_else(|| format!("duration {s:?} is too large"))?;
    if secs == 0 {
        return Err(format!("duration {s:?} must be greater than zero"));
    }
    Ok(Duration::from_secs(secs))
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_duration(&s)
            .map(HumanDuration)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    server: RawServer,
    session: RawSession,
    #[serde(default)]
    login: RawLogin,
    users: BTreeMap<String, RawUser>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    #[serde(default = "default_address")]
    address: SocketAddr,
    portal_url: String,
    #[serde(default)]
    trusted_proxies: Vec<String>,
    #[serde(default)]
    default_redirect_url: Option<String>,
    #[serde(default)]
    insecure_dev_mode: bool,
}

fn default_address() -> SocketAddr {
    "0.0.0.0:9091".parse().expect("static address")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSession {
    domain: String,
    #[serde(default = "default_cookie_name")]
    cookie_name: String,
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default = "default_expiry")]
    expiry: HumanDuration,
    #[serde(default)]
    jwt_secret_file: Option<PathBuf>,
    #[serde(default)]
    jwt_secret: Option<String>,
}

fn default_cookie_name() -> String {
    "rs_auth_session".into()
}
fn default_version() -> u32 {
    1
}
fn default_expiry() -> HumanDuration {
    HumanDuration(Duration::from_secs(12 * 3600))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLogin {
    #[serde(default = "default_max_attempts")]
    max_attempts: u32,
    #[serde(default = "default_window")]
    window: HumanDuration,
}

impl Default for RawLogin {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            window: default_window(),
        }
    }
}

fn default_max_attempts() -> u32 {
    5
}
fn default_window() -> HumanDuration {
    HumanDuration(Duration::from_secs(300))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUser {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    password: String,
}

#[derive(Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub session: SessionConfig,
    pub login: LoginConfig,
    pub users: BTreeMap<String, User>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub address: SocketAddr,
    pub portal_url: Url,
    pub trusted_proxies: Vec<IpNet>,
    pub default_redirect_url: Url,
    pub insecure_dev_mode: bool,
}

#[derive(Clone)]
pub struct SessionConfig {
    pub domain: String,
    pub cookie_name: String,
    pub version: u32,
    pub expiry: Duration,
    pub secret: Vec<u8>,
}

impl fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionConfig")
            .field("domain", &self.domain)
            .field("cookie_name", &self.cookie_name)
            .field("version", &self.version)
            .field("expiry", &self.expiry)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct LoginConfig {
    pub max_attempts: u32,
    pub window: Duration,
}

#[derive(Clone)]
pub struct User {
    pub display_name: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub password_hash: String,
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("display_name", &self.display_name)
            .field("email", &self.email)
            .field("groups", &self.groups)
            .field("password_hash", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("server", &self.server)
            .field("session", &self.session)
            .field("login", &self.login)
            .field("users", &self.users)
            .finish()
    }
}

#[derive(Debug)]
pub struct Loaded {
    pub config: Config,
    pub warnings: Vec<String>,
}

pub trait Environment {
    fn var(&self, name: &str) -> Option<String>;
    fn read_file(&self, path: &Path) -> std::io::Result<Vec<u8>>;
}

pub struct RealEnvironment;

impl Environment for RealEnvironment {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
    fn read_file(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }
}

impl Config {
    pub fn load_file(path: &Path) -> Result<Loaded, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|error| ConfigError::Read {
            path: path.to_owned(),
            error,
        })?;
        let mut loaded = Self::from_yaml(&text, &RealEnvironment)?;
        if let Some(w) = permission_warning(path) {
            loaded.warnings.push(w);
        }
        Ok(loaded)
    }

    pub fn from_yaml(text: &str, env: &dyn Environment) -> Result<Loaded, ConfigError> {
        let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
        let raw: RawConfig = serde_yaml_ng::from_str(text)?;
        let mut warnings = Vec::new();

        let insecure = raw.server.insecure_dev_mode;
        if insecure {
            warnings.push(
                "server.insecure_dev_mode is on: cookies are not marked Secure. Never use this in production."
                    .into(),
            );
        }

        let portal_url = parse_url("server.portal_url", &raw.server.portal_url, insecure)?;
        if portal_url.query().is_some() || portal_url.fragment().is_some() {
            return invalid("server.portal_url must not have a query or fragment");
        }
        if portal_url.path() != "/" {
            return invalid(
                "server.portal_url must be the root of its own host, like https://auth.example.com",
            );
        }

        if raw.server.trusted_proxies.is_empty() {
            return invalid(
                "server.trusted_proxies must list at least one address or CIDR, such as 172.18.0.0/16. \
                 Only requests from these addresses can call /api/verify.",
            );
        }
        let mut trusted_proxies = Vec::new();
        for p in &raw.server.trusted_proxies {
            trusted_proxies.push(parse_net(p)?);
        }

        let domain = raw
            .session
            .domain
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase();
        if domain.is_empty() || !domain.contains('.') && domain != "localhost" {
            return invalid(format!(
                "session.domain {:?} must be a domain like example.com",
                raw.session.domain
            ));
        }
        if domain.parse::<std::net::IpAddr>().is_ok() {
            return invalid(format!(
                "session.domain {domain:?} must be a domain name, not an IP address"
            ));
        }
        if domain
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
            || !domain
                .split('.')
                .all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'))
        {
            return invalid(format!(
                "session.domain {domain:?} has characters that are not allowed"
            ));
        }

        let portal_host = portal_url
            .host_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !host_in_domain(&portal_host, &domain) {
            return invalid(format!(
                "server.portal_url host {portal_host:?} must be {domain} or a subdomain of it, \
                 or the session cookie will not reach the portal"
            ));
        }

        let default_redirect_url = match &raw.server.default_redirect_url {
            Some(s) => {
                let u = parse_url("server.default_redirect_url", s, insecure)?;
                let h = u.host_str().unwrap_or_default().to_ascii_lowercase();
                if !host_in_domain(&h, &domain) {
                    return invalid(format!(
                        "server.default_redirect_url host {h:?} must be {domain} or a subdomain of it"
                    ));
                }
                u
            }
            None => portal_url.join("logged-in").expect("static path"),
        };

        let cookie_name = raw.session.cookie_name.clone();
        if cookie_name.is_empty()
            || !cookie_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return invalid("session.cookie_name may only use letters, digits, '_' and '-'");
        }
        if cookie_name == crate::csrf::SECURE_COOKIE_NAME
            || cookie_name == crate::csrf::DEV_COOKIE_NAME
        {
            return invalid(format!(
                "session.cookie_name cannot be {cookie_name:?}, which rs-auth uses for its CSRF cookie"
            ));
        }

        let secret = resolve_secret(&raw.session, env, &mut warnings)?;
        if let Some(w) = raw
            .session
            .jwt_secret_file
            .as_deref()
            .and_then(permission_warning)
        {
            warnings.push(w);
        }

        let expiry = raw.session.expiry.0;
        if expiry < Duration::from_secs(60) {
            return invalid("session.expiry must be at least 1m");
        }
        if expiry > Duration::from_secs(400 * 86_400) {
            return invalid("session.expiry must be at most 400d");
        }

        if raw.login.max_attempts == 0 {
            return invalid("login.max_attempts must be at least 1");
        }

        if raw.users.is_empty() {
            return invalid("users must list at least one user");
        }
        let mut users = BTreeMap::new();
        for (name, u) in raw.users {
            validate_username(&name)?;
            if let Err(e) = password::check_phc(&u.password) {
                return invalid(format!("users.{name}.password: {e}"));
            }
            if password::weak_params(&u.password) {
                warnings.push(format!(
                    "users.{name}.password uses weak Argon2 settings. Re-hash it with `rs-auth hash-password`."
                ));
            }
            for g in &u.groups {
                if g.is_empty()
                    || g.contains(',')
                    || g.chars().any(|c| c.is_control() || c.is_whitespace())
                {
                    return invalid(format!(
                        "users.{name}.groups: {g:?} must be non-empty with no commas or spaces"
                    ));
                }
            }
            let display_name = u.display_name.unwrap_or_else(|| name.clone());
            if display_name.chars().any(char::is_control) {
                return invalid(format!("users.{name}.display_name has control characters"));
            }
            if let Some(email) = &u.email
                && (email.chars().any(|c| c.is_control() || c.is_whitespace())
                    || !email
                        .split_once('@')
                        .is_some_and(|(l, r)| !l.is_empty() && !r.is_empty() && !r.contains('@')))
            {
                return invalid(format!(
                    "users.{name}.email {email:?} does not look like an email address"
                ));
            }
            users.insert(
                name,
                User {
                    display_name,
                    email: u.email,
                    groups: u.groups,
                    password_hash: u.password,
                },
            );
        }

        Ok(Loaded {
            config: Config {
                server: ServerConfig {
                    address: raw.server.address,
                    portal_url,
                    trusted_proxies,
                    default_redirect_url,
                    insecure_dev_mode: insecure,
                },
                session: SessionConfig {
                    domain,
                    cookie_name,
                    version: raw.session.version,
                    expiry,
                    secret,
                },
                login: LoginConfig {
                    max_attempts: raw.login.max_attempts,
                    window: raw.login.window.0,
                },
                users,
            },
            warnings,
        })
    }

    pub fn issuer(&self) -> String {
        self.server.portal_url.origin().ascii_serialization()
    }
}

fn parse_url(field: &str, s: &str, insecure: bool) -> Result<Url, ConfigError> {
    let u = Url::parse(s)
        .map_err(|e| ConfigError::Invalid(format!("{field} {s:?} is not a URL: {e}")))?;
    match u.scheme() {
        "https" => {}
        "http" if insecure => {}
        "http" => {
            return invalid(format!(
                "{field} must use https (http needs server.insecure_dev_mode)"
            ));
        }
        other => return invalid(format!("{field} has unsupported scheme {other:?}")),
    }
    if u.host_str().is_none() {
        return invalid(format!("{field} must have a host"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return invalid(format!("{field} must not contain a username or password"));
    }
    Ok(u)
}

fn unmap(n: IpNet) -> IpNet {
    if let IpNet::V6(v6) = n
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.network().to_ipv4_mapped()
        && let Ok(net) = ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96)
    {
        return IpNet::V4(net);
    }
    n
}

fn parse_net(s: &str) -> Result<IpNet, ConfigError> {
    let s = s.trim();
    if let Ok(n) = s.parse::<IpNet>() {
        return Ok(unmap(n.trunc()));
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(unmap(IpNet::from(ip)));
    }
    invalid(format!(
        "server.trusted_proxies entry {s:?} is not an IP address or CIDR"
    ))
}

fn validate_username(name: &str) -> Result<(), ConfigError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
    if ok {
        Ok(())
    } else {
        invalid(format!(
            "username {name:?} may only use letters, digits, '.', '_', '-' and '@' (up to 64)"
        ))
    }
}

fn resolve_secret(
    s: &RawSession,
    env: &dyn Environment,
    warnings: &mut Vec<String>,
) -> Result<Vec<u8>, ConfigError> {
    let (secret, source) = if let Some(path) = &s.jwt_secret_file {
        let bytes = env.read_file(path).map_err(|error| ConfigError::Read {
            path: path.clone(),
            error,
        })?;
        (trim_trailing_newline(bytes), "session.jwt_secret_file")
    } else if let Some(v) = env.var(SECRET_ENV) {
        (v.into_bytes(), SECRET_ENV)
    } else if let Some(v) = &s.jwt_secret {
        warnings.push(
            "session.jwt_secret is set in the config file. Prefer jwt_secret_file or the RS_AUTH_JWT_SECRET env var."
                .into(),
        );
        (v.clone().into_bytes(), "session.jwt_secret")
    } else {
        return invalid(format!(
            "no JWT secret: set session.jwt_secret_file, the {SECRET_ENV} env var, or session.jwt_secret"
        ));
    };
    if secret.len() < MIN_SECRET_LEN {
        return invalid(format!(
            "the JWT secret from {source} is {} bytes; it must be at least {MIN_SECRET_LEN}. \
             Try: openssl rand -hex 32",
            secret.len()
        ));
    }
    Ok(secret)
}

fn trim_trailing_newline(mut b: Vec<u8>) -> Vec<u8> {
    while matches!(b.last(), Some(b'\n' | b'\r')) {
        b.pop();
    }
    b
}

pub fn host_in_domain(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len() + 1
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

#[cfg(unix)]
fn permission_warning(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    (mode & 0o004 != 0).then(|| {
        format!(
            "{} is world-readable (mode {:o}). Run: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn permission_warning(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("12h").unwrap(), Duration::from_secs(43_200));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert!(parse_duration("12").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("0m").is_err());
        assert!(parse_duration("5w").is_err());
        assert!(parse_duration("-5m").is_err());
        assert!(parse_duration("99999999999999999999d").is_err());
    }

    #[test]
    fn domains() {
        assert!(host_in_domain("example.com", "example.com"));
        assert!(host_in_domain("auth.example.com", "example.com"));
        assert!(host_in_domain("a.b.example.com", "example.com"));
        assert!(!host_in_domain("badexample.com", "example.com"));
        assert!(!host_in_domain("example.com.evil.net", "example.com"));
        assert!(!host_in_domain("com", "example.com"));
        assert!(!host_in_domain(".example.com", "example.com"));
    }
}
