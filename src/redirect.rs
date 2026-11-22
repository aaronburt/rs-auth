use axum::http::HeaderMap;
use url::Url;

use crate::config::{Config, host_in_domain};

pub fn original_url(headers: &HeaderMap) -> Option<Url> {
    let get = |name: &str| {
        headers
            .get_all(name)
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let proto = get("x-forwarded-proto")?.to_ascii_lowercase();
    if proto != "https" && proto != "http" {
        return None;
    }
    let host = get("x-forwarded-host")?;
    if host.contains(['/', '\\', '@', '?', '#']) {
        return None;
    }
    let uri = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/");
    let uri = if uri.starts_with('/') && !uri.starts_with("//") {
        uri
    } else {
        "/"
    };
    let url = Url::parse(&format!("{proto}://{host}{uri}")).ok()?;
    (url.host_str().is_some() && url.username().is_empty() && url.password().is_none())
        .then_some(url)
}

pub fn validate_rd(config: &Config, rd: &str) -> Option<Url> {
    let rd = rd.trim();
    if rd.is_empty() || rd.len() > 4096 {
        return None;
    }
    let url = Url::parse(rd).ok()?;
    match url.scheme() {
        "https" => {}
        "http" if config.server.insecure_dev_mode => {}
        _ => return None,
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    host_in_domain(&host, &config.session.domain).then_some(url)
}

pub fn target(config: &Config, rd: Option<&str>) -> Url {
    rd.and_then(|r| validate_rd(config, r))
        .unwrap_or_else(|| config.server.default_redirect_url.clone())
}

pub fn login_url(config: &Config, rd: Option<&Url>) -> Url {
    let mut u = config.server.portal_url.join("login").expect("static path");
    if let Some(rd) = rd {
        u.query_pairs_mut().append_pair("rd", rd.as_str());
    }
    u
}
