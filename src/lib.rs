//! rs-auth: a small forward-auth login portal for Traefik and Caddy.
//!
//! The reverse proxy asks `GET /api/verify` on every request. A valid session
//! cookie gets `200` with `Remote-*` headers; anything else gets a `302` to
//! the login page. Users and settings come from one YAML file.

#![forbid(unsafe_code)]

pub mod config;
pub mod cookie;
pub mod csrf;
pub mod net;
pub mod password;
pub mod ratelimit;
pub mod redirect;
pub mod routes;
pub mod state;
pub mod token;
pub mod ui;

pub use config::Config;
pub use routes::router;
pub use state::{AppState, SharedState};
