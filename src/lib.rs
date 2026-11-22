#![forbid(unsafe_code)]

pub mod access;
pub mod cli;
pub mod commands;
pub mod config;
pub mod cookie;
pub mod csrf;
pub mod net;
pub mod password;
pub mod random;
pub mod ratelimit;
pub mod redirect;
pub mod revoke;
pub mod routes;
pub mod state;
pub mod token;
pub mod totp;
pub mod ui;

pub use config::Config;
pub use routes::router;
pub use state::{AppState, SharedState};
