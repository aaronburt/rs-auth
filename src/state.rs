//! Everything the handlers share, built once at startup.

use std::sync::Arc;

use axum_extra::extract::cookie::CookieJar;
use tokio::sync::Semaphore;

use crate::config::{Config, User};
use crate::password;
use crate::ratelimit::RateLimiter;
use crate::token::{Hs256Signer, TokenError, TokenSigner};

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub config: Config,
    pub signer: Box<dyn TokenSigner>,
    pub limiter: RateLimiter,
    /// Verified against when the username is unknown, so timing matches.
    pub dummy_hash: String,
    /// Caps how many Argon2 checks run at once. Each one uses 64 MiB.
    pub hash_permits: Semaphore,
}

/// A request's signed-in user, with live data from the config.
pub struct SessionUser<'a> {
    pub username: &'a str,
    pub user: &'a User,
}

impl AppState {
    pub fn new(config: Config) -> SharedState {
        let signer = Box::new(Hs256Signer::new(&config.session.secret, &config.issuer()));
        let limiter = RateLimiter::new(config.login.max_attempts, config.login.window);
        let permits = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .clamp(1, 8);
        Arc::new(Self {
            signer,
            limiter,
            dummy_hash: password::dummy_hash(),
            hash_permits: Semaphore::new(permits),
            config,
        })
    }

    /// The signed-in user, if the request carries a valid session cookie.
    ///
    /// Valid means: good signature, our issuer, not expired, the current
    /// `session.version`, and the user still exists in the config.
    pub fn session_user(&self, jar: &CookieJar) -> Option<SessionUser<'_>> {
        let token = jar.get(&self.config.session.cookie_name)?.value();
        if token.is_empty() {
            return None;
        }
        let claims = match self.signer.verify(token) {
            Ok(c) => c,
            Err(TokenError::Expired) => {
                tracing::debug!("session expired");
                return None;
            }
            Err(_) => {
                tracing::debug!("session token rejected");
                return None;
            }
        };
        if claims.ver != self.config.session.version {
            tracing::debug!(user = %claims.sub, "session from an old session.version");
            return None;
        }
        let (username, user) = self.config.users.get_key_value(&claims.sub)?;
        Some(SessionUser { username, user })
    }

    /// Check a username and password. Unknown users still run a full Argon2
    /// verify against a dummy hash. Runs on the blocking pool.
    pub async fn check_password(self: &Arc<Self>, username: &str, password: String) -> bool {
        let Ok(_permit) = self.hash_permits.acquire().await else {
            return false;
        };
        let (hash, known) = match self.config.users.get(username) {
            Some(u) => (u.password_hash.clone(), true),
            None => (self.dummy_hash.clone(), false),
        };
        let ok = tokio::task::spawn_blocking(move || password::verify(&password, &hash))
            .await
            .unwrap_or(false);
        ok && known
    }
}
