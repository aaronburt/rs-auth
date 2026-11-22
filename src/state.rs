use std::sync::Arc;

use crate::cookie::CookieJar;
use tokio::sync::Semaphore;

use crate::config::{Config, User};
use crate::password;
use crate::ratelimit::RateLimiter;
use crate::revoke::Revocations;
use crate::token::{self, Claims, Hs256Signer, TokenError, TokenSigner};

pub type SharedState = Arc<AppState>;

pub const MAX_CONCURRENT_HASHES: usize = 4;

pub struct AppState {
    pub config: Config,
    pub signer: Box<dyn TokenSigner>,
    pub limiter: RateLimiter,
    pub dummy_hash: String,
    pub hash_permits: Arc<Semaphore>,
    pub revocations: Arc<Revocations>,
}

pub struct SessionUser<'a> {
    pub username: &'a str,
    pub user: &'a User,
    pub claims: Claims,
}

impl AppState {
    pub fn new(config: Config) -> SharedState {
        Self::try_new(config).expect("loading the revocation list")
    }

    pub fn try_new(config: Config) -> std::io::Result<SharedState> {
        let revocations = Arc::new(Revocations::load(
            config.session.revocation_file.as_deref(),
            token::now(),
        )?);
        let signer = Box::new(Hs256Signer::new(&config.session.secret, &config.issuer()));
        let limiter = RateLimiter::new(config.login.max_attempts, config.login.window);
        let permits = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .clamp(1, MAX_CONCURRENT_HASHES);
        Ok(Arc::new(Self {
            revocations,
            signer,
            limiter,
            dummy_hash: password::dummy_hash(
                config
                    .users
                    .values()
                    .next()
                    .map(|u| u.password_hash.as_str()),
            ),
            hash_permits: Arc::new(Semaphore::new(permits)),
            config,
        }))
    }

    pub fn fingerprint(&self, user: &User) -> String {
        token::password_fingerprint(&self.config.session.secret, &user.password_hash)
    }

    pub fn session_until(&self, claims: &Claims) -> u64 {
        claims.exp + token::LEEWAY_SECS
    }

    pub fn session_user(&self, jar: &CookieJar) -> Option<SessionUser<'_>> {
        let token = jar.get(&self.config.session.cookie_name)?;
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
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            claims.pwh.as_bytes(),
            self.fingerprint(user).as_bytes(),
        )) {
            tracing::debug!(user = %claims.sub, "session from before a password change");
            return None;
        }
        if self.revocations.is_revoked(&claims.jti, claims.iat) {
            tracing::debug!(user = %claims.sub, "session was signed out");
            return None;
        }
        Some(SessionUser {
            username,
            user,
            claims,
        })
    }

    pub async fn check_password(&self, username: &str, password: String) -> Option<&User> {
        let permit = Arc::clone(&self.hash_permits).acquire_owned().await.ok()?;
        let (hash, user) = match self.config.users.get(username) {
            Some(u) => (u.password_hash.clone(), Some(u)),
            None => (self.dummy_hash.clone(), None),
        };
        let ok = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            password::verify(&password, &hash)
        })
        .await
        .unwrap_or(false);
        if ok { user } else { None }
    }
}
