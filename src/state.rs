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
pub const MAX_QUEUED_LOGINS: usize = 16;
pub const USER_BUCKETS: u64 = 4096;

pub struct AppState {
    pub config: Config,
    pub signer: Box<dyn TokenSigner>,
    pub limiter: RateLimiter,
    pub user_limiter: Option<RateLimiter<u64>>,
    pub dummy_hash: String,
    pub hash_permits: Arc<Semaphore>,
    pub login_slots: Arc<Semaphore>,
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
        revocations.persist()?;
        let signer = Box::new(Hs256Signer::new(&config.session.secret, &config.issuer()));
        let limiter = RateLimiter::new(config.login.max_attempts, config.login.window);
        let user_limiter = (config.login.max_attempts_per_user > 0).then(|| {
            RateLimiter::with_capacity(
                config.login.max_attempts_per_user,
                config.login.window,
                usize::try_from(USER_BUCKETS).unwrap_or(usize::MAX) + 1,
            )
        });
        let permits = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .clamp(1, MAX_CONCURRENT_HASHES);
        Ok(Arc::new(Self {
            revocations,
            signer,
            limiter,
            user_limiter,
            dummy_hash: password::dummy_hash(
                config
                    .users
                    .values()
                    .next()
                    .map(|u| u.password_hash.as_str()),
            ),
            hash_permits: Arc::new(Semaphore::new(permits)),
            login_slots: Arc::new(Semaphore::new(permits + MAX_QUEUED_LOGINS)),
            config,
        }))
    }

    pub fn fingerprint(&self, user: &User) -> String {
        token::password_fingerprint(&self.config.session.secret, &user.password_hash)
    }

    pub fn session_until(&self, claims: &Claims) -> u64 {
        claims.exp + token::LEEWAY_SECS
    }

    pub fn user_bucket(&self, username: &str) -> u64 {
        use hmac::{KeyInit, Mac};
        let Ok(mut m) = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.config.session.secret)
        else {
            return 0;
        };
        m.update(b"rs-auth login user\0");
        m.update(username.as_bytes());
        let d = m.finalize().into_bytes();
        let mut first = [0u8; 8];
        first.copy_from_slice(d.get(..8).unwrap_or(&[0; 8]));
        u64::from_be_bytes(first) % USER_BUCKETS
    }

    pub fn signed_claims(&self, jar: &CookieJar) -> Option<Claims> {
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
        Some(claims)
    }

    pub fn unsaved_sign_out(&self, jar: &CookieJar) -> Option<Claims> {
        let claims = self.signed_claims(jar)?;
        (self.revocations.is_revoked(&claims.jti, claims.iat) && !self.revocations.is_saved())
            .then_some(claims)
    }

    pub fn session_user(&self, jar: &CookieJar) -> Option<SessionUser<'_>> {
        let claims = self.signed_claims(jar)?;
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
