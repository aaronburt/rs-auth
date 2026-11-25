use std::sync::Arc;

use crate::cookie::CookieJar;
use tokio::sync::Semaphore;

use crate::config::{Config, User};
use crate::lockout::Lockout;
use crate::password;
use crate::revoke::Revocations;
use crate::token::{self, Claims, Hs256Signer, TokenError, TokenSigner};
use crate::totp;
use crate::totp::Replay;

pub type SharedState = Arc<AppState>;

pub const MAX_CONCURRENT_HASHES: usize = 4;

pub struct AppState {
    pub config: Config,
    pub signer: Box<dyn TokenSigner>,
    pub lockout: Lockout,
    pub totp: Replay,
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
        revocations.persist()?;
        let signer = Box::new(Hs256Signer::new(&config.session.secret, &config.issuer()));
        let lockout = Lockout::new(
            config.login.max_attempts,
            config.login.window,
            &config.session.secret,
        );
        let permits = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .clamp(1, MAX_CONCURRENT_HASHES);
        Ok(Arc::new(Self {
            revocations,
            signer,
            lockout,
            totp: Replay::default(),
            hash_permits: Arc::new(Semaphore::new(permits)),
            config,
        }))
    }

    pub fn fingerprint(&self, user: &User) -> String {
        let material = match &user.totp_secret {
            Some(secret) => format!("{}\0{}", user.password_hash, totp::encode_secret(secret)),
            None => user.password_hash.clone(),
        };
        token::password_fingerprint(&self.config.session.secret, &material)
    }

    pub fn session_until(&self, claims: &Claims) -> u64 {
        claims.exp + token::LEEWAY_SECS
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

    pub async fn check_password(&self, hash: String, password: String) -> bool {
        let Ok(permit) = Arc::clone(&self.hash_permits).acquire_owned().await else {
            return false;
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            password::verify(&password, &hash)
        })
        .await
        .unwrap_or(false)
    }
}
