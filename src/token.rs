//! Session tokens: JWT claims, signing and verification.
//!
//! Signing sits behind [`TokenSigner`] so a later OIDC phase can swap the
//! HS256 secret for RS256 or EdDSA keys without touching the handlers.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// Clock leeway allowed when checking `exp`, in seconds.
pub const LEEWAY_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    /// The username key from the YAML.
    pub sub: String,
    /// Groups at login time. Informational only: verify reads live groups
    /// from the config.
    #[serde(default)]
    pub groups: Vec<String>,
    pub iat: u64,
    pub exp: u64,
    /// Must equal `session.version` for the token to be accepted.
    pub ver: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("token could not be signed")]
    Sign,
    #[error("token is invalid")]
    Invalid,
    #[error("token has expired")]
    Expired,
}

pub trait TokenSigner: Send + Sync {
    fn sign(&self, claims: &Claims) -> Result<String, TokenError>;
    /// Check signature, algorithm, issuer and expiry, and return the claims.
    fn verify(&self, token: &str) -> Result<Claims, TokenError>;
}

pub struct Hs256Signer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
}

impl Hs256Signer {
    pub fn new(secret: &[u8], issuer: &str) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.algorithms = vec![Algorithm::HS256];
        validation.leeway = LEEWAY_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.set_issuer(&[issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        Self {
            encoding: EncodingKey::from_secret(secret).expect("HS256 secret is validated at load"),
            decoding: DecodingKey::from_secret(secret).expect("HS256 secret is validated at load"),
            validation,
        }
    }
}

impl TokenSigner for Hs256Signer {
    fn sign(&self, claims: &Claims) -> Result<String, TokenError> {
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), claims, &self.encoding)
            .map_err(|_| TokenError::Sign)
    }

    fn verify(&self, token: &str) -> Result<Claims, TokenError> {
        // Cookies are small; refuse anything that is obviously not ours
        // before doing any work.
        if token.len() > 4096 {
            return Err(TokenError::Invalid);
        }
        jsonwebtoken::decode::<Claims>(token, &self.decoding, &self.validation)
            .map(|d| d.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::Expired,
                _ => TokenError::Invalid,
            })
    }
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const ISS: &str = "https://auth.example.com";

    fn claims(exp_offset: i64) -> Claims {
        let now = now();
        Claims {
            iss: ISS.into(),
            sub: "aaron".into(),
            groups: vec!["admins".into()],
            iat: now,
            exp: (now as i64 + exp_offset) as u64,
            ver: 1,
        }
    }

    #[test]
    fn round_trip() {
        let s = Hs256Signer::new(SECRET, ISS);
        let c = claims(3600);
        let t = s.sign(&c).unwrap();
        assert_eq!(s.verify(&t).unwrap(), c);
    }

    #[test]
    fn expired_is_rejected_after_leeway() {
        let s = Hs256Signer::new(SECRET, ISS);
        let t = s.sign(&claims(-(LEEWAY_SECS as i64) - 5)).unwrap();
        assert_eq!(s.verify(&t), Err(TokenError::Expired));
        // Inside the leeway still passes.
        let t = s.sign(&claims(-5)).unwrap();
        assert!(s.verify(&t).is_ok());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let a = Hs256Signer::new(SECRET, ISS);
        let b = Hs256Signer::new(b"ffffffffffffffffffffffffffffffff", ISS);
        let t = a.sign(&claims(3600)).unwrap();
        assert_eq!(b.verify(&t), Err(TokenError::Invalid));
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let a = Hs256Signer::new(SECRET, "https://evil.example.com");
        let b = Hs256Signer::new(SECRET, ISS);
        let mut c = claims(3600);
        c.iss = "https://evil.example.com".into();
        let t = a.sign(&c).unwrap();
        assert_eq!(b.verify(&t), Err(TokenError::Invalid));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let s = Hs256Signer::new(SECRET, ISS);
        let t = s.sign(&claims(3600)).unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        let mut c = claims(3600);
        c.sub = "root".into();
        let forged = URL_SAFE_NO_PAD.encode(serde_json_like(&c));
        let t2 = format!("{}.{}.{}", parts[0], forged, parts[2]);
        assert_eq!(s.verify(&t2), Err(TokenError::Invalid));
    }

    #[test]
    fn alg_none_is_rejected() {
        let s = Hs256Signer::new(SECRET, ISS);
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD.encode(serde_json_like(&claims(3600)));
        assert_eq!(
            s.verify(&format!("{header}.{body}.")),
            Err(TokenError::Invalid)
        );
    }

    #[test]
    fn garbage_is_rejected() {
        let s = Hs256Signer::new(SECRET, ISS);
        assert_eq!(s.verify(""), Err(TokenError::Invalid));
        assert_eq!(s.verify("a.b.c"), Err(TokenError::Invalid));
        assert_eq!(s.verify(&"a".repeat(5000)), Err(TokenError::Invalid));
    }

    fn serde_json_like(c: &Claims) -> Vec<u8> {
        format!(
            r#"{{"iss":"{}","sub":"{}","groups":[],"iat":{},"exp":{},"ver":{}}}"#,
            c.iss, c.sub, c.iat, c.exp, c.ver
        )
        .into_bytes()
    }
}
