use jsonwebtoken::crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils};
use jsonwebtoken::errors::{ErrorKind, Result as JwtResult};
use jsonwebtoken::signature::{self, Signer, Verifier};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

pub const LEEWAY_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub pwh: String,
    pub ver: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    Sign,
    Invalid,
    Expired,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sign => "token could not be signed",
            Self::Invalid => "token is invalid",
            Self::Expired => "token has expired",
        })
    }
}

impl std::error::Error for TokenError {}

pub trait TokenSigner: Send + Sync {
    fn sign(&self, claims: &Claims) -> Result<String, TokenError>;
    fn verify(&self, token: &str) -> Result<Claims, TokenError>;
}

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

struct HmacSigner(HmacSha256);
struct HmacVerifier(HmacSha256);

fn hmac_for(secret: &[u8]) -> JwtResult<HmacSha256> {
    use hmac::KeyInit;
    HmacSha256::new_from_slice(secret).map_err(|_| ErrorKind::InvalidKeyFormat.into())
}

impl Signer<Vec<u8>> for HmacSigner {
    fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        use hmac::Mac;
        let mut m = self.0.clone();
        m.update(msg);
        Ok(m.finalize().into_bytes().to_vec())
    }
}

impl JwtSigner for HmacSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

impl Verifier<Vec<u8>> for HmacVerifier {
    fn verify(&self, msg: &[u8], sig: &Vec<u8>) -> Result<(), signature::Error> {
        use hmac::Mac;
        let mut m = self.0.clone();
        m.update(msg);
        m.verify_slice(sig).map_err(signature::Error::from_source)
    }
}

impl JwtVerifier for HmacVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

fn hs256_only_signer(alg: &Algorithm, key: &EncodingKey) -> JwtResult<Box<dyn JwtSigner>> {
    if *alg != Algorithm::HS256 || key.family() != AlgorithmFamily::Hmac {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    Ok(Box::new(HmacSigner(hmac_for(key.as_bytes())?)))
}

fn hs256_only_verifier(alg: &Algorithm, key: &DecodingKey) -> JwtResult<Box<dyn JwtVerifier>> {
    if *alg != Algorithm::HS256 || key.family() != AlgorithmFamily::Hmac {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    Ok(Box::new(HmacVerifier(hmac_for(key.try_get_as_bytes()?)?)))
}

static HS256_ONLY: CryptoProvider = CryptoProvider {
    signer_factory: hs256_only_signer,
    verifier_factory: hs256_only_verifier,
    key_utils: KeyUtils::new_unimplemented(),
};

fn install_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = HS256_ONLY.install_default();
    });
}

pub struct Hs256Signer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
}

impl Hs256Signer {
    pub fn new(secret: &[u8], issuer: &str) -> Self {
        install_provider();
        let mut validation = Validation::new(Algorithm::HS256);
        validation.algorithms = vec![Algorithm::HS256];
        validation.leeway = LEEWAY_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.set_issuer(&[issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "sub", "jti"]);
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

pub fn new_jti() -> String {
    crate::random::hex::<16>()
}

pub fn password_fingerprint(secret: &[u8], password_hash: &str) -> String {
    use base64::Engine;
    use hmac::{KeyInit, Mac};
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(b"rs-auth pwh\0");
    mac.update(password_hash.as_bytes());
    let out = mac.finalize().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&out[..8])
}

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
            iat: now,
            exp: now
                .checked_add_signed(exp_offset)
                .expect("test offset fits"),
            jti: new_jti(),
            pwh: "abc".into(),
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
        let t = s
            .sign(&claims(-i64::try_from(LEEWAY_SECS).expect("small") - 5))
            .unwrap();
        assert_eq!(s.verify(&t), Err(TokenError::Expired));
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

    #[test]
    fn fingerprint_changes_with_hash_and_secret() {
        let a = password_fingerprint(SECRET, "$argon2id$one");
        assert_eq!(a, password_fingerprint(SECRET, "$argon2id$one"));
        assert_ne!(a, password_fingerprint(SECRET, "$argon2id$two"));
        assert_ne!(
            a,
            password_fingerprint(b"ffffffffffffffffffffffffffffffff", "$argon2id$one")
        );
        assert_eq!(a.len(), 11);
    }

    fn forge(header: &str, c: &Claims, key: &[u8]) -> String {
        use hmac::{KeyInit, Mac};
        let h = URL_SAFE_NO_PAD.encode(header);
        let b = URL_SAFE_NO_PAD.encode(serde_json_like(c));
        let mut m = HmacSha256::new_from_slice(key).unwrap();
        m.update(format!("{h}.{b}").as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(m.finalize().into_bytes());
        format!("{h}.{b}.{sig}")
    }

    #[test]
    fn hand_built_hs256_matches_the_library() {
        let s = Hs256Signer::new(SECRET, ISS);
        let c = claims(3600);
        let t = forge(r#"{"alg":"HS256","typ":"JWT"}"#, &c, SECRET);
        assert_eq!(s.verify(&t).unwrap(), c);
    }

    #[test]
    fn other_algorithms_are_rejected_even_when_signed() {
        let s = Hs256Signer::new(SECRET, ISS);
        for alg in ["HS384", "HS512", "RS256", "ES256", "EdDSA", "none", "hs256"] {
            let t = forge(
                &format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#),
                &claims(3600),
                SECRET,
            );
            assert_eq!(s.verify(&t), Err(TokenError::Invalid), "{alg} was accepted");
        }
    }

    #[test]
    fn a_flipped_signature_bit_is_rejected() {
        let s = Hs256Signer::new(SECRET, ISS);
        let t = s.sign(&claims(3600)).unwrap();
        let (rest, sig) = t.rsplit_once('.').unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(sig).unwrap();
        raw[0] ^= 1;
        let bad = format!("{rest}.{}", URL_SAFE_NO_PAD.encode(&raw));
        assert_eq!(s.verify(&bad), Err(TokenError::Invalid));
        let short = format!("{rest}.{}", URL_SAFE_NO_PAD.encode(&raw[..31]));
        assert_eq!(s.verify(&short), Err(TokenError::Invalid));
    }

    #[test]
    fn missing_claims_are_rejected() {
        let s = Hs256Signer::new(SECRET, ISS);
        let h = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
        let now = now();
        for body in [
            format!(r#"{{"iss":"{ISS}","sub":"a","iat":{now},"jti":"ab","pwh":"x","ver":1}}"#),
            format!(
                r#"{{"sub":"a","iat":{now},"exp":{},"jti":"ab","pwh":"x","ver":1}}"#,
                now + 60
            ),
            format!(
                r#"{{"iss":"{ISS}","sub":"a","iat":{now},"exp":{},"pwh":"x","ver":1}}"#,
                now + 60
            ),
        ] {
            use hmac::{KeyInit, Mac};
            let b = URL_SAFE_NO_PAD.encode(&body);
            let mut m = HmacSha256::new_from_slice(SECRET).unwrap();
            m.update(format!("{h}.{b}").as_bytes());
            let t = format!(
                "{h}.{b}.{}",
                URL_SAFE_NO_PAD.encode(m.finalize().into_bytes())
            );
            assert_eq!(s.verify(&t), Err(TokenError::Invalid), "{body}");
        }
    }

    fn serde_json_like(c: &Claims) -> Vec<u8> {
        format!(
            r#"{{"iss":"{}","sub":"{}","iat":{},"exp":{},"jti":"{}","pwh":"{}","ver":{}}}"#,
            c.iss, c.sub, c.iat, c.exp, c.jti, c.pwh, c.ver
        )
        .into_bytes()
    }
}
