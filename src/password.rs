//! Argon2id password hashing and verification.

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};

/// Longest password we will hash. Anything longer is rejected without
/// running Argon2, so a huge form body cannot burn CPU.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// The parameters `hash-password` uses: Argon2id, 64 MiB, 3 passes, 4 lanes.
fn hasher() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 3, 4, None).expect("static argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password into an Argon2id PHC string with a fresh random salt.
pub fn hash(password: &str) -> Result<String, String> {
    if password.is_empty() {
        return Err("password must not be empty".into());
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(format!("password must be at most {MAX_PASSWORD_LEN} bytes"));
    }
    hasher()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Check that `phc` is a well-formed Argon2id PHC string.
pub fn check_phc(phc: &str) -> Result<(), String> {
    let parsed = PasswordHash::new(phc).map_err(|_| {
        "must be an Argon2id hash from `rs-auth hash-password` (plain-text passwords are not accepted)"
            .to_string()
    })?;
    if parsed.algorithm.as_str() != "argon2id" {
        return Err(format!(
            "uses {}, but only argon2id hashes are accepted",
            parsed.algorithm.as_str()
        ));
    }
    if parsed.hash.is_none() || parsed.salt.is_none() {
        return Err("is missing its salt or hash".into());
    }
    // Make sure the params are ones argon2 can actually run.
    Params::try_from(&parsed).map_err(|e| format!("has bad parameters: {e}"))?;
    Ok(())
}

/// Verify `password` against a PHC string. Comparison is constant time.
pub fn verify(password: &str, phc: &str) -> bool {
    if password.len() > MAX_PASSWORD_LEN {
        return false;
    }
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A hash of a random password, used for unknown usernames so a miss costs
/// the same time as a wrong password.
pub fn dummy_hash() -> String {
    let random: [u8; 24] = rand::random();
    let pw: String = random.iter().map(|b| format!("{b:02x}")).collect();
    hash(&pw).expect("hashing a random password")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash("correct horse").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
        check_phc(&h).unwrap();
        assert!(verify("correct horse", &h));
        assert!(!verify("wrong horse", &h));
        assert!(!verify("", &h));
    }

    #[test]
    fn salts_differ() {
        assert_ne!(hash("x").unwrap(), hash("x").unwrap());
    }

    #[test]
    fn rejects_bad_hashes() {
        assert!(check_phc("hunter2").is_err());
        assert!(check_phc("").is_err());
        assert!(
            check_phc("$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA").is_err()
        );
        assert!(check_phc("$2b$12$abcdefghijklmnopqrstuv").is_err());
        assert!(!verify("x", "not a hash"));
    }

    #[test]
    fn length_limits() {
        assert!(hash("").is_err());
        assert!(hash(&"a".repeat(MAX_PASSWORD_LEN + 1)).is_err());
        let h = hash("short").unwrap();
        assert!(!verify(&"a".repeat(MAX_PASSWORD_LEN + 1), &h));
    }
}
