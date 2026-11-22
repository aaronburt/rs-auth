use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};

pub const MAX_PASSWORD_LEN: usize = 1024;

fn hasher() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 3, 4, None).expect("static argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

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
    Params::try_from(&parsed).map_err(|e| format!("has bad parameters: {e}"))?;
    Ok(())
}

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

pub fn dummy_hash(like: Option<&str>) -> String {
    let pw = crate::random::hex::<24>();
    let params = like
        .and_then(|phc| PasswordHash::new(phc).ok())
        .and_then(|parsed| Params::try_from(&parsed).ok());
    match params {
        Some(p) => Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
            .hash_password(pw.as_bytes())
            .map(|h| h.to_string())
            .unwrap_or_else(|_| hash(&pw).expect("hashing a random password")),
        None => hash(&pw).expect("hashing a random password"),
    }
}

pub fn weak_params(phc: &str) -> bool {
    PasswordHash::new(phc)
        .ok()
        .and_then(|parsed| Params::try_from(&parsed).ok())
        .is_some_and(|p| p.m_cost() < 19_456 || p.t_cost() < 2)
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
    fn dummy_hash_copies_params() {
        let params = Params::new(256, 1, 1, None).unwrap();
        let user = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password(b"x")
            .unwrap()
            .to_string();
        assert!(dummy_hash(Some(&user)).starts_with("$argon2id$v=19$m=256,t=1,p=1$"));
        assert!(dummy_hash(None).starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
        assert!(weak_params(&user));
        assert!(!weak_params(&hash("x").unwrap()));
    }

    #[test]
    fn length_limits() {
        assert!(hash("").is_err());
        assert!(hash(&"a".repeat(MAX_PASSWORD_LEN + 1)).is_err());
        let h = hash("short").unwrap();
        assert!(!verify(&"a".repeat(MAX_PASSWORD_LEN + 1), &h));
    }
}
