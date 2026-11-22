use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub const STEP_SECS: u64 = 30;
pub const DIGITS: usize = 6;
pub const MIN_SECRET_BYTES: usize = 16;
pub const SECRET_BYTES: usize = 20;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode_secret(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buf >> bits) & 31) as usize]));
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buf << (5 - bits)) & 31) as usize]));
    }
    out
}

pub fn decode_secret(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    let cleaned = text
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .collect::<String>();
    let cleaned = cleaned.trim_end_matches('=');
    for c in cleaned.chars() {
        let upper = c.to_ascii_uppercase();
        let Some(v) = BASE32.iter().position(|b| char::from(*b) == upper) else {
            return Err(format!("{c:?} is not a base32 character (A-Z and 2-7)"));
        };
        buf = (buf << 5) | u32::try_from(v).unwrap_or(0);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap_or(0));
            buf &= (1 << bits) - 1;
        }
    }
    if out.len() < MIN_SECRET_BYTES {
        return Err(
            "must be at least 26 base32 characters (16 bytes); make one with `rs-auth totp-secret`"
                .into(),
        );
    }
    Ok(out)
}

pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&step.to_be_bytes());
    let digest: [u8; 20] = mac.finalize().into_bytes().into();
    let offset = usize::from(digest[19] & 0x0f);
    let word = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    (word & 0x7fff_ffff) % 1_000_000
}

pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

pub fn parse_code(input: &str) -> Option<u32> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn matching_step(secret: &[u8], code: u32, now: u64, after: u64) -> Option<u64> {
    let center = step_at(now);
    let mut found = None;
    for step in center.saturating_sub(1)..=center + 1 {
        let hit = bool::from(
            code.to_be_bytes()
                .ct_eq(&code_at(secret, step).to_be_bytes()),
        );
        if hit && step > after && found.is_none() {
            found = Some(step);
        }
    }
    found
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    step: u64,
    previous: u64,
}

#[derive(Default)]
pub struct Replay {
    last: Mutex<HashMap<String, u64>>,
}

impl Replay {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, u64>> {
        self.last.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn accept(&self, user: &str, secret: &[u8], input: &str, now: u64) -> Option<Accepted> {
        let code = parse_code(input)?;
        let mut last = self.lock();
        let previous = last.get(user).copied().unwrap_or(0);
        let step = matching_step(secret, code, now, previous)?;
        last.insert(user.to_owned(), step);
        Some(Accepted { step, previous })
    }

    pub fn release(&self, user: &str, accepted: Accepted) {
        let mut last = self.lock();
        if last.get(user) == Some(&accepted.step) {
            last.insert(user.to_owned(), accepted.previous);
        }
    }
}

pub fn otpauth_uri(secret: &str, account: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        percent(issuer),
        percent(account),
        percent(issuer)
    )
}

fn percent(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_vectors() {
        for (time, expected) in [
            (59u64, 94_287_082u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ] {
            assert_eq!(code_at(RFC_SECRET, step_at(time)), expected % 1_000_000);
        }
    }

    #[test]
    fn base32_round_trip_and_rfc4648_vectors() {
        assert_eq!(encode_secret(b"foobar"), "MZXW6YTBOI");
        assert_eq!(encode_secret(b"fooba"), "MZXW6YTB");
        assert_eq!(encode_secret(b""), "");
        assert_eq!(encode_secret(b"f"), "MY");
        assert_eq!(
            decode_secret(&encode_secret(RFC_SECRET)).unwrap(),
            RFC_SECRET
        );
        assert_eq!(
            decode_secret("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq").unwrap(),
            RFC_SECRET
        );
        assert_eq!(
            decode_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====").unwrap(),
            RFC_SECRET
        );
    }

    #[test]
    fn rejects_bad_secrets() {
        assert!(decode_secret("").is_err());
        assert!(decode_secret("MZXW6YTB").unwrap_err().contains("at least"));
        assert!(
            decode_secret("GEZDGNBVGY3TQOJQGEZDGNB1")
                .unwrap_err()
                .contains("not a base32 character")
        );
    }

    #[test]
    fn parses_codes() {
        assert_eq!(parse_code("123456"), Some(123_456));
        assert_eq!(parse_code(" 123 456 "), Some(123_456));
        assert_eq!(parse_code("000123"), Some(123));
        for bad in [
            "",
            "12345",
            "1234567",
            "12345a",
            "١٢٣٤٥٦",
            "+12345",
            "-12345",
        ] {
            assert_eq!(parse_code(bad), None, "{bad}");
        }
    }

    fn code_text(secret: &[u8], step: u64) -> String {
        format!("{:06}", code_at(secret, step))
    }

    #[test]
    fn accepts_the_window_and_nothing_wider() {
        let now = 1_700_000_010;
        let step = step_at(now);
        for (offset, ok) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let r = Replay::default();
            let s = step.checked_add_signed(offset).unwrap();
            let got = r.accept("a", RFC_SECRET, &code_text(RFC_SECRET, s), now);
            assert_eq!(got.is_some(), ok, "offset {offset}");
        }
    }

    #[test]
    fn a_wrong_code_is_refused() {
        let r = Replay::default();
        let now = 1_700_000_010;
        let good = code_at(RFC_SECRET, step_at(now));
        let wrong = format!("{:06}", (good + 1) % 1_000_000);
        let near =
            [-1i64, 0, 1].map(|o| code_at(RFC_SECRET, step_at(now).checked_add_signed(o).unwrap()));
        assert!(!near.contains(&((good + 1) % 1_000_000)));
        assert!(r.accept("a", RFC_SECRET, &wrong, now).is_none());
        assert!(r.accept("a", RFC_SECRET, "abc", now).is_none());
        assert!(
            r.accept(
                "a",
                b"another secret 16b+",
                &code_text(RFC_SECRET, step_at(now)),
                now
            )
            .is_none()
        );
    }

    #[test]
    fn a_code_works_once() {
        let r = Replay::default();
        let now = 1_700_000_010;
        let text = code_text(RFC_SECRET, step_at(now));
        assert!(r.accept("a", RFC_SECRET, &text, now).is_some());
        assert!(r.accept("a", RFC_SECRET, &text, now).is_none());
        assert!(r.accept("a", RFC_SECRET, &text, now + 20).is_none());
        assert!(r.accept("b", RFC_SECRET, &text, now).is_some());
    }

    #[test]
    fn an_older_code_cannot_follow_a_newer_one() {
        let r = Replay::default();
        let now = 1_700_000_010;
        let step = step_at(now);
        assert!(
            r.accept("a", RFC_SECRET, &code_text(RFC_SECRET, step + 1), now)
                .is_some()
        );
        assert!(
            r.accept("a", RFC_SECRET, &code_text(RFC_SECRET, step), now)
                .is_none()
        );
        assert!(
            r.accept("a", RFC_SECRET, &code_text(RFC_SECRET, step - 1), now)
                .is_none()
        );
        assert!(
            r.accept("a", RFC_SECRET, &code_text(RFC_SECRET, step + 2), now + 30)
                .is_some()
        );
    }

    #[test]
    fn releasing_a_claim_lets_the_same_code_try_again() {
        let r = Replay::default();
        let now = 1_700_000_010;
        let text = code_text(RFC_SECRET, step_at(now));
        let first = r.accept("a", RFC_SECRET, &text, now).unwrap();
        r.release("a", first);
        let again = r.accept("a", RFC_SECRET, &text, now).unwrap();
        assert_eq!(first, again);
    }

    #[test]
    fn a_stale_release_does_not_undo_a_newer_claim() {
        let r = Replay::default();
        let now = 1_700_000_010;
        let step = step_at(now);
        let old = r
            .accept("a", RFC_SECRET, &code_text(RFC_SECRET, step), now)
            .unwrap();
        let newer = r
            .accept("a", RFC_SECRET, &code_text(RFC_SECRET, step + 1), now)
            .unwrap();
        r.release("a", old);
        assert!(
            r.accept("a", RFC_SECRET, &code_text(RFC_SECRET, step + 1), now)
                .is_none()
        );
        r.release("a", newer);
        assert!(
            r.accept("a", RFC_SECRET, &code_text(RFC_SECRET, step + 1), now)
                .is_some()
        );
    }

    #[test]
    fn otpauth_uri_is_escaped() {
        let uri = otpauth_uri("ABC", "a b@x", "rs auth");
        assert_eq!(
            uri,
            "otpauth://totp/rs%20auth:a%20b%40x?secret=ABC&issuer=rs%20auth&algorithm=SHA1&digits=6&period=30"
        );
    }
}
