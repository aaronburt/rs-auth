use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hmac::{KeyInit, Mac};

/// Usernames are counted in this many keyed buckets, so unknown names lock out
/// exactly like real ones and memory stays bounded.
pub const BUCKETS: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    Locked,
    Allowed { at: Instant, locked_after: bool },
}

/// Locks an account after `max_attempts` failed sign-ins within `window`.
pub struct Lockout {
    key: Vec<u8>,
    max_attempts: usize,
    window: Duration,
    attempts: Mutex<HashMap<u64, VecDeque<Instant>>>,
}

fn prune(q: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while q.front().is_some_and(|t| now.duration_since(*t) >= window) {
        q.pop_front();
    }
}

impl Lockout {
    pub fn new(max_attempts: u32, window: Duration, key: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            max_attempts: max_attempts.max(1) as usize,
            window,
            attempts: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, VecDeque<Instant>>> {
        self.attempts.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn bucket(&self, username: &str) -> u64 {
        let Ok(mut m) = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.key) else {
            return 0;
        };
        m.update(b"rs-auth login user\0");
        m.update(username.as_bytes());
        let d = m.finalize().into_bytes();
        let mut first = [0u8; 8];
        first.copy_from_slice(d.get(..8).unwrap_or(&[0; 8]));
        u64::from_be_bytes(first) % BUCKETS
    }

    /// Counts an attempt before the password is checked, so parallel guesses
    /// can't slip past the limit. Give it back with `refund` on success.
    pub fn try_attempt(&self, username: &str) -> Attempt {
        self.try_attempt_at(username, Instant::now())
    }

    pub fn try_attempt_at(&self, username: &str, now: Instant) -> Attempt {
        let bucket = self.bucket(username);
        let mut attempts = self.lock();
        let q = attempts.entry(bucket).or_default();
        prune(q, now, self.window);
        if q.len() >= self.max_attempts {
            return Attempt::Locked;
        }
        q.push_back(now);
        Attempt::Allowed {
            at: now,
            locked_after: q.len() >= self.max_attempts,
        }
    }

    pub fn refund(&self, username: &str, at: Instant) {
        let bucket = self.bucket(username);
        let mut attempts = self.lock();
        if let Some(q) = attempts.get_mut(&bucket) {
            if let Some(i) = q.iter().rposition(|t| *t == at) {
                q.remove(i);
            }
            if q.is_empty() {
                attempts.remove(&bucket);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lockout(max: u32) -> Lockout {
        Lockout::new(max, Duration::from_secs(60), b"test key")
    }

    fn locked_after(a: Attempt) -> bool {
        matches!(
            a,
            Attempt::Allowed {
                locked_after: true,
                ..
            }
        )
    }

    #[test]
    fn locks_after_max_attempts() {
        let l = lockout(3);
        let t = Instant::now();
        assert!(!locked_after(l.try_attempt_at("aaron", t)));
        assert!(!locked_after(l.try_attempt_at("aaron", t)));
        assert!(locked_after(l.try_attempt_at("aaron", t)));
        assert_eq!(l.try_attempt_at("aaron", t), Attempt::Locked);
    }

    #[test]
    fn other_accounts_are_unaffected() {
        let l = lockout(1);
        let t = Instant::now();
        assert!(locked_after(l.try_attempt_at("aaron", t)));
        assert_eq!(l.try_attempt_at("aaron", t), Attempt::Locked);
        assert!(matches!(
            l.try_attempt_at("guest", t),
            Attempt::Allowed { .. }
        ));
    }

    #[test]
    fn unlocks_when_the_window_passes() {
        let l = lockout(2);
        let t = Instant::now();
        l.try_attempt_at("aaron", t);
        l.try_attempt_at("aaron", t + Duration::from_secs(10));
        assert_eq!(
            l.try_attempt_at("aaron", t + Duration::from_secs(30)),
            Attempt::Locked
        );
        assert!(matches!(
            l.try_attempt_at("aaron", t + Duration::from_secs(60)),
            Attempt::Allowed { .. }
        ));
    }

    #[test]
    fn attempts_while_locked_do_not_extend_the_lockout() {
        let l = lockout(2);
        let t = Instant::now();
        l.try_attempt_at("aaron", t);
        l.try_attempt_at("aaron", t);
        assert_eq!(
            l.try_attempt_at("aaron", t + Duration::from_secs(50)),
            Attempt::Locked
        );
        assert!(matches!(
            l.try_attempt_at("aaron", t + Duration::from_secs(61)),
            Attempt::Allowed { .. }
        ));
    }

    #[test]
    fn refund_removes_only_that_attempt() {
        let l = lockout(3);
        let t = Instant::now();
        l.try_attempt_at("aaron", t);
        l.try_attempt_at("aaron", t + Duration::from_secs(1));
        let Attempt::Allowed { at, .. } = l.try_attempt_at("aaron", t + Duration::from_secs(2))
        else {
            panic!("should be allowed");
        };
        assert_eq!(l.try_attempt_at("aaron", at), Attempt::Locked);
        l.refund("aaron", at);
        assert!(locked_after(l.try_attempt_at("aaron", at)));
    }

    #[test]
    fn refunding_the_last_attempt_forgets_the_account() {
        let l = lockout(3);
        let Attempt::Allowed { at, .. } = l.try_attempt("aaron") else {
            panic!("should be allowed");
        };
        l.refund("aaron", at);
        assert!(l.lock().is_empty());
        l.refund("aaron", at);
        l.refund("nobody", at);
    }

    #[test]
    fn buckets_are_stable_bounded_and_keyed() {
        let l = lockout(1);
        assert_eq!(l.bucket("aaron"), l.bucket("aaron"));
        for name in ["aaron", "guest", "", "x".repeat(200).as_str()] {
            assert!(l.bucket(name) < BUCKETS);
        }
        let other = Lockout::new(1, Duration::from_secs(60), b"another key");
        assert!((0..32).any(|n| l.bucket(&n.to_string()) != other.bucket(&n.to_string())));
    }
}
