use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const SWEEP_THRESHOLD: usize = 10_000;
const SWEEP_COOLDOWN: Duration = Duration::from_secs(10);
const MAX_ENTRIES: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    Locked,
    Allowed { at: Instant, locked_after: bool },
}

struct Inner {
    attempts: HashMap<IpAddr, VecDeque<Instant>>,
    last_sweep: Option<Instant>,
}

pub struct RateLimiter {
    max_attempts: usize,
    window: Duration,
    max_entries: usize,
    inner: Mutex<Inner>,
}

pub fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
        },
    }
}

fn prune(q: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while q.front().is_some_and(|t| now.duration_since(*t) >= window) {
        q.pop_front();
    }
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self::with_capacity(max_attempts, window, MAX_ENTRIES)
    }

    pub fn with_capacity(max_attempts: u32, window: Duration, max_entries: usize) -> Self {
        Self {
            max_attempts: max_attempts.max(1) as usize,
            window,
            max_entries: max_entries.max(1),
            inner: Mutex::new(Inner {
                attempts: HashMap::new(),
                last_sweep: None,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sweep(&self, inner: &mut Inner, now: Instant, force: bool) {
        let due = inner
            .last_sweep
            .is_none_or(|t| now.duration_since(t) >= SWEEP_COOLDOWN);
        if !(force || due) {
            return;
        }
        let window = self.window;
        inner.attempts.retain(|_, q| {
            prune(q, now, window);
            !q.is_empty()
        });
        inner.last_sweep = Some(now);
    }

    pub fn is_locked(&self, ip: IpAddr) -> bool {
        self.is_locked_at(ip, Instant::now())
    }

    pub fn is_locked_at(&self, ip: IpAddr, now: Instant) -> bool {
        let k = key(ip);
        let mut inner = self.lock();
        let Some(q) = inner.attempts.get_mut(&k) else {
            return false;
        };
        prune(q, now, self.window);
        if q.is_empty() {
            inner.attempts.remove(&k);
            return false;
        }
        q.len() >= self.max_attempts
    }

    pub fn try_attempt(&self, ip: IpAddr) -> Attempt {
        self.try_attempt_at(ip, Instant::now())
    }

    pub fn try_attempt_at(&self, ip: IpAddr, now: Instant) -> Attempt {
        let k = key(ip);
        let mut inner = self.lock();
        if !inner.attempts.contains_key(&k) {
            if inner.attempts.len() >= SWEEP_THRESHOLD.min(self.max_entries) {
                self.sweep(&mut inner, now, false);
            }
            if inner.attempts.len() >= self.max_entries {
                self.sweep(&mut inner, now, true);
                if inner.attempts.len() >= self.max_entries {
                    return Attempt::Locked;
                }
            }
        }
        let q = inner.attempts.entry(k).or_default();
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

    pub fn refund(&self, ip: IpAddr, at: Instant) {
        let k = key(ip);
        let mut inner = self.lock();
        if let Some(q) = inner.attempts.get_mut(&k) {
            if let Some(i) = q.iter().rposition(|t| *t == at) {
                q.remove(i);
            }
            if q.is_empty() {
                inner.attempts.remove(&k);
            }
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.lock().attempts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    fn fail(rl: &RateLimiter, ip: IpAddr, t: Instant) -> Attempt {
        rl.try_attempt_at(ip, t)
    }

    #[test]
    fn locks_after_max_attempts() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let t = Instant::now();
        assert!(matches!(
            fail(&rl, ip(1), t),
            Attempt::Allowed {
                locked_after: false,
                ..
            }
        ));
        assert!(matches!(
            fail(&rl, ip(1), t),
            Attempt::Allowed {
                locked_after: false,
                ..
            }
        ));
        assert!(!rl.is_locked_at(ip(1), t));
        assert!(matches!(
            fail(&rl, ip(1), t),
            Attempt::Allowed {
                locked_after: true,
                ..
            }
        ));
        assert!(rl.is_locked_at(ip(1), t));
        assert_eq!(fail(&rl, ip(1), t), Attempt::Locked);
        assert!(!rl.is_locked_at(ip(2), t));
    }

    #[test]
    fn unlocks_when_window_passes() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let t = Instant::now();
        fail(&rl, ip(1), t);
        fail(&rl, ip(1), t + Duration::from_secs(10));
        assert!(rl.is_locked_at(ip(1), t + Duration::from_secs(30)));
        assert!(!rl.is_locked_at(ip(1), t + Duration::from_secs(60)));
        assert!(!rl.is_locked_at(ip(1), t + Duration::from_secs(200)));
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn attempts_while_locked_do_not_extend_lockout() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let t = Instant::now();
        fail(&rl, ip(1), t);
        fail(&rl, ip(1), t);
        assert_eq!(
            fail(&rl, ip(1), t + Duration::from_secs(50)),
            Attempt::Locked
        );
        assert!(!rl.is_locked_at(ip(1), t + Duration::from_secs(61)));
    }

    #[test]
    fn refund_removes_only_that_attempt() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let t = Instant::now();
        fail(&rl, ip(1), t);
        fail(&rl, ip(1), t + Duration::from_secs(1));
        let Attempt::Allowed { at, .. } = fail(&rl, ip(1), t + Duration::from_secs(2)) else {
            panic!("should be allowed");
        };
        assert!(rl.is_locked_at(ip(1), at));
        rl.refund(ip(1), at);
        assert!(!rl.is_locked_at(ip(1), at));
        assert!(matches!(
            fail(&rl, ip(1), at),
            Attempt::Allowed {
                locked_after: true,
                ..
            }
        ));
    }

    #[test]
    fn ipv6_addresses_in_one_64_share_a_bucket() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let t = Instant::now();
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        fail(&rl, a, t);
        fail(&rl, b, t);
        assert!(rl.is_locked_at(a, t));
        assert!(rl.is_locked_at(b, t));
        assert!(!rl.is_locked_at(other, t));
    }

    #[test]
    fn mapped_ipv4_shares_bucket_with_ipv4() {
        assert_eq!(key("::ffff:10.0.0.1".parse().unwrap()), ip(1));
    }

    #[test]
    fn full_table_fails_closed_for_new_clients() {
        let rl = RateLimiter::with_capacity(5, Duration::from_secs(60), 3);
        let t = Instant::now();
        for n in 1..=3 {
            assert!(matches!(fail(&rl, ip(n), t), Attempt::Allowed { .. }));
        }
        assert_eq!(fail(&rl, ip(4), t), Attempt::Locked);
        assert!(matches!(fail(&rl, ip(1), t), Attempt::Allowed { .. }));
        assert!(matches!(
            fail(&rl, ip(4), t + Duration::from_secs(61)),
            Attempt::Allowed { .. }
        ));
        assert_eq!(rl.tracked(), 1);
    }

    #[test]
    fn sweeps_stale_entries_with_cooldown() {
        let rl = RateLimiter::new(5, Duration::from_secs(1));
        let t = Instant::now();
        for i in 0..u32::try_from(SWEEP_THRESHOLD).expect("small constant") {
            fail(&rl, IpAddr::from(i.to_be_bytes()), t);
        }
        assert_eq!(rl.tracked(), SWEEP_THRESHOLD);
        fail(&rl, ip(1), t + Duration::from_secs(5));
        assert_eq!(rl.tracked(), 1);
        for i in 0..u32::try_from(SWEEP_THRESHOLD).expect("small constant") {
            fail(
                &rl,
                IpAddr::from((i + 1_000_000).to_be_bytes()),
                t + Duration::from_secs(5),
            );
        }
        fail(&rl, ip(2), t + Duration::from_secs(7));
        assert_eq!(
            rl.tracked(),
            SWEEP_THRESHOLD + 2,
            "no sweep inside the cooldown"
        );
    }
}
