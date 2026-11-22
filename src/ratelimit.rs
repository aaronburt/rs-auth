//! Per-IP limit on failed sign-in attempts.
//!
//! Each client IP may fail `max_attempts` times within a sliding `window`.
//! Once it hits the limit it is locked out until its oldest failure falls out
//! of the window. A successful sign-in clears that IP's failures. The limit is
//! per IP only, so it reveals nothing about whether a username exists.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many tracked IPs trigger a sweep of stale entries.
const SWEEP_THRESHOLD: usize = 10_000;

pub struct RateLimiter {
    max_attempts: usize,
    window: Duration,
    failures: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self {
            max_attempts: max_attempts.max(1) as usize,
            window,
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, VecDeque<Instant>>> {
        // A panic while holding the lock cannot leave the map in a bad
        // state, so recover rather than propagate the poison.
        self.failures.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn prune(q: &mut VecDeque<Instant>, now: Instant, window: Duration) {
        while q.front().is_some_and(|t| now.duration_since(*t) >= window) {
            q.pop_front();
        }
    }

    /// True when `ip` has used up its attempts.
    pub fn is_locked(&self, ip: IpAddr) -> bool {
        self.is_locked_at(ip, Instant::now())
    }

    pub fn is_locked_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.lock();
        let Some(q) = map.get_mut(&ip) else {
            return false;
        };
        Self::prune(q, now, self.window);
        if q.is_empty() {
            map.remove(&ip);
            return false;
        }
        q.len() >= self.max_attempts
    }

    /// Record a failed attempt. Returns true if `ip` is now locked out.
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        self.record_failure_at(ip, Instant::now())
    }

    pub fn record_failure_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.lock();
        if map.len() >= SWEEP_THRESHOLD {
            let window = self.window;
            map.retain(|_, q| {
                Self::prune(q, now, window);
                !q.is_empty()
            });
        }
        let q = map.entry(ip).or_default();
        Self::prune(q, now, self.window);
        if q.len() < self.max_attempts {
            q.push_back(now);
        }
        q.len() >= self.max_attempts
    }

    /// Forget an IP's failures after a successful sign-in.
    pub fn clear(&self, ip: IpAddr) {
        self.lock().remove(&ip);
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn locks_after_max_failures() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let t = Instant::now();
        assert!(!rl.record_failure_at(ip(1), t));
        assert!(!rl.record_failure_at(ip(1), t));
        assert!(!rl.is_locked_at(ip(1), t));
        assert!(rl.record_failure_at(ip(1), t));
        assert!(rl.is_locked_at(ip(1), t));
        // Other IPs are unaffected.
        assert!(!rl.is_locked_at(ip(2), t));
    }

    #[test]
    fn unlocks_when_window_passes() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let t = Instant::now();
        rl.record_failure_at(ip(1), t);
        rl.record_failure_at(ip(1), t + Duration::from_secs(10));
        assert!(rl.is_locked_at(ip(1), t + Duration::from_secs(30)));
        // The first failure expires at t+60, freeing one attempt.
        assert!(!rl.is_locked_at(ip(1), t + Duration::from_secs(60)));
        assert!(!rl.is_locked_at(ip(1), t + Duration::from_secs(200)));
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn failures_while_locked_do_not_extend_lockout() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let t = Instant::now();
        rl.record_failure_at(ip(1), t);
        rl.record_failure_at(ip(1), t);
        rl.record_failure_at(ip(1), t + Duration::from_secs(50));
        assert!(!rl.is_locked_at(ip(1), t + Duration::from_secs(61)));
    }

    #[test]
    fn success_clears() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let t = Instant::now();
        rl.record_failure_at(ip(1), t);
        rl.clear(ip(1));
        assert!(!rl.record_failure_at(ip(1), t));
    }

    #[test]
    fn sweeps_stale_entries() {
        let rl = RateLimiter::new(5, Duration::from_secs(1));
        let t = Instant::now();
        for i in 0..SWEEP_THRESHOLD as u32 {
            rl.record_failure_at(IpAddr::from(i.to_be_bytes()), t);
        }
        assert_eq!(rl.tracked(), SWEEP_THRESHOLD);
        rl.record_failure_at(ip(1), t + Duration::from_secs(5));
        assert_eq!(rl.tracked(), 1);
    }
}
