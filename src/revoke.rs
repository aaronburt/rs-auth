use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_ENTRIES: usize = 100_000;

#[derive(Clone, Copy)]
struct Entry {
    until: u64,
    iat: u64,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    floor: u64,
}

impl Inner {
    fn drop_covered(&mut self) {
        let floor = self.floor;
        self.entries.retain(|_, e| e.iat > floor);
    }

    fn make_room(&mut self, max: usize) -> usize {
        let mut dropped = 0;
        while self.entries.len() >= max {
            let Some(oldest) = self.entries.values().map(|e| e.iat).min() else {
                break;
            };
            let before = self.entries.len();
            self.floor = self.floor.max(oldest);
            self.drop_covered();
            dropped += before - self.entries.len();
        }
        dropped
    }
}

pub struct Revocations {
    path: Option<PathBuf>,
    max_entries: usize,
    inner: Mutex<Inner>,
    write_lock: Arc<Mutex<()>>,
}

fn well_formed(jti: &str) -> bool {
    !jti.is_empty() && jti.len() <= 64 && jti.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Revocations {
    pub fn in_memory() -> Self {
        Self::with_capacity(None, MAX_ENTRIES)
    }

    fn with_capacity(path: Option<PathBuf>, max_entries: usize) -> Self {
        Self {
            path,
            max_entries: max_entries.max(1),
            inner: Mutex::new(Inner::default()),
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn load(path: Option<&Path>, now: u64) -> std::io::Result<Self> {
        Self::load_with_capacity(path, now, MAX_ENTRIES)
    }

    pub fn load_with_capacity(
        path: Option<&Path>,
        now: u64,
        max_entries: usize,
    ) -> std::io::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::with_capacity(None, max_entries));
        };
        let mut r = Self::with_capacity(Some(path.to_owned()), max_entries);
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        let inner = r.inner.get_mut().unwrap_or_else(|e| e.into_inner());
        for line in text.lines() {
            let mut it = line.split_whitespace();
            match (it.next(), it.next().and_then(|u| u.parse::<u64>().ok())) {
                (Some("floor"), Some(f)) => inner.floor = inner.floor.max(f),
                (Some(jti), Some(until)) if well_formed(jti) && until > now => {
                    let iat = it.next().and_then(|i| i.parse().ok()).unwrap_or(until);
                    inner.entries.insert(jti.to_owned(), Entry { until, iat });
                }
                _ => {}
            }
        }
        inner.drop_covered();
        if inner.entries.len() > max_entries {
            inner.make_room(max_entries + 1);
        }
        Ok(r)
    }

    pub fn is_revoked(&self, jti: &str, iat: u64) -> bool {
        let inner = self.lock();
        (inner.floor > 0 && iat <= inner.floor) || inner.entries.contains_key(jti)
    }

    pub fn floor(&self) -> u64 {
        self.lock().floor
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub async fn revoke(self: &Arc<Self>, jti: &str, iat: u64, until: u64, now: u64) {
        if !well_formed(jti) {
            return;
        }
        {
            let mut inner = self.lock();
            inner.entries.retain(|_, e| e.until > now);
            if iat <= inner.floor {
                return;
            }
            if inner.entries.len() >= self.max_entries {
                let dropped = inner.make_room(self.max_entries);
                tracing::warn!(
                    dropped,
                    floor = inner.floor,
                    "revocation list is full; every session started at or before the floor is now refused"
                );
            }
            inner.entries.insert(jti.to_owned(), Entry { until, iat });
        }
        if self.path.is_none() {
            return;
        }
        let me = Arc::clone(self);
        match tokio::task::spawn_blocking(move || me.persist()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "could not save the revocation list"),
            Err(e) => tracing::error!(error = %e, "could not save the revocation list"),
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let body: String = {
            let inner = self.lock();
            let mut b = String::new();
            if inner.floor > 0 {
                b.push_str(&format!("floor {}\n", inner.floor));
            }
            for (k, e) in &inner.entries {
                b.push_str(&format!("{k} {} {}\n", e.until, e.iat));
            }
            b
        };
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rs-auth-rev-{name}-{}", crate::token::new_jti()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn jti(n: u32) -> String {
        format!("{n:032x}")
    }

    #[tokio::test]
    async fn revoke_and_reload() {
        let dir = tmp("reload");
        let path = dir.join("revoked");
        let r = Arc::new(Revocations::load(Some(&path), 100).unwrap());
        assert!(r.is_empty());
        r.revoke("abcd", 50, 500, 100).await;
        r.revoke("not hex!", 50, 500, 100).await;
        assert!(r.is_revoked("abcd", 9999));
        assert!(!r.is_revoked("beef", 9999));
        assert_eq!(r.len(), 1);

        let again = Revocations::load(Some(&path), 100).unwrap();
        assert!(again.is_revoked("abcd", 9999));
        let later = Revocations::load(Some(&path), 600).unwrap();
        assert!(!later.is_revoked("abcd", 9999));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn expired_entries_are_pruned_on_write() {
        let r = Arc::new(Revocations::in_memory());
        r.revoke("aa", 10, 150, 100).await;
        r.revoke("bb", 10, 900, 200).await;
        assert!(!r.is_revoked("aa", 9999));
        assert!(r.is_revoked("bb", 9999));
    }

    #[tokio::test]
    async fn a_full_list_raises_the_floor_instead_of_forgetting_sessions() {
        let r = Arc::new(Revocations::load_with_capacity(None, 0, 3).unwrap());
        for n in 1..=3u32 {
            r.revoke(&jti(n), u64::from(n) * 10, 10_000, 1).await;
        }
        assert_eq!(r.len(), 3);
        assert_eq!(r.floor(), 0);

        r.revoke(&jti(4), 40, 10_000, 1).await;
        assert_eq!(
            r.floor(),
            10,
            "the oldest session's start time becomes the floor"
        );
        for n in 1..=4u32 {
            assert!(
                r.is_revoked(&jti(n), u64::from(n) * 10),
                "session {n} must stay revoked"
            );
        }
        assert!(
            !r.is_revoked(&jti(9), 11),
            "sessions started after the floor are not affected"
        );
        assert!(
            r.is_revoked(&jti(9), 10),
            "a session started at the floor is refused (fail closed)"
        );
        assert!(r.is_revoked(&jti(9), 5), "and so is anything older");
        assert_eq!(r.len(), 3, "the covered entry was dropped to make room");
    }

    #[tokio::test]
    async fn sessions_older_than_the_floor_are_not_stored_again() {
        let r = Arc::new(Revocations::load_with_capacity(None, 0, 1).unwrap());
        r.revoke(&jti(1), 100, 10_000, 1).await;
        r.revoke(&jti(2), 200, 10_000, 1).await;
        assert_eq!(r.floor(), 100);
        r.revoke(&jti(3), 50, 10_000, 1).await;
        assert!(r.is_revoked(&jti(3), 50));
        assert_eq!(r.len(), 1);
    }

    #[tokio::test]
    async fn identical_start_times_are_all_covered() {
        let r = Arc::new(Revocations::load_with_capacity(None, 0, 2).unwrap());
        for n in 1..=5u32 {
            r.revoke(&jti(n), 70, 10_000, 1).await;
        }
        for n in 1..=5u32 {
            assert!(r.is_revoked(&jti(n), 70));
        }
        assert!(r.floor() >= 70);
    }

    #[tokio::test]
    async fn the_floor_and_entries_survive_a_restart() {
        let dir = tmp("floor");
        let path = dir.join("revoked");
        let r = Arc::new(Revocations::load_with_capacity(Some(&path), 0, 2).unwrap());
        for n in 1..=3u32 {
            r.revoke(&jti(n), u64::from(n) * 10, 10_000, 1).await;
        }
        let floor = r.floor();
        assert!(floor > 0);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(&format!("floor {floor}\n")));

        let again = Revocations::load_with_capacity(Some(&path), 0, 2).unwrap();
        assert_eq!(again.floor(), floor);
        for n in 1..=3u32 {
            assert!(again.is_revoked(&jti(n), u64::from(n) * 10));
        }
        assert!(!again.is_revoked(&jti(9), 1000));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn loading_tolerates_junk_and_the_older_two_column_format() {
        let dir = tmp("junk");
        let path = dir.join("revoked");
        std::fs::write(
            &path,
            format!(
                "garbage\n\nfloor notanumber\nnot-hex 500\n{} abc\n{} 500\n{} 50 40\n{} 500 60\n",
                jti(1),
                jti(2),
                jti(3),
                jti(4)
            ),
        )
        .unwrap();
        let r = Revocations::load(Some(&path), 100).unwrap();
        assert!(!r.is_revoked(&jti(1), 1000), "a bad expiry is skipped");
        assert!(r.is_revoked(&jti(2), 1000), "two columns still load");
        assert!(!r.is_revoked(&jti(3), 1000), "expired entries are dropped");
        assert!(r.is_revoked(&jti(4), 1000));
        assert_eq!(r.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_with_too_many_entries_is_trimmed_by_raising_the_floor() {
        let dir = tmp("big");
        let path = dir.join("revoked");
        let body: String = (1..=10u32)
            .map(|n| format!("{} 10000 {}\n", jti(n), n * 10))
            .collect();
        std::fs::write(&path, body).unwrap();
        let r = Revocations::load_with_capacity(Some(&path), 0, 4).unwrap();
        assert!(r.len() <= 4);
        for n in 1..=10u32 {
            assert!(r.is_revoked(&jti(n), u64::from(n) * 10), "session {n}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unreadable_file_stops_startup() {
        let dir = tmp("dir");
        assert!(
            Revocations::load(Some(&dir), 0).is_err(),
            "a directory is not a list"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_save_failure_keeps_the_revocation_in_memory() {
        let dir = tmp("nosave");
        let path = dir.join("missing-dir").join("revoked");
        let r = Arc::new(Revocations::load(Some(&path), 0).unwrap());
        r.revoke(&jti(1), 10, 500, 1).await;
        assert!(r.is_revoked(&jti(1), 10));
        assert!(!path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
