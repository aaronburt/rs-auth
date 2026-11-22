use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_ENTRIES: usize = 100_000;

pub struct Revocations {
    path: Option<PathBuf>,
    entries: Mutex<HashMap<String, u64>>,
    write_lock: Arc<Mutex<()>>,
}

fn well_formed(jti: &str) -> bool {
    !jti.is_empty() && jti.len() <= 64 && jti.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Revocations {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            entries: Mutex::new(HashMap::new()),
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn load(path: Option<&Path>, now: u64) -> std::io::Result<Self> {
        let mut r = Self::in_memory();
        let Some(path) = path else {
            return Ok(r);
        };
        r.path = Some(path.to_owned());
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        let map = r.entries.get_mut().unwrap_or_else(|e| e.into_inner());
        for line in text.lines() {
            let mut it = line.split_whitespace();
            if let (Some(jti), Some(until)) = (it.next(), it.next().and_then(|u| u.parse().ok()))
                && well_formed(jti)
                && until > now
            {
                map.insert(jti.to_owned(), until);
            }
        }
        Ok(r)
    }

    pub fn is_revoked(&self, jti: &str) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(jti)
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub async fn revoke(self: &Arc<Self>, jti: &str, until: u64, now: u64) {
        if !well_formed(jti) {
            return;
        }
        {
            let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            map.retain(|_, u| *u > now);
            if map.len() >= MAX_ENTRIES {
                tracing::warn!("revocation list is full; dropping the entry closest to expiry");
                if let Some(k) = map.iter().min_by_key(|(_, u)| **u).map(|(k, _)| k.clone()) {
                    map.remove(&k);
                }
            }
            map.insert(jti.to_owned(), until);
        }
        if self.path.is_none() {
            return;
        }
        let me = Arc::clone(self);
        let res = tokio::task::spawn_blocking(move || me.persist()).await;
        match res {
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
            let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            map.iter().map(|(k, u)| format!("{k} {u}\n")).collect()
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

    #[tokio::test]
    async fn revoke_and_reload() {
        let dir = std::env::temp_dir().join(format!("rs-auth-rev-{}", crate::token::new_jti()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revoked");
        let r = Arc::new(Revocations::load(Some(&path), 100).unwrap());
        assert!(r.is_empty());
        r.revoke("abcd", 500, 100).await;
        r.revoke("not hex!", 500, 100).await;
        assert!(r.is_revoked("abcd"));
        assert_eq!(r.len(), 1);

        let again = Revocations::load(Some(&path), 100).unwrap();
        assert!(again.is_revoked("abcd"));
        let later = Revocations::load(Some(&path), 600).unwrap();
        assert!(!later.is_revoked("abcd"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn expired_entries_are_pruned_on_write() {
        let r = Arc::new(Revocations::in_memory());
        r.revoke("aa", 150, 100).await;
        r.revoke("bb", 900, 200).await;
        assert!(!r.is_revoked("aa"));
        assert!(r.is_revoked("bb"));
    }
}
