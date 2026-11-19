//! A week-long cache of the root expiry a probe answered for an authority.
//!
//! This is not the pin. A pin is a bundle the user chose and the verifier holds
//! an imprint against, while a probed date is provisional display material
//! until a seal pins the root. An entry is therefore dropped after [`TTL`]
//! rather than trusted, and a stale or malformed entry only means "ask again":
//! the request costs less than showing a date that a rotation has outlived.

// The worker and the picker that read this arrive in a later change.
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

/// How long a probed answer is shown: one week.
pub const TTL: i64 = 7 * 86_400;

/// One answered probe: the root's `notAfter` day and the fingerprint of the
/// root it names, both taken from the authority verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cached {
    pub not_after: String,
    pub fingerprint: String,
}

/// The directory the entries live in: `$XDG_CONFIG_HOME` when set,
/// `~/.config` otherwise, then `git-time/probe`.
#[must_use]
pub fn dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("git-time").join("probe")
}

/// The cached answer for `id`, only when it is younger than [`TTL`].
///
/// The entry is one line of three tab-separated fields: the day, the second it
/// was fetched, and the fingerprint. Anything else — a missing file, a short or
/// long line, a non-numeric second — is stale rather than an error.
#[must_use]
pub fn cached(id: &str, now: jiff::Timestamp) -> Option<Cached> {
    let text = fs::read_to_string(dir().join(id)).ok()?;
    let mut fields = text.trim_end().split('\t');
    let not_after = fields.next()?;
    let at = fields.next()?.parse::<i64>().ok()?;
    let fingerprint = fields.next()?;
    if fields.next().is_some() || now.as_second().saturating_sub(at) > TTL {
        return None;
    }
    Some(Cached {
        not_after: not_after.to_owned(),
        fingerprint: fingerprint.to_owned(),
    })
}

/// Remember `served` for `id`, answering whether it was written.
#[must_use]
pub fn store(id: &str, served: &Cached, now: jiff::Timestamp) -> bool {
    let dir = dir();
    let _ = fs::create_dir_all(&dir);
    let line = format!(
        "{}\t{}\t{}\n",
        served.not_after,
        now.as_second(),
        served.fingerprint
    );
    fs::write(dir.join(id), line).is_ok()
}

/// Drop the entry for `id`, answering whether there was one.
#[must_use]
pub fn forget(id: &str) -> bool {
    fs::remove_file(dir().join(id)).is_ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use super::{Cached, TTL, cached, forget, store};

    /// A process-wide temporary `XDG_CONFIG_HOME`.
    ///
    /// The variable is read at every `dir()` call, so it is re-asserted here in
    /// case another test in this process moved it.
    pub(crate) fn xdg() -> &'static Path {
        static XDG: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        let dir = XDG.get_or_init(|| tempfile::TempDir::new().expect("xdg dir"));
        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path()) };
        dir.path()
    }

    /// The `XDG_CONFIG_HOME` variable is process-wide and several tests share the
    /// id `x`, so the tests that move or use it take turns — across modules too.
    pub(crate) fn xdg_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn at(seconds: i64) -> jiff::Timestamp {
        jiff::Timestamp::from_second(seconds).expect("a second")
    }

    fn served() -> Cached {
        Cached {
            not_after: "2035-02-09".to_owned(),
            fingerprint: "aa".repeat(32),
        }
    }

    #[test]
    fn a_stored_entry_reads_back_within_the_ttl() {
        let _guard = xdg_lock();
        xdg();
        let _ = store("x", &served(), at(1_000));
        let entry = cached("x", at(1_000 + TTL - 1)).expect("still fresh");
        assert_eq!(entry.not_after, "2035-02-09");
        assert_eq!(entry.fingerprint, "aa".repeat(32));
    }

    #[test]
    fn an_entry_older_than_the_ttl_is_stale() {
        let _guard = xdg_lock();
        xdg();
        let _ = store("x", &served(), at(1_000));
        assert!(cached("x", at(1_000 + TTL + 1)).is_none());
    }

    #[test]
    fn a_rewritten_entry_replaces_the_date() {
        let _guard = xdg_lock();
        xdg();
        let _ = store("x", &served(), at(1_000));
        let newer = Cached {
            not_after: "2040-01-01".to_owned(),
            fingerprint: "bb".repeat(32),
        };
        let _ = store("x", &newer, at(1_100));
        let entry = cached("x", at(1_100)).expect("fresh");
        assert_eq!(entry.not_after, "2040-01-01");
    }

    #[test]
    fn a_malformed_entry_is_stale_not_an_error() {
        let _guard = xdg_lock();
        xdg();
        let path = super::dir().join("x");
        std::fs::create_dir_all(super::dir()).expect("dir");
        std::fs::write(&path, "not a date\nnope\n").expect("write");
        assert!(cached("x", at(1_000)).is_none());
    }

    #[test]
    fn forgetting_removes_the_entry() {
        let _guard = xdg_lock();
        xdg();
        let _ = store("x", &served(), at(1_000));
        assert!(forget("x"));
        assert!(cached("x", at(1_000)).is_none());
        assert!(!forget("x"));
    }

    #[test]
    // The restore makes the directory world-writable, which this test accepts:
    // it only has to leave a writable parent behind for `TempDir`'s cleanup.
    #[allow(clippy::permissions_set_readonly_false)]
    fn a_write_under_a_read_only_parent_does_not_panic() {
        let _guard = xdg_lock();
        xdg();
        let root = super::dir().join("ro");
        std::fs::create_dir_all(&root).expect("dir");
        let mut permissions = std::fs::metadata(&root).expect("metadata").permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&root, permissions).expect("chmod");
        let entry = Cached {
            not_after: "2035-02-09".to_owned(),
            fingerprint: "aa".repeat(32),
        };
        // A root-owned sandbox can still write into the read-only directory, so
        // the write's answer has to agree with what a read then finds.
        assert_eq!(
            store("ro/x", &entry, at(1_000)),
            cached("ro/x", at(1_000)).is_some()
        );
        let mut permissions = std::fs::metadata(&root).expect("metadata").permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&root, permissions).expect("chmod");
    }
}
