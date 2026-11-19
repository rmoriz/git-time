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

use der::Encode as _;
use git_time_core::presets::Preset;

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

/// What a probe reply justifies showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Served {
    /// A root the preset publishes, with the date and fingerprint to cache.
    Known(Cached),
    /// Certificates were parsed, but none of them is a root the preset
    /// publishes — the authority serves a leaf first, or the bundle holds only
    /// the path, or nothing at all.
    Unpublished,
    /// The reply carried no certificate, or its date is not a date.
    Failed,
}

/// What `bundle` says about `preset` at `now`: the newest still-live published
/// root in it, else the newest published root in it, else why neither exists.
///
/// Every certificate is checked against every value the preset publishes, and a
/// match on any of them is the whole check: a leaf can never carry a root's
/// fingerprint, so a match alone means this certificate is a root worth trusting
/// a date from. Doing this is what lets a prose answer or a leaf-first reply be
/// reported instead of printed.
///
/// A matched date that does not parse as `YYYY-MM-DD` is [`Served::Failed`]:
/// nothing sensible can be shown for it.
#[must_use]
pub fn probed_from(preset: &Preset, bundle: &[u8], now: jiff::Timestamp) -> Served {
    let certificates = super::anchors::parse_certificates(bundle);
    if certificates.is_empty() {
        return Served::Failed;
    }

    let mut matched: Vec<Cached> = Vec::new();
    for certificate in certificates {
        let Ok(der) = certificate.to_der() else {
            continue;
        };
        if super::install::fingerprint_matches(preset.fingerprints, &der).is_none() {
            continue;
        }
        matched.push(Cached {
            not_after: super::anchors::not_after(&certificate),
            fingerprint: super::anchors::fingerprint(&der),
        });
    }

    // The greatest date that is still live, else the greatest date at all; the
    // dates sort as strings because they are `YYYY-MM-DD`.
    let chosen = matched
        .iter()
        .filter(|served| !super::anchors::expired(&served.not_after, now))
        .max_by(|left, right| left.not_after.cmp(&right.not_after))
        .or_else(|| {
            matched
                .iter()
                .max_by(|left, right| left.not_after.cmp(&right.not_after))
        });
    let Some(chosen) = chosen else {
        return Served::Unpublished;
    };
    if chosen.not_after.parse::<jiff::civil::Date>().is_err() {
        return Served::Failed;
    }
    Served::Known(chosen.clone())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;
    use std::process::{Command, Stdio};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use git_time_core::presets::{self, Preset};

    use super::{Cached, TTL, cached, forget, store};

    /// The captured FreeTSA root: the one published fingerprint a test can match.
    const FREETSA_ROOT: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../git-time-core/tests/fixtures/freetsa_root.pem"
    );

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

    /// Run `openssl` with `args`, or panic with its stderr.
    fn openssl(args: &[&std::ffi::OsStr]) {
        let output = Command::new("openssl")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("openssl is available");
        assert!(
            output.status.success(),
            "openssl {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn os(value: &Path) -> &std::ffi::OsStr {
        value.as_os_str()
    }

    /// A config file carrying the CA extensions for `openssl req -x509`, once.
    fn ca_config(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("ca.cnf");
        std::fs::write(
            &path,
            "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\ncommonName=Common Name\n\
             [v3_ca]\nbasicConstraints=critical,CA:TRUE\n\
             keyUsage=critical,keyCertSign,cRLSign\n",
        )
        .expect("write CA config");
        path
    }

    /// A self-signed CA whose validity window closed in 2020, as PEM.
    fn stale_ca(dir: &Path) -> std::path::PathBuf {
        let key = dir.join("stale-key.pem");
        let ca = dir.join("stale-ca.pem");
        openssl(&[
            "req".as_ref(),
            "-x509".as_ref(),
            "-sha256".as_ref(),
            "-newkey".as_ref(),
            "ec".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_paramgen_curve:P-256".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_param_enc:named_curve".as_ref(),
            "-nodes".as_ref(),
            "-keyout".as_ref(),
            os(&key),
            "-out".as_ref(),
            os(&ca),
            "-not_before".as_ref(),
            "20200101000000Z".as_ref(),
            "-not_after".as_ref(),
            "20200201000000Z".as_ref(),
            "-subj".as_ref(),
            "/CN=stale-ca".as_ref(),
            "-config".as_ref(),
            os(&ca_config(dir)),
            "-extensions".as_ref(),
            "v3_ca".as_ref(),
        ]);
        ca
    }

    /// The DER of the first PEM certificate in `pem`.
    fn first_der(pem: &str) -> Vec<u8> {
        let body = pem
            .split_once("-----\n")
            .and_then(|(_, rest)| rest.split_once("\n-----END"))
            .map(|(body, _)| body.replace('\n', ""))
            .expect("a PEM certificate block");
        BASE64.decode(body).expect("base64")
    }

    /// The FreeTSA root's DER.
    fn freetsa_der() -> Vec<u8> {
        first_der(&std::fs::read_to_string(FREETSA_ROOT).expect("fixture"))
    }

    /// The SHA-256 fingerprint of `bytes`' first certificate in the preset
    /// spelling: uppercase, colon separated. `bytes` may be PEM or DER; a preset
    /// publishes the digest of the DER.
    fn colon(bytes: &[u8]) -> String {
        match std::str::from_utf8(bytes) {
            Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => {
                git_time_core::trust::fingerprint(&first_der(text))
            }
            _ => git_time_core::trust::fingerprint(bytes),
        }
    }

    #[test]
    fn a_published_root_yields_its_date() {
        let preset = presets::find("freetsa").expect("preset");
        let bundle = std::fs::read(FREETSA_ROOT).expect("fixture");
        match super::probed_from(preset, &bundle, at(1_000)) {
            super::Served::Known(cached) => {
                assert!(cached.not_after.starts_with("20"), "{}", cached.not_after);
                assert!(!cached.fingerprint.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_root_nothing_published_is_unpublished() {
        // The FreeTSA root is not a value the APED preset publishes.
        let preset = presets::find("aped").expect("preset");
        let other = std::fs::read(FREETSA_ROOT).expect("fixture");
        assert!(matches!(
            super::probed_from(preset, &other, at(1_000)),
            super::Served::Unpublished
        ));
    }

    #[test]
    fn prose_is_failed() {
        let preset = presets::find("freetsa").expect("preset");
        assert!(matches!(
            super::probed_from(preset, b"<html>204 OK</html>", at(1_000)),
            super::Served::Failed
        ));
    }

    #[test]
    fn the_newest_live_matching_root_wins() {
        // Two matching roots, one expired in 2020: the live one's date is the one
        // shown. Both are PEM, so the concatenation also exercises the parser's
        // PEM scanner across two blocks.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let stale = std::fs::read(stale_ca(dir.path())).expect("fixture");
        let live = std::fs::read(FREETSA_ROOT).expect("fixture");
        let mut bundle = stale.clone();
        bundle.extend(&live);
        assert_eq!(
            crate::cmd::anchors::parse_certificates(&bundle).len(),
            2,
            "both roots are readable from the bundle"
        );
        let (stale_fp, live_fp) = (colon(&stale), colon(&freetsa_der()));
        let stale_fp: &'static str = Box::leak(stale_fp.into_boxed_str());
        let live_fp: &'static str = Box::leak(live_fp.into_boxed_str());
        let published: &'static [&'static str] =
            Box::leak(vec![stale_fp, live_fp].into_boxed_slice());
        let preset = Preset {
            name: "both",
            url: "",
            anchor_url: "",
            chain: &[],
            alg: "sha256",
            policy: None,
            fingerprints: published,
            insecure_http: false,
            curated: false,
        };
        match super::probed_from(&preset, &bundle, at(1_000)) {
            super::Served::Known(cached) => assert_ne!(cached.not_after, "2020-02-01"),
            other => panic!("{other:?}"),
        }
    }
}
