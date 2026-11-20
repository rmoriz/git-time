//! A week-long cache of the root expiry a probe answered for an authority.
//!
//! This is not the pin. A pin is a bundle the user chose and the verifier holds
//! an imprint against, while a probed date is provisional display material
//! until a seal pins the root. An entry is therefore dropped after [`TTL`]
//! rather than trusted, and a stale or malformed entry only means "ask again":
//! the request costs less than showing a date that a rotation has outlived.

use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use der::Encode as _;
use git_time_core::presets::Preset;

/// How long a probed answer is shown: one week.
pub const TTL: i64 = 7 * 86_400;

/// How long a leaving picker waits for the rows already in flight.
///
/// Neither fetch path bounds a quit: a stub runs through `Command::output()`
/// with no timeout at all, and the network path times each request — one bundle
/// plus every chain member — not the probe. Two seconds is long enough for a git
/// call that is already exiting to hand over what it has, and short enough that
/// `q`, Esc and Ctrl-C still feel immediate.
pub const SETTLE: Duration = Duration::from_secs(2);

/// One answered probe: the root's `notAfter` day and the fingerprint of the
/// root it names.
///
/// The fingerprint is the bare lowercase hex SHA-256 that
/// [`super::anchors::fingerprint`] computes — 64 characters, never the SHA-1
/// spelling most presets publish and never the raw bytes of the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cached {
    pub not_after: String,
    pub fingerprint: String,
}

/// The directory the entries live in: the probe leaf under
/// [`super::anchors::config_home`], so the cache stays a sibling of the pins.
#[must_use]
pub fn dir() -> PathBuf {
    super::anchors::config_home().join("git-time").join("probe")
}

/// The cached answer for `id`, only when it is younger than [`TTL`].
///
/// The entry is one line of three tab-separated fields: the day, the second it
/// was fetched, and the fingerprint. Anything else — a missing file, a short or
/// long line, a non-numeric second, a day that is not a day, a fingerprint that
/// is not 64 lowercase hex — is stale rather than an error.
#[must_use]
pub fn cached(id: &str, now: jiff::Timestamp) -> Option<Cached> {
    let text = fs::read_to_string(dir().join(id)).ok()?;
    let mut fields = text.trim_end().split('\t');
    let not_after = fields.next()?;
    let at = fields.next()?.parse::<i64>().ok()?;
    let fingerprint = fields.next()?;
    if fields.next().is_some()
        || now.as_second().saturating_sub(at) > TTL
        || not_after.parse::<jiff::civil::Date>().is_err()
        || fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
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
///
/// A refresh no longer calls this: it re-queues every row and lets a `Known`
/// answer overwrite the entry, so a failed fetch leaves the previous one to age
/// out against [`TTL`]. This is the "drop it for real" path, used by the tests
/// to start from an empty cache.
#[must_use]
#[allow(dead_code)]
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
    /// The reply carried no certificate, its date is not a date, or a matched
    /// certificate could not be re-encoded — nothing of it can be judged.
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
/// A matched certificate whose date is not `YYYY-MM-DD` is no candidate, and a
/// re-encode failure is no candidate either; when nothing survives and one of
/// those happened, the reply parsed but cannot be judged, so it is
/// [`Served::Failed`]. A match anywhere still wins over both.
#[must_use]
pub fn probed_from(preset: &Preset, bundle: &[u8], now: jiff::Timestamp) -> Served {
    let certificates = super::anchors::parse_certificates(bundle);
    if certificates.is_empty() {
        return Served::Failed;
    }

    let mut matched: Vec<Cached> = Vec::new();
    let mut unjudgeable = false;
    for certificate in certificates {
        let Ok(der) = certificate.to_der() else {
            unjudgeable = true;
            continue;
        };
        if super::install::fingerprint_matches(preset.fingerprints, &der).is_none() {
            continue;
        }
        let not_after = super::anchors::not_after(&certificate);
        // A date that is not a day cannot win a greatest-date selection, so it
        // is dropped now rather than after one has already been picked.
        if not_after.parse::<jiff::civil::Date>().is_err() {
            unjudgeable = true;
            continue;
        }
        matched.push(Cached {
            not_after,
            fingerprint: super::anchors::fingerprint(&der),
        });
    }
    if matched.is_empty() {
        return if unjudgeable {
            Served::Failed
        } else {
            Served::Unpublished
        };
    }

    // The greatest date that is still live, else the greatest date at all: an
    // all-expired reply still names a date, and `expired` marks it later. The
    // dates sort as strings because every one of them is `YYYY-MM-DD`. At least
    // one candidate exists, so the choice cannot fall through.
    let chosen = matched
        .iter()
        .filter(|served| !super::anchors::expired(&served.not_after, now))
        .max_by(|left, right| left.not_after.cmp(&right.not_after))
        .or_else(|| {
            matched
                .iter()
                .max_by(|left, right| left.not_after.cmp(&right.not_after))
        })
        .expect("`matched` is not empty");
    Served::Known(chosen.clone())
}

/// How many bundles are fetched at once.
///
/// One thread per row would put twenty-odd sockets in front of the picker's
/// first frame; four keep the frame free, and a hang only costs a quarter of
/// the table instead of all of it.
pub const PROBE_THREADS: usize = 4;

/// One fetch: the bundle at `url`, with the certificates of `chain` appended.
///
/// Injected so a test answers from a fixture and never opens a socket.
pub type Fetch = Arc<dyn Fn(&str, &[&str]) -> Result<Vec<u8>, String> + Send + Sync>;

/// The real fetch, on a runtime of its own per call.
///
/// The threads are detached, so a runtime shared between them would have to
/// outlive every worker; building one per call is cheap next to the socket and
/// keeps the lifetime local.
#[must_use]
pub fn network_fetch() -> Fetch {
    Arc::new(|url, chain| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("cannot build the runtime: {error}"))?;
        runtime.block_on(super::anchors::fetch_chain(url, chain))
    })
}

/// The queue the threads take rows from.
struct Queue {
    rows: VecDeque<usize>,
    /// Rows a thread has popped but not yet answered for: part of `pending`, so
    /// a caller that waits for zero is not racing a reply still being fetched.
    in_flight: usize,
    closed: bool,
}

/// Everything the workers share with the `Prober` that owns them.
struct Shared {
    presets: &'static [Preset],
    fetch: Fetch,
    queue: Mutex<Queue>,
    wake: Condvar,
    failed: AtomicUsize,
}

/// A queue of rows being probed by detached threads, and their results.
///
/// The process exit ends the threads, so nothing is ever joined: a prober that
/// is dropped closes the queue and lets the workers wind down on their own.
pub struct Prober {
    shared: Arc<Shared>,
    results: Receiver<(usize, Served)>,
}

impl Prober {
    /// Queue every preset except the `skip`ped indices and start the workers.
    #[must_use]
    pub fn start(presets: &'static [Preset], fetch: Fetch, skip: &[usize]) -> Self {
        let mut rows = VecDeque::new();
        enqueue(&mut rows, presets.len(), skip);
        let shared = Arc::new(Shared {
            presets,
            fetch,
            queue: Mutex::new(Queue {
                rows,
                in_flight: 0,
                closed: false,
            }),
            wake: Condvar::new(),
            failed: AtomicUsize::new(0),
        });
        let (sender, results) = mpsc::channel();
        for _ in 0..PROBE_THREADS {
            let shared = Arc::clone(&shared);
            let sender = sender.clone();
            std::thread::spawn(move || work(&shared, &sender));
        }
        Self { shared, results }
    }

    /// Queue every preset except the `skip`ped indices again, whether or not an
    /// earlier run has delivered or is still working on them.
    ///
    /// A row can therefore be reported more than once: [`Prober::drain`]'s
    /// caller keys by index and keeps the last answer, and a [`Served::Known`]
    /// store overwrites the entry the earlier answer left — the cache holds one
    /// date per authority, so the newest reply is the one that counts.
    pub fn refresh(&self, skip: &[usize]) {
        {
            let mut queue = lock(&self.shared);
            enqueue(&mut queue.rows, self.shared.presets.len(), skip);
        }
        self.shared.wake.notify_all();
    }

    /// Every result that has arrived since the last call.
    ///
    /// An index may arrive more than once — see [`Prober::refresh`] — so a
    /// caller keys by index rather than counting the results.
    #[must_use]
    pub fn drain(&self) -> Vec<(usize, Served)> {
        self.results.try_iter().collect()
    }

    /// Close the queue and take every answer still in flight, in arrival order.
    ///
    /// The queue closes first, so a row no worker has taken up is given back
    /// instead of being fetched into a screen that is already leaving. The
    /// workers then finish what they hold and drop their senders, which is what
    /// ends the receive: nothing is joined, and [`SETTLE`] bounds the whole wait
    /// against one instant, because neither fetch path bounds a quit. Whatever
    /// has not arrived by then is dropped; the cache write happens before the
    /// send, so a dropped answer is still cached for the next run.
    ///
    /// This is the last drain: [`Prober::drain`] would no longer see the queue's
    /// late answers because the receiver is consumed here.
    #[must_use]
    pub fn settle(self) -> Vec<(usize, Served)> {
        {
            let mut queue = lock(&self.shared);
            queue.closed = true;
        }
        self.shared.wake.notify_all();
        let deadline = Instant::now() + SETTLE;
        let mut results = self.drain();
        // `checked_duration_since` also ends the loop once the deadline has
        // passed during the previous receive.
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            // Either error (the deadline, or every sender gone) ends the drain.
            match self.results.recv_timeout(left) {
                Ok(result) => results.push(result),
                Err(_) => break,
            }
        }
        results
    }

    /// The rows still queued or in flight.
    //
    // The headless drain in `tsa::preset_list` waits on this; the picker repaints
    // on delivered answers and, at the deadline-bounded leave, waits on the
    // channel rather than this counter. The tests that want a finished run read
    // it too.
    #[must_use]
    pub fn pending(&self) -> usize {
        let queue = lock(&self.shared);
        queue.rows.len() + queue.in_flight
    }

    /// How many rows answered [`Served::Failed`] or [`Served::Unpublished`].
    //
    // The picker counts cells instead, so only this module's tests read it; the
    // tally has to survive a cell being overwritten by a later answer, which is
    // why the count lives here rather than being derived from a `Probes`.
    #[allow(dead_code)]
    #[must_use]
    pub fn failed(&self) -> usize {
        self.shared.failed.load(Ordering::Relaxed)
    }
}

impl Drop for Prober {
    fn drop(&mut self) {
        let mut queue = lock(&self.shared);
        queue.closed = true;
        drop(queue);
        self.shared.wake.notify_all();
    }
}

/// Take the queue lock, ignoring a panic in a previous holder.
fn lock(shared: &Shared) -> MutexGuard<'_, Queue> {
    shared
        .queue
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Append every index below `count` that is not in `skip`, in order.
fn enqueue(rows: &mut VecDeque<usize>, count: usize, skip: &[usize]) {
    rows.extend((0..count).filter(|index| !skip.contains(index)));
}

/// The in-flight mark of one popped row.
///
/// A guard rather than a written-out decrement: a panic inside the injected
/// fetch would otherwise leave the counter above zero for good, and every
/// caller that reads `pending() == 0` as "done" would wait forever. Dropped
/// after the result is sent and counted, so zero still means both happened.
struct InFlight<'a>(&'a Shared);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut queue = lock(self.0);
        queue.in_flight = queue.in_flight.saturating_sub(1);
        drop(queue);
        // A caller polling `pending` needs no wake, but a queue that is emptied
        // from here should not leave anyone else's wait asleep on it.
        self.0.wake.notify_all();
    }
}

/// One worker: take a row, fetch it, judge it, store a date only if justified,
/// and report the answer.
fn work(shared: &Shared, sender: &Sender<(usize, Served)>) {
    loop {
        let index = {
            let mut queue = lock(shared);
            loop {
                if queue.closed {
                    return;
                }
                if let Some(index) = queue.rows.pop_front() {
                    queue.in_flight += 1;
                    break index;
                }
                queue = shared
                    .wake
                    .wait(queue)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        };
        // Held across the fetch, the judgement and the send, so the row stays
        // pending until its answer is in the channel — or until a panic here
        // gives it back.
        let in_flight = InFlight(shared);

        let preset = &shared.presets[index];
        let now = jiff::Timestamp::now();
        let served = match (shared.fetch)(preset.url, preset.chain) {
            Ok(bundle) => {
                let served = probed_from(preset, &bundle, now);
                if let Served::Known(cached) = &served {
                    let _ = store(preset.name, cached, now);
                }
                served
            }
            // Both failures are one `Failed` and the reason is dropped: the
            // display shows a marker, not a cause, and a reason field would be
            // guessed at until a caller needs it.
            Err(_) => Served::Failed,
        };
        let counted = matches!(served, Served::Failed | Served::Unpublished);
        // A row whose result the caller can no longer receive was not a failure
        // of the probe, so it is only counted once the send worked.
        let sent = sender.send((index, served)).is_ok();
        if counted && sent {
            shared.failed.fetch_add(1, Ordering::Relaxed);
        }
        // Last, so `pending() == 0` already means sent and counted.
        drop(in_flight);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};

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

    #[test]
    fn both_state_dirs_hang_off_one_config_home() {
        let _guard = xdg_lock();
        let base = std::path::PathBuf::from(xdg());
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &base) };
        let home = crate::cmd::anchors::config_home();
        assert_eq!(home, base);
        assert_eq!(super::dir(), home.join("git-time/probe"));
        assert_eq!(crate::cmd::anchors::dir(), home.join("git-time/anchors"));
    }

    /// Write one raw entry line, which `store` cannot do once a field is shaped
    /// wrong.
    fn write_entry(id: &str, line: &str) {
        std::fs::create_dir_all(super::dir()).expect("probe dir");
        std::fs::write(super::dir().join(id), line).expect("entry");
    }

    #[test]
    fn only_a_day_and_a_bare_sha256_parse() {
        let _guard = xdg_lock();
        let now = jiff::Timestamp::from_second(1_800_000_000).expect("instant");
        let good = "cc".repeat(32);
        let cases = [
            ("2041-03-07", good.clone(), true),
            (
                "2041-03-07",
                format!("CC:{}", good[2..].to_uppercase()),
                false,
            ),
            ("2041-03-07", good[..40].to_owned(), false),
            ("2041-03-07", good[..63].to_owned(), false),
            ("2041-03-07", format!("{good}0"), false),
            ("2041-03-07", "zz".repeat(32), false),
            ("07.03.2041", good, false),
        ];
        for (index, (day, fingerprint, accepted)) in cases.iter().enumerate() {
            let id = format!("shape-{index}");
            write_entry(&id, &format!("{day}\t1800000000\t{fingerprint}"));
            assert_eq!(
                super::cached(&id, now).is_some(),
                *accepted,
                "{day} {fingerprint}"
            );
        }
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
                assert_eq!(cached.not_after, "2041-03-07");
                // The cache and every later comparison spell a fingerprint as
                // lowercase hex; a nearby helper hands out the uppercase colon
                // form instead, so the spelling is pinned here.
                assert_eq!(cached.fingerprint.len(), 64);
                assert!(
                    cached
                        .fingerprint
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                    "{}",
                    cached.fingerprint
                );
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

    /// The stale 2020 root followed by the live FreeTSA root, both PEM, with the
    /// preset values that publish each — so a caller publishes either or both.
    /// The concatenation also exercises the parser's PEM scanner across blocks.
    fn stale_and_live() -> (Vec<u8>, &'static str, &'static str) {
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
        let stale_fp: &'static str = Box::leak(colon(&stale).into_boxed_str());
        let live_fp: &'static str = Box::leak(colon(&freetsa_der()).into_boxed_str());
        (bundle, stale_fp, live_fp)
    }

    fn preset_publishing(fingerprints: &'static [&'static str]) -> Preset {
        Preset {
            name: "both",
            url: "",
            anchor_url: "",
            chain: &[],
            alg: "sha256",
            policy: None,
            fingerprints,
            insecure_http: false,
            curated: false,
        }
    }

    #[test]
    fn the_newest_live_matching_root_wins() {
        // By 2030 the 2020 root is dead and the live one's date is the one shown.
        let (bundle, stale_fp, live_fp) = stale_and_live();
        let published: &'static [&'static str] =
            Box::leak(vec![stale_fp, live_fp].into_boxed_slice());
        match super::probed_from(&preset_publishing(published), &bundle, at(1_900_000_000)) {
            super::Served::Known(cached) => assert_eq!(cached.not_after, "2041-03-07"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn among_live_roots_the_newest_date_is_shown() {
        // Neither root is expired in 1970; the greatest date still has to win.
        let (bundle, stale_fp, live_fp) = stale_and_live();
        let published: &'static [&'static str] =
            Box::leak(vec![stale_fp, live_fp].into_boxed_slice());
        match super::probed_from(&preset_publishing(published), &bundle, at(1_000)) {
            super::Served::Known(cached) => assert_eq!(cached.not_after, "2041-03-07"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_all_expired_reply_still_names_the_greatest_date() {
        // Only the dead root is published, so the fallback answers; the date is
        // reported and `expired` marks it where it is shown.
        let (bundle, stale_fp, _live_fp) = stale_and_live();
        let published: &'static [&'static str] = Box::leak(vec![stale_fp].into_boxed_slice());
        match super::probed_from(&preset_publishing(published), &bundle, at(1_600_000_000)) {
            super::Served::Known(cached) => assert_eq!(cached.not_after, "2020-02-01"),
            other => panic!("{other:?}"),
        }
    }

    thread_local! {
        /// The log the next `answering` closure on this thread writes to.
        ///
        /// A thread-local rather than an argument keeps the closure shape the
        /// worker takes, and one log per test keeps two tests' fetches apart:
        /// the presets are global, so a shared log could not attribute a URL.
        static URLS: RefCell<Option<Arc<Mutex<Vec<String>>>>> = const { RefCell::new(None) };
    }

    /// A fresh URL log, armed for the `answering` closure built on this thread.
    fn urls() -> Arc<Mutex<Vec<String>>> {
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        URLS.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&log)));
        log
    }

    /// A fetch that logs its URL and answers the PEM at `path` whatever it was
    /// asked for: every row gets the same FreeTSA root.
    fn answering(path: &'static str) -> super::Fetch {
        let log = URLS
            .with(|slot| slot.borrow_mut().take())
            .expect("call urls() first");
        Arc::new(move |url, _| {
            log.lock().unwrap().push(url.to_owned());
            std::fs::read(path).map_err(|error| error.to_string())
        })
    }

    /// The row of the FreeTSA preset: the one fingerprint a fixture can match.
    fn freetsa_index() -> usize {
        presets::PRESETS
            .iter()
            .position(|preset| preset.name == "freetsa")
            .expect("the freetsa preset")
    }

    /// Drain `prober` until nothing is queued or in flight, then answer what
    /// came back.
    ///
    /// The worker is threaded, so this polls with a bound; `pending` counts the
    /// rows in flight as well, which makes zero mean every reply is already in
    /// the channel rather than merely picked up.
    fn wait(prober: &super::Prober) -> Vec<(usize, super::Served)> {
        for _ in 0..250 {
            if prober.pending() == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(prober.pending(), 0, "the queue drains");
        prober.drain()
    }

    #[test]
    fn a_result_carries_the_index_and_is_stored() {
        let _guard = xdg_lock();
        xdg();
        urls();
        let _ = forget("freetsa");
        let prober = super::Prober::start(&presets::PRESETS, answering(FREETSA_ROOT), &[]);
        let results = wait(&prober);
        assert!(results.iter().any(|(index, served)| {
            *index == freetsa_index() && matches!(served, super::Served::Known(_))
        }));
        assert!(super::cached("freetsa", jiff::Timestamp::now()).is_some());
    }

    #[test]
    fn skipped_indices_are_not_fetched() {
        let _guard = xdg_lock();
        xdg();
        let urls = urls();
        let prober = super::Prober::start(&presets::PRESETS, answering(FREETSA_ROOT), &[1]);
        wait(&prober);
        let urls = urls.lock().unwrap();
        assert_eq!(urls.len(), presets::PRESETS.len() - 1, "the rest fetched");
        assert!(!urls.contains(&presets::PRESETS[1].url.to_owned()));
    }

    #[test]
    fn a_failing_fetch_counts_and_answers_failed() {
        let prober = super::Prober::start(
            &presets::PRESETS,
            Arc::new(|_, _| Err("down".to_owned())),
            &[],
        );
        let results = wait(&prober);
        assert!(
            results
                .iter()
                .all(|(_, served)| matches!(served, super::Served::Failed))
        );
        assert_eq!(prober.failed(), presets::PRESETS.len());
    }

    #[test]
    fn settling_takes_the_in_flight_rows_and_starts_no_other() {
        let _guard = xdg_lock();
        xdg();
        let urls = urls();
        // Log first, then park, so the log says which rows were taken up and the
        // workers cannot cycle through the table before `settle` is called.
        let log = Arc::clone(&urls);
        let fetch: super::Fetch = Arc::new(move |url, _| {
            log.lock().unwrap().push(url.to_owned());
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::read(FREETSA_ROOT).map_err(|error| error.to_string())
        });
        let prober = super::Prober::start(&presets::PRESETS, fetch, &[]);
        // Every worker parks on its first row; the rest of the table is queued.
        for _ in 0..200 {
            if urls.lock().unwrap().len() >= super::PROBE_THREADS {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let results = prober.settle();
        let asked = urls.lock().unwrap().len();
        assert_eq!(results.len(), asked, "every started row answered");
        assert!(
            asked < presets::PRESETS.len(),
            "the queue was not drained: {asked}"
        );
    }

    #[test]
    fn settling_gives_up_on_a_parked_fetch_at_the_deadline() {
        let _guard = xdg_lock();
        xdg();
        // The gate is never opened, so only the deadline can end the settle. The
        // URL is logged before the park so the test can see a worker has taken a
        // row: `settle` refunds an untaken row, and a refunded queue closes the
        // channel at once instead of waiting.
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let urls = urls();
        let log = Arc::clone(&urls);
        let fetch: super::Fetch = {
            let gate = Arc::clone(&gate);
            Arc::new(move |url, _| {
                log.lock().unwrap().push(url.to_owned());
                let (open, wake) = &*gate;
                let mut ready = open.lock().unwrap();
                while !*ready {
                    ready = wake.wait(ready).unwrap();
                }
                std::fs::read(FREETSA_ROOT).map_err(|error| error.to_string())
            })
        };
        let prober = super::Prober::start(&presets::PRESETS, fetch, &[]);
        for _ in 0..200 {
            if !urls.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!urls.lock().unwrap().is_empty(), "a worker took a row");
        let started = std::time::Instant::now();
        let results = prober.settle();
        let waited = started.elapsed();
        assert!(results.is_empty(), "nothing can answer: {}", results.len());
        assert!(waited >= super::SETTLE, "waited the deadline: {waited:?}");
        assert!(
            waited < std::time::Duration::from_secs(5),
            "and not much past it: {waited:?}"
        );
    }

    #[test]
    fn a_panicking_fetch_leaves_the_queue_drainable() {
        let _guard = xdg_lock();
        xdg();
        urls();
        // One row panics inside the fetch; that worker dies, but the rest of
        // the table still has to come back and `pending` still has to reach
        // zero, or a caller waiting on it would hang for good.
        let panicky = presets::PRESETS[freetsa_index()].url;
        let fetch: super::Fetch = Arc::new(move |url, _| {
            if url == panicky {
                panic!("the fixture panics here");
            }
            std::fs::read(FREETSA_ROOT).map_err(|error| error.to_string())
        });
        let prober = super::Prober::start(&presets::PRESETS, fetch, &[]);
        let results = wait(&prober);
        assert_eq!(results.len(), presets::PRESETS.len() - 1);
    }

    #[test]
    fn refresh_mid_run_reports_a_row_twice() {
        let _guard = xdg_lock();
        xdg();
        urls();
        // The gate parks every worker inside its fetch, so no row can finish
        // before the refresh: the mid-run case is the only one that can leave a
        // row both in flight and queued again.
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let fetch: super::Fetch = {
            let gate = Arc::clone(&gate);
            Arc::new(move |_, _| {
                let (open, wake) = &*gate;
                let mut ready = open.lock().unwrap();
                while !*ready {
                    ready = wake.wait(ready).unwrap();
                }
                drop(ready);
                std::fs::read(FREETSA_ROOT).map_err(|error| error.to_string())
            })
        };
        let prober = super::Prober::start(&presets::PRESETS, fetch, &[]);
        prober.refresh(&[]);
        // Every row is outstanding once before and once after the refresh, and
        // none has finished, so both runs are all still pending.
        assert_eq!(prober.pending(), 2 * presets::PRESETS.len());
        assert!(prober.drain().is_empty());

        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        let mut indices: Vec<usize> = wait(&prober).into_iter().map(|(index, _)| index).collect();
        indices.sort_unstable();
        assert!(
            indices.windows(2).any(|pair| pair[0] == pair[1]),
            "an index is reported twice"
        );
    }

    #[test]
    fn refresh_queues_everything_again() {
        let _guard = xdg_lock();
        xdg();
        urls();
        let prober = super::Prober::start(&presets::PRESETS, answering(FREETSA_ROOT), &[]);
        wait(&prober);
        prober.refresh(&[]);
        assert!(prober.pending() >= presets::PRESETS.len());
        wait(&prober);
    }

    #[test]
    fn an_answer_without_a_date_leaves_the_cache_untouched() {
        let _guard = xdg_lock();
        xdg();
        let _ = forget("freetsa");
        let failing = super::Prober::start(
            &presets::PRESETS,
            Arc::new(|_, _| Err("down".to_owned())),
            &[],
        );
        let results = wait(&failing);
        assert!(
            results
                .iter()
                .all(|(_, served)| matches!(served, super::Served::Failed))
        );
        assert!(cached("freetsa", jiff::Timestamp::now()).is_none());

        // A readable reply that names a root the authority does not publish is
        // `Unpublished`, and it may not write a date either.
        urls();
        let _ = forget("aped");
        let aped: &'static Preset = presets::find("aped").expect("preset");
        let unpublished =
            super::Prober::start(std::slice::from_ref(aped), answering(FREETSA_ROOT), &[]);
        let results = wait(&unpublished);
        assert!(matches!(
            results.as_slice(),
            [(0, super::Served::Unpublished)]
        ));
        assert!(cached("aped", jiff::Timestamp::now()).is_none());
    }
}
