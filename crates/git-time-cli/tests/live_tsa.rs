//! The live network path: one public authority, a real commit, a real verdict.
//!
//! Unlike every other integration test this one talks to the internet. It seals
//! through **FreeTSA** (`https://freetsa.org/tsr`, anchored at
//! `https://freetsa.org/files/cacert.pem`) by default; set `GIT_TIME_LIVE_TSA_URL`
//! to another RFC 3161 endpoint to seal through that one instead, in which case
//! the endpoint's own self-signed root is fetched as the anchor. Exactly one
//! authority is configured, so `time.required` is one and every failure names
//! that one authority.
//!
//! It is `#[ignore]` so the ordinary suite stays offline, and it skips — with a
//! `live_tsa: SKIP:` line, the reason and a success — only when the network is
//! clearly unusable: the anchor fetch failed with a connection, DNS or TLS
//! error, or the seal ran and recorded nothing but timeout/transport failures.
//!
//! A verdict that is not `SEALED` although the network answered is a **failure**,
//! not a skip: an `UNSEALED` commit, an `UNDER-QUORUM` block, or a `Fail` line
//! naming an unreadable anchor, a rejected policy or a malformed response all
//! mean the evidence path regressed. In that case the test asserts `verify`
//! exited `1` and quotes its output, so the judge is proven to agree.
//!
//! Both temporary directories own their cleanup, and the anchors are removed
//! explicitly on every path — the bundle under `$XDG_CONFIG_HOME/git-time/anchors`
//! with its `.pem.new` staging, and any `~/.config/git-time/anchors/*.pem` that
//! appeared during the run — so a skip or a failure leaves nothing behind. The
//! developer's git, XDG and `git-time` environment is kept out, and the binary's
//! own directory goes in front of `PATH` so the installed shims find it.
//!
//! Run it with:
//!
//! ```console
//! $ cargo test -p git-time-cli --test live_tsa -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use git_time_core::presets;
use tempfile::TempDir;

/// The binary under test, built by cargo for this integration test.
const BIN: &str = env!("CARGO_BIN_EXE_git-time");

/// The config id of the single authority the test configures.
const ID: &str = "live";

/// The preset used when [`TSA_URL_VARIABLE`] is unset.
const DEFAULT_PRESET: &str = "freetsa";

/// The variable that swaps the authority the test seals with.
const TSA_URL_VARIABLE: &str = "GIT_TIME_LIVE_TSA_URL";

/// The authority the run seals with.
struct Authority {
    /// The timestamp endpoint.
    url: String,
    /// Where its anchor bundle is fetched from; the endpoint itself when it was
    /// chosen by the environment.
    anchor_url: String,
    /// The TSA policy to request, for a preset that publishes one.
    policy: Option<String>,
}

impl Authority {
    /// FreeTSA, or the endpoint [`TSA_URL_VARIABLE`] names.
    fn selected() -> Self {
        let override_url = std::env::var(TSA_URL_VARIABLE)
            .ok()
            .filter(|url| !url.trim().is_empty());
        if let Some(url) = override_url {
            // A hand-picked endpoint may be a load balancer whose GET answers
            // prose, so its own URL is also the anchor source: the fetch asks
            // it for a token and takes the self-signed root of the reply.
            return Self {
                anchor_url: url.clone(),
                url,
                policy: None,
            };
        }
        let preset = presets::find(DEFAULT_PRESET).expect("the freetsa preset exists");
        Self {
            url: preset.url.to_owned(),
            anchor_url: preset.anchor_url.to_owned(),
            policy: preset.policy.map(str::to_owned),
        }
    }
}

/// A throwaway repository and the XDG directory its anchors land in.
struct Live {
    repo: TempDir,
    xdg: TempDir,
    /// The anchors present in the developer's directory before the run, so the
    /// cleanup removes only what this run created.
    home_anchors_before: Vec<PathBuf>,
}

impl Live {
    /// Initialise a repository that is insulated from the developer's config.
    fn new() -> Self {
        let home_anchors_before = Self::home_anchors()
            .and_then(|dir| std::fs::read_dir(dir).ok())
            .map(anchor_files)
            .unwrap_or_default();
        let live = Self {
            repo: TempDir::new().expect("repo dir"),
            xdg: TempDir::new().expect("xdg dir"),
            home_anchors_before,
        };
        let initialized = live.git(&["init", "-q", "-b", "main"]);
        assert!(
            initialized.status.success(),
            "git init: {}",
            text(&initialized.stderr)
        );
        for args in [
            ["config", "user.name", "Live Test"],
            ["config", "user.email", "live@example.com"],
            ["config", "commit.gpgsign", "false"],
            // One authority is configured, so one answer is a seal.
            ["config", "time.required", "1"],
            // The default deadline bounds a bad day at ten seconds; this keeps
            // the whole test inside one.
            ["config", "time.deadline", "10s"],
        ] {
            let configured = live.git(&args);
            assert!(
                configured.status.success(),
                "git {args:?}: {}",
                text(&configured.stderr)
            );
        }
        live
    }

    fn path(&self) -> &Path {
        self.repo.path()
    }

    fn anchors(&self) -> PathBuf {
        self.xdg.path().join("git-time/anchors")
    }

    /// Where the test pins its one anchor; the XDG default, named explicitly so
    /// the cleanup and the policy cannot disagree about the file.
    fn anchor_path(&self) -> PathBuf {
        self.anchors().join(format!("{ID}.pem"))
    }

    /// The developer's anchor directory, when `HOME` names one.
    fn home_anchors() -> Option<PathBuf> {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/git-time/anchors"))
    }

    /// The environment every child gets: no developer config, our own XDG, and
    /// the binary's directory first on `PATH` so the shims resolve it.
    fn env(&self) -> Vec<(&'static str, String)> {
        let bin_dir = Path::new(BIN).parent().expect("the binary has a directory");
        let path = std::env::var_os("PATH").unwrap_or_default();
        vec![
            ("GIT_CONFIG_GLOBAL", "/dev/null".to_owned()),
            ("GIT_CONFIG_SYSTEM", "/dev/null".to_owned()),
            (
                "XDG_CONFIG_HOME",
                self.xdg.path().to_string_lossy().into_owned(),
            ),
            (
                "PATH",
                format!("{}:{}", bin_dir.display(), path.to_string_lossy()),
            ),
        ]
    }

    fn command(&self, program: &str, args: &[&str]) -> Output {
        Command::new(program)
            .arg("-C")
            .arg(self.path())
            .args(args)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_TIME_SKIP")
            // The network is the point: a fetch stub from the outer shell must
            // not stand in for it.
            .env_remove("GIT_TIME_ANCHOR_FETCH_CMD")
            .envs(self.env())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("runs the command")
    }

    fn git(&self, args: &[&str]) -> Output {
        self.command("git", args)
    }

    fn time(&self, args: &[&str]) -> Output {
        self.command(BIN, args)
    }

    /// Commit one file and hand back the output of the whole call.
    fn commit(&self, message: &str) -> Output {
        let name = format!("{}.txt", message.replace(' ', "-"));
        std::fs::write(self.path().join(&name), message).expect("writes the file");
        let added = self.git(&["add", &name]);
        assert!(added.status.success(), "{}", text(&added.stderr));
        self.git(&["commit", "-m", message])
    }
}

impl Drop for Live {
    /// Remove the anchors the run created. The `TempDir` fields would take our
    /// XDG copy with them, but the deletion is explicit so the guarantee holds
    /// even where `XDG_CONFIG_HOME` is not insulated.
    fn drop(&mut self) {
        if let Ok(entries) = std::fs::read_dir(self.anchors()) {
            for path in anchor_files(entries) {
                let _ = std::fs::remove_file(path);
            }
        }
        let home = Self::home_anchors();
        if let Some(home) = &home
            && *home != self.anchors()
            && let Ok(entries) = std::fs::read_dir(home)
        {
            for path in anchor_files(entries) {
                if !self.home_anchors_before.contains(&path) {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}

/// The `.pem` bundles and `.pem.new` staging files of a directory listing.
fn anchor_files(entries: std::fs::ReadDir) -> Vec<PathBuf> {
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".pem") || name.ends_with(".pem.new"))
        })
        .collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn skip(reason: &str) {
    eprintln!("live_tsa: SKIP: {reason}; the offline suite is unaffected");
}

/// Whether `text` reads as the network, not the code, being unavailable: a
/// connection, DNS or TLS failure from the anchor fetch.
///
/// `reqwest`'s own summary of every such failure is `error sending request for
/// url …`; the markers beside it are the causes it names when it names any, and
/// keep the function honest if the summary ever changes.
fn network_error(text: &str) -> bool {
    const MARKERS: [&str; 11] = [
        "dns",
        "connect",
        "connection",
        "tls",
        "handshake",
        "peer certificate",
        "timed out",
        "timeout",
        "unreachable",
        "no route",
        "error sending request",
    ];
    let lowered = text.to_ascii_lowercase();
    MARKERS.iter().any(|marker| lowered.contains(marker))
}

/// Whether one recorded `Fail` reason is the authority staying away rather than
/// evidence of a bug.
///
/// The seal writes exactly three network shapes: `timeout` when the deadline
/// abandoned the attempt, a transport error when no response arrived, and the
/// HTTP status a proxy or the authority itself answered. Everything else —
/// `malformed timestamp response`, `rejected (status …)`, `invalid-…`, a missing
/// anchor — is a reason to fail.
fn outage(reason: &str) -> bool {
    reason == "timeout"
        || reason.starts_with("timestamp authority request failed")
        || reason.starts_with("http 5")
        || reason.starts_with("http 429")
}

#[test]
#[ignore = "talks to the public timestamp authorities over the network"]
fn a_public_authority_seals_a_commit_and_verify_passes() {
    let live = Live::new();
    let authority = Authority::selected();

    // The hooks are local; only the authority below needs the network.
    let installed = live.time(&["install", "--no-tsa"]);
    assert!(
        installed.status.success(),
        "install failed: {}",
        text(&installed.stderr)
    );

    let anchor_path = live.anchor_path().to_string_lossy().into_owned();
    let mut add = vec![
        "tsa".to_owned(),
        "add".to_owned(),
        authority.url.clone(),
        "--id".to_owned(),
        ID.to_owned(),
        "--anchor".to_owned(),
        anchor_path,
    ];
    if let Some(policy) = &authority.policy {
        add.push("--policy".to_owned());
        add.push(policy.clone());
    }
    let add: Vec<&str> = add.iter().map(String::as_str).collect();
    let added = live.time(&add);
    assert!(
        added.status.success(),
        "tsa add failed: {}",
        text(&added.stderr)
    );

    let fetched = live.time(&["anchor", "fetch", &authority.anchor_url, "--id", ID]);
    if !fetched.status.success() {
        let why = text(&fetched.stderr);
        if network_error(&why) {
            skip(&format!(
                "cannot fetch the anchor from {}: {}",
                authority.anchor_url,
                why.trim()
            ));
            eprintln!("live_tsa: fetch said:\n{why}");
            return;
        }
        panic!(
            "anchor fetch from {} failed for a non-network reason: {why}",
            authority.anchor_url
        );
    }
    assert!(
        std::fs::metadata(live.anchor_path()).is_ok_and(|metadata| metadata.len() > 0),
        "the fetch left no anchor at {}",
        live.anchor_path().display()
    );

    let output = live.commit("live seal");
    let stderr = text(&output.stderr);
    if !output.status.success() {
        // Only the commit itself failing is an error here: git ignoring the
        // hook is not possible on a successful commit.
        panic!("commit failed: {stderr}");
    }
    // Under quorum still prints `sealed`; an absent line means the hook never
    // got as far as stamping, which the network answer no longer excuses.
    assert!(
        stderr.contains("rfc3161: sealed"),
        "the hook did not seal: {stderr}"
    );

    let verify = live.time(&["verify"]);
    let stdout = text(&verify.stdout);
    let verdict = text(&verify.stderr);
    let answers: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix(&format!("{ID}: ")))
        .collect();

    if verify.status.success() {
        assert!(
            stdout.contains(" SEALED"),
            "the network answered but the verdict is not SEALED: {stdout}{verdict}"
        );
        assert!(
            stdout.starts_with("PASS"),
            "the verdict is SEALED but not a PASS: {stdout}{verdict}"
        );
    } else {
        // The judge has to agree with the failure, or the test below would be
        // asserting something `verify` does not call a failure.
        assert_eq!(
            verify.status.code(),
            Some(1),
            "verify did not exit 1: {stdout}{verdict}"
        );
        let only_outages = !answers.is_empty()
            && answers
                .iter()
                .all(|answer| answer.strip_prefix("fail: ").is_some_and(outage));
        if only_outages && stdout.contains("UNDER-QUORUM") {
            skip("no authority answered (only timeout/transport failures recorded)");
            eprintln!("live_tsa: verify said:\n{stdout}{verdict}");
            return;
        }
        panic!(
            "the network answered but the seal did not hold ({}):\n{stdout}{verdict}",
            if stdout.contains("UNSEALED") {
                "UNSEALED"
            } else {
                "not SEALED"
            }
        );
    }

    // The promise the seal makes about the rest of the repository.
    let status = live.git(&["status", "--porcelain"]);
    assert_eq!(text(&status.stdout).trim(), "", "the worktree stays clean");
    let fsck = live.git(&["fsck", "--no-progress"]);
    assert!(fsck.status.success(), "git fsck: {}", text(&fsck.stderr));

    eprintln!(
        "live_tsa: sealed through {}, verdict: {}",
        authority.url,
        stdout.lines().next().unwrap_or_default()
    );
}
