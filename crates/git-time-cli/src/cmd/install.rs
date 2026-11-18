//! `git time install`: wire the hooks and pin authorities.
//!
//! What is always wired are the two hooks a commit actually needs: `post-commit`
//! for an ordinary commit and `post-merge` for a merge, which never runs
//! `post-commit`. `pre-commit` and `pre-merge-commit` are wired only under
//! `time.gate = pre-commit`, so a repository that does not want the hard gate
//! carries no extra hook.
//!
//! A foreign hook at any of those names is not overwritten: it is renamed next to
//! the shim as `<name>.pre-time` — or the next free `<name>.pre-time.<n>` when a
//! husky or pre-commit-framework run regenerated the hook since the last install
//! — and the shim runs it first, propagating its failure. The summary names every
//! preserve, so a user can see both originals survive. The hooks directory is the
//! one `git rev-parse --git-path hooks` answers, so a `core.hooksPath` from husky
//! or the pre-commit framework is where the shims land — not `.git/hooks`, which
//! those tools never run.
//!
//! `install` wires the hooks. The authority set belongs to the repository, not
//! to a flag: a repository that already has `time.tsa.*` keys keeps them
//! exactly as they are, and an empty one hands over to `tsa select` on a
//! terminal so `git time install` alone still ends in a working setup. A fetch
//! that fails only warns: the hooks are still worth wiring, and `doctor` names
//! the missing bundle. When the failure leaves an anchor path missing under the
//! gate, the summary says loudly that commits will be refused. A fetched bundle
//! is parsed into certificates before it replaces the pinned one, so prose
//! cannot masquerade as an anchor. `--no-tsa` writes no authority at all.

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use git_time_core::presets::Preset as Authority;
use git_time_core::repo::Repo;
use git_time_core::trust::AnchorStore;

use crate::cmd::{Exit, anchors, git_stdout, hooks, open};

/// What pinning one authority came to.
pub(crate) struct Pinned {
    /// The config id.
    pub(crate) id: &'static str,
    /// How many of its config keys were already set and left alone.
    pub(crate) kept: usize,
    /// Where its anchor is expected, and whether that path is now missing.
    pub(crate) missing_anchor: Option<PathBuf>,
    /// Whether the fetched root was not the fingerprint the preset expects, so
    /// the bundle was left unpinned.
    pub(crate) fingerprint_mismatch: bool,
}

/// Run `git time install`.
pub async fn run(directory: Option<std::path::PathBuf>, no_tsa: bool) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    let dir = match hooks::hooks_dir(&repo) {
        Ok(dir) => dir,
        Err(exit) => return exit,
    };
    let created = !dir.exists();
    if let Err(error) = std::fs::create_dir_all(&dir) {
        return Exit::config(format!(
            "cannot create the hooks directory {}: {error}",
            dir.display()
        ));
    }

    let gated = match gate(&repo) {
        Ok(gated) => gated,
        Err(exit) => return exit,
    };
    let wired = if gated {
        hooks::ALL_HOOKS.to_vec()
    } else {
        hooks::POST_HOOKS.to_vec()
    };

    let mut preserved = Vec::new();
    for name in &wired {
        match hooks::wire(&dir, name) {
            Ok(Some(chained)) => preserved.push(format!("{name} -> {chained}")),
            Ok(None) => {}
            Err(exit) => return exit,
        }
    }

    // The wiring is done, so say so before anything can take over the screen.
    if crate::cmd::doctor::binary_on_path().is_none() {
        eprintln!(
            "rfc3161: warning: git-time is not on PATH; the hooks will do nothing until it is"
        );
    }
    println!(
        "hooks dir: {}{}",
        dir.display(),
        if created { " (created)" } else { "" }
    );
    println!("wired: {}", wired.join(", "));
    if !preserved.is_empty() {
        println!("preserved: {}", preserved.join(", "));
    }

    // The authority set is the repository's, not the command line's: a
    // configured repository keeps what it has, and an empty one hands over to
    // the selector so `git time install` alone still ends in a working setup.
    let keep = !no_tsa && anchors::any_section(&repo).unwrap_or(false);
    let authorities: Vec<&Authority> = if no_tsa || keep {
        Vec::new()
    } else if std::io::stdin().is_terminal() {
        return crate::cmd::tsa::select(&repo, true, false).await;
    } else {
        return Exit::usage(
            "git time install: no authority is configured and stdin is not a terminal; use `git \
             time tsa select`, `git time tsa preset add <id>`, or `git time tsa add <url>`",
        );
    };
    let mut kept = 0_usize;
    let mut unpinned: Vec<(String, PathBuf)> = Vec::new();
    let mut mismatched = 0_usize;
    // What is already configured is not fetched again, but it is still checked:
    // an anchor path that does not load is exactly what doctor would name.
    if keep {
        for anchor in anchors::configured(&repo).unwrap_or_default() {
            if !anchor.path.exists() || !crate::cmd::tsa::pinned(&anchor.id, &anchor.path) {
                unpinned.push((anchor.id, anchor.path));
            }
        }
    }
    for authority in &authorities {
        match pin(&repo, authority).await {
            Ok(pinned) => {
                kept += pinned.kept;
                // A mismatch already said its loud line naming both values; the
                // generic "no anchor" warning would only repeat the tail of it.
                if pinned.fingerprint_mismatch {
                    mismatched += 1;
                } else if let Some(path) = pinned.missing_anchor {
                    unpinned.push((pinned.id.to_owned(), path));
                }
            }
            Err(exit) => return exit,
        }
    }

    if no_tsa {
        println!("tsa: none configured (--no-tsa)");
    } else if keep {
        let existing = anchors::configured(&repo).map_or(0, |anchors| anchors.len());
        println!("tsa: {existing} existing authority(ies) kept");
    } else {
        println!(
            "tsa: {} configured{}",
            authorities.len(),
            if kept > 0 {
                format!(" ({kept} existing key(s) kept)")
            } else {
                String::new()
            }
        );
    }
    if mismatched > 0 {
        println!(
            "tsa: {mismatched} root fingerprint(s) did not match; the bundle(s) were not pinned"
        );
    }
    for (id, path) in &unpinned {
        if gated {
            eprintln!(
                "rfc3161: warning: no anchor for `{id}` at {}; with time.gate = pre-commit every \
                 commit will be refused until it is pinned (run: git time install once the fetch works)",
                path.display()
            );
        } else {
            eprintln!(
                "rfc3161: warning: no anchor for `{id}` at {}; tokens of that authority cannot be \
                 verified until it is pinned",
                path.display()
            );
        }
    }
    Exit::ok()
}

/// Write the config of `authority` that is not set yet, and try to pin its
/// anchor.
///
/// A key that is already set is left alone, so a working configuration is not
/// clobbered. The config is written even when the fetch fails, so the authority
/// is listed and `doctor` can report the missing anchor instead of the entry
/// vanishing.
///
/// The anchor lands where the policy will read it: an already configured
/// `time.tsa.<id>.anchor` path wins over the default
/// `$XDG_CONFIG_HOME/git-time/anchors/<id>.pem`, because a freshly fetched
/// bundle the policy never looks at would print a fingerprint of the wrong file.
pub(crate) async fn pin(repo: &Repo, authority: &Authority) -> Result<Pinned, Exit> {
    let base = format!("time.tsa.{}", authority.name);
    // Read before writing: the key may be set already and is then the target.
    let configured = anchors::configured(repo)?
        .into_iter()
        .find(|anchor| anchor.id == authority.name)
        .map(|anchor| anchor.path);
    let path = match configured {
        Some(path) => path,
        None => anchors::dir().join(format!("{}.pem", authority.name)),
    };
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Err(Exit::config(format!(
            "cannot create the anchors directory {}: {error}",
            parent.display()
        )));
    }
    let anchor_path = path.to_string_lossy().into_owned();
    let mut fields = vec![
        ("url", authority.url.to_owned()),
        ("alg", authority.alg.to_owned()),
        ("anchor", anchor_path),
    ];
    if let Some(policy) = authority.policy {
        fields.push(("policy", policy.to_owned()));
    }
    if authority.insecure_http {
        fields.push(("insecure-http", "true".to_owned()));
    }
    let mut kept = 0_usize;
    for (field, value) in fields {
        if set(repo, &format!("{base}.{field}"), &value)? {
            kept += 1;
        }
    }

    let mut fingerprint_mismatch = false;
    let mut missing_anchor = None;
    match anchors::fetch(authority.anchor_url).await {
        Ok(bytes) => match install_anchor(authority, &path, &bytes) {
            Ok(fingerprint) => {
                // A pinned root is only worth something when the match is
                // visible: the reader has to be able to see that the fetch was
                // checked, not just that a file appeared.
                if let Some(expected) = authority.fingerprint {
                    println!("{}: root fingerprint matches {expected}", authority.name);
                } else {
                    // Trust on first use: the printed value is the only thing
                    // that makes the first pin reviewable, so it is said loudly
                    // and in full.
                    println!(
                        "{}: no published root fingerprint (trust on first use); the fetched \
                         root is {fingerprint} — compare it with the authority's own publication",
                        authority.name
                    );
                }
                // The fingerprint of the first certificate, the same value
                // `anchor list` and the lock carry, not of the whole file: a
                // bundle may append chain certificates and would otherwise get
                // two hashes.
                println!(
                    "anchor {}: {} sha256 {}",
                    authority.name,
                    path.display(),
                    fingerprint
                );
            }
            Err(AnchorProblem::Mismatch { expected, found }) => {
                fingerprint_mismatch = true;
                // Loud, and both values spelled out: this is the one case where
                // the fetched bundle is thrown away although it is well formed.
                eprintln!(
                    "rfc3161: warning: the root fetched for `{}` from {} does not match: \
                     expected {expected}, got {found}; the bundle was not pinned{}",
                    authority.name,
                    authority.anchor_url,
                    if path.exists() {
                        " and the existing anchor is untouched"
                    } else {
                        ""
                    }
                );
            }
            Err(AnchorProblem::Unusable(reason)) => eprintln!(
                "rfc3161: warning: the anchor of `{}` from {} is unusable: {reason}",
                authority.name, authority.anchor_url
            ),
        },
        Err(error) => eprintln!(
            "rfc3161: warning: cannot fetch the anchor of `{}` from {}: {error}",
            authority.name, authority.anchor_url
        ),
    }
    if !path.exists() {
        missing_anchor = Some(path);
    }
    Ok(Pinned {
        id: authority.name,
        kept,
        missing_anchor,
        fingerprint_mismatch,
    })
}

/// The digest of `der` in the length the expected fingerprint is written in.
///
/// SHA-1 (20 octets) and SHA-256 (32) are both published by authorities and both
/// pinned; taking the length from the expectation keeps a mismatched spelling a
/// mismatch instead of silently comparing the wrong digest.
fn matching_digest(expected: &str, der: &[u8]) -> String {
    if expected.split(':').count() == 20 {
        git_time_core::trust::sha1_fingerprint(der)
    } else {
        git_time_core::trust::fingerprint(der)
    }
}

/// Why a fetched bundle was not pinned.
enum AnchorProblem {
    /// It is not a certificate bundle, or could not be written.
    Unusable(String),
    /// Its root is not the fingerprint the preset expects.
    Mismatch {
        /// The fingerprint the preset pins.
        expected: String,
        /// The fingerprint the bundle actually carries.
        found: String,
    },
}

/// Parse `bytes` as `id`'s bundle before it replaces what is pinned at `path`.
///
/// The bundle is staged next to the target and moved over it only after
/// [`AnchorStore::load`] accepted every certificate, so a fetch that returned
/// prose or a truncated block leaves the previous anchor untouched.
///
/// When the preset expects a root fingerprint, the first certificate — the one
/// that would become the anchor — must carry it. A mismatch writes nothing: the
/// previous pin, if any, survives and the path stays absent otherwise, which is
/// exactly what `doctor` reports as a missing anchor.
fn install_anchor(
    authority: &Authority,
    path: &Path,
    bytes: &[u8],
) -> Result<String, AnchorProblem> {
    let staging = path.with_extension("pem.new");
    std::fs::write(&staging, bytes).map_err(|error| {
        AnchorProblem::Unusable(format!("cannot write {}: {error}", staging.display()))
    })?;
    if let Err(error) = AnchorStore::load(&[(authority.name.to_owned(), staging.clone())]) {
        let reason = error.to_string();
        // A previous anchor is never replaced by an unparseable bundle; when
        // there is none, the bad bytes are kept so doctor can name them as
        // unparseable instead of as a fetch that never happened.
        if path.exists() {
            let _ = std::fs::remove_file(&staging);
        } else {
            let _ = std::fs::rename(&staging, path);
        }
        return Err(AnchorProblem::Unusable(reason));
    }
    let der = crate::cmd::anchor::first_certificate(bytes).ok_or_else(|| {
        AnchorProblem::Unusable(format!("{} carried no certificate", path.display()))
    })?;
    let fingerprint = anchors::fingerprint(&der);
    if let Some(expected) = authority.fingerprint {
        let found = matching_digest(expected, &der);
        if !expected.eq_ignore_ascii_case(&found) {
            // Nothing is written at all: an expected-but-wrong root must not
            // become the anchor merely because it parsed.
            let _ = std::fs::remove_file(&staging);
            return Err(AnchorProblem::Mismatch {
                expected: expected.to_owned(),
                found,
            });
        }
    }
    std::fs::rename(&staging, path).map_err(|error| {
        let _ = std::fs::remove_file(&staging);
        AnchorProblem::Unusable(format!("cannot write {}: {error}", path.display()))
    })?;
    Ok(fingerprint)
}

/// Set one repository-local config key unless it is already set.
///
/// Returns whether an existing value was kept. `--replace-all` would flatten a
/// hand-tuned value (a different mirror, a longer timeout) on every run, so the
/// keys are only written when absent.
fn set(repo: &Repo, key: &str, value: &str) -> Result<bool, Exit> {
    match git_stdout(repo, &["config", "--local", "--get", key]) {
        Ok(existing) if !existing.trim().is_empty() => Ok(true),
        Ok(_) => {
            git_stdout(repo, &["config", "--local", key, value])?;
            Ok(false)
        }
        // git exits 1 for an unset key, which `git_stdout` reports as usage.
        Err(exit) if exit.code() == 2 => {
            git_stdout(repo, &["config", "--local", key, value])?;
            Ok(false)
        }
        Err(exit) => Err(exit),
    }
}

/// Whether `time.gate = pre-commit` is configured.
pub(crate) fn gate(repo: &Repo) -> Result<bool, Exit> {
    Ok(repo
        .config_non_empty("time.gate")
        .map_err(Exit::config)?
        .is_some_and(|value| value.eq_ignore_ascii_case("pre-commit")))
}
