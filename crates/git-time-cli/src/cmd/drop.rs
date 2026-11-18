//! `git time drop`: leave the next commit unsealed on purpose.
//!
//! Not every commit deserves evidence — a typo fix on a work-in-progress branch
//! is noise. `GIT_TIME_SKIP=1` skips one command, but it lives in the shell and
//! is easy to forget; `drop` is the same intent written into the repository, so
//! it survives the next shell and the next `git commit`.
//!
//! The marker is `time-skip` inside the git directory. The hook consumes it
//! (deletes it) and records the commit it applied to in `time-dropped`, one
//! object id per line, so the drop stays readable after the commit exists:
//! `git time seal` says `skipped (dropped)` instead of sealing it, and
//! `--force` seals it anyway.
//!
//! Only a hook run that ends in a seal consumes the marker: a squash merge's
//! `post-merge` fires before the commit exists and a rebase the policy leaves
//! alone seals nothing, so both leave the marker for the commit it belongs to.
//!
//! `time-dropped` is pruned on every drop, on a hook seal (an amend fires one)
//! and on `seal --force`, and is capped: entries whose object is gone and the
//! oldest beyond the cap are dropped, so the file cannot grow forever.
//!
//! `git time verify` reads the same record and reports `UNSEALED (dropped)`
//! rather than a plain unsealed commit.

use std::io::Write as _;
use std::process::Command;

use git_time_core::repo::Repo;
use git_time_core::verify::DROPPED_FILE;

use crate::cmd::{Exit, git_path, open};

/// The marker file that makes the next commit a drop.
const MARKER: &str = "time-skip";

/// The record of dropped commits, one object id per line.
const DROPPED: &str = DROPPED_FILE;

/// How many entries `time-dropped` keeps at most.
const DROPPED_MAX: usize = 200;

/// Run `git time drop`.
pub async fn run(directory: Option<std::path::PathBuf>) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    let marker = match git_path(&repo, MARKER) {
        Ok(marker) => marker,
        Err(exit) => return exit,
    };
    if let Err(error) = std::fs::write(&marker, "") {
        return Exit::config(format!("cannot write the drop marker: {error}"));
    }
    println!("rfc3161: the next commit will not be sealed");
    println!("run 'git time seal' afterwards to seal it anyway");
    Exit::ok()
}

/// Whether a drop is pending, without consuming it.
pub fn pending(repo: &Repo) -> bool {
    git_path(repo, MARKER).is_ok_and(|marker| marker.exists())
}

/// Consume the drop marker: `true` when the commit being finished is a drop.
///
/// The marker is removed, not emptied: either the whole drop is taken or none
/// of it is. A failed unlink is reported instead of answered `false`, because
/// the marker stays behind and a commit sealed here would leave it to drop the
/// *next* commit as well.
pub fn consume(repo: &Repo) -> Result<bool, Exit> {
    let marker = git_path(repo, MARKER)?;
    if !marker.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&marker)
        .map_err(|error| Exit::seal(format!("cannot consume the drop marker: {error}")))?;
    Ok(true)
}

/// Remember that `oid` was dropped on purpose.
///
/// A failed write only costs `seal` not knowing about the drop; the commit is
/// unsealed either way.
pub fn record(repo: &Repo, oid: &str) {
    let Ok(path) = git_path(repo, DROPPED) else {
        return;
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{oid}");
    }
    prune(repo);
}

/// Whether `oid` is recorded as dropped.
pub fn is_dropped(repo: &Repo, oid: &str) -> bool {
    let Ok(path) = git_path(repo, DROPPED) else {
        return false;
    };
    std::fs::read_to_string(path)
        .map(|text| text.lines().any(|line| line.trim() == oid))
        .unwrap_or(false)
}

/// Forget `oid`: it was sealed after all (`seal --force`).
pub fn forget(repo: &Repo, oid: &str) {
    let Ok(path) = git_path(repo, DROPPED) else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let kept = entries(&text);
    let live: Vec<&str> = kept.iter().copied().filter(|line| *line != oid).collect();
    if live.len() != kept.len() {
        let _ = std::fs::write(&path, joined(&live));
    }
}

/// Drop the entries of `time-dropped` whose object no longer resolves, and the
/// oldest beyond [`DROPPED_MAX`].
///
/// Both are best-effort: a file that cannot be read or rewritten only leaves a
/// stale line behind, which `seal` reports as `skipped (dropped)` — the safe
/// direction, since it never seals something by accident.
pub fn prune(repo: &Repo) {
    let Ok(path) = git_path(repo, DROPPED) else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let kept = entries(&text);
    let bounded = &kept[kept.len().saturating_sub(DROPPED_MAX)..];
    let live: Vec<&str> = bounded
        .iter()
        .copied()
        .filter(|oid| resolves(repo, oid))
        .collect();
    if live.len() != kept.len() {
        let _ = std::fs::write(&path, joined(&live));
    }
}

/// The non-empty, trimmed lines of `text`.
fn entries(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

/// `lines` as file content, one per line.
fn joined(lines: &[&str]) -> String {
    lines.iter().map(|line| format!("{line}\n")).collect()
}

/// Whether `oid` still names a commit in this repository.
fn resolves(repo: &Repo, oid: &str) -> bool {
    let revision = format!("{oid}^{{commit}}");
    Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(["cat-file", "-e", &revision])
        .output()
        .is_ok_and(|output| output.status.success())
}
