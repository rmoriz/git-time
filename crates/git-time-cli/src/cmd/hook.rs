//! `git time hook <event>`: seal the commit git just made, or gate the next
//! one.
//!
//! The hook is the only caller git runs on its own, so it is the most careful
//! one: it never touches the index or the worktree (the seal only reads objects
//! and moves a ref), it stays quiet unless there is something to say, and a
//! failure is silent to git — exit `0` — unless `time.on-failure = fail`.
//!
//! **A merge needs its own hook.** Measured on 2.56: `git merge --no-ff` runs
//! `pre-merge-commit` and `post-merge`, and never `post-commit`. Sealing from
//! `post-commit` alone would cover ordinary commits and silently miss every
//! merge. The same is true of a `post-merge` that fires for a squash: there the
//! commit is still to be made, so `post-merge` finds HEAD already sealed and
//! stays quiet — and it must not consume a pending drop either, or the drop
//! would land on the commit before the one it was meant for.
//!
//! The events git calls are served:
//!
//! - `post-commit` — an ordinary commit (and everything else that commits:
//!   `--amend`, `cherry-pick`, `revert`, a rebase replay);
//! - `post-merge` — a merge (`0`) and a squash merge's bookkeeping (`1`);
//! - `pre-commit` and `pre-merge-commit` — the hard gate, only when
//!   `time.gate = pre-commit`: the two events git calls before a commit and
//!   before a merge commit, respectively. A `HEAD`-less reachability probe
//!   against every configured TSA over a dummy digest. Fewer than `required`
//!   answers refuses the commit with exit `1` before any object is written.
//!   Under the default `post-commit` gate the events do nothing, so wiring them
//!   unconditionally is safe. A pending drop short-circuits the gate: the commit
//!   is going to stay unsealed on purpose, so a dead TSA must not stop it.
//!
//! What it says is one line, in the terms a reader acts on:
//!
//! - sealed: `rfc3161: sealed <oid> by <ok>/<total> TSA(s)`
//! - short quorum: `rfc3161: sealed <oid> under quorum (<ok> of <required>) —
//!   see git time verify`
//! - gate refused: `rfc3161: gate failed: <answered> of <total> TSA(s)
//!   answered, <required> required — commit refused`, exit `1`
//! - failure: `rfc3161: seal failed: <reason>`, exit `3` when so configured
//! - no usable anchor at all: one `rfc3161: seal failed: <id>: <reason>` line per
//!   authority that has no readable anchor, exit `3` when so configured. One bad
//!   bundle costs its own authority, not the seal: the others still stamp.
//! - a commit already reachable from a remote-tracking ref, which a seal would
//!   rewrite out from under the remote: `rfc3161: skipping published <oid7>
//!   (run: git time seal --force)`, exit `0`
//! - a second run over an already sealed commit, and every other skip: nothing
//!
//! **Published history is never rewritten here.** A `git pull` that only
//! fast-forwards fires `post-merge` for a commit the remote already has;
//! sealing it would move the branch past `origin/main` and make the next push
//! non-fast-forward. The hook leaves such a commit alone and `seal --force` is
//! the explicit way to rewrite it anyway.
//!
//! A skip that still means "no evidence" — a total outage with
//! `time.record-failures = false` (`NoTokensRecorded`), or a HEAD that moved
//! away mid-seal (`HeadMoved`) — is not silent: it is a failure line, and exit
//! `3` under `fail`.
//!
//! A rebase rewrites commits without the user's hand on each one, so
//! `time.seal-during-rebase` decides whether the hook works at all (`all`),
//! only for the commit the rebase ends on (`tip`), or not at all (`off`, with
//! the exact `git time seal --range` command to run afterwards).

use std::path::Path;

use git_time_core::imprint::{Alg, Digest};
use git_time_core::policy::{Gate, OnFailure, Policy, SealDuringRebase};
use git_time_core::repo::Repo;
use git_time_core::seal::{SealError, SealOutcome, SkipReason, seal};
use git_time_core::tsa::{PoolPolicy, StampRequest, pool};

use crate::cmd::{Exit, drop, git_path_exists, head_commit, open, short};

/// What the rebase todo is called.
const MERGE_TODO: &str = "git-rebase-todo";

/// The marker that says the `off` hint was already printed in this rebase.
const HINT_MARKER: &str = "time-hinted";

/// `GIT_TIME_SKIP`: any non-empty value disables the hook for one command.
const SKIP_VARIABLE: &str = "GIT_TIME_SKIP";

/// The todo verbs that make a commit.
///
/// Everything else — comments, blanks and the commands that only move the
/// sequencer (`exec`, `break`, `label`, `reset`, `update-ref`, `noop`) or
/// discard a commit (`drop`) — is no remaining work. Counting them would make
/// the commit before them look like "not the tip", and `tip` would under-seal.
const COMMITTING_VERBS: [&str; 12] = [
    "pick", "p", "reword", "r", "edit", "e", "merge", "m", "fixup", "f", "squash", "s",
];

/// The hook git invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A commit was just created.
    PostCommit,
    /// A merge finished. A merge never runs `post-commit`, so this is the only
    /// event that covers it.
    PostMerge,
    /// A commit is about to be created; the gate, when one is configured.
    PreCommit,
    /// A merge is about to create its commit; the gate, when one is configured.
    /// A merge never runs `pre-commit`.
    PreMergeCommit,
}

impl Event {
    /// Whether the event is the gate, which must run before a commit exists.
    #[must_use]
    fn is_gate(self) -> bool {
        matches!(self, Self::PreCommit | Self::PreMergeCommit)
    }
}

/// Run a hook.
///
/// `squash` is `post-merge`'s flag argument: git passes `1` for a squash,
/// where the commit is still to be made, and `0` for a real merge.
///
/// Every failure ends in [`Exit::ok`] unless the policy says `fail`, in which
/// case it ends on `3`. The gate is the exception: it exits `1` on a short
/// quorum because refusing is its whole job.
pub async fn run(directory: Option<std::path::PathBuf>, event: Event, squash: bool) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return warn(None, &seal_line(&exit)),
    };
    if skipped() {
        return Exit::ok();
    }
    let policy = match Policy::load(&repo) {
        Ok(policy) => policy,
        // No policy means no `on-failure` to consult: warn is the default. A
        // gate that is switched on has to refuse, though, so read that one key
        // back before deciding.
        Err(error) => {
            if event.is_gate() && gate_configured(&repo) {
                return Exit::with(1, format!("rfc3161: gate failed: {error}"));
            }
            return warn(None, &format!("seal failed: {error}"));
        }
    };
    if !policy.enabled {
        return Exit::ok();
    }
    if event.is_gate() {
        // A dropped commit is going to stay unsealed on purpose, so the gate —
        // which exists to stop a commit that would be sealed unsealed — has
        // nothing to protect. Leaving the marker for `post-commit`.
        if drop::pending(&repo) {
            return Exit::ok();
        }
        return gate(&policy).await;
    }

    // Only a path that ends in a seal may consume the drop marker; anything
    // else would take the drop away from the commit it was meant for.
    if event == Event::PostMerge && squash {
        // `post-merge 1` fires before the squash commit exists.
        return Exit::ok();
    }
    if event == Event::PostCommit
        && let Some(rebase) = rebase_position(&repo)
    {
        match policy.seal_during_rebase {
            SealDuringRebase::All => {}
            SealDuringRebase::Tip if !rebase.is_last => return Exit::ok(),
            SealDuringRebase::Tip => {}
            SealDuringRebase::Off => {
                // Once per rebase: the marker lives in the rebase state
                // directory, which git deletes when the rebase ends.
                if !rebase.hinted() {
                    eprintln!(
                        "rfc3161: rebase in progress, run 'git time seal --range {}..HEAD' afterwards",
                        rebase.onto
                    );
                    rebase.mark_hinted();
                }
                return Exit::ok();
            }
        }
    }

    // A dropped commit: the marker is consumed and the commit remembered, so
    // `git time seal` can say why it is unsealed. Deliberately silent.
    match drop::consume(&repo) {
        Ok(true) => {
            if let Ok(Some(oid)) = head_commit(&repo) {
                drop::record(&repo, &oid);
            }
            return Exit::ok();
        }
        Ok(false) => {}
        // The marker is still there, so the commit must stay unsealed rather
        // than take the drop from the next one.
        Err(exit) => return warn(Some(&policy), &seal_line(&exit)),
    }

    let oid = match head_commit(&repo) {
        Ok(Some(oid)) => oid,
        Ok(None) => return Exit::ok(),
        Err(exit) => return warn(Some(&policy), &seal_line(&exit)),
    };

    // Published history stays as the remote has it: a hook seal is a rewrite,
    // and one on a fast-forwarded commit would make the next push non-ff.
    if published(&repo, &oid) {
        eprintln!(
            "rfc3161: skipping published {} (run: git time seal --force)",
            short(&oid)
        );
        return Exit::ok();
    }

    // A force-seal or an amend elsewhere can leave entries that no longer
    // resolve; this is the one place every commit passes through.
    drop::prune(&repo);

    let outcome = seal(&repo, &policy, policy.backends(), policy.anchors(), &oid).await;
    match outcome {
        Ok(SealOutcome::Sealed { oid, ok, total }) => {
            eprintln!("rfc3161: sealed {} by {ok}/{total} TSA(s)", short(&oid));
            Exit::ok()
        }
        Ok(SealOutcome::UnderQuorum { oid, failures }) => {
            let ok = policy.backends().len().saturating_sub(failures.len());
            eprintln!(
                "rfc3161: sealed {} under quorum ({ok} of {}) — see git time verify",
                short(&oid),
                policy.required
            );
            if policy.on_failure == OnFailure::Fail {
                Exit::with(3, String::new())
            } else {
                Exit::ok()
            }
        }
        // The commit exists but carries no evidence: say so, and it is a
        // failure under `fail` even though the seal itself did not error.
        Ok(SealOutcome::Skipped(SkipReason::NoTokensRecorded)) => {
            failure(&policy, "no TSA answered (no tokens recorded)")
        }
        Ok(SealOutcome::Skipped(SkipReason::HeadMoved)) => {
            failure(&policy, "HEAD moved while sealing")
        }
        // A second run over a sealed commit, and every other skip, is silence.
        Ok(SealOutcome::Skipped(_)) => Exit::ok(),
        // Nothing could even be attempted: one line per authority that has no
        // anchor, so the reader sees which bundle to restore.
        Err(SealError::NoUsableAnchor) => no_anchor(&policy),
        Err(error) => warn(Some(&policy), &format!("seal failed: {error}")),
    }
}

/// `GIT_TIME_SKIP` set to a non-empty value.
fn skipped() -> bool {
    std::env::var_os(SKIP_VARIABLE).is_some_and(|value| !value.is_empty())
}

/// Whether `time.gate = pre-commit`, read on its own so a policy that fails to
/// load can still be judged by it.
fn gate_configured(repo: &Repo) -> bool {
    repo.config_non_empty("time.gate")
        .ok()
        .flatten()
        .is_some_and(|value| value.eq_ignore_ascii_case("pre-commit"))
}

/// Whether `oid` is reachable from a remote-tracking ref, and so already
/// published.
///
/// A fast-forward `git pull` fires only `post-merge`, for a commit the remote
/// already has. Sealing it would rewrite it, and the branch would stand ahead
/// of its remote: the next push could only be forced. An unreadable listing
/// answers "not published" — sealing is the normal outcome, and a wrong guess
/// there is only an unwanted rewrite of local history, never a lost commit.
fn published(repo: &Repo, oid: &str) -> bool {
    crate::cmd::git_stdout(
        repo,
        &[
            "for-each-ref",
            "--contains",
            oid,
            "--format=%(refname)",
            "refs/remotes",
        ],
    )
    .map(|listing| !listing.trim().is_empty())
    .unwrap_or(false)
}

/// The pre-commit probe: refuse the commit when fewer than `required`
/// authorities answer a HEAD-less request.
///
/// The digest is a dummy — nothing is sealed here and the token is discarded —
/// so the probe costs one round trip and proves reachability, which is what the
/// gate is for.
async fn gate(policy: &Policy) -> Exit {
    if policy.gate != Gate::PreCommit {
        return Exit::ok();
    }
    let dummy = Digest {
        alg: Alg::Sha256,
        bytes: vec![0; Alg::Sha256.digest_len()],
    };
    let request = match StampRequest::new(dummy, &mut rand::rng()) {
        Ok(request) => request,
        Err(error) => return Exit::with(1, format!("rfc3161: gate failed: {error}")),
    };
    let pool_policy = PoolPolicy {
        required: policy.required,
        deadline: policy.deadline,
    };
    let outcome = pool::run(policy.backends(), &request, &pool_policy).await;
    let answered = outcome.tokens.len();
    if answered >= policy.required {
        return Exit::ok();
    }
    Exit::with(
        1,
        format!(
            "rfc3161: gate failed: {answered} of {} TSA(s) answered, {} required — commit refused",
            policy.backends().len(),
            policy.required
        ),
    )
}

/// Where a rebase in progress stands.
struct Rebase {
    /// git's state directory for the rebase.
    dir: std::path::PathBuf,
    /// The commit the rebase replays onto, named in the `off` hint.
    onto: String,
    /// Whether the commit being sealed is the one the rebase ends on.
    is_last: bool,
}

impl Rebase {
    /// Whether the `off` hint was already said.
    fn hinted(&self) -> bool {
        self.dir.join(HINT_MARKER).exists()
    }

    /// Remember that the `off` hint was said.
    fn mark_hinted(&self) {
        // A failed write only costs a repeated line.
        let _ = std::fs::write(self.dir.join(HINT_MARKER), "");
    }
}

/// Describe the rebase in progress, or `None` when there is none.
///
/// A rebase is in progress exactly when git's own state directory for one
/// exists — `rebase-merge` for the sequencer backend, `rebase-apply` for the
/// patch backend. The last step is the one whose todo holds no committing
/// command left; that is how `tip` knows the commit it should keep.
fn rebase_position(repo: &Repo) -> Option<Rebase> {
    let merge = git_path_exists(repo, "rebase-merge");
    let apply = git_path_exists(repo, "rebase-apply");
    let dir = merge.clone().or_else(|| apply.clone())?;
    let onto = read_line(&dir.join("onto"))?;
    let is_last = match merge.as_deref() {
        Some(dir) => todo_is_empty(&dir.join(MERGE_TODO)),
        // The patch backend keeps its place as counters, not a todo list; every
        // replayed commit is tip-like there, so `tip` seals all of them.
        None => true,
    };
    Some(Rebase { dir, onto, is_last })
}

/// The first non-empty line of `path`.
fn read_line(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

/// Whether a rebase todo has no step left that makes a commit.
///
/// Only the committing verbs count. Comments, blank lines, `exec`, `break`,
/// `label`, `reset`, `update-ref`, `noop` and `drop` make no commit: with any
/// of them trailing, the last pick still sees a non-empty todo and would never
/// be taken for the tip. A missing todo is read as "nothing left", so an
/// unreadable file cannot turn `tip` into a no-op on the final commit.
fn todo_is_empty(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return true;
    };
    !text.lines().map(str::trim).any(|line| {
        !line.is_empty()
            && !line.starts_with('#')
            && line
                .split_whitespace()
                .next()
                .is_some_and(|verb| COMMITTING_VERBS.contains(&verb))
    })
}

/// Report a failure and choose the exit code: `3` with `on-failure = fail`,
/// `0` otherwise.
fn warn(policy: Option<&Policy>, message: &str) -> Exit {
    eprintln!("rfc3161: {message}");
    match policy.map(|policy| policy.on_failure) {
        Some(OnFailure::Fail) => Exit::with(3, String::new()),
        _ => Exit::ok(),
    }
}

/// Report a seal that produced no evidence, under the policy's failure mode.
fn failure(policy: &Policy, message: &str) -> Exit {
    eprintln!("rfc3161: seal failed: {message}");
    failure_exit(policy)
}

/// Report the authorities that have no anchor, one line each, under the policy's
/// failure mode.
///
/// The failure reasons are per authority, so the reader learns which bundle to
/// restore instead of a single line naming all of them.
fn no_anchor(policy: &Policy) -> Exit {
    for tsa in &policy.tsas {
        if policy.anchors().anchor(&tsa.id).is_none() {
            eprintln!(
                "rfc3161: seal failed: {}: {}",
                tsa.id,
                policy.anchor_failure(&tsa.id).unwrap_or("anchor unusable")
            );
        }
    }
    failure_exit(policy)
}

/// The exit code a seal failure ends on, without printing anything.
fn failure_exit(policy: &Policy) -> Exit {
    match policy.on_failure {
        OnFailure::Fail => Exit::with(3, String::new()),
        OnFailure::Warn => Exit::ok(),
    }
}

/// `seal failed: <reason>`, without the `git time: ` prefix an [`Exit`] carries
/// for its own reporting.
fn seal_line(exit: &Exit) -> String {
    let message = exit.message();
    let reason = message.strip_prefix("git time: ").unwrap_or(&message);
    format!("seal failed: {reason}")
}
