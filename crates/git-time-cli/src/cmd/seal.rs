//! `git time seal`: seal HEAD, or every commit of a range, without the hook.
//!
//! The no-argument form is exactly what the hook does, with the outcome printed
//! instead of swallowed. A commit dropped on purpose (`git time drop`) says
//! `skipped (dropped)` and stays untouched unless `--force` overrides the drop.
//! The range form is what `time.seal-during-rebase = off` and a replayed patch
//! point at: it walks the range oldest first, topologically, and seals the
//! commits that carry no matching evidence, skipping the dropped ones the same
//! way unless `--force`.
//!
//! Sealing is a rewrite of one commit, and the seal engine insists that HEAD
//! names the commit it rewrites (that is how a lost race is detected). A range
//! therefore parks HEAD on each commit with `update-ref --no-deref`, which moves
//! no file: the index and the worktree are untouched throughout. Only the last
//! commit of the range is sealed through the branch when the range ends at the
//! branch tip, so the seal lands where the user will look for it; every other
//! commit is sealed detached and HEAD is put back afterwards.
//!
//! A sealed commit of an older range member is a *new* object, and nothing
//! repoints its child at it: the printed id is where its evidence lives, and
//! `git time verify <id>` reaches it. Only the commit that is also the branch
//! tip stays reachable through the branch.
//!
//! `--force` re-seals a commit whose block already matches its own pre-image.
//! Because the imprint is taken over the pre-image, the same content always
//! yields the same imprint, so the engine would call it already sealed: the
//! commit is first rebuilt without its block (its signature is kept) and that
//! block-free object is what gets a fresh token.

use git_time_core::imprint::{Alg, Digest, digest};
use git_time_core::object::CommitObject;
use git_time_core::policy::Policy;
use git_time_core::repo::{Head, Repo};
use git_time_core::seal::{SealError, SealOutcome, SkipReason, seal};
use git_time_core::store;

use crate::cmd::{Exit, detach_head, drop, head_commit, open, restore_head, short};

/// Run `git time seal`.
pub async fn run(
    directory: Option<std::path::PathBuf>,
    range: Option<String>,
    force: bool,
) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    let policy = match Policy::load(&repo) {
        Ok(policy) => policy,
        Err(error) => return Exit::config(format!("cannot read the policy: {error}")),
    };
    match range {
        Some(range) => seal_range(&repo, &policy, &range, force).await,
        None => {
            let oid = match head_commit(&repo) {
                Ok(Some(oid)) => oid,
                Ok(None) => return Exit::seal("HEAD does not point at a commit"),
                Err(exit) => return exit,
            };
            // A dropped commit was left unsealed on purpose, so sealing it is
            // only right when asked for: `--force` overrides the drop.
            if !force && drop::is_dropped(&repo, &oid) {
                println!("rfc3161: skipped (dropped)");
                return Exit::ok();
            }
            let exit = seal_one(&repo, &policy, &oid, force).await;
            if force && exit.code() == 0 {
                // Bound the record: this commit is no longer a drop.
                drop::prune(&repo);
            }
            exit
        }
    }
}

/// Seal every commit of `range`, oldest first.
///
/// `--topo-order` (with `--reverse`) keeps every parent ahead of its children
/// whatever the committer dates say, so a rebased or backdated range still
/// walks in an order the seal can rebuild from.
async fn seal_range(repo: &Repo, policy: &Policy, range: &str, force: bool) -> Exit {
    let listing =
        match crate::cmd::git_stdout(repo, &["rev-list", "--reverse", "--topo-order", range]) {
            Ok(listing) => listing,
            Err(exit) => return exit,
        };
    let commits: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let Some(last) = commits.last().copied() else {
        println!("nothing to seal in {range}");
        return Exit::ok();
    };

    let original = match repo.head() {
        Ok(head) => head,
        Err(error) => return Exit::config(format!("cannot read HEAD: {error}")),
    };
    // Only a range that ends at the branch tip is sealed through the branch;
    // anything older leaves the branch alone.
    let tip = match head_commit(repo) {
        Ok(tip) => tip,
        Err(exit) => return exit,
    };
    let ends_at_tip = tip.as_deref() == Some(last);

    let mut failed = false;
    let mut stopped = None;
    for (index, oid) in commits.iter().copied().enumerate() {
        let is_last = index + 1 == commits.len();
        // A dropped commit was left unsealed on purpose: skip it without moving
        // HEAD at all, unless `--force` overrides the drop. HEAD is put back by
        // the `restore_head` after the loop either way.
        if !force && drop::is_dropped(repo, oid) {
            println!("rfc3161: skipped (dropped)");
            continue;
        }
        let placed = if is_last && ends_at_tip {
            restore_head(repo, &original)
        } else {
            detach_head(repo, oid)
        };
        if let Err(exit) = placed {
            failed = true;
            stopped = Some(exit);
            break;
        }

        if !force && matches!(is_sealed(repo, oid), Ok(true)) {
            println!("already sealed {}", short(oid));
            continue;
        }
        if seal_one(repo, policy, oid, force).await.code() != 0 {
            failed = true;
        }
    }

    // HEAD goes back on every path, including a failure or an early stop: a
    // range walk must never leave the user on a detached HEAD. When the range
    // ended at the branch tip the last iteration already restored it, so this
    // is a no-op there.
    if let Err(exit) = restore_head(repo, &original) {
        return exit;
    }
    if force {
        drop::prune(repo);
    }
    if let Some(exit) = stopped {
        return exit;
    }
    if failed {
        Exit::seal("at least one commit could not be sealed")
    } else {
        Exit::ok()
    }
}

/// Seal one commit and print what happened.
async fn seal_one(repo: &Repo, policy: &Policy, oid: &str, force: bool) -> Exit {
    // The outcome shadows `oid`; the drop entry names the commit before it.
    let before = oid;
    let target = if force {
        match strip_block(repo, oid) {
            Ok(target) => target,
            Err(exit) => {
                let message = exit.message();
                if !message.is_empty() {
                    eprintln!("{message}");
                }
                return Exit::with(exit.code(), String::new());
            }
        }
    } else {
        oid.to_owned()
    };

    let outcome = seal(repo, policy, policy.backends(), policy.anchors(), &target).await;
    let sealed = matches!(
        outcome,
        Ok(SealOutcome::Sealed { .. } | SealOutcome::UnderQuorum { .. })
    );
    if force && sealed {
        // The drop was overridden: the commit is not to be reported as dropped
        // any more, whichever path asked for the force.
        drop::forget(repo, before);
    }
    match outcome {
        Ok(SealOutcome::Sealed { oid, ok, total }) => {
            println!("sealed {} by {ok}/{total} TSA(s)", short(&oid));
            Exit::ok()
        }
        Ok(SealOutcome::UnderQuorum { oid, failures }) => {
            let ok = policy.backends().len().saturating_sub(failures.len());
            println!(
                "sealed {} under quorum ({ok} of {}) — see git time verify",
                short(&oid),
                policy.required
            );
            Exit::with(1, String::new())
        }
        Ok(SealOutcome::Skipped(SkipReason::AlreadySealed)) => {
            println!("already sealed {}", short(oid));
            Exit::ok()
        }
        // A total outage with `record-failures = false`: the commit stays as it
        // was and nothing said so, so this is a failure, not a quiet skip.
        Ok(SealOutcome::Skipped(SkipReason::NoTokensRecorded)) => {
            eprintln!("seal failed for {}: no TSA answered", short(oid));
            Exit::with(1, String::new())
        }
        Ok(SealOutcome::Skipped(reason)) => {
            println!("skipped {} ({})", short(oid), reason_text(reason));
            Exit::ok()
        }
        // The error is about the object the seal was handed — with `--force`
        // that is the stripped one, never the original.
        Err(SealError::NoUsableAnchor) => {
            for tsa in &policy.tsas {
                if policy.anchors().anchor(&tsa.id).is_none() {
                    eprintln!(
                        "seal failed for {}: {}: {}",
                        short(&target),
                        tsa.id,
                        policy.anchor_failure(&tsa.id).unwrap_or("anchor unusable")
                    );
                }
            }
            Exit::with(1, String::new())
        }
        Err(error) => {
            eprintln!("seal failed for {}: {error}", short(&target));
            Exit::with(1, String::new())
        }
    }
}

/// Whether `oid` already carries a block that claims the imprint of its own
/// pre-image, mirroring the engine's own check.
fn is_sealed(repo: &Repo, oid: &str) -> Result<bool, Exit> {
    let (object, _raw) = repo
        .read_commit(oid)
        .map_err(|error| Exit::seal(format!("cannot read {}: {error}", short(oid))))?;
    let pre = object.pre_image(store::PREFIX);
    let Some(trailer) = pre.trailer else {
        return Ok(false);
    };
    let Ok(Some(block)) = store::decode(&trailer) else {
        return Ok(false);
    };
    let imprint = Digest {
        alg: Alg::Sha256,
        bytes: digest(Alg::Sha256, &pre.bytes),
    };
    Ok(block.imprint == imprint)
}

/// Rebuild `oid` without its block, keeping its signature headers, write it and
/// move HEAD (or the branch HEAD names) to it; returns the new object id.
fn strip_block(repo: &Repo, oid: &str) -> Result<String, Exit> {
    let (object, _raw) = repo
        .read_commit(oid)
        .map_err(|error| Exit::seal(format!("cannot read {}: {error}", short(oid))))?;
    let pre = object.pre_image(store::PREFIX);
    if pre.trailer.is_none() {
        return Ok(oid.to_owned());
    }
    let mut stripped = CommitObject::parse(&pre.bytes)
        .map_err(|error| Exit::seal(format!("cannot parse {}: {error}", short(oid))))?;
    // The old signature is worthless over the new message, but the seal signs
    // the rebuilt object again from the header, so it is carried over here.
    for (index, (name, value)) in object.headers.iter().enumerate() {
        if name == b"gpgsig" || name == b"gpgsig-sha256" {
            let at = index.min(stripped.headers.len());
            stripped.headers.insert(at, (name.clone(), value.clone()));
        }
    }
    let new = repo
        .write_commit(&stripped.compose())
        .map_err(|error| Exit::seal(format!("cannot write {}: {error}", short(oid))))?;

    let head = repo
        .head()
        .map_err(|error| Exit::config(format!("cannot read HEAD: {error}")))?;
    let mut command = std::process::Command::new("git");
    command.arg("-C").arg(repo.path());
    match &head {
        Head::Symref(name) => {
            command.args(["update-ref", name.as_str(), new.as_str(), oid]);
        }
        Head::Detached(_) => {
            command.args(["update-ref", "--no-deref", "HEAD", new.as_str(), oid]);
        }
    }
    let output = command
        .output()
        .map_err(|error| Exit::config(format!("cannot run git: {error}")))?;
    if output.status.success() {
        Ok(new)
    } else {
        Err(Exit::seal(format!(
            "cannot move HEAD off {}: {}",
            short(oid),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// The words for a skip.
fn reason_text(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::NotACommit => "not a commit",
        SkipReason::HeadMoved => "HEAD moved",
        SkipReason::Disabled => "disabled",
        SkipReason::AlreadySealed => "already sealed",
        SkipReason::NoTokensRecorded => "no tokens recorded",
    }
}
