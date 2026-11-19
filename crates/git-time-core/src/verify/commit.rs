//! Commit-level verification: the verdict on one commit's evidence.
//!
//! The order is the contract, and every step is decided before the next:
//!
//! 1. the commit is read; a trailer block is decoded from its pre-image (a note
//!    is used when the trailer holds only an imprint, which is what note storage
//!    writes);
//! 2. **the imprint decides.** The pre-image is hashed again and compared to the
//!    block's own claim; a mismatch is [`Verdict::BadImprint`], whatever the
//!    block says. The block's `Object` field is provenance only and is never
//!    trusted back out;
//! 3. every token is judged by [`crate::verify::token`] against the pinned
//!    anchors and the imprint recomputed for the token's own algorithm;
//! 4. distinct TSA ids that verified are counted against `policy.required`;
//! 5. the signature is read from the object and verified: a broken signature is
//!    [`Verdict::BadSig`] even over a sealed commit, because evidence with a
//!    broken signature is not a PASS;
//! 6. a committer date later than a token's genTime is a **warning**, never a
//!    failure: it says backdating or clock skew, not a broken token.
//!
//! Verification is read-only in the sense that matters — no ref, index or
//! worktree is touched and no network call is made — but `sigcheck::verify`
//! writes the object it checks into the object database, because
//! `git verify-commit` works on objects, not bytes.
//!
//! A commit dropped on purpose is [`Verdict::Unsealed`] with
//! [`CommitEvidence::dropped`] set: the marker is read from the git directory
//! under the name the `drop` command writes, so the two cannot drift apart.
//!
//! The verdict is the whole of this module's judgement. `--require-*` gates
//! belong to the caller: a gate never rewrites a verdict, it only decides
//! whether the evidence is a PASS, so the verdict stays readable as what the
//! evidence actually is. `time.require-signed` is a command-line flag, not a
//! config key; [`Policy::require_signed`] is filled from that flag.

use std::collections::BTreeSet;
use std::path::PathBuf;

use jiff::Timestamp;

use super::token::{Invalid, TokenVerdict, token as judge};
use crate::imprint::{Digest, digest};
use crate::object::CommitObject;
use crate::policy::Policy;
use crate::repo::{Repo, RepoError, run_git};
use crate::seal::{NOTE_REF, committer_time, gen_time_window};
use crate::sigcheck::{self, VerifyOutcome};
use crate::store::{self, TrailerBlock};
use crate::trust::AnchorStore;

/// The file inside the git directory that records dropped commits, one object id
/// per line. The `drop` command writes it.
pub const DROPPED_FILE: &str = "time-dropped";

/// The per-TSA verdict of a token that verified.
const VALID: &str = "valid";

/// The per-TSA verdict of a TSA that was asked and did not answer usefully.
const FAIL: &str = "fail";

/// The verdict on one commit.
///
/// Every variant except [`Verdict::Sealed`] and [`Verdict::Unsealed`] is a
/// failure; [`Verdict::Unsealed`] is a failure only when a caller asks for a
/// seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `required` distinct TSAs verified and the signature is acceptable.
    Sealed,
    /// Evidence exists but fewer than `required` distinct TSAs verified.
    UnderQuorum,
    /// The commit carries a block, but no authority was configured when it was
    /// sealed: nothing was asked, so nothing failed either.
    None,
    /// The commit carries no trailer block (and no note).
    Unsealed,
    /// The pre-image no longer hashes to the imprint the block claims.
    BadImprint,
    /// Tokens exist but not one of them verified, for reasons other than trust.
    BadToken,
    /// No TSA of the commit is pinned, or every token is.
    Untrusted,
    /// The signature is broken, or it could not be checked at all.
    BadSig,
    /// The commit is unsigned and a signature was required.
    Unsigned,
}

impl Verdict {
    /// The stable, lowercase name used in machine output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::UnderQuorum => "under-quorum",
            Self::None => "none",
            Self::Unsealed => "unsealed",
            Self::BadImprint => "bad-imprint",
            Self::BadToken => "bad-token",
            Self::Untrusted => "untrusted",
            Self::BadSig => "bad-sig",
            Self::Unsigned => "unsigned",
        }
    }

    /// Whether the verdict is an evidence problem in itself.
    ///
    /// [`Verdict::Unsealed`] is not: an unsealed commit is what an unsealed
    /// repository looks like, and only a caller that requires a seal turns it
    /// into a failure.
    #[must_use]
    pub fn is_pass(self) -> bool {
        matches!(self, Self::Sealed | Self::Unsealed)
    }
}

/// What `git verify-commit` said about the commit signature, as evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// The signature holds.
    Good,
    /// The signature is there and does not match the object.
    Bad,
    /// There is no signature.
    Unsigned,
    /// Verification could not run or is inconclusive; the text says why.
    Error(String),
}

impl SignatureStatus {
    /// The stable, lowercase name used in machine output.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Bad => "bad",
            Self::Unsigned => "unsigned",
            Self::Error(_) => "error",
        }
    }
}

/// The judgement on one TSA: its token (or its failure) and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaEvidence {
    /// The configured TSA id.
    pub id: String,
    /// The TSA's genTime, for a token that verified.
    pub gen_time: Option<Timestamp>,
    /// `valid`, an [`Invalid`](crate::verify::Invalid) name, or `fail` for a
    /// recorded failure.
    pub verdict: &'static str,
    /// A human reason: the recorded failure, the signer's label, or why the
    /// anchor is missing.
    pub detail: Option<String>,
    /// The signing certificate's serial in lowercase hex, for a token that
    /// verified.
    pub serial: Option<String>,
    /// SHA-256 of the pinned anchor's first certificate, when one is pinned.
    ///
    /// Written out so a reader can compare it against the authority's own
    /// publication without trusting this output: a verdict says a token is
    /// good, this says under which root.
    pub anchor: Option<String>,
}

/// Everything verification found about one commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitEvidence {
    /// The commit that was judged.
    pub oid: String,
    /// The verdict.
    pub verdict: Verdict,
    /// The imprint the block declares, when it decoded.
    ///
    /// The declared value, not the recomputed one: a `BadImprint` is visible
    /// exactly because the two differ.
    pub imprint: Option<Digest>,
    /// The `X-RFC3161-Object` provenance field, when the block carries one.
    pub object_field: Option<String>,
    /// One entry per token and per recorded failure, in block order.
    pub per_tsa: Vec<TsaEvidence>,
    /// The signature's state.
    pub signature: SignatureStatus,
    /// Whether the commit is recorded as dropped on purpose. Typed rather than a
    /// warning string so a consumer needs no text matching.
    pub dropped: bool,
    /// The number of distinct TSA ids that verified, and the number the verdict
    /// was built from.
    pub valid: usize,
    /// Non-failing observations: committer-clock skew, a malformed block, a
    /// signature that could not be checked.
    pub warnings: Vec<String>,
}

/// The TSA ids `oid` was sealed by, in block order, without judging anything.
///
/// A restore path uses this: a token that will never verify without an anchor
/// still names the authority whose anchor has to be pinned before it can. A
/// commit with no readable block names nothing, and so does a `Fail` record's
/// authority — it was configured when the commit was sealed.
///
/// # Errors
///
/// [`VerifyError::Repo`] when `oid` does not resolve, is not a commit, or the
/// object database cannot be read.
pub fn named_tsas(repo: &Repo, oid: &str) -> Result<Vec<String>, VerifyError> {
    let (object, _raw) = repo.read_commit(oid)?;
    let pre = object.pre_image(store::PREFIX);
    let mut ids = Vec::new();
    if let Block::Present(block) = block_of(repo, oid, pre.trailer.as_deref()) {
        ids.extend(block.tokens.into_iter().map(|token| token.id));
        ids.extend(block.failures.into_iter().map(|failure| failure.id));
    }
    Ok(ids)
}

/// Judge the evidence of `oid`.
///
/// `anchors` is the pinned material; `policy` supplies the quorum and whether an
/// unsigned commit is a failure. `Ok` carries a verdict for every readable
/// commit, including ugly ones; [`VerifyError`] is reserved for a commit that
/// cannot be read at all.
///
/// # Errors
///
/// [`VerifyError::Repo`] when `oid` does not resolve, is not a commit, or the
/// object database cannot be read.
pub fn commit(
    repo: &Repo,
    anchors: &AnchorStore,
    oid: &str,
    policy: &Policy,
) -> Result<CommitEvidence, VerifyError> {
    let (object, _raw) = repo.read_commit(oid)?;
    let pre = object.pre_image(store::PREFIX);
    let mut warnings = Vec::new();

    let signature = match sigcheck::verify(&object, repo) {
        VerifyOutcome::Good => SignatureStatus::Good,
        VerifyOutcome::Bad => {
            warnings.push("the commit signature does not hold".to_owned());
            SignatureStatus::Bad
        }
        VerifyOutcome::Unsigned => SignatureStatus::Unsigned,
        VerifyOutcome::Error(detail) => {
            warnings.push(format!(
                "the commit signature could not be checked: {detail}"
            ));
            SignatureStatus::Error(detail)
        }
    };

    let mut evidence = CommitEvidence {
        oid: oid.to_owned(),
        verdict: Verdict::Unsealed,
        imprint: None,
        object_field: None,
        per_tsa: Vec::new(),
        signature,
        dropped: false,
        valid: 0,
        warnings,
    };

    match block_of(repo, oid, pre.trailer.as_deref()) {
        Block::None => {
            evidence.dropped = is_dropped(repo, oid);
        }
        Block::Malformed(reason) => {
            evidence
                .warnings
                .push(format!("the trailer block cannot be read: {reason}"));
            evidence.verdict = Verdict::BadToken;
        }
        Block::Present(block) => {
            evidence.imprint = Some(block.imprint.clone());
            evidence.object_field = block.object.clone();
            judge_tokens(&mut evidence, &block, &pre.bytes, anchors, policy, &object);
        }
    }

    // A broken signature outranks a passing verdict: a valid token over a broken
    // commit is never a PASS. An inconclusive check is treated the same way —
    // doubt fails closed. A verdict that already fails on the block itself
    // (`BadImprint`, `BadToken`, `Untrusted`, `UnderQuorum`) is kept, because it
    // names the actual evidence problem; the signature state is still reported
    // beside it.
    let passing = matches!(evidence.verdict, Verdict::Sealed | Verdict::Unsealed);
    if passing {
        match &evidence.signature {
            SignatureStatus::Bad | SignatureStatus::Error(_) => evidence.verdict = Verdict::BadSig,
            SignatureStatus::Unsigned if policy.require_signed => {
                evidence.verdict = Verdict::Unsigned;
            }
            _ => {}
        }
    }

    Ok(evidence)
}

/// Count and judge the block's tokens, and set the evidence's verdict.
fn judge_tokens(
    evidence: &mut CommitEvidence,
    block: &TrailerBlock,
    pre_image: &[u8],
    anchors: &AnchorStore,
    policy: &Policy,
    object: &CommitObject,
) {
    let expected = Digest {
        alg: block.imprint.alg,
        bytes: digest(block.imprint.alg, pre_image),
    };
    let bad_imprint = expected.bytes != block.imprint.bytes;

    let committer = committer_time(object);
    let window = gen_time_window(committer);
    let mut valid: BTreeSet<&str> = BTreeSet::new();
    let mut untrusted = 0usize;

    for record in &block.tokens {
        let imprint = Digest {
            alg: record.alg,
            bytes: digest(record.alg, pre_image),
        };
        let anchor = anchors
            .anchor(&record.id)
            .map(|anchor| crate::trust::fingerprint(anchor.root.as_bytes()));
        match judge(record, &imprint, window.clone(), anchors) {
            TokenVerdict::Valid {
                gen_time,
                tsa,
                serial,
            } => {
                valid.insert(record.id.as_str());
                evidence.per_tsa.push(TsaEvidence {
                    id: record.id.clone(),
                    gen_time: Some(gen_time),
                    verdict: VALID,
                    detail: Some(tsa),
                    serial: Some(serial),
                    anchor,
                });
                if gen_time < committer {
                    evidence.warnings.push(format!(
                        "committer date {committer} is after the genTime of `{}` ({gen_time})",
                        record.id
                    ));
                }
            }
            TokenVerdict::Invalid(invalid) => {
                if invalid == Invalid::Untrusted {
                    untrusted += 1;
                }
                // The token's own reason is the verdict; a missing pin is worth
                // spelling out because that is what the reader has to restore.
                let detail = match anchors.anchor(&record.id) {
                    None => Some(format!("no anchor pinned for `{}`", record.id)),
                    Some(_) => Some("the token does not chain to the pinned anchor".to_owned()),
                };
                evidence.per_tsa.push(TsaEvidence {
                    id: record.id.clone(),
                    gen_time: None,
                    verdict: invalid.as_str(),
                    detail,
                    serial: None,
                    anchor,
                });
            }
        }
    }

    // A recorded failure is evidence of its own: it names the authority that
    // stayed silent, which is what an under-quorum line has to explain.
    for failure in &block.failures {
        evidence.per_tsa.push(TsaEvidence {
            id: failure.id.clone(),
            gen_time: None,
            verdict: FAIL,
            detail: Some(failure.reason.clone()),
            serial: None,
            anchor: None,
        });
    }

    let tokens = block.tokens.len();
    evidence.valid = valid.len();
    evidence.verdict = if bad_imprint {
        // The block lies about the pre-image, so the token verdicts are only
        // context; the evidence itself is broken whatever they say.
        Verdict::BadImprint
    } else if tokens == 0 {
        if block.failures.is_empty() {
            // A block and nothing else: no authority was configured when this
            // was sealed. "Under quorum" would be read as authorities that
            // stayed silent, and there were none to stay silent.
            Verdict::None
        } else {
            // Nothing but `Fail` lines: no token was presented, and each
            // authority present is named as to why.
            Verdict::UnderQuorum
        }
    } else if valid.is_empty() {
        if untrusted == tokens {
            Verdict::Untrusted
        } else {
            Verdict::BadToken
        }
    } else if valid.len() < policy.required {
        Verdict::UnderQuorum
    } else {
        Verdict::Sealed
    };
}

/// What the commit's evidence looks like before it is judged.
enum Block {
    /// No trailer block and no note.
    None,
    /// A block that could not be decoded.
    Malformed(String),
    /// The block to judge.
    Present(TrailerBlock),
}

/// The block of `oid`, from its trailer or — when the trailer holds only an
/// imprint, which is what note storage writes — from its note.
fn block_of(repo: &Repo, oid: &str, trailer: Option<&[u8]>) -> Block {
    let Some(trailer) = trailer else {
        return Block::None;
    };
    let block = match store::decode(trailer) {
        Ok(Some(block)) => block,
        Ok(None) => return Block::None,
        Err(error) => return Block::Malformed(error.to_string()),
    };
    if !block.tokens.is_empty() {
        return Block::Present(block);
    }
    match note_block(repo, oid) {
        Note::Absent => Block::Present(block),
        Note::Malformed(reason) => Block::Malformed(reason),
        Note::Present(note) => Block::Present(note),
    }
}

/// What a commit's note holds.
enum Note {
    /// No note at all, or one that is not a block.
    Absent,
    /// A note that could not be decoded.
    Malformed(String),
    /// The block written beside the commit.
    Present(TrailerBlock),
}

/// The block stored as a note on `oid` under [`NOTE_REF`].
fn note_block(repo: &Repo, oid: &str) -> Note {
    let refspec = format!("--ref={NOTE_REF}");
    let Ok(run) = run_git(repo.path(), &["notes", &refspec, "show", oid], None) else {
        return Note::Absent;
    };
    if !run.succeeded() {
        return Note::Absent;
    }
    match store::decode(&run.stdout) {
        Ok(Some(block)) => Note::Present(block),
        Ok(None) => Note::Absent,
        Err(error) => Note::Malformed(error.to_string()),
    }
}

/// Whether `oid` is recorded in the drop file inside the git directory.
///
/// The git directory is asked for by git itself (`rev-parse --git-path`), so a
/// linked worktree reads its own drop file. A file that cannot be read answers
/// "not dropped": that only costs the `(dropped)` detail.
fn is_dropped(repo: &Repo, oid: &str) -> bool {
    let Ok(run) = run_git(
        repo.path(),
        &["rev-parse", "--git-path", DROPPED_FILE],
        None,
    ) else {
        return false;
    };
    if !run.succeeded() {
        return false;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&run.stdout).trim());
    let path = if path.is_absolute() {
        path
    } else {
        repo.path().join(path)
    };
    std::fs::read_to_string(path).is_ok_and(|text| text.lines().any(|line| line.trim() == oid))
}

/// Why a commit could not be judged.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The commit could not be read.
    #[error(transparent)]
    Repo(#[from] RepoError),
}
