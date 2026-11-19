//! The seal itself: turn one commit into timestamped evidence, or leave it
//! untouched.
//!
//! The order is the contract and every step is checked, not assumed:
//!
//! 1. the commit is still the tip, and it is a commit;
//! 2. the pre-image is extracted and stamped by every configured TSA that has a
//!    pinned anchor;
//! 3. every token is verified against the pinned anchors before it is kept, and
//!    the roots that vouched at its genTime are written down beside it;
//! 4. the object is rebuilt and the rewrite is *proved*: stripping the new
//!    trailer and signature must reproduce the sealed pre-image byte for byte,
//!    both before signing and on the final bytes;
//! 5. only then is the object written and the ref moved, and only if it still
//!    holds the object the seal started from.
//!
//! Anchors are per authority. A missing or unparseable bundle costs its own TSA
//! a `Fail` line, not the seal: the other authorities still answer and seal. The
//! seal only stops when no configured authority has a usable anchor, because
//! then no answer could be verified at all.
//!
//! The prove-then-write order is why a signature failure loses nothing: the
//! object is not written until the signature holds, so the original commit stays
//! exactly as it was.
//!
//! A replayed patch or an amended commit carries an old block; it is stripped by
//! [`CommitObject::pre_image`] and replaced. A commit whose block already claims
//! the imprint of its own pre-image is [`SkipReason::AlreadySealed`] and not
//! rewritten again.
//!
//! The note is written *before* the ref moves, so a lost compare-and-swap leaves
//! the note of a commit nobody points at: an orphan note. The move is retried
//! against the newer tip by the caller, which writes its own note; the orphan is
//! harmless and stays behind.
//!
//! Storage follows the policy: the block goes in the trailer, to
//! `refs/notes/rfc3161`, or both. A note-stored seal keeps only the imprint in
//! the commit, so the object stays small while the evidence lives beside it.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::Arc;

use jiff::Timestamp;

use crate::imprint::{Alg, Digest, digest};
use crate::object::CommitObject;
use crate::policy::{OnFailure, Policy, Store};
use crate::repo::{CasOutcome, Head, Repo, RepoError, run_git};
use crate::sigcheck::{self, SigHeader, SignatureState};
use crate::store::{self, FailureRecord, TokenRecord, TrailerBlock};
use crate::trust::{self, AnchorStore};
use crate::tsa::{PoolPolicy, StampRequest, TsaBackend, TsaError, pool};
use crate::verify::{self, TokenVerdict};

/// The note ref evidence is stored on under `time.store = note|both`.
pub const NOTE_REF: &str = "rfc3161";

/// How far before the commit time, and after now, a genTime may be.
///
/// A day in either direction absorbs clock skew between the machine and the
/// TSAs without accepting a token from another era. The lower bound is anchored
/// at the commit, not at now, so sealing an older commit from `git time seal
/// --range` still works.
const GEN_TIME_SLACK_SECONDS: i64 = 24 * 60 * 60;

/// The failure reason for an authority the passed anchor store does not pin and
/// whose policy holds no load error.
const NO_ANCHOR_REASON: &str = "no-anchor-pinned";

/// What a seal produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealOutcome {
    /// The commit was sealed and its ref moved.
    Sealed {
        /// The new commit object.
        oid: String,
        /// How many tokens verified.
        ok: usize,
        /// How many authorities were asked.
        total: usize,
    },
    /// Fewer tokens verified than the quorum asked for, but the evidence that
    /// did verify was written.
    UnderQuorum {
        /// The new commit object.
        oid: String,
        /// Every authority that did not contribute a token.
        failures: Vec<FailureRecord>,
    },
    /// The object was left exactly as it was.
    Skipped(SkipReason),
}

/// Why a seal did not attempt, or did not produce, evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The object the seal was pointed at is not a commit.
    NotACommit,
    /// HEAD moved before the commit could be read.
    HeadMoved,
    /// `time.enabled` is false.
    Disabled,
    /// The object already carries a block that claims the imprint of its own
    /// pre-image.
    AlreadySealed,
    /// Nothing verified and `time.record-failures` is false, so a rewrite would
    /// only add an empty block.
    NoTokensRecorded,
}

/// Why a seal failed.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// Reading or writing the repository failed.
    #[error(transparent)]
    Repo(#[from] RepoError),
    /// The block could not be encoded.
    #[error(transparent)]
    Store(#[from] store::EncodeError),
    /// A timestamp request could not be built, or a token's verification
    /// verdict could not be turned into a record.
    #[error(transparent)]
    Tsa(#[from] TsaError),
    /// Re-signing the rebuilt object failed; the original commit is untouched.
    #[error(transparent)]
    Sign(#[from] sigcheck::SignError),
    /// The rewrite did not reproduce the sealed pre-image.
    #[error("rebuilt object does not reproduce the pre-image: {detail}")]
    Invariant {
        /// How the stripped bytes differ: which side is longer and where the
        /// first differing byte sits.
        detail: String,
    },
    /// HEAD moved while the seal ran; the caller prints the `git time seal`
    /// hint.
    #[error("HEAD moved to {0} while sealing")]
    HeadMoved(String),
    /// The ref could not be moved although it still held the sealed object.
    #[error("the ref could not be moved: {0}")]
    RefUnmoved(String),
    /// Not one configured authority has an anchor that loaded, so no answer
    /// could be verified. The commit is untouched.
    #[error("no configured TSA has a usable anchor (run: git time doctor)")]
    NoUsableAnchor,
    /// The rebuilt object could not be read back.
    #[error(transparent)]
    Parse(#[from] crate::object::ParseError),
}

/// Seal the commit `oid`.
///
/// `tsas` and `anchors` are the authorities to ask and the material to check
/// their answers against; usually [`Policy::backends`] and [`Policy::anchors`].
///
/// Anchors are handled per authority: an authority without a pinned anchor is
/// not asked, and its place in the block is a `Fail` line whose reason comes
/// from [`Policy::anchor_failures`]. Only when no authority has a usable anchor
/// at all does the seal stop with [`SealError::NoUsableAnchor`], because nothing
/// it wrote could be verified.
///
/// # Errors
///
/// [`SealError`] when the repository or the block cannot be read or written,
/// when re-signing fails, when the rewrite does not reproduce the pre-image, when
/// the ref is at a different object after the seal, or when no configured
/// authority has an anchor.
pub async fn seal(
    repo: &Repo,
    policy: &Policy,
    tsas: &[Arc<dyn TsaBackend>],
    anchors: &AnchorStore,
    oid: &str,
) -> Result<SealOutcome, SealError> {
    if !policy.enabled {
        return Ok(SealOutcome::Skipped(SkipReason::Disabled));
    }

    let head = repo.head()?;
    let (object, _raw) = match repo.read_commit(oid) {
        Ok(pair) => pair,
        Err(RepoError::NotACommit(_)) => {
            return Ok(SealOutcome::Skipped(SkipReason::NotACommit));
        }
        Err(error) => return Err(error.into()),
    };
    if head_target(repo, &head)?.as_deref() != Some(oid) {
        return Ok(SealOutcome::Skipped(SkipReason::HeadMoved));
    }

    let pre = object.pre_image(store::PREFIX);
    let imprint = Digest {
        alg: Alg::Sha256,
        bytes: digest(Alg::Sha256, &pre.bytes),
    };

    if already_sealed(&object, &imprint) {
        return Ok(SealOutcome::Skipped(SkipReason::AlreadySealed));
    }

    // `X-RFC3161-Object` names the commit the tokens are taken over: the object
    // the *stripped* bytes hash to. Provenance only, never trusted back out of
    // the block — the imprint above is what decides.
    let object_id = repo.hash_commit(&pre.bytes)?;

    // An authority whose anchor did not load cannot produce a verifiable token,
    // so it is not asked: it fails up front, for its own id, and the seal goes
    // on with the authorities that are pinned.
    let mut anchor_failures = Vec::new();
    let mut usable: Vec<Arc<dyn TsaBackend>> = Vec::with_capacity(tsas.len());
    for source in tsas {
        if anchors.anchor(source.id()).is_some() {
            usable.push(Arc::clone(source));
        } else {
            anchor_failures.push(FailureRecord {
                id: source.id().to_owned(),
                reason: sanitize(
                    policy
                        .anchor_failure(source.id())
                        .unwrap_or(NO_ANCHOR_REASON),
                ),
            });
        }
    }
    // Nothing pinned at all: every answer would be `Untrusted`, so say that
    // instead of writing a block that proves nothing.
    if usable.is_empty() && !tsas.is_empty() {
        return Err(SealError::NoUsableAnchor);
    }

    // One request template per authority, each with its own algorithm and
    // policy; the pool draws a distinct nonce for every source from these.
    let mut requests = Vec::with_capacity(usable.len());
    for source in &usable {
        let (alg, tsa_policy) = policy
            .tsa(source.id())
            .map(|tsa| (tsa.alg, tsa.policy.clone()))
            .unwrap_or((Alg::Sha256, None));
        let request = StampRequest::new(
            Digest {
                alg,
                bytes: digest(alg, &pre.bytes),
            },
            &mut rand::rng(),
        )?
        .with_policy(tsa_policy)?;
        requests.push(request);
    }

    let pool_policy = PoolPolicy {
        required: policy.required,
        deadline: policy.deadline,
    };
    let outcome = pool::run_each(&usable, &requests, &pool_policy).await;

    let window = gen_time_window(committer_time(&object));
    let mut tokens = Vec::with_capacity(outcome.tokens.len());
    // The roots each verified id was checked against, sorted and de-duplicated
    // until the block wants a list.
    let mut anchor_roots: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut failures: Vec<FailureRecord> = anchor_failures;
    failures.extend(
        outcome
            .failures
            .into_iter()
            .map(|(id, reason)| FailureRecord {
                id,
                reason: sanitize(&reason),
            }),
    );
    for stamped in outcome.tokens {
        let record = TokenRecord {
            id: stamped.id,
            alg: stamped.request.imprint.alg,
            policy: stamped.request.policy,
            nonce: stamped.request.nonce,
            token: stamped.token,
        };
        // The answer is checked against the digest of the algorithm the
        // request actually asked for, not against the sha256 one used as the
        // store's imprint.
        let expected = Digest {
            alg: record.alg,
            bytes: digest(record.alg, &pre.bytes),
        };
        match verify::token(&record, &expected, window.clone(), anchors, &[]) {
            TokenVerdict::Valid { gen_time, .. } => {
                // The roots that vouched, at the token's own genTime: a
                // backfilled commit is stamped now, so the committer-time root
                // may already be retired. An id with no anchor or no root in the
                // window cannot get here — the verdict proved one exists — but a
                // missing entry stays empty rather than invented.
                if let Some(anchor) = anchors.anchor(&record.id) {
                    let prints = anchor_roots.entry(record.id.clone()).or_default();
                    for root in anchor.roots_at(gen_time) {
                        prints.insert(trust::fingerprint(root.as_bytes()));
                    }
                }
                tokens.push(record);
            }
            TokenVerdict::Invalid(invalid) => failures.push(FailureRecord {
                id: record.id,
                reason: format!("invalid-{}", invalid.as_str()),
            }),
        }
    }

    // With failure recording off, no `Fail` line is written at all — not even
    // when some tokens did verify. The quorum verdict below is unaffected.
    if !policy.record_failures {
        failures.clear();
    }

    // An `Anchor` line whose id has no record left is a ghost `encode` refuses.
    // Because a line is only collected from a token that verified, the clear
    // above cannot take a referent away today; the filter keeps that true if the
    // collection ever widens. Sorted sets render as sorted lists.
    anchor_roots.retain(|id, _| {
        tokens.iter().any(|token| &token.id == id)
            || failures.iter().any(|failure| &failure.id == id)
    });
    let anchor_roots: BTreeMap<String, Vec<String>> = anchor_roots
        .into_iter()
        .map(|(id, prints)| (id, prints.into_iter().collect()))
        .collect();

    if tokens.is_empty() && !policy.record_failures {
        return Ok(SealOutcome::Skipped(SkipReason::NoTokensRecorded));
    }

    let block = TrailerBlock {
        imprint: imprint.clone(),
        object: Some(object_id),
        anchors: anchor_roots,
        tokens,
        failures,
        extra: Vec::new(),
    };

    // Note storage keeps the commit small: the block goes beside the object and
    // the trailer holds only the imprint. The block is still bounded, so a
    // hostile token cannot make the note unbounded either.
    let note_block = matches!(policy.store, Store::Note | Store::Both)
        .then(|| store::encode(&block, policy.max_trailer_bytes))
        .transpose()?;
    let on_trailer = policy.store != Store::Note;

    let trailer = if on_trailer {
        store::encode(&block, policy.max_trailer_bytes)?
    } else {
        let stamp_only = TrailerBlock {
            imprint,
            object: None,
            anchors: BTreeMap::new(),
            tokens: Vec::new(),
            failures: Vec::new(),
            extra: Vec::new(),
        };
        store::encode(&stamp_only, policy.max_trailer_bytes)?
    };

    // Headers and message from the *pre-image*, not the raw object: an object
    // that already carried a block (an amended or replayed commit) must not keep
    // its old block, or the invariant below would count it as message.
    let mut stripped = CommitObject::parse(&pre.bytes)?;
    let mut message = std::mem::take(&mut stripped.message);
    message.push(b'\n');
    message.extend_from_slice(&trailer);
    message.push(b'\n');
    let mut candidate = CommitObject {
        headers: stripped.headers,
        message,
    };

    let state = sigcheck::inspect(&object);
    assert_invariant(&candidate, &pre.bytes)?;

    if let SignatureState::Unsigned = state {
        // Nothing to splice; the candidate is final.
    } else if let Some(header) = state.header() {
        let unsigned = candidate.without_signature();
        let armor = sigcheck::sign(&unsigned, &state, repo)?;
        candidate = splice(unsigned, header, &object, &armor);
    }

    assert_invariant(&candidate, &pre.bytes)?;

    let bytes = candidate.compose();
    let new_oid = repo.write_commit(&bytes)?;

    if let Some(note) = note_block.as_deref() {
        write_note(repo, &new_oid, note)?;
    }

    match repo.cas_update(&head, oid, &new_oid)? {
        CasOutcome::Moved => {}
        CasOutcome::Retry { current, .. } => return Err(SealError::HeadMoved(current)),
        CasOutcome::GaveUp { stderr } => return Err(SealError::RefUnmoved(stderr)),
    }

    // Count what actually landed: encoding may drop a token over the budget, and
    // note storage puts the evidence beside the object instead of in it.
    let evidence: &[u8] = if on_trailer {
        &trailer
    } else {
        note_block.as_deref().unwrap_or_default()
    };
    let recorded = store::decode(evidence).ok().flatten();
    let ok = recorded.as_ref().map_or(0, |block| block.tokens.len());
    if ok >= policy.required {
        Ok(SealOutcome::Sealed {
            oid: new_oid,
            ok,
            total: tsas.len(),
        })
    } else {
        Ok(SealOutcome::UnderQuorum {
            oid: new_oid,
            failures: recorded.map(|block| block.failures).unwrap_or_default(),
        })
    }
}

/// The current value of what `head` names, used to notice a moved HEAD before
/// any work is done.
fn head_target(repo: &Repo, head: &Head) -> Result<Option<String>, RepoError> {
    match head {
        Head::Symref(name) => repo.resolve_ref(name),
        Head::Detached(oid) => Ok(Some(oid.clone())),
    }
}

/// Whether `object` already carries a block that seals exactly these bytes.
///
/// The decision is the imprint alone: it is the digest of the pre-image, the one
/// piece of content a seal claims, and the only field note storage keeps in the
/// commit. Nothing is trusted back out of the block's `Object` field, so an
/// object that was replayed or amended and carried its old block along still
/// re-seals whenever its bytes changed. An object whose block matches its own
/// bytes is left as it is, whatever the block says it was taken over.
fn already_sealed(object: &CommitObject, imprint: &Digest) -> bool {
    let Some(trailer) = object.pre_image(store::PREFIX).trailer else {
        return false;
    };
    let Ok(Some(block)) = store::decode(&trailer) else {
        return false;
    };
    block.imprint == *imprint
}

/// Assert that stripping `candidate` gives back `expected` byte for byte.
fn assert_invariant(candidate: &CommitObject, expected: &[u8]) -> Result<(), SealError> {
    let stripped = candidate.pre_image(store::PREFIX).bytes;
    if stripped == expected {
        return Ok(());
    }
    Err(SealError::Invariant {
        detail: difference(&stripped, expected),
    })
}

/// Describe how `actual` differs from `expected`: which side is longer and where
/// the first differing byte is, so a failing invariant can be acted on.
fn difference(actual: &[u8], expected: &[u8]) -> String {
    let shared = actual.len().min(expected.len());
    let offset = (0..shared)
        .find(|index| actual[*index] != expected[*index])
        .unwrap_or(shared);
    let longer = match actual.len().cmp(&expected.len()) {
        std::cmp::Ordering::Greater => format!(
            "the rebuilt object is {} bytes longer than the pre-image",
            actual.len() - expected.len()
        ),
        std::cmp::Ordering::Less => format!(
            "the rebuilt object is {} bytes shorter than the pre-image",
            expected.len() - actual.len()
        ),
        std::cmp::Ordering::Equal => {
            format!("both sides are {} bytes long", expected.len())
        }
    };
    if offset == shared {
        format!("{longer}, first difference at byte {offset} (end of the shorter side)")
    } else {
        format!("{longer}, first difference at byte {offset}")
    }
}

/// Put `armor` back under `header`, where it sat in `original`.
///
/// git stores a signature as `gpgsig <first line>` with every following line
/// prefixed by one space; the header value holds the unfolded lines and
/// [`CommitObject::compose`] writes the prefixes. The position is the one the
/// old signature had, so the object keeps its header order.
fn splice(
    mut commit: CommitObject,
    header: SigHeader,
    original: &CommitObject,
    armor: &[u8],
) -> CommitObject {
    let index = original
        .headers
        .iter()
        .position(|(name, _)| {
            std::str::from_utf8(name)
                .ok()
                .and_then(SigHeader::from_name)
                .is_some()
        })
        .unwrap_or(commit.headers.len());
    let value = armor.strip_suffix(b"\n").unwrap_or(armor).to_vec();
    commit
        .headers
        .insert(index, (header.as_str().as_bytes().to_vec(), value));
    commit
}

/// Write `block` as a note on `oid` under [`NOTE_REF`].
///
/// The note is replaced when it exists, so a re-seal overwrites its old note
/// rather than stacking a second one.
fn write_note(repo: &Repo, oid: &str, block: &[u8]) -> Result<(), SealError> {
    let refspec = format!("--ref={NOTE_REF}");
    let args = ["notes", refspec.as_str(), "add", "-f", "-F", "-", oid];
    let run = run_git(repo.path(), &args, Some(block))?;
    if run.succeeded() {
        return Ok(());
    }
    Err(SealError::Repo(RepoError::Git {
        command: args.join(" "),
        stderr: run.stderr,
    }))
}

/// The genTime window tokens are accepted in: a day around the anchor time.
///
/// The anchor is the earlier one on the lower side and the later one on the
/// upper, so neither a committer date far ahead of now nor a commit sealed long
/// after it was made can push its own genTime out of the window.
pub(crate) fn gen_time_window(commit_time: Timestamp) -> Range<Timestamp> {
    let now = Timestamp::now();
    let low = commit_time.min(now);
    let high = commit_time.max(now);
    let start = low.as_second().saturating_sub(GEN_TIME_SLACK_SECONDS);
    let end = high.as_second().saturating_add(GEN_TIME_SLACK_SECONDS);
    let start = Timestamp::from_second(start).unwrap_or(Timestamp::MIN);
    let end = Timestamp::from_second(end).unwrap_or(Timestamp::MAX);
    start..end
}

/// The committer timestamp of `object`.
///
/// A committer line is `committer <name> <email> <seconds> <offset>`; the
/// seconds are the second-to-last whitespace-separated field. An object without
/// a usable one falls back to now.
pub(crate) fn committer_time(object: &CommitObject) -> Timestamp {
    object
        .header("committer")
        .and_then(|value| value.rsplit(|byte| *byte == b' ').nth(1))
        .and_then(|seconds| std::str::from_utf8(seconds).ok())
        .and_then(|seconds| seconds.parse::<i64>().ok())
        .and_then(|seconds| Timestamp::from_second(seconds).ok())
        .unwrap_or_else(Timestamp::now)
}

/// A failure reason the trailer format can carry.
///
/// Transport reasons are prose (`http 503: unavailable`, a rejection's
/// `statusString`), and the block stores one `key=value` per field with spaces
/// and semicolons as separators. Everything outside a small safe set becomes
/// `-`, and the text is trimmed to a diagnostic length, so a TSA's error page
/// cannot break the block or bloat it.
fn sanitize(reason: &str) -> String {
    const MAX_CHARS: usize = 200;
    let mut out = String::with_capacity(reason.len().min(MAX_CHARS));
    let mut last_dash = false;
    for character in reason.chars() {
        let keep = character.is_ascii_alphanumeric()
            || matches!(character, '-' | '.' | '_' | ':' | '/' | '(' | ')');
        if keep {
            out.push(character);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
        if out.chars().count() >= MAX_CHARS {
            break;
        }
    }
    // A trailing separator reads as an unfinished sentence.
    out.trim_end_matches('-').to_owned()
}

/// Whether the policy asks for a warning rather than a hard failure; used by
/// callers that only need the exit code.
#[must_use]
pub fn is_warning(policy: &Policy) -> bool {
    policy.on_failure == OnFailure::Warn
}
