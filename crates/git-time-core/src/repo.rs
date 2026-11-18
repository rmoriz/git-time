//! The repository a seal runs in.
//!
//! Signing, verification and the seal itself all point git at one directory;
//! this module is the only place in the crate that starts git at all. It offers
//! what the pipeline needs and nothing more: configuration, where HEAD points,
//! reading and writing raw commit objects, and moving a ref only if it is still
//! where the seal found it.
//!
//! Every invocation runs through one helper, which captures both streams and
//! names the command it ran, so a failure carries git's own words instead of a
//! bare exit code.

use std::cell::Cell;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::object::CommitObject;
use crate::repo::RepoError::{Git, Io, NoHead, NotACommit, NotARepo, Rejected};

/// The reflog message every ref move of a seal is recorded under.
const REFLOG_MESSAGE: &str = "rfc3161 seal";

/// How many times a refusal is tried while the ref still holds the old value.
const CAS_ATTEMPTS: u32 = 3;

/// The first wait between attempts, and the default of [`Repo::set_retry_delay`];
/// attempt `n` waits `n` times it, so the waits grow linearly: 50 and 100 ms,
/// 150 ms in total.
const CAS_BACKOFF: Duration = Duration::from_millis(50);

/// A repository, identified by its directory.
#[derive(Debug, Clone)]
pub struct Repo {
    path: PathBuf,
    /// Waited `attempt` times between refused ref moves; see
    /// [`Repo::set_retry_delay`].
    retry_delay: Duration,
    /// `update-ref` invocations of the last `cas_update`, for diagnostics; see
    /// [`Repo::update_ref_attempts`].
    update_ref_attempts: Cell<u32>,
}

/// Two handles are the same repository when they name the same directory.
///
/// The other fields are settings and diagnostics of one handle, not facts about
/// the repository: the retry delay is a knob, and the attempt count belongs to
/// the last `cas_update`. Including them would stop two handles to the same
/// repository from comparing equal as soon as one of them ran a ref move.
impl PartialEq for Repo {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for Repo {}

/// Where HEAD points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    /// HEAD names a branch, given by its full ref name.
    Symref(String),
    /// HEAD is detached at a commit, given by its object id.
    Detached(String),
}

impl Head {
    /// The ref a move has to name: the branch, or `HEAD` itself when detached.
    fn refname(&self) -> &str {
        match self {
            // A commit id is not a stable refusal target across a race, so a
            // detached HEAD is moved through HEAD, which keeps it detached.
            Self::Symref(name) => name,
            Self::Detached(_) => "HEAD",
        }
    }
}

/// What became of a compare-and-swap ref move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasOutcome {
    /// The ref was still at the old value and now holds the new one.
    Moved,
    /// The ref no longer holds the old value. Repeating the same move cannot
    /// succeed: the caller must rebuild its object against `current` — the tip
    /// the ref holds now — and call again.
    Retry {
        /// The object id the ref holds now, to rebuild against.
        current: String,
        /// git's stderr from the refusal, for diagnostics.
        stderr: String,
    },
    /// The ref could not be moved; the caller surfaces `stderr` rather than
    /// retrying, since nothing about its object was wrong.
    ///
    /// Two cases end here. The ref still held the old value and stayed put — a
    /// lock, a permission, some other transient refusal — which is retried
    /// across the attempts and then given up on. Or the ref was deleted
    /// mid-seal, which leaves no tip to rebuild against and is answered at once
    /// with a message naming the ref.
    GaveUp {
        /// git's stderr from the last refusal.
        stderr: String,
    },
}

/// What one git invocation left behind, whether or not it succeeded.
///
/// Exit codes are kept as answers rather than turned into errors at once:
/// `config` and `symbolic-ref` both use exit 1 for "none", and `cas_update`
/// treats a failed `update-ref` as a fact to inspect.
pub(crate) struct Run {
    /// The exit code, or `None` when git was killed by a signal.
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    /// git's stderr, trimmed of surrounding whitespace.
    pub(crate) stderr: String,
}

impl Run {
    pub(crate) fn succeeded(&self) -> bool {
        self.code == Some(0)
    }
}

impl Repo {
    /// Open the repository at `path`, which may be any directory inside it.
    ///
    /// The check is git's own: a path git does not recognise as a repository is
    /// refused here instead of at the first command that needs one. Its stderr
    /// is kept, because "not a repository" is not the only reason git says no —
    /// a broken `.git` file or a repository owned by another user reads very
    /// differently and must not be flattened into one message.
    pub fn open(path: &Path) -> Result<Self, RepoError> {
        let run = run_git(path, &["rev-parse", "--git-dir"], None)?;
        if !run.succeeded() {
            return Err(NotARepo {
                path: path.to_path_buf(),
                stderr: run.stderr,
            });
        }
        Ok(Self {
            path: path.to_path_buf(),
            retry_delay: CAS_BACKOFF,
            update_ref_attempts: Cell::new(0),
        })
    }

    /// The directory every git command is pointed at.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Use `delay` as the first wait between refused [`Repo::cas_update`]
    /// attempts instead of the 50 ms default; attempt `n` waits `n` times it,
    /// so the waits still grow linearly.
    ///
    /// Meant for tests and for callers that need a tighter budget than the
    /// 150 ms the default spends. Nothing but the ref move is affected.
    pub fn set_retry_delay(&mut self, delay: Duration) {
        self.retry_delay = delay;
    }

    /// How many `update-ref` invocations the last [`Repo::cas_update`] made.
    ///
    /// Diagnostics only: the count is reset when the next `cas_update` starts.
    #[must_use]
    pub fn update_ref_attempts(&self) -> u32 {
        self.update_ref_attempts.get()
    }

    /// The last value of the config key `key`, or `None` when it is unset.
    ///
    /// The key is passed to git as one argument, never through a shell, so a
    /// value containing spaces or metacharacters cannot change the command. Both
    /// line-ending bytes are trimmed: a value read from a CRLF config would
    /// otherwise carry a `\r` into comparisons.
    pub fn config(&self, key: &str) -> Result<Option<String>, RepoError> {
        let args = ["config", "--get", key];
        let run = self.run(&args, None)?;
        match run.code {
            Some(0) => Ok(Some(trim(&run.stdout))),
            // `git config --get` exits 1 when the key has no value.
            Some(1) => Ok(None),
            _ => Err(failure(&args, run.stderr)),
        }
    }

    /// Like [`Repo::config`], but a key set to the empty string counts as
    /// unset, the way git treats `key =` for settings that name something.
    pub fn config_non_empty(&self, key: &str) -> Result<Option<String>, RepoError> {
        Ok(self.config(key)?.filter(|value| !value.is_empty()))
    }

    /// Where HEAD points, as a branch name or a detached commit id.
    ///
    /// A repository without a commit yet has no answer: the branch HEAD is on
    /// exists, but nothing is at its tip.
    pub fn head(&self) -> Result<Head, RepoError> {
        let args = ["symbolic-ref", "-q", "HEAD"];
        let symbolic = self.run(&args, None)?;
        match symbolic.code {
            Some(0) => {
                let name = trim(&symbolic.stdout);
                if self.resolve_ref("HEAD")?.is_none() {
                    return Err(NoHead);
                }
                Ok(Head::Symref(name))
            }
            // A detached HEAD is not a symbolic ref, and git says so with 1.
            Some(1) => {
                let rev = self.run(&["rev-parse", "HEAD"], None)?;
                if !rev.succeeded() {
                    return Err(NoHead);
                }
                Ok(Head::Detached(trim(&rev.stdout)))
            }
            _ => Err(failure(&args, symbolic.stderr)),
        }
    }

    /// Read the commit object `oid`, parsed, with its bytes exactly as stored.
    ///
    /// The raw bytes are what a signature and an imprint are taken over, so they
    /// are handed on untouched next to the parsed form.
    ///
    /// The type is asked for first: only an object git positively reports as
    /// something other than a commit becomes [`RepoError::NotACommit`]. A
    /// missing object, a corrupt one or a repository git cannot read keeps its
    /// own error instead of being flattened into "not a commit".
    pub fn read_commit(&self, oid: &str) -> Result<(CommitObject, Vec<u8>), RepoError> {
        self.require_commit(oid)?;
        let args = ["cat-file", "commit", oid];
        let run = self.run(&args, None)?;
        if !run.succeeded() {
            return Err(failure(&args, run.stderr));
        }
        let parsed = CommitObject::parse(&run.stdout)?;
        Ok((parsed, run.stdout))
    }

    /// Refuse `oid` unless the object database positively says it is a commit.
    ///
    /// git answers the type or exits non-zero; the exit is kept as an error, so
    /// a broken repository is not mistaken for a non-commit.
    fn require_commit(&self, oid: &str) -> Result<(), RepoError> {
        let args = ["cat-file", "-t", oid];
        let run = self.run(&args, None)?;
        if !run.succeeded() {
            return Err(failure(&args, run.stderr));
        }
        if trim(&run.stdout) == "commit" {
            Ok(())
        } else {
            Err(NotACommit(oid.to_owned()))
        }
    }

    /// Write `bytes` as a commit object and return its id.
    ///
    /// `hash-object` runs git's fsck over the object, so a rebuild git would not
    /// accept fails here, with git's stderr as [`RepoError::Rejected`].
    ///
    /// That check is best-effort: fsck obeys the user's configuration, and
    /// `fsck.skipList` can suppress findings, so a clean return here is not a
    /// proof of well-formedness. The authoritative check is the seal pipeline's
    /// own "strip the composed object and compare it to the sealed pre-image"
    /// assertion; fsck is the early, cheaper warning in front of it.
    pub fn write_commit(&self, bytes: &[u8]) -> Result<String, RepoError> {
        let args = ["hash-object", "-w", "-t", "commit", "--stdin"];
        let run = self.run(&args, Some(bytes))?;
        if !run.succeeded() {
            return Err(Rejected(run.stderr));
        }
        object_id(&args, &run)
    }

    /// The object id `bytes` would be stored under as a commit, without storing
    /// it.
    ///
    /// No `-w`, so nothing reaches the object database: this is how a field that
    /// names the object can be filled in before it is known whether a rewrite is
    /// even written. git's fsck still runs, so an object it would refuse is
    /// reported here too.
    pub fn hash_commit(&self, bytes: &[u8]) -> Result<String, RepoError> {
        let args = ["hash-object", "-t", "commit", "--stdin"];
        let run = self.run(&args, Some(bytes))?;
        if !run.succeeded() {
            return Err(failure(&args, run.stderr));
        }
        object_id(&args, &run)
    }

    /// Move the ref `head` names from `old` to `new`, if it is still at `old`.
    ///
    /// A refusal is not automatically an error, and what the caller can do next
    /// depends on whether the ref moved:
    ///
    /// - The ref no longer holds `old`: [`CasOutcome::Retry`] at once, carrying
    ///   the tip it holds now. Repeating the same move cannot succeed, so there
    ///   is no point in waiting. The caller rebuilds its object against
    ///   `current` and calls again.
    /// - The ref still holds `old`: a lock, a permission or another transient
    ///   refusal. Retried here, up to three attempts with a linear wait (50 and
    ///   100 ms by default; see [`Repo::set_retry_delay`]), then
    ///   [`CasOutcome::GaveUp`] with git's stderr — the ref could not be moved
    ///   at all and the caller surfaces the stderr.
    ///
    /// A ref deleted mid-seal has no tip to rebuild against, so it is
    /// [`CasOutcome::GaveUp`] straight away, with a message naming the ref.
    ///
    /// The reflog entry is best-effort. User configuration such as
    /// `core.logAllRefUpdates=false` (off by default in bare repositories) drops
    /// it, and the move still succeeds. The audit evidence is the trailered
    /// object plus the ref value, never the reflog.
    pub fn cas_update(&self, head: &Head, old: &str, new: &str) -> Result<CasOutcome, RepoError> {
        let refname = head.refname();
        let args = ["update-ref", "-m", REFLOG_MESSAGE, refname, new, old];
        let mut attempt: u32 = 1;
        self.update_ref_attempts.set(0);
        loop {
            let run = self.run(&args, None)?;
            self.update_ref_attempts.set(attempt);
            if run.succeeded() {
                return Ok(CasOutcome::Moved);
            }
            match self.resolve_ref(refname)? {
                // The ref moved: another build is what can still succeed.
                Some(current) if current != old => {
                    return Ok(CasOutcome::Retry {
                        current,
                        stderr: run.stderr,
                    });
                }
                // The ref is gone: there is nothing to rebuild against.
                None => {
                    return Ok(CasOutcome::GaveUp {
                        stderr: format!("{refname} no longer exists: {}", run.stderr),
                    });
                }
                Some(_) => {}
            }
            if attempt >= CAS_ATTEMPTS {
                return Ok(CasOutcome::GaveUp { stderr: run.stderr });
            }
            std::thread::sleep(backoff(self.retry_delay, attempt));
            attempt += 1;
        }
    }

    /// The commit `refname` currently names, if it names one at all.
    pub fn resolve_ref(&self, refname: &str) -> Result<Option<String>, RepoError> {
        let args = ["rev-parse", "-q", "--verify", refname];
        let run = self.run(&args, None)?;
        match run.code {
            Some(0) => Ok(Some(trim(&run.stdout))),
            Some(1) => Ok(None),
            _ => Err(failure(&args, run.stderr)),
        }
    }

    /// Run git in this repository, with `input` on stdin.
    fn run(&self, args: &[&str], input: Option<&[u8]>) -> Result<Run, RepoError> {
        run_git(&self.path, args, input)
    }
}

/// Run `git -C path args`, optionally with `input` on stdin, and capture both
/// streams.
///
/// `args` is joined into the command name any error built from this run reports.
pub(crate) fn run_git(path: &Path, args: &[&str], input: Option<&[u8]>) -> Result<Run, RepoError> {
    let mut command = Command::new("git");
    command.arg("-C").arg(path).args(args);
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn()?;
    if let Some(input) = input {
        let Some(mut stdin) = child.stdin.take() else {
            return Err(Io("git has no stdin to write to".to_owned()));
        };
        if let Err(error) = stdin.write_all(input) {
            // Closing stdin lets git finish; a broken pipe usually means it has
            // already failed, and its stderr says why. Reap it either way
            // instead of leaving it behind.
            drop(stdin);
            let output = child.wait_with_output()?;
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if stderr.is_empty() {
                return Err(Io(format!(
                    "writing to git {} failed: {error}",
                    args.join(" ")
                )));
            }
            return Err(failure(args, stderr));
        }
        // Dropping stdin is the end-of-input signal.
    }
    let output = child.wait_with_output()?;
    Ok(Run {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

/// The wait before the attempt after `attempt`: `delay` times the attempt
/// number, so the waits grow linearly.
fn backoff(delay: Duration, attempt: u32) -> Duration {
    delay * attempt
}

/// The object id in `run`'s stdout, checked to look like one.
fn object_id(args: &[&str], run: &Run) -> Result<String, RepoError> {
    let oid = trim(&run.stdout);
    let well_formed =
        matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !well_formed {
        return Err(Git {
            command: args.join(" "),
            stderr: format!("unexpected object id {oid:?}"),
        });
    }
    Ok(oid)
}

/// The error for a failed run of `args`.
fn failure(args: &[&str], stderr: String) -> RepoError {
    Git {
        command: args.join(" "),
        stderr,
    }
}

/// git output as a string, without the line terminator.
fn trim(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches(['\n', '\r'])
        .to_owned()
}

/// Why a repository could not be opened or queried.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RepoError {
    /// The path is not inside a git repository, in git's own words.
    #[error("{} is not a git repository: {stderr}", path.display())]
    NotARepo {
        /// The directory that was offered.
        path: PathBuf,
        /// git's stderr, which says more than "not a repository" when it can.
        stderr: String,
    },
    /// HEAD does not reach a commit; the branch is unborn.
    #[error("HEAD does not point at a commit yet")]
    NoHead,
    /// The object exists but is not a commit: a blob, a tree, an annotated tag.
    #[error("object {0} is not a commit")]
    NotACommit(String),
    /// git refused to store the object, usually in fsck.
    #[error("git refused the object: {0}")]
    Rejected(String),
    /// A stored object could not be parsed.
    #[error(transparent)]
    Parse(#[from] crate::object::ParseError),
    /// A git command failed.
    #[error("git {command} failed: {stderr}")]
    Git {
        /// The command and its arguments.
        command: String,
        /// git's stderr.
        stderr: String,
    },
    /// git could not be spawned at all.
    #[error("{0}")]
    Io(String),
}

impl From<std::io::Error> for RepoError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
