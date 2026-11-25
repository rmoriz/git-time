//! Repository plumbing the seal pipeline stands on: where HEAD points, reading
//! and writing raw commit objects, and the compare-and-swap ref move.
//!
//! The tests are cut off from the developer's git config the same way the
//! sigcheck tests are — `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` point at
//! `/dev/null` — so nothing on the machine can steer branch names or reflogs.

#![allow(
    unsafe_code,
    reason = "the harness points the process environment at a temporary directory before any child runs"
)]

use git_time_core::object::{CommitObject, ParseError};
use git_time_core::repo::{CasOutcome, Head, Repo, RepoError};

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Once;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const MESSAGE: &str = "subject\n";

/// Keeps the developer's global and system git config out of the test binary.
fn insulate() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: this is the only writer of these two variables in the binary.
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", "/dev/null");
            std::env::set_var("GIT_CONFIG_SYSTEM", "/dev/null");
        }
    });
}

/// Run git in `dir` with `input` on stdin and return the raw output.
fn git_output(dir: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns git");
    {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(input)
            .expect("writes stdin");
    }
    child.wait_with_output().expect("waits for git")
}

/// Run git in `dir`, assert success and return stdout.
fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = git_output(dir, args, b"");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// A commit object with an empty tree and no signature, ready for `hash-object`.
fn object(message: &str) -> Vec<u8> {
    format!(
        "tree {EMPTY_TREE}\nauthor Test <t@example.com> 1700000000 +0000\n\
         committer Test <t@example.com> 1700000000 +0000\n\n{message}"
    )
    .into_bytes()
}

/// A temporary repository, its handle, and the branch HEAD is on.
fn repo() -> (TempDir, Repo) {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    git(dir.path(), &["init", "-q", "-b", "main"]);
    git(dir.path(), &["config", "user.name", "Test"]);
    git(dir.path(), &["config", "user.email", "t@example.com"]);
    let repo = Repo::open(dir.path()).expect("opens the fresh repository");
    (dir, repo)
}

/// Make a commit with git itself, returning its object id.
fn commit(repo: &Repo, message: &str) -> String {
    git(
        repo.path(),
        &["commit", "-q", "--allow-empty", "-m", message],
    );
    String::from_utf8(git(repo.path(), &["rev-parse", "HEAD"]))
        .expect("an object id is ASCII")
        .trim_end()
        .to_owned()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// --- config --------------------------------------------------------------

#[test]
fn config_entries_lists_every_match_in_config_order() {
    let (dir, repo) = repo();
    git(dir.path(), &["config", "time.required", "2"]);
    git(
        dir.path(),
        &["config", "time.tsa.one.url", "https://one.example/tsr"],
    );
    git(
        dir.path(),
        &["config", "time.tsa.one.anchor", "a path with spaces.pem"],
    );
    // A repeated key: git keeps every value, the last one wins for `--get`.
    git(dir.path(), &["config", "--add", "time.required", "3"]);

    let entries = repo
        .config_entries("^time\\.")
        .expect("reads the matching keys");
    assert_eq!(
        entries,
        vec![
            ("time.required".to_owned(), "2".to_owned()),
            ("time.required".to_owned(), "3".to_owned()),
            (
                "time.tsa.one.url".to_owned(),
                "https://one.example/tsr".to_owned()
            ),
            (
                "time.tsa.one.anchor".to_owned(),
                "a path with spaces.pem".to_owned()
            ),
        ]
    );
    assert_eq!(
        repo.config("time.required"),
        Ok(Some("3".to_owned())),
        "the last value is what `--get` answers"
    );
    assert_eq!(repo.config_entries("^time\\.nope"), Ok(Vec::new()));
}

// --- head ----------------------------------------------------------------

#[test]
fn head_names_the_branch() {
    let (dir, repo) = repo();
    commit(&repo, "first");
    let branch = text(&git(dir.path(), &["symbolic-ref", "HEAD"]))
        .trim_end()
        .to_owned();

    assert_eq!(repo.head(), Ok(Head::Symref(branch)));
}

#[test]
fn head_reports_the_commit_of_a_detached_head() {
    let (dir, repo) = repo();
    let oid = commit(&repo, "first");
    git(dir.path(), &["checkout", "-q", "--detach", &oid]);

    assert_eq!(repo.head(), Ok(Head::Detached(oid)));
}

#[test]
fn a_repository_without_commits_has_no_head() {
    let (_dir, repo) = repo();
    assert_eq!(repo.head(), Err(RepoError::NoHead));
}

// --- objects -------------------------------------------------------------

#[test]
fn read_commit_returns_the_exact_bytes_git_stored() {
    let (_dir, repo) = repo();
    let oid = commit(&repo, MESSAGE);
    let stored = git(repo.path(), &["cat-file", "commit", &oid]);

    let (parsed, raw) = repo.read_commit(&oid).expect("reads the commit");
    assert_eq!(raw, stored, "the raw bytes are handed on untouched");
    assert_eq!(parsed.compose(), stored);
    assert_eq!(CommitObject::parse(&raw), Ok(parsed.clone()));
    assert_eq!(
        text(parsed.header("tree").expect("the commit has a tree")),
        EMPTY_TREE
    );
    assert_eq!(parsed.message, MESSAGE.as_bytes());
}

#[test]
fn read_commit_of_a_missing_object_is_a_git_error() {
    let (_dir, repo) = repo();
    let missing = "0123456789012345678901234567890123456789";
    // No object at all is not the same answer as an object of the wrong type:
    // the repo, not the caller's oid, is what could be wrong.
    let error = repo.read_commit(missing).expect_err("no such object");
    let RepoError::Git { command, stderr } = &error else {
        panic!("expected Git, got {error:?}");
    };
    assert_eq!(
        command,
        "cat-file commit 0123456789012345678901234567890123456789"
    );
    assert!(!stderr.is_empty(), "git's own words are kept");
}

#[test]
fn read_commit_of_a_blob_or_tree_is_not_a_commit() {
    let (dir, repo) = repo();
    let blob =
        text(&git_output(dir.path(), &["hash-object", "-w", "--stdin"], b"blob body").stdout)
            .trim_end()
            .to_owned();
    assert_eq!(
        repo.read_commit(&blob),
        Err(RepoError::NotACommit(blob.clone()))
    );
    assert_eq!(
        repo.read_commit(EMPTY_TREE),
        Err(RepoError::NotACommit(EMPTY_TREE.to_owned()))
    );
}

#[test]
fn hash_commit_names_the_object_without_writing_it() {
    let (_dir, repo) = repo();
    let bytes = object(MESSAGE);

    let oid = repo.hash_commit(&bytes).expect("hashes the object");
    // Identical to what storing it would produce, so a caller can name the
    // object before deciding to write it.
    assert_eq!(
        text(
            &git_output(
                repo.path(),
                &["hash-object", "-t", "commit", "--stdin"],
                &bytes,
            )
            .stdout
        )
        .trim_end(),
        oid
    );
    // Nothing was written: the commit does not resolve yet.
    assert!(
        !git_output(repo.path(), &["cat-file", "-e", &oid], b"")
            .status
            .success()
    );

    let written = repo.write_commit(&bytes).expect("writes the object");
    assert_eq!(written, oid);
}

#[test]
fn hash_commit_reports_an_object_git_refuses() {
    let (_dir, repo) = repo();
    // No `tree` header: fsck refuses it even without `-w`.
    let broken = format!(
        "author Test <t@example.com> 1700000000 +0000\n\
         committer Test <t@example.com> 1700000000 +0000\n\n{MESSAGE}"
    );

    let error = repo
        .hash_commit(broken.as_bytes())
        .expect_err("fsck rejects a commit without a tree");
    assert!(matches!(error, RepoError::Git { .. }), "{error:?}");
    assert!(error.to_string().contains("fsck"), "{error}");
}

#[test]
fn an_unparsable_object_surfaces_the_parse_error() {
    let (_dir, repo) = repo();
    // A commit without the blank line before the message: git stores it, the
    // parser refuses it.
    let broken = format!(
        "tree {EMPTY_TREE}\nauthor Test <t@example.com> 1700000000 +0000\n\
         committer Test <t@example.com> 1700000000 +0000\nno separator\n"
    );
    let oid = text(
        &git_output(
            repo.path(),
            &["hash-object", "-w", "-t", "commit", "--stdin"],
            broken.as_bytes(),
        )
        .stdout,
    )
    .trim_end()
    .to_owned();

    assert_eq!(
        repo.read_commit(&oid),
        Err(RepoError::Parse(ParseError::MissingSeparator))
    );
}

#[test]
fn write_commit_round_trips_through_read_commit() {
    let (_dir, repo) = repo();
    let bytes = object(MESSAGE);

    let oid = repo.write_commit(&bytes).expect("writes the object");
    assert_eq!(oid.len(), 40);
    assert!(oid.chars().all(|c| c.is_ascii_hexdigit()), "{oid}");

    let (parsed, raw) = repo.read_commit(&oid).expect("reads it back");
    assert_eq!(raw, bytes);
    assert_eq!(parsed.message, MESSAGE.as_bytes());
}

#[test]
fn write_commit_reports_an_object_git_refuses() {
    let (_dir, repo) = repo();
    // No `tree` header: git's fsck rejects it and says why.
    let broken = format!(
        "author Test <t@example.com> 1700000000 +0000\n\
         committer Test <t@example.com> 1700000000 +0000\n\n{MESSAGE}"
    );

    let error = repo
        .write_commit(broken.as_bytes())
        .expect_err("fsck rejects a commit without a tree");
    let RepoError::Rejected(stderr) = error else {
        panic!("expected Rejected, got {error:?}");
    };
    assert!(stderr.contains("fsck"), "{stderr}");
}

// --- CAS ref move --------------------------------------------------------

/// The branch a `Head::Symref` names, for tests that only set up branches.
fn branch(head: &Head) -> String {
    match head {
        Head::Symref(name) => name.clone(),
        Head::Detached(_) => panic!("the branch is checked out"),
    }
}

/// The lock file git takes while it moves `head`'s ref.
fn ref_lock(repo: &Repo, head: &Head) -> std::path::PathBuf {
    let git_dir = text(&git(repo.path(), &["rev-parse", "--absolute-git-dir"]))
        .trim_end()
        .to_owned();
    let refname = match head {
        Head::Symref(name) => name.clone(),
        Head::Detached(_) => "HEAD".to_owned(),
    };
    let lock = Path::new(&git_dir).join(format!("{refname}.lock"));
    std::fs::create_dir_all(lock.parent().expect("refs live in a directory"))
        .expect("creates the ref directories");
    lock
}

#[test]
fn cas_update_moves_the_branch_and_records_a_reflog_entry() {
    let (dir, repo) = repo();
    let old = commit(&repo, "first");
    let new = repo.write_commit(&object("second\n")).expect("writes");
    let head = repo.head().expect("a head");
    let refname = branch(&head);

    assert_eq!(repo.cas_update(&head, &old, &new), Ok(CasOutcome::Moved));

    assert_eq!(
        text(&git(dir.path(), &["rev-parse", &refname])),
        format!("{new}\n")
    );
    // The seal's own entry is the newest one; the commit before it stays below.
    let reflog = text(&git(
        dir.path(),
        &["reflog", "show", "--format=%gs", &refname],
    ));
    assert_eq!(
        reflog.lines().next(),
        Some("rfc3161 seal"),
        "the seal's move is the first reflog entry: {reflog}"
    );
}

#[test]
fn cas_update_moves_a_detached_head() {
    let (dir, repo) = repo();
    let old = commit(&repo, "first");
    git(dir.path(), &["checkout", "-q", "--detach", &old]);
    let new = repo.write_commit(&object("second\n")).expect("writes");
    let head = repo.head().expect("a head");

    assert_eq!(repo.cas_update(&head, &old, &new), Ok(CasOutcome::Moved));
    assert_eq!(
        repo.head(),
        Ok(Head::Detached(new)),
        "HEAD itself moved, still detached"
    );
}

#[test]
fn a_stale_old_asks_for_a_rebuild_at_once() {
    let (dir, mut repo) = repo();
    // A wait long enough to see one, short enough that no wait at all is the
    // only way to stay under the bound below.
    repo.set_retry_delay(Duration::from_millis(2));
    let stale = commit(&repo, "first");
    let current = commit(&repo, "second");
    let new = repo.write_commit(&object("sealed\n")).expect("writes");
    let head = repo.head().expect("a head");
    let refname = branch(&head);

    // The branch now points at `current`, so `stale` can never win: the answer
    // must come from the first attempt, without any of the retry waits. The
    // attempt count carries that on its own, so no wall-clock bound is needed.
    let outcome = repo.cas_update(&head, &stale, &new).expect("an outcome");

    let CasOutcome::Retry {
        current: tip,
        stderr,
    } = outcome
    else {
        panic!("expected Retry, got {outcome:?}");
    };
    assert_eq!(tip, current, "the tip to rebuild against");
    assert!(!stderr.is_empty(), "git's refusal is carried along");
    assert_eq!(
        repo.update_ref_attempts(),
        1,
        "a rebuild is asked for after exactly one update-ref"
    );
    assert_eq!(repo.head(), Ok(head), "the branch did not move");
    assert_eq!(
        text(&git(dir.path(), &["rev-parse", &refname])),
        format!("{current}\n"),
        "the ref still holds the tip that refused"
    );
}

#[test]
fn a_detached_head_moved_while_sealing_asks_for_a_rebuild() {
    let (dir, mut repo) = repo();
    repo.set_retry_delay(Duration::from_millis(2));
    let first = commit(&repo, "first");
    git(dir.path(), &["checkout", "-q", "--detach", &first]);
    let head = repo.head().expect("a head");
    // Somebody else commits on the detached HEAD, moving it past `first`.
    let second = commit(&repo, "second");
    let new = repo.write_commit(&object("sealed\n")).expect("writes");

    // The seal holds `first` while HEAD is at `second`: the prepared object
    // hangs off a tip that is gone, so the seal has to be rebuilt.
    let outcome = repo.cas_update(&head, &first, &new).expect("an outcome");
    let CasOutcome::Retry { current, .. } = outcome else {
        panic!("expected Retry, got {outcome:?}");
    };
    assert_eq!(current, second);
    assert_eq!(repo.update_ref_attempts(), 1);
    assert_eq!(repo.head(), Ok(Head::Detached(second)));
}

#[test]
fn a_held_lock_is_retried_and_then_gives_up() {
    let (dir, mut repo) = repo();
    repo.set_retry_delay(Duration::from_millis(2));
    let old = commit(&repo, "first");
    let new = repo.write_commit(&object("second\n")).expect("writes");
    let head = repo.head().expect("a head");
    let refname = branch(&head);
    let lock = ref_lock(&repo, &head);
    // A live lock nobody releases: the ref still holds `old`, so the move is
    // recoverable but never becomes possible here.
    std::fs::write(&lock, "").expect("takes the lock");

    let started = Instant::now();
    let outcome = repo.cas_update(&head, &old, &new).expect("an outcome");
    let elapsed = started.elapsed();

    let CasOutcome::GaveUp { stderr } = outcome else {
        panic!("expected GaveUp, got {outcome:?}");
    };
    assert!(
        stderr.to_lowercase().contains("lock"),
        "git's own words are kept: {stderr}"
    );
    assert_eq!(
        repo.update_ref_attempts(),
        3,
        "every attempt is spent before giving up"
    );
    // Two waits of 2 ms and 4 ms: the offsets above cannot be mistaken for a
    // single attempt even on a fast machine, and no upper bound is needed.
    assert!(
        elapsed >= Duration::from_millis(6),
        "the waits between the attempts were spent, took only {elapsed:?}"
    );
    assert_eq!(repo.head(), Ok(head), "the branch did not move");
    assert_eq!(
        text(&git(dir.path(), &["rev-parse", &refname])),
        format!("{old}\n"),
        "the ref still holds the old tip"
    );
    assert!(lock.exists(), "the foreign lock is untouched");
}

#[test]
fn a_lock_released_during_the_retries_still_moves() {
    let (_dir, mut repo) = repo();
    // git itself already waits 100 ms for a held ref lock before it refuses
    // (`core.filesRefLockTimeout`), so a release inside that window would let
    // the first attempt succeed and the test would prove nothing about our own
    // retries. Cutting git's wait short makes the refusal prompt, so the release
    // below lands between the paced attempts: the case the retries exist for.
    git(repo.path(), &["config", "core.filesRefLockTimeout", "10"]);
    // Waits of 120 ms and 240 ms: the first attempt refuses after roughly 50 ms,
    // the release lands at 100 ms, and the second attempt at about 170 ms finds
    // the lock gone.
    repo.set_retry_delay(Duration::from_millis(120));
    let old = commit(&repo, "first");
    let new = repo.write_commit(&object("second\n")).expect("writes");
    let head = repo.head().expect("a head");
    let lock = ref_lock(&repo, &head);
    std::fs::write(&lock, "").expect("takes the lock");

    // A thread stalled well past the release delay must not panic either: git
    // may then win the race and rename the lock away before the `remove_file`
    // here gets to it, so the release only has to be tolerant of nothing left to
    // take.
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        let _ = std::fs::remove_file(&lock);
    });
    let outcome = repo.cas_update(&head, &old, &new).expect("an outcome");
    releaser.join().expect("the releaser finishes");

    assert_eq!(outcome, CasOutcome::Moved);
    // The point of the test: the lock was still held when the move started, so
    // the retry path is what carried it, never the first attempt alone.
    assert!(
        repo.update_ref_attempts() >= 2,
        "the refused first attempt was retried, took {}",
        repo.update_ref_attempts()
    );
    assert_eq!(repo.head(), Ok(Head::Symref(branch(&head))));
}

#[test]
fn a_branch_deleted_while_sealing_gives_up_with_a_message() {
    let (dir, repo) = repo();
    let old = commit(&repo, "first");
    let new = repo.write_commit(&object("sealed\n")).expect("writes");
    let head = repo.head().expect("a head");
    // Deleting the checked-out branch needs a detached HEAD first.
    git(dir.path(), &["checkout", "-q", "--detach", &old]);
    git(dir.path(), &["update-ref", "-d", &branch(&head)]);

    let outcome = repo.cas_update(&head, &old, &new).expect("an outcome");
    let CasOutcome::GaveUp { stderr } = outcome else {
        panic!("expected GaveUp, got {outcome:?}");
    };
    assert!(stderr.contains("no longer exists"), "{stderr}");
    assert!(
        stderr.contains(&branch(&head)),
        "the message names the ref: {stderr}"
    );
}

#[test]
fn a_missing_reflog_does_not_fail_the_move() {
    let (dir, repo) = repo();
    let old = commit(&repo, "first");
    // Turn logging off and drop the log the commit wrote, so the absence is
    // certain: the reflog is best-effort and the move must not depend on it.
    git(dir.path(), &["config", "core.logAllRefUpdates", "false"]);
    let git_dir = text(&git(dir.path(), &["rev-parse", "--absolute-git-dir"]))
        .trim_end()
        .to_owned();
    std::fs::remove_dir_all(Path::new(&git_dir).join("logs")).expect("drops the reflog");
    let new = repo.write_commit(&object("second\n")).expect("writes");
    let head = repo.head().expect("a head");

    assert_eq!(repo.cas_update(&head, &old, &new), Ok(CasOutcome::Moved));
    assert_eq!(
        text(&git(dir.path(), &["rev-parse", &branch(&head)])),
        format!("{new}\n")
    );
    let reflog = git(
        dir.path(),
        &["reflog", "show", "--format=%gs", &branch(&head)],
    );
    assert!(reflog.is_empty(), "no reflog entry is written: {reflog:?}");
}

// --- open and config -----------------------------------------------------

#[test]
fn open_refuses_a_plain_directory() {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    let error = Repo::open(dir.path()).expect_err("not a repository");
    let RepoError::NotARepo { path, stderr } = &error else {
        panic!("expected NotARepo, got {error:?}");
    };
    assert_eq!(path, dir.path());
    assert!(!stderr.is_empty(), "git's own words are kept");
    assert!(
        error.to_string().contains("not a git repository"),
        "{error}"
    );
}

#[test]
fn open_keeps_stderr_of_a_broken_gitfile() {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join(".git"), "not a gitfile\n").expect("writes the gitfile");

    // git says more than "not a repository": the gitfile is malformed, and that
    // is what has to survive into the error.
    let error = Repo::open(dir.path()).expect_err("a broken .git is not openable");
    let RepoError::NotARepo { stderr, .. } = &error else {
        panic!("expected NotARepo, got {error:?}");
    };
    assert!(stderr.contains("gitfile"), "{stderr}");
    assert!(error.to_string().contains("gitfile"), "{error}");
}

#[test]
fn a_config_value_ending_in_a_carriage_return_is_stripped() {
    let (dir, repo) = repo();
    // A real CR inside a quoted value: git prints it, the newline trimming has
    // to take it along.
    let mut config = String::new();
    std::fs::read_to_string(dir.path().join(".git/config"))
        .expect("reads the config")
        .clone_into(&mut config);
    config.push_str("[demo]\n\tvalue = \"x\r\"\r\n");
    std::fs::write(dir.path().join(".git/config"), &config).expect("writes the config");

    assert_eq!(repo.config("demo.value"), Ok(Some("x".to_owned())));
}
