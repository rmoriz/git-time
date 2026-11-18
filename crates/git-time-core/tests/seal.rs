//! The seal, end to end: real repositories, real HTTP stub authorities and the
//! real verifier.
//!
//! Every case runs against authorities minted for the test with `openssl ts
//! -reply`, so the token really answers the request's imprint and nonce, and the
//! pinned root is a throwaway CA made for that test. Nothing here trusts a
//! fixture that was not issued for the seal at hand — except the one test that
//! deliberately serves a token for a *different* imprint.
//!
//! The repository is hermetic: `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM` and
//! `GNUPGHOME` point into temporary directories, so nothing on the machine can
//! steer branches, signing keys or hooks.

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use git_time_core::imprint::{Alg, digest};
use git_time_core::object::CommitObject;
use git_time_core::policy::{ConfigError, OnFailure, Policy, SealDuringRebase, Store};
use git_time_core::repo::{Head, Repo, RepoError};
use git_time_core::seal::{SealError, SealOutcome, SkipReason, seal};
use git_time_core::store::{self, TrailerBlock};
use git_time_core::trust::AnchorStore;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::Duration;

use tempfile::TempDir;

/// The granted FreeTSA response; used only where a token for another imprint is
/// wanted.
const GRANTED_OTHER: &[u8] = include_bytes!("fixtures/resp_granted_freetsa.tsr");
/// The FreeTSA rejection; it refuses the request without needing a stub TSA.
const REJECTED: &[u8] = include_bytes!("fixtures/resp_rejected_freetsa.tsr");
/// The pinned FreeTSA root, for the wrong-imprint test.
const FREETSA_ROOT: &str = include_str!("fixtures/freetsa_root.pem");

const MESSAGE: &str = "seal me\n";

/// Keep the developer's git and gpg configuration out of the test binary.
fn insulate() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: the only writer of these variables in the binary, run before
        // anything spawns git or gpg.
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", "/dev/null");
            std::env::set_var("GIT_CONFIG_SYSTEM", "/dev/null");
        }
    });
}

/// Run git in `dir` with `input` on stdin.
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

/// A temporary repository with one commit, plus that commit's id.
fn repo_with_commit() -> (TempDir, Repo, String) {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    git(dir.path(), &["init", "-q", "-b", "main"]);
    git(dir.path(), &["config", "user.name", "Test"]);
    git(dir.path(), &["config", "user.email", "t@example.com"]);
    let repo = Repo::open(dir.path()).expect("opens the fresh repository");
    let oid = commit(&repo, MESSAGE);
    (dir, repo, oid)
}

/// Make an empty commit with git itself and return its id.
fn commit(repo: &Repo, message: &str) -> String {
    git(
        repo.path(),
        &["commit", "-q", "--allow-empty", "-m", message],
    );
    text(&git(repo.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The parsed object at `oid` and its exact bytes.
fn read(repo: &Repo, oid: &str) -> (CommitObject, Vec<u8>) {
    repo.read_commit(oid).expect("reads the commit")
}

/// The reflog `update-ref` wrote, newest entry first.
fn reflog(dir: &Path) -> String {
    text(&git(dir, &["reflog", "show", "--format=%gs", "main"]))
}

// --- throwaway authorities ----------------------------------------------

/// A throwaway TSA: a CA, a timestamping leaf and the config `openssl ts
/// -reply` needs.
struct Authority {
    dir: TempDir,
    /// The CA certificate, pinned as this authority's anchor.
    ca: PathBuf,
    config: PathBuf,
    counter: AtomicUsize,
}

impl Authority {
    /// Mint the authority. This costs a handful of openssl runs; tests share one
    /// authority between cases where they can.
    fn new() -> Self {
        let dir = TempDir::new().expect("authority dir");
        let path = dir.path();
        let ca_key = path.join("ca-key.pem");
        let ca = path.join("ca.pem");
        let leaf_key = path.join("leaf-key.pem");
        let leaf_csr = path.join("leaf.csr");
        let leaf = path.join("leaf.pem");
        let extensions = path.join("leaf.ext");

        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            &pstr(&ca_key),
            "-out",
            &pstr(&ca),
            "-days",
            "2",
            "-subj",
            "/CN=seal-test-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            &pstr(&leaf_key),
            "-out",
            &pstr(&leaf_csr),
            "-subj",
            "/CN=seal-test-tsa",
        ]);
        std::fs::write(
            &extensions,
            "basicConstraints=critical,CA:FALSE\n\
             keyUsage=critical,digitalSignature\n\
             extendedKeyUsage=critical,timeStamping\n",
        )
        .expect("write leaf extensions");
        openssl(&[
            "x509",
            "-req",
            "-in",
            &pstr(&leaf_csr),
            "-CA",
            &pstr(&ca),
            "-CAkey",
            &pstr(&ca_key),
            "-CAcreateserial",
            "-out",
            &pstr(&leaf),
            "-days",
            "2",
            "-extfile",
            &pstr(&extensions),
        ]);

        std::fs::write(path.join("tsaserial"), "01\n").expect("write serial");
        let config = path.join("tsa.cnf");
        // Absolute paths throughout: `serial` is resolved against the working
        // directory, not against `dir`.
        std::fs::write(
            &config,
            format!(
                "[tsa]\ndefault_tsa = tsa_config1\n\n[tsa_config1]\n\
                 dir = {dir}\nserial = {serial}\nsigner_cert = {leaf}\ncerts = {ca}\n\
                 signer_key = {key}\nsigner_digest = sha256\n\
                 default_policy = 1.2.3.4.1\ndigests = sha256, sha512\n\
                 accuracy = secs:1\nordering = yes\ntsa_name = yes\n\
                 ess_cert_id_chain = yes\n",
                dir = pstr(path),
                serial = pstr(&path.join("tsaserial")),
                leaf = pstr(&leaf),
                ca = pstr(&ca),
                key = pstr(&leaf_key),
            ),
        )
        .expect("write tsa config");

        Self {
            dir,
            ca,
            config,
            counter: AtomicUsize::new(0),
        }
    }

    /// A granted `TimeStampResp` for the DER `query` in front of it.
    ///
    /// This is a real TSA answer: the token's imprint and nonce come from the
    /// query, so a token that verifies could only have been issued for the
    /// request the seal sent.
    fn mint(&self, query: &[u8]) -> Vec<u8> {
        let index = self.counter.fetch_add(1, Ordering::SeqCst);
        let stem = self.dir.path().join(format!("q{index}"));
        let query_file = stem.with_extension("tsq");
        let response_file = stem.with_extension("tsr");
        std::fs::write(&query_file, query).expect("write query");
        openssl(&[
            "ts",
            "-reply",
            "-queryfile",
            &pstr(&query_file),
            "-config",
            &pstr(&self.config),
            "-out",
            &pstr(&response_file),
        ]);
        std::fs::read(&response_file).expect("read response")
    }

    /// A PEM bundle holding only the CA, for a policy anchor.
    fn bundle(&self) -> PathBuf {
        self.ca.clone()
    }
}

/// Run openssl with `args` and assert it succeeded.
fn openssl(args: &[&str]) {
    let output = Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("openssl is available");
    assert!(
        output.status.success(),
        "openssl {args:?} failed: {}",
        text(&output.stderr)
    );
}

fn pstr(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

// --- stub authorities ---------------------------------------------------

/// How a stub answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Mint a real token for the request.
    Grant,
    /// Answer with a granted-then-rejected response.
    Reject,
    /// Answer with the FreeTSA fixture, a token for another imprint.
    WrongImprint,
}

#[derive(Clone)]
struct StubState {
    mode: Mode,
    authority: Option<Arc<Authority>>,
    /// When set, make an empty commit here before answering, so HEAD moves
    /// while the seal is in flight.
    move_head_in: Option<PathBuf>,
    hits: Arc<AtomicUsize>,
}

/// A stub authority on a loopback port.
struct Stub {
    url: String,
    hits: Arc<AtomicUsize>,
}

impl Stub {
    async fn spawn(mode: Mode, authority: Option<Arc<Authority>>) -> Self {
        Self::spawn_beside(mode, authority, None).await
    }

    async fn spawn_beside(
        mode: Mode,
        authority: Option<Arc<Authority>>,
        move_head_in: Option<PathBuf>,
    ) -> Self {
        let hits = Arc::new(AtomicUsize::new(0));
        let state = StubState {
            mode,
            authority,
            move_head_in,
            hits: Arc::clone(&hits),
        };
        let app = Router::new().route("/tsr", post(handle)).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub");
        let addr = listener.local_addr().expect("stub address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://{addr}/tsr"),
            hits,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn handle(State(state): State<StubState>, _headers: HeaderMap, body: Bytes) -> Response {
    state.hits.fetch_add(1, Ordering::SeqCst);
    if let Some(path) = &state.move_head_in {
        let status = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["commit", "-q", "--allow-empty", "-m", "concurrent"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawns git");
        assert!(status.success(), "the concurrent commit failed");
    }
    match state.mode {
        Mode::Grant => {
            let authority = state
                .authority
                .clone()
                .expect("grant mode needs an authority");
            let response = authority.mint(&body);
            ([(CONTENT_TYPE, "application/timestamp-response")], response).into_response()
        }
        Mode::Reject => (StatusCode::OK, REJECTED.to_vec()).into_response(),
        Mode::WrongImprint => (StatusCode::OK, GRANTED_OTHER.to_vec()).into_response(),
    }
}

// --- policy plumbing ----------------------------------------------------

/// Point `id` at `stub` in the repository config, with `anchor` pinned.
fn configure_tsa(repo: &Repo, id: &str, stub: &Stub, anchor: &Path) {
    let path = repo.path();
    git(path, &["config", &format!("time.tsa.{id}.url"), &stub.url]);
    git(
        path,
        &[
            "config",
            &format!("time.tsa.{id}.anchor"),
            &anchor.to_string_lossy(),
        ],
    );
    git(path, &["config", &format!("time.tsa.{id}.alg"), "sha256"]);
    git(path, &["config", &format!("time.tsa.{id}.timeout"), "5s"]);
}

/// Load the policy and tighten the deadline so a hanging case cannot sit for the
/// ten-second default.
fn policy(repo: &Repo) -> Policy {
    let mut policy = Policy::load(repo).expect("policy loads");
    policy.deadline = Duration::from_secs(5);
    policy
}

/// Run a seal with the policy's own sources and anchors.
async fn run(repo: &Repo, policy: &Policy, oid: &str) -> Result<SealOutcome, SealError> {
    seal(repo, policy, policy.backends(), policy.anchors(), oid).await
}

/// The block a sealed object carries.
fn block(object: &CommitObject) -> TrailerBlock {
    let trailer = object
        .pre_image(store::PREFIX)
        .trailer
        .expect("the object carries a trailer");
    store::decode(&trailer)
        .expect("the block decodes")
        .expect("the block is there")
}

/// The header values of `name` in `object`, byte for byte.
fn header<'a>(object: &'a CommitObject, name: &str) -> Option<&'a [u8]> {
    object.header(name)
}

/// Whether `object` still has the headers a rewrite must not touch.
fn assert_headers_preserved(before: &CommitObject, after: &CommitObject) {
    for name in [
        "tree",
        "parent",
        "author",
        "committer",
        "mergetag",
        "encoding",
    ] {
        assert_eq!(
            header(before, name),
            header(after, name),
            "header `{name}` changed"
        );
        // Parents can repeat; compare the whole sequence.
        if name == "parent" {
            let before: Vec<&[u8]> = before
                .headers
                .iter()
                .filter(|(header, _)| header == b"parent")
                .map(|(_, value)| value.as_slice())
                .collect();
            let after: Vec<&[u8]> = after
                .headers
                .iter()
                .filter(|(header, _)| header == b"parent")
                .map(|(_, value)| value.as_slice())
                .collect();
            assert_eq!(before, after, "parents changed");
        }
    }
}

// --- the seal -----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_healthy_tsas_seal_and_preserve_the_object() {
    let (dir, repo, oid) = repo_with_commit();
    let first = Arc::new(Authority::new());
    let second = Arc::new(Authority::new());
    let one = Stub::spawn(Mode::Grant, Some(Arc::clone(&first))).await;
    let two = Stub::spawn(Mode::Grant, Some(Arc::clone(&second))).await;
    configure_tsa(&repo, "one", &one, &first.bundle());
    configure_tsa(&repo, "two", &two, &second.bundle());
    // The second authority stamps a SHA-512 imprint, so the block records the
    // per-authority algorithm next to the SHA-256 one the store itself uses.
    git(repo.path(), &["config", "time.tsa.two.alg", "sha512"]);

    let policy = policy(&repo);
    let (before, before_bytes) = read(&repo, &oid);
    let before_pre = before.pre_image(store::PREFIX).bytes;
    let pre = digest(Alg::Sha256, &before_pre);

    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed {
        oid: new_oid,
        ok,
        total,
    } = outcome
    else {
        panic!("expected a seal, got {outcome:?}");
    };
    assert_eq!((ok, total), (2, 2));
    assert_eq!(one.hits(), 1);
    assert_eq!(two.hits(), 1);

    // the ref moved to the new object
    let head = text(&git(dir.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned();
    assert_eq!(head, new_oid);
    assert_eq!(reflog(dir.path()).lines().next(), Some("rfc3161 seal"));

    let (after, after_bytes) = read(&repo, &new_oid);
    assert_headers_preserved(&before, &after);
    assert!(after.message.starts_with(MESSAGE.as_bytes()));

    // the rewrite is byte-exact around the trailer
    let pre_after = after.pre_image(store::PREFIX);
    assert_eq!(pre_after.bytes, before.pre_image(store::PREFIX).bytes);
    assert_eq!(
        pre_after.bytes,
        CommitObject::parse(&before_bytes)
            .expect("parses")
            .pre_image(store::PREFIX)
            .bytes
    );

    let block = block(&after);
    assert_eq!(block.imprint, block_imprint(&pre));
    // `Object` names the commit the timestamped bytes hash to, which is also
    // what the block would name for any unstamped copy of these bytes.
    assert_eq!(
        block.object.as_deref(),
        Some(
            repo.hash_commit(&before_pre)
                .expect("hashes the pre-image")
                .as_str()
        ),
        "the block names the timestamped bytes, not the input oid"
    );
    assert_eq!(block.tokens.len(), 2);
    assert!(block.failures.is_empty(), "{:?}", block.failures);
    let ids: Vec<&str> = block.tokens.iter().map(|token| token.id.as_str()).collect();
    assert_eq!(ids, ["one", "two"]);
    assert_eq!(block.tokens[0].alg, Alg::Sha256);
    assert_eq!(block.tokens[1].alg, Alg::Sha512);
    assert!(after_bytes.len() > before_bytes.len());
    // The input was unsigned, so the rewrite must not invent a signature.
    assert!(header(&after, "gpgsig").is_none(), "{after:?}");
    assert!(header(&after, "gpgsig-sha256").is_none(), "{after:?}");

    // A second seal of the same object is a no-op.
    assert_eq!(
        run(&repo, &policy, &new_oid)
            .await
            .map_err(|error| error.to_string()),
        Ok(SealOutcome::Skipped(SkipReason::AlreadySealed))
    );
}

/// The imprint a digest is stored as.
fn block_imprint(bytes: &[u8]) -> git_time_core::imprint::Digest {
    git_time_core::imprint::Digest {
        alg: Alg::Sha256,
        bytes: bytes.to_vec(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_quorum_stores_the_failures_and_stays_under_quorum() {
    let (_dir, repo, oid) = repo_with_commit();
    let healthy = Arc::new(Authority::new());
    let good = Stub::spawn(Mode::Grant, Some(Arc::clone(&healthy))).await;
    let bad = Stub::spawn(Mode::Reject, None).await;
    configure_tsa(&repo, "good", &good, &healthy.bundle());
    configure_tsa(&repo, "bad", &bad, &healthy.bundle());

    let mut policy = policy(&repo);
    policy.required = 2;
    let (before, _) = read(&repo, &oid);

    let outcome = run(&repo, &policy, &oid).await.expect("writes evidence");
    let SealOutcome::UnderQuorum {
        oid: new_oid,
        failures,
    } = outcome
    else {
        panic!("expected an under-quorum seal, got {outcome:?}");
    };
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].id, "bad");
    assert!(failures[0].reason.contains("reject"), "{failures:?}");

    let (after, _) = read(&repo, &new_oid);
    assert_headers_preserved(&before, &after);
    let block = block(&after);
    assert_eq!(block.tokens.len(), 1);
    assert_eq!(block.failures.len(), 1);
    assert_eq!(block.failures[0].id, "bad");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_answer_meets_a_quorum_of_one_even_if_the_other_rejects() {
    let (_dir, repo, oid) = repo_with_commit();
    let healthy = Arc::new(Authority::new());
    let good = Stub::spawn(Mode::Grant, Some(Arc::clone(&healthy))).await;
    let bad = Stub::spawn(Mode::Reject, None).await;
    configure_tsa(&repo, "good", &good, &healthy.bundle());
    configure_tsa(&repo, "bad", &bad, &healthy.bundle());

    let policy = policy(&repo);
    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed {
        oid: new_oid,
        ok,
        total,
    } = outcome
    else {
        panic!("expected a seal, got {outcome:?}");
    };
    assert_eq!((ok, total), (1, 2));

    let (after, _) = read(&repo, &new_oid);
    let block = block(&after);
    assert_eq!(block.tokens.len(), 1);
    assert_eq!(block.tokens[0].id, "good");
    assert_eq!(block.failures.len(), 1);
    assert_eq!(block.failures[0].id, "bad");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_answer_still_writes_a_block_of_failures() {
    let (_dir, repo, oid) = repo_with_commit();
    let anchor = Arc::new(Authority::new());
    let one = Stub::spawn(Mode::Reject, None).await;
    let two = Stub::spawn(Mode::Reject, None).await;
    configure_tsa(&repo, "one", &one, &anchor.bundle());
    configure_tsa(&repo, "two", &two, &anchor.bundle());

    let policy = policy(&repo);
    let (before, _) = read(&repo, &oid);
    let outcome = run(&repo, &policy, &oid).await.expect("writes a block");
    let SealOutcome::UnderQuorum {
        oid: new_oid,
        failures,
    } = outcome
    else {
        panic!("expected an under-quorum seal, got {outcome:?}");
    };
    assert_eq!(failures.len(), 2);

    let (after, _) = read(&repo, &new_oid);
    assert_headers_preserved(&before, &after);
    let trailer = text(&after.pre_image(store::PREFIX).trailer.expect("trailer"));
    let block = block(&after);
    assert!(block.tokens.is_empty());
    assert_eq!(block.failures.len(), 2);
    let lines: Vec<&str> = trailer.lines().collect();
    assert_eq!(lines.len(), 4, "{trailer}");
    assert!(lines[0].starts_with("X-RFC3161-Imprint: "));
    assert!(lines[1].starts_with("X-RFC3161-Object: "));
    assert!(lines[2].starts_with("X-RFC3161-Fail: id=one; reason="));
    assert!(lines[3].starts_with("X-RFC3161-Fail: id=two; reason="));
    // Reasons are prose upstream and single fields here: no spaces, no `;`.
    assert!(
        lines[2]
            .trim_start_matches("X-RFC3161-Fail: id=one; reason=")
            .bytes()
            .all(|byte| byte != b' ' && byte != b';'),
        "{trailer}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_answer_and_no_failure_recording_the_object_is_untouched() {
    let (dir, repo, oid) = repo_with_commit();
    let anchor = Arc::new(Authority::new());
    let one = Stub::spawn(Mode::Reject, None).await;
    configure_tsa(&repo, "one", &one, &anchor.bundle());

    let mut policy = policy(&repo);
    policy.record_failures = false;
    let (before, before_bytes) = read(&repo, &oid);

    assert_eq!(
        run(&repo, &policy, &oid)
            .await
            .map_err(|error| error.to_string()),
        Ok(SealOutcome::Skipped(SkipReason::NoTokensRecorded))
    );
    let head = text(&git(dir.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned();
    assert_eq!(head, oid);
    let (after, after_bytes) = read(&repo, &oid);
    assert_eq!(before, after);
    assert_eq!(before_bytes, after_bytes);
    assert!(before.pre_image(store::PREFIX).trailer.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_failure_recording_a_verified_token_leaves_no_fail_line() {
    let (_dir, repo, oid) = repo_with_commit();
    let healthy = Arc::new(Authority::new());
    let good = Stub::spawn(Mode::Grant, Some(Arc::clone(&healthy))).await;
    let bad = Stub::spawn(Mode::Reject, None).await;
    configure_tsa(&repo, "good", &good, &healthy.bundle());
    configure_tsa(&repo, "bad", &bad, &healthy.bundle());

    let mut policy = policy(&repo);
    policy.record_failures = false;
    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed {
        oid: new_oid, ok, ..
    } = outcome
    else {
        panic!("expected a seal, got {outcome:?}");
    };
    assert_eq!(ok, 1, "the healthy authority still sealed");

    let (after, _) = read(&repo, &new_oid);
    let trailer = text(&after.pre_image(store::PREFIX).trailer.expect("trailer"));
    assert!(
        !trailer.contains("X-RFC3161-Fail:"),
        "no `Fail` line is written: {trailer}"
    );
    assert_eq!(block(&after).failures.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_for_another_imprint_is_a_failure_not_a_token() {
    let (_dir, repo, oid) = repo_with_commit();
    let stub = Stub::spawn(Mode::WrongImprint, None).await;
    let anchors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/freetsa_root.pem");
    configure_tsa(&repo, "freetsa", &stub, &anchors);

    let policy = policy(&repo);
    let outcome = run(&repo, &policy, &oid).await.expect("writes failures");
    let SealOutcome::UnderQuorum {
        oid: new_oid,
        failures,
    } = outcome
    else {
        panic!("expected an under-quorum seal, got {outcome:?}");
    };
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].reason, "invalid-imprint");

    let (after, _) = read(&repo, &new_oid);
    let block = block(&after);
    assert!(block.tokens.is_empty());
    assert_eq!(block.failures.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_anchor_costs_only_its_own_authority() {
    let (_dir, repo, oid) = repo_with_commit();
    let healthy = Arc::new(Authority::new());
    let good = Stub::spawn(Mode::Grant, Some(Arc::clone(&healthy))).await;
    let unpinned = Stub::spawn(Mode::Grant, Some(Arc::clone(&healthy))).await;
    configure_tsa(&repo, "good", &good, &healthy.bundle());
    let missing = healthy.dir.path().join("absent.pem");
    configure_tsa(&repo, "unpinned", &unpinned, &missing);

    // The policy is readable although one anchor is not: that gap is the seal's
    // business, not the loader's.
    let policy = policy(&repo);
    assert!(policy.anchors().anchor("unpinned").is_none());

    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed {
        oid: new_oid,
        ok,
        total,
    } = outcome
    else {
        panic!("expected a seal, got {outcome:?}");
    };
    assert_eq!((ok, total), (1, 2));
    assert_eq!(good.hits(), 1);
    assert_eq!(unpinned.hits(), 0, "an unverifiable TSA is not asked");

    let (after, _) = read(&repo, &new_oid);
    let block = block(&after);
    assert_eq!(block.tokens.len(), 1);
    assert_eq!(block.tokens[0].id, "good");
    // One `Fail` for the missing anchor, naming it, and it survives the wire
    // format: no bogus retry, no silent gap.
    assert_eq!(block.failures.len(), 1, "{:?}", block.failures);
    assert_eq!(block.failures[0].id, "unpinned");
    assert!(
        block.failures[0].reason.contains("absent.pem"),
        "{:?}",
        block.failures
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unparseable_anchor_costs_only_its_own_authority() {
    let (_dir, repo, oid) = repo_with_commit();
    let healthy = Arc::new(Authority::new());
    let good = Stub::spawn(Mode::Grant, Some(Arc::clone(&healthy))).await;
    let prose_tsa = Stub::spawn(Mode::Grant, Some(Arc::clone(&healthy))).await;
    configure_tsa(&repo, "good", &good, &healthy.bundle());
    let prose = healthy.dir.path().join("prose.pem");
    std::fs::write(&prose, "this is prose, not a certificate\n").expect("write prose");
    configure_tsa(&repo, "prose", &prose_tsa, &prose);

    let policy = policy(&repo);
    assert!(policy.anchors().anchor("prose").is_none());

    // An unparseable bundle is handled like a missing one: its authority fails,
    // the healthy one still seals.
    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed {
        oid: new_oid, ok, ..
    } = outcome
    else {
        panic!("expected a seal, got {outcome:?}");
    };
    assert_eq!(ok, 1);
    assert_eq!(prose_tsa.hits(), 0);

    let (after, _) = read(&repo, &new_oid);
    let block = block(&after);
    assert_eq!(block.tokens.len(), 1);
    assert_eq!(block.failures.len(), 1, "{:?}", block.failures);
    assert_eq!(block.failures[0].id, "prose");
    assert!(
        block.failures[0].reason.contains("prose.pem"),
        "{:?}",
        block.failures
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_usable_anchor_the_commit_is_left_alone() {
    let (dir, repo, oid) = repo_with_commit();
    let authority = Arc::new(Authority::new());
    let one = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    let two = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    let missing = authority.dir.path().join("absent.pem");
    configure_tsa(&repo, "one", &one, &missing);
    configure_tsa(&repo, "two", &two, &missing);

    let policy = policy(&repo);
    let (before, before_bytes) = read(&repo, &oid);
    let error = run(&repo, &policy, &oid)
        .await
        .expect_err("nothing to verify");
    assert!(matches!(error, SealError::NoUsableAnchor), "{error:?}");

    assert_eq!(one.hits(), 0, "no authority is asked");
    assert_eq!(two.hits(), 0);
    let head = text(&git(dir.path(), &["rev-parse", "HEAD"]));
    assert_eq!(head.trim(), oid, "the ref did not move");
    let (after, after_bytes) = read(&repo, &oid);
    assert_eq!(before, after);
    assert_eq!(before_bytes, after_bytes);
    assert!(before.pre_image(store::PREFIX).trailer.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_head_that_moves_during_the_seal_leaves_the_other_commit_alone() {
    let (dir, repo, oid) = repo_with_commit();
    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn_beside(
        Mode::Grant,
        Some(Arc::clone(&authority)),
        Some(dir.path().to_path_buf()),
    )
    .await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());

    let policy = policy(&repo);
    let error = run(&repo, &policy, &oid).await.expect_err("HEAD moved");
    let SealError::HeadMoved(current) = error else {
        panic!("expected HeadMoved, got {error:?}");
    };

    let head = text(&git(dir.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned();
    assert_eq!(head, current);
    assert_ne!(head, oid);
    // The concurrent commit is exactly as it was made: no trailer, no token.
    let (other, _) = read(&repo, &head);
    assert!(other.pre_image(store::PREFIX).trailer.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_policy_skips_the_seal() {
    let (_dir, repo, oid) = repo_with_commit();
    let mut policy = policy(&repo);
    policy.enabled = false;

    assert_eq!(
        run(&repo, &policy, &oid)
            .await
            .map_err(|error| error.to_string()),
        Ok(SealOutcome::Skipped(SkipReason::Disabled))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blob_is_not_a_commit_but_an_absent_object_is_an_error() {
    let (dir, repo, _oid) = repo_with_commit();
    let blob =
        text(&git_output(dir.path(), &["hash-object", "-w", "--stdin"], b"blob body").stdout)
            .trim()
            .to_owned();
    let mut policy = policy(&repo);
    policy.enabled = true;
    assert_eq!(
        run(&repo, &policy, &blob)
            .await
            .map_err(|error| error.to_string()),
        Ok(SealOutcome::Skipped(SkipReason::NotACommit))
    );

    // An id git has no object for is not a wrong type: the repository could not
    // answer, so a skip would hide a real problem.
    let missing = "0123456789012345678901234567890123456789";
    let error = run(&repo, &policy, missing)
        .await
        .expect_err("a missing object is no skip");
    assert!(
        matches!(error, SealError::Repo(RepoError::Git { .. })),
        "{error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn note_storage_writes_the_block_beside_the_commit() {
    let (_dir, repo, oid) = repo_with_commit();
    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());

    let mut policy = policy(&repo);
    policy.store = Store::Note;
    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed { oid: new_oid, .. } = outcome else {
        panic!("expected a seal, got {outcome:?}");
    };

    // The note carries the whole block, tokens and all.
    let note = git(repo.path(), &["notes", "--ref=rfc3161", "show", &new_oid]);
    let note = store::decode(&note)
        .expect("the note decodes")
        .expect("the note carries a block");
    let (sealed, _) = read(&repo, &new_oid);
    let pre = sealed.pre_image(store::PREFIX).bytes;
    assert_eq!(
        note.object.as_deref(),
        Some(
            repo.hash_commit(&pre)
                .expect("hashes the pre-image")
                .as_str()
        )
    );
    assert_eq!(note.tokens.len(), 1);
    assert_eq!(note.tokens[0].id, "one");

    // The commit trailer keeps only the imprint.
    let (after, _) = read(&repo, &new_oid);
    let trailer = text(&after.pre_image(store::PREFIX).trailer.expect("trailer"));
    let lines: Vec<&str> = trailer.lines().collect();
    assert_eq!(lines.len(), 1, "{trailer}");
    assert!(lines[0].starts_with("X-RFC3161-Imprint: sha256:"));
    let imprint = git_time_core::imprint::Digest::parse(
        lines[0]
            .strip_prefix("X-RFC3161-Imprint: ")
            .expect("imprint line"),
    )
    .expect("imprint parses");
    assert_eq!(
        imprint.bytes,
        digest(
            Alg::Sha256,
            &CommitObject::parse(&git(repo.path(), &["cat-file", "commit", &new_oid]))
                .expect("parses")
                .pre_image(store::PREFIX)
                .bytes
        )
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_storage_writes_the_block_and_the_trailer() {
    let (_dir, repo, oid) = repo_with_commit();
    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());

    let mut policy = policy(&repo);
    policy.store = Store::Both;
    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed { oid: new_oid, .. } = outcome else {
        panic!("expected a seal, got {outcome:?}");
    };

    let note = git(repo.path(), &["notes", "--ref=rfc3161", "show", &new_oid]);
    assert_eq!(
        store::decode(&note)
            .expect("decodes")
            .expect("block")
            .tokens
            .len(),
        1
    );
    let (after, _) = read(&repo, &new_oid);
    assert_eq!(block(&after).tokens.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_amended_sealed_commit_is_resealed_without_duplicating_the_block() {
    let (dir, repo, oid) = repo_with_commit();
    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());

    let policy = policy(&repo);
    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed { oid: sealed, .. } = outcome else {
        panic!("expected a seal, got {outcome:?}");
    };

    // `--amend` carries the old block along, but not to a matching object id.
    // A different author date changes the bytes while the message, block
    // included, is carried over verbatim.
    git(
        dir.path(),
        &[
            "commit",
            "-q",
            "--amend",
            "--allow-empty",
            "--no-edit",
            "--date",
            "2026-01-02T03:04:05Z",
        ],
    );
    let amended = text(&git(dir.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned();
    assert_ne!(amended, sealed);
    let (before, _) = read(&repo, &amended);
    assert!(
        before.pre_image(store::PREFIX).trailer.is_some(),
        "stale block"
    );

    let outcome = run(&repo, &policy, &amended).await.expect("re-seals");
    let SealOutcome::Sealed { oid: fresh, ok, .. } = outcome else {
        panic!("expected a re-seal, got {outcome:?}");
    };
    assert_eq!(ok, 1);

    let (after, _) = read(&repo, &fresh);
    // One block, not two, and it names the amended pre-image.
    let trailer = text(&after.pre_image(store::PREFIX).trailer.expect("trailer"));
    assert_eq!(
        trailer.matches("X-RFC3161-Imprint: ").count(),
        1,
        "{trailer}"
    );
    assert!(after.message.starts_with(MESSAGE.as_bytes()), "{after:?}");
    let block = block(&after);
    assert_eq!(block.tokens.len(), 1);
    assert_eq!(
        block.imprint.bytes,
        digest(Alg::Sha256, &after.pre_image(store::PREFIX).bytes)
    );
}

// --- policy -------------------------------------------------------------

#[test]
fn policy_parses_every_key() {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    git(dir.path(), &["init", "-q", "-b", "main"]);
    let repo = Repo::open(dir.path()).expect("opens the repository");
    let anchor = dir.path().join("anchor.pem");
    std::fs::write(&anchor, FREETSA_ROOT).expect("write anchor");

    for (key, value) in [
        ("time.required", "2"),
        ("time.deadline", "2s"),
        ("time.on-failure", "fail"),
        ("time.gate", "pre-commit"),
        ("time.store", "note"),
        ("time.seal-during-rebase", "tip"),
        ("time.record-failures", "false"),
        ("time.enabled", "false"),
        ("time.max-trailer-bytes", "1024"),
        ("time.tsa.freetsa.url", "http://127.0.0.1:1/tsr"),
        ("time.tsa.freetsa.anchor", &anchor.to_string_lossy()),
        ("time.tsa.freetsa.alg", "sha512"),
        ("time.tsa.freetsa.policy", "1.2.3.4.1"),
        ("time.tsa.freetsa.timeout", "750ms"),
    ] {
        git(dir.path(), &["config", key, value]);
    }

    let policy = Policy::load(&repo).expect("policy loads");
    assert_eq!(policy.required, 2);
    assert_eq!(policy.deadline, Duration::from_secs(2));
    assert_eq!(policy.on_failure, OnFailure::Fail);
    assert_eq!(policy.gate, git_time_core::policy::Gate::PreCommit);
    assert_eq!(policy.store, Store::Note);
    assert_eq!(policy.seal_during_rebase, SealDuringRebase::Tip);
    assert!(!policy.record_failures);
    assert!(!policy.enabled);
    assert_eq!(policy.max_trailer_bytes, 1024);
    assert_eq!(policy.tsas.len(), 1);
    let tsa = &policy.tsas[0];
    assert_eq!(tsa.id, "freetsa");
    assert_eq!(tsa.url, "http://127.0.0.1:1/tsr");
    assert_eq!(tsa.anchor, anchor);
    assert_eq!(tsa.alg, Alg::Sha512);
    assert_eq!(tsa.policy.as_deref(), Some("1.2.3.4.1"));
    assert_eq!(tsa.timeout, Duration::from_millis(750));
    assert_eq!(policy.backends().len(), 1);
    assert_eq!(policy.backends()[0].id(), "freetsa");
    assert_eq!(policy.anchors().len(), 1);
}

#[test]
fn policy_rejects_a_non_numeric_quorum() {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    git(dir.path(), &["init", "-q", "-b", "main"]);
    let repo = Repo::open(dir.path()).expect("opens the repository");
    git(dir.path(), &["config", "time.required", "two"]);

    let error = Policy::load(&repo).expect_err("`two` is not a count");
    assert!(error.to_string().contains("time.required"), "{error}");
    assert!(error.to_string().contains("two"), "{error}");
}

#[test]
fn policy_rejects_an_unknown_enum_value_per_key() {
    insulate();
    // One repository and one bad key per case: a permissive enum in one key
    // cannot be hidden behind a rejection in another.
    for (key, value, expected) in [
        ("time.on-failure", "fial", "`warn` or `fail`"),
        ("time.gate", "mid-commit", "`post-commit` or `pre-commit`"),
        ("time.store", "database", "`trailer`, `note` or `both`"),
        (
            "time.seal-during-rebase",
            "sometimes",
            "`all`, `tip` or `off`",
        ),
    ] {
        let dir = TempDir::new().expect("temp dir");
        git(dir.path(), &["init", "-q", "-b", "main"]);
        let repo = Repo::open(dir.path()).expect("opens the repository");
        git(dir.path(), &["config", key, value]);

        let error = Policy::load(&repo).expect_err("an unknown enum must not default");
        let message = error.to_string();
        assert!(message.contains(key), "the error names the key: {message}");
        assert!(
            message.contains(value),
            "the error names the value: {message}"
        );
        assert!(
            message.contains(expected),
            "the error states the vocabulary: {message}"
        );
        assert!(matches!(error, ConfigError::Invalid { .. }), "{error:?}");
    }
}

#[test]
fn policy_rejects_a_tsa_without_url_or_anchor() {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    git(dir.path(), &["init", "-q", "-b", "main"]);
    let repo = Repo::open(dir.path()).expect("opens the repository");

    git(
        dir.path(),
        &["config", "time.tsa.broken.url", "http://127.0.0.1:1"],
    );
    let error = Policy::load(&repo).expect_err("the TSA has no anchor");
    assert!(error.to_string().contains("anchor"), "{error}");
}

/// A configured anchor that does not exist costs its own authority only: the
/// policy still loads and names the bundle, so the seal can record it.
#[test]
fn a_missing_anchor_is_recorded_per_authority_not_fatal() {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    git(dir.path(), &["init", "-q", "-b", "main"]);
    let repo = Repo::open(dir.path()).expect("opens the repository");
    let anchor = dir.path().join("anchor.pem");
    std::fs::write(&anchor, FREETSA_ROOT).expect("write anchor");

    for (id, path) in [
        ("good", anchor.clone()),
        ("broken", PathBuf::from("/nope.pem")),
    ] {
        git(
            dir.path(),
            &[
                "config",
                &format!("time.tsa.{id}.url"),
                "http://127.0.0.1:1",
            ],
        );
        git(
            dir.path(),
            &[
                "config",
                &format!("time.tsa.{id}.anchor"),
                &path.to_string_lossy(),
            ],
        );
    }

    let policy = Policy::load(&repo).expect("a missing anchor is not a config error");
    assert_eq!(policy.backends().len(), 2);
    assert_eq!(policy.anchors().len(), 1);
    assert!(policy.anchors().anchor("good").is_some());
    assert!(policy.anchor_failure("good").is_none());
    let reason = policy.anchor_failure("broken").expect("recorded");
    assert!(reason.contains("/nope.pem"), "{reason}");
}

// --- signature ----------------------------------------------------------

/// A throwaway OpenPGP key, generated once per test binary.
fn signing_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| {
        insulate();
        let home = TempDir::new().expect("gpg home");
        // SAFETY: set once, before the only gpg runs of this binary.
        unsafe { std::env::set_var("GNUPGHOME", home.path()) };
        // The home must outlive every test, so it is leaked deliberately.
        std::mem::forget(home);

        openssl_gpg(&[
            "--batch",
            "--passphrase",
            "",
            "--quick-gen-key",
            "Seal Test <seal@example.com>",
            "rsa2048",
            "sign",
            "never",
        ]);
        let listing = text(
            &Command::new("gpg")
                .args(["--list-keys", "--with-colons"])
                .output()
                .expect("gpg lists keys")
                .stdout,
        );
        let fingerprint = listing
            .lines()
            .find_map(|line| {
                line.strip_prefix("fpr:::::::::")
                    .and_then(|rest| rest.split(':').next())
            })
            .expect("a freshly generated key has a fingerprint")
            .to_owned();

        // Warm the agent so the first real signature does not race key lookup.
        openssl_gpg(&[
            "--batch",
            "--armor",
            "--detach-sign",
            "-u",
            &fingerprint,
            "-o",
            "-",
        ]);
        fingerprint
    })
}

fn openssl_gpg(args: &[&str]) {
    let status = Command::new("gpg")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("gpg is available");
    assert!(status.success(), "gpg {args:?} failed");
}

/// Configure signing and make an empty signed commit; its id is returned.
fn signed_commit(repo: &Repo, message: &str) -> String {
    let fingerprint = signing_key();
    git(repo.path(), &["config", "gpg.format", "openpgp"]);
    git(repo.path(), &["config", "gpg.program", "gpg"]);
    git(repo.path(), &["config", "user.signingkey", fingerprint]);
    git(
        repo.path(),
        &["commit", "-q", "--allow-empty", "-S", "-m", message],
    );
    old_of(repo)
}

/// A repository whose tip is a signed commit, plus that commit's id.
fn signed_repo() -> (TempDir, Repo, String) {
    let (dir, repo, _) = repo_with_commit();
    let oid = signed_commit(&repo, "signed");
    (dir, repo, oid)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_commit_is_sealed_and_still_verifies() {
    let (dir, repo, _) = repo_with_commit();
    let fingerprint = signing_key();
    git(dir.path(), &["config", "gpg.format", "openpgp"]);
    git(dir.path(), &["config", "gpg.program", "gpg"]);
    git(dir.path(), &["config", "user.signingkey", fingerprint]);
    git(
        dir.path(),
        &["commit", "-q", "--allow-empty", "-S", "-m", "signed"],
    );
    let oid = text(&git(dir.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned();

    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());

    let policy = policy(&repo);
    let (before, _) = read(&repo, &oid);
    assert!(before.header("gpgsig").is_some(), "the fixture is signed");
    let pre = before.pre_image(store::PREFIX);

    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed { oid: new_oid, .. } = outcome else {
        panic!("expected a seal, got {outcome:?}");
    };

    let (after, _) = read(&repo, &new_oid);
    assert!(after.header("gpgsig").is_some(), "the signature is back");
    assert_headers_preserved(&before, &after);
    // The signature covers the trailer, the token imprint does not.
    assert_eq!(after.pre_image(store::PREFIX).bytes, pre.bytes);

    // Both directions still hold: git accepts the signature, and the token
    // answers the pre-image the trailer claims.
    let verified = git_output(dir.path(), &["verify-commit", &new_oid], b"");
    assert!(
        verified.status.success(),
        "verify-commit failed: {}",
        text(&verified.stderr)
    );
    let block = block(&after);
    assert_eq!(
        block.imprint.bytes,
        digest(Alg::Sha256, &after.pre_image(store::PREFIX).bytes)
    );
    assert_eq!(block.tokens.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sha256_commit_keeps_its_gpgsig_sha256_header() {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    git(
        dir.path(),
        &["init", "-q", "-b", "main", "--object-format=sha256"],
    );
    git(dir.path(), &["config", "user.name", "Test"]);
    git(dir.path(), &["config", "user.email", "t@example.com"]);
    let repo = Repo::open(dir.path()).expect("opens the fresh repository");
    let oid = signed_commit(&repo, "signed");

    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());
    let policy = policy(&repo);

    let (before, _) = read(&repo, &oid);
    assert!(header(&before, "gpgsig-sha256").is_some(), "fixture");
    assert!(header(&before, "gpgsig").is_none(), "fixture");

    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed { oid: new_oid, .. } = outcome else {
        panic!("expected a seal, got {outcome:?}");
    };

    // An "always `gpgsig`" regression passes a SHA-1 repository and fails here.
    let (after, _) = read(&repo, &new_oid);
    assert!(header(&after, "gpgsig-sha256").is_some(), "{after:?}");
    assert!(header(&after, "gpgsig").is_none(), "{after:?}");
    assert_headers_preserved(&before, &after);
    let verified = git_output(dir.path(), &["verify-commit", &new_oid], b"");
    assert!(
        verified.status.success(),
        "verify-commit failed: {}",
        text(&verified.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_signature_aborts_the_seal_and_keeps_the_commit() {
    let (dir, repo, _) = repo_with_commit();
    let fingerprint = signing_key();
    git(dir.path(), &["config", "gpg.format", "openpgp"]);
    git(dir.path(), &["config", "gpg.program", "gpg"]);
    git(dir.path(), &["config", "user.signingkey", fingerprint]);
    git(
        dir.path(),
        &["commit", "-q", "--allow-empty", "-S", "-m", "signed"],
    );
    let oid = text(&git(dir.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned();

    // Signing again is made to fail: the re-sign takes the key from the
    // existing signature, so the configured key is not what breaks.
    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());
    let policy = policy(&repo);
    let (_, before_bytes) = read(&repo, &oid);

    git(dir.path(), &["config", "gpg.program", "false"]);
    let error = run(&repo, &policy, &oid).await.expect_err("signing fails");
    assert!(matches!(error, SealError::Sign(_)), "{error:?}");

    let head = text(&git(dir.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned();
    assert_eq!(head, oid);
    let (_, after_bytes) = read(&repo, &oid);
    assert_eq!(before_bytes, after_bytes);
}

// --- the policy's own refusals ------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_head_must_point_at_the_object_being_sealed() {
    let (_dir, repo, _oid) = repo_with_commit();
    let other = commit(&repo, "other");
    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());
    let policy = policy(&repo);
    let old = text(&git_output(repo.path(), &["rev-parse", "HEAD~1"], b"").stdout)
        .trim()
        .to_owned();

    assert_eq!(
        run(&repo, &policy, &old)
            .await
            .map_err(|error| error.to_string()),
        Ok(SealOutcome::Skipped(SkipReason::HeadMoved))
    );
    assert_eq!(other, old_of(&repo), "HEAD did not move");
}

fn old_of(repo: &Repo) -> String {
    text(&git(repo.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detached_head_is_sealed_at_itself() {
    let (dir, repo, oid) = repo_with_commit();
    git(dir.path(), &["checkout", "-q", "--detach", &oid]);
    assert_eq!(repo.head(), Ok(Head::Detached(oid.clone())));

    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());
    let policy = policy(&repo);

    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    assert!(matches!(outcome, SealOutcome::Sealed { .. }), "{outcome:?}");
    assert!(
        matches!(repo.head(), Ok(Head::Detached(_))),
        "still detached"
    );
}

/// The anchors type is used through the policy; keep the import honest.
#[test]
fn an_empty_anchor_store_trusts_nothing() {
    let empty = AnchorStore::load(&[]).expect("an empty store loads");
    assert!(empty.is_empty());
}

/// `Vec<T>` clones used by the outcome must stay comparable by value, and the
/// invariant error must say how the bytes differ.
#[test]
fn seal_errors_are_displayable() {
    let error = SealError::HeadMoved("abc".to_owned());
    assert!(error.to_string().contains("abc"));
    let error = SealError::RefUnmoved("locked".to_owned());
    assert!(error.to_string().contains("locked"));
    let error = SealError::Invariant {
        detail:
            "the rebuilt object is 2 bytes longer than the pre-image, first difference at byte 7"
                .to_owned(),
    };
    let message = error.to_string();
    assert!(message.contains("2 bytes longer"), "{message}");
    assert!(message.contains("byte 7"), "{message}");
    let _ = Mutex::new(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_signed_commit_is_not_resealed() {
    let (_dir, repo, _) = signed_repo();
    let oid = old_of(&repo);

    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());
    let policy = policy(&repo);

    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed { oid: sealed, .. } = outcome else {
        panic!("expected a seal, got {outcome:?}");
    };
    let (after, sealed_bytes) = read(&repo, &sealed);
    // The writer named the timestamped bytes, so the second run must recognise
    // its own work even under a signature.
    assert_eq!(
        block(&after).object.as_deref(),
        Some(
            repo.hash_commit(&after.pre_image(store::PREFIX).bytes)
                .expect("hashes the pre-image")
                .as_str()
        )
    );

    let second = run(&repo, &policy, &sealed)
        .await
        .map_err(|error| error.to_string());
    println!("second seal on a signed commit = {second:?}");
    assert_eq!(second, Ok(SealOutcome::Skipped(SkipReason::AlreadySealed)));
    assert_eq!(old_of(&repo), sealed, "the ref did not move again");
    let (again, again_bytes) = read(&repo, &sealed);
    assert_eq!(again_bytes, sealed_bytes, "the object is byte-identical");
    assert_eq!(block(&again).tokens.len(), 1, "no second token was added");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_note_sealed_commit_is_not_resealed() {
    let (_dir, repo, oid) = repo_with_commit();
    let authority = Arc::new(Authority::new());
    let stub = Stub::spawn(Mode::Grant, Some(Arc::clone(&authority))).await;
    configure_tsa(&repo, "one", &stub, &authority.bundle());
    let mut policy = policy(&repo);
    policy.store = Store::Note;

    let outcome = run(&repo, &policy, &oid).await.expect("seals");
    let SealOutcome::Sealed { oid: sealed, .. } = outcome else {
        panic!("expected a seal, got {outcome:?}");
    };
    let notes = |oid: &str| {
        text(&git(repo.path(), &["notes", "--ref=rfc3161", "list"]))
            .lines()
            .filter(|line| line.split_whitespace().nth(1) == Some(oid))
            .count()
    };
    assert_eq!(notes(&sealed), 1, "the seal left its note");
    let (before, before_bytes) = read(&repo, &sealed);

    // Note mode carries no `Object` line at all, so only the imprint can tell
    // the second run that the work is already done.
    assert!(before.pre_image(store::PREFIX).trailer.is_some());
    let second = run(&repo, &policy, &sealed)
        .await
        .map_err(|error| error.to_string());
    println!("second seal on a note-sealed commit = {second:?}");
    assert_eq!(second, Ok(SealOutcome::Skipped(SkipReason::AlreadySealed)));
    assert_eq!(old_of(&repo), sealed, "the ref did not move again");
    assert_eq!(notes(&sealed), 1, "no second note was written");
    assert_eq!(notes(&oid), 0, "no orphan note for the old object");
    let (after, after_bytes) = read(&repo, &sealed);
    assert_eq!(after_bytes, before_bytes, "the object is byte-identical");
    assert!(after.pre_image(store::PREFIX).trailer.is_some());
}
