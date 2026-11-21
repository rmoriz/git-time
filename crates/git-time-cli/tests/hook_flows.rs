//! The hook and the git flows it has to survive, end to end.
//!
//! Every case runs the real binary: a repository under a temporary directory,
//! its `post-commit` **and** `post-merge` shims pointing at the matching
//! `git time hook` event (a merge never runs `post-commit` — measured), and a
//! stub authority on loopback that mints a genuine RFC 3161 token for the
//! request in flight with `openssl ts -reply`. The token therefore answers
//! exactly the imprint and nonce the seal sent, and the pinned anchor is the
//! throwaway CA made for the test — no fixture is trusted that was not issued
//! for the run.
//!
//! The certificates are built for the older `openssl` a run may meet (LibreSSL,
//! OpenSSL 1.1.1) as well as a current one: `-sha256` and a named curve, because
//! their defaults (SHA-1 signatures, explicit EC parameters) are outside what
//! `webpki` verifies, a per-CA serial file because `-CAcreateserial` writes into
//! the shared temp directory and races between parallel fixtures, and a config
//! section for the CA extensions because 1.1.1 adds `basicConstraints` itself.
//!
//! The repository is hermetic: `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM` and
//! `GNUPGHOME` point into temporary directories and `GIT_DIR`/`GIT_WORK_TREE`/
//! `GIT_TIME_SKIP` are cleared, so nothing on the machine steers branches,
//! signing keys, hooks or skips.
//!
//! After every case the whole rewrite is checked: the hook's line was printed,
//! the commit carries exactly one block, the tree, parents and author are
//! untouched, the worktree is clean and `git fsck` says nothing.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once, OnceLock};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use git_time_core::imprint::{Alg, digest};
use git_time_core::object::CommitObject;
use git_time_core::store;
use tempfile::TempDir;

/// The binary under test, built by cargo for this integration test.
const BIN: &str = env!("CARGO_BIN_EXE_git-time");

/// The block marker whose count must be exactly one after every seal.
const IMPRINT: &str = "\nX-RFC3161-Imprint:";

/// Keep the developer's git and gpg configuration out of the test binary.
fn insulate() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: the only writer of these variables in the binary, run before
        // anything spawns git or gpg.
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", "/dev/null");
            std::env::set_var("GIT_CONFIG_SYSTEM", "/dev/null");
            std::env::remove_var("GIT_DIR");
            std::env::remove_var("GIT_WORK_TREE");
            std::env::remove_var("GIT_INDEX_FILE");
            std::env::remove_var("GIT_TIME_SKIP");
        }
    });
}

/// The environment every git and binary invocation gets.
fn insulated_env() -> Vec<(&'static str, &'static str)> {
    insulate();
    vec![
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ]
}

/// Run `git` in `dir` with the insulated environment and `input` on stdin.
fn git_output_env(dir: &Path, args: &[&str], input: &[u8], env: &[(&str, &str)]) -> Output {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_TIME_SKIP")
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns git");
    {
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(input)
            .expect("writes stdin");
    }
    let output = child.wait_with_output().expect("waits for git");
    note_failure(dir, args, &output);
    output
}

/// Show what a seal recorded when it went wrong: the hook line alone says
/// nothing about *why* an authority failed, while the reasons are trailers on
/// the commit — which no assertion ever prints.
fn note_failure(dir: &Path, args: &[&str], output: &Output) {
    let evidence = evidence(dir);
    if output.status.success() && !evidence.contains("X-RFC3161-Fail") {
        return;
    }
    eprintln!(
        "--- {:?} -> {:?}\nfixture openssl:\n{}stdout:\n{}\nstderr:\n{}\nevidence:\n{}",
        args,
        output.status,
        openssl_identity(),
        text(&output.stdout),
        text(&output.stderr),
        evidence
    );
}

/// The `openssl` the fixtures were built with, once per run: a LibreSSL and an
/// OpenSSL differ in the very defaults that decide whether a token verifies.
fn openssl_identity() -> String {
    static IDENTITY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    IDENTITY
        .get_or_init(|| {
            let output = Command::new("openssl").args(["version", "-a"]).output();
            match output {
                Ok(output) => format!("{}{}", text(&output.stdout), text(&output.stderr)),
                Err(error) => format!("openssl unavailable: {error}\n"),
            }
        })
        .clone()
}

/// The seal's own record on the current commit, without the bulky token.
fn evidence(dir: &Path) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["log", "-1", "--format=%B"])
        .output()
        .expect("reads the commit");
    text(&output.stdout)
        .lines()
        .filter(|line| line.starts_with("X-RFC3161") && !line.starts_with("X-RFC3161-Token:"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn git_output(dir: &Path, args: &[&str], input: &[u8]) -> Output {
    git_output_env(dir, args, input, &insulated_env())
}

/// Run git in `dir`, assert success and return stdout.
fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = git_output(dir, args, b"");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        text(&output.stderr)
    );
    output.stdout
}

/// Run git in `dir` with extra environment and assert success.
fn git_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) {
    let output = git_output_env(dir, args, b"", env);
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        text(&output.stderr)
    );
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Run the binary with `args` in `dir`.
fn run_time(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(BIN);
    command
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_TIME_SKIP")
        .envs(insulated_env().iter().copied())
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command.output().expect("runs the binary");
    note_failure(dir, args, &output);
    output
}

// --- throwaway authority ------------------------------------------------

/// A throwaway TSA: a CA, a timestamping leaf and the config `openssl ts
/// -reply` needs.
struct Authority {
    dir: TempDir,
    ca: PathBuf,
    config: PathBuf,
    counter: AtomicUsize,
}

impl Authority {
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
            "-sha256",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-pkeyopt",
            "ec_param_enc:named_curve",
            "-nodes",
            "-keyout",
            &pstr(&ca_key),
            "-out",
            &pstr(&ca),
            "-days",
            "2",
            "-subj",
            "/CN=hook-flow-ca",
            "-config",
            &ca_config(path),
            "-extensions",
            "v3_ca",
        ]);
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-pkeyopt",
            "ec_param_enc:named_curve",
            "-nodes",
            "-keyout",
            &pstr(&leaf_key),
            "-out",
            &pstr(&leaf_csr),
            "-subj",
            "/CN=hook-flow-tsa",
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
            "-sha256",
            "-in",
            &pstr(&leaf_csr),
            "-CA",
            &pstr(&ca),
            "-CAkey",
            &pstr(&ca_key),
            "-CAserial",
            &serial(&ca),
            "-out",
            &pstr(&leaf),
            "-days",
            "2",
            "-extfile",
            &pstr(&extensions),
        ]);

        std::fs::write(path.join("tsaserial"), "01\n").expect("write serial");
        let config = path.join("tsa.cnf");
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

    /// A granted `TimeStampResp` for the DER `query`.
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

    fn bundle(&self) -> PathBuf {
        self.ca.clone()
    }
}

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

/// A per-authority serial file for `openssl x509 -CAserial`.
///
/// LibreSSL's `-CAcreateserial` ignores the CA's directory and writes a bare
/// `.srl` into the shared temp directory, so parallel fixtures race on one file
/// and occasionally read it half-written. Owning the path keeps them apart.
fn serial(ca: &Path) -> String {
    let path = ca.with_extension("srl");
    std::fs::write(&path, "01\n").expect("write serial");
    pstr(&path)
}

/// A config file carrying the CA extensions for `openssl req -x509`.
///
/// `-addext basicConstraints` duplicates the extension OpenSSL 1.1.1 adds by
/// itself for `-x509`, and `webpki` rejects a duplicated extension; a config
/// section is written exactly once by every version.
fn ca_config(dir: &Path) -> String {
    let path = dir.join("ca.cnf");
    std::fs::write(
        &path,
        "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\ncommonName=Common Name\n\
         [v3_ca]\nbasicConstraints=critical,CA:TRUE\n\
         keyUsage=critical,keyCertSign,cRLSign\n",
    )
    .expect("write CA config");
    pstr(&path)
}

// --- stub authority -----------------------------------------------------

#[derive(Clone)]
struct StubState {
    authority: Arc<Authority>,
    hits: Arc<AtomicUsize>,
}

/// A stub authority on a loopback port that mints real tokens for the requests
/// it receives.
///
/// The server lives on its own runtime. Blocking `openssl` runs directly in the
/// handler, so the test's own runtime only has to drive the process under test.
struct Stub {
    url: String,
    hits: Arc<AtomicUsize>,
    _runtime: tokio::runtime::Runtime,
}

impl Stub {
    fn spawn(authority: Arc<Authority>) -> Self {
        let hits = Arc::new(AtomicUsize::new(0));
        let state = StubState {
            authority,
            hits: Arc::clone(&hits),
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("stub runtime");
        let url = runtime.block_on(async {
            let app = Router::new().route("/tsr", post(handle)).with_state(state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind stub");
            let addr = listener.local_addr().expect("stub address");
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            format!("http://{addr}/tsr")
        });
        Self {
            url,
            hits,
            _runtime: runtime,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn handle(State(state): State<StubState>, _headers: HeaderMap, body: Bytes) -> Response {
    state.hits.fetch_add(1, Ordering::SeqCst);
    let response = state.authority.mint(&body);
    ([(CONTENT_TYPE, "application/timestamp-response")], response).into_response()
}

// --- the repository -----------------------------------------------------

/// A temporary repository with its `post-commit` shim wired to this binary.
struct Repo {
    dir: TempDir,
    authority: Arc<Authority>,
    stub: Option<Stub>,
    /// Distinguishes the commit dates, so a replay always differs from the
    /// commit it replays even within the same wall-clock second.
    dates: AtomicUsize,
}

impl Repo {
    /// A repository with one sealed base commit and a live stub TSA.
    fn new() -> Self {
        let mut repo = Self::upright();
        repo.init();
        repo.serve();
        repo.commit("base");
        repo
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// A repository with a base commit and a TSA nothing listens on.
    fn with_down_tsa() -> Self {
        let mut repo = Self::upright();
        repo.init();
        repo.dead_tsa();
        repo.commit("base");
        repo
    }

    /// Bare skeleton without a base commit.
    fn upright() -> Self {
        let dir = TempDir::new().expect("temp dir");
        let authority = Arc::new(Authority::new());
        Self {
            dir,
            authority,
            stub: None,
            dates: AtomicUsize::new(0),
        }
    }

    fn init(&mut self) {
        let path = self.dir.path().to_path_buf();
        git(&path, &["init", "-q", "-b", "main"]);
        git(&path, &["config", "user.name", "Test"]);
        git(&path, &["config", "user.email", "t@example.com"]);
        git(&path, &["config", "commit.gpgsign", "false"]);
        git(&path, &["config", "tag.gpgsign", "false"]);
        git(&path, &["config", "gpg.program", "gpg"]);
        // Generous on purpose: the suite runs dozens of these repositories at
        // once, and a five-second seal budget expires under CI load — on the
        // same commit the same test spent 4.1s of it on Ubuntu and ran out on
        // macOS, which reads as "under quorum (0 of 1)" instead of "by 1/1".
        git(&path, &["config", "time.deadline", "30s"]);
        git(&path, &["config", "time.tsa.stub.timeout", "30s"]);
        // The hook is what the whole task is about. Two hooks are needed: a
        // merge never runs `post-commit`, so `post-merge` is not optional.
        for (name, event) in [("post-commit", "post-commit"), ("post-merge", "post-merge")] {
            self.wire(name, event);
        }
    }

    /// Wire a hook of this repository to `git time hook <event>`.
    fn wire(&self, name: &str, event: &str) {
        let hooks = self.path().join(".git").join("hooks");
        std::fs::create_dir_all(&hooks).expect("hooks dir");
        let hook = hooks.join(name);
        std::fs::write(
            &hook,
            format!("#!/bin/sh\nexec {} hook {event} \"$@\"\n", quote(BIN)),
        )
        .expect("write hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
                .expect("chmod hook");
        }
    }

    /// Remove a hook of this repository.
    fn unwire(&self, name: &str) {
        let hook = self.path().join(".git").join("hooks").join(name);
        if hook.exists() {
            std::fs::remove_file(hook).expect("remove hook");
        }
    }

    /// Wire a hook that only has to exist (a merge hook git runs but which is
    /// not one of this task's events).
    fn wire_stub(&self, name: &str) {
        let hooks = self.path().join(".git").join("hooks");
        std::fs::create_dir_all(&hooks).expect("hooks dir");
        let hook = hooks.join(name);
        std::fs::write(&hook, "#!/bin/sh\nexit 0\n").expect("write hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
                .expect("chmod hook");
        }
    }

    /// Point the configured TSA at a live stub.
    fn serve(&mut self) {
        let stub = Stub::spawn(Arc::clone(&self.authority));
        git(
            self.path(),
            &["config", "time.tsa.stub.url", stub.url.as_str()],
        );
        git(
            self.path(),
            &[
                "config",
                "time.tsa.stub.anchor",
                &pstr(&self.authority.bundle()),
            ],
        );
        self.stub = Some(stub);
    }

    /// Point the configured TSA at a port nothing listens on.
    fn dead_tsa(&self) {
        git(
            self.path(),
            &["config", "time.tsa.stub.url", "http://127.0.0.1:1/tsr"],
        );
        git(
            self.path(),
            &[
                "config",
                "time.tsa.stub.anchor",
                &pstr(&self.authority.bundle()),
            ],
        );
    }

    fn hits(&self) -> usize {
        self.stub.as_ref().map_or(0, Stub::hits)
    }

    fn head(&self) -> String {
        text(&git(self.path(), &["rev-parse", "HEAD"]))
            .trim()
            .to_owned()
    }

    /// Commit the file `name` and return the commit id.
    fn commit(&self, message: &str) -> String {
        let name = format!("{}.txt", message.replace(' ', "-"));
        std::fs::write(self.path().join(&name), message).expect("write file");
        git(self.path(), &["add", &name]);
        let index = self.dates.fetch_add(1, Ordering::SeqCst);
        let date = format!("2020-01-01T00:00:{index:02}Z");
        let output = git_output_env(
            self.path(),
            &["commit", "-q", "-m", message, "--date", &date],
            b"",
            &[("GIT_COMMITTER_DATE", date.as_str())],
        );
        assert!(
            output.status.success(),
            "commit failed: {}",
            text(&output.stderr)
        );
        self.head()
    }

    /// The raw commit object `rev` names.
    fn object(&self, rev: &str) -> String {
        text(&git(self.path(), &["cat-file", "commit", rev]))
    }

    /// How many timestamp blocks `rev` carries.
    fn blocks(&self, rev: &str) -> usize {
        self.object(rev).matches(IMPRINT).count()
    }

    /// Whether `rev` carries a block whose imprint matches its own pre-image.
    ///
    /// A rebase carries the old block along, so a replayed commit can hold a
    /// block that is present but stale; only a matching imprint counts.
    fn is_sealed(&self, rev: &str) -> bool {
        let raw = git(self.path(), &["cat-file", "commit", rev]);
        let object = CommitObject::parse(&raw).expect("parses");
        let pre = object.pre_image(store::PREFIX);
        let Some(trailer) = pre.trailer else {
            return false;
        };
        let Ok(Some(block)) = store::decode(&trailer) else {
            return false;
        };
        block.imprint.bytes == digest(Alg::Sha256, &pre.bytes)
    }

    /// A snapshot of what a rewrite must not change.
    ///
    /// Only the header section is scanned: a message line that happens to start
    /// with `tree ` or `parent ` must not be taken for a header.
    fn snapshot(&self, rev: &str) -> Snapshot {
        let raw = self.object(rev);
        let header = |name: &str| {
            raw.split_once("\n\n")
                .map_or("", |(headers, _message)| headers)
                .lines()
                .filter_map(|line| line.strip_prefix(&format!("{name} ")))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        Snapshot {
            tree: header("tree"),
            parents: header("parent"),
            author: header("author"),
        }
    }

    /// The raw bytes of the `mergetag` header, folds and all, or `None`.
    fn mergetag(&self, rev: &str) -> Option<String> {
        let raw = self.object(rev);
        let headers = raw.split_once("\n\n").map_or("", |(headers, _)| headers);
        let mut lines = headers.lines();
        let mut tag = None;
        while let Some(line) = lines.next() {
            if line.starts_with("mergetag ") {
                let mut value = line.to_owned();
                for next in lines.by_ref() {
                    let Some(continuation) = next.strip_prefix(' ') else {
                        break;
                    };
                    value.push('\n');
                    value.push_str(continuation);
                }
                tag = Some(value);
                break;
            }
        }
        tag
    }

    fn status(&self) -> String {
        text(&git(self.path(), &["status", "--porcelain"]))
    }

    fn fsck(&self) -> Output {
        git_output(self.path(), &["fsck", "--strict"], b"")
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    tree: Vec<String>,
    parents: Vec<String>,
    author: Vec<String>,
}

/// Quote a path for `sh`.
fn quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', r#"'\''"#))
}

/// Assert that a case left the repository exactly as it should: one block on
/// `rev`, the expected tree and parents, an author that is still the configured
/// identity (or `expected.author` when given), and nothing dirty.
fn assert_rewrite(repo: &Repo, rev: &str, expected: &Snapshot) {
    assert_rewrite_count(repo, rev, expected, 1);
}

/// [`assert_rewrite`], with the number of blocks the commit must carry.
fn assert_rewrite_count(repo: &Repo, rev: &str, expected: &Snapshot, blocks: usize) {
    let after = repo.snapshot(rev);
    assert_eq!(after.tree, expected.tree, "tree changed");
    assert_eq!(after.parents, expected.parents, "parents changed");
    if expected.author.is_empty() {
        assert_eq!(after.author.len(), 1, "{after:?}");
        assert!(
            after.author[0].starts_with("Test <t@example.com> "),
            "author changed: {:?}",
            after.author
        );
    } else {
        assert_eq!(after.author, expected.author, "author changed");
    }
    assert_eq!(repo.blocks(rev), blocks, "block count");
    assert_eq!(repo.status(), "", "the worktree is clean");
    let fsck = repo.fsck();
    assert!(
        fsck.status.success(),
        "git fsck failed: {}",
        text(&fsck.stderr)
    );
    assert_eq!(text(&fsck.stdout).trim(), "", "git fsck is silent");
    assert_eq!(text(&fsck.stderr).trim(), "", "git fsck is silent");
}

/// An expectation for [`assert_rewrite`] that checks the shape but not the
/// author line, whose timestamp is the wall clock.
fn shape(tree: Vec<String>, parents: Vec<String>) -> Snapshot {
    Snapshot {
        tree,
        parents,
        author: Vec::new(),
    }
}

/// Assert that git succeeded and the hook said its one line on stderr.
///
/// git itself writes progress to stdout; the hook's own output must be on
/// stderr, so the line is looked for there.
fn assert_said(output: &Output) -> String {
    assert!(
        output.status.success(),
        "expected success, got {:?}: {}",
        output.status.code(),
        text(&output.stderr)
    );
    let stderr = text(&output.stderr);
    assert!(
        !text(&output.stdout).contains("rfc3161:"),
        "the hook writes to stderr only: {}",
        text(&output.stdout)
    );
    stderr.trim().to_owned()
}

// --- cases --------------------------------------------------------------

#[test]
fn a_plain_commit_is_sealed() {
    let repo = Repo::new();
    let base = repo.head();
    let expected = shape(repo.snapshot(&base).tree, vec![base.clone()]);

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "plain"],
        b"",
    );
    let said = assert_said(&output);
    assert_eq!(repo.hits(), 2, "the base commit and this one were stamped");
    assert_eq!(
        said,
        format!("rfc3161: sealed {} by 1/1 TSA(s)", &repo.head()[..7])
    );
    assert!(said.ends_with("TSA(s)"), "{said}");

    let head = repo.head();
    assert_rewrite(&repo, &head, &expected);
}

/// A plain-`http` authority warns at seal, because the imprint travels in the
/// clear — the token is still verified against the pinned root. One line for all
/// of them: five are named, the rest counted, so a wide selection does not bury
/// the seal output.
#[test]
fn many_insecure_authorities_warn_on_one_capped_line() {
    let repo = Repo::new();
    git(
        repo.path(),
        &["config", "time.tsa.stub.url", "http://127.0.0.1:1/tsr"],
    );
    git(
        repo.path(),
        &["config", "time.tsa.stub.insecure-http", "true"],
    );
    for extra in 1..=6 {
        git(
            repo.path(),
            &[
                "config",
                &format!("time.tsa.extra{extra}.url"),
                "http://127.0.0.1:1/tsr",
            ],
        );
        git(
            repo.path(),
            &[
                "config",
                &format!("time.tsa.extra{extra}.anchor"),
                &pstr(&repo.authority.bundle()),
            ],
        );
        git(
            repo.path(),
            &[
                "config",
                &format!("time.tsa.extra{extra}.insecure-http"),
                "true",
            ],
        );
    }

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "many insecure"],
        b"",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("7 authorities use plain http ("),
        "all seven are counted: {stderr}"
    );
    assert!(
        stderr.contains("and 2 more)"),
        "only five are named: {stderr}"
    );
    assert_eq!(
        stderr.matches("authorities use plain http").count(),
        1,
        "one line, not one per authority: {stderr}"
    );
}

#[test]
fn a_tofu_pin_warns_at_seal_time() {
    let repo = Repo::new();
    git(repo.path(), &["config", "time.tsa.stub.tofu", "true"]);

    let output = git_output(repo.path(), &["commit", "--allow-empty", "-m", "tofu"], b"");
    assert!(
        output.status.success(),
        "on-failure = warn keeps the commit: {}",
        text(&output.stderr)
    );
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("1 authority is pinned without a comparison (stub)"),
        "the authority is named: {stderr}"
    );
    assert!(
        stderr.contains("git time anchor confirm stub"),
        "the way out is named: {stderr}"
    );
    // One line for all of them, five named and the rest counted.
    for extra in 1..=6 {
        git(
            repo.path(),
            &[
                "config",
                &format!("time.tsa.extra{extra}.url"),
                "http://127.0.0.1:1/tsr",
            ],
        );
        git(
            repo.path(),
            &[
                "config",
                &format!("time.tsa.extra{extra}.anchor"),
                &pstr(&repo.authority.bundle()),
            ],
        );
        git(
            repo.path(),
            &["config", &format!("time.tsa.extra{extra}.tofu"), "true"],
        );
    }
    let wide = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "many tofu"],
        b"",
    );
    assert!(wide.status.success(), "{}", text(&wide.stderr));
    let stderr = text(&wide.stderr);
    assert!(
        stderr.contains("7 authorities are pinned without a comparison ("),
        "all seven are counted: {stderr}"
    );
    assert!(stderr.contains("and 2 more)"), "only five named: {stderr}");
    assert_eq!(
        stderr.matches("pinned without a comparison").count(),
        1,
        "one line, not one per authority: {stderr}"
    );
}

#[test]
fn an_unmarked_pin_is_quiet_at_seal_time() {
    let repo = Repo::new();
    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "no tofu"],
        b"",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        !text(&output.stderr).contains("pinned without a comparison"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn an_insecure_authority_warns_at_seal_time() {
    let repo = Repo::new();
    git(
        repo.path(),
        &["config", "time.tsa.stub.insecure-http", "true"],
    );

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "insecure"],
        b"",
    );
    assert!(
        output.status.success(),
        "on-failure = warn keeps the commit: {}",
        text(&output.stderr)
    );
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("1 authority uses plain http (stub)"),
        "the authority is named: {stderr}"
    );
    assert!(
        stderr.contains("integrity is still verified, transport is not"),
        "the mitigation is named: {stderr}"
    );
    assert!(
        stderr.contains("rfc3161: sealed "),
        "the seal still happened: {stderr}"
    );
}

#[test]
fn an_empty_commit_is_sealed() {
    let repo = Repo::new();
    let base = repo.head();
    let tree = repo.snapshot(&base).tree;

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "empty"],
        b"",
    );
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");
    let head = repo.head();
    let after = repo.snapshot(&head);
    assert_eq!(after.tree, tree, "the tree is unchanged");
    assert_eq!(after.parents, vec![base]);
    assert_eq!(repo.blocks(&head), 1);
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

/// A repository whose only merge hooks are the two git actually runs, with a
/// base and a divergent feature branch. Every commit so far is unsealed.
fn merge_fixture() -> (Repo, String, String, String) {
    let mut repo = Repo::upright();
    repo.init();
    repo.serve();
    // The measured fact this task rests on: a merge runs `pre-merge-commit` and
    // `post-merge`, and never `post-commit`.
    repo.unwire("post-commit");
    repo.wire_stub("pre-merge-commit");
    let base = repo.commit("base");
    git(repo.path(), &["checkout", "-q", "-b", "feature"]);
    let feature_tip = repo.commit("feature");
    git(repo.path(), &["checkout", "-q", "main"]);
    let main_tip = repo.commit("main work");
    (repo, base, feature_tip, main_tip)
}

#[test]
fn a_merge_commit_is_sealed_with_both_parents() {
    let (repo, base, feature_tip, main_tip) = merge_fixture();
    assert!(
        !repo.path().join(".git/hooks/post-commit").exists(),
        "nothing relies on post-commit for a merge"
    );
    assert_eq!(repo.blocks(&base), 0);

    // Capture the merge's exact shape first, with the seal switched off, then
    // put the branch back and do the real merge through the hook.
    let prepared = shape_of(&repo, &feature_tip, &main_tip);
    let again = shape_of(&repo, &feature_tip, &main_tip);
    assert_eq!(again.tree, prepared.tree, "the merge is deterministic");
    assert_eq!(again.parents, prepared.parents);
    // The merge's author is the wall clock, so only its shape is pinned.
    let expected = shape(prepared.tree.clone(), prepared.parents.clone());

    let output = git_output(
        repo.path(),
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
        b"",
    );
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");

    let head = repo.head();
    let after = repo.snapshot(&head);
    assert_eq!(after.tree, expected.tree, "the merged tree is untouched");
    assert_eq!(after.parents, vec![main_tip, feature_tip], "both parents");
    assert_rewrite(&repo, &head, &expected);
}

/// The tree and parent ids a merge of `feature` into `main` produces.
///
/// The merge is made once with `GIT_TIME_SKIP=1` and undone again, so the
/// expectation is taken from git itself rather than guessed.
fn shape_of(repo: &Repo, feature_tip: &str, main_tip: &str) -> Snapshot {
    let start = repo.head();
    let output = git_output_env(
        repo.path(),
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
        b"",
        &[("GIT_TIME_SKIP", "1")],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    let prepared = repo.snapshot("HEAD");
    assert_eq!(
        prepared.parents,
        vec![main_tip.to_owned(), feature_tip.to_owned()]
    );
    assert_eq!(
        text(&output.stderr).trim(),
        "",
        "the skipped merge is silent"
    );
    git(repo.path(), &["reset", "-q", "--hard", &start]);
    prepared
}

#[test]
fn a_squash_merge_is_sealed_and_its_hook_argument_is_accepted() {
    let repo = Repo::new();
    let base = repo.head();
    git(repo.path(), &["checkout", "-q", "-b", "feature"]);
    repo.commit("feature");
    git(repo.path(), &["checkout", "-q", "main"]);

    // `post-merge` is called with `1` for a squash; the extra argument must not
    // be mistaken for a usage error.
    let output = git_output(repo.path(), &["merge", "--squash", "feature"], b"");
    assert!(output.status.success(), "{}", text(&output.stderr));

    // The tree the commit will get, taken before it exists and therefore
    // before any seal can touch it.
    let tree = text(&git(repo.path(), &["write-tree"]));
    let tree = tree.trim().to_owned();

    let output = git_output(repo.path(), &["commit", "-q", "-m", "squashed"], b"");
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");

    let head = repo.head();
    assert_eq!(
        repo.snapshot(&head).tree,
        vec![tree.clone()],
        "the tree is kept"
    );
    assert_rewrite(&repo, &head, &shape(vec![tree], vec![base]));
}

#[test]
fn a_drop_survives_a_squash_merge_and_lands_on_its_commit() {
    let repo = Repo::new();
    let base = repo.head();
    git(repo.path(), &["checkout", "-q", "-b", "feature"]);
    repo.commit("feature");
    git(repo.path(), &["checkout", "-q", "main"]);
    let marker = repo.path().join(".git/time-skip");
    let drop = run_time(repo.path(), &["drop"], &[]);
    assert!(drop.status.success(), "{}", text(&drop.stderr));

    // `post-merge 1` fires before the squash commit exists: no commit to seal,
    // so the merge must not take the drop.
    let output = git_output(repo.path(), &["merge", "--squash", "feature"], b"");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stderr).trim(), "", "the merge stays silent");
    assert!(marker.exists(), "the squash merge keeps the drop");
    assert_eq!(repo.head(), base, "still before the commit");

    let output = git_output(repo.path(), &["commit", "-q", "-m", "squashed"], b"");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stderr).trim(), "", "a drop is silent");
    assert!(!marker.exists(), "the commit consumes the marker");

    // The drop landed where it was meant: on the commit, not on the merge.
    let head = repo.head();
    assert_ne!(head, base);
    assert_eq!(repo.blocks(&head), 0, "the commit is unsealed on purpose");
    assert!(!repo.is_sealed(&head));
    let recorded = std::fs::read_to_string(repo.path().join(".git/time-dropped"))
        .expect("the drop is recorded");
    assert!(
        recorded.lines().any(|line| line.trim() == head),
        "{recorded}"
    );
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

/// A throwaway OpenPGP key, generated once per test binary.
fn signing_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| {
        insulate();
        let home = TempDir::new().expect("gpg home");
        // SAFETY: set once, before the only gpg runs of this binary.
        unsafe { std::env::set_var("GNUPGHOME", home.path()) };
        std::mem::forget(home);

        gpg(&[
            "--batch",
            "--passphrase",
            "",
            "--quick-gen-key",
            "Hook Test <hook@example.com>",
            "rsa2048",
            "sign",
            "never",
        ]);
        let listing = text(
            &Command::new("gpg")
                .args(["--list-keys", "--with-colons"])
                .env("GNUPGHOME", std::env::var("GNUPGHOME").expect("home"))
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
        // Warm the agent so the first signature does not race key lookup.
        gpg(&[
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

fn gpg(args: &[&str]) {
    let status = Command::new("gpg")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env("GNUPGHOME", std::env::var("GNUPGHOME").expect("home"))
        .status()
        .expect("gpg is available");
    assert!(status.success(), "gpg {args:?} failed");
}

#[test]
fn a_signed_tag_merge_keeps_its_mergetag() {
    let repo = Repo::new();
    let key = signing_key();
    git(repo.path(), &["config", "user.signingkey", key]);
    git(repo.path(), &["config", "gpg.format", "openpgp"]);
    git(repo.path(), &["checkout", "-q", "-b", "feature"]);
    repo.commit("tagged");
    git(
        repo.path(),
        &["tag", "-s", "-m", "signed tag", "v1", "feature"],
    );
    git(repo.path(), &["checkout", "-q", "main"]);
    let start = repo.head();

    // The mergetag header is the signed tag as git embedded it. Take it from a
    // hook-less merge first, so the comparison is over the real bytes and not
    // a presence check.
    let prepared = git_output_env(
        repo.path(),
        &["merge", "--no-ff", "-m", "merge tag", "v1"],
        b"",
        &[("GIT_TIME_SKIP", "1")],
    );
    assert!(prepared.status.success(), "{}", text(&prepared.stderr));
    let before = repo.mergetag("HEAD").expect("git embedded the mergetag");
    let parents = repo.snapshot("HEAD").parents;
    let tree = repo.snapshot("HEAD").tree;
    git(repo.path(), &["reset", "-q", "--hard", &start]);

    let output = git_output(
        repo.path(),
        &["merge", "--no-ff", "-m", "merge tag", "v1"],
        b"",
    );
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");

    let head = repo.head();
    assert_eq!(
        repo.mergetag(&head).as_deref(),
        Some(before.as_str()),
        "the mergetag header is byte-identical"
    );
    assert_eq!(repo.snapshot(&head).parents, parents, "both parents kept");
    assert_eq!(repo.snapshot(&head).tree, tree, "the tree is kept");
    assert_eq!(repo.blocks(&head), 1);
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn a_cherry_pick_is_sealed() {
    let repo = Repo::new();
    git(repo.path(), &["checkout", "-q", "-b", "feature"]);
    let picked = repo.commit("picked");
    let picked_tree = repo.snapshot(&picked).tree;
    git(repo.path(), &["checkout", "-q", "main"]);
    let base = repo.head();

    let output = git_output(repo.path(), &["cherry-pick", &picked], b"");
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");

    let head = repo.head();
    assert_ne!(head, picked);
    assert_rewrite(&repo, &head, &shape(picked_tree, vec![base]));
}

/// A repository with a sealed base and three commits on top, ready to be
/// rebased as a whole.
fn three_commits() -> Repo {
    let mut repo = Repo::upright();
    repo.init();
    // `git rebase --root` leaves a reference to the empty tree without writing
    // it; store it once so `git fsck` stays quiet.
    git(repo.path(), &["hash-object", "-w", "-t", "tree", "--stdin"]);
    repo.serve();
    for message in ["one", "two", "three"] {
        repo.commit(message);
    }
    repo
}

/// One line of `git rev-list --parents`: a commit and its parent ids.
#[derive(Debug, PartialEq, Eq)]
struct Line {
    oid: String,
    parents: Vec<String>,
}

/// The commit graph HEAD names, newest first, as `git rev-list --parents`
/// reports it.
fn rev_list_parents(repo: &Repo) -> Vec<Line> {
    text(&git(repo.path(), &["rev-list", "--parents", "HEAD"]))
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace().map(str::to_owned);
            Line {
                oid: fields.next().unwrap_or_default(),
                parents: fields.collect(),
            }
        })
        .collect()
}

/// Assert that the replayed history kept the shape of the history it replaced:
/// every tree and author identical, every parent the previous replay's parent.
fn assert_replayed_shape(repo: &Repo, before: &[Line]) {
    let after = rev_list_parents(repo);
    assert_eq!(after.len(), before.len(), "the replay dropped a commit");
    for (index, (now, then)) in after.iter().zip(before).enumerate() {
        assert_eq!(
            repo.snapshot(&now.oid).tree,
            repo.snapshot(&then.oid).tree,
            "tree of replay {index}"
        );
        assert_eq!(
            repo.snapshot(&now.oid).author,
            repo.snapshot(&then.oid).author,
            "author of replay {index}"
        );
        let expected: Vec<String> = after
            .get(index + 1)
            .map(|child| vec![child.oid.clone()])
            .unwrap_or_default();
        assert_eq!(now.parents, expected, "parents of replay {index}");
    }
}

#[test]
fn a_rebase_seals_every_replayed_commit_by_default() {
    let repo = three_commits();
    let before = rev_list_parents(&repo);
    let output = git_output(repo.path(), &["rebase", "--force-rebase", "--root"], b"");
    assert!(
        output.status.success(),
        "rebase failed: {}",
        text(&output.stderr)
    );
    assert!(
        text(&output.stderr).contains("Successfully rebased"),
        "{}",
        text(&output.stderr)
    );

    let log = text(&git(repo.path(), &["rev-list", "HEAD"]));
    let commits: Vec<&str> = log.lines().collect();
    assert_eq!(commits.len(), 3);
    for commit in commits {
        assert!(repo.is_sealed(commit), "{commit} is sealed");
    }
    assert_eq!(text(&output.stderr).matches("rfc3161: sealed ").count(), 3);
    assert_replayed_shape(&repo, &before);
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn a_rebase_with_tip_seals_only_the_tip() {
    let repo = three_commits();
    git(repo.path(), &["config", "time.seal-during-rebase", "tip"]);
    let before = rev_list_parents(&repo);

    let output = git_output(repo.path(), &["rebase", "--force-rebase", "--root"], b"");
    assert!(
        output.status.success(),
        "rebase failed: {}",
        text(&output.stderr)
    );

    let log = text(&git(repo.path(), &["rev-list", "HEAD"]));
    let commits: Vec<&str> = log.lines().collect();
    assert_eq!(commits.len(), 3);
    assert!(repo.is_sealed(commits[0]), "the tip is sealed");
    assert!(!repo.is_sealed(commits[1]), "the middle is not sealed");
    assert!(!repo.is_sealed(commits[2]), "the root is not sealed");
    assert_eq!(
        text(&output.stderr).matches("rfc3161: sealed ").count(),
        1,
        "one line, for the tip"
    );
    assert_replayed_shape(&repo, &before);
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn a_drop_during_a_tip_rebase_lands_on_the_tip() {
    let repo = three_commits();
    git(repo.path(), &["config", "time.seal-during-rebase", "tip"]);
    let marker = repo.path().join(".git/time-skip");
    let drop = run_time(repo.path(), &["drop"], &[]);
    assert!(drop.status.success(), "{}", text(&drop.stderr));

    // The replays before the tip seal nothing, so they must not take the drop:
    // it belongs to the one commit `tip` does seal.
    let output = git_output(repo.path(), &["rebase", "--force-rebase", "--root"], b"");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(!marker.exists(), "the tip consumes the marker");
    assert_eq!(
        text(&output.stderr).matches("rfc3161: sealed ").count(),
        0,
        "the tip is the dropped commit: {}",
        text(&output.stderr)
    );

    let log = text(&git(repo.path(), &["rev-list", "HEAD"]));
    let commits: Vec<&str> = log.lines().collect();
    assert_eq!(commits.len(), 3);
    // The replay carries the old block along, so only a matching imprint proves
    // a seal: the tip's is stale, it was dropped.
    assert!(!repo.is_sealed(commits[0]), "the tip is left unsealed");
    assert!(!repo.is_sealed(commits[1]), "the middle was never sealed");
    let recorded = std::fs::read_to_string(repo.path().join(".git/time-dropped"))
        .expect("the drop is recorded");
    assert!(
        recorded.lines().any(|line| line.trim() == commits[0]),
        "the tip is the recorded drop: {recorded}"
    );
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn a_trailing_exec_step_does_not_hide_the_tip() {
    let repo = three_commits();
    git(repo.path(), &["config", "time.seal-during-rebase", "tip"]);

    // A step after the last pick keeps the todo non-empty; only `exec` is left,
    // which makes no commit, so the last pick is still the tip.
    let output = git_output_env(
        repo.path(),
        &["rebase", "--force-rebase", "--root", "-i"],
        b"",
        &[(
            "GIT_SEQUENCE_EDITOR",
            "sh -c 'printf \"exec true\\n\" >> \"$1\"' sh",
        )],
    );
    assert!(
        output.status.success(),
        "rebase failed: {}",
        text(&output.stderr)
    );

    let log = text(&git(repo.path(), &["rev-list", "HEAD"]));
    let commits: Vec<&str> = log.lines().collect();
    assert_eq!(commits.len(), 3);
    assert!(repo.is_sealed(commits[0]), "the tip is still sealed");
    assert_eq!(
        text(&output.stderr).matches("rfc3161: sealed ").count(),
        1,
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn a_trailing_break_step_does_not_hide_the_tip() {
    let repo = three_commits();
    git(repo.path(), &["config", "time.seal-during-rebase", "tip"]);
    let before = rev_list_parents(&repo);

    // `break` stops the rebase after the picks and makes no commit; it must not
    // stop the last pick from being taken for the tip.
    let output = git_output_env(
        repo.path(),
        &["rebase", "--force-rebase", "--root", "-i"],
        b"",
        &[(
            "GIT_SEQUENCE_EDITOR",
            "sh -c 'printf \"break\\n\" >> \"$1\"' sh",
        )],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));

    let log = text(&git(repo.path(), &["rev-list", "HEAD"]));
    let commits: Vec<&str> = log.lines().collect();
    assert_eq!(commits.len(), 3);
    assert!(
        repo.is_sealed(commits[0]),
        "the tip is sealed: {}",
        text(&output.stderr)
    );
    assert!(!repo.is_sealed(commits[1]), "the middle is not sealed");
    assert_eq!(
        text(&output.stderr).matches("rfc3161: sealed ").count(),
        1,
        "exactly one seal, for the tip: {}",
        text(&output.stderr)
    );
    assert_replayed_shape(&repo, &before);

    // Finish the stopped rebase and check the history is still the replayed one.
    let finish = git_output_env(
        repo.path(),
        &["rebase", "--continue"],
        b"",
        &[("GIT_EDITOR", "true")],
    );
    assert!(finish.status.success(), "{}", text(&finish.stderr));
    assert_replayed_shape(&repo, &before);
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn a_rebase_with_off_seals_nothing_and_names_the_range() {
    let repo = three_commits();
    git(repo.path(), &["config", "time.seal-during-rebase", "off"]);
    let before = rev_list_parents(&repo);

    let output = git_output(repo.path(), &["rebase", "--force-rebase", "--root"], b"");
    assert!(
        output.status.success(),
        "rebase failed: {}",
        text(&output.stderr)
    );

    let log = text(&git(repo.path(), &["rev-list", "HEAD"]));
    for commit in log.lines() {
        assert!(!repo.is_sealed(commit), "{commit} is not sealed");
    }
    assert_replayed_shape(&repo, &before);
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("git time seal --range"),
        "the hint names the command: {stderr}"
    );
    assert!(
        stderr.contains("..HEAD"),
        "the hint names the range: {stderr}"
    );
    assert_eq!(
        stderr.matches("rebase in progress").count(),
        1,
        "the hint is said once, not per commit: {stderr}"
    );
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn an_amend_replaces_the_old_imprint() {
    let repo = Repo::new();
    let sealed = repo.commit("amend me");
    assert_eq!(repo.blocks(&sealed), 1);
    let old_imprint = repo
        .object(&sealed)
        .lines()
        .find_map(|line| line.strip_prefix("X-RFC3161-Imprint: ").map(str::to_owned))
        .expect("the sealed commit carries an imprint");
    let before = repo.snapshot(&sealed);
    let author = &before.author[0];
    let mut fields = author.split_whitespace().rev();
    let offset = fields.next().expect("an author offset");
    let seconds = fields.next().expect("an author timestamp");
    let date = format!("@{seconds} {offset}");

    let output = git_output(
        repo.path(),
        &[
            "commit",
            "-q",
            "--amend",
            "--allow-empty",
            "--no-edit",
            "--date",
            &date,
        ],
        b"",
    );
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");

    let head = repo.head();
    assert_ne!(head, sealed);
    assert_eq!(repo.blocks(&head), 1, "one block, not two");
    assert!(
        !repo.object(&head).contains(&old_imprint),
        "the old imprint is gone"
    );
    assert_rewrite(&repo, &head, &before);
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn a_no_verify_commit_is_still_sealed() {
    let repo = Repo::new();
    let base = repo.head();
    let expected = shape(repo.snapshot(&base).tree, vec![base.clone()]);

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "--no-verify", "-m", "unverified"],
        b"",
    );
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");
    let head = repo.head();
    assert_rewrite(&repo, &head, &expected);
}

#[test]
fn a_skipped_commit_is_untouched() {
    let repo = Repo::new();
    let base = repo.head();
    let expected = shape(repo.snapshot(&base).tree, vec![base]);

    let output = git_output_env(
        repo.path(),
        &["commit", "--allow-empty", "-m", "skipped"],
        b"",
        &[("GIT_TIME_SKIP", "1")],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stderr).trim(), "", "silent");
    let head = repo.head();
    assert_eq!(repo.blocks(&head), 0);
    assert_eq!(repo.hits(), 1, "only the base commit was stamped");
    assert_rewrite_count(&repo, &head, &expected, 0);
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn a_drop_suppresses_exactly_one_commit_and_is_consumed() {
    let repo = Repo::new();
    let base = repo.head();
    assert_eq!(repo.hits(), 1, "only the base commit was stamped");

    let marker = repo.path().join(".git/time-skip");
    let drop = run_time(repo.path(), &["drop"], &[]);
    assert!(drop.status.success(), "{}", text(&drop.stderr));
    assert!(
        text(&drop.stdout).contains("next commit"),
        "{}",
        text(&drop.stdout)
    );
    assert!(marker.exists(), "the marker is written");

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "dropped"],
        b"",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stderr).trim(), "", "a drop is silent");
    assert!(!marker.exists(), "the marker is consumed");
    let dropped = repo.head();
    assert_eq!(repo.blocks(&dropped), 0, "the dropped commit is untouched");
    assert_eq!(repo.hits(), 1, "no stamp was requested");
    assert_eq!(repo.snapshot(&dropped).parents, vec![base]);

    // Exactly one commit: the next one is sealed again.
    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "after"],
        b"",
    );
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");
    assert_eq!(repo.blocks(&repo.head()), 1);
    assert_eq!(repo.hits(), 2);
}

#[test]
fn an_unconsumable_drop_marker_is_reported_and_leaves_the_commit_unsealed() {
    let repo = Repo::new();
    let base = repo.head();
    // A directory sits where the marker file is expected: `remove_file` fails.
    let marker = repo.path().join(".git/time-skip");
    std::fs::create_dir(&marker).expect("marker directory");
    assert_eq!(repo.hits(), 1, "only the base commit was stamped");

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "dropped"],
        b"",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert_eq!(stderr.lines().count(), 1, "one line: {stderr:?}");
    assert!(
        stderr
            .trim()
            .starts_with("rfc3161: seal failed: cannot consume the drop marker"),
        "{stderr}"
    );

    // The commit is not sealed and the marker is still there, so the drop was
    // not half-taken.
    let head = repo.head();
    assert_ne!(head, base);
    assert_eq!(repo.blocks(&head), 0);
    assert!(marker.is_dir());
    assert_eq!(repo.hits(), 1, "no seal was attempted");
    assert_eq!(repo.status(), "");
}

#[test]
fn a_dropped_commit_is_reported_as_dropped_by_seal() {
    let repo = Repo::new();
    let drop = run_time(repo.path(), &["drop"], &[]);
    assert!(drop.status.success(), "{}", text(&drop.stderr));
    git(repo.path(), &["commit", "--allow-empty", "-m", "dropped"]);

    let seal = run_time(repo.path(), &["seal"], &[]);
    assert!(seal.status.success(), "{}", text(&seal.stderr));
    assert_eq!(text(&seal.stdout).trim(), "rfc3161: skipped (dropped)");
    assert_eq!(repo.blocks(&repo.head()), 0, "nothing was sealed");

    // `--force` overrides the drop.
    let forced = run_time(repo.path(), &["seal", "--force"], &[]);
    assert!(forced.status.success(), "{}", text(&forced.stderr));
    assert!(repo.is_sealed(&repo.head()));
    assert_eq!(repo.blocks(&repo.head()), 1);
}

#[test]
fn a_published_commit_is_skipped_and_force_still_seals_it() {
    let repo = Repo::new();
    // A bare origin and a second working copy that publishes one more commit.
    let bare = TempDir::new().expect("bare dir");
    git(bare.path(), &["init", "-q", "--bare", "-b", "main"]);
    git(
        repo.path(),
        &["remote", "add", "origin", &pstr(bare.path())],
    );
    git(repo.path(), &["push", "-q", "origin", "main"]);
    git(repo.path(), &["fetch", "-q", "origin"]);
    git(repo.path(), &["branch", "-q", "-u", "origin/main"]);

    let other = TempDir::new().expect("other dir");
    git(
        other.path(),
        &["clone", "-q", "-b", "main", &pstr(bare.path()), "."],
    );
    git(other.path(), &["config", "user.name", "Other"]);
    git(other.path(), &["config", "user.email", "o@example.com"]);
    let name = other.path().join("published.txt");
    std::fs::write(&name, "published").expect("write file");
    git(other.path(), &["add", "published.txt"]);
    git(other.path(), &["commit", "-q", "-m", "published"]);
    git(other.path(), &["push", "-q", "origin", "main"]);
    let published = text(&git(other.path(), &["rev-parse", "HEAD"]))
        .trim()
        .to_owned();

    // A fast-forward pull fires only `post-merge`; the commit is on the remote,
    // so sealing it here would put the branch ahead of `origin/main`.
    let output = git_output(repo.path(), &["pull", "-q"], b"");
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert_eq!(stderr.lines().count(), 1, "exactly one line: {stderr:?}");
    assert_eq!(
        stderr.trim(),
        format!(
            "rfc3161: skipping published {} (run: git time seal --force)",
            &published[..7]
        )
    );
    assert_eq!(repo.head(), published, "the commit is left untouched");
    assert_eq!(repo.blocks(&published), 0);
    assert!(!repo.is_sealed(&published));
    assert_eq!(repo.status(), "");

    // `--force` stays the explicit override.
    let forced = run_time(repo.path(), &["seal", "--force"], &[]);
    assert!(forced.status.success(), "{}", text(&forced.stderr));
    let head = repo.head();
    assert_ne!(head, published);
    assert!(repo.is_sealed(&head));
    assert_eq!(repo.blocks(&head), 1);
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn seal_range_skips_a_dropped_commit_unless_forced() {
    let repo = Repo::new();
    let base = repo.head();
    git_env(
        repo.path(),
        &["commit", "--allow-empty", "-m", "one"],
        &[("GIT_TIME_SKIP", "1")],
    );
    let drop = run_time(repo.path(), &["drop"], &[]);
    assert!(drop.status.success(), "{}", text(&drop.stderr));
    git(repo.path(), &["commit", "--allow-empty", "-m", "dropped"]);
    let dropped = repo.head();
    assert_eq!(repo.blocks(&dropped), 0, "the drop is unsealed");
    git_env(
        repo.path(),
        &["commit", "--allow-empty", "-m", "after"],
        &[("GIT_TIME_SKIP", "1")],
    );
    let after = repo.head();
    let range = format!("{base}..{after}");

    // The hint the `off` rebase prints points here, so the range has to honour
    // the drop: the dropped commit is named and left alone.
    let run = run_time(repo.path(), &["seal", "--range", &range], &[]);
    assert!(run.status.success(), "{}", text(&run.stderr));
    let lines: Vec<String> = text(&run.stdout).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[1], "rfc3161: skipped (dropped)");
    assert!(lines[0].starts_with("sealed "), "{lines:?}");
    assert!(lines[2].starts_with("sealed "), "{lines:?}");
    assert_eq!(
        git_stdout_in(&repo, &["rev-parse", "HEAD~1"]),
        dropped,
        "the dropped commit was not rewritten"
    );
    assert_eq!(repo.blocks(&dropped), 0, "and stays unsealed");

    // `--force` overrides the drop for the whole range.
    let forced = run_time(repo.path(), &["seal", "--range", &range, "--force"], &[]);
    assert!(forced.status.success(), "{}", text(&forced.stderr));
    let lines: Vec<String> = text(&forced.stdout).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines.iter().all(|line| line.starts_with("sealed ")));
    assert!(
        !run_status_dropped(&repo, &dropped),
        "the drop is forgotten"
    );
    assert_eq!(repo.status(), "");
}

/// Whether `time-dropped` still names `oid`.
fn run_status_dropped(repo: &Repo, oid: &str) -> bool {
    std::fs::read_to_string(repo.path().join(".git/time-dropped"))
        .map(|text| text.lines().any(|line| line.trim() == oid))
        .unwrap_or(false)
}

#[test]
fn a_pre_commit_gate_refuses_a_commit_when_the_tsa_is_down() {
    let repo = Repo::with_down_tsa();
    git(repo.path(), &["config", "time.gate", "pre-commit"]);
    repo.wire("pre-commit", "pre-commit");
    let base = repo.head();

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "gated"],
        b"",
    );
    assert!(!output.status.success(), "the commit is refused");
    assert_eq!(repo.head(), base, "no commit was created");
    let stderr = text(&output.stderr);
    assert!(stderr.contains("rfc3161: gate failed:"), "{stderr}");
    assert!(
        stderr.contains("0 of 1 TSA(s) answered, 1 required"),
        "{stderr}"
    );
    assert!(stderr.contains("commit refused"), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "one line: {stderr:?}");
}

#[test]
fn a_pending_drop_short_circuits_the_gate() {
    let repo = Repo::with_down_tsa();
    git(repo.path(), &["config", "time.gate", "pre-commit"]);
    repo.wire("pre-commit", "pre-commit");
    let base = repo.head();
    let marker = repo.path().join(".git/time-skip");
    let drop = run_time(repo.path(), &["drop"], &[]);
    assert!(drop.status.success(), "{}", text(&drop.stderr));

    // The commit is going to stay unsealed on purpose, so a dead TSA must not
    // stop it: the gate exists to stop a commit that would be sealed unsealed.
    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "dropped"],
        b"",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stderr).trim(), "", "silent");
    let head = repo.head();
    assert_ne!(head, base, "the commit was made");
    assert_eq!(repo.blocks(&head), 0, "and left unsealed");
    assert!(!marker.exists(), "the marker is consumed");
    assert_eq!(repo.hits(), 0, "the probe never ran");
}

#[test]
fn a_pre_commit_gate_allows_the_commit_when_the_tsa_answers() {
    let repo = Repo::new();
    git(repo.path(), &["config", "time.gate", "pre-commit"]);
    repo.wire("pre-commit", "pre-commit");
    let base = repo.head();
    let expected = shape(repo.snapshot(&base).tree, vec![base]);

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "gated"],
        b"",
    );
    let said = assert_said(&output);
    heading(&said);
    let head = repo.head();
    assert_rewrite(&repo, &head, &expected);
    // The probe costs one request, the seal another.
    assert_eq!(repo.hits(), 3, "base, probe and seal");
}

/// The hook's seal line, which the gate does not print.
fn heading(said: &str) {
    assert!(said.starts_with("rfc3161: sealed "), "{said}");
}

#[test]
fn a_pre_commit_hook_does_nothing_under_the_post_commit_gate() {
    let repo = Repo::new();
    repo.wire("pre-commit", "pre-commit");
    let base = repo.head();
    let expected = shape(repo.snapshot(&base).tree, vec![base]);

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "plain"],
        b"",
    );
    let said = assert_said(&output);
    heading(&said);
    let head = repo.head();
    assert_rewrite(&repo, &head, &expected);
    assert_eq!(repo.hits(), 2, "no probe under post-commit");
}

#[test]
fn seal_range_walks_a_merge_topologically() {
    let repo = Repo::new();
    let base = repo.head();
    git(repo.path(), &["checkout", "-q", "-b", "feature"]);
    // A parent dated far *after* its child: only a topological walk (or luck)
    // can put it first.
    commit_at(&repo, "feature", "2030-01-01T00:00:00Z");
    git(repo.path(), &["checkout", "-q", "main"]);
    let main_tip = commit_at(&repo, "main work", "2020-01-01T00:00:10Z");
    let merged = git_output_env(
        repo.path(),
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
        b"",
        &[
            ("GIT_TIME_SKIP", "1"),
            ("GIT_COMMITTER_DATE", "2021-01-01T00:00:00Z"),
        ],
    );
    assert!(merged.status.success(), "{}", text(&merged.stderr));
    let merge_oid = repo.head();
    commit_at(&repo, "after", "2022-01-01T00:00:00Z");
    let feature_oid = text(&git(repo.path(), &["rev-parse", "feature"]))
        .trim()
        .to_owned();

    let range = format!("{base}..HEAD");
    // The contract of the walk: every parent comes before its children, however
    // the committer dates fall. The feature parent is dated far *after* its
    // child on purpose.
    let topo: Vec<String> = text(&git(
        repo.path(),
        &["rev-list", "--reverse", "--topo-order", &range],
    ))
    .lines()
    .map(str::to_owned)
    .collect();
    let graph: Vec<Line> = text(&git(
        repo.path(),
        &["rev-list", "--parents", "--topo-order", &range],
    ))
    .lines()
    .map(|line| {
        let mut fields = line.split_whitespace().map(str::to_owned);
        Line {
            oid: fields.next().unwrap_or_default(),
            parents: fields.collect(),
        }
    })
    .collect();
    for (index, oid) in topo.iter().enumerate() {
        let parents = graph
            .iter()
            .find(|line| &line.oid == oid)
            .map(|line| line.parents.clone())
            .unwrap_or_default();
        for parent in parents {
            if let Some(position) = topo.iter().position(|seen| *seen == parent) {
                assert!(position < index, "{parent} precedes {oid}");
            }
        }
    }
    assert!(
        topo.iter().position(|oid| *oid == feature_oid).unwrap_or(9)
            < topo.iter().position(|oid| *oid == merge_oid).unwrap_or(0),
        "the parent precedes the merge topologically: {topo:?}"
    );

    let run = run_time(repo.path(), &["seal", "--range", &range], &[]);
    assert!(run.status.success(), "{}", text(&run.stderr));
    let lines: Vec<String> = text(&run.stdout).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 4, "{:?}", lines);

    let sealed: Vec<String> = lines
        .iter()
        .map(|line| {
            assert!(line.starts_with("sealed "), "{line}");
            git_stdout_in(
                &repo,
                &["rev-parse", line.split_whitespace().nth(1).expect("oid")],
            )
        })
        .collect();

    // The printed order is the topological one: each commit is printed in the
    // place its source holds.
    for (sealed, source) in sealed.iter().zip(&topo) {
        assert_eq!(
            repo.snapshot(sealed).tree,
            repo.snapshot(source).tree,
            "printed in topological order"
        );
    }
    assert_eq!(repo.snapshot(&sealed[0]).parents, vec![base.clone()]);
    assert_eq!(repo.snapshot(&sealed[1]).parents, vec![base]);
    // The merge keeps both parents, in order.
    let sealed_merge = &sealed[2];
    assert_eq!(
        repo.snapshot(sealed_merge).parents,
        vec![main_tip, feature_oid.clone()]
    );
    assert_eq!(repo.snapshot(&sealed[3]).parents, vec![merge_oid.clone()]);
    assert_eq!(
        repo.snapshot(sealed_merge).tree,
        repo.snapshot(&merge_oid).tree
    );
    assert_eq!(repo.head(), sealed[3]);
    assert_eq!(repo.status(), "");
}

/// Commit `message` with an explicit committer and author date.
fn commit_at(repo: &Repo, message: &str, date: &str) -> String {
    git_env(
        repo.path(),
        &[
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            message,
            "--date",
            date,
        ],
        &[("GIT_COMMITTER_DATE", date), ("GIT_TIME_SKIP", "1")],
    );
    repo.head()
}

#[test]
fn a_failed_seal_with_warn_leaves_the_commit_and_exits_zero() {
    let repo = Repo::with_down_tsa();
    let base = repo.head();
    let expected = shape(repo.snapshot(&base).tree, vec![base]);

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "warned"],
        b"",
    );
    let stderr = assert_said(&output);
    assert!(stderr.contains("under quorum"), "{stderr}");
    assert!(stderr.contains("see git time verify"), "{stderr}");

    // The commit survives with a block of failure records, and git is happy.
    let head = repo.head();
    assert_rewrite(&repo, &head, &expected);
}

/// Two configured authorities, neither with a readable anchor: the commit is
/// made, nothing is sealed, and every authority gets its own line.
///
/// The exact shape of defect 1: one unreadable bundle must not swallow the
/// warning for the others, and `warn` must still leave the commit alone.
#[test]
fn missing_anchors_leave_the_commit_unsealed_with_one_line_per_authority() {
    let repo = Repo::new();
    let base = repo.head();
    let expected = shape(repo.snapshot(&base).tree, vec![base.clone()]);
    for (id, url) in [("stub", None), ("other", Some("http://127.0.0.1:1/tsr"))] {
        if let Some(url) = url {
            git(repo.path(), &["config", &format!("time.tsa.{id}.url"), url]);
        }
        git(
            repo.path(),
            &[
                "config",
                &format!("time.tsa.{id}.anchor"),
                &pstr(&repo.path().join(format!("gone-{id}.pem"))),
            ],
        );
    }

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "unanchored"],
        b"",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));

    let stderr = text(&output.stderr);
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 2, "one line per authority: {stderr:?}");
    assert!(
        lines
            .iter()
            .any(|line| line.contains("stub") && line.contains("gone-stub.pem")),
        "{stderr}"
    );
    assert!(
        lines
            .iter()
            .all(|line| line.starts_with("rfc3161: seal failed: ")),
        "{stderr}"
    );
    assert!(lines.iter().any(|line| line.contains("other")), "{stderr}");

    let head = repo.head();
    assert_ne!(head, base, "the commit was made");
    assert_eq!(repo.blocks(&head), 0, "and is untouched");
    assert_rewrite_count(&repo, &head, &expected, 0);
}

/// Wire `post-commit` so a wrapper records the hook's exit status, the way a
/// caller that honours `on-failure = fail` sees it (git itself ignores it).
fn wire_status_hook(repo: &Repo, status: &Path, stderr: &Path) {
    let hook = repo.path().join(".git").join("hooks").join("post-commit");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\n{} hook post-commit 2>>{}\necho $? > {}\n",
            quote(BIN),
            quote(&pstr(stderr)),
            quote(&pstr(status))
        ),
    )
    .expect("write hook");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
            .expect("chmod hook");
    }
}

#[test]
fn a_failed_seal_with_fail_exits_three() {
    let repo = Repo::with_down_tsa();
    // A fresh, unsealed commit: the base commit already carries its failure
    // block, and a second attempt would just be `AlreadySealed`.
    git_env(
        repo.path(),
        &["commit", "--allow-empty", "-m", "failing"],
        &[("GIT_TIME_SKIP", "1")],
    );
    git(repo.path(), &["config", "time.on-failure", "fail"]);
    let scratch = TempDir::new().expect("scratch dir");
    let status = scratch.path().join("hook.status");
    let stderr_file = scratch.path().join("hook.stderr");
    wire_status_hook(&repo, &status, &stderr_file);
    let oid = repo.head();
    let expected = shape(repo.snapshot(&oid).tree, vec![oid.clone()]);

    // Through a real `git commit`: git ignores the hook's status, so the
    // wrapper records it and the commit has to exist either way.
    git(repo.path(), &["config", "commit.gpgsign", "false"]);
    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "committed while down"],
        b"",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));

    assert_eq!(
        std::fs::read_to_string(&status)
            .expect("status recorded")
            .trim(),
        "3",
        "the hook exits 3 under `fail`"
    );
    let line = std::fs::read_to_string(&stderr_file).expect("stderr recorded");
    assert_eq!(line.lines().count(), 1, "exactly one line: {line:?}");
    assert!(line.starts_with("rfc3161: sealed "), "{line}");
    assert!(line.contains("under quorum (0 of 1)"), "{line}");

    // The commit exists and now carries the failure block.
    let head = repo.head();
    assert_ne!(head, oid);
    assert_eq!(head.len(), 40);
    assert_rewrite(&repo, &head, &expected);
}

#[test]
fn a_total_outage_without_failure_records_is_loud_under_fail() {
    let repo = Repo::with_down_tsa();
    git_env(
        repo.path(),
        &["commit", "--allow-empty", "-m", "failing"],
        &[("GIT_TIME_SKIP", "1")],
    );
    git(repo.path(), &["config", "time.on-failure", "fail"]);
    git(repo.path(), &["config", "time.record-failures", "false"]);
    let scratch = TempDir::new().expect("scratch dir");
    let status = scratch.path().join("hook.status");
    let stderr_file = scratch.path().join("hook.stderr");
    wire_status_hook(&repo, &status, &stderr_file);

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "no evidence"],
        b"",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));

    // Nothing was written, so the seal is `Skipped(NoTokensRecorded)` — and
    // that is a failure, not the silence of a skip.
    assert_eq!(
        std::fs::read_to_string(&status)
            .expect("status recorded")
            .trim(),
        "3"
    );
    let line = std::fs::read_to_string(&stderr_file).expect("stderr recorded");
    assert_eq!(line.lines().count(), 1, "exactly one line: {line:?}");
    assert_eq!(
        line.trim(),
        "rfc3161: seal failed: no TSA answered (no tokens recorded)"
    );
    let head = repo.head();
    assert_eq!(repo.blocks(&head), 0, "the commit is untouched");
}

#[test]
fn a_total_outage_without_failure_records_is_loud_under_warn_too() {
    let repo = Repo::with_down_tsa();
    git_env(
        repo.path(),
        &["commit", "--allow-empty", "-m", "failing"],
        &[("GIT_TIME_SKIP", "1")],
    );
    git(repo.path(), &["config", "time.record-failures", "false"]);
    let scratch = TempDir::new().expect("scratch dir");
    let status = scratch.path().join("hook.status");
    let stderr_file = scratch.path().join("hook.stderr");
    wire_status_hook(&repo, &status, &stderr_file);

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "no evidence"],
        b"",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(
        std::fs::read_to_string(&status)
            .expect("status recorded")
            .trim(),
        "0",
        "warn never turns non-zero"
    );
    let line = std::fs::read_to_string(&stderr_file).expect("stderr recorded");
    assert_eq!(line.lines().count(), 1, "exactly one line: {line:?}");
    assert!(line.contains("seal failed: no TSA answered"), "{line}");
    assert_eq!(repo.blocks(&repo.head()), 0);
}

/// Run the hook with a `git` ahead of the real one on `PATH` that answers the
/// second `refs/heads/main` lookup with `stale`, so HEAD looks moved.
fn run_hook_with_moved_head(repo: &Repo, stale: &str) -> Output {
    let real = text(
        &Command::new("sh")
            .args(["-c", "command -v git"])
            .output()
            .expect("resolves git")
            .stdout,
    )
    .trim()
    .to_owned();
    let dir = TempDir::new().expect("shim dir");
    let count = dir.path().join("count");
    let script = dir.path().join("git");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nfor arg in \"$@\"; do\n\
             if [ \"$arg\" = refs/heads/main ]; then\n\
             n=$(cat {count} 2>/dev/null || echo 0)\n\
             n=$((n+1))\n echo \"$n\" > {count}\n\
             if [ \"$n\" -ge 2 ]; then echo {stale}; exit 0; fi\n\
             fi\ndone\nexec {real} \"$@\"\n",
            count = quote(&pstr(&count)),
            stale = quote(stale),
            real = quote(&real),
        ),
    )
    .expect("write shim");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod shim");
    }
    let path = format!(
        "{}:{}",
        pstr(dir.path()),
        std::env::var("PATH").unwrap_or_default()
    );
    run_time(repo.path(), &["hook", "post-commit"], &[("PATH", &path)])
}

#[test]
fn a_head_that_moved_is_loud_and_exits_three_under_fail() {
    let repo = Repo::new();
    let base = repo.head();
    git_env(
        repo.path(),
        &["commit", "--allow-empty", "-m", "raced"],
        &[("GIT_TIME_SKIP", "1")],
    );
    git(repo.path(), &["config", "time.on-failure", "fail"]);
    let expected = shape(repo.snapshot("HEAD").tree, repo.snapshot("HEAD").parents);

    // The stale answer is the base commit, so the seal is told HEAD is there.
    let direct = run_hook_with_moved_head(&repo, &base);
    assert_eq!(direct.status.code(), Some(3), "{}", text(&direct.stderr));
    assert_eq!(
        text(&direct.stderr).trim(),
        "rfc3161: seal failed: HEAD moved while sealing"
    );
    assert_eq!(text(&direct.stderr).lines().count(), 1, "one line");
    // HEAD itself never moved, and the commit is untouched.
    let head = repo.head();
    assert_ne!(head, base);
    assert_eq!(repo.blocks(&head), 0);
    assert_rewrite_count(&repo, &head, &expected, 0);
}

#[test]
fn a_head_that_moved_is_silently_tolerated_under_warn() {
    let repo = Repo::new();
    let base = repo.head();
    git_env(
        repo.path(),
        &["commit", "--allow-empty", "-m", "raced"],
        &[("GIT_TIME_SKIP", "1")],
    );
    let direct = run_hook_with_moved_head(&repo, &base);
    assert_eq!(direct.status.code(), Some(0), "{}", text(&direct.stderr));
    assert!(text(&direct.stderr).contains("seal failed: HEAD moved"));
    assert_eq!(repo.blocks(&repo.head()), 0);
}

#[test]
fn a_signed_commit_stays_signed_after_the_seal() {
    let repo = Repo::new();
    let key = signing_key();
    git(repo.path(), &["config", "user.signingkey", key]);
    git(repo.path(), &["config", "gpg.format", "openpgp"]);
    git(repo.path(), &["config", "commit.gpgsign", "true"]);
    let base = repo.head();
    let expected = shape(repo.snapshot(&base).tree, vec![base]);

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "signed"],
        b"",
    );
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");
    let head = repo.head();
    assert!(
        repo.object(&head).contains("\ngpgsig "),
        "the signature is kept: {}",
        repo.object(&head)
    );
    git(repo.path(), &["verify-commit", "HEAD"]);
    assert_rewrite(&repo, &head, &expected);

    // `--force` rebuilds the object; it must sign it again, not keep a stale
    // signature over the new message.
    let forced = run_time(repo.path(), &["seal", "--force"], &[]);
    assert!(forced.status.success(), "{}", text(&forced.stderr));
    let forced_head = repo.head();
    assert_ne!(forced_head, head);
    assert_eq!(repo.blocks(&forced_head), 1);
    assert!(repo.is_sealed(&forced_head));
    git(repo.path(), &["verify-commit", "HEAD"]);
}

#[test]
fn seal_range_walks_oldest_first_and_seals_each_commit() {
    let repo = Repo::new();
    // Unsealed commits: every one of them is made with the hook switched off.
    for message in ["one", "two", "three", "four"] {
        git_env(
            repo.path(),
            &["commit", "--allow-empty", "-m", message],
            &[("GIT_TIME_SKIP", "1")],
        );
    }
    for index in 0..4 {
        let rev = format!("HEAD~{index}");
        assert!(!repo.is_sealed(&rev), "the fixture is unsealed");
    }

    let range = "HEAD~3..HEAD";
    // Newest first, as `rev-list` prints it.
    let wanted: Vec<String> = text(&git(repo.path(), &["rev-list", range]))
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(wanted.len(), 3);
    let base = git_stdout_in(&repo, &["rev-parse", "HEAD~3"]);

    let run = run_time(repo.path(), &["seal", "--range", range], &[]);
    assert!(run.status.success(), "{}", text(&run.stderr));
    let lines: Vec<String> = text(&run.stdout).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 3, "{:?}", lines);

    // Each line names the object that now carries the evidence.
    let sealed: Vec<String> = lines
        .iter()
        .map(|line| {
            assert!(line.starts_with("sealed "), "{line}");
            let short = line.split_whitespace().nth(1).expect("`sealed <oid> by`");
            git_stdout_in(&repo, &["rev-parse", short])
        })
        .collect();
    for (sealed, original) in sealed.iter().zip(wanted.iter().rev()) {
        assert_ne!(sealed, original, "the commit was rewritten");
        assert_eq!(repo.blocks(sealed), 1, "{sealed}");
        assert!(repo.is_sealed(sealed), "{sealed}");
    }

    // Oldest first: the first seal hangs off the base, and each following one
    // off the commit its source had for a parent.
    assert_eq!(repo.snapshot(&sealed[0]).parents, vec![base]);
    assert_eq!(repo.snapshot(&sealed[1]).parents, vec![wanted[2].clone()]);
    assert_eq!(repo.snapshot(&sealed[2]).parents, vec![wanted[1].clone()]);
    // The range's tip is the branch tip: the branch moved to its sealed form.
    assert_eq!(repo.head(), sealed[2]);
    assert_eq!(repo.status(), "");
    // The older sealed objects are deliberately unreachable, so fsck may call
    // them dangling; it must still succeed.
    assert!(repo.fsck().status.success());
}

/// Run git in `repo` and return trimmed stdout, asserting success.
fn git_stdout_in(repo: &Repo, args: &[&str]) -> String {
    text(&git(repo.path(), args)).trim().to_owned()
}

#[test]
fn a_detached_head_commit_is_sealed() {
    let repo = Repo::new();
    let base = repo.head();
    git(repo.path(), &["checkout", "-q", "--detach", &base]);
    let expected = shape(repo.snapshot("HEAD").tree, vec![base]);

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "detached"],
        b"",
    );
    let said = assert_said(&output);
    assert!(said.starts_with("rfc3161: sealed "), "{said}");

    let head = repo.head();
    let symbolic = git_output(repo.path(), &["symbolic-ref", "-q", "HEAD"], b"");
    assert!(!symbolic.status.success(), "still detached");
    assert_eq!(text(&symbolic.stdout).trim(), "");
    assert_rewrite(&repo, &head, &expected);
}

#[test]
fn seal_without_a_range_seals_head_and_reports_a_second_run() {
    let repo = Repo::new();
    let oid = repo.commit("manual");
    assert!(repo.is_sealed(&oid));

    let again = run_time(repo.path(), &["seal"], &[]);
    assert!(again.status.success(), "{}", text(&again.stderr));
    assert!(
        text(&again.stdout).contains(&format!("already sealed {}", &oid[..7])),
        "{}",
        text(&again.stdout)
    );
}

#[test]
fn seal_force_replaces_the_evidence() {
    let repo = Repo::new();
    let oid = repo.commit("forced");
    let old_tokens = repo
        .object(&oid)
        .lines()
        .filter(|line| line.starts_with("X-RFC3161-Token:"))
        .count();
    assert_eq!(old_tokens, 1, "the fixture carries one token");

    let forced = run_time(repo.path(), &["seal", "--force"], &[]);
    assert!(forced.status.success(), "{}", text(&forced.stderr));
    assert!(
        text(&forced.stdout).contains("sealed "),
        "{}",
        text(&forced.stdout)
    );

    // The imprint is over the pre-image and therefore the same; the fresh
    // token is what changes, and it replaces the old one instead of stacking.
    let head = repo.head();
    assert_ne!(head, oid);
    assert_eq!(repo.blocks(&head), 1, "one block, not two");
    assert!(repo.is_sealed(&head));
    assert!(repo.object(&head).contains("X-RFC3161-Object: "));
    assert_eq!(repo.status(), "");
    assert!(repo.fsck().status.success());
}

#[test]
fn seal_rejects_an_unknown_range() {
    let repo = Repo::new();
    let output = run_time(repo.path(), &["seal", "--range", "nope..HEAD"], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("rev-list"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn seal_outside_a_repository_exits_two() {
    let dir = TempDir::new().expect("temp dir");
    let output = run_time(dir.path(), &["seal"], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("not a git repository"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn the_version_is_printed() {
    let output = Command::new(BIN).arg("--version").output().expect("runs");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        text(&output.stdout).contains(env!("CARGO_PKG_VERSION")),
        "{}",
        text(&output.stdout)
    );
}

#[test]
fn a_bare_authority_subcommand_shows_its_usage() {
    let output = Command::new(BIN).arg("tsa").output().expect("runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        text(&output.stderr).contains("Usage:"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn an_authority_subcommand_shows_its_help() {
    let cases: [&[&str]; 3] = [
        &["tsa", "--help"],
        &["tsa", "add", "--help"],
        &["anchor", "pin", "--help"],
    ];
    for args in cases {
        let output = Command::new(BIN).args(args).output().expect("runs");
        assert!(
            output.status.success(),
            "{args:?}: {}",
            text(&output.stderr)
        );
        assert!(
            text(&output.stdout).contains("Usage:"),
            "{args:?}: {}",
            text(&output.stdout)
        );
    }
    // A missing required argument is a usage error, not a panic.
    let missing = Command::new(BIN)
        .args(["tsa", "add"])
        .output()
        .expect("runs");
    assert_eq!(missing.status.code(), Some(2));
    assert!(
        text(&missing.stderr).contains("Usage:"),
        "{}",
        text(&missing.stderr)
    );
}

/// The quick start is the whole onboarding: a first-time reader needs the two
/// setup commands, the commit, and the judge. It has to show on the short help
/// too, because that is the one people actually type.
#[test]
fn both_help_forms_carry_the_quick_start() {
    for flag in ["-h", "--help"] {
        let output = Command::new(BIN).arg(flag).output().expect("runs");
        assert!(output.status.success(), "{flag}");
        let stdout = text(&output.stdout);
        for line in [
            "Quick start:",
            "git time tsa select",
            "git time install",
            "git time verify",
            "docs/manual.md",
        ] {
            assert!(stdout.contains(line), "{flag} lacks {line}: {stdout}");
        }
    }
}

/// A tool asked to be auditable must be able to name itself: version, author,
/// licence, source. `-V` is the flag people actually use.
#[test]
fn the_version_line_names_the_provenance() {
    for flag in ["-V", "--version"] {
        let output = Command::new(BIN).arg(flag).output().expect("runs");
        assert!(output.status.success(), "{flag}");
        let stdout = text(&output.stdout);
        for part in [
            "git time ",
            "Copyright (C) 2026 Roland Moriz",
            "GPL-2.0-only",
            "https://github.com/rmoriz/git-time",
        ] {
            assert!(stdout.contains(part), "{flag} lacks {part}: {stdout}");
        }
    }
}

/// The stub is a TSA, not a rubber stamp: what it issued answers exactly the
/// imprint of the pre-image, and the seal records it under the `stub` id.
#[test]
fn the_evidence_names_the_imprint_and_the_issuer() {
    let repo = Repo::new();
    let oid = repo.commit("evidence");

    let object = repo.object(&oid);
    let imprint = object
        .lines()
        .find_map(|line| line.strip_prefix("X-RFC3161-Imprint: "))
        .expect("an imprint");
    let pre = CommitObject::parse(object.as_bytes())
        .expect("parses")
        .pre_image(store::PREFIX);
    let expected = digest(Alg::Sha256, &pre.bytes);
    assert_eq!(
        format!("sha256:{}", hex(&expected)),
        imprint,
        "the imprint is over the pre-image, algorithm included"
    );
    assert!(object.contains("id=stub;"), "the stub issued it: {object}");
    assert!(object.contains("X-RFC3161-Object: "), "{object}");
    assert_eq!(repo.blocks(&oid), 1);
}

/// Lower-case hex of a digest.
fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
