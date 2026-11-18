//! `git time verify` and `git time log`, end to end.
//!
//! The harness is copied from `hook_flows.rs`: its helpers are private to that
//! integration-test binary, so a trimmed form of the same throwaway authority,
//! stub TSA, insulated repository and GPG key lives here rather than in a third
//! module. It mints genuine tokens with `openssl ts -reply` for the request in
//! flight and pins the throwaway CA made for the run, so no verdict is reached
//! on fixture bytes that were not issued here.
//!
//! The certificates are built for LibreSSL as well as OpenSSL: `-sha256` and a
//! named curve, because LibreSSL's defaults (SHA-1 signatures, explicit EC
//! parameters) are outside what `webpki` verifies, and a per-CA serial file
//! because `-CAcreateserial` writes into the shared temp directory and races
//! between parallel fixtures.
//!
//! The repository is hermetic (`GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` at
//! `/dev/null`, `GNUPGHOME` in a temp dir, `GIT_DIR`/`GIT_WORK_TREE` cleared)
//! and every case checks the read-only contract where it matters: `verify` adds
//! no stub hit and leaves the ref, the index and the worktree alone.

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
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

/// The binary under test, built by cargo for this integration test.
const BIN: &str = env!("CARGO_BIN_EXE_git-time");

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
    child.wait_with_output().expect("waits for git")
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
fn run_time(dir: &Path, args: &[&str]) -> Output {
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
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.output().expect("runs the binary")
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
            "/CN=verify-cli-ca",
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
            "-pkeyopt",
            "ec_param_enc:named_curve",
            "-nodes",
            "-keyout",
            &pstr(&leaf_key),
            "-out",
            &pstr(&leaf_csr),
            "-subj",
            "/CN=verify-cli-tsa",
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

// --- stub authority -----------------------------------------------------

#[derive(Clone)]
struct StubState {
    authority: Arc<Authority>,
    hits: Arc<AtomicUsize>,
}

/// A stub authority on a loopback port that mints real tokens for the requests
/// it receives.
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
        // Generous: the suite runs dozens of repositories at once and a 5s
        // budget has expired under CI load. See hook_flows.rs.
        git(&path, &["config", "time.deadline", "30s"]);
        git(&path, &["config", "time.tsa.stub.timeout", "30s"]);
        self.wire("post-commit", "post-commit");
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

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Point the configured TSA at a live stub and pin its throwaway CA.
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

    /// Forget the anchor: every token becomes `untrusted`.
    fn drop_anchor(&self) {
        git(
            self.path(),
            &[
                "config",
                "time.tsa.stub.anchor",
                &pstr(&self.path().join("missing-anchor.pem")),
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

    /// Commit without trusting the hook, so it stays unsealed.
    fn commit_unsealed(&self, message: &str) -> String {
        let name = format!("{}.txt", message.replace(' ', "-"));
        std::fs::write(self.path().join(&name), message).expect("write file");
        git(self.path(), &["add", &name]);
        git_env(
            self.path(),
            &["commit", "-q", "-m", message],
            &[("GIT_TIME_SKIP", "1")],
        );
        self.head()
    }

    /// The raw commit object `rev` names.
    fn object(&self, rev: &str) -> String {
        text(&git(self.path(), &["cat-file", "commit", rev]))
    }

    /// Replace the object `rev` names with `edit`'s rewrite of its bytes and put
    /// the branch on the result; returns the new id.
    fn rewrite(&self, rev: &str, edit: impl Fn(&str) -> String) -> String {
        let before = self.object(rev);
        let after = edit(&before);
        assert_ne!(after, before, "the rewrite changed something");
        let oid = self.hash_object("commit", after.as_bytes());
        git(self.path(), &["update-ref", "HEAD", &oid]);
        oid
    }

    /// Write `bytes` into the object database as an object of `kind` and return
    /// its id.
    fn hash_object(&self, kind: &str, bytes: &[u8]) -> String {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(self.path())
            .args(["hash-object", "-w", "--literally", "-t", kind, "--stdin"])
            .envs(insulated_env().iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawns git");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(bytes)
            .expect("writes the object");
        let output = child.wait_with_output().expect("waits for git");
        assert!(
            output.status.success(),
            "hash-object failed: {}",
            text(&output.stderr)
        );
        text(&output.stdout).trim().to_owned()
    }

    /// The value the running verify calls the seam between pre-image and trailer.
    fn trailer_seam(object: &str) -> usize {
        object
            .find("\n\nX-RFC3161-")
            .map(|index| index + 1)
            .expect("a sealed commit has a trailer block")
    }

    fn status(&self) -> String {
        text(&git(self.path(), &["status", "--porcelain"]))
    }
}

/// Quote a path for `sh`.
fn quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', r#"'\''"#))
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The number of objects reachable from every ref: the visible history.
fn visible_objects(repo: &Repo) -> usize {
    text(&git(repo.path(), &["rev-list", "--objects", "--all"]))
        .lines()
        .count()
}

/// Every ref and its target, as one comparable block.
fn refs(repo: &Repo) -> String {
    text(&git(repo.path(), &["for-each-ref"]))
}

/// Run the verifier against `rev` and return the process output.
fn verify(repo: &Repo, rev: &str, extra: &[&str]) -> Output {
    let mut args = vec!["verify"];
    args.extend_from_slice(extra);
    args.push(rev);
    run_time(repo.path(), &args)
}

/// The human lines of a verify run, stdout first and stderr appended.
fn lines(output: &Output) -> Vec<String> {
    let mut all: Vec<String> = text(&output.stdout).lines().map(str::to_owned).collect();
    all.extend(text(&output.stderr).lines().map(str::to_owned));
    all
}

/// The first line of a verify run, which carries the verdict.
fn first_line(output: &Output) -> String {
    lines(output).into_iter().next().unwrap_or_default()
}

/// Parse a verify `--json` run.
fn json_commits(output: &Output) -> Vec<Value> {
    let doc: Value = serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    doc.get("commits")
        .and_then(Value::as_array)
        .expect("`commits` is an array")
        .clone()
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
            "Verify Test <verify@example.com>",
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

/// Configure `repo` to sign commits with the throwaway key.
fn sign_here(repo: &Repo) {
    let key = signing_key();
    git(repo.path(), &["config", "user.signingkey", key]);
    git(repo.path(), &["config", "gpg.format", "openpgp"]);
    git(repo.path(), &["config", "commit.gpgsign", "true"]);
}

// --- cases --------------------------------------------------------------

/// A sealed commit passes, and verifying it costs no stub request.
#[test]
fn a_sealed_commit_passes_without_touching_the_network() {
    let repo = Repo::new();
    let oid = repo.head();
    let hits = repo.hits();
    assert_eq!(hits, 1, "only the base commit was stamped");

    let output = verify(&repo, &oid, &[]);
    let line = first_line(&output);
    assert_eq!(output.status.code(), Some(0), "{line}");
    assert!(line.starts_with(&format!("PASS {} SEALED 1/1 TSA(s)", &oid[..7])));
    assert!(text(&output.stdout).lines().count() == 1, "{line}");
    assert_eq!(repo.hits(), hits, "verify never calls a TSA");
    assert_eq!(repo.head(), oid, "the ref is untouched");
    assert_eq!(repo.status(), "");
}

/// A message rewritten after the seal no longer matches its imprint.
#[test]
fn a_tampered_message_is_a_bad_imprint() {
    let repo = Repo::new();
    let oid = repo.rewrite(&repo.head(), |object| {
        // Change the message body, leaving the trailer block in place.
        object.replacen("\n\nbase\n", "\n\nbase, edited\n", 1)
    });

    let output = verify(&repo, &oid, &[]);
    let line = first_line(&output);
    assert_eq!(output.status.code(), Some(1), "{line}");
    assert!(line.contains("BAD-IMPRINT"), "{line}");
    assert!(line.starts_with("FAIL "), "{line}");
}

/// An unsealed commit passes by default and fails under `--require-sealed`.
#[test]
fn an_unsealed_commit_passes_unless_a_seal_is_required() {
    let repo = Repo::new();
    let oid = repo.commit_unsealed("plain");

    let output = verify(&repo, &oid, &[]);
    let line = first_line(&output);
    assert_eq!(output.status.code(), Some(0), "{line}");
    assert!(line.contains("UNSEALED"), "{line}");
    assert!(line.starts_with("PASS "), "{line}");
    let free = json_commits(&verify(&repo, &oid, &["--json"]));
    assert_eq!(free[0]["verdict"], "unsealed", "{free:?}");
    assert_eq!(free[0]["pass"], true, "{free:?}");
    assert_eq!(free[0]["gates"], json!([]), "{free:?}");
    assert_eq!(free[0]["required"], 1, "{free:?}");

    let required = verify(&repo, &oid, &["--require-sealed"]);
    let line = first_line(&required);
    assert_eq!(required.status.code(), Some(1), "{line}");
    assert!(line.starts_with("FAIL "), "{line}");
    assert!(line.contains("(REQUIRE-SEALED)"), "{line}");
    let gated = json_commits(&verify(&repo, &oid, &["--require-sealed", "--json"]));
    assert_eq!(gated[0]["verdict"], "unsealed", "{gated:?}");
    assert_eq!(gated[0]["pass"], false, "a gate cannot be read as success");
    assert_eq!(gated[0]["gates"], json!(["require-sealed"]), "{gated:?}");
    assert_eq!(gated[0]["required"], 1, "{gated:?}");
}

/// A dropped commit says so, and `--require-sealed` rejects it.
#[test]
fn a_dropped_commit_is_unsealed_and_says_dropped() {
    let repo = Repo::new();
    let drop = run_time(repo.path(), &["drop"]);
    assert!(drop.status.success(), "{}", text(&drop.stderr));
    let oid = repo.head();
    git(repo.path(), &["commit", "--allow-empty", "-m", "dropped"]);
    let dropped = repo.head();
    assert_ne!(dropped, oid);

    let output = verify(&repo, &dropped, &["--require-sealed"]);
    let line = first_line(&output);
    assert_eq!(output.status.code(), Some(1), "{line}");
    assert!(line.contains("UNSEALED (dropped"), "{line}");
}

/// A token whose TSA has no pinned anchor is untrusted.
#[test]
fn a_missing_anchor_is_untrusted() {
    let repo = Repo::new();
    let oid = repo.head();
    repo.drop_anchor();

    let output = verify(&repo, &oid, &[]);
    let line = first_line(&output);
    assert_eq!(output.status.code(), Some(1), "{line}");
    assert!(line.contains("UNTRUSTED"), "{line}");
    let all = lines(&output);
    assert!(
        all.iter().any(|line| line.contains("untrusted")),
        "the reason is named: {all:?}"
    );
}

/// A broken signature fails even though the token answers the imprint.
#[test]
fn a_bad_signature_is_bad_sig_with_a_valid_token() {
    let repo = Repo::new();
    sign_here(&repo);
    let oid = repo.commit("signed");
    // Corrupt one base64 character inside the armour, not its markers.
    let oid = repo.rewrite(&oid, |object| {
        let mut lines: Vec<String> = object.lines().map(str::to_owned).collect();
        for line in &mut lines {
            // Armour body lines are continuation lines: the byte to corrupt is
            // the tenth one *after* git's leading space.
            let start = usize::from(line.starts_with(' '));
            let content = &line[start..];
            if content.len() > 20
                && !content.contains(' ')
                && !content.starts_with("-----")
                && !content.starts_with('=')
            {
                let mut bytes = line.as_bytes().to_vec();
                let at = start + 10;
                bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
                *line = String::from_utf8(bytes).expect("ascii");
                break;
            }
        }
        let mut text = lines.join("\n");
        text.push('\n');
        text
    });

    let output = verify(&repo, &oid, &[]);
    let line = first_line(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{line}\n{}",
        text(&output.stderr)
    );
    assert!(line.contains("BAD-SIG"), "{line}");
    let evidence = json_commits(&verify(&repo, &oid, &["--json"]));
    assert_eq!(evidence[0]["signature"], "bad");
    // The token is still valid: the verdict comes from the signature override,
    // not from the token having stopped verifying.
    assert_eq!(
        evidence[0]["per_tsa"][0]["verdict"], "valid",
        "{evidence:?}"
    );
    assert_eq!(evidence[0]["valid"], 1, "{evidence:?}");
    assert_eq!(evidence[0]["pass"], false, "{evidence:?}");
}

/// A valid token on an unsigned commit is sealed; `--require-signed` is not.
#[test]
fn a_valid_token_without_a_signature_is_sealed_but_unsigned() {
    let repo = Repo::new();
    let oid = repo.head();

    let output = verify(&repo, &oid, &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let evidence = json_commits(&output);
    assert_eq!(evidence[0]["verdict"], "sealed");
    assert_eq!(evidence[0]["signature"], "unsigned");
    assert_eq!(evidence[0]["pass"], true, "{evidence:?}");
    assert_eq!(evidence[0]["gates"], json!([]), "{evidence:?}");

    let required = verify(&repo, &oid, &["--require-signed"]);
    let line = first_line(&required);
    assert_eq!(required.status.code(), Some(1), "{line}");
    assert!(line.starts_with("FAIL "), "{line}");
    assert!(line.contains("REQUIRE-SIGNED"), "{line}");
    let gated = json_commits(&verify(&repo, &oid, &["--require-signed", "--json"]));
    assert_eq!(gated[0]["verdict"], "sealed", "a gate is not a verdict");
    assert_eq!(gated[0]["pass"], false, "{gated:?}");
    assert_eq!(gated[0]["gates"], json!(["require-signed"]), "{gated:?}");
}

/// A short quorum fails and names the silent TSA.
#[test]
fn a_short_quorum_is_under_quorum_with_reasons() {
    let repo = Repo::with_down_tsa();
    git(repo.path(), &["config", "time.required", "2"]);
    let oid = repo.head();

    let output = verify(&repo, &oid, &[]);
    let all = lines(&output);
    assert_eq!(output.status.code(), Some(1), "{all:?}");
    assert!(all[0].contains("UNDER-QUORUM"), "{all:?}");
    assert!(all[0].contains("0/2 TSA(s)"), "{all:?}");
    assert!(
        all.iter()
            .any(|line| line.contains("stub") && line.contains("fail")),
        "the failing TSA is named: {all:?}"
    );
}

/// One valid token below a quorum of two is under-quorum (the boundary: some
/// evidence, not enough).
#[test]
fn one_valid_token_below_the_quorum_is_under_quorum() {
    let repo = Repo::new();
    git(repo.path(), &["config", "time.required", "2"]);
    let oid = repo.head();

    let output = verify(&repo, &oid, &[]);
    let all = lines(&output);
    assert_eq!(output.status.code(), Some(1), "{all:?}");
    assert!(all[0].contains("UNDER-QUORUM"), "{all:?}");
    assert!(all[0].contains("1/2 TSA(s)"), "{all:?}");
    let evidence = json_commits(&verify(&repo, &oid, &["--json"]));
    assert_eq!(evidence[0]["verdict"], "under-quorum", "{evidence:?}");
    assert_eq!(evidence[0]["valid"], 1, "{evidence:?}");
    assert_eq!(evidence[0]["required"], 2, "{evidence:?}");
    assert_eq!(
        evidence[0]["per_tsa"][0]["verdict"], "valid",
        "the one good token is still reported: {evidence:?}"
    );
}

/// A token that fails for a reason other than trust is `BadToken`, and the
/// block still decodes: the token's declared imprint algorithm is patched while
/// the imprint line is recomputed, so only the token mismatches.
#[test]
fn a_token_answering_a_different_imprint_is_bad_token() {
    let repo = Repo::new();
    let oid = repo.rewrite(&repo.head(), |object| {
        let seam = Repo::trailer_seam(object);
        let pre_image = &object[..seam];
        let mut lines: Vec<String> = object.lines().map(str::to_owned).collect();
        for line in &mut lines {
            if let Some(rest) = line.strip_prefix("X-RFC3161-Token: ") {
                *line = format!(
                    "X-RFC3161-Token: {}",
                    rest.replace("alg=sha256", "alg=sha512")
                );
            }
        }
        let imprint = hex(&Sha256::digest(pre_image.as_bytes()));
        for line in &mut lines {
            if line.starts_with("X-RFC3161-Imprint: ") {
                *line = format!("X-RFC3161-Imprint: sha256:{imprint}");
            }
        }
        let mut text = lines.join("\n");
        text.push('\n');
        text
    });

    let output = verify(&repo, &oid, &[]);
    let all = lines(&output);
    assert_eq!(output.status.code(), Some(1), "{all:?}");
    assert!(all[0].contains("BAD-TOKEN"), "{all:?}");
    let evidence = json_commits(&verify(&repo, &oid, &["--json"]));
    assert_eq!(evidence[0]["verdict"], "bad-token", "{evidence:?}");
    assert_eq!(
        evidence[0]["per_tsa"][0]["verdict"], "imprint",
        "the reason is the imprint, not trust: {evidence:?}"
    );
}

/// A block that does not decode is `BadToken`; it never falls through to
/// `Unsealed` or `Sealed`.
#[test]
fn a_malformed_block_is_bad_token() {
    let repo = Repo::new();
    let oid = repo.rewrite(&repo.head(), |object| {
        object.replacen("X-RFC3161-Imprint: ", "X-RFC3161-Imprint:", 1)
    });

    let output = verify(&repo, &oid, &[]);
    let all = lines(&output);
    assert_eq!(output.status.code(), Some(1), "{all:?}");
    assert!(all[0].contains("BAD-TOKEN"), "{all:?}");
    assert!(!all[0].contains("SEALED"), "{all:?}");
    assert!(
        all.iter().any(|line| line.contains("cannot be read")),
        "the malformed block is named: {all:?}"
    );
    let evidence = json_commits(&verify(&repo, &oid, &["--json"]));
    assert_eq!(evidence[0]["verdict"], "bad-token", "{evidence:?}");
}

/// An invalid range is a usage error.
#[test]
fn an_invalid_range_is_a_usage_error() {
    let repo = Repo::new();
    let output = run_time(repo.path(), &["verify", "--range", "nope..nope"]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("nope..nope"), "{stderr}");
}

/// A non-commit argument is a usage error, not a verdict.
#[test]
fn a_non_commit_argument_is_a_usage_error() {
    let repo = Repo::new();
    let blob = repo.hash_object("blob", b"not a commit");
    let output = verify(&repo, &blob, &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("is not a commit"), "{stderr}");
}

/// A repository without commits says so and exits 2.
#[test]
fn an_empty_repository_is_a_usage_error() {
    let mut repo = Repo::upright();
    repo.init();
    repo.serve();
    let output = run_time(repo.path(), &["verify"]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("no commits"), "{stderr}");
}

/// A HEAD that names a missing object is not "no commits": git's own stderr
/// comes through and it is still a usage error.
#[test]
fn a_dangling_head_surfaces_gits_error() {
    let repo = Repo::new();
    std::fs::write(
        repo.path().join(".git/HEAD"),
        "1111111111111111111111111111111111111111\n",
    )
    .unwrap_or_else(|error| panic!("cannot write HEAD: {error}"));

    let output = run_time(repo.path(), &["verify"]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(!stderr.contains("no commits"), "{stderr}");
    assert!(
        stderr.contains("bad object"),
        "git's reason is kept: {stderr}"
    );
}

/// An empty range judges nothing and succeeds with an empty document.
#[test]
fn an_empty_range_is_an_empty_document_and_success() {
    let repo = Repo::new();
    let head = repo.head();
    let output = run_time(
        repo.path(),
        &["verify", "--range", &format!("{head}..{head}"), "--json"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(json_commits(&output).len(), 0, "{}", text(&output.stdout));
}

/// The signed path calls `hash-object -w`: the loose object is allowed, the
/// visible history and the refs are not.
#[test]
fn verify_on_a_signed_commit_leaves_history_and_refs_alone() {
    let repo = Repo::new();
    sign_here(&repo);
    let oid = repo.commit("signed");
    let objects = visible_objects(&repo);
    let before = refs(&repo);

    let output = verify(&repo, &oid, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));

    assert_eq!(
        visible_objects(&repo),
        objects,
        "no commit is added or lost"
    );
    assert_eq!(refs(&repo), before, "no ref appears or moves");
    assert!(
        !refs(&repo).contains("refs/notes/"),
        "no note ref is written"
    );
    assert_eq!(repo.status(), "");
}

/// `log --json` reports a commit it cannot read inside the document.
#[test]
fn log_json_reports_an_unreadable_commit_in_the_document() {
    let repo = Repo::new();
    // A commit git will resolve but the commit parser refuses: `bad_name` is not
    // an header name the parser accepts.
    let oid = repo.hash_object(
        "commit",
        b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
          author A <a@b> 0 +0000\n\
          committer A <a@b> 0 +0000\n\
          bad_name x\n\n\
          broken\n",
    );

    let output = run_time(repo.path(), &["log", "--json", &oid]);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output.stderr));
    let evidence = json_commits(&output);
    assert_eq!(evidence.len(), 1, "{evidence:?}");
    assert_eq!(evidence[0]["oid"], oid.as_str());
    assert_eq!(evidence[0]["verdict"], "error", "{evidence:?}");
    assert!(evidence[0]["error"].is_string(), "{evidence:?}");
    assert!(evidence[0]["signature"].is_null(), "{evidence:?}");
    assert!(evidence[0]["imprint"].is_null(), "{evidence:?}");
    assert_eq!(evidence[0]["per_tsa"], json!([]), "{evidence:?}");
    assert_eq!(evidence[0]["warnings"], json!([]), "{evidence:?}");
    assert_eq!(evidence[0]["dropped"], false, "{evidence:?}");
    assert!(
        evidence[0].get("pass").is_none(),
        "the log makes no judgement: {evidence:?}"
    );
}

/// The contract split is pinned: `log` reports a failing verdict and still
/// exits `0`; the same commit through `verify` says `pass: false` and exits `1`.
#[test]
fn log_reports_a_failing_verdict_that_verify_fails() {
    let repo = Repo::new();
    let oid = repo.rewrite(&repo.head(), |object| {
        object.replacen("\n\nbase\n", "\n\nbase, edited\n", 1)
    });

    let logged = run_time(repo.path(), &["log", "--json"]);
    assert_eq!(logged.status.code(), Some(0), "{}", text(&logged.stderr));
    let evidence = json_commits(&logged);
    assert_eq!(evidence[0]["verdict"], "bad-imprint", "{evidence:?}");
    assert!(
        evidence[0].get("pass").is_none(),
        "no gate slot in the log: {evidence:?}"
    );
    assert!(evidence[0].get("gates").is_none(), "{evidence:?}");
    assert!(evidence[0].get("required").is_none(), "{evidence:?}");

    let verified = verify(&repo, &oid, &["--json"]);
    assert_eq!(
        verified.status.code(),
        Some(1),
        "{}",
        text(&verified.stderr)
    );
    let evidence = json_commits(&verified);
    assert_eq!(evidence[0]["pass"], false, "{evidence:?}");
}

/// `--json` carries the same verdict as the human output, with evidence.

#[test]
fn the_json_document_matches_the_human_verdict() {
    let repo = Repo::new();
    let oid = repo.rewrite(&repo.head(), |object| {
        object.replacen("\n\nbase\n", "\n\nbase, edited\n", 1)
    });

    let human = verify(&repo, &oid, &[]);
    let json = verify(&repo, &oid, &["--json"]);
    let evidence = json_commits(&json);
    assert_eq!(evidence.len(), 1, "{evidence:?}");
    assert_eq!(evidence[0]["verdict"], "bad-imprint");
    assert!(evidence[0]["imprint"].is_string(), "{evidence:?}");
    assert!(evidence[0]["per_tsa"].is_array(), "{evidence:?}");
    assert_eq!(evidence[0]["pass"], false, "{evidence:?}");
    assert_eq!(evidence[0]["required"], 1, "{evidence:?}");
    assert_eq!(evidence[0]["gates"], json!([]), "{evidence:?}");
    assert_eq!(evidence[0]["dropped"], false, "{evidence:?}");
    assert_eq!(
        human.status.code(),
        json.status.code(),
        "the exit codes agree"
    );
    assert!(first_line(&human).contains("BAD-IMPRINT"));
}

/// `log` prints one line per commit, with the TSA id and its genTime.
#[test]
fn log_prints_one_line_per_commit_with_evidence() {
    let repo = Repo::new();
    let base = repo.head();
    let tip = repo.commit("second");

    let output = run_time(repo.path(), &["log", "--range", &format!("{base}..{tip}")]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let all: Vec<String> = text(&output.stdout).lines().map(str::to_owned).collect();
    assert_eq!(all.len(), 1, "{all:?}");
    let fields: Vec<&str> = all[0].split_whitespace().collect();
    assert_eq!(fields[0], &tip[..7], "the commit id comes first");
    assert_eq!(fields[1], "stub", "the TSA id is named");
    assert!(
        fields[2].contains('T') && fields[2].ends_with('Z'),
        "the genTime is printed: {all:?}"
    );
    assert_eq!(fields[3], "sealed");
}

/// A future committer date is a warning, never a failure.
#[test]
fn a_committer_date_after_gen_time_is_a_warning() {
    let repo = Repo::new();
    git_env(
        repo.path(),
        &["commit", "--allow-empty", "-m", "future"],
        &[
            ("GIT_TIME_SKIP", "1"),
            ("GIT_COMMITTER_DATE", "2030-01-01T00:00:00Z"),
        ],
    );
    let oid = repo.head();
    let sealed = run_time(repo.path(), &["seal"]);
    assert!(sealed.status.success(), "{}", text(&sealed.stderr));

    let output = verify(&repo, &repo.head(), &[]);
    let all = lines(&output);
    assert_eq!(output.status.code(), Some(0), "{all:?}");
    assert!(all[0].contains("SEALED"), "{all:?}");
    assert!(
        all.iter().any(|line| line.contains("committer")),
        "the skew is said: {all:?}"
    );
    let _ = oid;
}

/// An in-note seal is judged from the note, not from the imprint-only trailer.
#[test]
fn a_note_stored_seal_is_verified_from_the_note() {
    let repo = Repo::new();
    git(repo.path(), &["config", "time.store", "note"]);
    let oid = repo.commit("noted");

    let output = verify(&repo, &oid, &[]);
    let line = first_line(&output);
    assert_eq!(output.status.code(), Some(0), "{line}");
    assert!(line.contains("SEALED"), "{line}");
}
