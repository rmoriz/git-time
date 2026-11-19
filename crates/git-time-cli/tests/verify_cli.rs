//! `git time verify` and `git time log`, end to end.
//!
//! The harness is copied from `hook_flows.rs`: its helpers are private to that
//! integration-test binary, so a trimmed form of the same throwaway authority,
//! stub TSA, insulated repository and GPG key lives here rather than in a third
//! module. It mints genuine tokens with `openssl ts -reply` for the request in
//! flight and pins the throwaway CA made for the run, so no verdict is reached
//! on fixture bytes that were not issued here.
//!
//! The certificates are built for the older `openssl` a run may meet (LibreSSL,
//! OpenSSL 1.1.1) as well as a current one: `-sha256` and a named curve, because
//! their defaults (SHA-1 signatures, explicit EC parameters) are outside what
//! `webpki` verifies, a per-CA serial file because `-CAcreateserial` writes into
//! the shared temp directory and races between parallel fixtures, and a config
//! section for the CA extensions because 1.1.1 adds `basicConstraints` itself.
//!
//! The repository is hermetic (`GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` at
//! `/dev/null`, `GNUPGHOME` in a temp dir, `GIT_DIR`/`GIT_WORK_TREE` cleared)
//! and every case checks the read-only contract where it matters: `verify` adds
//! no stub hit and leaves the ref, the index and the worktree alone.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};

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

/// Run the binary with `args` in `dir`, plus `env` on top of the insulated set.
fn run_time_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(BIN);
    command
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_TIME_SKIP")
        .envs(env.iter().copied())
        .envs(insulated_env().iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.output().expect("runs the binary")
}

/// Run the binary with `args` in `dir`.
fn run_time(dir: &Path, args: &[&str]) -> Output {
    run_time_env(dir, args, &[])
}

// --- throwaway authority ------------------------------------------------

/// A throwaway TSA: a CA, a timestamping leaf and the config `openssl ts
/// -reply` needs.
struct Authority {
    dir: TempDir,
    ca: PathBuf,
    config: PathBuf,
    counter: AtomicUsize,
    /// `openssl ts -reply` updates the one serial file, so two replies at once
    /// (the two-TSA cases serve both ids from one stub) race on it.
    mint: Mutex<()>,
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
            mint: Mutex::new(()),
        }
    }

    /// A granted `TimeStampResp` for the DER `query`.
    fn mint(&self, query: &[u8]) -> Vec<u8> {
        // Held across the openssl call: the serial file is the one piece of
        // shared state between two replies, and a collision makes the reply
        // fail (which shows up much later as a missing token).
        let _guard = self.mint.lock().unwrap_or_else(|error| error.into_inner());
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

    /// Start a stub for the current authority without writing any config, so an
    /// anchor path `tsa add` chose survives.
    fn spawn(&mut self) {
        self.stub = Some(Stub::spawn(Arc::clone(&self.authority)));
    }

    /// Point the configured TSA at a live stub and pin its throwaway CA.
    fn serve(&mut self) {
        self.spawn();
        let url = self.stub.as_ref().expect("a serving stub").url.clone();
        git(self.path(), &["config", "time.tsa.stub.url", &url]);
        git(
            self.path(),
            &[
                "config",
                "time.tsa.stub.anchor",
                &pstr(&self.authority.bundle()),
            ],
        );
    }

    /// Point a second authority at the same stub, so a commit carries two
    /// tokens and a generated script must emit a block per token.
    fn second_tsa(&self) {
        let url = self.stub.as_ref().expect("a serving stub").url.clone();
        git(self.path(), &["config", "time.tsa.stub2.url", &url]);
        git(
            self.path(),
            &[
                "config",
                "time.tsa.stub2.anchor",
                &pstr(&self.authority.bundle()),
            ],
        );
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

/// Run the verifier with an empty `XDG_CONFIG_HOME`, the way a machine that
/// never pinned this authority's roots would, and return the output.
fn verify_without_anchors(repo: &Repo, rev: &str, extra: &[&str]) -> Output {
    let xdg = TempDir::new().expect("empty XDG_CONFIG_HOME");
    let xdg_path = pstr(xdg.path());
    let mut args = vec!["verify"];
    args.extend_from_slice(extra);
    args.push(rev);
    let output = run_time_env(repo.path(), &args, &[("XDG_CONFIG_HOME", &xdg_path)]);
    std::mem::forget(xdg);
    output
}

/// The fingerprint `rev`'s block names for its TSA, from the block itself.
fn named_root_of(repo: &Repo, rev: &str) -> String {
    let object = repo.object(rev);
    let line = object
        .lines()
        .find(|line| line.starts_with("X-RFC3161-Anchor: "))
        .expect("the sealed block names its root");
    let (_, fingerprint) = line
        .split_once("; sha256=")
        .expect("the anchor line carries a fingerprint");
    fingerprint.to_owned()
}

/// The decoded evidence block of `rev`.
fn block(repo: &Repo, rev: &str) -> git_time_core::store::TrailerBlock {
    let object = repo.object(rev);
    let trailer = &object[Repo::trailer_seam(&object)..];
    git_time_core::store::decode(trailer.as_bytes())
        .expect("the block decodes")
        .expect("the commit carries a block")
}

/// Run `anchor fetch` of the stub against `command`'s answer, with `accept`
/// passed through.
fn fetch(repo: &Repo, url: &str, command: &str, accept: &[&str]) -> Output {
    let mut args = vec!["anchor", "fetch", url, "--id", "stub", "--insecure-http"];
    for value in accept {
        args.push("--accept");
        args.push(value);
    }
    run_time_env(
        repo.path(),
        &args,
        &[("GIT_TIME_ANCHOR_FETCH_CMD", command)],
    )
}

/// The fingerprint HEAD's block names for its TSA, from the block itself.
fn named_root(repo: &Repo) -> String {
    named_root_of(repo, "HEAD")
}

/// A fingerprint nobody pinned.
const UNPINNED: &str = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:\
                        00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

/// Rewrite HEAD so its block names [`UNPINNED`] instead of the root it sealed
/// with, and return the new id. The pre-image is left alone, so only the imprint
/// is recomputed and the changed field is the named root.
fn rename_root(repo: &Repo) -> String {
    let named = named_root(repo);
    repo.rewrite("HEAD", |object| {
        let seam = Repo::trailer_seam(object);
        let pre_image = &object[..seam];
        let mut lines: Vec<String> = object.lines().map(str::to_owned).collect();
        for line in &mut lines {
            if let Some(rest) = line.strip_prefix("X-RFC3161-Anchor: ") {
                let (id, fingerprint) = rest
                    .strip_prefix("id=")
                    .expect("the anchor line names its id")
                    .split_once("; sha256=")
                    .expect("the anchor value carries a fingerprint");
                assert_eq!(fingerprint, named, "the block names its sealing root");
                *line = format!("X-RFC3161-Anchor: id={id}; sha256={UNPINNED}");
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
    })
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

/// Whether `binary` runs; `arg` is its harmless version flag.
fn have(binary: &str, arg: &str) -> bool {
    Command::new(binary)
        .arg(arg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// `git time verify --openssl` needs `openssl ts` and `zstd`: the tests that run
/// the printed script skip when either is missing, the way `hook_flows.rs`
/// treats a missing `openssl`.
fn script_tools() -> bool {
    have("openssl", "version")
}

/// Run a generated script with `sh`, in the repository and with the user's
/// anchor directory out of reach.
fn run_script(repo: &Repo, script: &str) -> Output {
    let path = repo.path().join(".git/time-audit.sh");
    std::fs::write(&path, script).expect("write the script");
    let xdg = TempDir::new().expect("empty XDG_CONFIG_HOME");
    let output = Command::new("sh")
        .arg(&path)
        .current_dir(repo.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .envs(insulated_env().iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("runs sh");
    std::mem::forget(xdg);
    output
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

/// Records are separated by a blank line: each is several lines long, and
/// without the gap the next `PASS` reads as another answer of the previous one.
#[test]
fn a_blank_line_separates_two_commit_records() {
    let repo = Repo::new();
    let second = repo.commit("second");
    repo.commit("third");

    let output = verify(&repo, &second, &["HEAD"]);
    let all = lines(&output);
    assert_eq!(output.status.code(), Some(0), "{all:?}");
    let blank = all.iter().position(String::is_empty).expect("a blank line");
    assert!(
        blank > 0 && all[blank - 1].starts_with("  stub: valid "),
        "{all:?}"
    );
    assert!(
        all[blank + 1].starts_with("PASS "),
        "the next record follows the gap: {all:?}"
    );
    assert_eq!(
        all.last().map(String::as_str).map(str::is_empty),
        Some(false)
    );
}

/// A sealed commit passes, and verifying it costs no stub request.
#[test]
fn a_sealed_commit_passes_without_touching_the_network() {
    let repo = Repo::new();
    let oid = repo.head();
    let hits = repo.hits();
    assert_eq!(hits, 1, "only the base commit was stamped");

    let output = verify(&repo, &oid, &[]);
    let all = lines(&output);
    let line = &all[0];
    assert_eq!(output.status.code(), Some(0), "{line}");
    assert!(line.starts_with(&format!("PASS {} SEALED 1/1 TSA(s)", &oid[..7])));
    // The detail is on a pass too: who answered and when. The anchor is long
    // and repeats on every pass, so it stays in `--json` only.
    let detail = &all[1];
    assert!(detail.starts_with("  stub: valid "), "{detail}");
    assert!(detail.contains("; serial "), "{detail}");
    assert!(!detail.contains("; anchor "), "{detail}");
    assert_eq!(all.len(), 2, "{all:?}");

    // The machine form carries the anchor a reader checks the root against.
    let json_out = verify(&repo, &oid, &["--json"]);
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("one JSON document");
    let tsa = &parsed["commits"][0]["per_tsa"][0];
    assert_eq!(tsa["verdict"], "valid");
    assert!(
        tsa["serial"].as_str().is_some_and(|s| !s.is_empty()),
        "{tsa}"
    );
    assert!(
        tsa["anchor"].as_str().is_some_and(|s| s.contains(':')),
        "{tsa}"
    );

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
    // Nothing pinned at all is not the same as a named root gone missing, so the
    // restore hint stays off.
    assert!(
        !all.iter().any(|line| line.contains("tsa restore")),
        "{all:?}"
    );
}

/// A block naming a root this machine has not pinned is untrusted, names the
/// root, and points at the command that brings it.
#[test]
fn a_block_naming_an_unpinned_root_is_untrusted_with_a_restore_hint() {
    let repo = Repo::new();
    let oid = rename_root(&repo);

    let output = verify_without_anchors(&repo, &oid, &[]);
    let all = lines(&output);
    assert_eq!(output.status.code(), Some(1), "{all:?}");
    assert!(all[0].contains("UNTRUSTED 0/1"), "{all:?}");
    let detail = all
        .iter()
        .find(|line| line.contains("anchor-not-pinned"))
        .unwrap_or_else(|| panic!("the reason is named: {all:?}"));
    assert!(detail.contains(UNPINNED), "the root is named: {all:?}");
    assert!(
        detail.contains("tsa restore"),
        "the command is named: {all:?}"
    );
    assert!(
        all.iter()
            .any(|line| line.trim() == "`git time tsa restore` pins it"),
        "the hint line is there: {all:?}"
    );
}

/// The machine form carries the roots the block names, so a consumer can name
/// them without re-reading the commit.
#[test]
fn json_carries_the_anchors_the_block_names() {
    let repo = Repo::new();
    let oid = rename_root(&repo);

    let evidence = json_commits(&verify_without_anchors(&repo, &oid, &["--json"]));
    assert_eq!(evidence[0]["verdict"], "untrusted", "{evidence:?}");
    assert_eq!(
        evidence[0]["per_tsa"][0]["anchors"],
        json!([UNPINNED]),
        "{evidence:?}"
    );

    // `log` reports the same evidence, so it carries the field too.
    let xdg = TempDir::new().expect("empty XDG_CONFIG_HOME");
    let xdg_path = pstr(xdg.path());
    let logged = run_time_env(
        repo.path(),
        &["log", "--json", &oid],
        &[("XDG_CONFIG_HOME", &xdg_path)],
    );
    let evidence = json_commits(&logged);
    assert_eq!(
        evidence[0]["per_tsa"][0]["anchors"],
        json!([UNPINNED]),
        "{evidence:?}"
    );
}

/// `anchors` is there even when the block names none: an empty array, not a
/// missing key, so a consumer needs no absence check.
#[test]
fn json_anchors_is_empty_when_the_block_names_none() {
    let repo = Repo::new();
    repo.drop_anchor();
    let oid = repo.rewrite("HEAD", |object| {
        let seam = Repo::trailer_seam(object);
        let pre_image = &object[..seam];
        let mut lines: Vec<String> = object
            .lines()
            .filter(|line| !line.starts_with("X-RFC3161-Anchor: "))
            .map(str::to_owned)
            .collect();
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

    let evidence = json_commits(&verify_without_anchors(&repo, &oid, &["--json"]));
    assert_eq!(evidence[0]["verdict"], "untrusted", "{evidence:?}");
    assert_eq!(
        evidence[0]["per_tsa"][0]["anchors"],
        json!([]),
        "{evidence:?}"
    );
}

/// A token older than every pinned root names the fetch hint: the fix is to
/// fetch the authority's current bundle, not to restore a root the block names.
#[test]
fn a_token_older_than_every_pinned_root_names_the_fetch_hint() {
    let repo = Repo::new();
    let oid = repo.head();
    // A root minted after the token's genTime: validity starts at a whole
    // second, so wait for the next one before minting it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch");
    std::thread::sleep(std::time::Duration::from_nanos(u64::from(
        1_000_000_000 - now.subsec_nanos(),
    )));
    let later = Authority::new();
    git(
        repo.path(),
        &["config", "time.tsa.stub.anchor", &pstr(&later.bundle())],
    );

    let output = verify_without_anchors(&repo, &oid, &[]);
    let all = lines(&output);
    assert_eq!(output.status.code(), Some(1), "{all:?}");
    assert!(all[0].contains("UNTRUSTED 0/1"), "{all:?}");
    assert!(
        all.iter().any(|line| line.contains("no pinned root")),
        "the reason is named: {all:?}"
    );
    assert!(
        all.iter().any(|line| line.trim()
            == "run `git time anchor fetch` and accept the root that is valid now"),
        "the hint line is there: {all:?}"
    );
}

/// A whole rotation on one repository: the fetch alone is refused and writes
/// nothing, the accepted root is appended next to the retired one, the old
/// commit keeps verifying and the new block names the new root. The lock diff is
/// the review artifact: one added line, the retired root's line still there.
#[test]
fn history_survives_a_rotation_end_to_end() {
    let mut repo = Repo::upright();
    repo.init();
    repo.spawn();
    let mut url = repo.stub.as_ref().expect("a stub").url.clone();
    let store = TempDir::new().expect("anchor store");
    let stored = store.path().join("anchors/stub.pem");

    // The bundle lives at an explicit path, the way a machine that pinned it
    // once does — the seal, the fetch and the lock all resolve the same file.
    // The keys are the ones `tsa add` writes; `init` already made the section.
    std::fs::create_dir_all(stored.parent().expect("a parent")).expect("anchor dir");
    git(repo.path(), &["config", "time.tsa.stub.url", &url]);
    git(
        repo.path(),
        &["config", "time.tsa.stub.anchor", &pstr(&stored)],
    );
    git(
        repo.path(),
        &["config", "time.tsa.stub.insecure-http", "true"],
    );

    // Root A is the first pin, taken on trust on first use.
    let serve_a = format!("cat {}", pstr(&repo.authority.bundle()));
    let first = fetch(&repo, &url, &serve_a, &[]);
    assert!(first.status.success(), "{}", text(&first.stderr));
    let a_pinned = std::fs::read(&stored).expect("the pinned root");
    let a = certificate_fingerprint(&repo.authority.bundle());

    let old = repo.commit("under root a");
    assert_eq!(named_root_of(&repo, &old), a, "the old block names A");

    // The reviewer records what was pinned.
    let pin = run_time(repo.path(), &["anchor", "pin"]);
    assert!(pin.status.success(), "{}", text(&pin.stderr));
    let lock_before =
        std::fs::read_to_string(repo.path().join("time.anchors-lock")).expect("the lock");
    let a_lock = a.replace(':', "").to_ascii_lowercase();
    assert_eq!(lock_before, format!("stub {a_lock}\n"));

    // The authority rotates: a fresh root B answers and signs from now on.
    let rotated = Arc::new(Authority::new());
    repo.authority = Arc::clone(&rotated);
    repo.spawn();
    url = repo.stub.as_ref().expect("a stub").url.clone();
    git(repo.path(), &["config", "time.tsa.stub.url", &url]);
    let serve_b = format!("cat {}", pstr(&rotated.bundle()));
    let b = certificate_fingerprint(&rotated.bundle());
    assert_ne!(a, b, "a rotation is a different root");

    // Fail-closed: the fetch alone is not a trust decision.
    let refused = fetch(&repo, &url, &serve_b, &[]);
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused.stderr));
    let stderr = text(&refused.stderr);
    assert!(stderr.contains("does not match"), "{stderr}");
    assert!(stderr.contains(&a), "the pinned value: {stderr}");
    assert!(stderr.contains(&b), "the fetched value: {stderr}");
    assert!(
        stderr.contains(&format!("--accept {b}")),
        "the fix is named: {stderr}"
    );
    assert_eq!(
        std::fs::read(&stored).expect("the store"),
        a_pinned,
        "a refusal writes nothing"
    );

    // A human compares B with the authority's own publication and says yes.
    let accept = format!("stub={b}");
    let accepted = fetch(&repo, &url, &serve_b, &[accept.as_str()]);
    assert!(accepted.status.success(), "{}", text(&accepted.stderr));
    assert!(
        text(&accepted.stdout).contains("1 root(s) appended, 2 now pinned"),
        "{}",
        text(&accepted.stdout)
    );
    let both = git_time_core::trust::AnchorStore::load(&[("stub".to_owned(), stored.clone())])
        .expect("both roots load")
        .anchor("stub")
        .map(|anchor| anchor.roots.len());
    assert_eq!(both, Some(2), "the retired root stays next to the new one");

    // The accepted root is written first. Every build before the anchor line
    // takes the first certificate as *the* anchor, so that reader now checks
    // new evidence and fails the old commit; a current reader reads the line.
    let (new_first_dir, new_first) = certificate_at(&stored, 0);
    assert_eq!(
        certificate_fingerprint(&new_first),
        b,
        "the fresh root leads the bundle"
    );
    let (retired_dir, retired_second) = certificate_at(&stored, 1);
    assert_eq!(
        certificate_fingerprint(&retired_second),
        a,
        "the retired root follows it"
    );
    git(
        repo.path(),
        &["config", "time.tsa.stub.anchor", &pstr(&new_first)],
    );
    let older_reader = verify(&repo, &old, &[]);
    let older = lines(&older_reader);
    assert_eq!(older_reader.status.code(), Some(1), "{older:?}");
    assert!(
        older.iter().any(|line| line.contains("UNTRUSTED")),
        "the old block is unverified on a first-certificate reader: {older:?}"
    );
    drop(new_first_dir);
    drop(retired_dir);

    // With the whole bundle the old commit still verifies.
    git(
        repo.path(),
        &["config", "time.tsa.stub.anchor", &pstr(&stored)],
    );
    let surviving = verify(&repo, &old, &[]);
    assert_eq!(surviving.status.code(), Some(0), "{:?}", lines(&surviving));
    assert!(first_line(&surviving).contains("PASS"));

    // The lock diff is one added line, and the retired root's line survives.
    // The file is sorted by id and fingerprint, so the pair may be in either
    // order depending on the fingerprints; both lines must be there, sorted.
    let pin = run_time(repo.path(), &["anchor", "pin"]);
    assert!(pin.status.success(), "{}", text(&pin.stderr));
    let lock_after =
        std::fs::read_to_string(repo.path().join("time.anchors-lock")).expect("the lock");
    let written: Vec<&str> = lock_after.lines().collect();
    let mut sorted = written.clone();
    sorted.sort_unstable();
    assert_eq!(written, sorted, "the lock is sorted: {lock_after}");
    let mut both = vec![
        format!("stub {}", a.replace(':', "").to_ascii_lowercase()),
        format!("stub {}", b.replace(':', "").to_ascii_lowercase()),
    ];
    both.sort_unstable();
    let mut actual: Vec<String> = written.iter().map(|line| (*line).to_owned()).collect();
    actual.sort_unstable();
    assert_eq!(actual, both, "{lock_after}");
    assert_eq!(written.len(), 2, "one line added, the old one kept");

    // A new commit is stamped by B, and its block says so.
    let new = repo.commit("under root b");
    assert_eq!(block(&repo, &old).anchors["stub"], vec![a]);
    let new_block = block(&repo, &new);
    let named = &new_block.anchors["stub"];
    assert!(named.contains(&b), "the new block names B: {named:?}");
    assert_eq!(new_block.tokens.len(), 1, "the token was kept");

    let fresh = verify(&repo, &new, &[]);
    assert_eq!(fresh.status.code(), Some(0), "{:?}", lines(&fresh));

    // A reader that holds only the retired root refuses the block: the named
    // root B is not pinned here, and A cannot stand in for it. The reason and
    // the fix are named.
    let named_only = name_only(&repo, &new, std::slice::from_ref(&b));
    let retired = store.path().join("anchors/retired.pem");
    std::fs::write(&retired, &a_pinned).expect("the retired root");
    git(
        repo.path(),
        &["config", "time.tsa.stub.anchor", &pstr(&retired)],
    );
    let without = verify(&repo, &named_only, &[]);
    let all = lines(&without);
    assert_eq!(without.status.code(), Some(1), "{all:?}");
    assert!(
        all.iter().any(|line| line.contains("anchor-not-pinned")),
        "{all:?}"
    );
    assert!(
        all.iter().any(|line| line.contains(&b)),
        "the root is named: {all:?}"
    );
    assert!(
        all.iter().any(|line| line.contains("tsa restore")),
        "the fix is named: {all:?}"
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

/// A block written when no authority was configured is `NONE`: nothing was
/// asked, so nothing stayed silent, and the hint names the way back.
#[test]
fn a_commit_sealed_without_any_tsa_is_none() {
    let repo = Repo::new();
    let removed = run_time(repo.path(), &["tsa", "remove", "stub"]);
    assert!(removed.status.success(), "{}", text(&removed.stderr));

    std::fs::write(repo.path().join("plain.txt"), "plain").expect("write file");
    git(repo.path(), &["add", "plain.txt"]);
    git(repo.path(), &["commit", "-q", "-m", "no authority"]);
    let oid = repo.head();

    let output = verify(&repo, &oid, &[]);
    let all = lines(&output);
    assert_eq!(output.status.code(), Some(1), "{all:?}");
    assert!(all[0].contains(" NONE "), "{all:?}");
    assert!(
        all.iter()
            .any(|line| line.contains("no TSA was configured") && line.contains("tsa restore")),
        "the hint is there: {all:?}"
    );

    let evidence = json_commits(&verify(&repo, &oid, &["--json"]));
    assert_eq!(evidence[0]["verdict"], "none", "{evidence:?}");
    assert_eq!(evidence[0]["per_tsa"], json!([]), "{evidence:?}");
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

// --- the --openssl audit script -----------------------------------------

/// The flag prints a script, one `openssl ts -verify` per token, and runs
/// nothing itself.
#[test]
fn openssl_prints_a_script_with_one_verify_per_token() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    repo.second_tsa();
    let oid = repo.commit("two tokens");

    let output = verify(&repo, &oid, &["--openssl"]);
    let script = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{script}{}",
        text(&output.stderr)
    );
    assert!(script.starts_with("#!/bin/sh\n"), "{script}");
    assert!(script.contains("set -eu"), "{script}");
    assert!(script.contains("mktemp -d) || exit 1"), "{script}");
    // Cleanup hangs off EXIT only; the signals exit, so their trap runs once.
    assert!(script.contains("trap cleanup EXIT"), "{script}");
    assert!(!script.contains("EXIT HUP INT TERM"), "{script}");
    for line in [
        "trap 'exit 130' INT",
        "trap 'exit 143' TERM",
        "trap 'exit 129' HUP",
    ] {
        assert!(script.contains(line), "missing `{line}`: {script}");
    }
    assert!(script.contains("-purpose timestampsign"), "{script}");
    // The script is a document: the payload is embedded, so nothing here walks
    // the repository or needs a decompressor.
    assert!(
        !script.contains("command git"),
        "no git call in the script: {script}"
    );
    assert!(
        !script.contains("zstd -d"),
        "no zstd call in the script: {script}"
    );
    assert_eq!(
        script.matches("<<'pre'").count(),
        1,
        "the pre-image is embedded once: {script}"
    );

    let token_lines = repo
        .object(&oid)
        .lines()
        .filter(|line| line.starts_with("X-RFC3161-Token: "))
        .count();
    assert_eq!(token_lines, 2, "the commit carries two tokens");
    assert_eq!(
        script
            .lines()
            .filter(|line| line.trim_start().starts_with("if openssl ts -verify"))
            .count(),
        token_lines,
        "one verification per token: {script}"
    );
    assert_eq!(
        script.matches("<<'token'").count(),
        token_lines,
        "one embedded token per token: {script}"
    );
}

/// The script re-verifies a sealed commit on its own.
#[test]
fn the_openssl_script_passes_a_sealed_commit() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    let oid = repo.head();
    let script = text(&verify(&repo, &oid, &["--openssl"]).stdout);

    let run = run_script(&repo, &script);
    let all = lines(&run);
    assert_eq!(run.status.code(), Some(0), "{all:?}");
    assert!(
        all.iter()
            .any(|line| line == &format!("PASS {} stub", &oid[..7])),
        "the token passes: {all:?}"
    );
    assert!(all.iter().any(|line| line == "OK"), "{all:?}");
}

/// The body of the `name` heredoc in `script`.
fn heredoc_body(script: &str, name: &str) -> String {
    let lines: Vec<&str> = script.lines().collect();
    let open = format!("<<'{name}'");
    let start = lines
        .iter()
        .position(|line| line.ends_with(&open))
        .unwrap_or_else(|| panic!("a `{name}` heredoc: {script}"))
        + 1;
    let end = start
        + lines[start..]
            .iter()
            .position(|line| *line == name)
            .unwrap_or_else(|| panic!("the `{name}` heredoc ends: {script}"));
    let mut body = lines[start..end].join("\n");
    if end > start {
        body.push('\n');
    }
    body
}

/// The base64 bodies of the certificates in `pem`, armor and wrapping stripped.
fn pem_bodies(pem: &str) -> Vec<String> {
    pem.split("-----END CERTIFICATE-----")
        .filter_map(|block| {
            let body: String = block
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            (!body.is_empty()).then_some(body)
        })
        .collect()
}

/// The base64 body of the one certificate in `path`, armor stripped.
fn pem_body(path: &Path) -> String {
    let pem = text(&std::fs::read(path).expect("read the certificate"));
    pem_bodies(&pem).remove(0)
}

/// A PEM file holding only certificate `index` of the bundle at `path`. The
/// temp dir comes back with it so the file lives as long as the caller needs.
fn certificate_at(path: &Path, index: usize) -> (TempDir, PathBuf) {
    let pem = text(&std::fs::read(path).expect("read the bundle"));
    let body = pem_bodies(&pem).remove(index);
    let dir = TempDir::new().expect("a certificate of its own");
    let single = dir.path().join("one.pem");
    let mut armored = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        armored.push_str(&String::from_utf8_lossy(chunk));
        armored.push('\n');
    }
    armored.push_str("-----END CERTIFICATE-----\n");
    std::fs::write(&single, armored).expect("write the certificate");
    (dir, single)
}

/// The `anchor.b64` heredoc of `script`, decoded to PEM.
fn decoded_anchor(script: &str) -> String {
    let encoded = heredoc_body(script, "anchor");
    let dir = TempDir::new().expect("decode dir");
    let source = dir.path().join("anchor.b64");
    let plain = dir.path().join("anchor.pem");
    std::fs::write(&source, encoded).expect("write the encoded anchor");
    let output = Command::new("openssl")
        .args(["base64", "-d", "-in"])
        .arg(&source)
        .arg("-out")
        .arg(&plain)
        .output()
        .expect("openssl is available");
    assert!(output.status.success(), "{}", text(&output.stderr));
    text(&std::fs::read(&plain).expect("read the decoded anchor"))
}

/// The SHA-256 fingerprint `openssl x509` prints for the certificate at `path`.
fn certificate_fingerprint(path: &Path) -> String {
    let output = Command::new("openssl")
        .args(["x509", "-noout", "-fingerprint", "-sha256", "-in"])
        .arg(path)
        .output()
        .expect("openssl is available");
    assert!(output.status.success(), "{}", text(&output.stderr));
    text(&output.stdout)
        .split_once('=')
        .expect("a fingerprint line")
        .1
        .trim()
        .to_owned()
}

/// Rewrite `rev` so its anchor line names exactly `fingerprints`, and return the
/// new id. The pre-image is untouched, so only the imprint is recomputed.
fn name_only(repo: &Repo, rev: &str, fingerprints: &[String]) -> String {
    let listed = fingerprints.join(",");
    repo.rewrite(rev, |object| {
        let seam = Repo::trailer_seam(object);
        let pre_image = &object[..seam];
        let mut lines: Vec<String> = object.lines().map(str::to_owned).collect();
        for line in &mut lines {
            if let Some(rest) = line.strip_prefix("X-RFC3161-Anchor: id=") {
                let (id, tail) = rest
                    .split_once("; sha256=")
                    .expect("the anchor value carries a fingerprint");
                // Whatever follows the list is kept, so a later field does not
                // silently disappear with the old fingerprints.
                let (_, after) = tail.split_once(';').unwrap_or((tail, ""));
                *line = format!("X-RFC3161-Anchor: id={id}; sha256={listed}{after}");
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
    })
}

/// A bundle with more than the root the token named still embeds only that
/// root, and the embedded anchor alone judges the token after the bundle on the
/// generating machine is gone.
#[test]
fn the_script_embeds_only_the_root_the_token_names() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    // A second, unrelated authority under the same id: after a rotation a
    // bundle holds both roots, and only the one the token was judged against
    // belongs in the script.
    let other = Authority::new();
    let both = repo.path().join("both.pem");
    let mut bundle = std::fs::read(repo.authority.bundle()).expect("read the sealing CA");
    bundle.extend(std::fs::read(other.bundle()).expect("read the other CA"));
    std::fs::write(&both, &bundle).expect("write the bundle");
    git(
        repo.path(),
        &["config", "time.tsa.stub.anchor", &pstr(&both)],
    );
    let sealing = certificate_fingerprint(&repo.authority.bundle());
    let stranger = certificate_fingerprint(&other.bundle());
    // Both roots are valid now, so the seal names both; an older block names
    // only the one that took the token.
    let oid = name_only(
        &repo,
        &repo.commit("two roots pinned"),
        std::slice::from_ref(&sealing),
    );
    assert!(
        repo.object(&oid)
            .contains(&format!("X-RFC3161-Anchor: id=stub; sha256={sealing}")),
        "the block names its root"
    );

    let script = text(&verify(&repo, &oid, &["--openssl"]).stdout);
    let embedded = pem_bodies(&decoded_anchor(&script));
    assert_eq!(embedded.len(), 1, "one root is embedded: {embedded:?}");
    assert_eq!(
        embedded[0],
        pem_body(&repo.authority.bundle()),
        "the named root is embedded"
    );
    assert_ne!(embedded[0], pem_body(&other.bundle()), "not the other one");
    assert_ne!(sealing, stranger, "the two roots differ");

    // The path the generating machine had is the only other source, and it is
    // removed here: what is left is the embedded anchor.
    std::fs::remove_file(&both).expect("remove the bundle");
    let run = run_script(&repo, &script);
    let all = lines(&run);
    assert_eq!(run.status.code(), Some(0), "{all:?}");
    assert!(all.iter().any(|line| line.starts_with("PASS ")), "{all:?}");
}

/// The validity check runs at the token's own genTime, not at wall clock, and
/// an openssl whose `ts -verify` lacks `-attime` says which check it could not
/// make instead of judging at now without a word.
///
/// Both branches are in the generated text either way, so what the local probe
/// actually decides is what is asserted here, and only a capable host's run can
/// show that the baked value is one openssl accepts.
#[test]
fn the_script_passes_attime_and_notes_when_unsupported() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    let oid = repo.head();
    let script = text(&verify(&repo, &oid, &["--openssl"]).stdout);

    // The token's own genTime, read back from the evidence: not the committer
    // date, and not the clock of this test.
    let evidence = json_commits(&verify(&repo, &oid, &["--json"]));
    let gen_time = evidence[0]["per_tsa"][0]["gen_time"]
        .as_str()
        .expect("the evidence names the genTime");
    let expected = gen_time
        .parse::<jiff::Timestamp>()
        .expect("the genTime parses")
        .as_second();
    let baked = script
        .lines()
        .find(|line| line.starts_with("attime_value='"))
        .unwrap_or_else(|| panic!("the genTime is baked in: {script}"));
    assert_eq!(
        baked
            .trim_start_matches("attime_value='")
            .trim_end_matches('\''),
        expected.to_string(),
        "the flag value is the token's genTime"
    );

    // The same trial the script's probe runs, decided here on this host.
    let probe = Command::new("openssl")
        .args(["ts", "-verify", "-attime", "1"])
        .output()
        .expect("openssl is available");
    let mut probe_text = text(&probe.stdout);
    probe_text.push_str(&text(&probe.stderr));
    let supported = !probe_text.lines().any(|line| line.starts_with("usage:"));
    assert!(
        script.contains("openssl ts -verify -attime"),
        "the probe is the same trial: {script}"
    );

    if supported {
        assert!(script.contains("attime=-attime"), "{script}");
        let run = run_script(&repo, &script);
        let all = lines(&run);
        assert_eq!(run.status.code(), Some(0), "{all:?}");
        assert!(all.iter().any(|line| line == "OK"), "{all:?}");
        assert!(
            !all.iter().any(|line| line.contains("no -attime")),
            "no omission on a host that has the flag: {all:?}"
        );
    } else {
        let run = run_script(&repo, &script);
        let all = lines(&run);
        assert!(
            all.iter()
                .any(|line| line.contains("no -attime, validity is judged at run time")),
            "the omission is named when the flag is missing: {all:?}"
        );
    }
}

/// A signed commit is rebuilt without its `gpgsig` header: the signature is
/// not part of the pre-image, and the script has to drop it too.
#[test]
fn the_openssl_script_rebuilds_a_signed_pre_image() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    sign_here(&repo);
    let oid = repo.commit("signed");
    let object = repo.object(&oid);
    assert!(object.contains("\ngpgsig "), "the commit is signed");
    let script = text(&verify(&repo, &oid, &["--openssl"]).stdout);

    let run = run_script(&repo, &script);
    let all = lines(&run);
    assert_eq!(run.status.code(), Some(0), "{all:?}");
    assert!(all.iter().any(|line| line.starts_with("PASS ")), "{all:?}");
}

/// A message edited after the seal breaks the imprint, and the script says so
/// rather than trusting its own reconstruction.
#[test]
fn a_tampered_pre_image_fails_the_openssl_script() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    let oid = repo.rewrite(&repo.head(), |object| {
        object.replacen("\n\nbase\n", "\n\nbase, edited\n", 1)
    });
    let script = text(&verify(&repo, &oid, &["--openssl"]).stdout);

    let run = run_script(&repo, &script);
    let all = lines(&run);
    assert_ne!(run.status.code(), Some(0), "{all:?}");
    assert!(
        all.iter()
            .any(|line| line.starts_with("FAIL ") && line.contains("imprint")),
        "the imprint mismatch is named: {all:?}"
    );
    assert!(all.iter().any(|line| line == "FAILED"), "{all:?}");
}

/// Exactly one directory is made, and it is gone again afterwards; an
/// interrupt stops the script and still cleans up, and a path that is not the
/// `mktemp` shape is never handed to anything destructive.
#[test]
fn the_openssl_script_cleans_its_scratch_directory() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    let oid = repo.head();
    let script = text(&verify(&repo, &oid, &["--openssl"]).stdout);
    let path = repo.path().join(".git/time-audit.sh");
    let tmp = TempDir::new().expect("TMPDIR");

    fn run(path: &Path, dir: &Path, tmp: &Path) -> Command {
        let mut command = Command::new("sh");
        command
            .arg(path)
            .current_dir(dir)
            .env("TMPDIR", tmp)
            .env("XDG_CONFIG_HOME", tmp)
            .envs(insulated_env().iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    assert!(
        script.contains("/*/*) rm -rf -- \"$scratch\""),
        "the path is checked before it is removed: {script}"
    );

    std::fs::write(&path, &script).expect("write the script");
    let output = run(&path, repo.path(), tmp.path())
        .output()
        .expect("runs sh");
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(
        std::fs::read_dir(tmp.path()).expect("read TMPDIR").count(),
        0,
        "the scratch directory is removed"
    );

    // A slow copy: the sleep leaves room to interrupt it mid-run.
    let slow = script.replace("set -eu\n", "set -eu\nsleep 2\n");
    std::fs::write(&path, &slow).expect("write the slow script");
    let mut child = run(&path, repo.path(), tmp.path())
        .spawn()
        .expect("spawns sh");
    std::thread::sleep(std::time::Duration::from_millis(300));
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kills sh");
    assert!(killed.success());
    let status = child.wait().expect("waits for sh");
    // A shell may report the trap's `exit 143` or die by the signal itself,
    // depending on whether it defers the trap past the running command.
    assert!(
        status.code().is_none() || status.code() == Some(143),
        "TERM stops the script: {status:?}"
    );
    assert_eq!(
        std::fs::read_dir(tmp.path()).expect("read TMPDIR").count(),
        0,
        "the scratch directory is removed on TERM too"
    );

    // No mktemp output at all: nothing may be deleted, and the run must still
    // end, not die in the trap.
    let canary = repo.path().join("canary");
    std::fs::write(&canary, "still here").expect("write canary");
    let bare = script.replace("scratch=$(mktemp -d) || exit 1", "scratch=");
    std::fs::write(&path, &bare).expect("write the bare script");
    let output = run(&path, repo.path(), tmp.path())
        .output()
        .expect("runs sh");
    // The shells differ in which status a failed redirect yields (dash 2, sh 1);
    // that the run ends at all, and above all that nothing is deleted, is the
    // point here.
    assert!(
        matches!(output.status.code(), Some(1 | 2)),
        "the run ends: {:?} {}",
        output.status.code(),
        text(&output.stderr)
    );
    assert!(canary.exists(), "a stray `rm -rf` would take this");
    assert!(tmp.path().exists());
}

/// A gate is decided when the script is generated: it is named, counted, and
/// still fails the run — while the tokens are verified all the same.
#[test]
fn a_gate_in_the_openssl_script_is_named_and_counted() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    let oid = repo.head();
    let output = verify(&repo, &oid, &["--openssl", "--require-signed"]);
    let script = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the generator only prints: {script}"
    );
    assert!(
        script.contains(&format!("NOTE {} require-signed", &oid[..7])),
        "{script}"
    );

    let run = run_script(&repo, &script);
    let all = lines(&run);
    assert_eq!(run.status.code(), Some(1), "{all:?}");
    assert!(all.iter().any(|line| line == "FAILED"), "{all:?}");
    assert!(
        all.iter().any(|line| line.starts_with("PASS ")),
        "the token is verified even under a gate: {all:?}"
    );
}

/// A message line that spells the heredoc delimiter must not end the payload
/// early: the delimiter is numbered until it cannot occur.
#[test]
fn a_message_line_equal_to_the_delimiter_is_kept() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    let oid = repo.commit("first\n\npre\nmore");
    let output = verify(&repo, &oid, &["--openssl"]);
    let script = text(&output.stdout);
    assert!(script.contains("<<'pre_1'"), "{script}");

    let run = run_script(&repo, &script);
    let all = lines(&run);
    assert_eq!(run.status.code(), Some(0), "{all:?}");
    assert!(
        all.iter().any(|line| line == "OK"),
        "the script passes: {all:?}"
    );
}

/// A message that is not UTF-8 cannot be printed as text; the pre-image falls
/// back to base64 and the script still verifies.
#[test]
fn a_message_that_is_not_utf8_falls_back_to_base64() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    // `git commit` would transcode a file to UTF-8, so the object is written by
    // hand: only a commit built elsewhere carries bytes that are not text.
    let repo = Repo::new();
    let head = repo.head();
    let tree = text(&git(
        repo.path(),
        &["rev-parse", &format!("{head}^{{tree}}")],
    ))
    .trim()
    .to_owned();
    let mut object = format!(
        "tree {tree}\nparent {head}\nauthor a <a@b> 1577836800 +0000\n\
         committer a <a@b> 1577836800 +0000\n\n"
    )
    .into_bytes();
    object.extend_from_slice(b"raw\xff\xfe bytes\n");
    let written = git_output(
        repo.path(),
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        &object,
    );
    let oid = text(&written.stdout).trim().to_owned();
    git(repo.path(), &["update-ref", "HEAD", &oid]);
    let sealed = run_time(repo.path(), &["seal"]);
    assert!(sealed.status.success(), "{}", text(&sealed.stderr));
    let oid = repo.head();

    let output = verify(&repo, &oid, &["--openssl"]);
    let script = text(&output.stdout);
    assert!(script.contains("<<'pre'"), "a base64 pre-image: {script}");
    assert!(script.contains("pre.b64"), "{script}");

    let run = run_script(&repo, &script);
    let all = lines(&run);
    assert_eq!(run.status.code(), Some(0), "{all:?}");
}

/// A token whose authority has no anchor is a failure of its own.
#[test]
fn a_token_without_an_anchor_fails_the_openssl_script() {
    if !script_tools() {
        eprintln!("skipping: openssl missing");
        return;
    }
    let repo = Repo::new();
    let oid = repo.head();
    repo.drop_anchor();
    let script = text(&verify(&repo, &oid, &["--openssl"]).stdout);

    let run = run_script(&repo, &script);
    let all = lines(&run);
    assert_ne!(run.status.code(), Some(0), "{all:?}");
    assert!(
        all.iter()
            .any(|line| line.contains("no anchor available for")),
        "{all:?}"
    );
}

/// A commit without a token is summarised, not silently left out.
#[test]
fn a_commit_without_a_token_is_summarised() {
    let repo = Repo::new();
    let oid = repo.commit_unsealed("plain");
    let script = text(&verify(&repo, &oid, &["--openssl"]).stdout);

    assert!(
        script.contains(&format!("SKIP {} unsealed", &oid[..7])),
        "{script}"
    );
    assert!(
        !script
            .lines()
            .any(|line| line.trim_start().starts_with("if openssl ts -verify")),
        "{script}"
    );
}

/// The script is an artifact for one seal, so it takes exactly one commit and
/// nothing that could select more: no default to HEAD, no range.
#[test]
fn openssl_needs_exactly_one_commit() {
    let repo = Repo::new();
    let head = repo.head();

    let none = run_time(repo.path(), &["verify", "--openssl"]);
    let stderr = text(&none.stderr);
    assert_eq!(none.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("exactly one commit"), "{stderr}");

    let two = run_time(repo.path(), &["verify", "--openssl", &head, &head]);
    let stderr = text(&two.stderr);
    assert_eq!(two.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("exactly one commit"), "{stderr}");

    let ranged = run_time(repo.path(), &["verify", "--openssl", "--range", "HEAD"]);
    let stderr = text(&ranged.stderr);
    assert_eq!(ranged.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--range") && stderr.contains("--openssl"),
        "{stderr}"
    );
}

/// One named commit is one block: the script cannot quietly grow a second
/// commit from somewhere else in the history.
#[test]
fn the_openssl_script_covers_only_the_named_commit() {
    let repo = Repo::new();
    let older = repo.head();
    let newer = repo.commit_unsealed("later");
    let script = text(&verify(&repo, &newer, &["--openssl"]).stdout);

    assert_eq!(
        script.matches("# ---- commit ").count(),
        1,
        "one commit block: {script}"
    );
    assert!(script.contains(&newer[..7]), "{script}");
    assert!(!script.contains(&older[..7]), "{script}");
}

/// `--json` and `--openssl` are two whole documents, so they exclude each
/// other.
#[test]
fn openssl_conflicts_with_json() {
    let repo = Repo::new();
    let output = verify(&repo, &repo.head(), &["--openssl", "--json"]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--json") && stderr.contains("--openssl"),
        "{stderr}"
    );
}
