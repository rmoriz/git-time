//! `git time tsa` and `git time anchor`, end to end.
//!
//! Every case runs the real binary in a hermetic repository: `GIT_CONFIG_GLOBAL`
//! and `GIT_CONFIG_SYSTEM` point at `/dev/null`, `XDG_CONFIG_HOME` at a private
//! directory and `GIT_DIR`/`GIT_WORK_TREE`/`GIT_TIME_SKIP` are cleared. Anchors
//! are never fetched over the network: `GIT_TIME_ANCHOR_FETCH_CMD` hands back a
//! throwaway CA, or prose when a failed fetch is the point.
//!
//! The authority commands are configuration work, so the cases pin the refusals
//! as closely as the happy paths: no repository, a duplicate id that must not
//! half-write the config, an `http://` endpoint, a policy that is not an OID, and
//! a garbage fetch that must leave the previous anchor byte for byte.
//!
//! `anchor pin` is a review artifact, not a trust store: test 8 proves `verify`
//! judges from the anchor and is unchanged when the lock is deleted.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

/// The binary under test, built by cargo for this integration test.
const BIN: &str = env!("CARGO_BIN_EXE_git-time");

/// Keep the developer's git configuration out of the test binary.
fn insulate() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: the only writer of these variables in the binary, run before
        // anything spawns git or the binary under test.
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

/// `PATH` with the binary's own directory in front, so a hook finds it.
fn path_env() -> String {
    let dir = Path::new(BIN).parent().expect("the binary has a directory");
    let base = std::env::var_os("PATH").unwrap_or_default();
    format!("{}:{}", dir.display(), base.to_string_lossy())
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn pstr(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The captured FreeTSA root, the one published fingerprint a test can match.
fn freetsa_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../git-time-core/tests/fixtures/freetsa_root.pem")
}

/// Lowercase hex of the SHA-256 of `bytes`.
fn fingerprint(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The SHA-256 fingerprint of `bytes` in the preset spelling: uppercase, colon
/// separated.
fn fingerprint_colon(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The DER of the first PEM certificate in `pem`.
fn first_der(pem: &str) -> Vec<u8> {
    let body = pem
        .split_once("-----\n")
        .and_then(|(_, rest)| rest.split_once("\n-----END"))
        .map(|(body, _)| body.replace('\n', ""))
        .expect("a PEM certificate block");
    BASE64.decode(body).expect("base64")
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
            "/CN=registry-ca",
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
            "/CN=registry-tsa",
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

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.ca).expect("read the CA")
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

// --- stub authority -----------------------------------------------------

#[derive(Clone)]
struct StubState {
    authority: Arc<Authority>,
}

/// A stub authority on a loopback port that mints real tokens for the requests
/// it receives.
struct Stub {
    url: String,
    _runtime: tokio::runtime::Runtime,
}

impl Stub {
    fn spawn(authority: Arc<Authority>) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("stub runtime");
        let url = runtime.block_on(async {
            let app = Router::new()
                .route("/tsr", post(handle))
                .with_state(StubState { authority });
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
            _runtime: runtime,
        }
    }
}

async fn handle(State(state): State<StubState>, _headers: HeaderMap, body: Bytes) -> Response {
    let response = state.authority.mint(&body);
    ([(CONTENT_TYPE, "application/timestamp-response")], response).into_response()
}

// --- the repository -----------------------------------------------------

/// A hermetic temporary repository with a throwaway authority.
struct Repo {
    dir: TempDir,
    xdg: TempDir,
    authority: Arc<Authority>,
    stub: Option<Stub>,
    dates: AtomicUsize,
}

impl Repo {
    fn new() -> Self {
        Self {
            dir: TempDir::new().expect("repo dir"),
            xdg: TempDir::new().expect("xdg dir"),
            authority: Arc::new(Authority::new()),
            stub: None,
            dates: AtomicUsize::new(0),
        }
    }

    /// A repository with the hooks wired, a live stub TSA configured as `stub`
    /// and its CA pinned.
    fn with_pinned_stub() -> Self {
        let mut repo = Self::new();
        repo.init();
        repo.serve();
        repo.add_tsa("stub", &repo.stub_url());
        assert!(
            repo.fetch_anchor("stub").status.success(),
            "the stub anchor is fetched"
        );
        repo
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn anchors(&self) -> PathBuf {
        self.xdg.path().join("git-time/anchors")
    }

    fn lock(&self) -> PathBuf {
        self.path().join("time.anchors-lock")
    }

    fn init(&self) {
        git(self.path(), &["init", "-q", "-b", "main"]);
        git(self.path(), &["config", "user.name", "Test"]);
        git(self.path(), &["config", "user.email", "t@example.com"]);
        git(self.path(), &["config", "commit.gpgsign", "false"]);
        git(self.path(), &["config", "tag.gpgsign", "false"]);
        git(self.path(), &["config", "time.deadline", "5s"]);

        let hooks = self.path().join(".git/hooks");
        std::fs::create_dir_all(&hooks).expect("hooks dir");
        let hook = hooks.join("post-commit");
        std::fs::write(
            &hook,
            format!("#!/bin/sh\nexec '{}' hook post-commit\n", BIN),
        )
        .expect("write hook");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
            .expect("chmod hook");
    }

    fn serve(&mut self) {
        self.stub = Some(Stub::spawn(Arc::clone(&self.authority)));
    }

    fn stub_url(&self) -> String {
        self.stub.as_ref().expect("a stub").url.clone()
    }

    fn run_time(&self, args: &[&str]) -> Output {
        self.run_time_env(args, &[])
    }

    fn run_time_env(&self, args: &[&str], env: &[(&str, String)]) -> Output {
        run_time_at(self.path(), self.xdg.path(), args, env)
    }

    /// Run a command with `input` on stdin.
    fn run_time_with_stdin(
        &self,
        args: &[&str],
        env: &[(&'static str, String)],
        input: &str,
    ) -> Output {
        run_time_stdin(self.path(), self.xdg.path(), args, env, input)
    }

    /// The environment that makes an anchor fetch hand back the throwaway CA.
    fn fetch_ca(&self) -> Vec<(&'static str, String)> {
        vec![(
            "GIT_TIME_ANCHOR_FETCH_CMD",
            format!("cat {}", pstr(&self.authority.ca)),
        )]
    }

    /// A fetch that answers FreeTSA's own URL with the fixture root and every
    /// other URL with the throwaway CA, so the one pinned preset with a kept
    /// fixture can be matched while the others exercise the mismatch path.
    fn fetch_known_root(&self) -> Vec<(&'static str, String)> {
        vec![(
            "GIT_TIME_ANCHOR_FETCH_CMD",
            format!(
                "case \"$GIT_TIME_ANCHOR_URL\" in https://freetsa.org/*) cat {} ;; *) cat {} ;; esac",
                pstr(&freetsa_root()),
                pstr(&self.authority.ca)
            ),
        )]
    }

    fn add_tsa(&self, id: &str, url: &str) {
        let output = self.run_time(&["tsa", "add", url, "--id", id, "--insecure-http"]);
        assert!(output.status.success(), "{}", text(&output.stderr));
    }

    fn fetch_anchor(&self, id: &str) -> Output {
        let url = self.stub_url();
        self.run_time_env(
            &["anchor", "fetch", &url, "--id", id, "--insecure-http"],
            &self.fetch_ca(),
        )
    }

    fn config(&self, key: &str) -> Option<String> {
        let output = git_output(self.path(), &["config", "--local", "--get", key]);
        output
            .status
            .success()
            .then(|| text(&output.stdout).trim().to_owned())
    }

    fn config_bytes(&self) -> Vec<u8> {
        std::fs::read(self.path().join(".git/config")).expect("read the local config")
    }

    fn commit(&self, message: &str) -> String {
        let name = format!("{}.txt", message.replace(' ', "-"));
        std::fs::write(self.path().join(&name), message).expect("write file");
        git(self.path(), &["add", &name]);
        let index = self.dates.fetch_add(1, Ordering::SeqCst);
        let date = format!("2020-01-01T00:00:{index:02}Z");
        let output = git_output_env(
            self.path(),
            &["commit", "-q", "-m", message, "--date", &date],
            &[("GIT_COMMITTER_DATE", date.as_str())],
        );
        assert!(output.status.success(), "{}", text(&output.stderr));
        text(&git(self.path(), &["rev-parse", "HEAD"]))
            .trim()
            .to_owned()
    }
}

fn insulated_env() -> Vec<(&'static str, &'static str)> {
    insulate();
    vec![
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ]
}

fn git_output_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_TIME_SKIP")
        .envs(insulated_env().iter().copied())
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns git");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(b"")
        .expect("writes stdin");
    child.wait_with_output().expect("waits for git")
}

fn git_output(dir: &Path, args: &[&str]) -> Output {
    git_output_env(dir, args, &[])
}

fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = git_output(dir, args);
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        text(&output.stderr)
    );
    output.stdout
}

/// Run the binary in `dir` with `XDG_CONFIG_HOME` at `xdg`.
fn run_time_at(dir: &Path, xdg: &Path, args: &[&str], env: &[(&str, String)]) -> Output {
    Command::new(BIN)
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_TIME_SKIP")
        .envs(insulated_env().iter().copied())
        .env("PATH", path_env())
        .env("XDG_CONFIG_HOME", xdg)
        .envs(env.iter().map(|(key, value)| (*key, value.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("runs the binary")
}

/// Run the binary with `input` on its stdin, the way a piped answer arrives.
fn run_time_stdin(
    dir: &Path,
    xdg: &Path,
    args: &[&str],
    env: &[(&str, String)],
    input: &str,
) -> Output {
    let mut child = Command::new(BIN)
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_TIME_SKIP")
        .envs(insulated_env().iter().copied())
        .env("PATH", path_env())
        .env("XDG_CONFIG_HOME", xdg)
        .envs(env.iter().map(|(key, value)| (*key, value.as_str())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns the binary");
    child
        .stdin
        .take()
        .expect("a stdin pipe")
        .write_all(input.as_bytes())
        .expect("writes the answer");
    child.wait_with_output().expect("runs the binary")
}

fn ok(output: &Output) -> String {
    assert!(output.status.success(), "{}", text(&output.stderr));
    text(&output.stdout)
}

/// The token after `marker` in `stdout`, asserted to be a SHA-256 in hex.
fn fingerprint_after(stdout: &str, marker: &str) -> String {
    let rest = stdout
        .split_once(marker)
        .unwrap_or_else(|| panic!("`{marker}` in {stdout}"))
        .1;
    let token = rest
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("a fingerprint after `{marker}` in {stdout}"));
    assert_eq!(token.len(), 64, "a SHA-256 is 64 hex digits: {token}");
    assert!(
        token.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "a SHA-256 is hex: {token}"
    );
    token.to_owned()
}

// --- cases --------------------------------------------------------------

#[test]
fn add_writes_the_section_and_derives_the_id_from_the_host() {
    let repo = Repo::new();
    repo.init();

    let output = repo.run_time(&[
        "tsa",
        "add",
        "https://tsa.example.net/tsr",
        "--alg",
        "sha512",
        "--policy",
        "1.2.3.4.1",
        "--timeout",
        "9s",
    ]);
    assert!(output.status.success(), "{}", text(&output.stderr));

    assert_eq!(
        repo.config("time.tsa.tsa-example-net.url").as_deref(),
        Some("https://tsa.example.net/tsr")
    );
    assert_eq!(
        repo.config("time.tsa.tsa-example-net.alg").as_deref(),
        Some("sha512")
    );
    assert_eq!(
        repo.config("time.tsa.tsa-example-net.policy").as_deref(),
        Some("1.2.3.4.1")
    );
    assert_eq!(
        repo.config("time.tsa.tsa-example-net.timeout").as_deref(),
        Some("9s")
    );
    let anchor = repo
        .config("time.tsa.tsa-example-net.anchor")
        .expect("the default anchor is written");
    assert!(
        anchor.starts_with(&pstr(&repo.anchors())),
        "the default anchor lives under the anchors dir: {anchor}"
    );

    let listing = ok(&repo.run_time(&["tsa", "list"]));
    assert!(listing.contains("tsa-example-net"), "{listing}");
    assert!(listing.contains("https://tsa.example.net/tsr"), "{listing}");
    assert!(listing.contains("sha512"), "{listing}");
    assert!(listing.contains("(missing)"), "{listing}");

    let json = ok(&repo.run_time(&["tsa", "list", "--json"]));
    let value: serde_json::Value = serde_json::from_str(&json).expect("list --json is JSON");
    assert_eq!(value[0]["id"], "tsa-example-net");
    assert_eq!(value[0]["anchored"], false);
}

#[test]
fn a_duplicate_id_exits_one_and_leaves_the_config_alone() {
    let repo = Repo::new();
    repo.init();
    assert!(
        repo.run_time(&["tsa", "add", "https://a.example/tsr", "--id", "twin"])
            .status
            .success()
    );
    let before = repo.config_bytes();

    let duplicate = repo.run_time(&["tsa", "add", "https://b.example/tsr", "--id", "twin"]);
    assert_eq!(duplicate.status.code(), Some(1));
    assert!(
        text(&duplicate.stderr).contains("twin"),
        "the message names the existing id: {}",
        text(&duplicate.stderr)
    );
    assert_eq!(repo.config_bytes(), before, "the config is unchanged");
}

#[test]
fn a_section_without_url_is_still_a_duplicate() {
    let repo = Repo::new();
    repo.init();
    // Hand-edited or half-written: no `url`, but a stale `policy` a merge would
    // silently keep.
    git(
        repo.path(),
        &["config", "--local", "time.tsa.twin.policy", "1.2.3.4.1"],
    );
    let before = repo.config_bytes();

    let duplicate = repo.run_time(&["tsa", "add", "https://b.example/tsr", "--id", "twin"]);
    assert_eq!(duplicate.status.code(), Some(1));
    assert!(text(&duplicate.stderr).contains("twin"));
    assert_eq!(repo.config_bytes(), before, "the config is unchanged");
}

#[test]
fn remove_deletes_the_section_and_an_unknown_id_exits_one() {
    let repo = Repo::new();
    repo.init();
    assert!(
        repo.run_time(&["tsa", "add", "https://a.example/tsr", "--id", "gone"])
            .status
            .success()
    );

    let removed = repo.run_time(&["tsa", "remove", "gone"]);
    assert!(removed.status.success(), "{}", text(&removed.stderr));
    for key in ["url", "alg", "anchor", "timeout"] {
        assert_eq!(repo.config(&format!("time.tsa.gone.{key}")), None, "{key}");
    }

    let unknown = repo.run_time(&["tsa", "remove", "never"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(text(&unknown.stderr).contains("never"));
}

#[test]
fn http_is_refused_without_the_flag_and_accepted_with_a_warning() {
    let repo = Repo::new();
    repo.init();

    let refused = repo.run_time(&["tsa", "add", "http://plain.example/tsr", "--id", "plain"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    let stderr = text(&refused.stderr);
    assert!(stderr.contains("--insecure-http"), "{stderr}");
    assert_eq!(
        repo.config("time.tsa.plain.url"),
        None,
        "nothing was written"
    );

    let accepted = repo.run_time(&[
        "tsa",
        "add",
        "http://plain.example/tsr",
        "--id",
        "plain",
        "--insecure-http",
    ]);
    assert!(accepted.status.success(), "{}", text(&accepted.stderr));
    assert!(
        text(&accepted.stderr).contains("warning"),
        "the risk is named: {}",
        text(&accepted.stderr)
    );
    assert_eq!(
        repo.config("time.tsa.plain.url").as_deref(),
        Some("http://plain.example/tsr")
    );
}

#[test]
fn a_bad_policy_oid_is_refused_at_add_time() {
    let repo = Repo::new();
    repo.init();

    let bad = repo.run_time(&[
        "tsa",
        "add",
        "https://policy.example/tsr",
        "--id",
        "policy",
        "--policy",
        "not-an-oid",
    ]);
    assert!(!bad.status.success());
    let stderr = text(&bad.stderr);
    assert!(
        stderr.contains("not a dotted-decimal OID"),
        "the request builder's wording: {stderr}"
    );
    assert_eq!(
        repo.config("time.tsa.policy.url"),
        None,
        "nothing was written"
    );
}

#[test]
fn anchor_fetch_pins_the_bundle_and_flips_the_listing() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    repo.add_tsa("stub", &repo.stub_url());
    let ca = repo.authority.bytes();
    let expected = fingerprint(&first_der(&text(&ca)));

    let fetched = repo.fetch_anchor("stub");
    let stdout = ok(&fetched);
    assert!(stdout.contains(&expected), "the fingerprint: {stdout}");
    let anchor = repo.anchors().join("stub.pem");
    assert!(stdout.contains(&pstr(&anchor)), "the path: {stdout}");
    assert_eq!(std::fs::read(&anchor).expect("the anchor"), ca);

    let listing = ok(&repo.run_time(&["tsa", "list"]));
    assert!(listing.contains("(anchored)"), "{listing}");
    let json = ok(&repo.run_time(&["tsa", "list", "--json"]));
    let value: serde_json::Value = serde_json::from_str(&json).expect("JSON");
    assert_eq!(value[0]["anchored"], true);
}

#[test]
fn a_garbage_fetch_leaves_the_existing_anchor_untouched() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    repo.add_tsa("stub", &repo.stub_url());
    assert!(repo.fetch_anchor("stub").status.success());
    let anchor = repo.anchors().join("stub.pem");
    let pinned = std::fs::read(&anchor).expect("the pinned anchor");

    let broken = repo.run_time_env(
        &[
            "anchor",
            "fetch",
            &repo.stub_url(),
            "--id",
            "stub",
            "--insecure-http",
        ],
        &[(
            "GIT_TIME_ANCHOR_FETCH_CMD",
            "printf 'this is prose, not a certificate\\n'".to_owned(),
        )],
    );
    assert_eq!(broken.status.code(), Some(1), "{}", text(&broken.stderr));
    assert_eq!(
        std::fs::read(&anchor).expect("the anchor"),
        pinned,
        "the previous anchor is untouched"
    );
}

#[test]
fn fetch_writes_the_configured_anchor_path_and_creates_its_directory() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    let custom = repo.path().join("custom/deep/ca.pem");
    let url = repo.stub_url();
    // A configured anchor wins over the default; `tsa add` itself creates the
    // missing parent so the path can actually be written later.
    let added = repo.run_time(&[
        "tsa",
        "add",
        &url,
        "--id",
        "stub",
        "--insecure-http",
        "--anchor",
        &pstr(&custom),
    ]);
    ok(&added);
    assert_eq!(
        repo.config("time.tsa.stub.anchor").as_deref(),
        Some(pstr(&custom).as_str())
    );
    assert!(custom.parent().expect("a parent").is_dir());

    let fetched = repo.fetch_anchor("stub");
    let stdout = ok(&fetched);
    let ca = repo.authority.bytes();
    let expected = fingerprint(&first_der(&text(&ca)));
    assert_eq!(std::fs::read(&custom).expect("the configured anchor"), ca);
    assert!(
        !repo.anchors().join("stub.pem").exists(),
        "the default path is untouched"
    );
    assert!(stdout.contains(&pstr(&custom)), "the path: {stdout}");
    assert!(stdout.contains(&expected), "the fingerprint: {stdout}");
    assert!(
        ok(&repo.run_time(&["tsa", "list"])).contains(&expected),
        "the listing names the new CA"
    );
}

#[test]
fn fetch_over_http_needs_the_flag_and_refuses_other_schemes() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    let url = repo.stub_url();

    let refused = repo.run_time(&["anchor", "fetch", &url, "--id", "stub"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert!(text(&refused.stderr).contains("--insecure-http"));
    assert!(!repo.anchors().join("stub.pem").exists());

    let accepted = repo.fetch_anchor("stub");
    assert!(accepted.status.success(), "{}", text(&accepted.stderr));
    assert!(
        text(&accepted.stderr).contains("warning"),
        "the risk is named: {}",
        text(&accepted.stderr)
    );

    let ftp = repo.run_time(&[
        "anchor",
        "fetch",
        "ftp://ftp.example/ca.pem",
        "--id",
        "other",
        "--insecure-http",
    ]);
    assert_eq!(ftp.status.code(), Some(2), "{}", text(&ftp.stderr));
    assert!(text(&ftp.stderr).contains("https://"));
}

#[test]
fn an_orphan_fetch_says_the_policy_will_not_read_it() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    let url = repo.stub_url();
    let fetched = repo.run_time_env(
        &["anchor", "fetch", &url, "--id", "orphan", "--insecure-http"],
        &repo.fetch_ca(),
    );
    assert!(fetched.status.success(), "{}", text(&fetched.stderr));
    assert!(
        text(&fetched.stderr).contains("orphan"),
        "the missing section is named: {}",
        text(&fetched.stderr)
    );
}

#[test]
fn anchor_list_json_carries_the_five_fields() {
    let repo = Repo::with_pinned_stub();
    let stdout = ok(&repo.run_time(&["anchor", "list", "--json"]));
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("list --json is JSON");
    let row = &value[0];
    assert_eq!(row["id"], "stub");
    assert_eq!(row["pinned"], true);
    let anchor = pstr(&repo.anchors().join("stub.pem"));
    assert_eq!(row["path"], anchor);
    let printed = row["fingerprint"].as_str().expect("a fingerprint");
    assert_eq!(printed.len(), 64);
    assert!(printed.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(
        row["not_after"]
            .as_str()
            .is_some_and(|date| !date.is_empty())
    );
}

#[test]
fn check_and_pin_name_an_unparseable_anchor() {
    let repo = Repo::with_pinned_stub();
    assert!(
        repo.run_time(&["anchor", "pin"]).status.success(),
        "the lock is written from the good anchor"
    );
    let lock = std::fs::read(repo.lock()).expect("the lock");
    let anchor = repo.anchors().join("stub.pem");
    std::fs::write(
        &anchor,
        "-----BEGIN CERTIFICATE-----\nZ2FyYmFnZQ==\n-----END CERTIFICATE-----\n",
    )
    .expect("write base64 garbage");

    let checked = repo.run_time(&["anchor", "pin", "--check"]);
    assert_eq!(checked.status.code(), Some(1));
    assert!(
        text(&checked.stderr).contains("unparseable"),
        "not merely `changed`: {}",
        text(&checked.stderr)
    );

    let repinned = repo.run_time(&["anchor", "pin"]);
    assert_eq!(repinned.status.code(), Some(1));
    assert!(text(&repinned.stderr).contains("no usable anchor"));
    assert_eq!(
        std::fs::read(repo.lock()).expect("the lock"),
        lock,
        "a failed pin leaves the previous lock"
    );
}

#[test]
fn pin_writes_the_lock_and_check_names_a_changed_anchor() {
    let repo = Repo::with_pinned_stub();
    let commit = repo.commit("base");
    let pinned = std::fs::read(repo.anchors().join("stub.pem")).expect("the anchor");
    let expected = fingerprint(&first_der(&text(&pinned)));

    let pin = repo.run_time(&["anchor", "pin"]);
    assert!(pin.status.success(), "{}", text(&pin.stderr));
    assert_eq!(
        std::fs::read_to_string(repo.lock()).expect("the lock"),
        format!("stub {expected}\n")
    );

    let matching = repo.run_time(&["anchor", "pin", "--check"]);
    assert!(matching.status.success(), "{}", text(&matching.stderr));

    // A different, valid CA at the same path: the lock now disagrees.
    let other = Authority::new();
    std::fs::write(repo.anchors().join("stub.pem"), other.bytes()).expect("swap the anchor");
    let changed = repo.run_time(&["anchor", "pin", "--check"]);
    assert_eq!(changed.status.code(), Some(1));
    assert!(
        text(&changed.stderr).contains("stub"),
        "the changed id is named: {}",
        text(&changed.stderr)
    );

    // The anchor, not the lock, drives the verdict: the swapped CA no longer
    // signs the token.
    let untrusted = repo.run_time(&["verify", &commit]);
    assert_eq!(
        untrusted.status.code(),
        Some(1),
        "{}",
        text(&untrusted.stdout)
    );
    assert!(
        text(&untrusted.stdout).contains("UNTRUSTED"),
        "{}",
        text(&untrusted.stdout)
    );

    // Restoring the anchor and deleting the lock keeps the PASS: verification
    // never reads the lock.
    std::fs::write(repo.anchors().join("stub.pem"), &pinned).expect("restore the anchor");
    std::fs::remove_file(repo.lock()).expect("remove the lock");
    let clean = repo.run_time(&["verify", &commit]);
    assert_eq!(clean.status.code(), Some(0), "{}", text(&clean.stdout));
    assert!(
        text(&clean.stdout).contains("PASS"),
        "{}",
        text(&clean.stdout)
    );
}

#[test]
fn preset_list_names_every_preset_and_marks_the_trust_level() {
    let repo = Repo::new();
    repo.init();

    let listing = ok(&repo.run_time(&["tsa", "preset", "list"]));
    for name in git_time_core::presets::names() {
        assert!(
            listing.lines().any(|line| line.starts_with(name)),
            "{name}: {listing}"
        );
    }
    // The published roots are shown, the TOFU presets say so, and a plain-http
    // endpoint is visible as such.
    assert!(listing.contains("https://freetsa.org/tsr"), "{listing}");
    assert!(
        listing.contains("A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC"),
        "{listing}"
    );
    assert!(listing.contains("tofu"), "{listing}");
    assert!(listing.contains("http://time.certum.pl"), "{listing}");
}

#[test]
fn preset_add_writes_the_install_config_and_prints_the_matched_fingerprint() {
    let repo = Repo::new();
    repo.init();

    let added = repo.run_time_env(
        &["tsa", "preset", "add", "freetsa"],
        &repo.fetch_known_root(),
    );
    assert!(added.status.success(), "{}", text(&added.stderr));
    assert_eq!(
        repo.config("time.tsa.freetsa.url").as_deref(),
        Some("https://freetsa.org/tsr")
    );
    assert_eq!(
        repo.config("time.tsa.freetsa.alg").as_deref(),
        Some("sha256")
    );
    assert_eq!(
        repo.config("time.tsa.freetsa.policy").as_deref(),
        Some("1.2.3.4.1")
    );
    let anchor = repo
        .config("time.tsa.freetsa.anchor")
        .expect("the anchor key is written");
    assert_eq!(anchor, pstr(&repo.anchors().join("freetsa.pem")));
    assert!(repo.anchors().join("freetsa.pem").exists(), "the anchor");

    let root = std::fs::read(freetsa_root()).expect("the fixture root");
    let expected = fingerprint(&first_der(&String::from_utf8_lossy(&root)));
    let stdout = text(&added.stdout);
    assert!(
        stdout.contains("freetsa: root fingerprint matches "),
        "the match is said: {stdout}"
    );
    let printed = fingerprint_after(&stdout, "sha256 ");
    assert_eq!(printed, expected, "the first certificate is fingerprinted");
}

/// A preset without a published root is trust on first use: the fetched
/// fingerprint is printed in full, and the add still succeeds.
#[test]
fn preset_add_of_a_tofu_preset_prints_the_fetched_fingerprint() {
    let repo = Repo::new();
    repo.init();

    let fetch = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat {}", pstr(&freetsa_root())),
    )];
    let added = repo.run_time_env(&["tsa", "preset", "add", "ai-moda"], &fetch);
    assert!(added.status.success(), "{}", text(&added.stderr));
    assert!(repo.anchors().join("ai-moda.pem").exists(), "the anchor");

    let stdout = text(&added.stdout);
    assert!(stdout.contains("trust on first use"), "{stdout}");
    let printed = fingerprint_after(&stdout, "root is ");
    assert_eq!(printed.len(), 64, "a full SHA-256: {printed}");
    assert!(
        printed.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "hex: {printed}"
    );
    let root = std::fs::read(freetsa_root()).expect("the fixture root");
    assert_eq!(
        printed,
        fingerprint(&first_der(&String::from_utf8_lossy(&root))),
        "the printed value is the value that was pinned"
    );
    // The TOFU preset publishes no expected value, so nothing is compared.
    assert!(!stdout.contains("root fingerprint matches"), "{stdout}");
}

/// The three presets with a published root refuse a different one, leave no
/// anchor behind, and name both values.
#[test]
fn a_published_fingerprint_mismatch_is_refused() {
    let repo = Repo::new();
    repo.init();
    let ca = std::fs::read_to_string(&repo.authority.ca).expect("the CA");
    let der = first_der(&ca);

    for id in ["sectigo", "certum", "izenpe"] {
        let added = repo.run_time_env(&["tsa", "preset", "add", id], &repo.fetch_ca());
        assert_eq!(
            added.status.code(),
            Some(1),
            "{id}: {}",
            text(&added.stderr)
        );
        assert!(
            !repo.anchors().join(format!("{id}.pem")).exists(),
            "{id}: nothing is pinned"
        );
        let stderr = text(&added.stderr);
        assert!(stderr.contains(id), "{id} is named: {stderr}");
        assert!(stderr.contains("does not match"), "{stderr}");
        let published = git_time_core::presets::find(id)
            .and_then(|preset| preset.fingerprint)
            .expect("a published root");
        assert!(stderr.contains(published), "{id}: {stderr}");
        // The fetched value is printed in the same digest length as the
        // published one, so it can be compared side by side.
        let fetched = if published.split(':').count() == 20 {
            git_time_core::trust::sha1_fingerprint(&der)
        } else {
            fingerprint_colon(&der)
        };
        assert!(stderr.contains(&fetched), "{id}: {stderr}");
        // The entry is still configured, so doctor can name the gap.
        assert!(repo.config(&format!("time.tsa.{id}.url")).is_some(), "{id}");
    }
}

#[test]
fn an_http_preset_records_the_insecure_transport() {
    let repo = Repo::new();
    repo.init();

    let added = repo.run_time_env(&["tsa", "preset", "add", "certum"], &repo.fetch_ca());
    assert_eq!(added.status.code(), Some(1), "{}", text(&added.stderr));
    assert_eq!(
        repo.config("time.tsa.certum.insecure-http").as_deref(),
        Some("true"),
        "the acceptance is recorded, the mismatch does not remove it"
    );

    let listing = ok(&repo.run_time(&["tsa", "list"]));
    let line = listing
        .lines()
        .find(|line| line.starts_with("certum "))
        .expect("the id is listed");
    assert!(line.ends_with("insecure-http"), "{line}");

    let json = ok(&repo.run_time(&["tsa", "list", "--json"]));
    assert!(json.contains("\"insecure_http\": true"), "{json}");
}

#[test]
fn tsa_add_writes_the_insecure_transport_when_accepted() {
    let repo = Repo::new();
    repo.init();

    let refused = repo.run_time(&["tsa", "add", "http://tsa.example/tsr", "--id", "acme"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert_eq!(repo.config("time.tsa.acme.url"), None, "nothing is written");

    repo.add_tsa("acme", "http://tsa.example/tsr");
    assert_eq!(
        repo.config("time.tsa.acme.insecure-http").as_deref(),
        Some("true")
    );

    // An https authority keeps the key absent.
    repo.add_tsa("safe", "https://tsa.example/tsr");
    assert_eq!(repo.config("time.tsa.safe.insecure-http"), None);
}

/// The prompt `tsa select` prints, so the count of re-asks can be counted.
const SELECT_PROMPT: &str = "Authorities to enable (e.g. 1,3-4, all, none): ";

/// Enable exactly the selected three, with their keys and a printed
/// fingerprint each.
#[test]
fn select_enables_exactly_the_chosen_authorities() {
    let repo = Repo::new();
    repo.init();

    let chosen = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive"],
        &repo.fetch_known_root(),
        "1,2,9\n",
    );
    assert_eq!(chosen.status.code(), Some(0), "{}", text(&chosen.stderr));

    let stdout = text(&chosen.stdout);
    for (id, url) in [
        ("freetsa", "https://freetsa.org/tsr"),
        ("ai-moda", "https://rfc3161.ai.moda"),
        ("cartaodecidadao", "http://ts.cartaodecidadao.pt/tsa/server"),
    ] {
        assert_eq!(
            repo.config(&format!("time.tsa.{id}.url")).as_deref(),
            Some(url)
        );
        assert_eq!(
            repo.config(&format!("time.tsa.{id}.alg")).as_deref(),
            Some("sha256")
        );
        assert!(repo.config(&format!("time.tsa.{id}.anchor")).is_some());
        assert!(repo.anchors().join(format!("{id}.pem")).exists(), "{id}");
        let line = stdout
            .lines()
            .find(|line| line.starts_with(&format!("enabled {id} ")))
            .unwrap_or_else(|| panic!("{id} enabled: {stdout}"));
        let printed = fingerprint_after(line, "fingerprint ");
        assert_eq!(printed.len(), 64, "{line}");
    }

    // Anything not chosen stays unconfigured.
    for id in ["sectigo", "certum", "izenpe", "aped"] {
        assert_eq!(repo.config(&format!("time.tsa.{id}.url")), None, "{id}");
    }
}

/// `none` removes the preset sections and leaves a hand-added authority alone.
#[test]
fn select_none_removes_preset_sections_but_not_hand_added_ones() {
    let repo = Repo::new();
    repo.init();
    let enabled = repo.run_time_env(
        &["tsa", "select", "--preset", "public"],
        &repo.fetch_known_root(),
    );
    assert!(
        repo.config("time.tsa.freetsa.url").is_some(),
        "{}",
        text(&enabled.stderr)
    );
    repo.add_tsa("acme", "http://tsa.example/tsr");

    let cleared = repo.run_time(&["tsa", "select", "--preset", "none"]);
    assert_eq!(cleared.status.code(), Some(0), "{}", text(&cleared.stderr));
    for id in git_time_core::presets::names() {
        assert_eq!(repo.config(&format!("time.tsa.{id}.url")), None, "{id}");
    }
    assert_eq!(
        repo.config("time.tsa.acme.url").as_deref(),
        Some("http://tsa.example/tsr"),
        "a hand-added section is not a preset's"
    );
    let stdout = text(&cleared.stdout);
    assert!(stdout.contains("disabled freetsa"), "{stdout}");
    assert!(!stdout.contains("disabled acme"), "{stdout}");
}

#[test]
fn select_reasks_three_times_then_exits_two() {
    let repo = Repo::new();
    repo.init();

    let refused = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive"],
        &repo.fetch_known_root(),
        "x\n99\n4-2\n",
    );
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert_eq!(
        text(&refused.stdout).matches(SELECT_PROMPT).count(),
        3,
        "one prompt per attempt: {}",
        text(&refused.stdout)
    );
    let stderr = text(&refused.stderr);
    assert!(stderr.contains("is not a selection"), "{stderr}");
    assert!(stderr.contains("counts backwards"), "{stderr}");
}

#[test]
fn select_refuses_a_non_terminal_stdin_and_names_the_alternatives() {
    let repo = Repo::new();
    repo.init();

    let refused = repo.run_time(&["tsa", "select"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    let stderr = text(&refused.stderr);
    assert!(stderr.contains("not a terminal"), "{stderr}");
    assert!(stderr.contains("tsa preset add"), "{stderr}");
    assert!(stderr.contains("tsa add"), "{stderr}");
    // Nothing was prompted, so nothing hangs a script.
    assert!(!text(&refused.stdout).contains(SELECT_PROMPT));
}

#[test]
fn select_dry_run_prints_the_plan_and_writes_nothing() {
    let repo = Repo::new();
    repo.init();

    let plan = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive", "--dry-run"],
        &repo.fetch_known_root(),
        "1,2\n",
    );
    assert_eq!(plan.status.code(), Some(0), "{}", text(&plan.stderr));
    let stdout = text(&plan.stdout);
    assert!(stdout.contains("would enable freetsa"), "{stdout}");
    assert!(stdout.contains("would enable ai-moda"), "{stdout}");
    assert_eq!(repo.config("time.tsa.freetsa.url"), None, "nothing written");
    assert!(!repo.anchors().join("freetsa.pem").exists());

    // A dry run of `none` says what it would remove and removes nothing.
    assert!(
        repo.run_time_env(
            &["tsa", "select", "--preset", "public"],
            &repo.fetch_known_root()
        )
        .status
        .code()
        .is_some()
    );
    let dry = repo.run_time(&["tsa", "select", "--preset", "none", "--dry-run"]);
    assert_eq!(dry.status.code(), Some(0), "{}", text(&dry.stderr));
    assert!(text(&dry.stdout).contains("would disable freetsa"));
    assert!(
        repo.config("time.tsa.freetsa.url").is_some(),
        "still enabled"
    );
}

#[test]
fn select_reports_a_failed_authority_and_still_pins_the_others() {
    let repo = Repo::new();
    repo.init();
    let fetch = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!(
            "case \"$GIT_TIME_ANCHOR_URL\" in https://freetsa.org/*) cat {} ;; *) exit 1 ;; esac",
            pstr(&freetsa_root())
        ),
    )];

    let chosen = repo.run_time_with_stdin(&["tsa", "select", "--interactive"], &fetch, "1,2\n");
    assert_eq!(chosen.status.code(), Some(1), "{}", text(&chosen.stderr));
    let stdout = text(&chosen.stdout);
    assert!(stdout.contains("enabled freetsa "), "{stdout}");
    assert!(
        stdout.contains("failed ai-moda: no anchor could be pinned"),
        "{stdout}"
    );
    assert!(repo.anchors().join("freetsa.pem").exists());
    assert_eq!(
        repo.config("time.tsa.ai-moda.url").as_deref(),
        Some("https://rfc3161.ai.moda")
    );
}

/// A query string is part of the endpoint: it has to survive validation and
/// land in the config exactly as given.
#[test]
fn a_query_string_is_stored_verbatim() {
    let repo = Repo::new();
    repo.init();
    let url = "http://tsa.cra.ge/signserver/tsa?workerName=qtsa";

    repo.add_tsa("cra-ge", url);
    assert_eq!(
        repo.config("time.tsa.cra-ge.url").as_deref(),
        Some(url),
        "the query is not stripped"
    );

    // The preset carries the same endpoint, so the two cannot drift.
    let preset = git_time_core::presets::find("cra-ge").expect("the preset exists");
    assert_eq!(preset.url, url);
    assert_eq!(preset.anchor_url, url);
}

#[test]
fn preset_add_exits_one_when_the_fetch_leaves_no_anchor() {
    let repo = Repo::new();
    repo.init();

    let failed = repo.run_time_env(
        &["tsa", "preset", "add", "freetsa"],
        &[("GIT_TIME_ANCHOR_FETCH_CMD", "false".to_owned())],
    );
    assert_eq!(failed.status.code(), Some(1), "{}", text(&failed.stderr));
    assert!(
        text(&failed.stderr).contains("no anchor"),
        "the warning is kept: {}",
        text(&failed.stderr)
    );
    // The entry is still listed, so doctor can name the missing anchor.
    assert_eq!(
        repo.config("time.tsa.freetsa.url").as_deref(),
        Some("https://freetsa.org/tsr")
    );

    let added = repo.run_time_env(
        &["tsa", "preset", "add", "freetsa"],
        &repo.fetch_known_root(),
    );
    assert_eq!(added.status.code(), Some(0), "{}", text(&added.stderr));
}

#[test]
fn every_registry_command_refuses_outside_a_repository() {
    let dir = TempDir::new().expect("a plain directory");
    let xdg = TempDir::new().expect("xdg dir");
    let cases: &[&[&str]] = &[
        &["tsa", "list"],
        &["tsa", "add", "https://a.example/tsr"],
        &["tsa", "remove", "a"],
        &["tsa", "preset", "list"],
        &["tsa", "preset", "add", "freetsa"],
        &["anchor", "list"],
        &["anchor", "fetch", "https://a.example/ca.pem", "--id", "a"],
        &["anchor", "pin"],
        &["anchor", "pin", "--check"],
        &["tsa", "select", "--preset", "public"],
    ];
    for args in cases {
        let output = run_time_at(dir.path(), xdg.path(), args, &[]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&output.stderr)
        );
    }
}
