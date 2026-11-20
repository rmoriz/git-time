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
//!
//! The throwaway certificates are built for LibreSSL as well as OpenSSL:
//! `-sha256` and a named curve, because LibreSSL's defaults (SHA-1 signatures,
//! explicit EC parameters) are outside what `webpki` verifies, and a per-CA
//! serial file because `-CAcreateserial` writes into the shared temp directory
//! and races between parallel fixtures.

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

/// A self-signed CA whose validity window closed in 2020, so every reader of the
/// bundle finds a root that is not valid now.
fn stale_ca(dir: &Path) -> PathBuf {
    let key = dir.join("stale-key.pem");
    let ca = dir.join("stale-ca.pem");
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
        &pstr(&key),
        "-out",
        &pstr(&ca),
        "-not_before",
        "20200101000000Z",
        "-not_after",
        "20200201000000Z",
        "-subj",
        "/CN=stale-ca",
        "-config",
        &ca_config(dir),
        "-extensions",
        "v3_ca",
    ]);
    ca
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
            "/CN=registry-ca",
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
        // Generous: the suite runs dozens of repositories at once and a 5s
        // budget has expired under CI load. See hook_flows.rs.
        git(self.path(), &["config", "time.deadline", "30s"]);

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

    /// Run the binary with `input` on a terminal.
    fn run_time_pty(&self, args: &[&str], env: &[(&str, String)], input: &str) -> Option<Output> {
        run_time_pty(self.path(), self.xdg.path(), args, env, input)
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

    /// Append `bundle`'s certificates to `id`'s anchor, as an accept does.
    fn append_anchor(&self, id: &str, bundle: &[u8]) {
        let path = self.anchors().join(format!("{id}.pem"));
        let mut bytes = std::fs::read(&path).expect("the pinned anchor");
        bytes.extend_from_slice(bundle);
        std::fs::write(&path, bytes).expect("append the root");
    }

    /// Commit an empty change whose message names `ids` in a token trailer.
    ///
    /// The hook is skipped with `drop`, so the message reaches the object as
    /// it was written: `restore` reads the ids the way a clone would.
    fn commit_naming(&self, ids: &[&str]) {
        self.commit_naming_roots(&ids.iter().map(|id| (*id, "")).collect::<Vec<_>>());
    }

    /// A block that also names the root each id was sealed under, as a seal
    /// writes it. An empty fingerprint leaves the id without an `Anchor` line.
    fn commit_naming_roots(&self, entries: &[(&str, &str)]) {
        let mut anchors: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut ids: Vec<&str> = Vec::new();
        for (id, fingerprint) in entries {
            if !fingerprint.is_empty() {
                anchors
                    .entry((*id).to_owned())
                    .or_default()
                    .push((*fingerprint).to_owned());
            }
            if !ids.contains(id) {
                ids.push(id);
            }
        }
        let skip = self.run_time(&["drop"]);
        assert!(skip.status.success(), "{}", text(&skip.stderr));
        // A real block, so the id is read exactly as it is from a sealed commit
        // without needing a TSA: the token bytes are never judged here.
        let block = git_time_core::store::TrailerBlock {
            imprint: git_time_core::imprint::Digest {
                alg: git_time_core::imprint::Alg::Sha256,
                bytes: vec![0; 32],
            },
            object: None,
            anchors,
            tokens: ids
                .iter()
                .map(|id| git_time_core::store::TokenRecord {
                    id: (*id).to_owned(),
                    alg: git_time_core::imprint::Alg::Sha256,
                    policy: None,
                    nonce: vec![0; 8],
                    token: vec![1, 2, 3],
                })
                .collect(),
            failures: Vec::new(),
            extra: Vec::new(),
        };
        let encoded = git_time_core::store::encode(&block, 64 * 1024).expect("encode the block");
        let mut message = String::from("sealed elsewhere\n\n");
        message.push_str(&String::from_utf8(encoded).expect("the block is text"));
        message.push('\n');
        let path = self.path().join("message.txt");
        std::fs::write(&path, message).expect("write message");
        git(
            self.path(),
            &["commit", "-q", "--allow-empty", "-F", "message.txt"],
        );
        std::fs::remove_file(&path).expect("remove message");
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

/// Quote `word` so `/bin/sh` reads it back as one word.
#[cfg(not(target_os = "macos"))]
fn sh_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Run the binary with `input` on a pseudo-terminal, the way an interactive
/// caller arrives.
///
/// `script(1)` is what supplies the terminal: the suite's own stdin is a pipe, so
/// the branches gated on `is_terminal` would never run otherwise. `None` when no
/// `script` is installed, so the suite still runs where it is missing.
///
/// The two `script`s disagree on how the command is named — util-linux wants one
/// `-c` line, BSD/macOS wants it positionally — and `-e` makes the child's status
/// the exit status on both. Only macOS is built here; another BSD would need the
/// positional branch too.
fn run_time_pty(
    dir: &Path,
    xdg: &Path,
    args: &[&str],
    env: &[(&str, String)],
    input: &str,
) -> Option<Output> {
    // The answer arrives from a file rather than a pipe: `script` reads its own
    // stdin and forwards it, and a pipe there can already be closed by the time
    // the picker quits on Linux (EPIPE on the tail).
    let answer = xdg.join("pty-answer");
    std::fs::write(&answer, input).ok()?;
    let mut script = Command::new("script");
    script.arg("-q").arg("-e").arg("/dev/null");
    #[cfg(target_os = "macos")]
    script.arg(BIN).arg("-C").arg(dir).args(args);
    #[cfg(not(target_os = "macos"))]
    {
        let mut line: Vec<String> = vec![BIN.to_owned(), "-C".to_owned(), pstr(dir)];
        line.extend(args.iter().map(|arg| (*arg).to_owned()));
        let line: Vec<String> = line.iter().map(|word| sh_quote(word)).collect();
        script.arg("-c").arg(line.join(" "));
    }
    let child = script
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_TIME_SKIP")
        .envs(insulated_env().iter().copied())
        .env("PATH", path_env())
        .env("XDG_CONFIG_HOME", xdg)
        .envs(env.iter().map(|(key, value)| (*key, value.as_str())))
        .stdin(Stdio::from(std::fs::File::open(&answer).ok()?))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child.wait_with_output().ok()
}

fn ok(output: &Output) -> String {
    assert!(output.status.success(), "{}", text(&output.stderr));
    text(&output.stdout)
}

/// The token after `marker` in `stdout`, asserted to be a SHA-256 in hex.
fn fingerprint_after(stdout: &str, marker: &str) -> String {
    let rest = stdout
        .rsplit_once(marker)
        .unwrap_or_else(|| panic!("`{marker}` in {stdout}"))
        .1;
    let token = rest
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("a fingerprint after `{marker}` in {stdout}"));
    // Colon separated uppercase: 20 octets (59) or 32 octets (95).
    assert!(
        token.len() == 59 || token.len() == 95,
        "a SHA-1 or a SHA-256 fingerprint: {token}"
    );
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b':'),
        "a fingerprint is hex: {token}"
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

/// A root that is not the pinned one is a rotation, and a fetch alone keeps
/// refusing it: the fetched value has to be accepted by fingerprint, then it is
/// appended next to the retired root instead of overwriting it.
#[test]
fn fetch_refuses_a_changed_root_and_appends_it_on_accept() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    repo.add_tsa("stub", &repo.stub_url());
    assert!(
        repo.fetch_anchor("stub").status.success(),
        "the first root is pinned"
    );
    let anchor = repo.anchors().join("stub.pem");
    let pinned = std::fs::read(&anchor).expect("the pinned anchor");
    let pinned_der = first_der(&text(&pinned));
    let expected = git_time_core::trust::fingerprint(&pinned_der);

    // A second authority answers at the same URL: a new root.
    let rotated = Authority::new();
    let fetched = rotated.bytes();
    let found = git_time_core::trust::fingerprint(&first_der(&text(&fetched)));
    let served = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat {}", pstr(&rotated.ca)),
    )];

    let refused = repo.run_time_env(
        &[
            "anchor",
            "fetch",
            &repo.stub_url(),
            "--id",
            "stub",
            "--insecure-http",
        ],
        &served,
    );
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused.stderr));
    let stderr = text(&refused.stderr);
    assert!(stderr.contains(&expected), "the pinned value: {stderr}");
    assert!(stderr.contains(&found), "the fetched value: {stderr}");
    assert_eq!(
        std::fs::read(&anchor).expect("the anchor"),
        pinned,
        "the refusal changes nothing"
    );

    let accepted = repo.run_time_env(
        &[
            "anchor",
            "fetch",
            &repo.stub_url(),
            "--id",
            "stub",
            "--insecure-http",
            "--accept",
            &found,
        ],
        &served,
    );
    let stdout = ok(&accepted);
    assert!(
        stdout.contains("1 root(s) appended, 2 now pinned"),
        "{stdout}"
    );
    let store = git_time_core::trust::AnchorStore::load(&[("stub".to_owned(), anchor.clone())])
        .expect("both roots load");
    let roots = &store.anchor("stub").expect("an anchor").roots;
    assert_eq!(roots.len(), 2, "the retired root stays next to the new one");
    assert_eq!(
        fingerprint_colon(roots[0].as_bytes()),
        found,
        "the accepted root is the first certificate every listing reports"
    );
}

/// An accept that names another value is not a confirmation: nothing is written.
#[test]
fn accept_with_a_wrong_fingerprint_changes_nothing() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    repo.add_tsa("stub", &repo.stub_url());
    assert!(repo.fetch_anchor("stub").status.success());
    let anchor = repo.anchors().join("stub.pem");
    let pinned = std::fs::read(&anchor).expect("the pinned anchor");

    let rotated = Authority::new();
    let served = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat {}", pstr(&rotated.ca)),
    )];
    // A well-formed SHA-1 of some other bytes, so only the value is wrong.
    let wrong = git_time_core::trust::sha1_fingerprint(b"another root");

    let accepted = repo.run_time_env(
        &[
            "anchor",
            "fetch",
            &repo.stub_url(),
            "--id",
            "stub",
            "--insecure-http",
            "--accept",
            &wrong,
        ],
        &served,
    );
    assert_eq!(
        accepted.status.code(),
        Some(1),
        "{}",
        text(&accepted.stderr)
    );
    assert!(
        text(&accepted.stderr).contains("does not match"),
        "{}",
        text(&accepted.stderr)
    );
    assert_eq!(
        std::fs::read(&anchor).expect("the anchor"),
        pinned,
        "the bundle is byte for byte what it was"
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

/// A root that closed in 2020 is not only named: the authority listing says
/// `expired` right where the next choice is made.
#[test]
fn tsa_list_marks_an_expired_root() {
    let repo = Repo::new();
    repo.init();
    repo.add_tsa("stale", "https://stale.example/tsr");
    let stale = stale_ca(repo.path());
    std::fs::create_dir_all(repo.anchors()).expect("anchors dir");
    std::fs::copy(&stale, repo.anchors().join("stale.pem")).expect("pin the stale CA");

    let listing = ok(&repo.run_time(&["tsa", "list"]));
    let root = listing
        .lines()
        .find(|line| line.trim_start().starts_with("root "))
        .unwrap_or_else(|| panic!("a root line: {listing}"));
    assert!(root.contains("2020-02-01"), "the date: {listing}");
    assert!(root.ends_with("expired"), "the verdict: {listing}");

    // The authority line speaks about its first root, so it carries the date
    // too: a reader who greps for the id sees it.
    let authority = listing.lines().next().expect("the authority line");
    assert!(authority.starts_with("stale "), "{listing}");
    assert!(authority.contains("2020-02-01 expired"), "{listing}");
}

/// The date is a machine field of its own, day-only, next to the fingerprint.
#[test]
fn json_carries_not_after() {
    let repo = Repo::with_pinned_stub();
    let stdout = ok(&repo.run_time(&["tsa", "list", "--json"]));
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("list --json is JSON");
    let date = value[0]["not_after"]
        .as_str()
        .unwrap_or_else(|| panic!("a not_after field: {stdout}"));
    assert_eq!(date.len(), 10, "a day, not an instant: {date}");
    assert_eq!(date.as_bytes()[4], b'-', "{date}");
    assert_eq!(date.as_bytes()[7], b'-', "{date}");
    // The roots array carries the same date and says it is still ahead.
    assert_eq!(value[0]["roots"][0]["not_after"], date, "{stdout}");
    assert_eq!(value[0]["roots"][0]["expired"], false, "{stdout}");
}

/// A section with only a `url` (what `tsa add` without `--anchor` leaves) still
/// pins at the default path, so its bundle is in use and must be listed.
#[test]
fn anchor_list_shows_a_bundle_of_a_url_only_section() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    // Hand-written, because `tsa add` always writes an `anchor` key: the section
    // carries a `url` alone, so the policy refuses it (`Missing anchor`) and only
    // the fallback to the default path can find the bundle. Fetching there pins
    // and uses it, so the listing must not make it invisible.
    let url = repo.stub_url();
    git(
        repo.path(),
        &["config", "--local", "time.tsa.stub.url", &url],
    );
    let fetched = repo.fetch_anchor("stub");
    assert!(fetched.status.success(), "{}", text(&fetched.stderr));
    let anchor = repo.anchors().join("stub.pem");
    assert!(anchor.exists(), "the default path is pinned and in use");
    let expected = fingerprint(&first_der(&text(&repo.authority.bytes())));

    let listing = ok(&repo.run_time(&["anchor", "list"]));
    assert!(listing.contains("stub"), "{listing}");
    assert!(
        listing.contains(&pstr(&anchor)),
        "the path is listed: {listing}"
    );
    assert!(listing.contains(&expected), "the root is listed: {listing}");
}

/// Every root of a chained bundle gets a line, in file order; the authority
/// line stays on the first certificate the lock names as the run's own root.
#[test]
fn anchor_list_names_every_root_with_its_date() {
    let repo = Repo::with_pinned_stub();
    let first = fingerprint(&first_der(&text(&repo.authority.bytes())));
    let fresh = Authority::new();
    let second = fingerprint(&first_der(&text(&fresh.bytes())));
    repo.append_anchor("stub", &fresh.bytes());

    let listing = ok(&repo.run_time(&["anchor", "list"]));
    let roots: Vec<&str> = listing
        .lines()
        .filter(|line| line.trim_start().starts_with("root "))
        .collect();
    assert_eq!(roots.len(), 2, "one line per root: {listing}");
    assert!(roots[0].contains(&first), "file order: {listing}");
    assert!(roots[1].contains(&second), "file order: {listing}");
    for line in &roots {
        assert_eq!(
            line.split_whitespace().nth(2).map(str::len),
            Some(10),
            "a day-only date: {line}"
        );
    }
    let authority = listing.lines().next().expect("the authority line");
    assert!(authority.starts_with("stub "), "{listing}");
    assert!(authority.contains(&first), "{listing}");

    let json = ok(&repo.run_time(&["anchor", "list", "--json"]));
    let value: serde_json::Value = serde_json::from_str(&json).expect("list --json is JSON");
    assert_eq!(
        value[0]["fingerprint"], first,
        "the top level stays the first"
    );
    assert_eq!(
        value[0]["roots"].as_array().map(Vec::len),
        Some(2),
        "{json}"
    );
    assert_eq!(value[0]["roots"][1]["fingerprint"], second, "{json}");
}

/// The authority line names one certificate: the first *root*. A bundle that
/// puts the authority's leaf first must not pair the leaf's fingerprint with the
/// root's date.
#[test]
fn the_authority_line_takes_fingerprint_and_date_from_the_first_root() {
    let repo = Repo::with_pinned_stub();
    let leaf = repo.authority.dir.path().join("leaf.pem");
    let mut bundle = std::fs::read(&leaf).expect("the leaf");
    bundle.extend(std::fs::read(&repo.authority.ca).expect("the root"));
    std::fs::write(repo.anchors().join("stub.pem"), bundle).expect("write the bundle");

    let root_fingerprint = fingerprint(&first_der(&text(&repo.authority.bytes())));
    let leaf_fingerprint = fingerprint(&first_der(
        &std::fs::read_to_string(&leaf).expect("the leaf PEM"),
    ));
    assert_ne!(root_fingerprint, leaf_fingerprint, "the two differ");

    for command in [["anchor", "list"], ["tsa", "list"]] {
        let listing = ok(&repo.run_time(&command));
        let authority = listing.lines().next().expect("the authority line");
        assert!(
            authority.contains(&root_fingerprint),
            "{command:?}: {listing}"
        );
        assert!(
            !authority.contains(&leaf_fingerprint),
            "{command:?}: {listing}"
        );
    }
}

/// A bundle the store rejects still says so, instead of reading as an empty one
/// next to a `pinned:true` the fingerprint no longer backs.
#[test]
fn anchor_list_names_an_unreadable_bundle() {
    let repo = Repo::with_pinned_stub();
    std::fs::write(repo.anchors().join("stub.pem"), "prose, not a bundle\n").expect("write prose");

    let listing = ok(&repo.run_time(&["anchor", "list"]));
    let lines: Vec<&str> = listing.lines().collect();
    assert!(lines[0].contains("pinned:false"), "{listing}");
    assert_eq!(lines[1].trim(), "(bundle unreadable)", "{listing}");
    assert!(!listing.contains(" root "), "{listing}");

    // The JSON says the same by having no fingerprint and no roots.
    let json = ok(&repo.run_time(&["anchor", "list", "--json"]));
    let value: serde_json::Value = serde_json::from_str(&json).expect("list --json is JSON");
    assert!(value[0]["fingerprint"].is_null(), "{json}");
    assert_eq!(value[0]["pinned"], false, "{json}");
    assert_eq!(
        value[0]["roots"].as_array().map(Vec::len),
        Some(0),
        "{json}"
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

/// The lock records every root, so a rotation is a diff of two lines rather
/// than an update of one value: the new root shows as `added`, a retired one as
/// `removed`.
#[test]
fn check_reports_an_added_root_after_an_accept() {
    let repo = Repo::with_pinned_stub();
    assert!(
        repo.run_time(&["anchor", "pin"]).status.success(),
        "the lock starts with the pinned root"
    );

    let fresh = Authority::new();
    let expected = fingerprint(&first_der(&text(&fresh.bytes())));
    repo.append_anchor("stub", &fresh.bytes());

    let checked = repo.run_time(&["anchor", "pin", "--check"]);
    assert_eq!(checked.status.code(), Some(1), "{}", text(&checked.stderr));
    let stderr = text(&checked.stderr);
    assert!(
        stderr.contains(&format!("added stub {expected}")),
        "the appended root is named as added: {stderr}"
    );
    assert!(
        !stderr.contains("mismatch stub"),
        "the pinned root did not change: {stderr}"
    );

    // A re-pin records both roots, and the check passes until the next one.
    assert!(repo.run_time(&["anchor", "pin"]).status.success());
    let lock = std::fs::read_to_string(repo.lock()).expect("the lock");
    assert_eq!(lock.lines().count(), 2, "{lock}");
    assert!(
        lock.lines().any(|line| line == format!("stub {expected}")),
        "the new root gets its own line: {lock}"
    );
    assert!(
        repo.run_time(&["anchor", "pin", "--check"])
            .status
            .success()
    );
}

/// A root that was dropped from the bundle is still in the lock: it is reported
/// as removed, not as a changed line.
#[test]
fn check_reports_a_removed_root() {
    let repo = Repo::with_pinned_stub();
    let pinned = std::fs::read(repo.anchors().join("stub.pem")).expect("the anchor");
    let dropped = fingerprint(&first_der(&text(&pinned)));
    assert!(repo.run_time(&["anchor", "pin"]).status.success());

    // A bundle that keeps only the second root: the first is retired.
    let fresh = Authority::new();
    repo.append_anchor("stub", &fresh.bytes());
    assert!(repo.run_time(&["anchor", "pin"]).status.success());
    std::fs::write(repo.anchors().join("stub.pem"), fresh.bytes()).expect("drop the first root");

    let checked = repo.run_time(&["anchor", "pin", "--check"]);
    assert_eq!(checked.status.code(), Some(1), "{}", text(&checked.stderr));
    let stderr = text(&checked.stderr);
    assert!(
        stderr.contains(&format!("removed stub {dropped}")),
        "the dropped root is named: {stderr}"
    );
}

/// The order of the lines is the sort order, not the file order: swapping two
/// roots in the bundle is not drift.
#[test]
fn a_reordered_bundle_matches_the_lock() {
    let repo = Repo::with_pinned_stub();
    let anchor = repo.anchors().join("stub.pem");
    let pinned = std::fs::read(&anchor).expect("the anchor");
    let pinned_first = fingerprint(&first_der(&text(&pinned)));
    assert!(repo.run_time(&["anchor", "pin"]).status.success());

    let fresh = Authority::new();
    repo.append_anchor("stub", &fresh.bytes());
    assert!(repo.run_time(&["anchor", "pin"]).status.success());
    let lock = std::fs::read(repo.lock()).expect("the lock");
    // The pinned root is the first certificate; put the appended one in front.
    let bundle = std::fs::read_to_string(&anchor).expect("the bundle");
    let fresh_bytes = String::from_utf8(fresh.bytes()).expect("PEM is text");
    let rest = bundle
        .strip_suffix(&fresh_bytes)
        .expect("the appended block is last");
    std::fs::write(&anchor, format!("{fresh_bytes}{rest}")).expect("swap the roots");

    // The swap really happened: the first certificate is the appended root now.
    let swapped = std::fs::read(&anchor).expect("the bundle");
    let now_first = fingerprint(&first_der(&text(&swapped)));
    assert_ne!(now_first, pinned_first, "the bundle order changed");
    assert_eq!(
        now_first,
        fingerprint(&first_der(&text(&fresh.bytes()))),
        "the appended root is the first certificate"
    );

    let checked = repo.run_time(&["anchor", "pin", "--check"]);
    assert!(
        checked.status.success(),
        "a reorder is no drift: {}",
        text(&checked.stderr)
    );
    // `check` never writes: the lock bytes are the ones `pin` wrote, still in
    // sorted line order although the bundle order reversed.
    assert_eq!(
        std::fs::read(repo.lock()).expect("the lock"),
        lock,
        "the check writes nothing"
    );
    let lines: Vec<&str> = std::str::from_utf8(&lock)
        .expect("the lock is text")
        .lines()
        .collect();
    let mut sorted = lines.clone();
    sorted.sort_unstable();
    assert_eq!(lines, sorted, "the lock keeps the sorted order");
}

/// A line with an id but no fingerprint names the id and no value: it is drift.
#[test]
fn check_refuses_a_lock_line_without_a_fingerprint() {
    let repo = Repo::with_pinned_stub();
    assert!(repo.run_time(&["anchor", "pin"]).status.success());
    let lock = std::fs::read_to_string(repo.lock()).expect("the lock");
    std::fs::write(repo.lock(), format!("{lock}stub \n")).expect("write a bare id line");

    let checked = repo.run_time(&["anchor", "pin", "--check"]);
    assert_eq!(checked.status.code(), Some(1), "{}", text(&checked.stderr));
    assert!(
        text(&checked.stderr).contains("mismatch stub: anchor is unparseable"),
        "{}",
        text(&checked.stderr)
    );
}

/// A broken line for a locked id wins over the pair difference: the id is
/// unparseable, so a same-id `added`/`removed` pair would say it twice.
#[test]
fn a_broken_line_suppresses_the_pair_difference_for_its_id() {
    let repo = Repo::with_pinned_stub();
    assert!(repo.run_time(&["anchor", "pin"]).status.success());
    // A second root, so the pair difference would be non-empty anyway.
    let fresh = Authority::new();
    repo.append_anchor("stub", &fresh.bytes());
    let lock = std::fs::read_to_string(repo.lock()).expect("the lock");
    std::fs::write(repo.lock(), format!("{lock}stub\n")).expect("write a broken line");

    let checked = repo.run_time(&["anchor", "pin", "--check"]);
    assert_eq!(checked.status.code(), Some(1), "{}", text(&checked.stderr));
    let stderr = text(&checked.stderr);
    assert!(
        stderr.contains("mismatch stub: anchor is unparseable"),
        "{stderr}"
    );
    assert!(!stderr.contains("added stub"), "{stderr}");
    assert!(!stderr.contains("removed stub"), "{stderr}");
}

/// Whitespace around a line belongs to neither the id nor the fingerprint.
#[test]
fn leading_whitespace_still_keys_the_id() {
    let repo = Repo::with_pinned_stub();
    assert!(repo.run_time(&["anchor", "pin"]).status.success());
    let lock = std::fs::read_to_string(repo.lock()).expect("the lock");
    let indented: String = lock.lines().map(|line| format!("  {line}\n")).collect();
    std::fs::write(repo.lock(), indented).expect("indent the lock");

    let checked = repo.run_time(&["anchor", "pin", "--check"]);
    assert!(checked.status.success(), "{}", text(&checked.stderr));
}

/// A lock line that cannot be parsed is drift, never silently dropped.
#[test]
fn check_refuses_an_unparseable_lock_line() {
    let repo = Repo::with_pinned_stub();
    assert!(repo.run_time(&["anchor", "pin"]).status.success());
    let lock = std::fs::read_to_string(repo.lock()).expect("the lock");
    std::fs::write(repo.lock(), format!("{lock}stub\n")).expect("write a broken line");

    let checked = repo.run_time(&["anchor", "pin", "--check"]);
    assert_eq!(checked.status.code(), Some(1), "{}", text(&checked.stderr));
    assert!(
        text(&checked.stderr).contains("mismatch stub: anchor is unparseable"),
        "{}",
        text(&checked.stderr)
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
    // The published roots are shown, no row is TOFU any more, and a plain-http
    // endpoint is visible as such.
    assert!(listing.contains("https://freetsa.org/tsr"), "{listing}");
    assert!(
        listing.contains("A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC"),
        "{listing}"
    );
    assert!(!listing.contains("tofu"), "{listing}");
    // Every row carries a fingerprint of its own instead.
    for preset in &git_time_core::presets::PRESETS {
        let published = preset.fingerprints.last().expect("a published root");
        assert!(
            listing
                .lines()
                .any(|line| line.starts_with(preset.name) && line.contains(published)),
            "{}: {listing}",
            preset.name
        );
    }
    assert!(listing.contains("http://time.certum.pl"), "{listing}");
    // The scope is a column: only the curated pair is a default.
    for name in ["freetsa", "digicert"] {
        assert!(
            listing
                .lines()
                .any(|line| line.starts_with(name) && line.contains(" default ")),
            "{name} is a default: {listing}"
        );
    }
    assert!(
        listing
            .lines()
            .any(|line| line.starts_with("sectigo") && line.contains(" opt-in ")),
        "the rest is opt-in: {listing}"
    );
}

/// A published root has a fingerprint but no local certificate, so it has no
/// date to read and says `-`/`(missing)` rather than fetching one — and no
/// longer says `tofu`.
#[test]
fn preset_list_says_no_date_for_a_published_root_without_a_local_pin() {
    let repo = Repo::new();
    repo.init();

    let listing = ok(&repo.run_time(&["tsa", "preset", "list"]));
    let fields = |prefix: &str| -> Vec<String> {
        listing
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("`{prefix}` in {listing}"))
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    };
    let sectigo = fields("sectigo ");
    assert_eq!(
        sectigo[4],
        *git_time_core::presets::find("sectigo")
            .expect("the preset")
            .fingerprints
            .last()
            .expect("a published value"),
        "the fingerprint is still printed: {listing}"
    );
    assert_eq!(
        sectigo[5], "-",
        "a published root without a local pin has no date: {listing}"
    );
    assert_eq!(sectigo[6], "(missing)", "{listing}");
    // The same is true of the curated row, and neither says `tofu`.
    let freetsa = fields("freetsa ");
    assert_eq!(
        freetsa[5], "-",
        "a published root without a local pin has no date: {listing}"
    );
    assert_eq!(freetsa[6], "(missing)", "{listing}");
    assert!(!listing.contains("tofu"), "no row is TOFU: {listing}");
}

/// A local bundle is the copy the date is read from, even when its root is
/// published: the date has to come from there, not be declared absent.
#[test]
fn preset_list_reads_the_date_from_a_pinned_bundle() {
    let repo = Repo::new();
    repo.init();
    let stale = stale_ca(repo.path());
    std::fs::create_dir_all(repo.anchors()).expect("anchors dir");
    std::fs::copy(&stale, repo.anchors().join("sectigo.pem")).expect("pin the stale CA");

    let listing = ok(&repo.run_time(&["tsa", "preset", "list"]));
    let sectigo = listing
        .lines()
        .find(|line| line.starts_with("sectigo "))
        .unwrap_or_else(|| panic!("the preset line: {listing}"));
    assert!(sectigo.contains("2020-02-01 expired"), "{listing}");
    assert!(!sectigo.contains("not pinned"), "{listing}");
    assert!(sectigo.contains("(anchored)"), "{listing}");
}

/// The rotation `!` reaches the printed line: the pinned bundle holds a root
/// nothing publishes, the probe answers the published one. The flag is the join
/// between `anchors::roots`, the cell and `pin_state`, so this is the wiring the
/// unit test cannot see. A control run without the bundle has nothing to compare
/// and no `!`.
#[test]
fn preset_list_marks_a_pinned_row_whose_served_root_the_bundle_lacks() {
    let repo = Repo::new();
    repo.init();
    let env = vec![(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat '{}'", pstr(&freetsa_root())),
    )];
    let freetsa = |listing: &str| -> String {
        listing
            .lines()
            .find(|line| line.starts_with("freetsa "))
            .unwrap_or_else(|| panic!("the freetsa line: {listing}"))
            .to_owned()
    };

    // Control: no bundle, so the served date stands in and nothing is compared.
    let control = ok(&repo.run_time_env(&["tsa", "preset", "list", "--refresh"], &env));
    let line = freetsa(&control);
    assert!(line.contains("fetch 2041-03-07"), "{line}");
    assert!(!line.contains('!'), "{line}");

    // The bundle is the one throwaway root, which the stub never answers: the
    // date stays the pin's, and the foreign answer is marked.
    let stale = stale_ca(repo.path());
    std::fs::create_dir_all(repo.anchors()).expect("anchors dir");
    std::fs::copy(&stale, repo.anchors().join("freetsa.pem")).expect("pin the stale CA");
    let listing = ok(&repo.run_time_env(&["tsa", "preset", "list", "--refresh"], &env));
    let line = freetsa(&listing);
    assert!(line.contains("2020-02-01 expired !"), "{line}");
    assert!(line.contains("(anchored)"), "{line}");
}

/// A bundle is append-ordered, not date-ordered: a retired root left in front
/// must not hide the live one's later date behind it.
#[test]
fn preset_list_shows_the_newest_live_root_of_a_mixed_bundle() {
    let repo = Repo::new();
    repo.init();
    let stale = stale_ca(repo.path());
    let mut bundle = std::fs::read(freetsa_root()).expect("the fixture root");
    bundle.extend(std::fs::read(&stale).expect("the stale CA"));
    std::fs::create_dir_all(repo.anchors()).expect("anchors dir");
    std::fs::write(repo.anchors().join("sectigo.pem"), bundle).expect("pin the bundle");

    let listing = ok(&repo.run_time(&["tsa", "preset", "list"]));
    let sectigo = listing
        .lines()
        .find(|line| line.starts_with("sectigo "))
        .unwrap_or_else(|| panic!("the preset line: {listing}"));
    assert!(sectigo.contains("2041-03-07"), "{listing}");
    assert!(!sectigo.contains("2020-02-01"), "{listing}");
}

/// The table stays offline: a plain run only reads the cache, and a row the
/// cache cannot answer keeps today's `-`. `--refresh` asks the stub and rewrites
/// the cache, so the plain run after it shows the date it found — and a further
/// `--refresh` asks again rather than trusting the entry it just wrote.
#[test]
fn preset_list_reads_the_probe_cache_and_only_refreshes_on_demand() {
    let repo = Repo::new();
    repo.init();
    // Every fetch is counted, so a run that opens one is visible.
    let calls_file = repo.path().join("probe-calls");
    let env = vec![(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!(
            "echo x >> '{}'; cat '{}'",
            pstr(&calls_file),
            pstr(&freetsa_root())
        ),
    )];
    let entry = repo.xdg.path().join("git-time/probe/freetsa");
    let calls = || {
        std::fs::read_to_string(&calls_file)
            .map(|text| text.lines().count())
            .unwrap_or(0)
    };
    let freetsa = |listing: &str| -> Vec<String> {
        listing
            .lines()
            .find(|line| line.starts_with("freetsa "))
            .unwrap_or_else(|| panic!("the freetsa line: {listing}"))
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    };

    // (a) No socket, no entry, and the `-` a published root without a local
    // certificate already says.
    let plain = ok(&repo.run_time_env(&["tsa", "preset", "list"], &env));
    assert_eq!(freetsa(&plain)[5], "-", "nothing was asked: {plain}");
    assert_eq!(calls(), 0, "a plain run fetches nothing: {plain}");
    assert!(!entry.exists(), "a plain run writes no cache entry");

    // (b) A refresh asks, caches what it found, and prints it.
    let refreshed = ok(&repo.run_time_env(&["tsa", "preset", "list", "--refresh"], &env));
    assert!(
        freetsa(&refreshed)
            .iter()
            .any(|field| field == "2041-03-07"),
        "{refreshed}"
    );
    assert!(entry.exists(), "the served date is cached");
    let asked = calls();
    assert!(asked > 0, "the stub was asked: {refreshed}");

    // The next plain run serves the entry and opens nothing.
    let cached = ok(&repo.run_time_env(&["tsa", "preset", "list"], &env));
    assert!(
        freetsa(&cached).iter().any(|field| field == "2041-03-07"),
        "{cached}"
    );
    assert_eq!(calls(), asked, "a plain run reuses the cache: {cached}");

    // A second refresh drops the entry instead of trusting it for a week.
    let again = ok(&repo.run_time_env(&["tsa", "preset", "list", "--refresh"], &env));
    assert!(calls() > asked, "a second refresh asks again: {again}");
    assert!(
        freetsa(&again).iter().any(|field| field == "2041-03-07"),
        "{again}"
    );

    // (c) A refresh whose fetch fails keeps the date the last successful one
    // cached: nothing is dropped up front, so a transient blip does not cost a
    // later run the answer. The row itself is `?` for this run — the refresh did
    // fail — but the entry is still there.
    let failing = vec![(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        "echo x >> '${calls_file}'; exit 1".replace("${calls_file}", &pstr(&calls_file)),
    )];
    let broken = ok(&repo.run_time_env(&["tsa", "preset", "list", "--refresh"], &failing));
    assert!(
        entry.exists(),
        "the failed refresh left the entry: {broken}"
    );
    assert!(
        freetsa(&broken).iter().any(|field| field == "?"),
        "the failed refresh says so: {broken}"
    );
    // The next plain run reads the surviving entry, not `-`.
    let survivor = ok(&repo.run_time_env(&["tsa", "preset", "list"], &env));
    assert!(
        freetsa(&survivor).iter().any(|field| field == "2041-03-07"),
        "the cached date survives: {survivor}"
    );
    assert!(
        !freetsa(&survivor).iter().any(|field| field == "-"),
        "{survivor}"
    );
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
    let der = first_der(&String::from_utf8_lossy(&root));
    // The fixture root is the one the preset publishes, and the match line
    // names the published spelling it matched: the older SHA-1 slot, because it
    // is listed first. Both spellings describe this root.
    let expected = git_time_core::trust::sha1_fingerprint(&der);
    let stdout = text(&added.stdout);
    assert!(
        stdout.contains("freetsa: root fingerprint matches "),
        "the match is said: {stdout}"
    );
    let printed = fingerprint_after(&stdout, "matches ");
    assert_eq!(printed, expected, "the first certificate is fingerprinted");
    assert_eq!(
        printed.len(),
        59,
        "the matched expectation is SHA-1, so is the line"
    );
    assert_eq!(
        git_time_core::trust::fingerprint(&der),
        *git_time_core::presets::find("freetsa")
            .expect("the preset")
            .fingerprints
            .last()
            .expect("the newest value"),
        "both spellings describe the same root"
    );
}

/// A published root refuses a different one, leaves no anchor behind, and names
/// both values.
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
            .and_then(|preset| preset.fingerprints.last().copied())
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

/// A preset that publishes more than one root names every one of them in a
/// refusal: a reader has to see the whole legitimate set, not just the newest.
#[test]
fn a_multi_value_preset_lists_every_published_root_on_a_mismatch() {
    let repo = Repo::new();
    repo.init();
    let preset = git_time_core::presets::find("freetsa").expect("the fixture preset");
    assert!(preset.fingerprints.len() >= 2, "{:?}", preset.fingerprints);

    let added = repo.run_time_env(&["tsa", "preset", "add", "freetsa"], &repo.fetch_ca());
    assert_eq!(added.status.code(), Some(1), "{}", text(&added.stderr));
    let stderr = text(&added.stderr);
    assert!(
        stderr.contains(&preset.fingerprints.join(" or ")),
        "both published values, joined: {stderr}"
    );
    assert!(
        !repo.anchors().join("freetsa.pem").exists(),
        "nothing is pinned"
    );
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

/// Enable exactly the two selected, with their keys. Only FreeTSA's root is
/// served, so it pins and prints its fingerprint; the second id is a published
/// preset whose root the stub CA is not, so it is reported failed while its
/// keys stay written.
#[test]
fn select_enables_exactly_the_chosen_authorities() {
    let repo = Repo::new();
    repo.init();

    let chosen = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive"],
        &repo.fetch_known_root(),
        "1,10\n",
    );
    assert_eq!(chosen.status.code(), Some(1), "{}", text(&chosen.stderr));

    let stdout = text(&chosen.stdout);
    for (id, url) in [
        ("freetsa", "https://freetsa.org/tsr"),
        ("apple", "http://timestamp.apple.com/ts01"),
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
    }

    // freetsa is served the root it publishes, so it is pinned and the line
    // names the matched value in the length that expectation is written in.
    let line = stdout
        .lines()
        .find(|line| line.starts_with("enabled freetsa "))
        .unwrap_or_else(|| panic!("freetsa enabled: {stdout}"));
    let printed = fingerprint_after(line, "fingerprint ");
    let root = std::fs::read(freetsa_root()).expect("the fixture root");
    assert_eq!(printed.len(), 95, "{line}");
    assert_eq!(
        printed,
        fingerprint_colon(&first_der(&String::from_utf8_lossy(&root))),
        "the served root: {line}"
    );
    assert!(repo.anchors().join("freetsa.pem").exists());

    // apple does not match, so nothing is pinned at a path that would be a
    // trust decision — but the entry stays configured so doctor can name it.
    // The mismatch warning leads, then the row is reported failed.
    let stderr = text(&chosen.stderr);
    assert!(stderr.contains("apple"), "{stderr}");
    assert!(stderr.contains("does not match"), "{stderr}");
    assert!(
        stdout.contains("failed apple: "),
        "the row is refused: {stdout}"
    );
    assert!(!repo.anchors().join("apple.pem").exists());

    // Anything not chosen stays unconfigured.
    for id in ["digicert", "sectigo", "certum", "izenpe", "aped"] {
        assert_eq!(repo.config(&format!("time.tsa.{id}.url")), None, "{id}");
    }
}

/// A piped answer is not echoed, so the prompt has to supply the line break
/// itself; otherwise the first output line runs into the prompt.
#[test]
fn a_piped_answer_does_not_leave_the_output_on_the_prompt_line() {
    let repo = Repo::new();
    repo.init();

    let answered = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive", "--dry-run"],
        &repo.fetch_known_root(),
        "1\n",
    );
    assert_eq!(
        answered.status.code(),
        Some(0),
        "{}",
        text(&answered.stderr)
    );
    let stdout = text(&answered.stdout);
    assert!(
        stdout.contains("all, none): \n"),
        "the prompt is closed: {stdout}"
    );
    assert!(
        !stdout.contains("all, none): would enable"),
        "nothing runs into the prompt: {stdout}"
    );
}

/// `none` removes the preset sections and leaves a hand-added authority alone.
#[test]
fn select_none_removes_preset_sections_but_not_hand_added_ones() {
    let repo = Repo::new();
    repo.init();
    let enabled = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive"],
        &repo.fetch_known_root(),
        "all\n",
    );
    assert!(
        repo.config("time.tsa.freetsa.url").is_some(),
        "{}",
        text(&enabled.stderr)
    );
    repo.add_tsa("acme", "http://tsa.example/tsr");

    let cleared = repo.run_time_with_stdin(&["tsa", "select", "--interactive"], &[], "none\n");
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

/// A typed buffer is the same selector over the same parser: exactly the named
/// rows are enabled once it is entered.
#[test]
fn select_typed_indices_enable_exactly_those() {
    let repo = Repo::new();
    repo.init();

    // `1` and `10` are freetsa and apple; the first is pinned against the
    // fixture, the second is a published preset the stub CA does not match, so
    // both sections are written and the run exits 1.
    let chosen = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive"],
        &repo.fetch_known_root(),
        "1,10\n",
    );
    assert_eq!(chosen.status.code(), Some(1), "{}", text(&chosen.stderr));
    assert!(repo.config("time.tsa.freetsa.url").is_some());
    assert!(repo.config("time.tsa.apple.url").is_some());
    assert!(
        text(&chosen.stderr).contains("apple"),
        "the second id is the one refused: {}",
        text(&chosen.stderr)
    );
    let listing = text(&git(
        repo.path(),
        &["config", "--get-regexp", "^time\\.tsa\\.[a-z-]*\\.url$"],
    ));
    assert_eq!(listing.lines().count(), 2, "{listing}");
}

/// Enter accepts the ticks, and the ticks start at what is configured: entering
/// the selector to change one authority keeps the others. `n` then `enter` is
/// still the removal path.
#[test]
fn select_enter_keeps_the_configured_authorities_and_none_removes_them() {
    let repo = Repo::new();
    repo.init();
    let enabled = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive"],
        &repo.fetch_known_root(),
        "1\n",
    );
    assert!(enabled.status.success(), "{}", text(&enabled.stderr));

    let kept = repo.run_time_with_stdin(&["tsa", "select", "--interactive"], &[], "\n");
    assert_eq!(kept.status.code(), Some(0), "{}", text(&kept.stderr));
    assert_eq!(
        repo.config("time.tsa.freetsa.url").as_deref(),
        Some("https://freetsa.org/tsr"),
        "the empty answer kept it"
    );
    assert!(
        text(&kept.stdout).contains("enabled freetsa "),
        "it was re-pinned, not dropped: {}",
        text(&kept.stdout)
    );

    let cleared = repo.run_time_with_stdin(&["tsa", "select", "--interactive"], &[], "none\n");
    assert_eq!(cleared.status.code(), Some(0), "{}", text(&cleared.stderr));
    assert_eq!(repo.config("time.tsa.freetsa.url"), None);
}

/// The table marks the configured rows, so the start state is visible, and an
/// empty answer keeps exactly them instead of disabling what was not touched. A
/// hand-added id has no row and is never touched.
#[test]
fn select_starts_from_the_configured_authorities() {
    let repo = Repo::new();
    repo.init();
    repo.add_tsa("freetsa", "https://freetsa.org/tsr");
    repo.add_tsa("digicert", "http://timestamp.digicert.com");
    repo.add_tsa("acme", "http://tsa.example/tsr");

    let plan =
        repo.run_time_with_stdin(&["tsa", "select", "--interactive", "--dry-run"], &[], "\n");
    assert_eq!(plan.status.code(), Some(0), "{}", text(&plan.stderr));
    let stdout = text(&plan.stdout);
    assert!(stdout.contains("1) [x] freetsa "), "{stdout}");
    assert!(stdout.contains("2) [x] digicert "), "{stdout}");
    assert!(stdout.contains("3) [ ] sectigo "), "{stdout}");
    assert!(
        !stdout.contains("acme"),
        "a hand-added id has no row and no plan line: {stdout}"
    );
    assert!(stdout.contains("would enable freetsa"), "{stdout}");
    assert!(stdout.contains("would enable digicert"), "{stdout}");
    assert!(!stdout.contains("would disable"), "{stdout}");

    // The empty answer saves the ticks, so the hand-added section survives.
    // freetsa pins against the fixture; digicert cannot match the stub root, so
    // the run exits 1 while both stay configured.
    let kept = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive"],
        &repo.fetch_known_root(),
        "\n",
    );
    assert_eq!(kept.status.code(), Some(1), "{}", text(&kept.stderr));
    assert_eq!(
        repo.config("time.tsa.acme.url").as_deref(),
        Some("http://tsa.example/tsr"),
        "the hand-added section is not a preset's"
    );
    assert!(
        !text(&kept.stdout).contains("disabled acme"),
        "{}",
        text(&kept.stdout)
    );
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
fn fetching_a_first_pin_prints_it_in_full() {
    // A hand-added authority publishes nothing, so nothing can be compared
    // against it: the printed root is the only artifact of the first pin.
    let repo = Repo::with_pinned_stub();
    let output = repo.fetch_anchor("acme");
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    let first = lines.first().expect("the report line");
    assert!(first.contains("trust on first use"), "{stdout}");
    // The root is printed in full, not truncated: twenty colon-separated bytes.
    let label = first
        .split("the fetched root is ")
        .nth(1)
        .expect("the printed root");
    assert_eq!(
        label.split(':').count(),
        20,
        "the whole fingerprint, not an ellipsis: {label}"
    );
    // And the anchor line names the file it was stored in and its SHA-256.
    assert!(
        lines[1].contains("/acme.pem") && lines[1].contains("sha256 "),
        "{stdout}"
    );
}

#[test]
fn install_carries_its_accept_over_the_handover() {
    // A repository with no authority hands over to the selector, and the refusal
    // hint names exactly `git time install --accept`, so the flag has to survive
    // that hop instead of being read only on the keep path.
    let repo = Repo::new();
    repo.init();
    // The fetch compares in the algorithm of the published value and speaks of
    // the fetched root's DER, so the accept has to be that digest; the refusal
    // prints it.
    let probe = repo.run_time_env(&["tsa", "preset", "add", "freetsa"], &repo.fetch_ca());
    let refused = text(&probe.stderr);
    let value = format!(
        "freetsa={}",
        refused
            .split_once("got ")
            .map(|(_, rest)| rest.split(';').next().unwrap_or_default().trim())
            .expect("the refusal names the fetched root")
    );
    // The probe configured the id, and the handover only happens without one.
    repo.run_time(&["tsa", "remove", "freetsa"]);
    assert!(!repo.anchors().join("freetsa.pem").exists());
    let Some(output) = repo.run_time_pty(&["install", "--accept", &value], &repo.fetch_ca(), "1\n")
    else {
        eprintln!("no script(1) here: the handover was not exercised");
        return;
    };
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", text(&output.stderr));
    assert!(
        stdout.contains("overriding the published fingerprint"),
        "{stdout}"
    );
    assert!(repo.anchors().join("freetsa.pem").exists(), "{stdout}");
    // And the root that landed is the accepted one, not whatever was served.
    let anchored = repo.anchors().join("freetsa.pem");
    let accepted = value
        .split_once('=')
        .map(|(_, found)| found)
        .unwrap_or_default();
    // The digest length is the algorithm, the same rule the accept follows.
    let alg = if accepted.len() == 95 {
        "-sha256"
    } else {
        "-sha1"
    };
    let printed = Command::new("openssl")
        .args([
            "x509",
            "-in",
            &pstr(&anchored),
            "-noout",
            "-fingerprint",
            alg,
        ])
        .output()
        .expect("openssl");
    let printed = text(&printed.stdout);
    assert!(
        printed
            .to_ascii_uppercase()
            .contains(&accepted.to_ascii_uppercase()),
        "{printed} does not carry {accepted}"
    );
}

#[test]
fn select_checks_the_terminal_before_it_reads_the_config() {
    // Both failures exit 2 with a message that does not say "not a terminal",
    // so only the message separates them: an unreadable configuration must not
    // win over the usage hint.
    let repo = Repo::new();
    repo.init();
    use std::os::unix::fs::PermissionsExt as _;
    let config = repo.path().join(".git/config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000))
        .expect("make the config unreadable");

    let refused = repo.run_time(&["tsa", "select"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    let stderr = text(&refused.stderr);
    assert!(stderr.contains("not a terminal"), "{stderr}");
    // The repository open would have said this instead had it run first.
    assert!(!stderr.contains("not a git repository"), "{stderr}");

    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644))
        .expect("restore the config");
}

/// The picker on the terminal a user actually has: the served date reaches the
/// frame while the probe is still in flight, and quitting with it in flight
/// still keeps the answer on the screen and in the cache. A second run whose
/// stub fails shows the cached date, so the cache is what an offline run reads.
#[test]
fn select_probes_the_open_rows_and_answers_from_the_cache_offline() {
    let repo = Repo::new();
    repo.init();
    // The log names what was asked, so a socket cannot pass for the stub.
    let log = repo.path().join("probe-urls");
    let served = format!(
        "printf '%s\\n' \"$GIT_TIME_ANCHOR_URL\" >> '{}'; cat '{}'",
        pstr(&log),
        pstr(&freetsa_root())
    );
    // Two spaces toggle and repaint before the quit, which gives a worker the
    // time to pick the row up: a row `settle` refunds from the queue never
    // answers, so without them the window would be one key read wide.
    let Some(first) = repo.run_time_pty(
        &["tsa", "select"],
        &[("GIT_TIME_ANCHOR_FETCH_CMD", served)],
        "  q\n",
    ) else {
        eprintln!("no script(1) here: the probing picker was not exercised");
        return;
    };
    let stdout = text(&first.stdout);
    assert!(first.status.success(), "{stdout}{}", text(&first.stderr));
    assert!(
        stdout.contains("fetch 2041-03-07"),
        "the served date is on the frame: {stdout}"
    );
    // Other rows were in flight as well, so the log holds more than this URL;
    // FreeTSA is the one the run must have asked.
    let asked = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        asked.lines().any(|url| url == "https://freetsa.org/tsr"),
        "the freetsa URL was fetched: {asked}{stdout}"
    );
    let entry = repo.xdg.path().join("git-time/probe/freetsa");
    let cache = std::fs::read_to_string(&entry).expect("the cached date");
    assert!(!cache.contains("BEGIN CERTIFICATE"), "{cache}");
    assert_eq!(cache.lines().count(), 1, "one line: {cache}");

    // The stub now fails. Pressing `r` requeues every row while nothing can
    // answer: the rows go `?` for that run, but no entry is dropped first, so the
    // date already cached survives and the next open shows it instead of `-`.
    let Some(broken) = repo.run_time_pty(
        &["tsa", "select"],
        &[("GIT_TIME_ANCHOR_FETCH_CMD", "exit 1".to_owned())],
        "r q\n",
    ) else {
        eprintln!("no script(1) here: the offline refresh was not exercised");
        return;
    };
    assert!(broken.status.success(), "{}", text(&broken.stderr));
    let survived = std::fs::read_to_string(&entry).expect("the cache survived the refresh");
    assert!(survived.contains("2041-03-07"), "{survived}");
    // A further open, still offline, seeds the row from that entry.
    let Some(reopened) = repo.run_time_pty(
        &["tsa", "select"],
        &[("GIT_TIME_ANCHOR_FETCH_CMD", "exit 1".to_owned())],
        "q\n",
    ) else {
        eprintln!("no script(1) here: the offline reopen was not exercised");
        return;
    };
    let stdout = text(&reopened.stdout);
    assert!(
        reopened.status.success(),
        "{stdout}{}",
        text(&reopened.stderr)
    );
    assert!(stdout.contains("fetch 2041-03-07"), "{stdout}");
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
    assert!(stdout.contains("would enable digicert"), "{stdout}");
    // The table itself carries the scope, so the choice is made on it.
    assert!(stdout.contains(" default "), "{stdout}");
    assert!(stdout.contains(" opt-in "), "{stdout}");
    assert_eq!(repo.config("time.tsa.freetsa.url"), None, "nothing written");
    assert!(!repo.anchors().join("freetsa.pem").exists());

    // A dry run of `none` says what it would remove and removes nothing.
    assert!(
        repo.run_time_with_stdin(
            &["tsa", "select", "--interactive"],
            &repo.fetch_known_root(),
            "1\n"
        )
        .status
        .code()
        .is_some()
    );
    let dry = repo.run_time_with_stdin(
        &["tsa", "select", "--interactive", "--dry-run"],
        &[],
        "none\n",
    );
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
        stdout.contains("failed digicert: no anchor could be pinned"),
        "{stdout}"
    );
    assert!(repo.anchors().join("freetsa.pem").exists());
    assert_eq!(
        repo.config("time.tsa.digicert.url").as_deref(),
        Some("http://timestamp.digicert.com")
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

/// `tsa preset add` has the flag a refusal hints at, and a bare value is
/// unambiguous because one preset names one id.
#[test]
fn preset_add_names_itself_in_the_hint_and_takes_a_bare_accept() {
    let repo = Repo::new();
    repo.init();
    let ca = std::fs::read_to_string(&repo.authority.ca).expect("the CA");
    let found = fingerprint_colon(&first_der(&ca));

    let refused = repo.run_time_env(&["tsa", "preset", "add", "freetsa"], &repo.fetch_ca());
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused.stderr));
    let stderr = text(&refused.stderr);
    assert!(
        stderr.contains(&format!(
            "git time tsa preset add freetsa --accept freetsa={found}"
        )),
        "the hint names the command that has the flag: {stderr}"
    );
    assert!(
        stderr.contains("to pin it"),
        "nothing is pinned, so the value is pinned: {stderr}"
    );
    assert!(
        !stderr.contains("next to the pinned root"),
        "a first pin has no pinned root to append to: {stderr}"
    );
    assert!(!repo.anchors().join("freetsa.pem").exists());

    let added = repo.run_time_env(
        &["tsa", "preset", "add", "freetsa", "--accept", &found],
        &repo.fetch_ca(),
    );
    assert_eq!(added.status.code(), Some(0), "{}", text(&added.stderr));
    assert!(repo.anchors().join("freetsa.pem").exists());
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
        &["tsa", "select"],
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

// --- restore ------------------------------------------------------------

/// The evidence names the authority and the preset carries a published root, so
/// a clone can backfill an anchor it never had without trusting the fetch.
#[test]
fn restore_pins_the_authority_the_evidence_names() {
    let repo = Repo::new();
    repo.init();
    repo.commit_naming(&["freetsa"]);

    let restored = repo.run_time_env(&["tsa", "restore"], &repo.fetch_known_root());
    let stdout = ok(&restored);
    assert!(
        stdout.contains("freetsa: root fingerprint matches"),
        "{stdout}"
    );
    assert!(stdout.contains("tsa: 1 pinned"), "{stdout}");
    assert!(
        stdout.contains("git time anchor pin"),
        "the fingerprints are named as unreviewed: {stdout}"
    );

    assert_eq!(
        repo.config("time.tsa.freetsa.url").as_deref(),
        Some("https://freetsa.org/tsr")
    );
    let anchor = repo
        .config("time.tsa.freetsa.anchor")
        .expect("the anchor path is written");
    assert!(Path::new(&anchor).exists(), "{anchor}");
}

/// A second run fetches nothing: the authority is pinned already, so a restore
/// over a long history costs no request for what is set up.
#[test]
fn restore_leaves_an_already_pinned_authority_alone() {
    let repo = Repo::with_pinned_stub();
    repo.commit_naming(&["stub"]);
    let offline = [("GIT_TIME_ANCHOR_FETCH_CMD", "false".to_owned())];

    let again = repo.run_time_env(&["tsa", "restore"], &offline);
    let stdout = ok(&again);
    assert!(
        stdout.contains("1 authority(ies) already pinned"),
        "{stdout}"
    );
    assert!(stdout.contains("tsa: 0 pinned"), "{stdout}");
    assert_eq!(text(&again.stderr), "", "nothing to warn about");
}

/// An id that is not a preset names no URL anywhere, so the fix is the two
/// `add`/`fetch` steps — and the run is a failure, because the point of the
/// command is a repository that verifies.
#[test]
fn restore_names_an_authority_that_is_not_a_preset() {
    let repo = Repo::new();
    repo.init();
    repo.commit_naming(&["tsa-example"]);

    let output = repo.run_time_env(&["tsa", "restore"], &repo.fetch_known_root());
    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("tsa-example: not a preset"), "{stderr}");
    assert!(
        stderr.contains("tsa add <url> --id tsa-example"),
        "{stderr}"
    );
    assert!(repo.config("time.tsa.tsa-example.url").is_none());
}

/// A root that is not the published one is not kept, and the run fails.
#[test]
fn restore_refuses_a_root_the_preset_does_not_publish() {
    let repo = Repo::new();
    repo.init();
    repo.commit_naming(&["sectigo"]);

    let output = repo.run_time_env(&["tsa", "restore"], &repo.fetch_ca());
    assert_eq!(output.status.code(), Some(1), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("sectigo: the fetched root is not the published fingerprint"),
        "{stderr}"
    );
    let stdout = text(&output.stdout);
    assert!(stdout.contains("tsa: 0 pinned, 1 refused"), "{stdout}");
}

/// History without evidence is not an error: there is nothing to backfill.
#[test]
fn restore_of_history_without_evidence_says_so() {
    let repo = Repo::new();
    repo.init();
    repo.commit_naming(&[]);

    let output = repo.run_time_env(&["tsa", "restore"], &repo.fetch_known_root());
    let stdout = ok(&output);
    assert!(
        stdout.contains("the evidence names no authority"),
        "{stdout}"
    );
}

/// A block names the root it was sealed under. A root the block names is pinned
/// without asking; a root it does not name needs the fingerprint to be accepted
/// and is appended to what is pinned, with the signature state of the block in
/// view.
#[test]
fn restore_appends_a_named_root_after_accept() {
    let repo = Repo::new();
    repo.init();
    let retired = Authority::new();
    let named = Authority::new();
    let served = Authority::new();
    let anchor = repo.anchors().join("freetsa.pem");
    std::fs::create_dir_all(repo.anchors()).expect("anchors dir");
    std::fs::write(&anchor, retired.bytes()).expect("pin the retired root");

    // The block names a root that is not the pinned one, so restore has to look.
    let named_fp = fingerprint_colon(&first_der(&text(&named.bytes())));
    repo.commit_naming_roots(&[("freetsa", &named_fp)]);
    let found_fp = fingerprint_colon(&first_der(&text(&served.bytes())));
    let fetch = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat {}", pstr(&served.ca)),
    )];

    let refused = repo.run_time_env(&["tsa", "restore"], &fetch);
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused.stderr));
    let stderr = text(&refused.stderr);
    assert!(
        stderr.contains(&named_fp),
        "the root the block names: {stderr}"
    );
    assert!(stderr.contains(&found_fp), "the root served: {stderr}");
    let stdout = text(&refused.stdout);
    assert!(
        stdout.contains("signature unsigned"),
        "the signature state sits next to the commit: {stdout}"
    );
    assert_eq!(
        std::fs::read(&anchor).expect("the anchor"),
        retired.bytes(),
        "the refusal changes nothing"
    );

    let accepted = repo.run_time_env(
        &["tsa", "restore", "--accept", &format!("freetsa={found_fp}")],
        &fetch,
    );
    let stdout = ok(&accepted);
    assert!(stdout.contains("1 root(s) appended"), "{stdout}");
    let store = git_time_core::trust::AnchorStore::load(&[("freetsa".to_owned(), anchor.clone())])
        .expect("both roots load");
    assert_eq!(
        store.anchor("freetsa").expect("an anchor").roots.len(),
        2,
        "the accepted root is appended, the retired one stays"
    );
}

/// A fetched root that is the one the block names needs no accept: the evidence
/// itself is the confirmation.
#[test]
fn restore_pins_a_named_root_without_an_accept() {
    let repo = Repo::new();
    repo.init();
    let named = Authority::new();
    let named_fp = fingerprint_colon(&first_der(&text(&named.bytes())));
    repo.commit_naming_roots(&[("freetsa", &named_fp)]);

    let fetch = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat {}", pstr(&named.ca)),
    )];
    let restored = repo.run_time_env(&["tsa", "restore"], &fetch);
    assert!(restored.status.success(), "{}", text(&restored.stderr));
    assert!(text(&restored.stdout).contains("tsa: 1 pinned"));
    assert_eq!(
        std::fs::read(repo.anchors().join("freetsa.pem")).expect("the anchor"),
        named.bytes()
    );
}

/// A pinned bundle whose only root has expired is not "covered": the root is
/// pinned and named, but nothing in it is valid now, so `restore` must fetch
/// instead of skipping. That skip is what made doctor's hint inert.
#[test]
fn restore_refetches_a_pinned_bundle_with_no_root_valid_now() {
    let repo = Repo::new();
    repo.init();
    let stale = stale_ca(repo.path());
    let stale_bytes = std::fs::read(&stale).expect("the stale bundle");
    let anchor = repo.anchors().join("freetsa.pem");
    std::fs::create_dir_all(repo.anchors()).expect("anchors dir");
    std::fs::write(&anchor, &stale_bytes).expect("pin the expired root");
    let stale_fp = fingerprint_colon(&first_der(&text(&stale_bytes)));
    repo.commit_naming_roots(&[("freetsa", &stale_fp)]);
    let fetch = [("GIT_TIME_ANCHOR_FETCH_CMD", format!("cat {}", pstr(&stale)))];

    let restored = repo.run_time_env(&["tsa", "restore"], &fetch);
    let stdout = ok(&restored);
    assert!(
        stdout.contains("1 pinned, 0 refused, 0 without a preset, 0 already pinned"),
        "the fetch is not skipped: {stdout}"
    );
    // The named root is the one served, so the merge adds nothing and the pinned
    // bundle is left as it was rather than replaced.
    let store = git_time_core::trust::AnchorStore::load(&[("freetsa".to_owned(), anchor)])
        .expect("the root still loads");
    assert_eq!(store.anchor("freetsa").expect("an anchor").roots.len(), 1);
}

/// A bundle an authority serves may be narrower than what is pinned. A root the
/// block names is appended instead of replacing the bundle, so the roots older
/// evidence still needs survive; the fresh root becomes the first certificate,
/// which is the one every listing reports.
#[test]
fn restore_appends_a_named_root_instead_of_dropping_the_pinned_one() {
    let repo = Repo::new();
    repo.init();
    let retired = Authority::new();
    let named = Authority::new();
    let anchor = repo.anchors().join("freetsa.pem");
    std::fs::create_dir_all(repo.anchors()).expect("anchors dir");
    let retired_bytes = retired.bytes();
    std::fs::write(&anchor, &retired_bytes).expect("pin the retired root");
    let retired_fp = fingerprint_colon(&first_der(&text(&retired_bytes)));
    let named_fp = fingerprint_colon(&first_der(&text(&named.bytes())));
    repo.commit_naming_roots(&[("freetsa", &named_fp)]);
    let fetch = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat {}", pstr(&named.ca)),
    )];

    let restored = repo.run_time_env(&["tsa", "restore"], &fetch);
    let stdout = ok(&restored);
    assert!(stdout.contains("1 root(s) appended"), "{stdout}");
    let store = git_time_core::trust::AnchorStore::load(&[("freetsa".to_owned(), anchor)])
        .expect("both roots load");
    let roots = &store.anchor("freetsa").expect("an anchor").roots;
    assert_eq!(roots.len(), 2, "nothing is dropped");
    assert_eq!(
        fingerprint_colon(roots[0].as_bytes()),
        named_fp,
        "the root this run brought is first"
    );
    assert_eq!(fingerprint_colon(roots[1].as_bytes()), retired_fp);
}

/// A block may name more than one root. One of them being pinned is not enough:
/// the missing one still has to be fetched, or the blocks naming it stay
/// unverifiable.
#[test]
fn restore_fetches_when_only_one_of_two_named_roots_is_pinned() {
    let repo = Repo::new();
    repo.init();
    let kept = Authority::new();
    let missing = Authority::new();
    let anchor = repo.anchors().join("freetsa.pem");
    std::fs::create_dir_all(repo.anchors()).expect("anchors dir");
    let kept_bytes = kept.bytes();
    std::fs::write(&anchor, &kept_bytes).expect("pin one of the two");
    let kept_fp = fingerprint_colon(&first_der(&text(&kept_bytes)));
    let missing_fp = fingerprint_colon(&first_der(&text(&missing.bytes())));
    repo.commit_naming_roots(&[("freetsa", &kept_fp), ("freetsa", &missing_fp)]);
    let fetch = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat {}", pstr(&missing.ca)),
    )];

    let restored = repo.run_time_env(&["tsa", "restore"], &fetch);
    let stdout = ok(&restored);
    assert!(
        !stdout.contains("authority(ies) already pinned"),
        "the missing root is fetched: {stdout}"
    );
    let store = git_time_core::trust::AnchorStore::load(&[("freetsa".to_owned(), anchor)])
        .expect("both roots load");
    let roots = &store.anchor("freetsa").expect("an anchor").roots;
    assert_eq!(roots.len(), 2, "the missing root is added");
    assert_eq!(fingerprint_colon(roots[0].as_bytes()), missing_fp);
    assert_eq!(fingerprint_colon(roots[1].as_bytes()), kept_fp);
}

/// An unchanged leaf-first bundle is the ordinary shape a TSA publishes. Its
/// first certificate is a leaf, not a root, so only comparing every pinned
/// certificate keeps the re-fetch from looking like a rotation.
#[test]
fn refetching_an_unchanged_leaf_first_bundle_is_not_a_rotation() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    repo.add_tsa("stub", &repo.stub_url());
    let authority = Authority::new();
    let leaf = std::fs::read_to_string(authority.dir.path().join("leaf.pem")).expect("the leaf");
    let bundle = authority.dir.path().join("bundle.pem");
    std::fs::write(&bundle, format!("{leaf}{}", text(&authority.bytes()))).expect("the bundle");
    let anchor = repo.anchors().join("stub.pem");
    let served = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat {}", pstr(&bundle)),
    )];
    let args = [
        "anchor",
        "fetch",
        &repo.stub_url(),
        "--id",
        "stub",
        "--insecure-http",
    ];

    let first = repo.run_time_env(&args, &served);
    assert!(first.status.success(), "{}", text(&first.stderr));

    let again = repo.run_time_env(&args, &served);
    let stdout = ok(&again);
    assert!(stdout.contains("chain material updated"), "{stdout}");
    // The merge reorders the file (roots before chain material), so the bytes
    // are not asserted: what has to stay is the one root, exactly once.
    let store = git_time_core::trust::AnchorStore::load(&[("stub".to_owned(), anchor)])
        .expect("the bundle still loads");
    let roots = &store.anchor("stub").expect("an anchor").roots;
    assert_eq!(roots.len(), 1, "no second root appears");
    assert_eq!(
        fingerprint_colon(roots[0].as_bytes()),
        fingerprint_colon(&first_der(&text(&authority.bytes()))),
        "the one root is the served one"
    );
}

/// A rotation served leaf-first: the old code judged the first certificate, saw
/// a leaf that changed, and refused — or, when the leaf repeated, replaced the
/// bundle and dropped the retired root. A root already pinned is accounted for
/// wherever it sits, so the fetch appends and the retired root, its lock line
/// and the block sealed under it all survive.
#[test]
fn a_leaf_first_rotation_keeps_the_retired_root_and_its_lock_line() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    repo.add_tsa("stub", &repo.stub_url());
    let leaf = |authority: &Authority| {
        std::fs::read_to_string(authority.dir.path().join("leaf.pem")).expect("the leaf")
    };
    let root = |authority: &Authority| text(&authority.bytes());

    // Generation 1 is a leaf-first bundle, the ordinary shape a TSA serves.
    let gen1 = repo.authority.dir.path().join("gen1.pem");
    std::fs::write(
        &gen1,
        format!("{}{}", leaf(&repo.authority), root(&repo.authority)),
    )
    .expect("the first generation");
    let args = [
        "anchor",
        "fetch",
        &repo.stub_url(),
        "--id",
        "stub",
        "--insecure-http",
    ];
    let served1 = [("GIT_TIME_ANCHOR_FETCH_CMD", format!("cat {}", pstr(&gen1)))];
    let first = repo.run_time_env(&args, &served1);
    assert!(first.status.success(), "{}", text(&first.stderr));
    let anchor = repo.anchors().join("stub.pem");
    let retired = fingerprint_colon(&first_der(&root(&repo.authority)));

    // A real block under that root, and the reviewer's record of what is pinned.
    let old = repo.commit("under the retired root");
    let pin = repo.run_time(&["anchor", "pin"]);
    assert!(pin.status.success(), "{}", text(&pin.stderr));
    let lock_before = std::fs::read_to_string(repo.lock()).expect("the lock");
    assert!(lock_before.contains(&retired.replace(':', "").to_ascii_lowercase()));

    // Generation 2 rotates the leaf and the root, and still serves the retired
    // root behind the leaf. The leaf sits first, so nothing about the pinned
    // root can be seen in the first certificate.
    let rotated = Authority::new();
    let fresh = fingerprint_colon(&first_der(&root(&rotated)));
    let gen2 = repo.authority.dir.path().join("gen2.pem");
    std::fs::write(
        &gen2,
        format!(
            "{}{}{}",
            leaf(&rotated),
            root(&repo.authority),
            root(&rotated)
        ),
    )
    .expect("the second generation");
    let served2 = [("GIT_TIME_ANCHOR_FETCH_CMD", format!("cat {}", pstr(&gen2)))];

    let appended = repo.run_time_env(&args, &served2);
    let stdout = ok(&appended);
    assert!(
        stdout.contains("1 root(s) appended, 2 now pinned"),
        "{stdout}"
    );
    let store = git_time_core::trust::AnchorStore::load(&[("stub".to_owned(), anchor.clone())])
        .expect("both roots load");
    let roots = &store.anchor("stub").expect("an anchor").roots;
    assert_eq!(roots.len(), 2, "the retired root stays next to the new one");
    assert_eq!(fingerprint_colon(roots[0].as_bytes()), fresh);
    assert_eq!(fingerprint_colon(roots[1].as_bytes()), retired);

    // The lock diff is one added line; the retired root's line is untouched.
    let pin = repo.run_time(&["anchor", "pin"]);
    assert!(pin.status.success(), "{}", text(&pin.stderr));
    let lock_after = std::fs::read_to_string(repo.lock()).expect("the lock");
    assert!(
        lock_after.contains(&retired.replace(':', "").to_ascii_lowercase()),
        "the retired root's line survives: {lock_after}"
    );
    assert!(
        lock_after.contains(&fresh.replace(':', "").to_ascii_lowercase()),
        "the new root's line is added: {lock_after}"
    );

    // The old block still verifies: its named root is still pinned.
    let verified = repo.run_time(&["verify", &old]);
    assert!(verified.status.success(), "{}", text(&verified.stderr));

    // A generation that serves neither pinned root is still refused, and the
    // accept is what decides: the root is named, then appended.
    let third = Authority::new();
    let gen3 = repo.authority.dir.path().join("gen3.pem");
    std::fs::write(&gen3, format!("{}{}", leaf(&third), root(&third))).expect("the third");
    let served3 = [("GIT_TIME_ANCHOR_FETCH_CMD", format!("cat {}", pstr(&gen3)))];
    let refused = repo.run_time_env(&args, &served3);
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused.stderr));
    let newest = fingerprint_colon(&first_der(&root(&third)));
    assert!(
        text(&refused.stderr).contains(&newest),
        "the root to accept: {}",
        text(&refused.stderr)
    );
    let mut with_accept: Vec<&str> = args.to_vec();
    with_accept.extend(["--accept", &newest]);
    let accepted = repo.run_time_env(&with_accept, &served3);
    let stdout = ok(&accepted);
    assert!(
        stdout.contains("1 root(s) appended, 3 now pinned"),
        "{stdout}"
    );
    let store = git_time_core::trust::AnchorStore::load(&[("stub".to_owned(), anchor)])
        .expect("all roots load");
    assert_eq!(store.anchor("stub").expect("an anchor").roots.len(), 3);
}

#[test]
fn restore_of_an_unusable_fetch_keeps_the_old_anchor_and_fails() {
    let mut repo = Repo::new();
    repo.init();
    repo.serve();
    // A preset id, so restore knows a URL to fetch, served by the stub.
    repo.add_tsa("freetsa", &repo.stub_url());
    let anchor = repo.anchors().join("freetsa.pem");
    assert!(
        repo.fetch_anchor("freetsa").status.success(),
        "the anchor is pinned once"
    );
    // A file that does not load, so the run has to fetch rather than skip.
    std::fs::write(&anchor, b"prose").expect("the anchor is replaced");
    repo.commit_naming(&["freetsa"]);

    let prose = [("GIT_TIME_ANCHOR_FETCH_CMD", "printf 'prose'".to_owned())];
    let output = repo.run_time_env(&["tsa", "restore"], &prose);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("no usable bundle; the pinned anchor is unchanged"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(&anchor).expect("the anchor"),
        b"prose",
        "the unusable file is left where doctor can name it"
    );
    assert!(
        text(&output.stdout).contains("tsa: 0 pinned, 1 refused"),
        "{}",
        text(&output.stdout)
    );
}
