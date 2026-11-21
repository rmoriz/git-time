//! `git time install`, `uninstall` and `doctor`, end to end.
//!
//! Every case runs the real binary. The shims it writes call `git-time` from
//! `PATH`, so the binary's own directory is put in front of `PATH` for every git
//! invocation — exactly the way an installed binary would be found. A foreign
//! hook is a plain `sh` script with a side effect, so chaining can be seen and a
//! failing one can prove the order.
//!
//! The repositories are hermetic: `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`,
//! `XDG_CONFIG_HOME` and `GNUPGHOME` point into temporary directories and
//! `GIT_DIR`/`GIT_WORK_TREE`/`GIT_TIME_SKIP` are cleared. Anchors are never
//! fetched over the network: `GIT_TIME_ANCHOR_FETCH_CMD` replaces the fetch, so
//! a case can hand back a throwaway CA or fail on purpose.
//!
//! The stub authority mints genuine RFC 3161 tokens with `openssl ts -reply` for
//! the request in flight, so a seal here is a real seal and the pinned anchor is
//! the throwaway CA made for the run.
//!
//! The certificates are built for the older `openssl` a run may meet (LibreSSL,
//! OpenSSL 1.1.1) as well as a current one: `-sha256` and a named curve, because
//! their defaults (SHA-1 signatures, explicit EC parameters) are outside what
//! `webpki` verifies, a per-CA serial file because `-CAcreateserial` writes into
//! the shared temp directory and races between parallel fixtures, and a config
//! section for the CA extensions because 1.1.1 adds `basicConstraints` itself.
//!
//! Beyond the happy paths, the cases pin the refusal paths: a second install over
//! a regenerated foreign hook keeps both originals and chains the newest; a shim
//! without `+x`, a dangling symlink, a missing binary, an anchor that is not a
//! certificate and an unknown gate are each a doctor problem with exit 1; a
//! hand-edited shim survives `uninstall` unless `--force` is passed; and neither a
//! second `install` nor an unparseable fetch destroys working config or
//! the previous anchor.

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
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

/// The binary under test, built by cargo for this integration test.
const BIN: &str = env!("CARGO_BIN_EXE_git-time");

/// The trailer marker a sealed commit carries.
const IMPRINT: &str = "\nX-RFC3161-Imprint:";

/// Keep the developer's git, gpg and XDG configuration out of the test binary.
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

/// `PATH` with the binary's own directory in front, so the shims find it.
fn path_env() -> String {
    let dir = Path::new(BIN).parent().expect("the binary has a directory");
    let base = std::env::var_os("PATH").unwrap_or_default();
    format!("{}:{}", dir.display(), base.to_string_lossy())
}

/// The environment every git and binary invocation gets.
fn insulated_env() -> Vec<(&'static str, String)> {
    insulate();
    vec![
        ("GIT_CONFIG_GLOBAL", "/dev/null".to_owned()),
        ("GIT_CONFIG_SYSTEM", "/dev/null".to_owned()),
        ("PATH", path_env()),
    ]
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
    use base64::Engine as _;
    let body = pem
        .split_once("-----\n")
        .and_then(|(_, rest)| rest.split_once("\n-----END"))
        .map(|(body, _)| body.replace('\n', ""))
        .expect("a PEM certificate block");
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("base64")
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
            "/CN=install-ca",
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
            "/CN=install-tsa",
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
}

/// A self-signed CA whose validity window closed in 2020, so no reader of the
/// bundle finds a root that is valid now.
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

/// A self-signed CA whose validity window opens in 2030, so a root-list reader
/// has to tell "not yet" apart from "expired".
fn future_ca(dir: &Path) -> PathBuf {
    let key = dir.join("future-key.pem");
    let ca = dir.join("future-ca.pem");
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
        "20300101000000Z",
        "-not_after",
        "20310101000000Z",
        "-subj",
        "/CN=future-ca",
        "-config",
        &ca_config(dir),
        "-extensions",
        "v3_ca",
    ]);
    ca
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

/// A temporary repository, a throwaway authority and a live stub TSA.
struct Repo {
    dir: TempDir,
    authority: Arc<Authority>,
    stub: Option<Stub>,
    xdg: TempDir,
    /// Distinguishes the commit dates, so a second commit always differs.
    dates: AtomicUsize,
}

impl Repo {
    /// An initialised repository with a sealed base commit and a live stub.
    fn new() -> Self {
        let mut repo = Self::upright();
        repo.init();
        repo.serve();
        repo.commit("base");
        repo
    }

    /// An initialised repository with a live stub and no commit yet.
    fn blank() -> Self {
        let mut repo = Self::upright();
        repo.init();
        repo.serve();
        repo
    }

    fn upright() -> Self {
        let dir = TempDir::new().expect("repo dir");
        let xdg = TempDir::new().expect("xdg dir");
        let authority = Arc::new(Authority::new());
        Self {
            dir,
            authority,
            stub: None,
            xdg,
            dates: AtomicUsize::new(0),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn anchors(&self) -> PathBuf {
        self.xdg.path().join("git-time/anchors")
    }

    fn init(&mut self) {
        let path = self.dir.path().to_path_buf();
        git(&path, &["init", "-q", "-b", "main"]);
        git(&path, &["config", "user.name", "Test"]);
        git(&path, &["config", "user.email", "t@example.com"]);
        git(&path, &["config", "commit.gpgsign", "false"]);
        git(&path, &["config", "tag.gpgsign", "false"]);
        // Generous: the suite runs dozens of repositories at once and a 5s
        // budget has expired under CI load. See hook_flows.rs.
        git(&path, &["config", "time.deadline", "30s"]);
        git(&path, &["config", "time.tsa.stub.timeout", "30s"]);
        git(
            &path,
            &["config", "time.tsa.stub.url", "http://127.0.0.1:1/tsr"],
        );
        git(
            &path,
            &["config", "time.tsa.stub.anchor", &pstr(&self.authority.ca)],
        );
    }

    /// Point the stub TSA at a live server.
    fn serve(&mut self) {
        let stub = Stub::spawn(Arc::clone(&self.authority));
        git(
            self.path(),
            &["config", "time.tsa.stub.url", stub.url.as_str()],
        );
        self.stub = Some(stub);
    }

    fn config(&self, key: &str, value: &str) {
        git(self.path(), &["config", key, value]);
    }

    fn unset(&self, key: &str) {
        let output = git_output(self.path(), &["config", "--unset-all", key], b"", &[]);
        let _ = output;
    }

    fn head(&self) -> String {
        text(&git(self.path(), &["rev-parse", "HEAD"]))
            .trim()
            .to_owned()
    }

    fn count(&self) -> usize {
        text(&git(self.path(), &["rev-list", "--count", "HEAD"]))
            .trim()
            .parse()
            .expect("a commit count")
    }

    /// Commit a block that names `id` under `fingerprint`, without a TSA: the
    /// token bytes are not judged here, and `restore` reads the ids and roots the
    /// way a clone would.
    fn commit_naming(&self, id: &str, fingerprint: &str) {
        let skip = self.run_time(&["drop"]);
        assert!(skip.status.success(), "{}", text(&skip.stderr));
        let mut anchors = std::collections::BTreeMap::new();
        anchors.insert(id.to_owned(), vec![fingerprint.to_owned()]);
        let block = git_time_core::store::TrailerBlock {
            imprint: git_time_core::imprint::Digest {
                alg: git_time_core::imprint::Alg::Sha256,
                bytes: vec![0; 32],
            },
            object: None,
            anchors,
            tokens: vec![git_time_core::store::TokenRecord {
                id: id.to_owned(),
                alg: git_time_core::imprint::Alg::Sha256,
                policy: None,
                nonce: vec![0; 8],
                token: vec![1, 2, 3],
            }],
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

    fn commit(&self, message: &str) -> String {
        let name = format!("{}.txt", message.replace(' ', "-"));
        std::fs::write(self.path().join(&name), message).expect("write file");
        git(self.path(), &["add", &name]);
        let index = self.dates.fetch_add(1, Ordering::SeqCst);
        let date = format!("2020-01-01T00:00:{index:02}Z");
        let output = git_output(
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

    /// How many timestamp blocks `rev` carries.
    fn blocks(&self, rev: &str) -> usize {
        text(&git(self.path(), &["cat-file", "commit", rev]))
            .matches(IMPRINT)
            .count()
    }

    fn hooks_dir(&self) -> PathBuf {
        self.path().join(".git/hooks")
    }

    fn run_time(&self, args: &[&str]) -> Output {
        self.run_time_env(args, &[])
    }

    /// Run with `input` on stdin, the way a piped answer arrives.
    fn run_time_with_stdin(&self, args: &[&str], env: &[(&str, String)], input: &str) -> Output {
        let mut command = Command::new(BIN);
        command
            .arg("-C")
            .arg(self.path())
            .args(args)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_TIME_SKIP")
            .envs(insulated_env())
            .env("XDG_CONFIG_HOME", self.xdg.path())
            .envs(env.iter().map(|(key, value)| (*key, value.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawns the binary");
        child
            .stdin
            .take()
            .expect("a stdin pipe")
            .write_all(input.as_bytes())
            .expect("writes the answer");
        child.wait_with_output().expect("runs the binary")
    }

    fn run_time_env(&self, args: &[&str], env: &[(&str, String)]) -> Output {
        let mut command = Command::new(BIN);
        command
            .arg("-C")
            .arg(self.path())
            .args(args)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_TIME_SKIP")
            .envs(insulated_env())
            .env("XDG_CONFIG_HOME", self.xdg.path())
            .envs(env.iter().map(|(key, value)| (*key, value.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.output().expect("runs the binary")
    }

    /// The environment that makes an anchor fetch hand back the throwaway CA.
    fn fetch_ca(&self) -> Vec<(&'static str, String)> {
        vec![(
            "GIT_TIME_ANCHOR_FETCH_CMD",
            format!("cat {}", pstr(&self.authority.ca)),
        )]
    }

    /// A fetch that answers FreeTSA's own URL with the fixture root and every
    /// other URL with the throwaway CA.
    ///
    /// Only FreeTSA's root is kept as a fixture, so it is the one preset whose
    /// published fingerprint can be matched here. The other pinned presets get
    /// the throwaway CA and are therefore refused — the mismatch path, which an
    /// install has to survive.
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

    /// Install the hooks and leave the authorities alone.
    fn install(&self) -> Output {
        self.run_time(&["install", "--no-tsa"])
    }

    /// Install the hooks, then enable `selection` through the selector's pipe
    /// route, which is what a script does and what a terminal does interactively.
    fn install_presets(&self, selection: &str, env: &[(&str, String)]) -> Output {
        // The wiring run ends in exit 2 when it finds nothing configured and
        // has no terminal; that is the hand-over being tested elsewhere.
        let wired = self.run_time(&["install"]);
        assert!(
            wired.status.success() || wired.status.code() == Some(2),
            "the hooks are wired first: {}",
            text(&wired.stderr)
        );
        self.run_time_with_stdin(&["tsa", "select", "--interactive"], env, selection)
    }
}

fn git_output(dir: &Path, args: &[&str], input: &[u8], env: &[(&str, &str)]) -> Output {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_TIME_SKIP")
        .envs(insulated_env())
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

fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = git_output(dir, args, b"", &[]);
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        text(&output.stderr)
    );
    output.stdout
}

/// The exact bytes of an installed shim, as `git time install` writes them.
fn shim(name: &str) -> String {
    format!(
        "#!/bin/sh\n\
         chained=\"$(dirname \"$0\")/{name}.pre-time\"\n\
         if [ -x \"$chained\" ]; then \"$chained\" \"$@\" || exit $?; fi\n\
         command -v git-time >/dev/null 2>&1 && exec git-time hook {name} \"$@\"; exit 0\n"
    )
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Write `content` as an executable hook.
fn write_exec(path: &Path, content: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, content).expect("write hook");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod hook");
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

// --- cases --------------------------------------------------------------

#[test]
fn install_wires_both_post_hooks_and_no_pre_hook_by_default() {
    let repo = Repo::new();
    let install = repo.install();
    assert!(
        install.status.success(),
        "install failed: {}",
        text(&install.stderr)
    );
    let stdout = text(&install.stdout);
    assert!(stdout.contains("post-commit"), "{stdout}");
    assert!(stdout.contains("post-merge"), "{stdout}");

    for name in ["post-commit", "post-merge"] {
        let hook = repo.hooks_dir().join(name);
        assert_eq!(read(&hook), shim(name), "{name} content");
        assert_eq!(mode(&hook) & 0o111, 0o111, "{name} is executable");
    }
    for name in ["pre-commit", "pre-merge-commit"] {
        assert!(
            !repo.hooks_dir().join(name).exists(),
            "{name} is not wired by default"
        );
    }
}

#[test]
fn the_gate_wires_both_pre_hooks() {
    let repo = Repo::new();
    repo.config("time.gate", "pre-commit");
    let install = repo.install();
    assert!(
        install.status.success(),
        "install failed: {}",
        text(&install.stderr)
    );

    for name in ["pre-commit", "pre-merge-commit"] {
        let hook = repo.hooks_dir().join(name);
        assert_eq!(read(&hook), shim(name), "{name} content");
        assert_eq!(mode(&hook) & 0o111, 0o111, "{name} is executable");
    }
    for name in ["post-commit", "post-merge"] {
        assert!(repo.hooks_dir().join(name).exists(), "{name} is wired");
    }
}

#[test]
fn install_honours_core_hooks_path() {
    let repo = Repo::new();
    let custom = TempDir::new().expect("custom hooks dir");
    repo.config("core.hooksPath", &pstr(custom.path()));
    let install = repo.install();
    assert!(
        install.status.success(),
        "install failed: {}",
        text(&install.stderr)
    );

    for name in ["post-commit", "post-merge"] {
        assert!(
            custom.path().join(name).exists(),
            "{name} in the custom dir"
        );
        assert!(
            !repo.hooks_dir().join(name).exists(),
            "{name} not in .git/hooks"
        );
    }
    assert!(
        text(&install.stdout).contains(&pstr(custom.path())),
        "the summary names the hooks dir: {}",
        text(&install.stdout)
    );
}

#[test]
fn a_foreign_hook_is_chained_and_still_runs_first() {
    let repo = Repo::new();
    let original = repo.hooks_dir().join("post-commit");
    let side_effect = repo.path().join("chained.log");
    std::fs::write(
        &original,
        format!(
            "#!/bin/sh\nprintf 'ran\\n' >> {}\nexit 0\n",
            pstr(&side_effect)
        ),
    )
    .expect("write foreign hook");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o755))
        .expect("chmod foreign hook");

    let install = repo.install();
    assert!(
        install.status.success(),
        "install failed: {}",
        text(&install.stderr)
    );
    assert!(
        repo.hooks_dir().join("post-commit.pre-time").exists(),
        "the foreign hook is preserved under the chained name"
    );

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "x"],
        b"",
        &[],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(read(&side_effect).trim(), "ran", "the chained hook ran");
    assert!(
        text(&output.stderr).contains("rfc3161: sealed"),
        "the seal ran too: {}",
        text(&output.stderr)
    );
    assert_eq!(repo.blocks(&repo.head()), 1);
}

#[test]
fn a_failing_foreign_pre_commit_still_blocks_the_commit() {
    let repo = Repo::new();
    repo.config("time.gate", "pre-commit");
    let original = repo.hooks_dir().join("pre-commit");
    std::fs::write(&original, "#!/bin/sh\nexit 1\n").expect("write foreign hook");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o755))
        .expect("chmod foreign hook");

    let install = repo.install();
    assert!(
        install.status.success(),
        "install failed: {}",
        text(&install.stderr)
    );
    let before = repo.count();

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "x"],
        b"",
        &[],
    );
    assert!(
        !output.status.success(),
        "the chained hook blocks the commit"
    );
    assert_eq!(repo.count(), before, "no commit was made");
    assert_eq!(
        read(&repo.hooks_dir().join("pre-commit.pre-time")),
        "#!/bin/sh\nexit 1\n"
    );
}

#[test]
fn uninstall_restores_the_original_and_is_idempotent() {
    let repo = Repo::new();
    let original = repo.hooks_dir().join("post-commit");
    let bytes = b"#!/bin/sh\n# exactly these bytes, no newline at the end";
    std::fs::write(&original, bytes).expect("write foreign hook");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700))
        .expect("chmod foreign hook");

    assert!(repo.install().status.success());
    assert_eq!(read(&original), shim("post-commit"));

    let uninstall = repo.run_time(&["uninstall"]);
    assert!(
        uninstall.status.success(),
        "uninstall failed: {}",
        text(&uninstall.stderr)
    );
    assert_eq!(std::fs::read(&original).expect("restored file"), bytes);
    assert_eq!(mode(&original), 0o700, "the mode is restored");
    assert!(
        !repo.hooks_dir().join("post-commit.pre-time").exists(),
        "the chained name is gone"
    );
    assert!(
        !repo.hooks_dir().join("post-merge").exists(),
        "the other shim is gone too"
    );

    let again = repo.run_time(&["uninstall"]);
    assert!(
        again.status.success(),
        "a second uninstall is a no-op success: {}",
        text(&again.stderr)
    );
    assert_eq!(std::fs::read(&original).expect("restored file"), bytes);
}

#[test]
fn a_second_install_is_idempotent() {
    let repo = Repo::new();
    assert!(repo.install().status.success());
    let first = read(&repo.hooks_dir().join("post-commit"));
    let second = repo.install();
    assert!(
        second.status.success(),
        "the second install failed: {}",
        text(&second.stderr)
    );

    assert_eq!(
        read(&repo.hooks_dir().join("post-commit")),
        first,
        "the shim is unchanged"
    );
    assert_eq!(
        read(&repo.hooks_dir().join("post-commit")),
        shim("post-commit")
    );
    assert!(
        !repo
            .hooks_dir()
            .join("post-commit.pre-time.pre-time")
            .exists(),
        "no doubled chained name"
    );
    assert!(
        !repo.hooks_dir().join("post-commit.pre-time").exists(),
        "an already wired hook is not chained again"
    );

    // A shim an older version wrote is still ours: an upgrade rewrites it rather
    // than chaining it in front of the new one.
    std::fs::write(
        repo.hooks_dir().join("post-commit"),
        "#!/bin/sh\nexec git-time hook post-commit \"$@\"\n",
    )
    .expect("write an old shim");
    let upgrade = repo.install();
    assert!(upgrade.status.success(), "{}", text(&upgrade.stderr));
    assert_eq!(
        read(&repo.hooks_dir().join("post-commit")),
        shim("post-commit"),
        "the old shim is rewritten"
    );
    assert!(
        !repo.hooks_dir().join("post-commit.pre-time").exists(),
        "the old shim was not chained"
    );
}

#[test]
fn a_regenerated_foreign_hook_keeps_the_first_preserve_and_chains_the_newest() {
    let repo = Repo::new();
    let hook = repo.hooks_dir().join("post-commit");
    let first = "#!/bin/sh\nprintf 'first\\n' >> \"$(dirname \"$0\")/../../ran.log\"\nexit 0\n";
    let second = "#!/bin/sh\nprintf 'second\\n' >> \"$(dirname \"$0\")/../../ran.log\"\nexit 0\n";
    write_exec(&hook, first);
    assert!(repo.install().status.success());

    // husky / the pre-commit framework regenerate their hook between runs.
    write_exec(&hook, second);
    let again = repo.install();
    assert!(
        again.status.success(),
        "the second install failed: {}",
        text(&again.stderr)
    );
    assert_eq!(read(&repo.hooks_dir().join("post-commit.pre-time")), first);
    assert_eq!(
        read(&repo.hooks_dir().join("post-commit.pre-time.1")),
        second
    );
    assert!(
        text(&again.stdout).contains("post-commit.pre-time.1"),
        "the summary names the used preserve: {}",
        text(&again.stdout)
    );
    assert!(
        read(&hook).contains("post-commit.pre-time.1"),
        "the shim chains the newest preserve"
    );

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "x"],
        b"",
        &[],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(
        read(&repo.path().join("ran.log")).trim(),
        "second",
        "only the newest foreign hook runs"
    );
}

#[test]
fn doctor_names_a_shim_that_lost_its_execute_bit() {
    let repo = Repo::new();
    assert!(repo.install().status.success());
    let hook = repo.hooks_dir().join("post-commit");
    chmod(&hook, 0o644);

    let broken = repo.run_time(&["doctor"]);
    assert_eq!(broken.status.code(), Some(1), "{}", text(&broken.stdout));
    let stdout = text(&broken.stdout);
    assert!(stdout.contains("post-commit: not-executable"), "{stdout}");
    assert!(stdout.contains("chmod +x"), "it says what to run: {stdout}");

    chmod(&hook, 0o755);
    let fixed = repo.run_time(&["doctor"]);
    assert_eq!(fixed.status.code(), Some(0), "{}", text(&fixed.stdout));
}

#[test]
fn doctor_names_a_dangling_hook_symlink() {
    let repo = Repo::new();
    assert!(repo.install().status.success());
    let hook = repo.hooks_dir().join("post-commit");
    std::fs::remove_file(&hook).expect("remove shim");
    std::os::unix::fs::symlink(repo.path().join("gone"), &hook).expect("symlink");

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    assert!(
        text(&doctor.stdout).contains("post-commit: dangling"),
        "{}",
        text(&doctor.stdout)
    );
}

#[test]
fn uninstall_keeps_a_hand_edited_shim_until_forced() {
    let repo = Repo::new();
    let hook = repo.hooks_dir().join("post-commit");
    let original = b"#!/bin/sh\nexit 0\n";
    std::fs::write(&hook, original).expect("write foreign hook");
    chmod(&hook, 0o755);
    assert!(repo.install().status.success());

    let edited = format!("#!/bin/sh\nPATH=/opt/bin:$PATH\n{}", shim("post-commit"));
    std::fs::write(&hook, &edited).expect("edit the shim");

    let uninstall = repo.run_time(&["uninstall"]);
    assert!(uninstall.status.success(), "{}", text(&uninstall.stderr));
    assert_eq!(read(&hook), edited, "the edited shim is left in place");
    assert!(
        text(&uninstall.stderr).contains("edited by hand"),
        "the warning says it was modified: {}",
        text(&uninstall.stderr)
    );
    assert!(
        repo.hooks_dir().join("post-commit.pre-time").exists(),
        "the original is still preserved, not restored over the edit"
    );

    let forced = repo.run_time(&["uninstall", "--force"]);
    assert!(forced.status.success(), "{}", text(&forced.stderr));
    assert_eq!(
        std::fs::read(&hook).expect("hook"),
        original,
        "the original is restored"
    );
    assert_eq!(
        read(&repo.hooks_dir().join("post-commit.pre-time.1")),
        edited,
        "the edited shim is kept too"
    );
}

#[test]
fn doctor_checks_each_pre_hook_and_rejects_an_unknown_gate() {
    let repo = Repo::new();
    repo.config("time.gate", "pre-commit");
    assert!(repo.install().status.success());
    std::fs::remove_file(repo.hooks_dir().join("pre-merge-commit")).expect("remove one pre hook");

    let one_missing = repo.run_time(&["doctor"]);
    assert_eq!(
        one_missing.status.code(),
        Some(1),
        "{}",
        text(&one_missing.stdout)
    );
    let stdout = text(&one_missing.stdout);
    assert!(!stdout.contains("hooks match"), "{stdout}");
    assert!(stdout.contains("pre-merge-commit"), "{stdout}");

    repo.config("time.gate", "sometimes");
    let unknown = repo.run_time(&["doctor"]);
    assert_eq!(unknown.status.code(), Some(1), "{}", text(&unknown.stdout));
    assert!(
        text(&unknown.stdout).contains("unknown time.gate value"),
        "{}",
        text(&unknown.stdout)
    );
}

#[test]
fn doctor_problems_when_git_time_is_not_on_path() {
    let repo = Repo::new();
    assert!(repo.install().status.success());
    // A PATH with the tools git needs, but without the binary's directory.
    let bare = "/usr/bin:/bin:/usr/sbin:/sbin".to_owned();
    let doctor = repo.run_time_env(&["doctor"], &[("PATH", bare)]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    assert!(
        text(&doctor.stdout).contains("not on PATH"),
        "{}",
        text(&doctor.stdout)
    );
}

#[test]
fn doctor_names_an_anchor_that_is_not_a_certificate() {
    let repo = Repo::new();
    let bogus = repo.path().join("bogus.pem");
    std::fs::write(&bogus, "this is prose, not a certificate\n").expect("write bogus anchor");
    repo.config("time.tsa.stub.anchor", &pstr(&bogus));
    assert!(repo.install().status.success());

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    assert!(
        text(&doctor.stdout).contains("unparseable anchor"),
        "{}",
        text(&doctor.stdout)
    );
}

#[test]
fn doctor_problems_no_root_valid_now() {
    let repo = Repo::new();
    let stale = stale_ca(repo.authority.dir.path());
    repo.config("time.tsa.stub.anchor", &pstr(&stale));
    assert!(repo.install().status.success());

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    let stdout = text(&doctor.stdout);
    assert!(
        stdout.contains("`anchor stub` has no root valid now"),
        "{stdout}"
    );
    // The way out names the real id and a real fingerprint, with no positional:
    // `restore`'s positional is a commit, so `<id>` there would be taken as one.
    let hint = stdout
        .lines()
        .find(|line| line.contains("accept a fresh one: "))
        .unwrap_or_else(|| panic!("the hint: {stdout}"));
    let command = hint
        .split_once("git time ")
        .map(|(_, command)| command.trim_end_matches(')').trim())
        .unwrap_or_else(|| panic!("the command: {hint}"));
    assert!(!command.contains("<fp>"), "a real fingerprint: {hint}");
    assert!(
        command.contains("--accept stub="),
        "the real id and value: {hint}"
    );
    // `stub` is not a preset, so the fetch goes by the configured URL; either
    // way `restore`/`fetch` must not be handed a bare id as if it were a commit.
    assert!(
        command.starts_with("anchor fetch ") || command.contains("tsa restore --accept st"),
        "{hint}"
    );
    assert!(!command.contains("restore stub"), "{hint}");

    // And it runs: the same stale bundle is served, so the accept matches it.
    let served = [("GIT_TIME_ANCHOR_FETCH_CMD", format!("cat {}", pstr(&stale)))];
    let args: Vec<&str> = command.split_whitespace().collect();
    let restored = repo.run_time_env(&args, &served);
    assert!(restored.status.success(), "{}", text(&restored.stderr));

    // The counts are part of the JSON shape, expired included.
    let json = repo.run_time(&["doctor", "--json"]);
    assert_eq!(json.status.code(), Some(1), "{}", text(&json.stdout));
    let value: serde_json::Value =
        serde_json::from_str(&text(&json.stdout)).expect("doctor --json is JSON");
    assert_eq!(value["anchors"][0]["roots"], 1, "{value}");
    assert_eq!(value["anchors"][0]["expired"], 1, "{value}");
}

/// A marked pin is a standing finding: `doctor` names the root, the confirming
/// command and the JSON field, and exits 1 until the comparison is recorded.
#[test]
fn doctor_keeps_naming_an_unconfirmed_pin() {
    let repo = Repo::blank();
    assert!(repo.install().status.success());
    repo.config("time.tsa.stub.tofu", "true");
    let root = fingerprint_colon(&first_der(&read(&repo.authority.ca)));

    let doctor = repo.run_time(&["doctor"]);
    let stdout = text(&doctor.stdout);
    assert_eq!(doctor.status.code(), Some(1), "{stdout}");
    let line = stdout
        .lines()
        .find(|line| line.starts_with("anchor stub: tofu "))
        .unwrap_or_else(|| panic!("the tofu line: {stdout}"));
    assert!(line.contains(&root), "the root to compare: {line}");
    let hint = stdout
        .lines()
        .find(|line| line.contains("anchor confirm stub "))
        .unwrap_or_else(|| panic!("the hint: {stdout}"));
    assert_eq!(
        hint,
        format!(
            "problem: `anchor stub` is pinned but was never compared (confirm it: git time \
             anchor confirm stub {root})"
        )
    );

    // The JSON carries the marker as a field of the anchor object.
    let json = repo.run_time(&["doctor", "--json"]);
    assert_eq!(json.status.code(), Some(1), "{}", text(&json.stdout));
    let value: serde_json::Value =
        serde_json::from_str(&text(&json.stdout)).expect("doctor --json is JSON");
    assert_eq!(value["anchors"][0]["tofu"], true, "{value}");

    // The printed command itself clears the line, the problem and the exit.
    let command = hint
        .split_once("git time ")
        .map(|(_, command)| command.trim_end_matches(')').trim())
        .unwrap_or_else(|| panic!("the command: {hint}"));
    let args: Vec<&str> = command.split_whitespace().collect();
    assert!(repo.run_time(&args).status.success(), "{command}");
    let after = repo.run_time(&["doctor"]);
    assert_eq!(after.status.code(), Some(0), "{}", text(&after.stdout));
    let stdout = text(&after.stdout);
    assert!(!stdout.contains("tofu"), "{stdout}");
    assert!(!stdout.contains("anchor confirm"), "{stdout}");
}

/// A marker outlives the bundle it was set for: the missing-bundle report still
/// names the comparison and the JSON still says the pin was unconfirmed.
#[test]
fn doctor_names_a_marked_pin_whose_bundle_is_gone() {
    let repo = Repo::blank();
    assert!(repo.install().status.success());
    repo.config("time.tsa.stub.tofu", "true");
    let moved = repo.path().join("moved-ca.pem");
    std::fs::rename(&repo.authority.ca, &moved).expect("move the anchor away");

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    let stdout = text(&doctor.stdout);
    let hint = stdout
        .lines()
        .find(|line| line.contains("was never compared"))
        .unwrap_or_else(|| panic!("the marker problem: {stdout}"));
    // `confirm` has nothing to check the value against while the bundle is
    // gone, so the hint pins it again first.
    let (fetch, then) = hint
        .split_once("pin it first: ")
        .unwrap_or_else(|| panic!("the fetch: {hint}"))
        .1
        .split_once(", then: ")
        .unwrap_or_else(|| panic!("both commands: {hint}"));
    let then = then.trim_end_matches(')').trim();

    let json = repo.run_time(&["doctor", "--json"]);
    let value: serde_json::Value =
        serde_json::from_str(&text(&json.stdout)).expect("doctor --json is JSON");
    assert_eq!(value["anchors"][0]["missing"], true, "{value}");
    assert_eq!(value["anchors"][0]["tofu"], true, "{value}");

    // Both commands are runnable as printed once the bundle is back.
    std::fs::rename(&moved, &repo.authority.ca).expect("put the anchor back");
    let fetch = fetch.strip_prefix("git time ").unwrap_or(fetch);
    let then = then.strip_prefix("git time ").unwrap_or(then);
    let args: Vec<&str> = fetch.split_whitespace().collect();
    let fetched = repo.run_time_env(&args, &repo.fetch_ca());
    assert!(
        fetched.status.success(),
        "{fetch}: {}",
        text(&fetched.stderr)
    );
    let args: Vec<&str> = then.split_whitespace().collect();
    assert!(repo.run_time(&args).status.success(), "{then}");
    assert!(repo.run_time(&["doctor"]).status.success());
}

/// A marker outside the vocabulary is a configuration error, not a quiet
/// `false`: the value is named and the run exits 2, the same as the seal.
#[test]
fn doctor_refuses_an_unparseable_tofu_value() {
    let repo = Repo::blank();
    assert!(repo.install().status.success());
    repo.config("time.tsa.stub.tofu", "maybe");

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(2), "{}", text(&doctor.stderr));
    let stderr = text(&doctor.stderr);
    assert!(stderr.contains("time.tsa.stub.tofu"), "{stderr}");
    assert!(stderr.contains("expected"), "{stderr}");
}

/// The same stale bundle on a *preset* id: the way out is `tsa restore`, and it
/// only fetches because an all-expired bundle is not covered. A root that is
/// pinned and named but expired used to make `restore` skip the fetch and exit 0,
/// so the hint was inert and doctor kept failing.
#[test]
fn doctor_hint_for_a_preset_actually_restores() {
    let repo = Repo::new();
    let stale = stale_ca(repo.authority.dir.path());
    let stale_fp = fingerprint_colon(&first_der(&read(&stale)));
    repo.config("time.tsa.freetsa.url", "https://freetsa.org/tsr");
    repo.config("time.tsa.freetsa.anchor", &pstr(&stale));
    repo.commit_naming("freetsa", &stale_fp);
    assert!(repo.install().status.success());
    // A published root was compared, so no marker is written for it.
    assert!(
        !git_output(
            repo.path(),
            &["config", "--local", "--get", "time.tsa.freetsa.tofu"],
            b"",
            &[]
        )
        .status
        .success()
    );

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    let stdout = text(&doctor.stdout);
    let hint = stdout
        .lines()
        .find(|line| line.contains("accept a fresh one: "))
        .unwrap_or_else(|| panic!("the hint: {stdout}"));
    let command = hint
        .split_once("git time ")
        .map(|(_, command)| command.trim_end_matches(')').trim())
        .unwrap_or_else(|| panic!("the command: {hint}"));
    assert!(
        command.starts_with("tsa restore --accept freetsa="),
        "a preset is restored, not refetched by hand: {hint}"
    );

    // And it runs: the published root the preset names is served, so the fetch is
    // verified rather than trusted and the expired bundle is repaired.
    let served = [(
        "GIT_TIME_ANCHOR_FETCH_CMD",
        format!("cat {}", pstr(&freetsa_root())),
    )];
    let args: Vec<&str> = command.split_whitespace().collect();
    let restored = repo.run_time_env(&args, &served);
    assert!(restored.status.success(), "{}", text(&restored.stderr));
    assert!(
        text(&restored.stdout).contains("1 pinned"),
        "{}",
        text(&restored.stdout)
    );

    // The expired root stays beside the fresh one, so the block that named it
    // stays backed by an anchor.
    let store =
        git_time_core::trust::AnchorStore::load(&[("freetsa".to_owned(), PathBuf::from(&stale))])
            .expect("both roots load");
    assert_eq!(
        store.anchor("freetsa").expect("an anchor").roots.len(),
        2,
        "the retired root is not dropped"
    );
}

/// A root that is not valid *yet* is not an expired root, and it must not
/// become the deadline the informational line prints either.
#[test]
fn doctor_does_not_count_a_future_root_as_expired() {
    let repo = Repo::new();
    let bundle = repo.path().join("mixed.pem");
    let mut bytes = Vec::new();
    for ca in [
        stale_ca(repo.authority.dir.path()),
        repo.authority.ca.clone(),
        future_ca(repo.authority.dir.path()),
    ] {
        bytes.extend(std::fs::read(&ca).expect("read a CA"));
    }
    std::fs::write(&bundle, bytes).expect("write the mixed bundle");
    repo.config("time.tsa.stub.anchor", &pstr(&bundle));
    assert!(repo.install().status.success());

    let json = repo.run_time(&["doctor", "--json"]);
    let value: serde_json::Value =
        serde_json::from_str(&text(&json.stdout)).expect("doctor --json is JSON");
    assert_eq!(value["anchors"][0]["roots"], 3, "{value}");
    assert_eq!(
        value["anchors"][0]["expired"], 1,
        "only the closed root is expired: {value}"
    );

    // The live root is the newest one valid now, so it is the deadline; the
    // future root's date is later and must not win.
    let stdout = text(&repo.run_time(&["doctor"]).stdout);
    let line = stdout
        .lines()
        .find(|line| line.contains("root(s), latest notAfter"))
        .unwrap_or_else(|| panic!("the count line: {stdout}"));
    assert!(!line.contains("2031-01-01"), "{line}");
}

/// The expiry sits next to the fingerprint, so a reader sees the stale root
/// before they see the problem line further down.
#[test]
fn doctor_shows_when_the_anchor_expires() {
    let repo = Repo::new();
    let stale = stale_ca(repo.authority.dir.path());
    repo.config("time.tsa.stub.anchor", &pstr(&stale));
    assert!(repo.install().status.success());

    let doctor = repo.run_time(&["doctor"]);
    let stdout = text(&doctor.stdout);
    let line = stdout
        .lines()
        .find(|line| line.starts_with("anchor stub: "))
        .unwrap_or_else(|| panic!("the anchor line: {stdout}"));
    assert!(line.contains("sha256"), "the fingerprint: {line}");
    assert!(line.contains("2020-02-01 expired"), "the verdict: {line}");

    // A live anchor is only quiet about a distant date; these fixtures close in
    // two days, so the warning is there as well.
    let live = Repo::new();
    assert!(live.install().status.success());
    let stdout = text(&live.run_time(&["doctor"]).stdout);
    assert!(stdout.contains("(expires soon)"), "{stdout}");
}

#[test]
fn doctor_problems_a_head_anchoring_an_unpinned_root() {
    let repo = Repo::blank();
    assert!(repo.install().status.success());
    repo.commit("base");
    let fingerprint = fingerprint_colon(&first_der(&read(&repo.authority.ca)));

    // Move the pinned bundle away: HEAD already names its root, so from now on
    // the line records evidence this machine cannot check.
    let moved = repo.path().join("moved-ca.pem");
    std::fs::rename(&repo.authority.ca, &moved).expect("move the anchor away");

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    let stdout = text(&doctor.stdout);
    let hint = stdout
        .lines()
        .find(|line| line.contains("which is not pinned ("))
        .unwrap_or_else(|| panic!("the hint: {stdout}"));
    // `stub` is not a preset, so the remedy fetches the configured URL; no
    // positional is handed over.
    let expected = format!(
        "HEAD names `anchor stub` fingerprint {fingerprint}, which is not pinned \
         (git time anchor fetch {} --id stub --insecure-http --accept stub={fingerprint})",
        repo.stub.as_ref().expect("a stub").url
    );
    assert!(stdout.contains(&expected), "{stdout}");
    assert!(
        !hint.contains("restore stub"),
        "no commit positional: {hint}"
    );

    // The command runs as printed: the root is fetched again and accepted.
    let command = hint
        .split_once("git time ")
        .map(|(_, command)| command.trim_end_matches(')').trim())
        .unwrap_or_else(|| panic!("the command: {hint}"));
    let args: Vec<&str> = command.split_whitespace().collect();
    let served = [("GIT_TIME_ANCHOR_FETCH_CMD", format!("cat {}", pstr(&moved)))];
    let restored = repo.run_time_env(&args, &served);
    assert!(restored.status.success(), "{}", text(&restored.stderr));
}

/// An id the config has lost has no URL to fetch, so the hint is the `add` that
/// configures one first.
#[test]
fn doctor_suggests_a_preset_for_an_unconfigured_anchored_id() {
    let repo = Repo::blank();
    assert!(repo.install().status.success());
    repo.commit("base");
    let fingerprint = fingerprint_colon(&first_der(&read(&repo.authority.ca)));
    repo.unset("time.tsa.stub.url");

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    // The policy refuses the section for the missing url, so doctor does too and
    // names the `add` that writes one; there is nothing to fetch until then.
    let expected = "anchor stub: no `time.tsa.stub.url` configured, so the policy refuses it \
         (run: git time tsa add <url> --id stub)";
    assert!(
        text(&doctor.stdout).contains(expected),
        "{}",
        text(&doctor.stdout)
    );
    // The root the block names is still pinned, so it is not reported unpinned.
    let unpinned = format!("HEAD names `anchor stub` fingerprint {fingerprint}");
    assert!(
        !text(&doctor.stdout).contains(&unpinned),
        "{}",
        text(&doctor.stdout)
    );
}

/// The whole happy path in one run: a commit sealed after `install` names a root
/// that *is* pinned, so doctor has nothing to report. The commit predates
/// install in `Repo::new`, so this is the guard for the fingerprint comparison
/// the block check does.
#[test]
fn a_sealed_commit_under_a_pinned_root_keeps_doctor_quiet() {
    let repo = Repo::blank();
    assert!(repo.install().status.success());
    repo.commit("sealed");

    let doctor = repo.run_time(&["doctor"]);
    let stdout = text(&doctor.stdout);
    assert_eq!(doctor.status.code(), Some(0), "{stdout}");
    assert!(!stdout.contains("problem:"), "{stdout}");
    // The block really does name the root it was judged against.
    let block = text(&git(repo.path(), &["cat-file", "commit", "HEAD"]));
    assert!(block.contains("X-RFC3161-Anchor: id=stub"), "{block}");
}

#[test]
fn a_second_selection_keeps_a_working_config() {
    let repo = Repo::blank();
    let first = repo.install_presets("1", &repo.fetch_known_root());
    assert!(first.status.success(), "{}", text(&first.stderr));

    repo.config("time.tsa.freetsa.url", "https://mirror.example/tsr");
    let second = repo.install_presets("1", &repo.fetch_known_root());
    let url = text(&git(repo.path(), &["config", "time.tsa.freetsa.url"]));
    assert_eq!(url.trim(), "https://mirror.example/tsr", "url is kept");
    assert!(
        text(&second.stdout).contains("key(s) kept"),
        "the skipped keys are reported: {}",
        text(&second.stdout)
    );
}

#[test]
fn a_failed_fetch_under_the_gate_warns_that_commits_are_refused() {
    let repo = Repo::blank();
    repo.config("time.gate", "pre-commit");
    let install = repo.install_presets("1", &[("GIT_TIME_ANCHOR_FETCH_CMD", "false".to_owned())]);
    assert!(
        text(&install.stderr).contains("will be refused"),
        "the gate consequence is named loudly: {}",
        text(&install.stderr)
    );
}

#[test]
fn an_unparseable_fetch_leaves_the_previous_anchor_untouched() {
    let repo = Repo::blank();
    assert!(
        repo.install_presets("1", &repo.fetch_known_root())
            .status
            .success()
    );
    let anchor = repo.anchors().join("freetsa.pem");
    let pinned = std::fs::read(&anchor).expect("pinned anchor");

    let prose = "this is prose, not a certificate\n";
    let _ = repo.install_presets(
        "1",
        &[("GIT_TIME_ANCHOR_FETCH_CMD", format!("printf '{prose}'"))],
    );
    assert_eq!(
        std::fs::read(&anchor).expect("anchor"),
        pinned,
        "the previous anchor is untouched"
    );

    // With nothing pinned before, the bad bytes are kept so doctor can name
    // them as unparseable instead of as never fetched.
    let fresh = Repo::blank();
    let _ = fresh.install_presets(
        "1",
        &[("GIT_TIME_ANCHOR_FETCH_CMD", format!("printf '{prose}'"))],
    );
    let doctor = fresh.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    assert!(
        text(&doctor.stdout).contains("unparseable anchor"),
        "{}",
        text(&doctor.stdout)
    );
}

#[test]
fn tsa_presets_write_the_expected_config() {
    let repo = Repo::blank();
    let none = repo.run_time(&["install", "--no-tsa"]);
    assert!(none.status.success(), "{}", text(&none.stderr));
    let after_none = text(&git(
        repo.path(),
        &["config", "--get-regexp", "^time\\.tsa\\."],
    ));
    assert!(!after_none.contains("time.tsa.freetsa"), "{after_none}");
    assert!(!after_none.contains("time.tsa.digicert"), "{after_none}");

    // The curated pair with a fetch that fails: the config is still written,
    // the failure is named, and the missing anchors are what doctor complains
    // about.
    let public = repo.install_presets("1,2", &[("GIT_TIME_ANCHOR_FETCH_CMD", "false".to_owned())]);
    let stderr = text(&public.stderr);
    assert!(stderr.contains("freetsa"), "{stderr}");
    assert!(stderr.contains("digicert"), "{stderr}");

    let listing = text(&git(
        repo.path(),
        &["config", "--get-regexp", "^time\\.tsa\\."],
    ));
    assert!(listing.contains("time.tsa.freetsa.url"), "{listing}");
    assert!(listing.contains("time.tsa.digicert.url"), "{listing}");
    assert!(listing.contains("https://freetsa.org/tsr"), "{listing}");
    assert!(
        listing.contains("http://timestamp.digicert.com"),
        "{listing}"
    );

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    let stdout = text(&doctor.stdout);
    assert!(stdout.contains("missing anchor"), "{stdout}");

    // `--no-tsa` writes no authority at all.
    let bare = Repo::blank();
    let no_tsa = bare.run_time(&["install", "--no-tsa"]);
    assert!(no_tsa.status.success(), "{}", text(&no_tsa.stderr));
    let listing = text(&git(
        bare.path(),
        &["config", "--get-regexp", "^time\\.tsa\\."],
    ));
    assert!(!listing.contains("time.tsa.freetsa"), "{listing}");
}

#[test]
fn doctor_names_problems_and_exits_one() {
    // Healthy: a live TSA with a readable anchor, the hooks installed, and no
    // gate configured.
    let repo = Repo::new();
    assert!(repo.install().status.success());
    let healthy = repo.run_time(&["doctor"]);
    assert_eq!(healthy.status.code(), Some(0), "{}", text(&healthy.stdout));
    let stdout = text(&healthy.stdout);
    assert!(stdout.contains("hooks dir"), "{stdout}");
    assert!(stdout.contains("post-commit: ours"), "{stdout}");
    assert!(stdout.contains("tsa: 1 configured"), "{stdout}");
    assert!(stdout.contains("enabled: true"), "{stdout}");
    assert!(
        stdout.contains("sha256"),
        "the anchor fingerprint: {stdout}"
    );

    let json = repo.run_time(&["doctor", "--json"]);
    assert_eq!(json.status.code(), Some(0), "{}", text(&json.stdout));
    let value: serde_json::Value =
        serde_json::from_str(&text(&json.stdout)).expect("doctor --json is JSON");
    assert_eq!(value["hooks"]["post-commit"], "ours");
    assert_eq!(value["problems"].as_array().map(Vec::len), Some(0));

    // No TSA at all.
    let repo = Repo::new();
    for key in ["url", "anchor", "timeout"] {
        repo.unset(&format!("time.tsa.stub.{key}"));
    }
    assert!(repo.install().status.success());
    let none = repo.run_time(&["doctor"]);
    assert_eq!(none.status.code(), Some(1));
    assert!(
        text(&none.stdout).contains("no TSA configured"),
        "{}",
        text(&none.stdout)
    );

    // Gate mismatch, in both directions.
    let repo = Repo::new();
    assert!(repo.install().status.success());
    repo.config("time.gate", "pre-commit");
    let mismatch = repo.run_time(&["doctor"]);
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(
        text(&mismatch.stdout).contains("gate mismatch"),
        "{}",
        text(&mismatch.stdout)
    );

    let repo = Repo::new();
    repo.config("time.gate", "pre-commit");
    assert!(repo.install().status.success());
    repo.unset("time.gate");
    let mismatch = repo.run_time(&["doctor"]);
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(
        text(&mismatch.stdout).contains("gate mismatch"),
        "{}",
        text(&mismatch.stdout)
    );
}

#[test]
fn a_merge_after_install_is_sealed() {
    let repo = Repo::new();
    assert!(repo.install().status.success());
    git(repo.path(), &["checkout", "-q", "-b", "feature"]);
    repo.commit("feature");
    git(repo.path(), &["checkout", "-q", "main"]);
    repo.commit("main work");

    let output = git_output(
        repo.path(),
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
        b"",
        &[],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("rfc3161: sealed"),
        "the merge was sealed: {}",
        text(&output.stderr)
    );
    assert_eq!(repo.blocks(&repo.head()), 1);
}

/// Without a flag, `install` writes the curated pair and nothing else: the
/// default must not cost a request per preset on every commit.
/// With nothing configured and no terminal, `install` cannot ask; it wires the
/// hooks anyway and names the three scriptable routes.
#[test]
fn install_without_authorities_refuses_a_non_tty_and_names_the_selector() {
    let repo = Repo::blank();
    for key in ["url", "anchor", "timeout"] {
        repo.unset(&format!("time.tsa.stub.{key}"));
    }

    let install = repo.run_time(&["install"]);
    assert_eq!(install.status.code(), Some(2), "{}", text(&install.stderr));
    let stderr = text(&install.stderr);
    assert!(stderr.contains("tsa select"), "{stderr}");
    assert!(stderr.contains("tsa preset add"), "{stderr}");
    assert!(stderr.contains("tsa add"), "{stderr}");
    // The hooks are wired regardless: only the authority choice is missing.
    assert!(repo.hooks_dir().join("post-commit").exists());
}

/// With one authority already configured, `install` never asks and writes none.
#[test]
fn install_with_an_authority_configured_does_not_ask() {
    let repo = Repo::blank();

    let install = repo.run_time(&["install"]);
    assert_eq!(install.status.code(), Some(0), "{}", text(&install.stderr));
    assert!(
        text(&install.stdout).contains("existing authority"),
        "{}",
        text(&install.stdout)
    );
    let listing = text(&git(
        repo.path(),
        &["config", "--get-regexp", r"^time\.tsa\.[a-z-]*\.url$"],
    ));
    assert!(listing.contains("time.tsa.stub.url"), "{listing}");
    assert!(!listing.contains("time.tsa.freetsa.url"), "{listing}");
}

/// A bare `--accept` names no id, so it can only be resolved when one authority
/// is involved. With two, the ids in play are named and nothing is pinned.
#[test]
fn a_bare_accept_on_a_two_authority_install_is_refused() {
    let repo = Repo::blank();
    for key in ["url", "anchor", "timeout"] {
        repo.unset(&format!("time.tsa.stub.{key}"));
    }
    for (id, url) in [
        ("freetsa", "https://freetsa.org/tsr"),
        ("digicert", "http://timestamp.digicert.com"),
    ] {
        repo.config(&format!("time.tsa.{id}.url"), url);
        repo.config(
            &format!("time.tsa.{id}.anchor"),
            &pstr(&repo.anchors().join(format!("{id}.pem"))),
        );
    }

    let install = repo.run_time(&["install", "--accept", "00:11:22:33:44"]);
    assert_eq!(install.status.code(), Some(2), "{}", text(&install.stderr));
    let stderr = text(&install.stderr);
    assert!(stderr.contains("freetsa"), "{stderr}");
    assert!(stderr.contains("digicert"), "{stderr}");
    assert!(
        !repo.anchors().join("freetsa.pem").exists(),
        "nothing is pinned on the usage error"
    );
}

#[test]
fn selecting_every_preset_fetches_and_prints_their_fingerprints() {
    let repo = Repo::new();
    let install = repo.install_presets("all", &repo.fetch_known_root());
    assert_eq!(install.status.code(), Some(1), "{}", text(&install.stderr));
    let stdout = text(&install.stdout);
    assert_eq!(
        stdout.matches("enabled ").count() + stdout.matches("failed ").count(),
        21,
        "every preset is written: {stdout}"
    );
    // The only matching root is FreeTSA's, so only it pins. Every other
    // published root is measured against the throwaway CA and refused.
    assert_eq!(stdout.matches("enabled ").count(), 1, "{stdout}");
    assert!(
        stdout.contains("freetsa: root fingerprint matches"),
        "the match is said out loud: {stdout}"
    );
    assert_eq!(
        stdout.matches("failed ").count(),
        20,
        "every mismatched root is refused: {stdout}"
    );

    // FreeTSA's own fixture root is the one a published fingerprint can match.
    let anchor = repo.anchors().join("freetsa.pem");
    assert_eq!(read(&anchor), read(&freetsa_root()), "the anchor is stored");
    let configured = text(&git(repo.path(), &["config", "time.tsa.freetsa.anchor"]));
    assert_eq!(configured.trim(), pstr(&anchor), "the anchor is absolute");
    let alg = text(&git(repo.path(), &["config", "time.tsa.freetsa.alg"]));
    assert_eq!(alg.trim(), "sha256");
}

/// A rotation leaves two legitimate values in the wild. Fetching the retired
/// one is a match, and the line has to name that value — not the newest.
#[test]
fn any_published_fingerprint_of_a_preset_accepts_the_root() {
    let repo = Repo::new();
    let preset = git_time_core::presets::find("freetsa").expect("the fixture preset");
    assert!(
        preset.fingerprints.len() >= 2,
        "the preset carries a retired and a current value: {:?}",
        preset.fingerprints
    );
    let retired = preset.fingerprints[0];
    assert_ne!(
        retired,
        *preset.fingerprints.last().expect("a current value"),
        "the retired value is not the newest"
    );

    let added = repo.run_time_env(
        &["tsa", "preset", "add", "freetsa"],
        &repo.fetch_known_root(),
    );
    assert!(added.status.success(), "{}", text(&added.stderr));
    let stdout = text(&added.stdout);
    assert!(
        stdout.contains(&format!("freetsa: root fingerprint matches {retired}")),
        "the line names the value that matched: {stdout}"
    );
    assert!(
        repo.anchors().join("freetsa.pem").exists(),
        "the retired root is pinned"
    );
}

#[test]
fn install_refuses_a_root_whose_fingerprint_does_not_match() {
    let repo = Repo::blank();
    let install = repo.install_presets("all", &repo.fetch_ca());
    assert_eq!(install.status.code(), Some(1), "{}", text(&install.stderr));

    // The fetched root is named next to the published one, and nothing is
    // pinned at a path that would otherwise be a trust decision.
    let stderr = text(&install.stderr);
    assert!(stderr.contains("does not match"), "{stderr}");
    for id in ["sectigo", "certum", "izenpe"] {
        assert!(stderr.contains(id), "{id} is named: {stderr}");
        assert!(
            !repo.anchors().join(format!("{id}.pem")).exists(),
            "{id} is not pinned"
        );
    }
    let ca = std::fs::read_to_string(&repo.authority.ca).expect("the CA");
    let fetched = fingerprint_colon(&first_der(&ca));
    for preset in ["sectigo", "certum", "izenpe"] {
        let published = git_time_core::presets::find(preset)
            .and_then(|preset| preset.fingerprints.last().copied())
            .expect("a published root");
        assert!(stderr.contains(published), "{preset}: {stderr}");
    }
    assert!(
        stderr.contains(&fetched),
        "the fetched value is named: {stderr}"
    );

    let doctor = repo.run_time(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", text(&doctor.stdout));
    assert!(text(&doctor.stdout).contains("missing anchor"));
}

#[test]
fn a_legacy_shim_chains_the_newest_preserve_not_the_stale_one() {
    let repo = Repo::new();
    let hook = repo.hooks_dir().join("post-commit");
    let first = "#!/bin/sh\nprintf 'first\\n' >> \"$(dirname \"$0\")/../../ran.log\"\nexit 0\n";
    let second = "#!/bin/sh\nprintf 'second\\n' >> \"$(dirname \"$0\")/../../ran.log\"\nexit 0\n";
    write_exec(&hook, first);
    assert!(repo.install().status.success());
    write_exec(&hook, second);
    assert!(repo.install().status.success());
    assert!(repo.hooks_dir().join("post-commit.pre-time.1").exists());

    // An older version's shim has no chain of its own and is rewritten. The
    // newest preserve is the one that tool last displaced; the stale
    // `.pre-time` from the first install must not be resurrected.
    std::fs::write(&hook, "#!/bin/sh\nexec git-time hook post-commit \"$@\"\n")
        .expect("write an old shim");
    let upgrade = repo.install();
    assert!(upgrade.status.success(), "{}", text(&upgrade.stderr));
    let content = read(&hook);
    assert!(content.contains("post-commit.pre-time.1"), "{content}");
    // No preserve was stacked for the rewrite (both are still there, no `.2`).
    assert!(repo.hooks_dir().join("post-commit.pre-time").exists());
    assert!(repo.hooks_dir().join("post-commit.pre-time.1").exists());
    assert!(!repo.hooks_dir().join("post-commit.pre-time.2").exists());

    let output = git_output(
        repo.path(),
        &["commit", "--allow-empty", "-m", "x"],
        b"",
        &[],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(
        read(&repo.path().join("ran.log")).trim(),
        "second",
        "the newest preserve runs, not the stale one"
    );
}

#[test]
fn force_uninstall_leaves_a_shim_with_nothing_to_restore_in_place() {
    let repo = Repo::new();
    assert!(repo.install().status.success());
    assert!(
        !repo.hooks_dir().join("post-commit.pre-time").exists(),
        "no original was preserved"
    );
    let hook = repo.hooks_dir().join("post-commit");
    let edited = format!("#!/bin/sh\nPATH=/opt/bin:$PATH\n{}", shim("post-commit"));
    std::fs::write(&hook, &edited).expect("edit the shim");

    // There is nothing to restore, so renaming and restoring again would leave
    // the hook wired while the output claimed it was kept.
    let forced = repo.run_time(&["uninstall", "--force"]);
    assert!(forced.status.success(), "{}", text(&forced.stderr));
    assert_eq!(read(&hook), edited, "the edited shim stays where it is");
    assert!(
        !repo.hooks_dir().join("post-commit.pre-time").exists(),
        "no preserve was invented"
    );
    let stdout = text(&forced.stdout);
    assert!(stdout.contains("left in place: post-commit"), "{stdout}");
    assert!(
        stdout.contains("removed 1 hook(s)"),
        "only post-merge: {stdout}"
    );

    // A second forced run says the same and still changes nothing.
    let again = repo.run_time(&["uninstall", "--force"]);
    assert!(again.status.success(), "{}", text(&again.stderr));
    assert_eq!(read(&hook), edited);
    assert!(text(&again.stdout).contains("left in place: post-commit"));
}

#[test]
fn install_fetches_into_the_configured_anchor_path() {
    let repo = Repo::blank();
    let anchor = repo.path().join("pinned/custom-ca.pem");
    repo.config("time.tsa.freetsa.anchor", &pstr(&anchor));

    let install = repo.install_presets("1", &repo.fetch_known_root());
    assert_eq!(install.status.code(), Some(0), "{}", text(&install.stderr));
    assert_eq!(
        read(&anchor),
        read(&freetsa_root()),
        "the policy reads this path, so this is where the bundle belongs"
    );
    assert!(
        !repo.anchors().join("freetsa.pem").exists(),
        "the XDG default is not used when a key exists"
    );
    let stdout = text(&install.stdout);
    assert!(
        stdout.contains(&pstr(&anchor)),
        "the fingerprint names the configured file: {stdout}"
    );
    let configured = text(&git(repo.path(), &["config", "time.tsa.freetsa.anchor"]));
    assert_eq!(configured.trim(), pstr(&anchor), "the key is unchanged");
}

#[test]
fn install_warns_about_a_missing_configured_anchor_under_the_gate() {
    let repo = Repo::blank();
    repo.config("time.gate", "pre-commit");
    let missing = repo.path().join("pinned/never-fetched.pem");
    repo.config("time.tsa.freetsa.anchor", &pstr(&missing));

    // The run itself, not the selector behind it: a configured id reaches the
    // pin attempt straight away, so the warning has to come from there.
    let install = repo.run_time_env(
        &["install"],
        &[("GIT_TIME_ANCHOR_FETCH_CMD", "false".to_owned())],
    );
    let stderr = text(&install.stderr);
    assert!(
        stderr.contains(&pstr(&missing)),
        "the warning names the configured path: {stderr}"
    );
    assert!(stderr.contains("will be refused"), "{stderr}");
}

/// A configured authority whose anchor file is gone — a moved home directory, a
/// deleted anchors directory — is pinned again instead of only warned about,
/// because the preset's published root makes that fetch checkable.
#[test]
fn a_configured_authority_without_an_anchor_is_pinned_again() {
    let repo = Repo::blank();
    assert!(
        repo.install_presets("1", &repo.fetch_known_root())
            .status
            .success()
    );
    let anchor = repo.anchors().join("freetsa.pem");
    std::fs::remove_file(&anchor).expect("the anchor is removed");

    let install = repo.run_time_env(&["install"], &repo.fetch_known_root());
    assert!(
        install.status.success(),
        "the anchors are not a reason to fail: {}",
        text(&install.stderr)
    );
    assert!(
        anchor.exists(),
        "the anchor is pinned again: {}",
        text(&install.stdout)
    );
    assert!(
        text(&install.stdout).contains("1 anchor(s) pinned again"),
        "the re-pin is reported: {}",
        text(&install.stdout)
    );
    assert!(
        text(&install.stdout).contains("root fingerprint matches"),
        "and it was a checked fetch: {}",
        text(&install.stdout)
    );
}
