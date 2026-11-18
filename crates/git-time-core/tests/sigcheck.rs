//! Commit signature state: what an object is signed with, how to sign it again,
//! and whether the signature on it still holds.
//!
//! The state must come from the object, never from config — that is what keeps
//! `git commit --no-gpg-sign` unsigned under `commit.gpgSign=true`. Every test
//! repo is cut off from the developer's git config and keys: git runs with
//! `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` at `/dev/null`, the settings each
//! test relies on are written into the repo itself, and every OpenPGP and SSH
//! fixture is built from an ephemeral home directory.

use git_time_core::object::CommitObject;
use git_time_core::repo::Repo;
use git_time_core::sigcheck::{
    Format, SigHeader, SignError, SignatureState, VerifyOutcome, format, inspect, sign, verify,
};

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, Once, PoisonError, Weak};

use tempfile::TempDir;

const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const SIGNER: &str = "Test <t@example.com>";
const SIGNER_MAIL: &str = "t@example.com";

/// A message without a final newline and with a body line that looks like a
/// header continuation, so signing cannot get its byte count from a rewrite.
const MESSAGE: &str = "subject\n body keeps its space\nno trailing newline";

/// Keeps the developer's global and system git config out of the whole binary.
///
/// Every repo would otherwise inherit `gpg.format`, `gpg.program`,
/// `gpg.ssh.allowedSignersFile` and whatever else is set on the machine, and a
/// developer with `gpg.format = ssh` would see the default-path test fail. The
/// settings a test needs are written into its own repo instead; the one test
/// that wants an ambient config points `GIT_CONFIG_GLOBAL` at it itself.
fn insulate() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: this is the only writer of these two variables except
        // `GlobalConfig`, which runs under `ENV_LOCK` with the value set here
        // and restores it afterwards.
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", "/dev/null");
            std::env::set_var("GIT_CONFIG_SYSTEM", "/dev/null");
        }
    });
}

/// Serialises the tests that change the ambient git config.
///
/// All other tests keep their `gpg.format` in their own repo, so an ambient
/// config can only reach them where they have no local setting.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A global git config for this process, in effect only while it lives.
///
/// Used to prove that a repo's own setting wins over an ambient one.
struct GlobalConfig {
    _dir: TempDir,
}

impl GlobalConfig {
    /// Point the process at a global config holding `contents`.
    ///
    /// The caller holds [`ENV_LOCK`] from before this call until after the guard
    /// is dropped.
    fn new(contents: &str) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let file = dir.path().join("gitconfig");
        std::fs::write(&file, contents).expect("writes the global config");
        // SAFETY: only written while `ENV_LOCK` is held.
        unsafe { std::env::set_var("GIT_CONFIG_GLOBAL", &file) };
        Self { _dir: dir }
    }
}

impl Drop for GlobalConfig {
    fn drop(&mut self) {
        // SAFETY: the guard is dropped before the lock is released.
        unsafe { std::env::set_var("GIT_CONFIG_GLOBAL", "/dev/null") };
    }
}

/// A temporary gpg home, whose agent is killed when the home goes away.
///
/// The agent dies before the `TempDir` does, or it would keep running against a
/// deleted directory. Killing can race the agent's own start-up, so it is
/// retried a few times.
struct GpgHome {
    _dir: TempDir,
}

impl GpgHome {
    fn new() -> Self {
        Self {
            _dir: TempDir::new().expect("temp home"),
        }
    }

    fn path(&self) -> &Path {
        self._dir.path()
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        // The socket disappearing means the agent is going away, but it can
        // briefly reappear while a last client is served, so require three
        // sightings before giving up on the kill.
        let mut gone = 0;
        for _ in 0..20 {
            let _ = Command::new("gpgconf")
                .args(["--kill", "gpg-agent"])
                .env("GNUPGHOME", self.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            std::thread::sleep(std::time::Duration::from_millis(10));
            if self.path().join("S.gpg-agent").exists() {
                gone = 0;
            } else {
                gone += 1;
                if gone == 3 {
                    break;
                }
            }
        }
    }
}

/// An ephemeral OpenPGP home with one key, generated once per test binary.
struct Pgp {
    _home: GpgHome,
    fingerprint: String,
}

/// An ephemeral SSH key pair with a matching allowed-signers file.
struct Ssh {
    _dir: TempDir,
    key: PathBuf,
    public_key: String,
    allowed_signers: PathBuf,
}

/// The expensive fixtures of this binary, shared between concurrent tests.
///
/// Created on first use and held only weakly by [`SHARED`], so the last test
/// using one drops it: the key home, the agent and its socket are torn down
/// instead of outliving the test run.
#[derive(Default)]
struct Fixtures {
    pgp: Option<Arc<Pgp>>,
    agent: Option<Arc<Agent>>,
}

static SHARED: Mutex<Option<Weak<Fixtures>>> = Mutex::new(None);

/// The shared fixtures, created when there is nothing live to reuse.
fn fixtures() -> Arc<Fixtures> {
    let mut slot = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(live) = slot.as_ref().and_then(Weak::upgrade) {
        return live;
    }
    // `insulate` first: the key and agent are made with the ambient config and
    // environment already pinned.
    insulate();
    let created = Arc::new(Fixtures {
        pgp: gpg_home(),
        agent: isolated_agent(),
    });
    *slot = Some(Arc::downgrade(&created));
    created
}

/// The shared OpenPGP fixture, or `None` when `gpg` is not installed.
fn pgp() -> Option<Tool<Pgp>> {
    let fixtures = fixtures();
    let value = fixtures.pgp.clone()?;
    Some(Tool {
        _fixtures: fixtures,
        value,
    })
}

/// The shared isolated agent, or `None` when `ssh-agent` is not installed.
fn agent() -> Option<Tool<Agent>> {
    let fixtures = fixtures();
    let value = fixtures.agent.clone()?;
    Some(Tool {
        _fixtures: fixtures,
        value,
    })
}

/// A shared fixture, kept alive together with the rest of its set.
///
/// Holding only the tool itself would let [`fixtures`] tear the set down — and
/// with it the process-wide `GNUPGHOME`/`SSH_AUTH_SOCK` — while another test
/// still signs with the key of the old set. Derefs to the tool.
struct Tool<T> {
    _fixtures: Arc<Fixtures>,
    value: Arc<T>,
}

impl<T> std::ops::Deref for Tool<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// A key home for gpg, with `GNUPGHOME` pointed at it for the whole binary.
fn gpg_home() -> Option<Arc<Pgp>> {
    if !have("gpg") {
        return None;
    }
    let home = GpgHome::new();
    // GNUPGHOME is process-wide, so it is set once here; every gpg in this
    // binary inherits it from now on and never sees the real home.
    // SAFETY: set while `SHARED` is locked and nothing of this process has
    // spawned gpg against the real home yet.
    unsafe { std::env::set_var("GNUPGHOME", home.path()) };

    run(
        Command::new("gpg").args([
            "--batch",
            "--passphrase",
            "",
            "--quick-gen-key",
            SIGNER,
            "rsa2048",
            "sign",
            "never",
        ]),
        &[],
    );

    let listed = String::from_utf8(
        run(
            Command::new("gpg").args(["--list-keys", "--with-colons"]),
            &[],
        )
        .stdout,
    )
    .expect("gpg lists ASCII");
    let fingerprint = listed
        .lines()
        .find_map(|line| line.strip_prefix("fpr:::::::::"))
        .and_then(|rest| rest.split(':').next())
        .expect("a freshly generated key has a fingerprint")
        .to_owned();

    // Warm the agent up once, so the first real signature does not race key
    // lookup and report a spurious "No public key".
    run(
        Command::new("gpg").args([
            "--batch",
            "--armor",
            "--detach-sign",
            "--output",
            "-",
            "-u",
            &fingerprint,
        ]),
        b"warm-up",
    );

    Some(Arc::new(Pgp {
        _home: home,
        fingerprint,
    }))
}

fn ssh() -> Option<Ssh> {
    if !have("ssh-keygen") {
        return None;
    }
    let dir = TempDir::new().expect("temp dir");
    let key = dir.path().join("id_ed25519");
    run(
        Command::new("ssh-keygen").args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            SIGNER_MAIL,
            "-f",
            key.to_str().expect("ascii path"),
        ]),
        &[],
    );
    let public_key = std::fs::read_to_string(key.with_extension("pub")).expect("public key");
    let public_key = public_key.trim_end().to_owned();
    let allowed_signers = dir.path().join("allowed_signers");
    std::fs::write(&allowed_signers, format!("{SIGNER_MAIL} {public_key}\n"))
        .expect("allowed signers");
    Some(Ssh {
        _dir: dir,
        key,
        public_key,
        allowed_signers,
    })
}

/// An isolated ssh-agent, so the `gpg.ssh.defaultKeyCommand` path can be
/// exercised without the user's agent or keys.
struct Agent {
    child: Child,
    _dir: TempDir,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An agent on a socket of its own, with `SSH_AUTH_SOCK` pointed at it.
fn isolated_agent() -> Option<Arc<Agent>> {
    if !have("ssh-agent") || !have("ssh-add") {
        return None;
    }
    let dir = TempDir::new().ok()?;
    let socket = dir.path().join("agent.sock");
    let child = Command::new("ssh-agent")
        // `-D` stays in the foreground: without it ssh-agent forks and the
        // child this handle holds is only the parent, so the agent would
        // survive the kill on drop.
        .args(["-D", "-a"])
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Every ssh-keygen and ssh-add of this binary now talks to it.
    // SAFETY: set while `SHARED` is locked, before any of them runs.
    unsafe { std::env::set_var("SSH_AUTH_SOCK", &socket) };
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Some(Arc::new(Agent { child, _dir: dir }))
}

/// Whether `program` resolves on `PATH` (both `gpg` and `ssh-keygen` exit
/// non-zero for `--version`, so they cannot be probed that way).
fn have(program: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Run a command with `stdin`, assert success, and return its output.
fn run(command: &mut Command, stdin: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns");
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(stdin)
        .expect("writes stdin");
    let output = child.wait_with_output().expect("waits");
    assert!(
        output.status.success(),
        "{} failed: {}",
        command.get_program().to_string_lossy(),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("spawns git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Like [`git`], with `input` written to git's stdin.
fn git_stdin(dir: &Path, args: &[&str], input: &[u8]) -> Vec<u8> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns git");
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(input)
        .expect("writes stdin");
    let output = child.wait_with_output().expect("waits");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// A temporary repository plus its handle.
fn repo() -> (TempDir, Repo) {
    init_repo(&[])
}

/// A temporary SHA-256 repository plus its handle, where git signs under
/// `gpgsig-sha256`.
fn sha256_repo() -> (TempDir, Repo) {
    init_repo(&["--object-format=sha256"])
}

/// A temporary repository created with `init_args`, plus its handle.
///
/// `insulate` has already cut the ambient config off; what a test relies on is
/// written here, in the repo, so nothing outside can steer it.
fn init_repo(init_args: &[&str]) -> (TempDir, Repo) {
    insulate();
    let dir = TempDir::new().expect("temp dir");
    let mut init = vec!["init", "-q"];
    init.extend_from_slice(init_args);
    git(dir.path(), &init);
    git(dir.path(), &["config", "user.signingkey", ""]);
    git(dir.path(), &["config", "gpg.format", "openpgp"]);
    git(dir.path(), &["config", "gpg.program", "gpg"]);
    git(dir.path(), &["config", "gpg.ssh.program", "ssh-keygen"]);
    let repo = Repo::open(dir.path()).expect("opens the fresh repository");
    (dir, repo)
}

/// A commit made by git itself with `-S`, so the signature sits in the header
/// git actually uses for the repository's object format.
fn commit_signed_by_git(repo: &Repo, pgp: &Pgp) -> CommitObject {
    git(
        repo.path(),
        &["config", "user.signingkey", &pgp.fingerprint],
    );
    git(repo.path(), &["config", "user.name", "Test"]);
    git(repo.path(), &["config", "user.email", SIGNER_MAIL]);
    git(repo.path(), &["config", "gpg.format", "openpgp"]);
    git(repo.path(), &["config", "gpg.program", "gpg"]);
    git(
        repo.path(),
        &["commit", "-q", "--allow-empty", "-S", "-m", "signed"],
    );
    CommitObject::parse(&git(repo.path(), &["cat-file", "commit", "HEAD"]))
        .expect("git writes a parsable commit")
}

fn object(message: &str) -> CommitObject {
    CommitObject::parse(
        format!(
            "tree {EMPTY_TREE}\nauthor {SIGNER} 1700000000 +0000\n\
             committer {SIGNER} 1700000000 +0000\n\n{message}"
        )
        .as_bytes(),
    )
    .expect("fixture parses")
}

/// The object with `armor` spliced in under `header`, the way the seal
/// pipeline will do it.
fn signed(object: &CommitObject, header: SigHeader, armor: &[u8]) -> CommitObject {
    let armor = std::str::from_utf8(armor).expect("armor is ASCII");
    let mut headers = object.headers.clone();
    headers.push((
        header.as_str().as_bytes().to_vec(),
        armor.trim_end_matches('\n').as_bytes().to_vec(),
    ));
    CommitObject {
        headers,
        message: object.message.clone(),
    }
}

fn sign_with_pgp(bytes: &[u8], pgp: &Pgp) -> Vec<u8> {
    run(
        Command::new("gpg").args([
            "--batch",
            "--armor",
            "--detach-sign",
            "--output",
            "-",
            "-u",
            &pgp.fingerprint,
        ]),
        bytes,
    )
    .stdout
}

fn sign_with_ssh(bytes: &[u8], ssh: &Ssh) -> Vec<u8> {
    run(
        Command::new("ssh-keygen").args([
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            ssh.key.to_str().expect("ascii path"),
            "-",
        ]),
        bytes,
    )
    .stdout
}

// --- inspect -------------------------------------------------------------

#[test]
fn signature_header_names_round_trip() {
    for header in [SigHeader::Gpgsig, SigHeader::GpgsigSha256] {
        assert_eq!(SigHeader::from_name(header.as_str()), Some(header));
    }
    assert_eq!(SigHeader::from_name("gpgsig-sha1"), None);
}

#[test]
fn an_object_without_gpgsig_is_unsigned() {
    assert_eq!(inspect(&object(MESSAGE)), SignatureState::Unsigned);
}

#[test]
fn inspect_reads_the_issuer_of_an_openpgp_signature() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let armor = sign_with_pgp(&object(MESSAGE).compose(), &pgp);
    let commit = signed(&object(MESSAGE), SigHeader::Gpgsig, &armor);

    assert_eq!(
        inspect(&commit),
        SignatureState::SignedOpenPgp {
            issuer: Some(pgp.fingerprint.clone()),
            header: SigHeader::Gpgsig,
        }
    );
}

#[test]
fn inspect_reads_a_sha256_signature_from_its_own_header() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (_dir, repo) = sha256_repo();
    let commit = commit_signed_by_git(&repo, &pgp);

    // git stores the signature under `gpgsig-sha256` here; reading `gpgsig`
    // alone would call this commit unsigned.
    assert_eq!(
        inspect(&commit),
        SignatureState::SignedOpenPgp {
            issuer: Some(pgp.fingerprint.clone()),
            header: SigHeader::GpgsigSha256,
        }
    );
}

#[test]
fn inspect_extracts_the_public_key_of_an_ssh_signature() {
    let Some(ssh) = ssh() else {
        eprintln!("skip: ssh-keygen unavailable");
        return;
    };
    let armor = sign_with_ssh(&object(MESSAGE).compose(), &ssh);
    let commit = signed(&object(MESSAGE), SigHeader::Gpgsig, &armor);

    let SignatureState::SignedSsh { public_key, header } = inspect(&commit) else {
        panic!("expected an SSH signature, got {:?}", inspect(&commit));
    };
    assert_eq!(header, SigHeader::Gpgsig);
    // The signature embeds the key blob only, not the comment on the
    // authorized-keys line it came from.
    let expected: Vec<&str> = ssh.public_key.split_whitespace().take(2).collect();
    assert_eq!(public_key, expected.join(" "));
}

#[test]
fn inspect_reads_the_object_while_commit_gpgsign_is_true() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (dir, _repo) = repo();
    git(dir.path(), &["config", "commit.gpgSign", "true"]);

    // `git commit --no-gpg-sign` writes no gpgsig even though config asks for
    // one: the object must win.
    assert_eq!(inspect(&object(MESSAGE)), SignatureState::Unsigned);

    let armor = sign_with_pgp(&object(MESSAGE).compose(), &pgp);
    let commit = signed(&object(MESSAGE), SigHeader::Gpgsig, &armor);
    assert!(matches!(
        inspect(&commit),
        SignatureState::SignedOpenPgp {
            issuer: Some(_),
            header: SigHeader::Gpgsig,
        }
    ));
}

#[test]
fn inspect_finds_a_gpgsig_sha256_header() {
    let mut commit = object(MESSAGE);
    commit
        .headers
        .push((b"gpgsig-sha256".to_vec(), b"opaque".to_vec()));
    assert_eq!(
        inspect(&commit),
        SignatureState::SignedOpenPgp {
            issuer: None,
            header: SigHeader::GpgsigSha256,
        }
    );
}

#[test]
fn inspect_prefers_gpgsig_when_both_headers_are_present() {
    let mut commit = object(MESSAGE);
    commit.headers.push((b"gpgsig".to_vec(), b"first".to_vec()));
    commit
        .headers
        .push((b"gpgsig-sha256".to_vec(), b"second".to_vec()));
    assert_eq!(
        inspect(&commit),
        SignatureState::SignedOpenPgp {
            issuer: None,
            header: SigHeader::Gpgsig,
        }
    );
}

#[test]
fn an_ssh_armor_without_a_readable_key_still_counts_as_signed() {
    let mut commit = object(MESSAGE);
    commit.headers.push((
        b"gpgsig".to_vec(),
        b"-----BEGIN SSH SIGNATURE-----\nnot base64\n-----END SSH SIGNATURE-----".to_vec(),
    ));
    assert_eq!(
        inspect(&commit),
        SignatureState::SignedSsh {
            public_key: String::new(),
            header: SigHeader::Gpgsig,
        }
    );
}

// --- format --------------------------------------------------------------

#[test]
fn gpg_format_defaults_to_openpgp() {
    // The lock keeps the ambient-config test from pointing `GIT_CONFIG_GLOBAL`
    // somewhere else while the default is asserted.
    let _lock = env_lock();
    let (dir, repo) = repo();
    // `init_repo` sets the format explicitly; without any setting the default
    // has to be git's.
    git(dir.path(), &["config", "--unset", "gpg.format"]);
    assert_eq!(format(&repo), Ok(Format::OpenPgp));
}

#[test]
fn a_repo_local_gpg_format_wins_over_the_ambient_one() {
    // `insulate` runs with the repo, before the ambient config replaces the
    // `/dev/null` global.
    let (dir, repo) = repo();
    let _lock = env_lock();
    let _global = GlobalConfig::new("[gpg]\n\tformat = ssh\n");

    assert_eq!(format(&repo), Ok(Format::OpenPgp));

    // The ambient value really is in effect, not shadowed by the insulation:
    // without the repo-local setting git reports it.
    git(dir.path(), &["config", "--unset", "gpg.format"]);
    assert_eq!(format(&repo), Ok(Format::Ssh));
}

#[test]
fn gpg_format_honours_ssh() {
    let (dir, repo) = repo();
    git(dir.path(), &["config", "gpg.format", "ssh"]);
    assert_eq!(format(&repo), Ok(Format::Ssh));

    // git compares the value without case.
    git(dir.path(), &["config", "gpg.format", "SSH"]);
    assert_eq!(format(&repo), Ok(Format::Ssh));
}

#[test]
fn gpg_format_rejects_unknown_values() {
    let (dir, repo) = repo();
    git(dir.path(), &["config", "gpg.format", "x509"]);
    let error = format(&repo).expect_err("x509 is not a git signing format");
    assert!(error.to_string().contains("x509"), "{error}");
}

// --- sign ----------------------------------------------------------------

#[test]
fn signed_openpgp_armor_is_emitted_with_its_final_newline() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (_dir, repo) = repo();
    let state = SignatureState::SignedOpenPgp {
        issuer: Some(pgp.fingerprint.clone()),
        header: SigHeader::Gpgsig,
    };
    let armor = sign(&object(MESSAGE), &state, &repo).expect("signs");

    assert!(armor.starts_with(b"-----BEGIN PGP SIGNATURE-----"));
    assert!(
        armor.ends_with(b"\n"),
        "the caller only prefixes, never adds"
    );
}

#[test]
fn signing_covers_exactly_the_composed_object_for_openpgp() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (_dir, repo) = repo();
    let commit = object(MESSAGE);
    // The issuer is left to `user.signingkey`, the config fallback.
    git(
        _dir.path(),
        &["config", "user.signingkey", &pgp.fingerprint],
    );

    let armor = sign(
        &commit,
        &SignatureState::SignedOpenPgp {
            issuer: None,
            header: SigHeader::Gpgsig,
        },
        &repo,
    )
    .expect("signs");

    // Verify the armor against `compose()` with gpg itself: a single
    // normalised or trimmed byte would make this fail.
    let files = TempDir::new().expect("temp dir");
    let signature = files.path().join("sig");
    let data = files.path().join("data");
    std::fs::write(&signature, &armor).expect("writes the signature");
    std::fs::write(&data, commit.compose()).expect("writes the object");
    run(
        Command::new("gpg")
            .args(["--batch", "--verify"])
            .arg(&signature)
            .arg(&data),
        &[],
    );
}

#[test]
fn signing_covers_exactly_the_composed_object_for_ssh() {
    let Some(ssh) = ssh() else {
        eprintln!("skip: ssh-keygen unavailable");
        return;
    };
    let (_dir, repo) = repo();
    let commit = object(MESSAGE);
    git(
        _dir.path(),
        &[
            "config",
            "user.signingkey",
            ssh.key.to_str().expect("ascii path"),
        ],
    );

    let armor = sign(
        &commit,
        &SignatureState::SignedSsh {
            public_key: ssh.public_key.clone(),
            header: SigHeader::Gpgsig,
        },
        &repo,
    )
    .expect("signs");
    assert!(armor.starts_with(b"-----BEGIN SSH SIGNATURE-----"));
    assert!(
        armor.ends_with(b"\n"),
        "the caller only prefixes, never adds"
    );

    let files = TempDir::new().expect("temp dir");
    let signature = files.path().join("sig");
    std::fs::write(&signature, &armor).expect("writes the signature");
    let mut verify = Command::new("ssh-keygen");
    verify
        .args([
            "-Y",
            "verify",
            "-f",
            ssh.allowed_signers.to_str().expect("ascii path"),
        ])
        .args(["-I", SIGNER_MAIL, "-n", "git", "-s"])
        .arg(&signature);
    verify.stdin(Stdio::piped());
    let mut child = verify.spawn().expect("spawns ssh-keygen");
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(&commit.compose())
        .expect("writes stdin");
    let output = child.wait_with_output().expect("waits");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_unknown_openpgp_key_is_key_unavailable() {
    let Some(_pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (_dir, repo) = repo();
    let state = SignatureState::SignedOpenPgp {
        issuer: Some("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_owned()),
        header: SigHeader::Gpgsig,
    };
    assert_eq!(
        sign(&object(MESSAGE), &state, &repo),
        Err(SignError::KeyUnavailable)
    );
}

#[test]
fn an_ssh_key_file_that_is_missing_is_key_unavailable() {
    let Some(ssh) = ssh() else {
        eprintln!("skip: ssh-keygen unavailable");
        return;
    };
    let (dir, repo) = repo();
    git(
        dir.path(),
        &["config", "user.signingkey", "/nonexistent/id_ed25519"],
    );
    let state = SignatureState::SignedSsh {
        public_key: ssh.public_key.clone(),
        header: SigHeader::Gpgsig,
    };
    assert_eq!(
        sign(&object(MESSAGE), &state, &repo),
        Err(SignError::KeyUnavailable)
    );
}

#[test]
fn a_missing_signer_program_is_failed_not_key_unavailable() {
    let (dir, repo) = repo();
    git(dir.path(), &["config", "gpg.program", "/nonexistent/gpg"]);
    let state = SignatureState::SignedOpenPgp {
        issuer: Some("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_owned()),
        header: SigHeader::Gpgsig,
    };

    // The key was never asked for, so this is not `KeyUnavailable`.
    let error = sign(&object(MESSAGE), &state, &repo).expect_err("the program is missing");
    let SignError::Failed(message) = &error else {
        panic!("expected Failed, got {error:?}");
    };
    assert!(message.contains("/nonexistent/gpg"), "{message}");
}

#[test]
fn ssh_signing_finds_the_key_through_the_default_key_command() {
    let Some(ssh) = ssh() else {
        eprintln!("skip: ssh-keygen unavailable");
        return;
    };
    let Some(_agent) = agent() else {
        eprintln!("skip: ssh-agent unavailable");
        return;
    };
    run(Command::new("ssh-add").arg(&ssh.key), &[]);

    let (dir, repo) = repo();
    git(
        dir.path(),
        &["config", "gpg.ssh.defaultKeyCommand", "ssh-add -L"],
    );
    git(
        dir.path(),
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            ssh.allowed_signers.to_str().expect("ascii path"),
        ],
    );

    // The state's key comes from the old signature; the agent only has to hold
    // the matching private half.
    let commit = object(MESSAGE);
    let old = inspect(&signed(
        &commit,
        SigHeader::Gpgsig,
        &sign_with_ssh(&commit.compose(), &ssh),
    ));
    let armor = sign(&commit, &old, &repo).expect("signs through the agent");

    assert_eq!(
        verify(&signed(&commit, SigHeader::Gpgsig, &armor), &repo),
        VerifyOutcome::Good
    );
}

#[test]
fn a_default_key_command_without_the_matching_key_is_key_unavailable() {
    let Some(ssh) = ssh() else {
        eprintln!("skip: ssh-keygen unavailable");
        return;
    };
    let Some(_agent) = agent() else {
        eprintln!("skip: ssh-agent unavailable");
        return;
    };

    let (dir, repo) = repo();
    // `ssh-add -l` lists fingerprints only, so no line carries a key blob.
    git(
        dir.path(),
        &["config", "gpg.ssh.defaultKeyCommand", "ssh-add -l"],
    );
    let state = SignatureState::SignedSsh {
        public_key: ssh.public_key.clone(),
        header: SigHeader::Gpgsig,
    };
    assert_eq!(
        sign(&object(MESSAGE), &state, &repo),
        Err(SignError::KeyUnavailable)
    );
}

#[test]
fn an_unsigned_state_cannot_be_signed() {
    let (_dir, repo) = repo();
    assert!(matches!(
        sign(&object(MESSAGE), &SignatureState::Unsigned, &repo),
        Err(SignError::Failed(_))
    ));
}

/// The guard this test verifies sits in a `debug_assert!`, so the whole test
/// exists in debug builds only: in release the assert is not there either.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "sign() received a signed object")]
fn sign_panics_on_an_object_that_still_carries_a_signature() {
    // The assert sits before the signer runs, so no gpg is needed.
    let (_dir, repo) = repo();
    let mut commit = object(MESSAGE);
    commit.headers.push((b"gpgsig".to_vec(), b"stale".to_vec()));
    let state = SignatureState::SignedOpenPgp {
        issuer: Some("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_owned()),
        header: SigHeader::Gpgsig,
    };

    // The armor would cover the old signature too, and git calls the result BAD.
    let _ = sign(&commit, &state, &repo);
}

// --- verify --------------------------------------------------------------

#[test]
fn verify_does_not_write_an_unsigned_object() {
    let (dir, repo) = repo();
    assert_eq!(verify(&object(MESSAGE), &repo), VerifyOutcome::Unsigned);
    // Nothing was written, so the object database is still empty.
    let counted = Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["count-objects", "-v"])
        .output()
        .expect("spawns git");
    let report = String::from_utf8_lossy(&counted.stdout).into_owned();
    assert!(
        report.contains("count: 0\n"),
        "verify must not write an unsigned object: {report}"
    );
}

#[test]
fn a_seal_keeps_a_sha256_signature_alive() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (_dir, repo) = sha256_repo();
    let commit = commit_signed_by_git(&repo, &pgp);
    let state = inspect(&commit);
    let header = state.header().expect("the git commit is signed");
    assert_eq!(header, SigHeader::GpgsigSha256);

    // What the seal does: strip the old signature, add the trailer, sign the
    // new bytes, splice the armor back under the same header.
    let mut stripped = commit.without_signature();
    stripped
        .message
        .extend_from_slice(b"\nX-RFC3161-Imprint: sha256:00\n");
    let armor = sign(&stripped, &state, &repo).expect("signs");
    let sealed = signed(&stripped, header, &armor);

    // git has to accept the object before it can be verified at all.
    let oid = git_stdin(
        repo.path(),
        &["hash-object", "-w", "-t", "commit", "--stdin"],
        &sealed.compose(),
    );
    assert_eq!(oid.len(), 64 + 1, "a SHA-256 object id is 32 bytes");

    assert_eq!(verify(&sealed, &repo), VerifyOutcome::Good);
}

#[test]
fn verify_accepts_a_freshly_signed_object() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (_dir, repo) = repo();
    let commit = object(MESSAGE);
    let armor = sign(
        &commit,
        &SignatureState::SignedOpenPgp {
            issuer: Some(pgp.fingerprint.clone()),
            header: SigHeader::Gpgsig,
        },
        &repo,
    )
    .expect("signs");

    assert_eq!(
        verify(&signed(&commit, SigHeader::Gpgsig, &armor), &repo),
        VerifyOutcome::Good
    );
}

#[test]
fn verify_rejects_a_tampered_object() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (_dir, repo) = repo();
    let commit = object(MESSAGE);
    let armor = sign(
        &commit,
        &SignatureState::SignedOpenPgp {
            issuer: Some(pgp.fingerprint.clone()),
            header: SigHeader::Gpgsig,
        },
        &repo,
    )
    .expect("signs");
    let mut commit = signed(&commit, SigHeader::Gpgsig, &armor);
    commit.message = b"tampered".to_vec();

    assert_eq!(verify(&commit, &repo), VerifyOutcome::Bad);
}

#[test]
fn verify_reports_an_error_when_the_object_cannot_be_written() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (_dir, repo) = repo();
    let commit = object(MESSAGE);
    let armor = sign_with_pgp(&commit.compose(), &pgp);
    let commit = signed(&commit, SigHeader::Gpgsig, &armor);

    // A commit object without a `tree` header fails git's fsck inside
    // `hash-object`, so verification never reaches gpg.
    let broken = CommitObject {
        headers: commit
            .headers
            .iter()
            .filter(|(name, _)| name != b"tree")
            .cloned()
            .collect(),
        message: commit.message.clone(),
    };
    let outcome = verify(&broken, &repo);
    let VerifyOutcome::Error(message) = outcome else {
        panic!("expected an error, got {outcome:?}");
    };
    assert!(!message.is_empty());
}

#[test]
fn verify_reports_an_error_when_the_signer_program_cannot_run() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (dir, repo) = repo();
    let commit = object(MESSAGE);
    let armor = sign_with_pgp(&commit.compose(), &pgp);
    let commit = signed(&commit, SigHeader::Gpgsig, &armor);

    // git reports a signer that cannot start as exit 1 too, but the signature
    // was never checked, so it must not read as a verdict on the object.
    git(dir.path(), &["config", "gpg.program", "/nonexistent/gpg"]);
    let outcome = verify(&commit, &repo);
    let VerifyOutcome::Error(message) = outcome else {
        panic!("expected an error, got {outcome:?}");
    };
    assert!(message.contains("/nonexistent/gpg"), "{message}");

    // A bare program name is not in the stderr in a matchable way, so the
    // wording git prints is what has to carry it.
    git(dir.path(), &["config", "gpg.program", "no-such-gpg"]);
    let outcome = verify(&commit, &repo);
    assert!(
        matches!(outcome, VerifyOutcome::Error(_)),
        "expected an error, got {outcome:?}"
    );
}

#[test]
fn verify_reports_an_error_when_the_allowed_signers_file_is_not_configured() {
    let Some(ssh) = ssh() else {
        eprintln!("skip: ssh-keygen unavailable");
        return;
    };
    // No `gpg.ssh.allowedSignersFile`: git can neither accept nor reject the
    // signer, so the signature is not `Bad`, it was never judged.
    let (_dir, repo) = repo();
    let commit = object(MESSAGE);
    let commit = signed(
        &commit,
        SigHeader::Gpgsig,
        &sign_with_ssh(&commit.compose(), &ssh),
    );

    let outcome = verify(&commit, &repo);
    let VerifyOutcome::Error(message) = outcome else {
        panic!("expected an error, got {outcome:?}");
    };
    assert!(message.contains("allowedSignersFile"), "{message}");

    // A configured file that merely lacks the key stays a verdict on the object.
    let elsewhere = TempDir::new().expect("temp dir");
    let empty = elsewhere.path().join("allowed_signers");
    std::fs::write(&empty, "").expect("writes the empty file");
    git(
        repo.path(),
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            empty.to_str().expect("ascii path"),
        ],
    );
    assert_eq!(verify(&commit, &repo), VerifyOutcome::Bad);
}

#[test]
fn an_ssh_signature_verifies_when_the_signer_is_allowed() {
    let Some(ssh) = ssh() else {
        eprintln!("skip: ssh-keygen unavailable");
        return;
    };
    let (dir, repo) = repo();
    git(
        dir.path(),
        &[
            "config",
            "user.signingkey",
            ssh.key.to_str().expect("ascii path"),
        ],
    );
    git(
        dir.path(),
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            ssh.allowed_signers.to_str().expect("ascii path"),
        ],
    );
    let commit = object(MESSAGE);
    let armor = sign(
        &commit,
        &SignatureState::SignedSsh {
            public_key: ssh.public_key.clone(),
            header: SigHeader::Gpgsig,
        },
        &repo,
    )
    .expect("signs");

    assert_eq!(
        verify(&signed(&commit, SigHeader::Gpgsig, &armor), &repo),
        VerifyOutcome::Good
    );
}

#[test]
fn sign_keeps_every_header_except_the_signature_ones() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    let (_dir, repo) = repo();

    // A signed commit that also carries `gpgsig-sha256`, an unknown header and
    // a mergetag-shaped multi-line header.
    let mut commit = object(MESSAGE);
    commit.headers.push((b"gpgsig".to_vec(), b"stale".to_vec()));
    commit
        .headers
        .push((b"gpgsig-sha256".to_vec(), b"also stale".to_vec()));
    commit.headers.push((b"x-note".to_vec(), b"kept".to_vec()));
    commit.headers.push((
        b"mergetag".to_vec(),
        b"object 1234\ntype commit\ntag v1\n-----BEGIN PGP SIGNATURE-----\n".to_vec(),
    ));

    // The caller signs the object without the signature headers.
    let stripped = commit.without_signature();
    assert!(stripped.header("gpgsig").is_none());
    assert_eq!(stripped.header("x-note"), Some(b"kept".as_slice()));
    assert!(stripped.header("mergetag").is_some());

    let armor = sign(
        &stripped,
        &SignatureState::SignedOpenPgp {
            issuer: Some(pgp.fingerprint.clone()),
            header: SigHeader::Gpgsig,
        },
        &repo,
    )
    .expect("signs");

    let files = TempDir::new().expect("temp dir");
    let signature = files.path().join("sig");
    let data = files.path().join("data");
    std::fs::write(&signature, &armor).expect("writes the signature");
    std::fs::write(&data, stripped.compose()).expect("writes the object");
    run(
        Command::new("gpg")
            .args(["--batch", "--verify"])
            .arg(&signature)
            .arg(&data),
        &[],
    );
}

#[test]
fn sign_uses_the_signature_issuer_over_a_configured_one() {
    let Some(pgp) = pgp() else {
        eprintln!("skip: gpg unavailable");
        return;
    };
    // A second, unrelated key in a home of its own.
    let elsewhere = GpgHome::new();
    let home = elsewhere.path().to_string_lossy().into_owned();
    run(
        Command::new("gpg")
            .args([
                "--homedir",
                &home,
                "--batch",
                "--passphrase",
                "",
                "--quick-gen-key",
                "Other <o@example.com>",
                "rsa2048",
                "sign",
                "never",
            ])
            .env_remove("GNUPGHOME"),
        &[],
    );
    let listed = String::from_utf8(
        run(
            Command::new("gpg")
                .args(["--homedir", &home, "--list-keys", "--with-colons"])
                .env_remove("GNUPGHOME"),
            &[],
        )
        .stdout,
    )
    .expect("ASCII");
    let other = listed
        .lines()
        .find_map(|line| line.strip_prefix("fpr:::::::::"))
        .and_then(|rest| rest.split(':').next())
        .expect("fingerprint")
        .to_owned();

    let (_dir, repo) = repo();
    git(_dir.path(), &["config", "user.signingkey", &other]);
    let commit = object(MESSAGE);
    let armor = sign(
        &commit,
        &SignatureState::SignedOpenPgp {
            issuer: Some(pgp.fingerprint.clone()),
            header: SigHeader::Gpgsig,
        },
        &repo,
    )
    .expect("signs");

    // The signature names the issuer, so the *other* home cannot verify it.
    let files = TempDir::new().expect("temp dir");
    let signature = files.path().join("sig");
    let data = files.path().join("data");
    std::fs::write(&signature, &armor).expect("writes the signature");
    std::fs::write(&data, commit.compose()).expect("writes the object");
    let verified = Command::new("gpg")
        .args(["--homedir", &home, "--batch", "--verify"])
        .arg(&signature)
        .arg(&data)
        .output()
        .expect("spawns gpg");
    let stderr = String::from_utf8_lossy(&verified.stderr).to_lowercase();
    assert!(
        !verified.status.success() && stderr.contains("no public key"),
        "the configured key must not have signed: {stderr}"
    );
}
