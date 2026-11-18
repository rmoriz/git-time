//! Commit signatures: what an object is signed with, how to sign it again, and
//! whether the signature on it still holds.
//!
//! The state is read from the object's signature header and nowhere else. That
//! is deliberate: `git commit --no-gpg-sign` under `commit.gpgSign=true` writes
//! no signature, and config alone would wrongly re-sign it. A rewritten commit
//! carries its signature state forward, so a signed commit is never turned into
//! an unsigned one by the rewrite.
//!
//! Both header names git uses count: `gpgsig` in a SHA-1 repository and
//! `gpgsig-sha256` in a SHA-256 one. They carry the same armor, so the state
//! records which of them the object had.
//!
//! Signing hands the exact bytes back to the caller. It never touches the
//! object and never writes a header; it takes the object *without* a signature
//! header, signs the bytes [`CommitObject::compose`] produces, and returns the
//! armor as the signer emitted it, trailing newline included. The caller
//! splices the armor back under [`SignatureState::header`] — the same header
//! name the object had, never a different one.
//!
//! Keys come from the signature: the OpenPGP issuer fingerprint is read out of
//! the armor with `gpg --list-packets`, the SSH public key out of the signature
//! blob itself. Configuration is only the fallback for a signature that carries
//! no issuer.
//!
//! Every key, fingerprint and path is one [`Command`] argument, never a shell
//! word. The one exception is `gpg.ssh.defaultKeyCommand`, itself a command
//! line, which runs under `sh -c` exactly as git runs it.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::object::CommitObject;
use crate::repo::{Repo, RepoError, run_git};

/// First line of an OpenPGP armor.
const PGP_ARMOR: &str = "-----BEGIN PGP SIGNATURE-----";
/// First line of an SSH signature armor.
const SSH_ARMOR: &str = "-----BEGIN SSH SIGNATURE-----";
/// Magic every SSHSIG blob starts with.
const SSH_MAGIC: &[u8] = b"SSHSIG";
/// The git signature namespace.
const SSH_NAMESPACE: &str = "git";

/// The header a commit signature lives in.
///
/// git writes `gpgsig` in a SHA-1 repository and `gpgsig-sha256` in a SHA-256
/// one; both hold the identical armor. A rewrite must put a signature back
/// under the header it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigHeader {
    /// `gpgsig`, the header of a SHA-1 repository.
    Gpgsig,
    /// `gpgsig-sha256`, the header of a SHA-256 repository.
    GpgsigSha256,
}

impl SigHeader {
    /// Every signature header, in the order [`inspect`] looks for them.
    const ALL: [Self; 2] = [Self::Gpgsig, Self::GpgsigSha256];

    /// The header's name in the object.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gpgsig => "gpgsig",
            Self::GpgsigSha256 => "gpgsig-sha256",
        }
    }

    /// The header called `name`, if it is one.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|header| header.as_str() == name)
    }
}

/// What a commit object is signed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureState {
    /// No signature header: the rewrite must leave the object unsigned.
    Unsigned,
    /// Signed with OpenPGP. `issuer` is the key fingerprint (or key ID) the
    /// signature names, when it names one; `header` is where it sits.
    SignedOpenPgp {
        issuer: Option<String>,
        header: SigHeader,
    },
    /// Signed with SSH. `public_key` is the embedded key as an
    /// `authorized_keys` line, or empty when the armor could not be read;
    /// `header` is where the signature sits.
    SignedSsh {
        public_key: String,
        header: SigHeader,
    },
}

impl SignatureState {
    /// The header the signature must be spliced back under, or `None` when
    /// there is none.
    ///
    /// Signing never writes the header itself, so the caller uses this name
    /// rather than a guessed one: a SHA-256 object must get `gpgsig-sha256`
    /// back, not `gpgsig`.
    #[must_use]
    pub fn header(&self) -> Option<SigHeader> {
        match self {
            Self::Unsigned => None,
            Self::SignedOpenPgp { header, .. } | Self::SignedSsh { header, .. } => Some(*header),
        }
    }
}

/// Which signing backend the repository uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `gpg.format = openpgp`, the git default.
    OpenPgp,
    /// `gpg.format = ssh`.
    Ssh,
}

/// The signing formats git knows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    /// `gpg.format` holds a value neither `openpgp` nor `ssh`.
    #[error("gpg.format must be `openpgp` or `ssh`, not {0:?}")]
    Unknown(String),
    /// The configuration could not be read.
    #[error(transparent)]
    Repo(#[from] RepoError),
}

/// Why a signature could not be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The signer asked and the user (or their PIN entry) said no.
    #[error("signing cancelled")]
    Cancelled,
    /// The key the signature names is not usable here.
    #[error("signing key unavailable")]
    KeyUnavailable,
    /// Anything else the signer reported, including a signer program that could
    /// not be started at all.
    #[error("{0}")]
    Failed(String),
}

/// What `git verify-commit` said about an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The signature holds.
    Good,
    /// The signature is there but does not match the object.
    Bad,
    /// There was no signature to check.
    Unsigned,
    /// Verification could not run or is inconclusive.
    Error(String),
}

/// What `commit` is signed with.
///
/// `gpgsig` wins over `gpgsig-sha256` when (wrongly) both are present, the
/// order git itself reads them in. An SSH armor whose key cannot be decoded is
/// still reported as signed, with an empty key, so the signature is never
/// dropped.
///
/// Reading an OpenPGP issuer spawns `gpg --list-packets`. Without a usable gpg
/// the issuer is `None`, which leaves key choice to configuration later on.
#[must_use]
pub fn inspect(commit: &CommitObject) -> SignatureState {
    let Some((header, value)) = SigHeader::ALL
        .into_iter()
        .find_map(|header| Some((header, commit.header(header.as_str())?)))
    else {
        return SignatureState::Unsigned;
    };
    let armor = String::from_utf8_lossy(value);
    if armor.starts_with(SSH_ARMOR) {
        return SignatureState::SignedSsh {
            public_key: ssh_public_key(&armor).unwrap_or_default(),
            header,
        };
    }
    // A signature header that is neither armor (x509 in a future git) still
    // marks the object as signed; it is simply re-signed with the default key.
    SignatureState::SignedOpenPgp {
        issuer: if armor.starts_with(PGP_ARMOR) {
            pgp_issuer(&armor)
        } else {
            None
        },
        header,
    }
}

/// The repository's signing format.
///
/// `gpg.format` defaults to `openpgp`, as in git, and is compared without case
/// like git does. A value git does not know is an error rather than a silent
/// fallback to a format the user did not ask for.
pub fn format(repo: &Repo) -> Result<Format, FormatError> {
    match repo.config("gpg.format")?.as_deref() {
        None => Ok(Format::OpenPgp),
        Some(value) if value.eq_ignore_ascii_case("openpgp") => Ok(Format::OpenPgp),
        Some(value) if value.eq_ignore_ascii_case("ssh") => Ok(Format::Ssh),
        Some(other) => Err(FormatError::Unknown(other.to_owned())),
    }
}

/// Sign `commit`, which must already be the final object without a signature
/// header, and return the armor exactly as the signer wrote it.
///
/// The caller splices the armor in under [`SignatureState::header`]: prefix the
/// first line with that header name and one space, indent every further line
/// with one space. Nothing is added here, so the bytes signed are exactly
/// [`CommitObject::compose`] of `commit`.
///
/// `commit` must not carry a `gpgsig`/`gpgsig-sha256` header: the armor would
/// then cover the old signature as well, and git rejects the spliced-in second
/// one. Debug builds assert this; use [`CommitObject::without_signature`] first.
pub fn sign(
    commit: &CommitObject,
    state: &SignatureState,
    repo: &Repo,
) -> Result<Vec<u8>, SignError> {
    debug_assert!(
        commit.header("gpgsig").is_none() && commit.header("gpgsig-sha256").is_none(),
        "sign() received a signed object"
    );
    let bytes = commit.compose();
    match state {
        SignatureState::Unsigned => Err(SignError::Failed(
            "an unsigned commit has no signature to reproduce".to_owned(),
        )),
        SignatureState::SignedOpenPgp { issuer, .. } => open_pgp(&bytes, issuer.as_deref(), repo),
        SignatureState::SignedSsh { public_key, .. } => ssh(&bytes, public_key, repo),
    }
}

/// Check the signature on `commit` with `git verify-commit`.
///
/// The object is written into the repository with `git hash-object -w` first,
/// because verify-commit only sees objects, not bytes. An unsigned object is
/// reported without writing anything.
#[must_use]
pub fn verify(commit: &CommitObject, repo: &Repo) -> VerifyOutcome {
    if matches!(inspect(commit), SignatureState::Unsigned) {
        return VerifyOutcome::Unsigned;
    }
    let oid = match run_git(
        repo.path(),
        &["hash-object", "-w", "-t", "commit", "--stdin"],
        Some(&commit.compose()),
    ) {
        Ok(run) if run.succeeded() => String::from_utf8_lossy(&run.stdout).trim().to_owned(),
        Ok(run) => return VerifyOutcome::Error(run.stderr),
        Err(error) => return VerifyOutcome::Error(error.to_string()),
    };
    match run_git(repo.path(), &["verify-commit", &oid], None) {
        Ok(run) if run.succeeded() => VerifyOutcome::Good,
        // Exit 1 is gpg's or ssh-keygen's signature verdict — unless the signer
        // never ran or could not be set up, which git also reports as exit 1.
        Ok(run) if run.code == Some(1) => {
            if signer_missing(&run.stderr, repo) {
                VerifyOutcome::Error(run.stderr)
            } else {
                VerifyOutcome::Bad
            }
        }
        Ok(run) => VerifyOutcome::Error(run.stderr),
        Err(error) => VerifyOutcome::Error(error.to_string()),
    }
}

/// Whether git's stderr says verification could not run at all.
///
/// Two shapes are covered: the signer program could not be started, which git
/// prefixes with `cannot run`/`cannot exec`, and SSH verification that has no
/// `gpg.ssh.allowedSignersFile` — git words that as "needs to be configured",
/// and without it no principal can be matched, so no verdict is possible.
///
/// A configured program given as a path appears in the message too; a bare
/// program name is not looked for, because `gpg` is part of every gpg message
/// and a bad signature would read as an error.
fn signer_missing(stderr: &str, repo: &Repo) -> bool {
    let lowered = stderr.to_lowercase();
    let named = repo
        .config_non_empty("gpg.program")
        .ok()
        .flatten()
        .filter(|program| program.contains(['/', '\\']))
        .is_some_and(|program| stderr.contains(&program));
    named
        || lowered.contains("cannot run")
        || lowered.contains("cannot exec")
        || lowered.contains("not found")
        || lowered.contains("needs to be configured")
}

// --- signing backends ----------------------------------------------------

fn open_pgp(bytes: &[u8], issuer: Option<&str>, repo: &Repo) -> Result<Vec<u8>, SignError> {
    // A signature without an issuer leaves the key to config, then to gpg's
    // configured default key.
    let issuer = match issuer {
        Some(issuer) => Some(issuer.to_owned()),
        None => repo.config_non_empty("user.signingkey").ok().flatten(),
    };
    let program = signer(repo, "gpg.program", "gpg");
    let mut command = Command::new(program);
    command.args(["--batch", "--armor", "--detach-sign", "--output", "-"]);
    if let Some(issuer) = issuer.as_deref().filter(|issuer| !issuer.is_empty()) {
        command.args(["-u", issuer]);
    }
    run(&mut command, bytes)
}

fn ssh(bytes: &[u8], public_key: &str, repo: &Repo) -> Result<Vec<u8>, SignError> {
    let key = ssh_key_file(public_key, repo)?;
    let program = signer(repo, "gpg.ssh.program", "ssh-keygen");
    let mut command = Command::new(program);
    command
        .args(["-Y", "sign", "-n", SSH_NAMESPACE, "-f"])
        .arg(&key.path)
        .arg("-");
    run(&mut command, bytes)
}

/// The program to sign with: `key` from config, `default` when it is unset.
///
/// git runs `gpg`/`ssh-keygen` from those keys, so a test or a box with the
/// tool under another name works here too.
fn signer(repo: &Repo, key: &str, default: &str) -> String {
    repo.config_non_empty(key)
        .ok()
        .flatten()
        .unwrap_or_else(|| default.to_owned())
}

/// A key file and the temporary directory keeping it alive, if it is one.
struct KeyFile {
    _dir: Option<tempfile::TempDir>,
    path: PathBuf,
}

/// The file `ssh-keygen` should sign with.
///
/// `user.signingkey` wins and is used as given, private or public key file
/// alike. Otherwise `gpg.ssh.defaultKeyCommand` is asked for the agents' keys
/// and the one matching the signature's embedded key is written to a temporary
/// file, which is how a public key names an agent-held private key.
fn ssh_key_file(public_key: &str, repo: &Repo) -> Result<KeyFile, SignError> {
    if let Some(configured) = repo.config_non_empty("user.signingkey").ok().flatten() {
        let path = expand_tilde(&configured);
        if !path.is_file() {
            return Err(SignError::KeyUnavailable);
        }
        return Ok(KeyFile { _dir: None, path });
    }

    let command_line = repo
        .config_non_empty("gpg.ssh.defaultKeyCommand")
        .ok()
        .flatten()
        .ok_or(SignError::KeyUnavailable)?;
    let listing = Command::new("sh")
        .arg("-c")
        .arg(&command_line)
        .output()
        .map_err(|error| SignError::Failed(error.to_string()))?;
    if !listing.status.success() {
        return Err(SignError::KeyUnavailable);
    }
    let listing = String::from_utf8_lossy(&listing.stdout);

    let mut lines = listing.lines().filter(|line| !line.trim().is_empty());
    let blob = public_key.split_whitespace().nth(1);
    let chosen = match blob {
        None => lines.next(),
        Some(blob) => lines.find(|line| line.split_whitespace().nth(1) == Some(blob)),
    }
    .ok_or(SignError::KeyUnavailable)?;

    let dir = tempfile::TempDir::new().map_err(|error| SignError::Failed(error.to_string()))?;
    let path = dir.path().join("key.pub");
    std::fs::write(&path, format!("{chosen}\n"))
        .map_err(|error| SignError::Failed(error.to_string()))?;
    Ok(KeyFile {
        _dir: Some(dir),
        path,
    })
}

// --- reading the armor ---------------------------------------------------

/// The issuer fingerprint (or key ID) an OpenPGP armor names.
fn pgp_issuer(armor: &str) -> Option<String> {
    let mut child = Command::new("gpg")
        .args(["--batch", "--list-packets"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // A failed write still has to be followed by a wait, or gpg is left
    // unreaped; the packets are then simply the ones gpg got.
    let mut stdin = child.stdin.take();
    if let Some(stdin) = stdin.as_mut() {
        let _ = stdin.write_all(armor.as_bytes());
    }
    // Dropping stdin ends gpg's input.
    drop(stdin);
    let packets = String::from_utf8_lossy(&child.wait_with_output().ok()?.stdout).into_owned();
    issuer_from_packets(&packets)
}

/// The issuer a `--list-packets` listing names.
///
/// The fingerprint is the exact key; v4 and v5 fingerprints both count, and the
/// key ID is the fallback for signatures from tools that write no fingerprint.
fn issuer_from_packets(packets: &str) -> Option<String> {
    packet_field(packets, "issuer fpr v4 ")
        .or_else(|| packet_field(packets, "issuer fpr v5 "))
        .or_else(|| packet_field(packets, "issuer key ID "))
}

/// The value after `label` on any packet line.
fn packet_field(packets: &str, label: &str) -> Option<String> {
    packets.lines().find_map(|line| {
        let (_, rest) = line.split_once(label)?;
        let value = rest.split_whitespace().next()?.trim_end_matches(')');
        (!value.is_empty()).then(|| value.to_owned())
    })
}

/// The public key an SSH signature blob embeds, as an `authorized_keys` line.
fn ssh_public_key(armor: &str) -> Option<String> {
    let body: String = armor
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let blob = BASE64.decode(body).ok()?;
    let rest = blob.strip_prefix(SSH_MAGIC)?;
    let (version, rest) = take_u32(rest)?;
    if version != 1 {
        return None;
    }
    let (key, _) = take_string(rest)?;
    let (kind, _) = take_string(key)?;
    Some(format!(
        "{} {}",
        std::str::from_utf8(kind).ok()?,
        BASE64.encode(key)
    ))
}

/// Split a 4-byte big-endian number off the front of `bytes`.
fn take_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (head, rest) = bytes.split_first_chunk::<4>()?;
    Some((u32::from_be_bytes(*head), rest))
}

/// Split an SSH `string`: a 4-byte length followed by that many bytes.
fn take_string(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = bytes.split_first_chunk::<4>()?;
    let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
    let (head, tail) = rest.split_at_checked(length)?;
    Some((head, tail))
}

// --- process plumbing ----------------------------------------------------

/// Run a signer with `input` on stdin and return its stdout on success.
fn run(command: &mut Command, input: &[u8]) -> Result<Vec<u8>, SignError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        // A missing program is not a missing key: the key was never tried.
        if error.kind() == std::io::ErrorKind::NotFound {
            SignError::Failed(format!(
                "{} could not be run: {error}",
                command.get_program().to_string_lossy()
            ))
        } else {
            SignError::Failed(error.to_string())
        }
    })?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(input)
        .map_err(|error| SignError::Failed(error.to_string()))?;
    // Closing stdin is the end-of-input signal; the pipe would otherwise be
    // held open and the signer would wait for more bytes forever.
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| SignError::Failed(error.to_string()))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    Err(classify(&output.stderr))
}

/// Turn a signer's stderr into the reason signing failed.
fn classify(stderr: &[u8]) -> SignError {
    let text = String::from_utf8_lossy(stderr);
    let lowered = text.to_lowercase();
    let says = |needles: &[&str]| needles.iter().any(|needle| lowered.contains(needle));

    if says(&["cancelled", "canceled", "pinentry"]) {
        SignError::Cancelled
    } else if says(&[
        "no secret key",
        "secret key not available",
        "no such file",
        "cannot open",
        "can't open",
    ]) {
        SignError::KeyUnavailable
    } else {
        SignError::Failed(text.trim().to_owned())
    }
}

/// Resolve a leading `~/` against `HOME`.
fn expand_tilde(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(rest),
            None => PathBuf::from(path),
        },
        None => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FPR: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

    #[test]
    fn an_issuer_fingerprint_is_read_from_a_v4_packet() {
        // The shape `gpg --list-packets` really prints.
        let packets = format!(
            ":signature packet: algo 1, keyid 89ABCDEF01234567\n\
             \thashed subpkt 33 len 21 (issuer fpr v4 {FPR})\n"
        );
        assert_eq!(issuer_from_packets(&packets).as_deref(), Some(FPR));
    }

    #[test]
    fn an_issuer_fingerprint_is_read_from_a_v5_packet() {
        let packets = format!(
            ":signature packet: algo 27, keyid 89ABCDEF01234567\n\
             \thashed subpkt 33 len 21 (issuer fpr v5 {FPR})\n"
        );
        assert_eq!(issuer_from_packets(&packets).as_deref(), Some(FPR));
    }

    #[test]
    fn the_key_id_is_the_fallback_without_a_fingerprint() {
        let packets = ":signature packet: algo 1, keyid 89ABCDEF01234567\n\
                       \tsubpkt 16 len 8 (issuer key ID 89ABCDEF01234567)\n";
        assert_eq!(
            issuer_from_packets(packets).as_deref(),
            Some("89ABCDEF01234567")
        );
    }

    #[test]
    fn a_listing_without_an_issuer_has_none() {
        assert_eq!(issuer_from_packets(":signature packet: algo 1\n"), None);
    }
}
