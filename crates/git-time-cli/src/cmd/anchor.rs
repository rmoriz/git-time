//! `git time anchor`: fetch anchor bundles, list them, and pin their digests.
//!
//! `fetch` downloads a PEM bundle, parses it into certificates **before**
//! touching the target, and only then replaces it. The target is the configured
//! `time.tsa.<id>.anchor` path when there is one and `anchors::dir()/<id>.pem`
//! otherwise, so the file that gets the fingerprint is the file the policy
//! reads. A failed or unparseable fetch leaves an existing bundle byte for
//! byte; only when nothing was pinned before are the bad bytes kept, so
//! `tsa list` and doctor can name them as unusable instead of as never fetched.
//!
//! `list` names each configured anchor with the fingerprint and `notAfter` of
//! its first certificate. The first certificate is the trust anchor, so a
//! `notAfter` in the past is a cheap stale signal. `--json` carries the same
//! fields for a machine reader.
//!
//! `pin` writes `time.anchors-lock` in the repository root, one
//! `<id> <sha256-fingerprint>` line per authority; `--check` compares the current
//! anchors against it and names every id that changed. The lock is a **review
//! artifact, not a trust store**: verification keeps judging tokens against the
//! pinned bundles, so deleting the lock changes no verdict. A changed bundle is
//! still caught by verification itself, one `UNTRUSTED` token at a time.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Subcommand;
use der::Decode;
use git_time_core::repo::Repo;
use x509_cert::Certificate;

use crate::cmd::{Exit, anchors, open, tsa::validate_id};

/// The subcommands of `git time anchor`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Download and pin one authority's PEM bundle.
    Fetch {
        /// The bundle URL.
        url: String,
        /// The TSA id the bundle belongs to.
        #[arg(long, value_name = "ID")]
        id: String,
        /// Accept a plain `http://` URL.
        #[arg(long)]
        insecure_http: bool,
        /// Append a root that is not the pinned one, by its fingerprint.
        #[arg(long, value_name = "FINGERPRINT")]
        accept: Option<String>,
    },
    /// List the configured anchors with their fingerprint and expiry.
    List {
        /// Print the listing as one JSON array.
        #[arg(long)]
        json: bool,
    },
    /// Record every anchor's fingerprint, or check it against the record.
    Pin {
        /// Compare the anchors against the lock instead of writing it.
        #[arg(long)]
        check: bool,
    },
}

/// The name of the lock file, in the repository root.
const LOCK: &str = "time.anchors-lock";

/// Run one `git time anchor` subcommand.
pub async fn run(directory: Option<PathBuf>, command: Command) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    match command {
        Command::Fetch {
            url,
            id,
            insecure_http,
            accept,
        } => fetch(&repo, &url, &id, insecure_http, accept.as_deref()).await,
        Command::List { json } => list(&repo, json),
        Command::Pin { check: against } => {
            if against {
                check(&repo)
            } else {
                pin(&repo)
            }
        }
    }
}

/// Fetch `url` into `id`'s bundle, parsing before writing.
///
/// A root the preset publishes or one already pinned is taken without asking,
/// and only the chain material around it is updated. A root that is neither is a
/// rotation: it is refused with both values until `accept` names it, and is then
/// appended next to the retired root instead of replacing it. Nothing is written
/// on a refusal.
async fn fetch(
    repo: &Repo,
    url: &str,
    id: &str,
    insecure_http: bool,
    accept: Option<&str>,
) -> Exit {
    if let Err(exit) = validate_id("anchor", id) {
        return exit;
    }
    if let Err(exit) = crate::cmd::tsa::validate_url("anchor", url, insecure_http) {
        return exit;
    }
    // The fetch is for one id, so a bare fingerprint is the intended spelling; an
    // id that names another authority is a typo worth refusing.
    let accept = match accept.map(super::accept::parse).transpose() {
        Ok(Some((named, fingerprint))) if named.is_empty() || named == id => Some(fingerprint),
        Ok(Some((named, _))) => {
            return Exit::usage(format!(
                "git time anchor: `--accept` names `{named}`, but the fetch is for `{id}`"
            ));
        }
        Ok(None) => None,
        Err(error) => return Exit::usage(format!("git time anchor: {error}")),
    };
    let target = match anchors::target(repo, id) {
        Ok(target) => target,
        Err(exit) => return exit,
    };
    if let Some(parent) = target.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Exit::config(format!(
            "cannot create the anchors directory {}: {error}",
            parent.display()
        ));
    }
    let pinned_before = target.exists();

    // A preset's issuers belong to its bundle: without them a reply that stops
    // below the root (`cartaodecidadao`) could never be chained.
    let preset = git_time_core::presets::find(id);
    let chain: &[&str] = preset.map(|preset| preset.chain).unwrap_or_default();
    let published: &[&'static str] = preset.map(|preset| preset.fingerprints).unwrap_or_default();
    let bytes = match anchors::fetch_chain(url, chain).await {
        Ok(bytes) => bytes,
        Err(error) => return Exit::seal(format!("git time anchor: cannot fetch {url}: {error}")),
    };

    let Some(der) = first_certificate(&bytes) else {
        // `apply` keeps the bad bytes when nothing was pinned, so doctor can
        // name them as unusable instead of as never fetched.
        return match super::accept::apply(
            id,
            &target,
            &bytes,
            published,
            &[],
            accept.as_deref(),
            true,
        ) {
            super::accept::Applied::Unusable(reason) => Exit::seal(format!(
                "git time anchor: the bundle from {url} is unusable: {reason}"
            )),
            _ => Exit::seal(format!("git time anchor: {url} carried no certificate")),
        };
    };
    let shown = anchors::fingerprint(&der);

    match super::accept::apply(id, &target, &bytes, published, &[], accept.as_deref(), true) {
        super::accept::Applied::Unusable(reason) => {
            return Exit::seal(format!(
                "git time anchor: the bundle from {url} is unusable: {reason}"
            ));
        }
        super::accept::Applied::Mismatch { expected, found } => {
            eprintln!(
                "git time anchor: the root fetched for `{id}` from {url} does not match: \
                 expected {expected}, got {found}; the bundle was not pinned and the existing \
                 anchor is untouched"
            );
            eprintln!(
                "git time anchor: pass `--accept {found}` to append it next to the pinned root"
            );
            return Exit::seal(String::new());
        }
        super::accept::Applied::Appended { added, roots, .. } => {
            println!("anchor {id}: {added} root(s) appended, {roots} now pinned");
        }
        super::accept::Applied::FirstPin { fingerprint } => {
            println!(
                "anchor {id}: no pinned root to compare (trust on first use); the fetched root is \
                 {fingerprint} — compare it with the authority's own publication"
            );
        }
        super::accept::Applied::Replaced { .. } => {
            if pinned_before {
                println!("anchor {id}: chain material updated");
            }
        }
    }
    println!("anchor {id}: {} sha256 {shown}", target.display());
    match anchors::section_exists(repo, id) {
        Ok(true) => {}
        Ok(false) => eprintln!(
            "rfc3161: warning: no `time.tsa.{id}` section exists yet; the bundle is an orphan \
             the policy will not read until `git time tsa add <url> --id {id}` (or an existing \
             section) points at it"
        ),
        Err(exit) => return exit,
    }
    Exit::ok()
}

/// The sibling path a fetch is staged at before it replaces the target.
pub(crate) fn staging_path(target: &Path) -> PathBuf {
    target.with_extension("pem.new")
}

/// Keep an unparseable bundle only when nothing was pinned before.
pub(crate) fn keep_unparsed(staging: &Path, target: &Path) {
    if target.exists() {
        let _ = std::fs::remove_file(staging);
    } else {
        let _ = std::fs::rename(staging, target);
    }
}

/// One line per configured anchor, or the same fields as JSON.
fn list(repo: &Repo, json: bool) -> Exit {
    let configured = match anchors::configured(repo) {
        Ok(configured) => configured,
        Err(exit) => return exit,
    };
    let rows: Vec<(&str, &Path, Option<String>, Option<String>)> = configured
        .iter()
        .map(|anchor| {
            let certificate = first_certificate_at(&anchor.path).and_then(|der| {
                let certificate = Certificate::from_der(&der).ok()?;
                Some((anchors::fingerprint(&der), certificate))
            });
            match certificate {
                Some((fingerprint, certificate)) => (
                    anchor.id.as_str(),
                    anchor.path.as_path(),
                    Some(fingerprint),
                    Some(certificate.tbs_certificate.validity.not_after.to_string()),
                ),
                None => (anchor.id.as_str(), anchor.path.as_path(), None, None),
            }
        })
        .collect();

    if json {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(id, path, fingerprint, not_after)| {
                serde_json::json!({
                    "id": id,
                    "path": path.to_string_lossy(),
                    "fingerprint": fingerprint,
                    "not_after": not_after,
                    "pinned": fingerprint.is_some(),
                })
            })
            .collect();
        match serde_json::to_string_pretty(&rows) {
            Ok(text) => println!("{text}"),
            Err(error) => return Exit::config(format!("cannot render JSON: {error}")),
        }
    } else {
        for (id, path, fingerprint, not_after) in &rows {
            println!(
                "{id} {} {} {} pinned:{}",
                path.display(),
                fingerprint.as_deref().unwrap_or("-"),
                not_after.as_deref().unwrap_or("-"),
                fingerprint.is_some(),
            );
        }
    }
    Exit::ok()
}

/// Write the lock: one `<id> <fingerprint>` line per configured authority.
fn pin(repo: &Repo) -> Exit {
    let mut lines = Vec::new();
    let mut problems = Vec::new();
    for anchor in match anchors::configured(repo) {
        Ok(configured) => configured,
        Err(exit) => return exit,
    } {
        match first_certificate_at(&anchor.path) {
            Some(der) => lines.push(format!("{} {}", anchor.id, anchors::fingerprint(&der))),
            None => problems.push(anchor.id),
        }
    }
    if !problems.is_empty() {
        for id in &problems {
            eprintln!("git time anchor: no usable anchor for `{id}`");
        }
        return Exit::seal(String::new());
    }

    let lock = repo.path().join(LOCK);
    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    if let Err(error) = std::fs::write(&lock, body) {
        return Exit::config(format!("cannot write {}: {error}", lock.display()));
    }
    println!("pinned {} anchor(s) in {LOCK}", lines.len());
    Exit::ok()
}

/// Compare the anchors against the lock and name every mismatch.
fn check(repo: &Repo) -> Exit {
    let lock = repo.path().join(LOCK);
    let body = match std::fs::read_to_string(&lock) {
        Ok(body) => body,
        Err(error) => {
            return Exit::seal(format!(
                "git time anchor: cannot read {}: {error}; run `git time anchor pin` first",
                lock.display()
            ));
        }
    };
    let recorded: BTreeMap<String, String> = body
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(id, fingerprint)| (id.to_owned(), fingerprint.trim().to_owned()))
        .collect();

    let mut current = BTreeMap::new();
    for anchor in match anchors::configured(repo) {
        Ok(configured) => configured,
        Err(exit) => return exit,
    } {
        // `first_certificate_at` parses the bytes as a certificate, exactly as
        // `pin` does, so base64 garbage is "unparseable" rather than "changed".
        let fingerprint = first_certificate_at(&anchor.path).map(|der| anchors::fingerprint(&der));
        current.insert(anchor.id, fingerprint);
    }

    let mut mismatches = Vec::new();
    for (id, fingerprint) in &recorded {
        match current.get(id.as_str()) {
            None => mismatches.push(format!("mismatch {id}: anchor is missing")),
            Some(None) => mismatches.push(format!("mismatch {id}: anchor is unparseable")),
            Some(Some(now)) if now != fingerprint => {
                mismatches.push(format!("mismatch {id}: anchor changed"));
            }
            Some(Some(_)) => {}
        }
    }
    for id in current.keys() {
        if !recorded.contains_key(id.as_str()) {
            mismatches.push(format!("mismatch {id}: not in the lock"));
        }
    }

    if mismatches.is_empty() {
        println!("anchors match the lock");
        return Exit::ok();
    }
    for mismatch in &mismatches {
        eprintln!("{mismatch}");
    }
    Exit::seal(String::new())
}

/// The DER of `path`'s first certificate, when it parses as one.
///
/// Shared with `tsa list`, so both listings name the same fingerprint.
pub(crate) fn first_certificate_at(path: &Path) -> Option<Vec<u8>> {
    let bytes = std::fs::read(path).ok()?;
    let der = first_certificate(&bytes)?;
    Certificate::from_der(&der).ok()?;
    Some(der)
}

/// The DER of the first PEM certificate in `pem`.
///
/// Shared with `install`, so both writer paths fingerprint the same bytes.
pub(crate) fn first_certificate(pem: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            inside = true;
            body.clear();
            continue;
        }
        if line == "-----END CERTIFICATE-----" {
            if inside {
                return BASE64.decode(body.as_bytes()).ok();
            }
            continue;
        }
        if inside {
            body.push_str(line);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_certificate_is_taken_and_junk_is_not() {
        let first = BASE64.encode(b"one");
        let second = BASE64.encode(b"two");
        let pem = format!(
            "prose\n-----BEGIN CERTIFICATE-----\n{first}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\n{second}\n-----END CERTIFICATE-----\n"
        );
        assert_eq!(first_certificate(pem.as_bytes()), Some(b"one".to_vec()));
        assert_eq!(first_certificate(b"no certificate here"), None);
        assert_eq!(
            first_certificate(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"),
            None
        );
    }

    #[test]
    fn staging_keeps_the_pem_stem() {
        let target = Path::new("/tmp/anchors/a.pem");
        assert_eq!(staging_path(target), Path::new("/tmp/anchors/a.pem.new"));
    }
}
