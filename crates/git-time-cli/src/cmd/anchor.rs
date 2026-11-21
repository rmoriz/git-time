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
//! its first root, then one line per root of the bundle. Both fields describe
//! that one certificate, so a bundle that names an intermediate first cannot
//! pair a root's date with the intermediate's fingerprint. A `notAfter` in the
//! past is a cheap stale signal; a chained bundle lists every root it holds, so
//! an appended one shows up as a second line. A bundle the store rejects is one
//! `  (bundle unreadable)` line instead of silently losing its roots. `--json`
//! carries the same fields for a machine reader, the roots as an array.
//!
//! `pin` writes `time.anchors-lock` in the repository root, one
//! `<id> <sha256-fingerprint>` line per root of every authority; `--check`
//! compares the current anchors against it and names every root that appeared or
//! disappeared. One line per root makes a rotation a pair of lines in the diff —
//! one `removed`, one `added` — instead of an in-place update of a value nobody
//! can review. The lock is a **review artifact, not a trust store**:
//! verification keeps judging tokens against the pinned bundles, so deleting the
//! lock changes no verdict. A changed bundle is still caught by verification
//! itself, one `UNTRUSTED` token at a time.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[cfg(test)]
use base64::Engine as _;
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Subcommand;
use git_time_core::repo::Repo;
use git_time_core::trust::AnchorStore;

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
    /// Record that a trust-on-first-use pin was compared out of band.
    Confirm {
        /// The TSA id the pin belongs to.
        id: String,
        /// The root that was compared. Defaults to every root in the bundle.
        fingerprint: Option<String>,
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
        Command::Confirm { id, fingerprint } => confirm(&repo, &id, fingerprint.as_deref()),
    }
}

/// Fetch `url` into `id`'s bundle, parsing before writing.
///
/// A root the preset publishes or one already pinned is taken without asking,
/// and only the chain material around it is updated. A root that is neither is a
/// rotation: it is refused with both values until `accept` names it, and is then
/// appended next to the retired root instead of replacing it. Nothing is written
/// on a refusal.
///
/// Both the comparison and the reported value are about roots: the bundle's
/// first certificate may be a signing leaf, and the pinned bundle plus the served
/// one are merged rather than overwritten, so a retired root survives a
/// generation change and the evidence naming it stays readable.
///
/// A first pin nothing could be checked against is marked (`time.tsa.<id>.tofu`)
/// until [`confirm`] records that a person compared it. A re-fetch of the same
/// root leaves the mark, because stability is not confirmation.
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
    // Whether a human named the root in this run. A confirmed root clears the
    // marker even when it is nothing new: the naming is the point.
    let accepted_named = accept.is_some();

    // The expectation a person stored when the section was written. A hand-edited
    // value that is not a fingerprint would compare as garbage, so it is refused
    // with the key named instead.
    let configured = match repo.config_non_empty(&format!("time.tsa.{id}.fingerprint")) {
        Ok(Some(value)) => match crate::cmd::tsa::validate_fingerprint(&value) {
            Ok(value) => Some(value),
            Err(reason) => {
                return Exit::config(format!(
                    "git time anchor: `time.tsa.{id}.fingerprint` holds {reason}"
                ));
            }
        },
        Ok(None) => None,
        Err(error) => return Exit::config(format!("git time anchor: {error}")),
    };

    // A preset's issuers belong to its bundle: without them a reply that stops
    // below the root (`cartaodecidadao`) could never be chained.
    let preset = git_time_core::presets::find(id);
    let chain: &[&str] = preset.map(|preset| preset.chain).unwrap_or_default();
    let published: &[&'static str] = preset.map(|preset| preset.fingerprints).unwrap_or_default();
    let bytes = match anchors::fetch_chain(url, chain).await {
        Ok(bytes) => bytes,
        Err(error) => return Exit::seal(format!("git time anchor: cannot fetch {url}: {error}")),
    };

    // The fingerprint every line reports is a **root**: a leaf first in the
    // bundle is not what the pin is checked against, so printing it would call a
    // leaf "the fetched root".
    let (sha256, expires, marked) = match super::accept::apply(
        id,
        &target,
        &bytes,
        published,
        &[],
        configured.as_deref(),
        accept.as_deref(),
        true,
    ) {
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
        super::accept::Applied::Appended {
            fingerprint: _,
            sha256,
            expires,
            added,
            roots,
        } => {
            println!("anchor {id}: {added} root(s) appended, {roots} now pinned");
            // An appended root was matched by something, so the pin is checked.
            (sha256, expires, Some(false))
        }
        super::accept::Applied::FirstPin {
            fingerprint,
            sha256,
            expires,
            accepted: false,
        } => {
            println!(
                "anchor {id}: no pinned root to compare (trust on first use); the fetched root is \
                 {} — compare it with the authority's own publication",
                super::accept::root_label(&fingerprint, expires.as_deref())
            );
            println!(
                "anchor {id}: then record the comparison: git time anchor confirm {id} {fingerprint}"
            );
            (sha256, expires, Some(true))
        }
        super::accept::Applied::FirstPin {
            fingerprint,
            sha256,
            expires,
            accepted: true,
        } => {
            println!(
                "anchor {id}: the accepted root {} was pinned; nothing was there to compare it \
                 with",
                super::accept::root_label(&fingerprint, expires.as_deref())
            );
            (sha256, expires, Some(false))
        }
        super::accept::Applied::Replaced {
            fingerprint: _,
            sha256,
            expires,
            matched,
        } => {
            if pinned_before {
                println!("anchor {id}: chain material updated");
            }
            // A match against a publication clears the marker, and so does an
            // accepted root; a re-fetch that only matched the root already
            // pinned says nothing new.
            (
                sha256,
                expires,
                if accepted_named {
                    Some(false)
                } else {
                    matched.map(|_| false)
                },
            )
        }
    };
    // Before the marker is written: it is itself a `time.tsa.<id>` key, and a
    // marked orphan is still an orphan.
    match anchors::section_exists(repo, id) {
        Ok(true) => {}
        Ok(false) => eprintln!(
            "rfc3161: warning: no `time.tsa.{id}` section exists yet; the bundle is an orphan \
             the policy will not read until `git time tsa add <url> --id {id}` (or an existing \
             section) points at it"
        ),
        Err(exit) => return exit,
    }
    if let Err(exit) = crate::cmd::tsa::mark_tofu(repo, id, marked) {
        return exit;
    }
    println!(
        "anchor {id}: {} sha256 {}",
        target.display(),
        super::accept::root_label(&sha256, expires.as_deref())
    );
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

/// One anchor as `anchor list` shows it.
struct Row {
    id: String,
    path: PathBuf,
    /// The fingerprint of the first root, when the bundle loads.
    fingerprint: Option<String>,
    /// Its `notAfter` as `YYYY-MM-DD`.
    not_after: Option<String>,
    /// Every root of the bundle, in file order.
    roots: Option<Vec<anchors::RootRow>>,
}

/// Record that the pin of `id` was compared with the authority's publication.
///
/// This is the whole point of the marker: the printed fingerprint of a
/// trust-on-first-use pin is only reviewable by a person, and until now nothing
/// recorded that the comparison happened. Nothing about trust changes — the
/// bundle already verifies — so the only work is reading what the pin holds,
/// naming it, and dropping the marker.
///
/// With a fingerprint the bundle must carry that root: a confirmation naming a
/// root nobody pinned would be a lie. The bare form confirms the whole bundle
/// and names every root, so the transcript says what was signed off. A pin that
/// was never marked is not an error, only worth saying.
fn confirm(repo: &Repo, id: &str, fingerprint: Option<&str>) -> Exit {
    if let Err(exit) = validate_id("anchor", id) {
        return exit;
    }
    let fingerprint = match fingerprint.map(crate::cmd::tsa::validate_fingerprint) {
        Some(Ok(fingerprint)) => Some(fingerprint),
        Some(Err(reason)) => return Exit::usage(format!("git time anchor: {reason}")),
        None => None,
    };
    let target = match anchors::target(repo, id) {
        Ok(target) => target,
        Err(exit) => return exit,
    };
    let Some(roots) = root_certificates(&target) else {
        return Exit::seal(format!(
            "git time anchor: no readable bundle at {}; pin it first with `git time anchor fetch`",
            target.display()
        ));
    };
    let confirmed: Vec<&Vec<u8>> = match &fingerprint {
        Some(value) => {
            let matching: Vec<&Vec<u8>> = roots
                .iter()
                .filter(|root| super::accept::matches(value, root))
                .collect();
            if matching.is_empty() {
                return Exit::seal(format!(
                    "git time anchor: `{value}` is not a root of {}; the marker was left alone",
                    target.display()
                ));
            }
            matching
        }
        None => roots.iter().collect(),
    };
    for root in &confirmed {
        println!(
            "anchor {id}: confirmed {} sha256 {}",
            git_time_core::trust::sha1_fingerprint(root),
            super::anchors::fingerprint(root)
        );
    }
    let marked = match repo.config_non_empty(&format!("time.tsa.{id}.tofu")) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => return Exit::config(format!("git time anchor: {error}")),
    };
    if let Err(exit) = crate::cmd::tsa::mark_tofu(repo, id, Some(false)) {
        return exit;
    }
    if marked {
        println!("anchor {id}: the pin is marked as compared");
    } else {
        println!("anchor {id}: the pin was not marked as unconfirmed; nothing to clear");
    }
    Exit::ok()
}

/// One line per configured anchor, or the same fields as JSON.
fn list(repo: &Repo, json: bool) -> Exit {
    let configured = match anchors::configured(repo) {
        Ok(configured) => configured,
        Err(exit) => return exit,
    };
    // A section may carry a `url` without an `anchor` key (hand-written or
    // half-migrated). The policy then refuses it as `Missing anchor`, but the
    // writers already fall back to the default path, so a bundle that was
    // fetched there is shown instead of being made invisible.
    let mut targets: BTreeMap<String, std::path::PathBuf> = BTreeMap::new();
    for id in anchors::tsa_ids(repo).unwrap_or_default() {
        targets.insert(id.clone(), anchors::dir().join(format!("{id}.pem")));
    }
    for anchor in &configured {
        targets.insert(anchor.id.clone(), anchor.path.clone());
    }
    // One instant for the whole listing: every date is judged as of one moment.
    let now = jiff::Timestamp::now();
    let rows: Vec<Row> = targets
        .iter()
        .map(|(id, path)| {
            let roots = anchors::roots(path);
            // Fingerprint and date come from the same certificate — the first
            // root — so a bundle that lists an intermediate first cannot show
            // the intermediate's fingerprint next to a root's date.
            let first = roots.as_ref().and_then(|roots| roots.first());
            Row {
                id: id.clone(),
                path: path.clone(),
                fingerprint: first.map(|root| root.fingerprint.clone()),
                not_after: first.map(|root| root.not_after.clone()),
                roots,
            }
        })
        .collect();

    if json {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                let roots: Vec<serde_json::Value> = row
                    .roots
                    .iter()
                    .flatten()
                    .map(|root| {
                        serde_json::json!({
                            "fingerprint": root.fingerprint,
                            "not_after": root.not_after,
                            "expired": anchors::expired(&root.not_after, now),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "id": row.id,
                    "path": row.path.to_string_lossy(),
                    "fingerprint": row.fingerprint,
                    "not_after": row.not_after,
                    "pinned": row.fingerprint.is_some(),
                    "roots": roots,
                })
            })
            .collect();
        match serde_json::to_string_pretty(&rows) {
            Ok(text) => println!("{text}"),
            Err(error) => return Exit::config(format!("cannot render JSON: {error}")),
        }
    } else {
        for row in &rows {
            let not_after = row.not_after.as_deref().unwrap_or("-");
            println!(
                "{} {} {} {} pinned:{}",
                row.id,
                row.path.display(),
                row.fingerprint.as_deref().unwrap_or("-"),
                anchors::expiry_text(not_after, now),
                row.fingerprint.is_some(),
            );
            for root in row.roots.iter().flatten() {
                println!(
                    "  root {} {}",
                    root.fingerprint,
                    anchors::expiry_text(&root.not_after, now),
                );
            }
            // A bundle that exists but that the store rejects pins nothing, so
            // the missing root lines would otherwise read as an empty bundle.
            if row.roots.is_none() && row.path.exists() {
                println!("  (bundle unreadable)");
            }
        }
    }
    Exit::ok()
}

/// Write the lock: one `<id> <fingerprint>` line per root, of every configured
/// authority.
///
/// The ids come from the `time.tsa.<id>.url` keys, not from the `anchor` keys, so
/// a section whose bundle resolves to the default path is locked like any other.
///
/// The lines are sorted by id and then fingerprint, so the order the bundle
/// happens to hold is not drift: a rotation keeps a retired root's line only
/// while the bundle still serves it, and adds the new one in its sorted place.
fn pin(repo: &Repo) -> Exit {
    let mut lines: Vec<(String, String)> = Vec::new();
    let mut problems = Vec::new();
    for id in match anchors::tsa_ids(repo) {
        Ok(ids) => ids,
        Err(exit) => return exit,
    } {
        let path = match anchors::target(repo, &id) {
            Ok(path) => path,
            Err(exit) => return exit,
        };
        match root_certificates(&path) {
            Some(roots) => {
                for der in roots {
                    lines.push((id.clone(), anchors::fingerprint(&der)));
                }
            }
            None => problems.push(id),
        }
    }
    if !problems.is_empty() {
        for id in &problems {
            eprintln!("git time anchor: no usable anchor for `{id}`");
        }
        return Exit::seal(String::new());
    }
    lines.sort();

    let lock = repo.path().join(LOCK);
    let mut body = String::new();
    for (id, fingerprint) in &lines {
        body.push_str(id);
        body.push(' ');
        body.push_str(fingerprint);
        body.push('\n');
    }
    if let Err(error) = std::fs::write(&lock, body) {
        return Exit::config(format!("cannot write {}: {error}", lock.display()));
    }
    println!("pinned {} root(s) in {LOCK}", lines.len());
    Exit::ok()
}

/// Compare the roots of the anchors against the lock.
///
/// Both sides are sets of `(id, fingerprint)`, so a root the bundle gained is
/// `added` and one it lost is `removed`; order is not part of it. A line the lock
/// formats unusably, and a locked bundle that no longer parses, keep the
/// existing `unparseable` wording, and an id with no bundle at all is `missing`.
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
    let mut recorded: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // A line with an id but no fingerprint: the id is named, the value is not.
    let mut unparseable: BTreeSet<String> = BTreeSet::new();
    for line in body.lines() {
        // Indentation and trailing blanks belong to neither field.
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match line.split_once(' ') {
            Some((id, fingerprint)) if !fingerprint.trim().is_empty() => {
                recorded
                    .entry(id.trim().to_owned())
                    .or_default()
                    .insert(fingerprint.trim().to_owned());
            }
            Some((id, _)) => {
                unparseable.insert(id.trim().to_owned());
            }
            None => {
                unparseable.insert(line.to_owned());
            }
        }
    }

    // A bundle that does not load is no expectation at all: the id is
    // unparseable, exactly as a broken lock line. Every configured id is
    // resolved, url-only sections through their default path, so a lock line for
    // a bundle that is in use is never reported missing.
    let mut current: BTreeMap<String, Option<BTreeSet<String>>> = BTreeMap::new();
    for id in match anchors::tsa_ids(repo) {
        Ok(ids) => ids,
        Err(exit) => return exit,
    } {
        let path = match anchors::target(repo, &id) {
            Ok(path) => path,
            Err(exit) => return exit,
        };
        let fingerprints = root_certificates(&path)
            .map(|roots| roots.iter().map(|der| anchors::fingerprint(der)).collect());
        current.insert(id, fingerprints);
    }

    let mut drift = Vec::new();
    for (id, fingerprints) in &recorded {
        if unparseable.contains(id) {
            drift.push(format!("mismatch {id}: anchor is unparseable"));
            continue;
        }
        match current.get(id) {
            None => drift.push(format!("mismatch {id}: anchor is missing")),
            Some(None) => drift.push(format!("mismatch {id}: anchor is unparseable")),
            Some(Some(now)) => {
                for fingerprint in now.difference(fingerprints) {
                    drift.push(format!("added {id} {fingerprint}"));
                }
                for fingerprint in fingerprints.difference(now) {
                    drift.push(format!("removed {id} {fingerprint}"));
                }
            }
        }
    }
    for id in &unparseable {
        if !recorded.contains_key(id) {
            drift.push(format!("mismatch {id}: anchor is unparseable"));
        }
    }
    for (id, fingerprints) in &current {
        if recorded.contains_key(id) || unparseable.contains(id) {
            continue;
        }
        match fingerprints {
            Some(fingerprints) => {
                for fingerprint in fingerprints {
                    drift.push(format!("added {id} {fingerprint}"));
                }
            }
            None => drift.push(format!("mismatch {id}: anchor is unparseable")),
        }
    }

    if drift.is_empty() {
        println!("anchors match the lock");
        return Exit::ok();
    }
    for line in &drift {
        eprintln!("{line}");
    }
    Exit::seal(String::new())
}

/// The DER of every root in the bundle at `path`, when the bundle loads.
///
/// A bundle only counts when [`AnchorStore`] accepts it whole, so a broken or
/// root-less bundle is `None` rather than an empty list. Intermediates are not
/// roots and stay out of the lock.
pub(crate) fn root_certificates(path: &Path) -> Option<Vec<Vec<u8>>> {
    let mut store = AnchorStore::default();
    store.insert("bundle", path).ok()?;
    let roots = store.anchor("bundle")?;
    Some(
        roots
            .roots
            .iter()
            .map(|root| root.as_bytes().to_vec())
            .collect(),
    )
}

/// The DER of the first PEM certificate in `pem`.
///
/// The writer paths fingerprint whole bundles, so only the tests still need the
/// first certificate.
#[cfg(test)]
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
