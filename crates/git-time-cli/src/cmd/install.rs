//! `git time install`: wire the hooks and pin authorities.
//!
//! What is always wired are the two hooks a commit actually needs: `post-commit`
//! for an ordinary commit and `post-merge` for a merge, which never runs
//! `post-commit`. `pre-commit` and `pre-merge-commit` are wired only under
//! `time.gate = pre-commit`, so a repository that does not want the hard gate
//! carries no extra hook.
//!
//! A foreign hook at any of those names is not overwritten: it is renamed next to
//! the shim as `<name>.pre-time` — or the next free `<name>.pre-time.<n>` when a
//! husky or pre-commit-framework run regenerated the hook since the last install
//! — and the shim runs it first, propagating its failure. The summary names every
//! preserve, so a user can see both originals survive. The hooks directory is the
//! one `git rev-parse --git-path hooks` answers, so a `core.hooksPath` from husky
//! or the pre-commit framework is where the shims land — not `.git/hooks`, which
//! those tools never run.
//!
//! `install` wires the hooks. The authority set belongs to the repository, not
//! to a flag: a repository that already has `time.tsa.*` keys keeps them
//! exactly as they are, and an empty one hands over to `tsa select` on a
//! terminal so `git time install` alone still ends in a working setup. A fetch
//! that fails only warns: the hooks are still worth wiring, and `doctor` names
//! the missing bundle. A configured authority whose anchor is gone is pinned
//! again when it is a preset. When the failure leaves an anchor path missing under the
//! gate, the summary says loudly that commits will be refused. A fetched bundle
//! is parsed into certificates before it replaces the pinned one, so prose
//! cannot masquerade as an anchor. `--no-tsa` writes no authority at all.

use std::collections::BTreeMap;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use git_time_core::presets;
use git_time_core::presets::Preset as Authority;
use git_time_core::repo::Repo;

use crate::cmd::{Exit, anchors, git_stdout, hooks, open};

/// What pinning one authority came to.
pub(crate) struct Pinned {
    /// The config id.
    pub(crate) id: &'static str,
    /// How many of its config keys were already set and left alone.
    pub(crate) kept: usize,
    /// Where its anchor is expected, and whether that path is now missing.
    pub(crate) missing_anchor: Option<PathBuf>,
    /// Whether the fetched root was not one of the fingerprints the preset
    /// publishes, so the bundle was left unpinned.
    pub(crate) fingerprint_mismatch: bool,
    /// Whether the fetch brought back something that is not a bundle, so
    /// whatever was pinned before is still the anchor.
    pub(crate) unusable: bool,
}

/// The environment `install` reads its `--accept` values from, resolved.
///
/// Run `git time install`.
pub async fn run(directory: Option<std::path::PathBuf>, no_tsa: bool, accept: &[String]) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    let dir = match hooks::hooks_dir(&repo) {
        Ok(dir) => dir,
        Err(exit) => return exit,
    };
    let created = !dir.exists();
    if let Err(error) = std::fs::create_dir_all(&dir) {
        return Exit::config(format!(
            "cannot create the hooks directory {}: {error}",
            dir.display()
        ));
    }

    let gated = match gate(&repo) {
        Ok(gated) => gated,
        Err(exit) => return exit,
    };
    let wired = if gated {
        hooks::ALL_HOOKS.to_vec()
    } else {
        hooks::POST_HOOKS.to_vec()
    };

    let mut preserved = Vec::new();
    for name in &wired {
        match hooks::wire(&dir, name) {
            Ok(Some(chained)) => preserved.push(format!("{name} -> {chained}")),
            Ok(None) => {}
            Err(exit) => return exit,
        }
    }

    // The wiring is done, so say so before anything can take over the screen.
    if crate::cmd::doctor::binary_on_path().is_none() {
        eprintln!(
            "rfc3161: warning: git-time is not on PATH; the hooks will do nothing until it is"
        );
    }
    println!(
        "hooks dir: {}{}",
        dir.display(),
        if created { " (created)" } else { "" }
    );
    println!("wired: {}", wired.join(", "));
    if !preserved.is_empty() {
        println!("preserved: {}", preserved.join(", "));
    }

    // The authority set is the repository's, not the command line's: a
    // configured repository keeps what it has, and an empty one hands over to
    // the selector so `git time install` alone still ends in a working setup.
    let keep = !no_tsa && anchors::any_section(&repo).unwrap_or(false);
    let authorities: Vec<&Authority> = if no_tsa || keep {
        Vec::new()
    } else if std::io::stdin().is_terminal() {
        return crate::cmd::tsa::select(&repo, accept, "git time install", true, false).await;
    } else {
        return Exit::usage(
            "git time install: no authority is configured and stdin is not a terminal; use `git \
             time tsa select`, `git time tsa preset add <id>`, or `git time tsa add <url>`",
        );
    };
    let mut kept = 0_usize;
    let mut pinned_again = 0_usize;
    let mut unpinned: Vec<(String, PathBuf)> = Vec::new();
    let mut mismatched = 0_usize;
    // A bare `--accept` carries no id, so it can only be read against the ids
    // actually in play: what is configured is as much in play as what is being
    // written. Several distinct ids make a bare value a usage error that names
    // them all.
    let mut in_play: Vec<String> = anchors::configured(&repo)
        .unwrap_or_default()
        .into_iter()
        .map(|anchor| anchor.id)
        .collect();
    for authority in &authorities {
        if !in_play.iter().any(|id| id == authority.name) {
            in_play.push(authority.name.to_owned());
        }
    }
    let in_play: Vec<&str> = in_play.iter().map(String::as_str).collect();
    let accept = match crate::cmd::accept::one_or_id(accept, &in_play) {
        Ok(accept) => accept,
        Err(error) => return Exit::usage(format!("git time install: {error}")),
    };
    let none = std::collections::BTreeMap::new();
    // What is already configured is not fetched again, but it is still checked:
    // an anchor path that does not load is exactly what doctor would name. A
    // configured id whose bundle is gone — a moved home directory, a deleted
    // anchors directory — is pinned again when it is a preset, because the
    // published root makes that fetch checkable and a repository that names an
    // authority in its evidence should be able to verify it here.
    if keep {
        for anchor in anchors::configured(&repo).unwrap_or_default() {
            if anchor.path.exists() && crate::cmd::tsa::pinned(&anchor.id, &anchor.path) {
                continue;
            }
            let Some(preset) = presets::find(&anchor.id) else {
                unpinned.push((anchor.id, anchor.path));
                continue;
            };
            match pin(&repo, preset, &accept, &none, "git time install").await {
                Ok(pinned) if pinned.fingerprint_mismatch => mismatched += 1,
                Ok(pinned) => match pinned.missing_anchor {
                    Some(path) => unpinned.push((pinned.id.to_owned(), path)),
                    None => pinned_again += 1,
                },
                Err(_) => unpinned.push((anchor.id, anchor.path)),
            }
        }
    }
    for authority in &authorities {
        match pin(&repo, authority, &accept, &none, "git time install").await {
            Ok(pinned) => {
                kept += pinned.kept;
                // A mismatch already said its loud line naming both values; the
                // generic "no anchor" warning would only repeat the tail of it.
                if pinned.fingerprint_mismatch {
                    mismatched += 1;
                } else if let Some(path) = pinned.missing_anchor {
                    unpinned.push((pinned.id.to_owned(), path));
                }
            }
            Err(exit) => return exit,
        }
    }

    if no_tsa {
        println!("tsa: none configured (--no-tsa)");
    } else if keep {
        let existing = anchors::configured(&repo).map_or(0, |anchors| anchors.len());
        println!(
            "tsa: {existing} existing authority(ies) kept{}",
            if pinned_again > 0 {
                format!(" ({pinned_again} anchor(s) pinned again)")
            } else {
                String::new()
            }
        );
    } else {
        println!(
            "tsa: {} configured{}",
            authorities.len(),
            if kept > 0 {
                format!(" ({kept} existing key(s) kept)")
            } else {
                String::new()
            }
        );
    }
    if mismatched > 0 {
        println!(
            "tsa: {mismatched} root fingerprint(s) did not match; the bundle(s) were not pinned"
        );
    }
    for (id, path) in &unpinned {
        if gated {
            eprintln!(
                "rfc3161: warning: no anchor for `{id}` at {}; with time.gate = pre-commit every \
                 commit will be refused until it is pinned (run: git time install once the fetch works)",
                path.display()
            );
        } else {
            eprintln!(
                "rfc3161: warning: no anchor for `{id}` at {}; tokens of that authority cannot be \
                 verified until it is pinned",
                path.display()
            );
        }
    }
    Exit::ok()
}

/// Write the config of `authority` that is not set yet, and try to pin its
/// anchor.
///
/// A key that is already set is left alone, so a working configuration is not
/// clobbered. The config is written even when the fetch fails, so the authority
/// is listed and `doctor` can report the missing anchor instead of the entry
/// vanishing.
///
/// The anchor lands where the policy will read it: an already configured
/// `time.tsa.<id>.anchor` path wins over the default
/// `$XDG_CONFIG_HOME/git-time/anchors/<id>.pem`, because a freshly fetched
/// bundle the policy never looks at would print a fingerprint of the wrong file.
///
/// `accept` carries the fingerprints a human confirmed, `named` the roots a
/// trailer block names for the id; both are keyed by id and empty on the paths
/// that have neither. `command` is how the caller is invoked, for the line that
/// tells a reader how to accept a refused root — not every caller has the flag.
pub(crate) async fn pin(
    repo: &Repo,
    authority: &Authority,
    accept: &BTreeMap<String, String>,
    named: &BTreeMap<String, Vec<String>>,
    command: &str,
) -> Result<Pinned, Exit> {
    let base = format!("time.tsa.{}", authority.name);
    // Read before writing: the key may be set already and is then the target.
    let configured = anchors::configured(repo)?
        .into_iter()
        .find(|anchor| anchor.id == authority.name)
        .map(|anchor| anchor.path);
    let path = match configured {
        Some(path) => path,
        None => anchors::dir().join(format!("{}.pem", authority.name)),
    };
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Err(Exit::config(format!(
            "cannot create the anchors directory {}: {error}",
            parent.display()
        )));
    }
    let anchor_path = path.to_string_lossy().into_owned();
    let mut fields = vec![
        ("url", authority.url.to_owned()),
        ("alg", authority.alg.to_owned()),
        ("anchor", anchor_path),
    ];
    if let Some(policy) = authority.policy {
        fields.push(("policy", policy.to_owned()));
    }
    if authority.insecure_http {
        fields.push(("insecure-http", "true".to_owned()));
    }
    let mut kept = 0_usize;
    for (field, value) in fields {
        if set(repo, &format!("{base}.{field}"), &value)? {
            kept += 1;
        }
    }

    let mut fingerprint_mismatch = false;
    let mut unusable = false;
    let mut missing_anchor = None;
    let named_roots: &[String] = named
        .get(authority.name)
        .map(Vec::as_slice)
        .unwrap_or_default();
    match anchors::fetch_chain(authority.anchor_url, authority.chain).await {
        Ok(bytes) => match install_anchor(
            authority,
            &path,
            &bytes,
            named_roots,
            accept.get(authority.name).map(String::as_str),
        ) {
            crate::cmd::accept::Applied::Replaced {
                matched: Some(expected),
                fingerprint,
                sha256: _,
                expires,
            } => {
                // A pinned root is only worth something when the match is
                // visible: the reader has to be able to see that the fetch was
                // checked, not just that a file appeared. The line names the
                // published value that matched, so a rotation is visible too.
                println!("{}: root fingerprint matches {expected}", authority.name);
                println!(
                    "anchor {}: {} fingerprint {}",
                    authority.name,
                    path.display(),
                    crate::cmd::accept::root_label(&fingerprint, expires.as_deref())
                );
            }
            crate::cmd::accept::Applied::Replaced {
                matched: None,
                fingerprint,
                sha256: _,
                expires,
            } => {
                // A root the block named, or one already pinned (a rotation a
                // human accepted earlier): the bundle is the same root with new
                // chain material.
                println!("anchor {}: chain material updated", authority.name);
                println!(
                    "anchor {}: {} fingerprint {}",
                    authority.name,
                    path.display(),
                    crate::cmd::accept::root_label(&fingerprint, expires.as_deref())
                );
            }
            crate::cmd::accept::Applied::Appended {
                fingerprint,
                sha256: _,
                expires,
                added,
                roots,
            } => {
                println!(
                    "anchor {}: {added} root(s) appended, {roots} now pinned",
                    authority.name
                );
                println!(
                    "anchor {}: {} fingerprint {}",
                    authority.name,
                    path.display(),
                    crate::cmd::accept::root_label(&fingerprint, expires.as_deref())
                );
            }
            crate::cmd::accept::Applied::FirstPin {
                fingerprint,
                sha256: _,
                expires,
                accepted: false,
            } => {
                // Trust on first use: the printed value is the only thing that
                // makes the first pin reviewable, so it is said loudly and in
                // full.
                println!(
                    "{}: no published root fingerprint (trust on first use); the fetched root is \
                     {} — compare it with the authority's own publication",
                    authority.name,
                    crate::cmd::accept::root_label(&fingerprint, expires.as_deref())
                );
                println!(
                    "anchor {}: {} fingerprint {}",
                    authority.name,
                    path.display(),
                    crate::cmd::accept::root_label(&fingerprint, expires.as_deref())
                );
            }
            crate::cmd::accept::Applied::FirstPin {
                fingerprint,
                sha256: _,
                expires,
                accepted: true,
            } => {
                // The accept overrode a published value that did not match.
                println!(
                    "{}: the accepted root {} was pinned, overriding the published fingerprint",
                    authority.name,
                    crate::cmd::accept::root_label(&fingerprint, expires.as_deref())
                );
                // The fingerprint of the root the pin is about, the same value
                // `anchor list` and the lock carry, not of the whole file: a
                // bundle may append chain certificates and would otherwise get
                // two hashes.
                println!(
                    "anchor {}: {} fingerprint {}",
                    authority.name,
                    path.display(),
                    crate::cmd::accept::root_label(&fingerprint, expires.as_deref())
                );
            }
            crate::cmd::accept::Applied::Mismatch { expected, found } => {
                fingerprint_mismatch = true;
                // Loud, and both values spelled out: this is the one case where
                // the fetched bundle is thrown away although it is well formed.
                eprintln!(
                    "rfc3161: warning: the root fetched for `{}` from {} does not match: \
                     expected {expected}, got {found}; the bundle was not pinned{}",
                    authority.name,
                    authority.anchor_url,
                    if path.exists() {
                        " and the existing anchor is untouched"
                    } else {
                        ""
                    }
                );
                eprintln!(
                    "rfc3161: warning: tsa {}: pass `{} --accept {}={found}` to {}",
                    authority.name,
                    command,
                    authority.name,
                    if path.exists() {
                        "append it next to the pinned root"
                    } else {
                        "pin it"
                    }
                );
            }
            crate::cmd::accept::Applied::Unusable(reason) => {
                unusable = true;
                eprintln!(
                    "rfc3161: warning: the anchor of `{}` from {} is unusable: {reason}",
                    authority.name, authority.anchor_url
                );
            }
        },
        Err(error) => eprintln!(
            "rfc3161: warning: cannot fetch the anchor of `{}` from {}: {error}",
            authority.name, authority.anchor_url
        ),
    }
    if !path.exists() {
        missing_anchor = Some(path);
    }
    Ok(Pinned {
        id: authority.name,
        kept,
        missing_anchor,
        fingerprint_mismatch,
        unusable,
    })
}

/// The digest of `der` in the length the expectation is written in.
///
/// SHA-1 (20 octets) and SHA-256 (32) are both published by authorities and both
/// pinned; taking the length from the expectation keeps a mismatched spelling a
/// mismatch instead of silently comparing the wrong digest — and makes a printed
/// value comparable with the line above it. Without an expectation (trust on
/// first use) it is SHA-1, because that printed value is the only artefact a
/// human gets to check.
pub(crate) fn digest_for(expected: Option<&str>, der: &[u8]) -> String {
    match expected {
        Some(expected) if expected.split(':').count() != 20 => {
            git_time_core::trust::fingerprint(der)
        }
        _ => git_time_core::trust::sha1_fingerprint(der),
    }
}

/// The digest of `der` in the length `expected` is written in.
///
/// Each published value is compared in its own length, so a preset may carry
/// both a SHA-1 and a SHA-256 spelling of one root. See [`digest_for`].
pub fn matching_digest(expected: &str, der: &[u8]) -> String {
    digest_for(Some(expected), der)
}

/// The published fingerprint in `fingerprints` that `der` carries.
///
/// Returns the value that matched — not the computed digest — so a success line
/// names what the preset actually published, and the newest value can stay last
/// without every line naming it. An empty list (trust on first use) and a root
/// no value describes both answer `None`: the caller decides the TOFU path, and
/// an unmatched non-empty list stays a refusal.
pub fn fingerprint_matches(fingerprints: &[&'static str], der: &[u8]) -> Option<&'static str> {
    fingerprints
        .iter()
        .find(|expected| matching_digest(expected, der).eq_ignore_ascii_case(expected))
        .copied()
}

/// Parse `bytes` as `authority`'s bundle before it may replace what is pinned at
/// `path`.
///
/// The bundle is staged next to the target and moved over it only after it
/// parsed, so prose or a truncated block leaves the previous anchor untouched.
/// Which roots count as expected and how an acceptance appends them instead is
/// [`crate::cmd::accept::apply`].
fn install_anchor(
    authority: &Authority,
    path: &Path,
    bytes: &[u8],
    named: &[String],
    accept: Option<&str>,
) -> crate::cmd::accept::Applied {
    crate::cmd::accept::apply(
        authority.name,
        path,
        bytes,
        authority.fingerprints,
        named,
        accept,
        false,
    )
}

/// Set one repository-local config key unless it is already set.
///
/// Returns whether an existing value was kept. `--replace-all` would flatten a
/// hand-tuned value (a different mirror, a longer timeout) on every run, so the
/// keys are only written when absent.
fn set(repo: &Repo, key: &str, value: &str) -> Result<bool, Exit> {
    match git_stdout(repo, &["config", "--local", "--get", key]) {
        Ok(existing) if !existing.trim().is_empty() => Ok(true),
        Ok(_) => {
            git_stdout(repo, &["config", "--local", key, value])?;
            Ok(false)
        }
        // git exits 1 for an unset key, which `git_stdout` reports as usage.
        Err(exit) if exit.code() == 2 => {
            git_stdout(repo, &["config", "--local", key, value])?;
            Ok(false)
        }
        Err(exit) => Err(exit),
    }
}

/// Whether `time.gate = pre-commit` is configured.
pub(crate) fn gate(repo: &Repo) -> Result<bool, Exit> {
    Ok(repo
        .config_non_empty("time.gate")
        .map_err(Exit::config)?
        .is_some_and(|value| value.eq_ignore_ascii_case("pre-commit")))
}

#[cfg(test)]
mod tests {
    use super::{digest_for, fingerprint_matches, matching_digest};

    /// 95 characters: 32 upper-hex octets, colon separated.
    const SHA256: &str = "05:63:B8:63:0D:62:D7:5A:BB:C8:AB:1E:4B:DF:B5:A8:99:B2:4D:43:81:13:7C:5E:5F:D6:D4:70:1A:57:33:9C";
    /// 59 characters: 20 upper-hex octets, colon separated.
    const SHA1: &str = "0B:93:07:6C:81:39:FA:2B:83:38:5F:78:28:D7:BE:75:73:40:D2:41";

    #[test]
    fn the_digest_length_follows_the_expectation() {
        let der = b"a certificate";

        let sha256 = digest_for(Some(SHA256), der);
        assert_eq!(sha256.len(), 95);
        assert_eq!(sha256, git_time_core::trust::fingerprint(der));

        let sha1 = digest_for(Some(SHA1), der);
        assert_eq!(sha1.len(), 59);
        assert_eq!(sha1, git_time_core::trust::sha1_fingerprint(der));
    }

    #[test]
    fn trust_on_first_use_is_sha1() {
        let der = b"a certificate";
        let printed = digest_for(None, der);
        assert_eq!(printed.len(), 59, "{printed}");
        assert_eq!(printed, git_time_core::trust::sha1_fingerprint(der));
    }

    /// The comparison is per value, in the length that value is written in: a
    /// preset carrying a SHA-1 and a SHA-256 spelling works for both.
    #[test]
    fn any_published_fingerprint_matches_and_the_match_is_named() {
        let der = b"a certificate";
        assert_eq!(
            matching_digest(SHA1, der),
            git_time_core::trust::sha1_fingerprint(der)
        );
        assert_eq!(
            matching_digest(SHA256, der),
            git_time_core::trust::fingerprint(der)
        );

        // The values have to be `'static` to be returned; a real preset owns
        // its slice.
        let retired: &'static str =
            Box::leak(git_time_core::trust::sha1_fingerprint(der).into_boxed_str());
        let current: &'static str =
            Box::leak(git_time_core::trust::fingerprint(der).into_boxed_str());
        assert_eq!(
            fingerprint_matches(&[retired, current], der),
            Some(retired),
            "the retired value is the one named"
        );
        assert_eq!(
            fingerprint_matches(&[current, retired], der),
            Some(current),
            "the newest value is named when it is listed first"
        );

        // An empty list is trust on first use, not a match; a non-empty list
        // that matches nothing is a refusal the caller turns into a mismatch.
        assert_eq!(fingerprint_matches(&[], der), None);
        assert_eq!(fingerprint_matches(&["00:11:22"], der), None);
    }
}
