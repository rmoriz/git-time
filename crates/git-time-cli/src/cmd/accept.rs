//! `--accept`: the root of a rotation, confirmed by a human.
//!
//! A bundle used to be replaced by whatever a fetch returned. Since a bundle
//! carries the whole history its authority ever signed with, replacing it
//! silently would change what every old commit verifies against: the retired
//! root has to stay next to the new one, and a new root has to be named by a
//! person before it is appended.
//!
//! The value is `id=fingerprint`, so one flag can address several authorities.
//! A bare fingerprint is resolved against the ids actually in play and is only
//! unambiguous when exactly one of them is: with two, the ids are listed and
//! the command is a usage error. An empty fingerprint is an error too, because
//! `--accept id=` would otherwise accept nothing at all.
//!
//! The comparison is case-insensitive and runs in the digest length the
//! fingerprint is written in, so a value copied from an authority's SHA-1
//! publication compares as well as a SHA-256 one. What is printed and stored of
//! the *fetched* value is always its canonical upper case.
//!
//! [`apply`] is the one write path: it parses before writing, refuses a root
//! nobody expected, and appends only when the fingerprint matches. A refused
//! apply leaves the bundle byte for byte as it was.
//!
//! Every judgement is about the **roots** a bundle carries, never about its
//! first certificate: a bundle that lists a signing leaf first is legal, and a
//! fetched bundle of the next generation re-serves a leaf the pinned one already
//! holds. Judging the first certificate made such a fetch look like nothing new
//! and let the replace path drop the retired root, after which every block naming
//! it was unverifiable and an `--accept` was accepted and ignored.
//!
//! The fetched or accepted root goes **first** in a merged bundle, ahead of the
//! pinned ones. Every listing reports a root as the authority line and then every
//! root, so an appended one shows up as a second line; the lock records each of
//! them on its own line too. That is the slot which has to mean "the root this
//! run brought"; a retired root stays behind it and keeps verifying old commits.
//! A merge that adds nothing is reported as a plain replacement, so a re-fetch of
//! the same generation stays quiet — but it still merges, because the served
//! bundle may name fewer roots than the pinned one and dropping the rest would
//! retire them silently.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use der::Decode as _;
use git_time_core::trust::{Anchor, AnchorStore};

use crate::cmd::anchor::{keep_unparsed, staging_path};
use crate::cmd::install::{digest_for, fingerprint_matches, matching_digest};

/// Split one `--accept` value into `(id, fingerprint)`.
///
/// A value without `=` is bare: the id is empty and the caller resolves it.
/// Only the first `=` splits, so a fingerprint that carried one would still
/// reach the comparison whole.
pub fn parse(value: &str) -> Result<(String, String), String> {
    let value = value.trim();
    let (id, fingerprint) = match value.split_once('=') {
        Some((id, fingerprint)) => (id.trim(), fingerprint.trim()),
        None => ("", value),
    };
    if fingerprint.is_empty() {
        return Err(format!(
            "`{value}` carries no fingerprint; write `<id>=<fingerprint>` or just the fingerprint"
        ));
    }
    Ok((id.to_owned(), fingerprint.to_ascii_uppercase()))
}

/// Resolve the bare accepts against the ids in play.
///
/// One id is what a bare value means; none or several are refused with the ids
/// spelled out, so the fix is visible. An id-carrying value is taken as given,
/// so ordering never matters.
pub fn one_or_id(
    values: &[String],
    pinned_ids: &[&str],
) -> Result<BTreeMap<String, String>, String> {
    let mut resolved = BTreeMap::new();
    for value in values {
        let (id, fingerprint) = parse(value)?;
        let id = if !id.is_empty() {
            id
        } else if pinned_ids.is_empty() {
            return Err(format!(
                "`{fingerprint}` carries no id and no authority is involved; write \
                 `<id>=<fingerprint>`"
            ));
        } else if let [only] = pinned_ids {
            (*only).to_owned()
        } else {
            return Err(format!(
                "`{fingerprint}` carries no id and {} are involved; write `<id>=<fingerprint>`",
                pinned_ids
                    .iter()
                    .map(|id| format!("`{id}`"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ));
        };
        resolved.insert(id, fingerprint);
    }
    Ok(resolved)
}

/// Whether `accept` names the certificate `der`.
///
/// The length of `accept` decides the digest, so a SHA-1 and a SHA-256 spelling
/// of the same root both compare. Case is not part of a fingerprint.
pub(crate) fn matches(accept: &str, der: &[u8]) -> bool {
    matching_digest(accept, der).eq_ignore_ascii_case(accept)
}

/// What applying a fetched bundle came to.
pub(crate) enum Applied {
    /// The bundle was written without appending anything: either it is the
    /// first pin, or a repeated fetch whose merge adds no root (only chain
    /// material is new). What matched is named.
    Replaced {
        /// The published value that matched, when one did.
        matched: Option<&'static str>,
        /// The fetched root in the printed length.
        fingerprint: String,
        /// The fetched root as lowercase SHA-256 hex, whatever the expectation's
        /// length: the summary line names that algorithm.
        sha256: String,
        /// The fetched root's own `notAfter`, as `YYYY-MM-DD`.
        expires: Option<String>,
    },
    /// Nothing was pinned: the fetch is the first pin, printed in full.
    FirstPin {
        /// The fetched root in the printed length.
        fingerprint: String,
        /// The fetched root as lowercase SHA-256 hex.
        sha256: String,
        /// Whether an `--accept` was what pinned it rather than trust on first
        /// use.
        accepted: bool,
        /// The fetched root's own `notAfter`, as `YYYY-MM-DD`.
        expires: Option<String>,
    },
    /// The root was accepted, by a human or by a block naming it: it was
    /// appended ahead of the pinned ones.
    Appended {
        /// The fetched root in the printed length.
        fingerprint: String,
        /// The fetched root as lowercase SHA-256 hex.
        sha256: String,
        /// The fetched root's own `notAfter`, as `YYYY-MM-DD`.
        expires: Option<String>,
        /// How many roots the append added.
        added: usize,
        /// How many roots the bundle holds now.
        roots: usize,
    },
    /// A new root nobody confirmed; nothing was written.
    Mismatch {
        /// The values that were expected, joined.
        expected: String,
        /// The fetched root.
        found: String,
    },
    /// The bundle is not a certificate bundle, or could not be written.
    Unusable(String),
}

/// What the roots a fetched bundle brought matched.
///
/// Every field is judged over the bundle's **roots**, never over its first
/// certificate: a bundle may list a signing leaf first, and the leaf is not what
/// the pin, the publication or the block is about.
#[derive(Default)]
struct Matched {
    /// The published value that matched, when one did.
    published: Option<&'static str>,
    /// A root is one a trailer block named.
    named: bool,
    /// A root is already pinned.
    pinned: bool,
    /// A root matches the value a person stored with
    /// `tsa add --fingerprint`.
    configured: bool,
}

/// What every report line says about the root a run is about: the value in the
/// expectation's spelling, the same root as SHA-256, and its `notAfter`.
struct Found {
    /// The fetched root in the printed length.
    fingerprint: String,
    /// The fetched root as lowercase SHA-256 hex.
    sha256: String,
    /// The fetched root's own `notAfter`, as `YYYY-MM-DD`.
    expires: Option<String>,
}

/// The `notAfter` of `der` as `YYYY-MM-DD`, when it parses.
fn expires_of(der: &[u8]) -> Option<String> {
    let certificate = x509_cert::Certificate::from_der(der).ok()?;
    Some(crate::cmd::anchors::not_after(&certificate))
}

/// A fingerprint with its root's expiry and verdict, the way the listings say
/// it: the date a choice is weighed by belongs next to the value that was
/// chosen.
pub(crate) fn root_label(fingerprint: &str, expires: Option<&str>) -> String {
    match expires {
        Some(not_after) => format!(
            "{fingerprint} {}",
            crate::cmd::anchors::expiry_text(not_after, jiff::Timestamp::now())
        ),
        None => fingerprint.to_owned(),
    }
}

/// Parse the fetched `bytes` as `id`'s bundle and place them at `path`.
///
/// `published` are the fingerprints the authority publishes, `named` the roots
/// a trailer block says the tokens were verified with, `configured` the value a
/// person stored with `tsa add --fingerprint`, and `accept` the value a human
/// passed. A root matching any of them is taken without asking.
///
/// A match against a root already in `path` is a match too: the retired root was
/// served again, and the fetch is only new chain material. Whatever matched, a
/// pinned bundle is **merged** rather than overwritten, so a root the fetch does
/// not serve cannot vanish: old evidence naming it stays verifiable, and the
/// quiet `replace` wording is kept for a merge that adds no root.
///
/// A root matching nothing is refused unless `accept` names it, in which case it
/// is appended the same way — the accept is what decides, so a fresh root the
/// served bundle brings along with a root already accounted for is appended too
/// rather than refused.
///
/// `tofu` says whether a root nothing describes may still be pinned when
/// nothing is pinned yet. That is the rule of `anchor fetch`, which is what a
/// person reaches for before anything exists; `install` and `tsa restore` treat
/// a mismatch as the failure it is, even on the first pin.
///
/// Nothing is written unless the whole bundle parsed, so a broken fetch leaves
/// the previous bundle untouched.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply(
    id: &str,
    path: &Path,
    bytes: &[u8],
    published: &[&'static str],
    named: &[String],
    configured: Option<&str>,
    accept: Option<&str>,
    tofu: bool,
) -> Applied {
    let staging = staging_path(path);
    if let Err(error) = std::fs::write(&staging, bytes) {
        return Applied::Unusable(format!("cannot write {}: {error}", staging.display()));
    }
    let staged = match AnchorStore::load(&[(id.to_owned(), staging.clone())]) {
        Ok(staged) => staged,
        Err(error) => {
            let reason = error.to_string();
            keep_unparsed(&staging, path);
            return Applied::Unusable(reason);
        }
    };
    let Some(anchor) = staged.anchor(id) else {
        let _ = std::fs::remove_file(&staging);
        return Applied::Unusable("the bundle carried no certificate".to_owned());
    };
    // The roots the fetch brings. A loaded bundle always has at least one, so an
    // empty list here is the "no certificate" case above.
    let served: Vec<Vec<u8>> = anchor
        .roots
        .iter()
        .map(|root| root.as_bytes().to_vec())
        .collect();
    let Some(served_first) = served.first().cloned() else {
        let _ = std::fs::remove_file(&staging);
        return Applied::Unusable("the bundle carried no certificate".to_owned());
    };

    // What is pinned now, both for the comparison and as the append target. A
    // bundle that does not load is no expectation at all; the fetch replaces it.
    let mut store = AnchorStore::default();
    let pinned = path.exists() && store.insert(id, path).is_ok();
    let pinned_roots: Vec<Vec<u8>> = store
        .anchor(id)
        .map(|anchor| {
            anchor
                .roots
                .iter()
                .map(|root| root.as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default();

    // The evidence of a block is the most specific expectation there is, the
    // publication of the authority the most general, then the value a person
    // stored; a root already pinned is expected again. The display names the most
    // specific source that exists, and the found value is spelled in that
    // source's length. Only a bundle no source describes is spelled in the SHA-1
    // form, the one every authority publishes.
    let display: Vec<String> = if !named.is_empty() {
        named.to_vec()
    } else if !published.is_empty() {
        published.iter().map(|value| (*value).to_owned()).collect()
    } else if let Some(configured) = configured {
        vec![configured.to_owned()]
    } else {
        pinned_roots
            .iter()
            .map(|root| git_time_core::trust::fingerprint(root))
            .collect()
    };
    let matches_configured = |configured: Option<&str>, root: &[u8]| {
        configured.is_some_and(|value| matches(value, root))
    };
    let matched = Matched {
        published: served
            .iter()
            .find_map(|root| fingerprint_matches(published, root)),
        named: served
            .iter()
            .any(|root| named.iter().any(|value| matches(value, root))),
        configured: served
            .iter()
            .any(|root| matches_configured(configured, root)),
        pinned: served.iter().any(|root| pinned_roots.contains(root)),
    };
    // Anything the fetch could be checked against. A stored value counts, so a
    // first pin that had one is a comparison and an unmatched root is a refusal.
    let expected =
        matched.named || matched.published.is_some() || matched.configured || matched.pinned;
    let accepted = accept.is_some_and(|value| served.iter().any(|root| matches(value, root)));
    // The root the run is about: the accepted one if `--accept` named one, else a
    // served root that is **not** pinned yet, else the first root any expectation
    // describes, else the first served one. A rotation is recorded from this
    // value, so a re-fetch that brings a new root must print that root, not one
    // the file already has. It is always a root, so "the fetched root is ..."
    // stays true — a leaf first in the file is neither.
    let is_pinned = |root: &[u8]| pinned_roots.iter().any(|pinned| pinned == root);
    let found_root = accept
        .and_then(|value| served.iter().find(|root| matches(value, root)))
        .or_else(|| served.iter().find(|root| !is_pinned(root)))
        .or_else(|| {
            served.iter().find(|root| {
                let root = root.as_slice();
                named.iter().any(|value| matches(value, root))
                    || fingerprint_matches(published, root).is_some()
                    || matches_configured(configured, root)
            })
        })
        .cloned()
        .unwrap_or(served_first);
    let found = Found {
        fingerprint: digest_for(display.last().map(String::as_str), &found_root),
        sha256: crate::cmd::anchors::fingerprint(&found_root),
        expires: expires_of(&found_root),
    };

    // Something the fetch brought is accounted for: a root already pinned, one a
    // publication names, one a block names, one a stored value names, or one a
    // human accepted. A pinned bundle is then merged, so the retired root
    // survives even when the served bundle no longer carries it.
    if pinned && (expected || accepted) {
        return append(&mut store, id, path, &staging, &found, matched.published);
    }
    if !pinned && expected {
        return match replace(&staging, path) {
            Ok(()) => Applied::Replaced {
                matched: matched.published,
                fingerprint: found.fingerprint,
                sha256: found.sha256,
                expires: found.expires,
            },
            Err(error) => Applied::Unusable(error),
        };
    }
    if !accepted {
        // Nothing is expected and nothing was pinned: trust on first use. A
        // stored value is an expectation, so it is not one of these.
        if !pinned && configured.is_none() && (tofu || display.is_empty()) {
            return match replace(&staging, path) {
                Ok(()) => Applied::FirstPin {
                    fingerprint: found.fingerprint,
                    sha256: found.sha256,
                    accepted: false,
                    expires: found.expires,
                },
                Err(error) => Applied::Unusable(error),
            };
        }
        let _ = std::fs::remove_file(&staging);
        return Applied::Mismatch {
            expected: display.join(" or "),
            found: found.fingerprint,
        };
    }
    // An accept with nothing to append to is a plain pin. A pinned bundle with
    // an accept already went through `append` above.
    match replace(&staging, path) {
        Ok(()) => Applied::FirstPin {
            fingerprint: found.fingerprint,
            sha256: found.sha256,
            accepted: true,
            expires: found.expires,
        },
        Err(error) => Applied::Unusable(error),
    }
}

/// Append the staged bundle to what is pinned at `path` and write the merge.
///
/// The new roots come first and the ones that were pinned follow, so the first
/// certificate keeps meaning "the root this run brought" for every listing and
/// for the lock. Nothing is added twice: [`AnchorStore::append`] collapses the
/// roots and intermediates that were already there.
fn append(
    store: &mut AnchorStore,
    id: &str,
    path: &Path,
    staging: &Path,
    found: &Found,
    published: Option<&'static str>,
) -> Applied {
    let pinned_roots: Vec<Vec<u8>> = store
        .anchor(id)
        .map(|anchor| {
            anchor
                .roots
                .iter()
                .map(|root| root.as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default();
    let added = match store.append(id, staging) {
        Ok(added) => added,
        Err(error) => {
            let _ = std::fs::remove_file(staging);
            return Applied::Unusable(error.to_string());
        }
    };
    let Some(anchor) = store.anchor(id) else {
        let _ = std::fs::remove_file(staging);
        return Applied::Unusable(format!("`{id}` is not pinned"));
    };
    let roots = anchor.roots.len();
    // A root that was already pinned (only its chain material is new) is a
    // refresh, not an append; the merge is written either way.
    let outcome = if added == 0 {
        Applied::Replaced {
            matched: published,
            fingerprint: found.fingerprint.clone(),
            sha256: found.sha256.clone(),
            expires: found.expires.clone(),
        }
    } else {
        Applied::Appended {
            fingerprint: found.fingerprint.clone(),
            sha256: found.sha256.clone(),
            expires: found.expires.clone(),
            added,
            roots,
        }
    };
    if let Err(error) = std::fs::write(staging, bundle(anchor, &pinned_roots)) {
        let _ = std::fs::remove_file(staging);
        return Applied::Unusable(format!("cannot write {}: {error}", staging.display()));
    }
    // The merged bundle is moved over the target like a fetch, so a failed
    // write cannot leave half a bundle behind.
    match replace(staging, path) {
        Ok(()) => outcome,
        Err(error) => Applied::Unusable(error),
    }
}

/// Move the staged bundle over the target.
fn replace(staging: &Path, path: &Path) -> Result<(), String> {
    std::fs::rename(staging, path).map_err(|error| {
        let _ = std::fs::remove_file(staging);
        format!("cannot write {}: {error}", path.display())
    })
}

/// `anchor` as a PEM bundle: the roots `pinned` did not hold first, then the
/// retired ones, then the intermediates. Duplicates are collapsed by
/// [`AnchorStore::append`], so the order only decides which certificate is
/// first — and the first one is what the listings report.
fn bundle(anchor: &Anchor, pinned: &[Vec<u8>]) -> Vec<u8> {
    let (fresh, retired): (Vec<_>, Vec<_>) = anchor
        .roots
        .iter()
        .partition(|root| !pinned.iter().any(|value| value == root.as_bytes()));
    let mut body = String::new();
    for certificate in fresh
        .into_iter()
        .chain(retired)
        .chain(anchor.intermediates.iter())
    {
        let encoded = BASE64.encode(certificate.as_bytes());
        body.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            body.push_str(&String::from_utf8_lossy(chunk));
            body.push('\n');
        }
        body.push_str("-----END CERTIFICATE-----\n");
    }
    body.into_bytes()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Applied, apply, one_or_id, parse};

    /// The FreeTSA fixture root and its published SHA-1, which is the spelling a
    /// first pin is put in: the payload `apply` is about does not matter here.
    const ROOT: &[u8] = include_bytes!("../../../git-time-core/tests/fixtures/freetsa_root.pem");
    const ROOT_SHA1: &str = "0B:93:07:6C:81:39:FA:2B:83:38:5F:78:28:D7:BE:75:73:40:D2:41";

    fn scratch(name: &str) -> PathBuf {
        tempfile::TempDir::new()
            .expect("temp dir")
            .keep()
            .join(name)
    }

    #[test]
    fn a_value_is_id_and_fingerprint_or_bare() {
        assert_eq!(
            parse("freetsa=0B:93"),
            Ok(("freetsa".to_owned(), "0B:93".to_owned()))
        );
        assert_eq!(parse(" 0b:93 "), Ok((String::new(), "0B:93".to_owned())));
        // Only the first `=` splits.
        assert_eq!(parse("a=0B=93"), Ok(("a".to_owned(), "0B=93".to_owned())));
        assert!(parse("freetsa=").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn a_bare_value_needs_exactly_one_id() {
        let values = [String::from("0B:93")];
        assert_eq!(
            one_or_id(&values, &["freetsa"]),
            Ok([("freetsa".to_owned(), "0B:93".to_owned())].into())
        );

        let error = one_or_id(&values, &[]).expect_err("no id");
        assert!(
            error.contains("freetsa") || error.contains("no authority"),
            "{error}"
        );

        let error = one_or_id(&values, &["freetsa", "digicert"]).expect_err("two ids");
        assert!(
            error.contains("freetsa") && error.contains("digicert"),
            "{error}"
        );

        // An id-carrying value needs no resolution.
        let named = [String::from("digicert=0B:93")];
        assert_eq!(
            one_or_id(&named, &["freetsa"]),
            Ok([("digicert".to_owned(), "0B:93".to_owned())].into())
        );
    }

    /// A configured expectation is an expectation: the first pin is a check, not
    /// trust on first use.
    #[test]
    fn a_configured_value_pins_a_matching_root() {
        let path = scratch("acme.pem");
        let applied = apply("acme", &path, ROOT, &[], &[], Some(ROOT_SHA1), None, true);
        assert!(
            matches!(applied, Applied::Replaced { matched: None, .. }),
            "{:?}",
            std::mem::discriminant(&applied)
        );
        assert!(path.exists(), "the bundle was written");
    }

    /// A configured value nothing served matches is the ordinary refusal, and it
    /// names the value that was expected in the configured spelling.
    #[test]
    fn a_configured_value_that_matches_nothing_is_a_mismatch() {
        let path = scratch("acme.pem");
        let expected = "00:".repeat(19) + "00";
        let applied = apply("acme", &path, ROOT, &[], &[], Some(&expected), None, true);
        match applied {
            Applied::Mismatch {
                expected: field,
                found,
            } => {
                assert_eq!(field, expected, "{field}");
                assert_eq!(found.len(), 59, "a SHA-1, the configured length: {found}");
            }
            _ => panic!("expected a mismatch"),
        }
        assert!(!path.exists(), "nothing was pinned");
    }

    /// An accept still decides, even with a configured value that does not match.
    #[test]
    fn an_accept_overrides_a_configured_value() {
        let path = scratch("acme.pem");
        let expected = "00:".repeat(19) + "00";
        let applied = apply(
            "acme",
            &path,
            ROOT,
            &[],
            &[],
            Some(&expected),
            Some(ROOT_SHA1),
            true,
        );
        assert!(
            matches!(applied, Applied::FirstPin { accepted: true, .. }),
            "the accept pins it"
        );
        assert!(path.exists(), "the bundle was written");
    }
}
