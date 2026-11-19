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

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use git_time_core::trust::{Anchor, AnchorStore};

use crate::cmd::anchor::{first_certificate, keep_unparsed, staging_path};
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
    /// The root was expected: the fetched bundle replaced the old one.
    Replaced {
        /// The published value that matched, when one did.
        matched: Option<&'static str>,
        /// The fetched root in the printed length.
        fingerprint: String,
    },
    /// Nothing was pinned: the fetch is the first pin, printed in full.
    FirstPin {
        /// The fetched root in the printed length.
        fingerprint: String,
    },
    /// A human accepted the root: it was appended next to the pinned ones.
    Appended {
        /// The fetched root in the printed length.
        fingerprint: String,
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

/// Parse the fetched `bytes` as `id`'s bundle and place them at `path`.
///
/// `published` are the fingerprints the authority publishes, `named` the roots
/// a trailer block says the tokens were verified with, and `accept` the value a
/// human passed. A root matching any of them replaces the bundle; a root
/// matching none is refused unless `accept` names it, in which case it is
/// appended instead. A match against the roots already in `path` is a match
/// too: the retired root came back, and the fetch is only new chain material.
///
/// `tofu` says whether a root nothing describes may still be pinned when
/// nothing is pinned yet. That is the rule of `anchor fetch`, which is what a
/// person reaches for before anything exists; `install` and `tsa restore` treat
/// a mismatch as the failure it is, even on the first pin.
///
/// Nothing is written unless the whole bundle parsed, so a broken fetch leaves
/// the previous bundle untouched.
pub(crate) fn apply(
    id: &str,
    path: &Path,
    bytes: &[u8],
    published: &[&'static str],
    named: &[String],
    accept: Option<&str>,
    tofu: bool,
) -> Applied {
    let staging = staging_path(path);
    if let Err(error) = std::fs::write(&staging, bytes) {
        return Applied::Unusable(format!("cannot write {}: {error}", staging.display()));
    }
    if let Err(error) = AnchorStore::load(&[(id.to_owned(), staging.clone())]) {
        let reason = error.to_string();
        keep_unparsed(&staging, path);
        return Applied::Unusable(reason);
    }
    let Some(der) = first_certificate(bytes) else {
        let _ = std::fs::remove_file(&staging);
        return Applied::Unusable("the bundle carried no certificate".to_owned());
    };

    // What is pinned now, both for the comparison and as the append target. A
    // bundle that does not load is no expectation at all; the fetch replaces it.
    let mut store = AnchorStore::default();
    let pinned = path.exists() && store.insert(id, path).is_ok();
    let pinned_roots: Vec<String> = store
        .anchor(id)
        .map(|anchor| {
            anchor
                .roots
                .iter()
                .map(|root| git_time_core::trust::fingerprint(root.as_bytes()))
                .collect()
        })
        .unwrap_or_default();

    // The evidence of a block is the most specific expectation there is, the
    // publication of the authority the most general; a root already pinned is
    // expected again. The display names the most specific source that exists,
    // and the found value is spelled in that source's length. Only a bundle no
    // source describes is spelled in the SHA-1 form, the one every authority
    // publishes.
    let display: Vec<&str> = if !named.is_empty() {
        named.iter().map(String::as_str).collect()
    } else if !published.is_empty() {
        published.to_vec()
    } else {
        pinned_roots.iter().map(String::as_str).collect()
    };
    let found = digest_for(display.last().copied(), &der);
    let published_match = fingerprint_matches(published, &der);
    let expected = published_match.is_some()
        || named.iter().any(|value| matches(value, &der))
        || pinned_roots.iter().any(|value| matches(value, &der));
    let accepted = accept.is_some_and(|value| matches(value, &der));

    if expected {
        return match replace(&staging, path) {
            Ok(()) => Applied::Replaced {
                matched: published_match,
                fingerprint: found,
            },
            Err(error) => Applied::Unusable(error),
        };
    }
    if !accepted {
        // Nothing is expected and nothing was pinned: trust on first use.
        if !pinned && (tofu || display.is_empty()) {
            return match replace(&staging, path) {
                Ok(()) => Applied::FirstPin { fingerprint: found },
                Err(error) => Applied::Unusable(error),
            };
        }
        let _ = std::fs::remove_file(&staging);
        return Applied::Mismatch {
            expected: display.join(" or "),
            found,
        };
    }
    if !pinned {
        // An accept with nothing to append to is a plain pin.
        return match replace(&staging, path) {
            Ok(()) => Applied::FirstPin { fingerprint: found },
            Err(error) => Applied::Unusable(error),
        };
    }
    let added = match store.append(id, &staging) {
        Ok(added) => added,
        Err(error) => {
            let _ = std::fs::remove_file(&staging);
            return Applied::Unusable(error.to_string());
        }
    };
    let Some(anchor) = store.anchor(id) else {
        let _ = std::fs::remove_file(&staging);
        return Applied::Unusable(format!("`{id}` is not pinned"));
    };
    let roots = anchor.roots.len();
    if let Err(error) = std::fs::write(&staging, bundle(anchor)) {
        let _ = std::fs::remove_file(&staging);
        return Applied::Unusable(format!("cannot write {}: {error}", staging.display()));
    }
    // The merged bundle is moved over the target like a fetch, so a failed
    // write cannot leave half a bundle behind.
    match replace(&staging, path) {
        Ok(()) => Applied::Appended {
            fingerprint: found,
            added,
            roots,
        },
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

/// `anchor` as a PEM bundle: its roots first, then its intermediates, duplicates
/// collapsed by [`AnchorStore::append`].
fn bundle(anchor: &Anchor) -> Vec<u8> {
    let mut body = String::new();
    for certificate in anchor.roots.iter().chain(anchor.intermediates.iter()) {
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
    use super::{one_or_id, parse};

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
}
