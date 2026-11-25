//! Pinned trust anchors for RFC 3161 token verification.
//!
//! A token is only evidence when it chains to a certificate the caller pinned
//! beforehand; the certificates the token itself carries are input, not trust.
//! This module is the pin side: one PEM bundle per TSA id, loaded once.
//!
//! A bundle's self-signed certificates (issuer equals subject) are that TSA's
//! trust anchors; every other certificate is an intermediate the TSA is allowed
//! to build a chain through (useful when a TSA omits them from its responses).
//! Classification is by self-signature, not by position: a bundle may name its
//! leaf first, and a rotated authority keeps its retired root next to the new
//! one. There is no header line to get wrong.
//!
//! Several roots per id are the point: a token is judged at its own genTime, so
//! an expired root is still exactly the right anchor for the evidence it signed.
//! [`Anchor::roots_at`] is the window query Task 4 will filter candidates with.
//!
//! There is deliberately no fallback to the platform root store: an empty store
//! makes every token [`crate::verify::Invalid::Untrusted`]. A token that was
//! "signed by someone" is not a token that was signed by *your* TSA.
//!
//! The separation is absolute in both directions: a certificate the token
//! carries is never promoted to an anchor, even when it is self-signed and sits
//! in the token's own `certificates` set. Only [`Anchor::roots`] ends a chain.
//! The `token_cannot_supply_its_own_anchor` test pins that.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use der::{Decode, Encode};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use sigstore_types::DerCertificate;
use x509_cert::Certificate;

/// The SHA-256 fingerprint of the certificate `der`, uppercase and colon
/// separated — the form `openssl x509 -fingerprint -sha256` prints.
///
/// It is the value a preset pins and the one a reader can compare against the
/// authority's own publication, so it is spelled the way both of them are
/// written. The empty string is impossible: a certificate always has a digest.
#[must_use]
pub fn fingerprint(der: &[u8]) -> String {
    colon(&Sha256::digest(der))
}

/// The SHA-1 fingerprint of the certificate `der`, in the same spelling.
///
/// Some authorities publish this shorter form and nothing else, so a preset can
/// pin 20 octets where another pins 32. SHA-1 collisions do not matter here: a
/// pinned root is compared as a whole value, not used to sign anything.
#[must_use]
pub fn sha1_fingerprint(der: &[u8]) -> String {
    colon(&Sha1::digest(der))
}

/// The preset spelling of a digest: uppercase hex octets, colon separated.
fn colon(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 3);
    for (index, byte) in digest.iter().enumerate() {
        use std::fmt::Write as _;
        if index > 0 {
            out.push(':');
        }
        // Writing into a String cannot fail.
        let _ = write!(out, "{byte:02X}");
    }
    out
}

/// The pinned material for one TSA: the roots plus its allowed intermediates.
#[derive(Debug, Clone, Default)]
pub struct Anchor {
    /// The trust anchors; a chain must terminate at one of them. A rotated
    /// authority keeps its retired root here, so the list is not a shortcut.
    pub roots: Vec<DerCertificate>,
    /// Intermediates the TSA may use, in bundle order.
    pub intermediates: Vec<DerCertificate>,
}

impl Anchor {
    /// The roots valid at `at`, in bundle order.
    ///
    /// A token is verified at its own genTime, and an authority rotates its
    /// key: the root that was current when the evidence was signed is the one
    /// that matters, not the one current now. Both ends of a validity window
    /// are inclusive. A root that cannot be parsed is skipped rather than
    /// promoted, and a time before the epoch matches nothing.
    #[must_use]
    pub fn roots_at(&self, at: jiff::Timestamp) -> Vec<&DerCertificate> {
        let Ok(second) = u64::try_from(at.as_second()) else {
            return Vec::new();
        };
        self.roots
            .iter()
            .filter(|certificate| {
                let Ok(certificate) = Certificate::from_der(certificate.as_bytes()) else {
                    return false;
                };
                let validity = &certificate.tbs_certificate().validity();
                let not_before = validity.not_before.to_unix_duration().as_secs();
                let not_after = validity.not_after.to_unix_duration().as_secs();
                not_before <= second && second <= not_after
            })
            .collect()
    }
}

/// The pinned anchors, keyed by TSA id.
///
/// Build it with [`AnchorStore::load`]; a store loaded from an empty source
/// list trusts nothing.
#[derive(Debug, Clone, Default)]
pub struct AnchorStore {
    anchors: BTreeMap<String, Anchor>,
}

impl AnchorStore {
    /// Load one PEM bundle per `(id, path)`.
    ///
    /// # Errors
    ///
    /// [`TrustError`] when a bundle cannot be read, holds no certificate, holds
    /// a certificate that is not DER-parseable, holds no self-signed root, or
    /// when an id is pinned twice. A partially loaded store is never returned:
    /// an anchor that failed half way would be a silent downgrade. Use
    /// [`AnchorStore::insert`] when one bad bundle out of several must not cost
    /// the rest.
    pub fn load(sources: &[(String, PathBuf)]) -> Result<Self, TrustError> {
        let mut store = Self::default();
        for (id, path) in sources {
            store.insert(id, path)?;
        }
        Ok(store)
    }

    /// Load and pin one bundle, keeping whatever the store already holds.
    ///
    /// # Errors
    ///
    /// [`TrustError`] for the same reasons as [`AnchorStore::load`]. On failure
    /// the store is left as it was: a bundle is either pinned whole or not at
    /// all.
    pub fn insert(&mut self, id: &str, path: &Path) -> Result<(), TrustError> {
        if self.anchors.contains_key(id) {
            return Err(TrustError::Duplicate { id: id.to_owned() });
        }
        let anchor = read_anchor(id, path)?;
        self.anchors.insert(id.to_owned(), anchor);
        Ok(())
    }

    /// Add the certificates of a bundle to `id`, leaving duplicates out.
    ///
    /// A rotation appends the new root next to the retired one instead of
    /// replacing it. Certificates already pinned — as a root or as an
    /// intermediate — are skipped, so a certificate never lands in both lists
    /// and appending the same bundle twice changes nothing.
    ///
    /// Returns the number of roots that were new. When `id` is not pinned yet
    /// the bundle is a plain [`AnchorStore::insert`], so a store holding nothing
    /// still gets a root.
    ///
    /// # Errors
    ///
    /// [`TrustError`] for the same reasons as [`AnchorStore::load`]. On failure
    /// the store is left as it was.
    pub fn append(&mut self, id: &str, path: &Path) -> Result<usize, TrustError> {
        let incoming = read_anchor(id, path)?;
        let anchor = self.anchors.entry(id.to_owned()).or_default();
        let mut seen: BTreeSet<Vec<u8>> = anchor
            .roots
            .iter()
            .chain(anchor.intermediates.iter())
            .map(|certificate| certificate.as_bytes().to_vec())
            .collect();
        let before = anchor.roots.len();
        for root in incoming.roots {
            if seen.insert(root.as_bytes().to_vec()) {
                anchor.roots.push(root);
            }
        }
        for intermediate in incoming.intermediates {
            if seen.insert(intermediate.as_bytes().to_vec()) {
                anchor.intermediates.push(intermediate);
            }
        }
        Ok(anchor.roots.len() - before)
    }

    /// The anchor pinned for `id`, when there is one.
    ///
    /// The returned material is the only trusted input of a verification; the
    /// token's own certificates are never consulted for trust.
    #[must_use]
    pub fn anchor(&self, id: &str) -> Option<&Anchor> {
        self.anchors.get(id)
    }

    /// Whether nothing at all is pinned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// The number of pinned TSA ids.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }
}

/// Read a bundle, first block first, as DER bytes paired with the parsed
/// certificate.
fn read_bundle(id: &str, path: &Path) -> Result<Vec<(DerCertificate, Certificate)>, TrustError> {
    let bytes = std::fs::read(path).map_err(|source| TrustError::Read {
        id: id.to_owned(),
        path: path.to_path_buf(),
        source,
    })?;

    let mut certificates = Vec::new();
    for block in CertificateDer::pem_slice_iter(&bytes) {
        let certificate = block.map_err(|error| TrustError::Malformed {
            id: id.to_owned(),
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
        // Parse now, so a bundle that is PEM-shaped but not a certificate fails
        // at load instead of turning into `Untrusted` at every later check.
        let parsed =
            Certificate::from_der(certificate.as_ref()).map_err(|error| TrustError::Malformed {
                id: id.to_owned(),
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?;
        certificates.push((DerCertificate::new(certificate.as_ref().to_vec()), parsed));
    }
    Ok(certificates)
}

/// Read a bundle and split it into roots and intermediates.
///
/// Classification is by self-signature: roots sign themselves, everything else
/// is an intermediate whatever its position. Duplicates are dropped, so a
/// certificate appears at most once and in one list. A bundle without a root is
/// an error — an anchor that can never end a chain is a silent hole.
fn read_anchor(id: &str, path: &Path) -> Result<Anchor, TrustError> {
    let mut roots = Vec::new();
    let mut intermediates = Vec::new();
    let mut seen = BTreeSet::new();
    let mut count = 0;
    for (certificate, parsed) in read_bundle(id, path)? {
        count += 1;
        if !seen.insert(certificate.as_bytes().to_vec()) {
            continue;
        }
        if is_self_signed(&parsed) {
            roots.push(certificate);
        } else {
            intermediates.push(certificate);
        }
    }
    if roots.is_empty() {
        let id = id.to_owned();
        let path = path.to_path_buf();
        if count == 0 {
            return Err(TrustError::Empty { id, path });
        }
        return Err(TrustError::NoRoot { id, path });
    }
    Ok(Anchor {
        roots,
        intermediates,
    })
}

/// Whether `certificate` names itself as its issuer.
///
/// The DER encodings are compared rather than the `Name` values: two `Name`s
/// can be equal yet spelled differently, and an alternate but equal encoding
/// must not reclassify a root as an intermediate.
fn is_self_signed(certificate: &Certificate) -> bool {
    match (
        certificate.tbs_certificate().issuer().to_der(),
        certificate.tbs_certificate().subject().to_der(),
    ) {
        (Ok(issuer), Ok(subject)) => issuer == subject,
        _ => false,
    }
}

/// Why an anchor bundle could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// The bundle could not be read.
    #[error("anchor `{id}` could not be read from {}: {source}", path.display())]
    Read {
        /// The TSA id the bundle belongs to.
        id: String,
        /// The bundle path.
        path: PathBuf,
        /// The read failure.
        source: std::io::Error,
    },
    /// The bundle holds no certificate.
    #[error("anchor `{id}` bundle {} holds no certificate", path.display())]
    Empty {
        /// The TSA id the bundle belongs to.
        id: String,
        /// The bundle path.
        path: PathBuf,
    },
    /// The bundle holds no self-signed root.
    #[error("anchor `{id}` bundle {} holds no root certificate", path.display())]
    NoRoot {
        /// The TSA id the bundle belongs to.
        id: String,
        /// The bundle path.
        path: PathBuf,
    },
    /// A certificate in the bundle is not DER.
    #[error("anchor `{id}` bundle {} is malformed: {reason}", path.display())]
    Malformed {
        /// The TSA id the bundle belongs to.
        id: String,
        /// The bundle path.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The same id was pinned twice.
    #[error("anchor `{id}` is pinned more than once")]
    Duplicate {
        /// The duplicated TSA id.
        id: String,
    },
}
