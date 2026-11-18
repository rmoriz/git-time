//! Pinned trust anchors for RFC 3161 token verification.
//!
//! A token is only evidence when it chains to a certificate the caller pinned
//! beforehand; the certificates the token itself carries are input, not trust.
//! This module is the pin side: one PEM bundle per TSA id, loaded once.
//!
//! Each bundle's **first** certificate is that TSA's trust anchor. Any further
//! certificates are intermediates the TSA is allowed to build a chain through
//! (useful when a TSA omits them from its responses). The bundle order is the
//! whole format — there is no header line to get wrong.
//!
//! There is deliberately no fallback to the platform root store: an empty store
//! makes every token [`crate::verify::Invalid::Untrusted`]. A token that was
//! "signed by someone" is not a token that was signed by *your* TSA.
//!
//! The separation is absolute in both directions: a certificate the token
//! carries is never promoted to an anchor, even when it is self-signed and sits
//! in the token's own `certificates` set. Only [`Anchor::root`] ends a chain.
//! The `token_cannot_supply_its_own_anchor` test pins that.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use der::Decode;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
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
    let digest = Sha256::digest(der);
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

/// The pinned material for one TSA: the anchor plus its allowed intermediates.
#[derive(Debug, Clone)]
pub struct Anchor {
    /// The trust anchor; a chain must terminate here.
    pub root: DerCertificate,
    /// Intermediates the TSA may use, in bundle order.
    pub intermediates: Vec<DerCertificate>,
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
    /// a certificate that is not DER-parseable, or when an id is pinned twice.
    /// A partially loaded store is never returned: an anchor that failed half
    /// way would be a silent downgrade. Use [`AnchorStore::insert`] when one bad
    /// bundle out of several must not cost the rest.
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
        let mut certificates = read_bundle(id, path)?;
        let Some(root) = certificates.next() else {
            return Err(TrustError::Empty {
                id: id.to_owned(),
                path: path.to_path_buf(),
            });
        };
        self.anchors.insert(
            id.to_owned(),
            Anchor {
                root,
                intermediates: certificates.collect(),
            },
        );
        Ok(())
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

/// Read a bundle into DER certificates, first block first.
fn read_bundle(id: &str, path: &Path) -> Result<impl Iterator<Item = DerCertificate>, TrustError> {
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
        Certificate::from_der(certificate.as_ref()).map_err(|error| TrustError::Malformed {
            id: id.to_owned(),
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
        certificates.push(DerCertificate::new(certificate.as_ref().to_vec()));
    }
    Ok(certificates.into_iter())
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
