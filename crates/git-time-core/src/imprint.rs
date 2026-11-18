//! Imprint digests over pre-image bytes.
//!
//! An imprint is a hash taken over the pre-image of a commit. The algorithm is
//! part of the artifact, not a policy detail: the `X-RFC3161-Imprint` trailer
//! records it so verification knows what to recompute, and a token that answers
//! a different algorithm is provably wrong rather than ambiguous.
//!
//! The pre-image bytes are hashed exactly as handed in — the caller passes
//! [`crate::object::PreImage::bytes`] and nothing is stripped here.
//!
//! The trailer value is ASCII by definition (`<alg>:<lowercase hex>`). The hash
//! itself stays bytes; only its rendered form is text.

use std::str::FromStr;

use sha2::{Digest as _, Sha256, Sha512};

/// A digest algorithm an imprint may use.
///
/// Only the two SHA-2 widths git and every TSA in the preset set speak are
/// accepted; there are deliberately no aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alg {
    /// SHA-256, 32 digest bytes.
    Sha256,
    /// SHA-512, 64 digest bytes.
    Sha512,
}

impl Alg {
    /// The algorithm's name as it appears in a trailer value, and exactly the
    /// string [`Alg::from_str`] accepts.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// The digest width in bytes.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

impl FromStr for Alg {
    type Err = ParseError;

    /// Parse a lowercase algorithm name; case and `sha-256` spelling matter.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(ParseError::UnknownAlg),
        }
    }
}

/// Hash `bytes` with `alg`.
#[must_use]
pub fn digest(alg: Alg, bytes: &[u8]) -> Vec<u8> {
    match alg {
        Alg::Sha256 => Sha256::digest(bytes).to_vec(),
        Alg::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}

/// An algorithm-tagged digest: what a TSA is asked to timestamp and what the
/// `X-RFC3161-Imprint` trailer carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    /// The algorithm `bytes` was produced with.
    pub alg: Alg,
    /// The raw digest bytes, [`Alg::digest_len`] long when built from
    /// [`digest`]. The fields are public, so a hand-built value is trusted as
    /// given and not re-validated.
    pub bytes: Vec<u8>,
}

impl Digest {
    /// Render the trailer value: `alg:hex`, hex lowercase.
    //
    // `Display` is deliberately not implemented; this is the trailer encoding,
    // not a general-purpose rendering.
    #[must_use]
    pub fn to_trailer_value(&self) -> String {
        let mut value = String::with_capacity(self.alg.as_str().len() + 1 + 2 * self.bytes.len());
        value.push_str(self.alg.as_str());
        value.push(':');
        for byte in &self.bytes {
            value.push(HEX[usize::from(byte >> 4)]);
            value.push(HEX[usize::from(byte & 0x0f)]);
        }
        value
    }

    /// Parse the trailer value back, accepting uppercase hex.
    ///
    /// Fails closed: the shape must be exactly `alg:hex`, the algorithm must be
    /// known, the hex must be the algorithm's width and hex characters only.
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        let Some((alg, hex)) = value.split_once(':') else {
            return Err(ParseError::Malformed);
        };
        if alg.is_empty() {
            return Err(ParseError::Malformed);
        }
        let alg: Alg = alg.parse()?;
        if hex.len() != 2 * alg.digest_len() {
            return Err(ParseError::WrongLength);
        }
        let mut bytes = Vec::with_capacity(alg.digest_len());
        for pair in hex.as_bytes().as_chunks::<2>().0 {
            let high = nibble(pair[0]).ok_or(ParseError::NotHex)?;
            let low = nibble(pair[1]).ok_or(ParseError::NotHex)?;
            bytes.push(high << 4 | low);
        }
        Ok(Self { alg, bytes })
    }
}

/// Lowercase hex digits, indexed by nibble.
const HEX: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Why an imprint trailer value could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The value is not `alg:hex`.
    #[error("imprint value is not `alg:hex`")]
    Malformed,
    /// The algorithm before the colon is not one we speak.
    #[error("unknown imprint algorithm")]
    UnknownAlg,
    /// The hex does not have the algorithm's digest width.
    #[error("imprint digest has the wrong hex length for its algorithm")]
    WrongLength,
    /// The hex contains a character outside `[0-9a-fA-F]`.
    #[error("imprint digest is not hex")]
    NotHex,
}
