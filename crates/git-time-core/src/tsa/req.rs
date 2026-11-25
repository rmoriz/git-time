//! Encoding of RFC 3161 `TimeStampReq`.
//!
//! The request is small enough that its DER is written here directly, byte by
//! byte, rather than through a generic serializer: the exact bytes are pinned by
//! a golden test, and a nonce whose leading bit is set must grow a `0x00` prefix
//! — rules a general-purpose encoder would make easy to lose behind a type.
//!
//! Version is always 1, the imprint algorithm is carried without parameters, and
//! `certReq` is emitted as `TRUE` (a DER `BOOLEAN` is `0xff`). No extensions are
//! ever sent.
//!
//! The request is what a TSA sees, so the nonce is drawn fresh from the caller's
//! RNG by [`StampRequest::new`]; a caller may override every field, including
//! the nonce, when it wants a reproducible request.
//!
//! The imprint width and the policy are checked while the request is built, so
//! [`encode`] can hand back plain bytes: a 20-byte "sha256" digest or a policy
//! typo never reaches a TSA. That holds for requests built through
//! [`StampRequest::new`] and [`StampRequest::with_policy`] only — the fields are
//! public, and a hand-written one skips the check.

use der::Tag;
// `RngCore` is a deprecated alias for `Rng` in `rand_core` 0.10; the
// controller-facing name is kept so callers and the brief agree.
#[allow(deprecated)]
use rand_core::RngCore;

use crate::imprint::{Alg, Digest};

use super::TsaError;

/// Length of the nonce [`StampRequest::new`] draws.
pub const NONCE_LEN: usize = 8;

/// DER content octets of the SHA-256 `AlgorithmIdentifier` OID,
/// `2.16.840.1.101.3.4.2.1`.
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// DER content octets of the SHA-512 `AlgorithmIdentifier` OID,
/// `2.16.840.1.101.3.4.2.3`.
const SHA512_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// A `TimeStampReq` ready to be encoded.
///
/// The fields are public so a caller can set a policy, turn certificate
/// requesting off, or pin a nonce; [`StampRequest::new`] fills the safe
/// defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampRequest {
    /// The digest the TSA is asked to timestamp.
    pub imprint: Digest,
    /// The nonce, sent as a positive `INTEGER`. Empty omits the field.
    pub nonce: Vec<u8>,
    /// A dotted-decimal OID in `reqPolicy`; `None` omits the field.
    ///
    /// [`StampRequest::with_policy`] validates and sets it; writing the field
    /// directly bypasses that check, and [`encode`] then omits a policy it
    /// cannot render.
    pub policy: Option<String>,
    /// Ask the TSA to include its certificate; DER `FALSE` is the default and
    /// omitted.
    pub cert_req: bool,
}

impl StampRequest {
    /// Build a request with a fresh [`NONCE_LEN`]-byte nonce, no policy, and
    /// `cert_req` set.
    ///
    /// # Errors
    ///
    /// [`TsaError::InvalidImprint`] when `imprint.bytes` is not
    /// [`Alg::digest_len`] long, so a mistagged digest cannot be sent.
    #[allow(deprecated)]
    pub fn new(imprint: Digest, rng: &mut impl RngCore) -> Result<Self, TsaError> {
        let expected = imprint.alg.digest_len();
        if imprint.bytes.len() != expected {
            return Err(TsaError::InvalidImprint(format!(
                "{} imprint is {} bytes, not {expected}",
                imprint.alg.as_str(),
                imprint.bytes.len()
            )));
        }

        let mut nonce = vec![0; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        Ok(Self {
            imprint,
            nonce,
            policy: None,
            cert_req: true,
        })
    }

    /// Set or clear the `reqPolicy`, rejecting a value that is not an OID.
    ///
    /// # Errors
    ///
    /// [`TsaError::InvalidPolicy`] carrying the offending string, so a policy
    /// typo surfaces here instead of silently letting the TSA issue under its
    /// default policy.
    pub fn with_policy(mut self, policy: Option<String>) -> Result<Self, TsaError> {
        if let Some(policy) = policy.as_deref() {
            encode_oid(policy).ok_or_else(|| TsaError::InvalidPolicy(policy.to_owned()))?;
        }
        self.policy = policy;
        Ok(self)
    }
}

/// Encode the request as a DER `TimeStampReq`.
///
/// A policy that went through [`StampRequest::with_policy`] was validated there
/// and is always rendered; one written straight into the public field bypasses
/// that check and is silently left out when it does not encode as an OID. An
/// empty nonce is left out as well.
#[must_use]
pub fn encode(request: &StampRequest) -> Vec<u8> {
    let oid = match request.imprint.alg {
        Alg::Sha256 => SHA256_OID,
        Alg::Sha512 => SHA512_OID,
    };

    // messageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }, with the
    // AlgorithmIdentifier carrying the OID and no parameters.
    let mut imprint = tlv(Tag::Sequence, &tlv(Tag::ObjectIdentifier, oid));
    imprint.extend_from_slice(&tlv(Tag::OctetString, &request.imprint.bytes));

    let mut body = tlv(Tag::Integer, &[1]);
    body.extend_from_slice(&tlv(Tag::Sequence, &imprint));

    if let Some(encoded) = request.policy.as_deref().and_then(encode_oid) {
        body.extend_from_slice(&tlv(Tag::ObjectIdentifier, &encoded));
    }
    if !request.nonce.is_empty() {
        body.extend_from_slice(&positive_integer(&request.nonce));
    }
    if request.cert_req {
        body.extend_from_slice(&tlv(Tag::Boolean, &[0xff]));
    }

    tlv(Tag::Sequence, &body)
}

/// One DER tag-length-value triple.
fn tlv(tag: Tag, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag_byte(tag));
    write_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// The single identifier octet of one of the low-tag-number `tag`s this module
/// emits. `der` 0.8 stopped converting `Tag` to `u8`; a tag above 30 would need
/// a second octet and does not occur here.
fn tag_byte(tag: Tag) -> u8 {
    debug_assert!(tag.number().value() < 31);
    (tag.class() as u8) | (u8::from(tag.is_constructed()) << 5) | (tag.number().value() as u8)
}

/// A DER definite length: short form below 128, else long form with the smallest
/// number of length octets.
fn write_length(length: usize, out: &mut Vec<u8>) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

/// A non-empty `INTEGER` holding `bytes` as a positive number: leading zeroes
/// are stripped and a `0x00` is prepended when the first significant byte has
/// its high bit set. All-zero input encodes as `INTEGER 0`, never as an empty
/// value.
fn positive_integer(bytes: &[u8]) -> Vec<u8> {
    let significant = match bytes.iter().position(|byte| *byte != 0) {
        Some(first) => &bytes[first..],
        None => &[0][..],
    };
    let mut content = Vec::with_capacity(significant.len() + 1);
    if significant[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(significant);
    tlv(Tag::Integer, &content)
}

/// Encode a dotted-decimal OID into DER content octets, or `None` when it is not
/// a valid OID.
fn encode_oid(oid: &str) -> Option<Vec<u8>> {
    let mut arcs = oid.split('.').map(parse_arc);
    let first = arcs.next()??;
    let second = arcs.next()??;
    if first > 2 || (first < 2 && second > 39) {
        return None;
    }

    let mut out = Vec::new();
    base128(first.checked_mul(40)?.checked_add(second)?, &mut out);
    for arc in arcs {
        base128(arc?, &mut out);
    }
    Some(out)
}

/// Parse one OID arc: ASCII digits only, since `str::parse` also takes a sign
/// and `+1` is not a dotted-decimal arc.
fn parse_arc(arc: &str) -> Option<u64> {
    if arc.is_empty() || !arc.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    arc.parse().ok()
}

/// Append `value` in base-128, continuation bit on every group but the last.
fn base128(mut value: u64, out: &mut Vec<u8>) {
    let mut groups = [0u8; 10];
    let mut first = groups.len();
    loop {
        first -= 1;
        groups[first] = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    let last = groups.len() - 1;
    for (index, group) in groups.iter().enumerate().skip(first) {
        out.push(if index == last { *group } else { *group | 0x80 });
    }
}
