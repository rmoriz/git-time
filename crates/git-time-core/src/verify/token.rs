//! Fail-closed verification of one RFC 3161 token.
//!
//! # The security boundary
//!
//! A token carries its own CMS chain. That chain is untrusted input: anybody can
//! mint a CA, self-sign a TSA certificate and produce a token that is
//! internally consistent. What makes a token evidence is that the chain
//! **terminates at the root pinned for that TSA id** in the
//! [`AnchorStore`](crate::trust::AnchorStore). The pinned root is the only
//! material taken from the pin; the signer and the intermediates are whatever
//! the token brought, and they are accepted only if they build a path to that
//! root. A CA certificate carried inside the token is therefore never an
//! anchor, however self-signed it looks (see the
//! `token_cannot_supply_its_own_anchor` test).
//!
//! # Order of checks
//!
//! The first failure wins, so a caller can rely on the cheapest, most specific
//! reason:
//!
//! 1. the CMS structure parses ([`Invalid::Malformed`]);
//! 2. the record's TSA id is pinned ([`Invalid::Untrusted`]);
//! 3. the signed signing-certificate attribute names the signer
//!    ([`Invalid::EssMissing`], [`Invalid::EssMismatch`],
//!    [`Invalid::EssMalformed`]), and the TSTInfo `tsa` name, when present, is
//!    the signer's ([`Invalid::TsaName`]). These come before the signature
//!    deliberately: the `sid` is outside it, so the attribute is the only signed
//!    binding to the certificate, and a token whose binding was patched has to
//!    say so instead of merely failing to verify;
//! 4. the CMS signature, the chain to the pinned root, and the timestamping EKU
//!    hold at the token's own genTime ([`Invalid::Untrusted`], or
//!    [`Invalid::Malformed`] for a structurally unusable signature); the EKU
//!    must be critical and name no purpose but timestamping, which is stricter
//!    than `webpki` alone (see [`sole_timestamping_eku`]);
//! 5. the record's imprint algorithm agrees with its imprint, and the TSTInfo
//!    imprint equals the expected imprint ([`Invalid::Imprint`]);
//! 6. the TSTInfo nonce equals the recorded one ([`Invalid::Nonce`]);
//! 7. the TSTInfo policy equals the recorded one, when one was recorded
//!    ([`Invalid::Policy`]);
//! 8. genTime lies inside the caller's range ([`Invalid::CertNotValidAtGenTime`]);
//! 9. genTime is not after the signer certificate's `notAfter`
//!    ([`Invalid::Expired`]). `webpki` already rejects a signer outside its
//!    validity at genTime, so this is shadowed in practice and kept as
//!    belt-and-braces ([`expired`] has its own unit test).
//!
//! One deliberate exception to "the signature comes first": a record that names
//! a policy while the TSTInfo carries none is answered with [`Invalid::Policy`]
//! before any cryptographic step: the check needs only the parsed structure, and
//! a token that claims a policy it does not carry should not be reported as
//! merely [`Invalid::Malformed`] just because its signature is over a differently
//! shaped TSTInfo.
//!
//! # Why the signature is verified here
//!
//! `sigstore-tsa`'s `verify_timestamp_for_authority` is the reference
//! implementation of the chain and EKU rules, and its
//! [`TsaAuthority`](sigstore_tsa::TsaAuthority) is used verbatim as the anchor
//! bundle. Its signature step cannot express ECDSA P-384 with SHA-512 — exactly
//! what FreeTSA signs with — because its scheme enum has no such variant, so the
//! CMS signature is verified directly here (`aws-lc-rs`) and the chain through
//! `rustls-webpki` with the same rules the library applies: build to the pinned
//! root, pin the signer to the token's own CMS signer, and require the
//! timestamping EKU at genTime.
//!
//! Two shapes `ring` cannot express are verified by a second, narrow path
//! instead (see [`verify_without_ring`]): a SHA-1 signer info, which LibreSSL's
//! `openssl ts -reply` writes whatever the query asked for, and an EC key whose
//! parameters are explicit domain parameters rather than a named curve. Both are
//! legal RFC 3161; refusing them would fail whole TSA services for the shape of
//! their signatures rather than their evidence.

//! # What is tolerated on purpose
//!
//! Three shapes in wide use are not what DER demands, and refusing them would
//! drop whole TSA services over formatting. None of them weakens a check: every
//! one stays inside bytes the TSA signed or fields the record compares.
//!
//! - **Signed attributes out of DER order.** Apple and Lex Persona sign the
//!   order they wrote instead of the sorted one. The attributes are re-tagged
//!   `SET OF` in arrival order ([`as_set`]), so the signature is checked over
//!   exactly what was signed.
//! - **Fractional seconds in genTime.** RFC 3161 allows them and Lex Persona
//!   sends milliseconds; `der` parses whole seconds only. The fraction is
//!   dropped ([`generalized_time`]) and the whole second compared.
//! - **A policy OID under three bytes.** Apple stamps under `1.2.3`, and `der`
//!   decodes OIDs through `const_oid`, which wants at least three arcs. The OID
//!   is read by hand ([`policy_oid`]) and compared as text with the record.
//!
//! A *CA* certificate without an EKU is accepted for the same reason
//! (RFC 5280 §4.2.1.12 makes a CA's EKU a restriction only when it is present),
//! while the signer must still carry a critical `timeStamping` EKU
//! ([`sole_timestamping_eku`]).

use std::collections::BTreeSet;
use std::ops::Range;

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1, ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA512_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512, UnparsedPublicKey, VerificationAlgorithm,
};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::TagNumber;
use der::asn1::{GeneralizedTime, Ia5String, ObjectIdentifier, OctetString, OctetStringRef};
use der::{Decode, Encode, Reader, Sequence, SliceReader, Tag};
use jiff::Timestamp;
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::signature::Verifier as _;
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use sigstore_tsa::TsaAuthority;
use sigstore_types::DerCertificate;
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName, SubjectKeyIdentifier};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::imprint::{Alg, Digest};
use crate::store::TokenRecord;
use crate::trust::AnchorStore;

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const OID_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const OID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// DER content octets of the timestamping extended key usage OID,
/// `1.3.6.1.5.5.7.3.8`.
const ID_KP_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

/// The verdict on one token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenVerdict {
    /// The token is evidence: it chains to the pinned root and answers exactly
    /// this imprint, nonce and policy at an acceptable time.
    Valid {
        /// The TSA's genTime.
        gen_time: Timestamp,
        /// The signing certificate's common name, for logs.
        tsa: String,
        /// The signing certificate's serial, lowercase hex, so a reader can
        /// name the exact certificate that signed rather than its subject
        /// alone.
        serial: String,
    },
    /// The token is noise, for the given reason.
    Invalid(Invalid),
}

impl TokenVerdict {
    /// Whether the verdict is [`TokenVerdict::Valid`].
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

/// Why a token is not evidence.
///
/// Every variant is a refusal; there is no "probably fine".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// The token answers a different imprint than the one expected.
    Imprint,
    /// The token answers a different nonce than the one the request carried.
    Nonce,
    /// No anchor is pinned for the record's TSA id, the chain does not reach
    /// the pinned anchor, or the signer's extended key usage is not a critical,
    /// sole timestamping one.
    Untrusted,
    /// genTime lies outside the range the caller allows.
    CertNotValidAtGenTime,
    /// The token was issued under a different policy than the record claims.
    Policy,
    /// The token is not a usable CMS `SignedData` with a `TSTInfo`.
    Malformed,
    /// genTime is after the signer certificate's `notAfter`.
    Expired,
    /// The token carries neither a `SigningCertificate` nor a
    /// `SigningCertificateV2` signed attribute.
    EssMissing,
    /// A signed signing-certificate attribute names a certificate other than
    /// the one that signed.
    EssMismatch,
    /// A signing-certificate attribute is present but not one identifier with
    /// one supported hash over `certs[0]`.
    EssMalformed,
    /// The TSTInfo's `tsa` field does not name the signer.
    TsaName,
}

impl Invalid {
    /// A short, stable name for machine output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Imprint => "imprint",
            Self::Nonce => "nonce",
            Self::Untrusted => "untrusted",
            Self::CertNotValidAtGenTime => "cert-not-valid-at-gen-time",
            Self::Policy => "policy",
            Self::Malformed => "malformed",
            Self::Expired => "expired",
            Self::EssMissing => "ess-missing",
            Self::EssMismatch => "ess-mismatch",
            Self::EssMalformed => "ess-malformed",
            Self::TsaName => "tsa-name",
        }
    }
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Verify `record` against `imprint`, `gen_time_range` and `anchors`.
///
/// `gen_time_range` is half-open: `start <= genTime < end`.
#[must_use]
pub fn token(
    record: &TokenRecord,
    imprint: &Digest,
    gen_time_range: Range<Timestamp>,
    anchors: &AnchorStore,
) -> TokenVerdict {
    let parsed = match Parsed::parse(&record.token) {
        Ok(parsed) => parsed,
        Err(invalid) => return TokenVerdict::Invalid(invalid),
    };

    let Some(anchor) = anchors.anchor(&record.id) else {
        return TokenVerdict::Invalid(Invalid::Untrusted);
    };

    // See the module docs: the one check that precedes the signature.
    if record.policy.is_some() && parsed.tst.policy.is_none() {
        return TokenVerdict::Invalid(Invalid::Policy);
    }

    match parsed.authenticate(anchor) {
        Ok(()) => {}
        Err(invalid) => return TokenVerdict::Invalid(invalid),
    }

    if !imprint_matches(record.alg, imprint, &parsed.tst) {
        return TokenVerdict::Invalid(Invalid::Imprint);
    }
    if !nonce_matches(&record.nonce, parsed.tst.nonce.as_deref()) {
        return TokenVerdict::Invalid(Invalid::Nonce);
    }
    if let Some(policy) = record.policy.as_deref()
        && parsed.tst.policy.as_deref() != Some(policy)
    {
        return TokenVerdict::Invalid(Invalid::Policy);
    }
    if !gen_time_range.contains(&parsed.tst.gen_time) {
        return TokenVerdict::Invalid(Invalid::CertNotValidAtGenTime);
    }
    if expired(parsed.tst.gen_time, parsed.not_after) {
        return TokenVerdict::Invalid(Invalid::Expired);
    }

    TokenVerdict::Valid {
        gen_time: parsed.tst.gen_time,
        tsa: common_name(&parsed.signer)
            .unwrap_or_else(|| parsed.signer.tbs_certificate.subject.to_string()),
        serial: hex(parsed.signer.tbs_certificate.serial_number.as_bytes()),
    }
}

/// The DER of the CMS signer certificate a token names, when it can be resolved.
///
/// # Untrusted subject
///
/// This resolves the signer from the token's own certificates and runs **no**
/// chain validation: the bytes may name any subject the token's author chose,
/// including one copied from a real TSA. Callers that display a subject next to
/// the token (Task 13) must treat it as a label, not as a verified identity;
/// only [`token`] decides trust. The DER is still useful as *material* (a key to
/// look up, a certificate to inspect), never as a result.
#[must_use]
pub fn signer_certificate(token: &[u8]) -> Option<Vec<u8>> {
    let signed_data = parse_signed_data(token).ok()?;
    let signer = find_signer(&signed_data).ok()?;
    signer.to_der().ok()
}

/// The imprint comparison.
///
/// The record's algorithm and the imprint's must agree first: a record that
/// disagrees with itself cannot be evidence, whichever half is "right". The
/// record's algorithm then selects the expected imprint OID, and the answered
/// OID must equal it and the bytes must be equal.
fn imprint_matches(record_alg: Alg, imprint: &Digest, tst: &Tst) -> bool {
    if record_alg != imprint.alg {
        return false;
    }
    let expected = match record_alg {
        Alg::Sha256 => OID_SHA256,
        Alg::Sha512 => OID_SHA512,
    };
    tst.imprint_alg == expected && tst.imprint == imprint.bytes
}

/// Whether genTime is past the signer certificate's `notAfter`.
///
/// Shadowed end-to-end by `webpki`'s validity check, which fails earlier with
/// [`Invalid::Untrusted`]; the branch is still a cheap second line of defence
/// and is unit-tested directly.
fn expired(gen_time: Timestamp, not_after: Timestamp) -> bool {
    gen_time > not_after
}

/// Compare two nonces after stripping the DER sign padding (or any other
/// leading zero), so a value encoded with and without a pad compares equal.
fn nonce_matches(recorded: &[u8], answered: Option<&[u8]>) -> bool {
    let Some(answered) = answered else {
        return recorded.iter().all(|byte| *byte == 0);
    };
    trim_zeros(recorded) == trim_zeros(answered)
}

fn trim_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first..]
}

/// Re-tag CMS signed attributes as the `SET OF` the signature covers.
///
/// The elements keep the order they arrived in: `der`'s `SetOfVec` would sort
/// them (and refuse a list that is not already sorted), but the signature is over
/// what the TSA wrote, and more than one TSA writes the attributes unsorted.
fn as_set(attributes: &[x509_cert::attr::Attribute]) -> Result<Vec<u8>, Invalid> {
    let mut body = Vec::new();
    for attribute in attributes {
        body.extend_from_slice(&attribute.to_der().map_err(|_| Invalid::Malformed)?);
    }
    let mut out = vec![0x31];
    der_length(&mut out, body.len());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Append a DER length in the shortest form.
fn der_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(u8::try_from(length).expect("short length"));
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("long length");
    let used = &bytes[first..];
    out.push(0x80 | u8::try_from(used.len()).expect("length bytes"));
    out.extend_from_slice(used);
}

/// The common name of a certificate's subject, when it has one.
fn common_name(certificate: &Certificate) -> Option<String> {
    for rdn in certificate.tbs_certificate.subject.0.iter() {
        for attribute in rdn.0.iter() {
            if attribute.oid == OID_COMMON_NAME {
                return Some(
                    attribute
                        .to_string()
                        .strip_prefix("CN=")
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
        }
    }
    None
}

/// A token, parsed far enough to judge it.
struct Parsed {
    tst: Tst,
    tst_info_der: Vec<u8>,
    signer: Certificate,
    not_after: Timestamp,
    intermediates: Vec<DerCertificate>,
    /// The signed attributes as parsed. The set is not the bytes the signature
    /// covers — [`Parsed::signed_attrs`] is — but reading it here keeps the
    /// identifier check off the re-encoded form.
    attributes: Attributes,
    signed_attrs: Vec<u8>,
    signature: Vec<u8>,
    digest_alg: ObjectIdentifier,
}

/// The TSTInfo fields verification needs.
struct Tst {
    policy: Option<String>,
    imprint_alg: ObjectIdentifier,
    imprint: Vec<u8>,
    nonce: Option<Vec<u8>>,
    gen_time: Timestamp,
    tsa: Option<GeneralName>,
}

/// The `certs` of a `SigningCertificate` or `SigningCertificateV2` attribute.
///
/// The two differ only in the identifier's `hashAlgorithm` field, so both
/// decode through the same shape (see [`EssId`]).
#[derive(Sequence)]
struct EssIds {
    certs: Vec<EssId>,
}

/// One `ESSCertID` (RFC 2634) or `ESSCertIDv2` (RFC 5035).
///
/// v1 has no `hashAlgorithm` field and is always SHA-1; v2 omits the field for
/// SHA-256. `issuerSerial` limits the path further and is not read here.
#[derive(Sequence)]
struct EssId {
    #[asn1(optional = "true")]
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    #[asn1(optional = "true")]
    _issuer_serial: Option<der::Any>,
}

impl Parsed {
    /// Parse the CMS structure: signer, chain, signed attributes and TSTInfo.
    fn parse(token: &[u8]) -> Result<Self, Invalid> {
        let signed_data = parse_signed_data(token)?;

        // One signer info: the signature, the digest and the attributes all come
        // from it, and a second one would have to be picked between.
        if signed_data.signer_infos.0.len() != 1 {
            return Err(Invalid::Malformed);
        }

        let econtent = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or(Invalid::Malformed)?;
        let tst_info_der = econtent.value();
        let tst = Tst::parse(tst_info_der)?;

        let signer = find_signer(&signed_data)?;
        let signer_serial = signer.tbs_certificate.serial_number.clone();
        let mut intermediates = Vec::new();
        for choice in signed_data
            .certificates
            .as_ref()
            .map(|set| set.0.iter())
            .into_iter()
            .flatten()
        {
            if let CertificateChoices::Certificate(certificate) = choice
                && certificate.tbs_certificate.serial_number != signer_serial
            {
                intermediates.push(DerCertificate::new(
                    certificate.to_der().map_err(|_| Invalid::Malformed)?,
                ));
            }
        }

        let signer_info = signed_data
            .signer_infos
            .0
            .get(0)
            .ok_or(Invalid::Malformed)?;
        let not_after = unix(signer.tbs_certificate.validity.not_after.to_unix_duration())?;
        let signed_attributes = signer_info
            .signed_attrs
            .as_ref()
            .ok_or(Invalid::Malformed)?;

        // RFC 5652: the attributes are stored under `[0] IMPLICIT` but the
        // signature covers them re-tagged as `SET OF`. `SetOfVec::try_from`
        // insists on the DER sort order, which several TSAs (Apple, Lex Persona)
        // do not produce; the signature still covers the order they wrote, so the
        // re-tagging keeps it.
        let attributes: Vec<x509_cert::attr::Attribute> =
            signed_attributes.iter().cloned().collect();
        let signed_attrs = as_set(&attributes)?;
        let attributes = Attributes::from_der(&signed_attrs).map_err(|_| Invalid::Malformed)?;

        Ok(Self {
            tst,
            tst_info_der: tst_info_der.to_vec(),
            signer,
            not_after,
            intermediates,
            attributes,
            signed_attrs,
            signature: signer_info.signature.as_bytes().to_vec(),
            digest_alg: signer_info.digest_alg.oid,
        })
    }

    /// Authenticate the token: the signed signer identifier, then the CMS
    /// signature, chain to a pinned root, and the timestamping EKU at the
    /// token's own genTime.
    ///
    /// The pinned roots are the only material taken from `anchor`; the signer
    /// and intermediates are the token's, and are pinned to `authority.leaf`.
    fn authenticate(&self, anchor: &crate::trust::Anchor) -> Result<(), Invalid> {
        // Before the signature: the identifier is what says *which* certificate
        // the signed bytes belong to, so a token that names another one is
        // answered as that rather than as a broken signature.
        signer_identification(&self.attributes, &self.signer)?;
        tsa_name(self.tst.tsa.as_ref(), &self.signer)?;

        let signer_der = self.signer.to_der().map_err(|_| Invalid::Malformed)?;

        // The token's own chain first, then whatever else the pin allows. The
        // two lists overlap in practice (a TSA that sends its root also has it
        // pinned), and webpki tolerates the duplicates, but a chain is easier to
        // read without them.
        let mut seen = BTreeSet::new();
        let intermediates: Vec<DerCertificate> = self
            .intermediates
            .iter()
            .chain(anchor.intermediates.iter())
            .filter(|certificate| seen.insert(certificate.as_bytes().to_vec()))
            .cloned()
            .collect();

        let authority = TsaAuthority::new(
            DerCertificate::new(signer_der.clone()),
            intermediates,
            // Task 4 filters candidates: for now the first root is the anchor.
            anchor.roots[0].clone(),
            None,
        );

        self.verify_signature()?;
        verify_chain(&authority, self.tst.gen_time)?;
        // `webpki` accepts an EKU of `timeStamping` plus anything else, and
        // ignores the criticality flag. RFC 3161 §2.3 is stricter: the signer is
        // a TSA and nothing else, and that restriction is critical.
        if !sole_timestamping_eku(&self.signer) {
            return Err(Invalid::Untrusted);
        }
        Ok(())
    }

    /// Verify the CMS signature over the signed attributes with the signer key,
    /// after binding the signed attributes to the TSTInfo they claim to cover.
    fn verify_signature(&self) -> Result<(), Invalid> {
        let message_digest = message_digest(&self.attributes)?;
        let computed = hash(&self.digest_alg, &self.tst_info_der)?;
        if message_digest != computed {
            return Err(Invalid::Malformed);
        }
        content_type(&self.attributes)?;

        let spki = &self.signer.tbs_certificate.subject_public_key_info;
        let Some(algorithm) = signature_algorithm(
            &spki.algorithm.oid,
            spki.algorithm.parameters.as_ref(),
            &self.digest_alg,
        ) else {
            return verify_without_ring(
                spki,
                &self.digest_alg,
                &self.signed_attrs,
                &self.signature,
            );
        };

        let key = spki.subject_public_key.raw_bytes();
        UnparsedPublicKey::new(algorithm, key)
            .verify(&self.signed_attrs, &self.signature)
            .map_err(|_| Invalid::Untrusted)
    }
}

/// Pick the signature algorithm from the key type and the declared digest.
///
/// A token whose declared digest and signature disagree simply fails to verify;
/// the mapping never guesses a fallback hash.
fn signature_algorithm(
    key: &ObjectIdentifier,
    parameters: Option<&der::Any>,
    digest: &ObjectIdentifier,
) -> Option<&'static dyn VerificationAlgorithm> {
    if *key == OID_ED25519 {
        return Some(&ED25519);
    }
    if *key == OID_RSA || *key == OID_RSA_PSS {
        // RFC 4055 keys declare PSS; RFC 3279 keys declare PKCS#1 v1.5.
        return match (digest, *key == OID_RSA_PSS) {
            (d, false) if *d == OID_SHA256 => Some(&RSA_PKCS1_2048_8192_SHA256),
            (d, false) if *d == OID_SHA384 => Some(&RSA_PKCS1_2048_8192_SHA384),
            (d, false) if *d == OID_SHA512 => Some(&RSA_PKCS1_2048_8192_SHA512),
            (d, true) if *d == OID_SHA256 => Some(&RSA_PSS_2048_8192_SHA256),
            (d, true) if *d == OID_SHA384 => Some(&RSA_PSS_2048_8192_SHA384),
            (d, true) if *d == OID_SHA512 => Some(&RSA_PSS_2048_8192_SHA512),
            _ => None,
        };
    }
    if *key != OID_EC_PUBLIC_KEY {
        return None;
    }

    let curve = parameters?.decode_as::<ObjectIdentifier>().ok()?;
    match (digest, curve) {
        (d, OID_SECP256R1) if *d == OID_SHA256 => Some(&ECDSA_P256_SHA256_ASN1),
        (d, OID_SECP256R1) if *d == OID_SHA384 => Some(&ECDSA_P256_SHA384_ASN1),
        (d, OID_SECP384R1) if *d == OID_SHA256 => Some(&ECDSA_P384_SHA256_ASN1),
        (d, OID_SECP384R1) if *d == OID_SHA384 => Some(&ECDSA_P384_SHA384_ASN1),
        (d, OID_SECP384R1) if *d == OID_SHA512 => Some(&ECDSA_P384_SHA512_ASN1),
        _ => None,
    }
}

/// Verify a signature `ring` has no algorithm for.
///
/// Two legal shapes reach here: a SHA-1 signer info (`ring` knows no SHA-1
/// algorithm; LibreSSL's `openssl ts -reply` writes SHA-1 whatever the query
/// asked for) and an EC key whose parameters are a full `SpecifiedECDomain`
/// instead of a named curve (LibreSSL's other default). The hash is computed
/// here and handed to a verifier that takes a pre-hash.
fn verify_without_ring(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    digest: &ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Invalid> {
    let key = spki.subject_public_key.raw_bytes();

    if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
        // Without a named curve both supported curves are tried: the key bytes
        // only parse as a point on the curve that actually signed.
        let named = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
        let p256 = named.as_ref().is_none_or(|curve| *curve == OID_SECP256R1);
        let p384 = named.as_ref().is_none_or(|curve| *curve == OID_SECP384R1);
        if !p256 && !p384 {
            return Err(Invalid::Malformed);
        }
        let hashed = hash(digest, message)?;

        if p256 && let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(key) {
            let signature =
                p256::ecdsa::Signature::from_der(signature).map_err(|_| Invalid::Malformed)?;
            if key.verify_prehash(&hashed, &signature).is_ok() {
                return Ok(());
            }
        }
        if p384 && let Ok(key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(key) {
            let signature =
                p384::ecdsa::Signature::from_der(signature).map_err(|_| Invalid::Malformed)?;
            if key.verify_prehash(&hashed, &signature).is_ok() {
                return Ok(());
            }
        }
        return Err(Invalid::Untrusted);
    }

    // The RSA verifiers hash the message themselves, so they take it as it is.
    let key_der = spki.to_der().map_err(|_| Invalid::Malformed)?;
    let key = rsa::RsaPublicKey::from_public_key_der(&key_der).map_err(|_| Invalid::Malformed)?;
    if spki.algorithm.oid == OID_RSA {
        let key = rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(key);
        let signature =
            rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| Invalid::Malformed)?;
        return key
            .verify(message, &signature)
            .map_err(|_| Invalid::Untrusted);
    }
    if spki.algorithm.oid == OID_RSA_PSS {
        let key = rsa::pss::VerifyingKey::<sha1::Sha1>::new(key);
        let signature = rsa::pss::Signature::try_from(signature).map_err(|_| Invalid::Malformed)?;
        return key
            .verify(message, &signature)
            .map_err(|_| Invalid::Untrusted);
    }
    Err(Invalid::Malformed)
}

/// Build the chain from the token's signer to the pinned root at `gen_time`,
/// requiring the timestamping EKU.
fn verify_chain(authority: &TsaAuthority, gen_time: Timestamp) -> Result<(), Invalid> {
    let root = CertificateDer::from(authority.root.as_bytes().to_vec());
    let trust_anchor = webpki::anchor_from_trusted_cert(&root).map_err(|_| Invalid::Untrusted)?;
    let signer = CertificateDer::from(authority.leaf.as_bytes().to_vec());
    let end_entity = webpki::EndEntityCert::try_from(&signer).map_err(|_| Invalid::Untrusted)?;
    let intermediates: Vec<CertificateDer<'static>> = authority
        .intermediates
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_bytes().to_vec()))
        .collect();

    let seconds = u64::try_from(gen_time.as_second()).map_err(|_| Invalid::Malformed)?;
    let at = UnixTime::since_unix_epoch(std::time::Duration::from_secs(seconds));

    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[trust_anchor],
            &intermediates,
            at,
            // `required_if_present`, not `required`: webpki applies the usage to
            // every certificate in the path, and CA certificates legitimately
            // carry no EKU (DFN, Belgium, CESnet). RFC 5280 makes a CA's EKU a
            // restriction only when present. The signer itself is held to the
            // strict rule by `sole_timestamping_eku`.
            webpki::KeyUsage::required_if_present(ID_KP_TIME_STAMPING),
            None,
            None,
        )
        .map(|_| ())
        .map_err(|_| Invalid::Untrusted)
}

/// Parse the outer `ContentInfo` and its `SignedData`.
fn parse_signed_data(token: &[u8]) -> Result<SignedData, Invalid> {
    let content_info = ContentInfo::from_der(token).map_err(|_| Invalid::Malformed)?;
    if content_info.content_type != OID_SIGNED_DATA {
        return Err(Invalid::Malformed);
    }
    let signed_data_der = content_info
        .content
        .to_der()
        .map_err(|_| Invalid::Malformed)?;
    let signed_data = SignedData::from_der(&signed_data_der).map_err(|_| Invalid::Malformed)?;
    if signed_data.encap_content_info.econtent_type != OID_TST_INFO {
        return Err(Invalid::Malformed);
    }
    Ok(signed_data)
}

/// Find the certificate the signer identifier names, among the token's own
/// certificates.
fn find_signer(signed_data: &SignedData) -> Result<Certificate, Invalid> {
    let signer_info = signed_data
        .signer_infos
        .0
        .get(0)
        .ok_or(Invalid::Malformed)?;
    let certificates = signed_data
        .certificates
        .as_ref()
        .ok_or(Invalid::Malformed)?;

    for choice in certificates.0.iter() {
        let CertificateChoices::Certificate(certificate) = choice else {
            continue;
        };
        if identifies(&signer_info.sid, certificate) {
            return Ok(certificate.clone());
        }
    }
    Err(Invalid::Malformed)
}

/// Whether `sid` names `certificate`.
fn identifies(sid: &SignerIdentifier, certificate: &Certificate) -> bool {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(issuer) => {
            certificate.tbs_certificate.issuer == issuer.issuer
                && certificate.tbs_certificate.serial_number == issuer.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(wanted) => certificate
            .tbs_certificate
            .extensions
            .as_ref()
            .into_iter()
            .flatten()
            .filter(|extension| extension.extn_id == OID_SUBJECT_KEY_ID)
            .any(|extension| {
                SubjectKeyIdentifier::from_der(extension.extn_value.as_bytes())
                    .is_ok_and(|key_id| key_id == *wanted)
            }),
    }
}

/// The `messageDigest` signed attribute value.
fn message_digest(attributes: &x509_cert::attr::Attributes) -> Result<Vec<u8>, Invalid> {
    let attribute = attributes
        .iter()
        .find(|attribute| attribute.oid == OID_MESSAGE_DIGEST)
        .ok_or(Invalid::Malformed)?;
    if attribute.values.len() != 1 {
        return Err(Invalid::Malformed);
    }
    let value = attribute.values.get(0).ok_or(Invalid::Malformed)?;
    let encoded = value.to_der().map_err(|_| Invalid::Malformed)?;
    OctetStringRef::from_der(&encoded)
        .map(|octets| octets.as_bytes().to_vec())
        .map_err(|_| Invalid::Malformed)
}

/// The `contentType` signed attribute, when present, must name a `TSTInfo`.
///
/// The econtent type is already checked during parsing; this catches the signed
/// attribute disagreeing with it, so a signature over attributes that claim to
/// cover something else is not read as a timestamp.
fn content_type(attributes: &x509_cert::attr::Attributes) -> Result<(), Invalid> {
    let Some(attribute) = attributes
        .iter()
        .find(|attribute| attribute.oid == OID_CONTENT_TYPE)
    else {
        // RFC 5652 requires it beside a messageDigest, but the binding above is
        // what carries the security, so its absence alone is not fatal.
        return Ok(());
    };
    if attribute.values.len() != 1 {
        return Err(Invalid::Malformed);
    }
    let value = attribute.values.get(0).ok_or(Invalid::Malformed)?;
    let encoded = value.to_der().map_err(|_| Invalid::Malformed)?;
    let oid = ObjectIdentifier::from_der(&encoded).map_err(|_| Invalid::Malformed)?;
    if oid == OID_TST_INFO {
        Ok(())
    } else {
        Err(Invalid::Malformed)
    }
}

/// Check the ESS signing-certificate attributes against the signer.
///
/// RFC 3161 §2.4.2 requires a signed `SigningCertificate` attribute
/// (`ESSCertID`, SHA-1) and RFC 5816 §2.2.1 widens that to
/// `SigningCertificateV2` (`ESSCertIDv2`, any hash, SHA-256 when the field is
/// omitted). The `sid` that the signer is looked up by is not covered by the
/// signature; this attribute is, and it is therefore the only signed binding
/// between the TSTInfo and the certificate that signed it. A token without one
/// is refused, and so is one naming another certificate.
///
/// Both attributes are judged even when one of them matched: a token carrying
/// both claims both, and neither excuses the other. Only `certs[0]` is the
/// signer; further identifiers constrain the path.
fn signer_identification(attributes: &Attributes, signer: &Certificate) -> Result<(), Invalid> {
    let v1: Vec<&Attribute> = attributes
        .iter()
        .filter(|attribute| attribute.oid == OID_SIGNING_CERTIFICATE)
        .collect();
    let v2: Vec<&Attribute> = attributes
        .iter()
        .filter(|attribute| attribute.oid == OID_SIGNING_CERTIFICATE_V2)
        .collect();

    if v1.is_empty() && v2.is_empty() {
        return Err(Invalid::EssMissing);
    }
    if v1.len() > 1 || v2.len() > 1 {
        return Err(Invalid::EssMalformed);
    }

    let signer_der = signer.to_der().map_err(|_| Invalid::EssMalformed)?;
    for attribute in v1.iter() {
        ess_identifier(attribute, OID_SHA1, &signer_der)?;
    }
    for attribute in v2.iter() {
        // No algorithm field means SHA-256; a named one is used as it is and an
        // unsupported one is refused further down.
        ess_identifier(attribute, OID_SHA256, &signer_der)?;
    }
    Ok(())
}

/// Whether one signing-certificate attribute's first identifier names the
/// certificate whose DER is `signer`.
///
/// `default_algorithm` is the hash the attribute means when it names none
/// (SHA-1 for v1, SHA-256 for v2).
fn ess_identifier(
    attribute: &Attribute,
    default_algorithm: ObjectIdentifier,
    signer: &[u8],
) -> Result<(), Invalid> {
    if attribute.values.len() != 1 {
        return Err(Invalid::EssMalformed);
    }
    let value = attribute.values.get(0).ok_or(Invalid::EssMalformed)?;
    let encoded = value.to_der().map_err(|_| Invalid::EssMalformed)?;
    let ids = EssIds::from_der(&encoded).map_err(|_| Invalid::EssMalformed)?;
    let Some(first) = ids.certs.first() else {
        return Err(Invalid::EssMalformed);
    };

    let algorithm = first
        .hash_algorithm
        .as_ref()
        .map_or(default_algorithm, |algorithm| algorithm.oid);
    let computed = hash(&algorithm, signer).map_err(|_| Invalid::EssMalformed)?;
    if computed == first.cert_hash.as_bytes() {
        Ok(())
    } else {
        Err(Invalid::EssMismatch)
    }
}

/// Whether the TSTInfo's `tsa` field names the signer.
///
/// RFC 3161 makes the field optional and informational, but when a TSA writes
/// it, it must be about the certificate that signed: a `directoryName` is
/// compared as DER against the signer's subject, and a `dNSName` must be one of
/// the signer's subject alternative names. Any other `GeneralName` choice is
/// not something a certificate can be held to here, so it is refused rather
/// than guessed at.
fn tsa_name(tsa: Option<&GeneralName>, signer: &Certificate) -> Result<(), Invalid> {
    let Some(tsa) = tsa else {
        return Ok(());
    };
    match tsa {
        GeneralName::DirectoryName(name) => {
            let name = name.to_der().map_err(|_| Invalid::TsaName)?;
            let subject = signer
                .tbs_certificate
                .subject
                .to_der()
                .map_err(|_| Invalid::TsaName)?;
            if name == subject {
                Ok(())
            } else {
                Err(Invalid::TsaName)
            }
        }
        GeneralName::DnsName(wanted) => {
            if dns_names(signer).iter().any(|name| name == wanted) {
                Ok(())
            } else {
                Err(Invalid::TsaName)
            }
        }
        _ => Err(Invalid::TsaName),
    }
}

/// The `dNSName`s in a certificate's subject alternative name extension.
///
/// A malformed extension contributes nothing rather than failing: the SAN is a
/// second way to name the signer, and the subject comparison is unaffected.
fn dns_names(certificate: &Certificate) -> Vec<Ia5String> {
    let mut names = Vec::new();
    for extension in certificate.tbs_certificate.extensions.iter().flatten() {
        if extension.extn_id != OID_SUBJECT_ALT_NAME {
            continue;
        }
        let Ok(alt_names) = SubjectAltName::from_der(extension.extn_value.as_bytes()) else {
            continue;
        };
        for name in alt_names.0 {
            if let GeneralName::DnsName(name) = name {
                names.push(name);
            }
        }
    }
    names
}

/// Whether the certificate's extended key usage is critical and names exactly
/// one purpose, `id-kp-timeStamping`.
///
/// RFC 3161 §2.3: "The EKU extension must be critical ... The TSA certificate
/// MUST have only the Time Stamping purpose". `webpki`'s
/// `KeyUsage::required` accepts dual-purpose and non-critical certs, so the
/// strict reading is enforced here. A non-critical, duplicated, multi-purpose or
/// `anyExtendedKeyUsage` EKU is all [`Invalid::Untrusted`], and so is a missing
/// one: with no EKU there is nothing that says the certificate is a TSA and
/// nothing else.
fn sole_timestamping_eku(certificate: &Certificate) -> bool {
    let mut seen = false;
    for extension in certificate.tbs_certificate.extensions.iter().flatten() {
        if extension.extn_id != OID_EXTENDED_KEY_USAGE {
            continue;
        }
        if seen {
            return false;
        }
        seen = true;
        if !extension.critical {
            return false;
        }
        let Ok(usage) = ExtendedKeyUsage::from_der(extension.extn_value.as_bytes()) else {
            return false;
        };
        if usage.0.len() != 1 || usage.0[0] != OID_KP_TIME_STAMPING {
            return false;
        }
    }
    seen
}

/// Lowercase hex, as the serial is rendered.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hash `bytes` with the digest the token declares, or `Malformed` for an
/// unknown one.
fn hash(algorithm: &ObjectIdentifier, bytes: &[u8]) -> Result<Vec<u8>, Invalid> {
    match *algorithm {
        d if d == OID_SHA1 => Ok(sha1::Sha1::digest(bytes).to_vec()),
        d if d == OID_SHA256 => Ok(Sha256::digest(bytes).to_vec()),
        d if d == OID_SHA384 => Ok(Sha384::digest(bytes).to_vec()),
        d if d == OID_SHA512 => Ok(Sha512::digest(bytes).to_vec()),
        _ => Err(Invalid::Malformed),
    }
}

impl Tst {
    /// Parse a DER `TSTInfo`.
    ///
    /// Only the fields verification needs are kept; the rest is walked so a
    /// wrongly shaped tail is still caught.
    fn parse(bytes: &[u8]) -> Result<Self, Invalid> {
        let mut outer = SliceReader::new(bytes).map_err(|_| Invalid::Malformed)?;
        let body = tlv(&mut outer, Tag::Sequence)?;
        outer.finish(()).map_err(|_| Invalid::Malformed)?;
        let mut reader = SliceReader::new(body).map_err(|_| Invalid::Malformed)?;

        let version = tlv(&mut reader, Tag::Integer)?;
        if trim_zeros(version) != [1] {
            return Err(Invalid::Malformed);
        }

        // RFC 3161 makes `policy` mandatory; accepted-without-policy tokens are
        // still judged field by field so the caller gets `Policy` rather than a
        // generic `Malformed` when the record names one.
        let policy = if next_tag(&mut reader)? == Some(Tag::ObjectIdentifier) {
            Some(policy_oid(&mut reader)?)
        } else {
            None
        };

        let imprint_body = tlv(&mut reader, Tag::Sequence)?;
        let mut imprint_reader = SliceReader::new(imprint_body).map_err(|_| Invalid::Malformed)?;
        let algorithm_body = tlv(&mut imprint_reader, Tag::Sequence)?;
        let mut algorithm_reader =
            SliceReader::new(algorithm_body).map_err(|_| Invalid::Malformed)?;
        let imprint_alg = algorithm_reader
            .decode::<ObjectIdentifier>()
            .map_err(|_| Invalid::Malformed)?;
        let imprint = tlv(&mut imprint_reader, Tag::OctetString)?.to_vec();
        imprint_reader.finish(()).map_err(|_| Invalid::Malformed)?;

        let _serial = tlv(&mut reader, Tag::Integer)?;
        let gen_time = generalized_time(tlv_full(&mut reader, Tag::GeneralizedTime)?)?;

        // Accuracy, then ordering, then the nonce.
        let mut nonce = None;
        if next_tag(&mut reader)? == Some(Tag::Sequence) {
            tlv(&mut reader, Tag::Sequence)?;
        }
        if next_tag(&mut reader)? == Some(Tag::Boolean) {
            tlv(&mut reader, Tag::Boolean)?;
        }
        if next_tag(&mut reader)? == Some(Tag::Integer) {
            nonce = Some(tlv(&mut reader, Tag::Integer)?.to_vec());
        }

        // The tail may hold a `[0]` TSA name and `[1]` extensions, nothing else.
        let mut tsa = None;
        while let Some(tag) = next_tag(&mut reader)? {
            match tag {
                Tag::ContextSpecific {
                    number: TagNumber::N0,
                    ..
                } => {
                    if tsa.is_some() {
                        return Err(Invalid::Malformed);
                    }
                    // EXPLICIT even under `IMPLICIT TAGS`: `GeneralName` is a
                    // CHOICE, so the field wraps its DER.
                    let content = tlv(&mut reader, tag)?;
                    tsa = Some(GeneralName::from_der(content).map_err(|_| Invalid::Malformed)?);
                }
                Tag::ContextSpecific {
                    number: TagNumber::N1,
                    ..
                } => {
                    tlv_full(&mut reader, tag)?;
                }
                _ => return Err(Invalid::Malformed),
            }
        }
        reader.finish(()).map_err(|_| Invalid::Malformed)?;

        Ok(Self {
            policy,
            imprint_alg,
            imprint,
            nonce,
            gen_time,
            tsa,
        })
    }
}

/// Read, as dotted decimal, the policy OID the TSTInfo declares.
///
/// `der` decodes OIDs through `const_oid`, which rejects any body shorter than
/// three bytes; Apple's policy `1.2.3` encodes to two. The policy is only ever
/// compared as text with the configured one, so it is decoded here.
fn policy_oid(reader: &mut SliceReader<'_>) -> Result<String, Invalid> {
    let body = tlv(reader, Tag::ObjectIdentifier)?;
    if body.is_empty() {
        return Err(Invalid::Malformed);
    }

    let mut arcs: Vec<String> = Vec::with_capacity(body.len() + 1);
    let mut value: u64 = 0;
    for byte in body {
        value = value
            .checked_mul(128)
            .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
            .ok_or(Invalid::Malformed)?;
        if byte & 0x80 != 0 {
            continue;
        }
        match arcs.len() {
            0 => {
                let (first, second) = match value {
                    0..=39 => (0, value),
                    40..=79 => (1, value - 40),
                    _ => (2, value - 80),
                };
                arcs.push(first.to_string());
                arcs.push(second.to_string());
            }
            _ => arcs.push(value.to_string()),
        }
        value = 0;
    }

    // A truncated group (continuation bit still set) is not a whole OID.
    if arcs.is_empty() || body.last().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(Invalid::Malformed);
    }
    Ok(arcs.join("."))
}

/// Convert a DER `GeneralizedTime` into a [`Timestamp`].
///
/// RFC 3161 allows fractional seconds and TSAs use them (Lex Persona sends
/// milliseconds), while the `der` crate accepts exactly the 15-byte whole-second
/// form RFC 5280 writes for certificates. Verification compares what the TSTInfo
/// declares, so the fraction is dropped before parsing; only the whole second is
/// kept anyway.
fn generalized_time(raw: &[u8]) -> Result<Timestamp, Invalid> {
    if let Ok(time) = GeneralizedTime::from_der(raw) {
        return timestamp(&time);
    }
    let body = raw.get(2..).ok_or(Invalid::Malformed)?;
    let point = body
        .iter()
        .position(|byte| *byte == b'.')
        .ok_or(Invalid::Malformed)?;
    let end = body
        .iter()
        .position(|byte| *byte == b'Z')
        .ok_or(Invalid::Malformed)?;
    if point >= end {
        return Err(Invalid::Malformed);
    }
    let mut trimmed = Vec::with_capacity(body.len());
    trimmed.push(0x18);
    trimmed.push(u8::try_from(body.len() - (end - point)).map_err(|_| Invalid::Malformed)?);
    trimmed.extend_from_slice(&body[..point]);
    trimmed.extend_from_slice(&body[end..]);
    timestamp(&GeneralizedTime::from_der(&trimmed).map_err(|_| Invalid::Malformed)?)
}

/// Convert a DER time into a [`Timestamp`].
fn timestamp(time: &GeneralizedTime) -> Result<Timestamp, Invalid> {
    unix(time.to_unix_duration())
}

/// Convert a duration since the epoch into a [`Timestamp`].
fn unix(duration: std::time::Duration) -> Result<Timestamp, Invalid> {
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| Invalid::Malformed)?;
    Timestamp::from_second(seconds).map_err(|_| Invalid::Malformed)
}

/// Read a whole tag-length-value, header included.
fn tlv_full<'a>(reader: &mut SliceReader<'a>, tag: Tag) -> Result<&'a [u8], Invalid> {
    let header = reader.peek_header().map_err(|_| Invalid::Malformed)?;
    if header.tag != tag {
        return Err(Invalid::Malformed);
    }
    let total = (header.encoded_len().map_err(|_| Invalid::Malformed)? + header.length)
        .map_err(|_| Invalid::Malformed)?;
    reader.read_slice(total).map_err(|_| Invalid::Malformed)
}

/// Read the content octets of a tag-length-value, header consumed.
fn tlv<'a>(reader: &mut SliceReader<'a>, tag: Tag) -> Result<&'a [u8], Invalid> {
    let header_len = reader
        .peek_header()
        .map_err(|_| Invalid::Malformed)?
        .encoded_len()
        .map_err(|_| Invalid::Malformed)?;
    let full = tlv_full(reader, tag)?;
    let header_len = usize::try_from(u32::from(header_len)).map_err(|_| Invalid::Malformed)?;
    Ok(&full[header_len..])
}

/// The tag of the next value, when there is one.
fn next_tag(reader: &mut SliceReader<'_>) -> Result<Option<Tag>, Invalid> {
    if reader.is_finished() {
        return Ok(None);
    }
    Ok(Some(
        reader.peek_header().map_err(|_| Invalid::Malformed)?.tag,
    ))
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::str::FromStr;

    use x509_cert::name::Name;

    use super::*;

    #[test]
    fn nonce_comparison_ignores_sign_padding() {
        assert!(nonce_matches(&[0x80, 0x01], Some(&[0x00, 0x80, 0x01])));
        assert!(nonce_matches(&[0x00, 0x00], Some(&[0x00])));
        assert!(nonce_matches(&[], Some(&[0x00])));
        assert!(!nonce_matches(&[0x01], None));
        assert!(!nonce_matches(&[], Some(&[0x00, 0x01])));
        assert!(!nonce_matches(&[0x01], Some(&[0x02])));
    }

    #[test]
    fn a_two_byte_policy_oid_is_read() {
        // `der` decodes OIDs through `const_oid`, which refuses a body under
        // three bytes; Apple's policy `1.2.3` encodes to two. The bytes are the
        // whole `06 02 2a 03` value.
        let value = [0x06, 0x02, 0x2a, 0x03];
        let mut reader = SliceReader::new(&value).expect("reader");
        assert_eq!(policy_oid(&mut reader).as_deref(), Ok("1.2.3"));
    }

    #[test]
    fn a_long_policy_oid_is_read() {
        let value = ObjectIdentifier::new("1.3.6.1.4.1.22542.3.2.0")
            .expect("OID")
            .to_der()
            .expect("DER");
        let mut reader = SliceReader::new(&value).expect("reader");
        assert_eq!(
            policy_oid(&mut reader).as_deref(),
            Ok("1.3.6.1.4.1.22542.3.2.0")
        );
    }

    #[test]
    fn a_policy_oid_ending_mid_arc_is_malformed() {
        let value = [0x06, 0x02, 0x2a, 0x86];
        let mut reader = SliceReader::new(&value).expect("reader");
        assert_eq!(policy_oid(&mut reader), Err(Invalid::Malformed));
    }

    #[test]
    fn a_fractional_general_time_keeps_the_whole_second() {
        // Lex Persona stamps milliseconds; `der` parses whole seconds only.
        let fractional = b"\x18\x1320261118212802.307Z";
        let whole = b"\x18\x0f20261118212802Z";
        assert_eq!(
            generalized_time(fractional).expect("fraction is dropped"),
            generalized_time(whole).expect("whole second")
        );
    }

    #[test]
    fn a_long_length_is_written_shortest() {
        let mut out = Vec::new();
        der_length(&mut out, 0x7f);
        der_length(&mut out, 0x80);
        der_length(&mut out, 0x0102);
        assert_eq!(out, [0x7f, 0x81, 0x80, 0x82, 0x01, 0x02]);
    }

    #[test]
    fn signed_attributes_keep_the_order_they_arrived_in() {
        // Apple and Lex Persona write the attributes out of DER order and sign
        // that order; `SetOfVec` would sort (and refuse) them.
        let attribute = |oid, value: &[u8]| x509_cert::attr::Attribute {
            oid,
            values: der::asn1::SetOfVec::try_from(vec![
                der::Any::from_der(value).expect("value parses"),
            ])
            .expect("set"),
        };
        let signing_time = attribute(
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5"),
            &[0x18, 0x01, 0x5a],
        );
        let content_type = attribute(OID_CONTENT_TYPE, &[0x06, 0x01, 0x2a]);

        // Handed over in the sorted order's reverse.
        let set = as_set(&[signing_time.clone(), content_type.clone()]).expect("set");

        let first = signing_time.to_der().expect("DER");
        let second = content_type.to_der().expect("DER");
        assert_eq!(set[0], 0x31);
        let body = &set[2..];
        assert_eq!(body.len(), first.len() + second.len());
        assert!(body.starts_with(&first));
        assert!(body.ends_with(&second));
    }

    #[test]
    fn expiry_is_after_not_after() {
        let at = |second| Timestamp::from_second(second).expect("in range");
        let not_after = at(1_000);

        // The branch directly: `webpki` shadows it end-to-end, so this is the
        // only coverage `Invalid::Expired` gets.
        assert!(expired(at(1_001), not_after));
        assert!(!expired(at(1_000), not_after));
        assert!(!expired(at(999), not_after));
    }

    #[test]
    fn record_algorithm_must_agree_with_imprint() {
        let imprint = Digest {
            alg: Alg::Sha256,
            bytes: vec![0; 32],
        };
        let tst = Tst {
            policy: None,
            imprint_alg: OID_SHA256,
            imprint: vec![0; 32],
            nonce: None,
            gen_time: Timestamp::from_second(0).expect("in range"),
            tsa: None,
        };

        assert!(imprint_matches(Alg::Sha256, &imprint, &tst));
        assert!(!imprint_matches(Alg::Sha512, &imprint, &tst));
    }

    /// A self-signed P-256 certificate carrying `eku` verbatim as its extended
    /// key usage extension, parsed back to DER.
    ///
    /// Only the extension line varies; everything else that `webpki` might care
    /// about is held constant, so a verdict difference comes from the EKU.
    fn certificate_with_eku(eku: &str) -> Certificate {
        certificate("/CN=eku-test", eku, None)
    }

    /// The same, under `subject`, with `san` as a subject alternative name
    /// extension when one is given.
    fn certificate(subject: &str, eku: &str, san: Option<&str>) -> Certificate {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let key = dir.path().join("key.pem");
        let certificate = dir.path().join("certificate.pem");
        let mut command = Command::new("openssl");
        command
            .args([
                "req",
                "-x509",
                "-sha256",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-pkeyopt",
                "ec_param_enc:named_curve",
                "-nodes",
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .args(["-days", "2", "-subj", subject])
            .arg("-addext")
            .arg("basicConstraints=critical,CA:FALSE")
            .arg("-addext")
            .arg(eku);
        if let Some(san) = san {
            command.arg("-addext").arg(san);
        }
        let status = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("openssl is available");
        assert!(status.success(), "openssl could not generate a certificate");

        let der = std::fs::read(&certificate).expect("read certificate");
        let der = DerCertificate::from_pem(std::str::from_utf8(&der).expect("certificate is PEM"))
            .expect("certificate parses");
        Certificate::from_der(der.as_bytes()).expect("certificate parses")
    }

    /// An attribute carrying already-encoded values.
    fn attribute_of(oid: ObjectIdentifier, values: Vec<Vec<u8>>) -> Attribute {
        let values = values
            .iter()
            .map(|value| der::Any::from_der(value).expect("value parses"))
            .collect::<Vec<_>>();
        Attribute {
            oid,
            values: der::asn1::SetOfVec::try_from(values).expect("values form a set"),
        }
    }

    /// One identifier for `certificate`, hashed with `digest`.
    ///
    /// The `hashAlgorithm` field is left out: v1 has no such field and a v2
    /// without one means SHA-256.
    fn ess_id(certificate: &Certificate, digest: ObjectIdentifier) -> EssId {
        let der = certificate.to_der().expect("certificate encodes");
        EssId {
            hash_algorithm: None,
            cert_hash: OctetString::new(hash(&digest, &der).expect("digest is supported"))
                .expect("hash fits"),
            _issuer_serial: None,
        }
    }

    /// The `SigningCertificate` (v1) or `SigningCertificateV2` (v2) attribute
    /// for `certificate`, under `oid`.
    ///
    /// v1 has no algorithm field and is always SHA-1; a v2 naming an algorithm
    /// hashes with it and a v2 without one means SHA-256.
    fn ess(oid: ObjectIdentifier, certificate: &Certificate, algorithm: Option<&str>) -> Attribute {
        let algorithm = algorithm.map(|oid| AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new(oid).expect("algorithm OID"),
            parameters: None,
        });
        let digest = if oid == OID_SIGNING_CERTIFICATE {
            OID_SHA1
        } else {
            algorithm
                .as_ref()
                .map_or(OID_SHA256, |algorithm| algorithm.oid)
        };
        let mut id = ess_id(certificate, digest);
        id.hash_algorithm = if oid == OID_SIGNING_CERTIFICATE {
            None
        } else {
            algorithm
        };
        let ids = EssIds { certs: vec![id] };
        attribute_of(oid, vec![ids.to_der().expect("identifiers encode")])
    }

    /// Run `signer_identification` over `attributes`.
    fn identification(attributes: Vec<Attribute>, signer: &Certificate) -> Result<(), Invalid> {
        let attributes = Attributes::try_from(attributes).expect("attributes form a set");
        signer_identification(&attributes, signer)
    }

    #[test]
    fn no_signer_identifier_is_ess_missing() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");

        assert_eq!(
            identification(Vec::new(), &signer),
            Err(Invalid::EssMissing)
        );
    }

    #[test]
    fn a_v1_identifier_naming_the_signer_is_accepted() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");

        assert_eq!(
            identification(vec![ess(OID_SIGNING_CERTIFICATE, &signer, None)], &signer),
            Ok(())
        );
    }

    #[test]
    fn a_v2_identifier_without_an_algorithm_is_sha256() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");

        assert_eq!(
            identification(
                vec![ess(OID_SIGNING_CERTIFICATE_V2, &signer, None)],
                &signer
            ),
            Ok(())
        );
    }

    #[test]
    fn both_identifiers_naming_the_signer_are_accepted() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");

        assert_eq!(
            identification(
                vec![
                    ess(OID_SIGNING_CERTIFICATE, &signer, None),
                    ess(OID_SIGNING_CERTIFICATE_V2, &signer, None),
                ],
                &signer
            ),
            Ok(())
        );
    }

    #[test]
    fn a_v2_identifier_naming_another_certificate_is_a_mismatch() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let other = certificate_with_eku("extendedKeyUsage=critical,timeStamping");

        // A match on the v1 attribute does not excuse the v2 one.
        assert_eq!(
            identification(
                vec![
                    ess(OID_SIGNING_CERTIFICATE, &signer, None),
                    ess(OID_SIGNING_CERTIFICATE_V2, &other, None),
                ],
                &signer
            ),
            Err(Invalid::EssMismatch)
        );
    }

    #[test]
    fn a_v1_identifier_naming_another_certificate_is_a_mismatch() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let other = certificate_with_eku("extendedKeyUsage=critical,timeStamping");

        assert_eq!(
            identification(vec![ess(OID_SIGNING_CERTIFICATE, &other, None)], &signer),
            Err(Invalid::EssMismatch)
        );
    }

    #[test]
    fn a_v2_identifier_with_the_wrong_algorithm_is_a_mismatch() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        // The hash is SHA-256 while the attribute says SHA-512.
        let mut id = ess_id(&signer, OID_SHA256);
        id.hash_algorithm = Some(AlgorithmIdentifierOwned {
            oid: OID_SHA512,
            parameters: None,
        });

        assert_eq!(
            identification(
                vec![attribute_of(
                    OID_SIGNING_CERTIFICATE_V2,
                    vec![
                        EssIds { certs: vec![id] }
                            .to_der()
                            .expect("identifiers encode")
                    ]
                )],
                &signer
            ),
            Err(Invalid::EssMismatch)
        );
    }

    #[test]
    fn a_v2_identifier_with_an_unsupported_algorithm_is_malformed() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        // MD5, which `hash` does not know.
        let id = ess_id(&signer, OID_SHA256);
        let mut id = id;
        id.hash_algorithm = Some(AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.2.5"),
            parameters: None,
        });

        assert_eq!(
            identification(
                vec![attribute_of(
                    OID_SIGNING_CERTIFICATE_V2,
                    vec![
                        EssIds { certs: vec![id] }
                            .to_der()
                            .expect("identifiers encode")
                    ]
                )],
                &signer
            ),
            Err(Invalid::EssMalformed)
        );
    }

    #[test]
    fn two_identifiers_of_one_version_are_malformed() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let other = certificate_with_eku("extendedKeyUsage=critical,timeStamping");

        // Identical values would be one DER element twice and cannot be built
        // as a set; the two attributes differ in the certificate they name.
        assert_eq!(
            identification(
                vec![
                    ess(OID_SIGNING_CERTIFICATE_V2, &signer, None),
                    ess(OID_SIGNING_CERTIFICATE_V2, &other, None),
                ],
                &signer
            ),
            Err(Invalid::EssMalformed)
        );
    }

    #[test]
    fn an_identifier_attribute_with_two_values_is_malformed() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let other = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let values = [&signer, &other]
            .into_iter()
            .map(|certificate| {
                EssIds {
                    certs: vec![ess_id(certificate, OID_SHA256)],
                }
                .to_der()
                .expect("identifiers encode")
            })
            .collect();

        assert_eq!(
            identification(
                vec![attribute_of(OID_SIGNING_CERTIFICATE_V2, values)],
                &signer
            ),
            Err(Invalid::EssMalformed)
        );
    }

    #[test]
    fn an_empty_cert_sequence_is_malformed() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let empty = EssIds { certs: Vec::new() };
        let empty = empty.to_der().expect("encodes");

        assert_eq!(
            identification(
                vec![attribute_of(OID_SIGNING_CERTIFICATE_V2, vec![empty])],
                &signer
            ),
            Err(Invalid::EssMalformed)
        );
    }

    #[test]
    fn a_trailing_identifier_limits_the_path_but_is_not_the_signer() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let other = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let ids = EssIds {
            certs: vec![ess_id(&signer, OID_SHA256), ess_id(&other, OID_SHA256)],
        };

        assert_eq!(
            identification(
                vec![attribute_of(
                    OID_SIGNING_CERTIFICATE_V2,
                    vec![ids.to_der().expect("encodes")]
                )],
                &signer
            ),
            Ok(())
        );
    }

    #[test]
    fn an_absent_tsa_name_is_accepted() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");

        assert_eq!(tsa_name(None, &signer), Ok(()));
    }

    #[test]
    fn the_signers_own_subject_is_accepted_as_tsa_name() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let name = GeneralName::DirectoryName(signer.tbs_certificate.subject.clone());

        assert_eq!(tsa_name(Some(&name), &signer), Ok(()));
    }

    #[test]
    fn another_subject_is_a_tsa_name_failure() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let name = GeneralName::DirectoryName(Name::from_str("CN=another").expect("DN parses"));

        assert_eq!(tsa_name(Some(&name), &signer), Err(Invalid::TsaName));
    }

    #[test]
    fn a_dns_name_among_the_san_names_is_accepted() {
        let signer = certificate(
            "/CN=eku-test",
            "extendedKeyUsage=critical,timeStamping",
            Some("subjectAltName=DNS:tsa.example"),
        );
        let name = GeneralName::DnsName(Ia5String::new("tsa.example").expect("DNS name"));

        assert_eq!(tsa_name(Some(&name), &signer), Ok(()));
    }

    #[test]
    fn a_dns_name_outside_the_san_names_is_a_tsa_name_failure() {
        let signer = certificate(
            "/CN=eku-test",
            "extendedKeyUsage=critical,timeStamping",
            Some("subjectAltName=DNS:tsa.example"),
        );
        let name = GeneralName::DnsName(Ia5String::new("other.example").expect("DNS name"));

        assert_eq!(tsa_name(Some(&name), &signer), Err(Invalid::TsaName));
    }

    #[test]
    fn another_general_name_choice_is_a_tsa_name_failure() {
        let signer = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        let name = GeneralName::UniformResourceIdentifier(
            Ia5String::new("https://tsa.example").expect("URI"),
        );

        assert_eq!(tsa_name(Some(&name), &signer), Err(Invalid::TsaName));
    }

    #[test]
    fn critical_sole_timestamping_eku_is_accepted() {
        let certificate = certificate_with_eku("extendedKeyUsage=critical,timeStamping");
        assert!(sole_timestamping_eku(&certificate));
    }

    #[test]
    fn non_critical_timestamping_eku_is_rejected() {
        let certificate = certificate_with_eku("extendedKeyUsage=timeStamping");
        assert!(!sole_timestamping_eku(&certificate));
    }

    #[test]
    fn non_critical_dual_purpose_eku_is_rejected() {
        let certificate = certificate_with_eku("extendedKeyUsage=serverAuth,timeStamping");
        assert!(!sole_timestamping_eku(&certificate));
    }

    #[test]
    fn critical_dual_purpose_eku_is_rejected() {
        let certificate = certificate_with_eku("extendedKeyUsage=critical,serverAuth,timeStamping");
        assert!(!sole_timestamping_eku(&certificate));
    }

    #[test]
    fn critical_any_extended_key_usage_is_rejected() {
        let certificate = certificate_with_eku("extendedKeyUsage=critical,anyExtendedKeyUsage");
        assert!(!sole_timestamping_eku(&certificate));
    }

    #[test]
    fn fixture_signer_eku_is_accepted() {
        let response = include_bytes!("../../tests/fixtures/resp_granted_freetsa.tsr");
        let token = match crate::tsa::parse_response(response).expect("fixture parses") {
            crate::tsa::RawResponse::Granted { token, .. } => token,
            crate::tsa::RawResponse::Rejected { .. } => panic!("fixture is granted"),
        };
        let signer = signer_certificate(&token).expect("fixture signer resolves");
        let signer = Certificate::from_der(&signer).expect("fixture signer parses");

        assert!(sole_timestamping_eku(&signer));
    }
}
