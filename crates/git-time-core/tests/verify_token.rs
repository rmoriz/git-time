//! Fail-closed verification of one RFC 3161 token against pinned anchors.
//!
//! Every case runs against the committed FreeTSA fixture, offline. The fixture
//! is only evidence once the FreeTSA root is pinned; with no anchor the very
//! same bytes are `Untrusted`.
//!
//! The throwaway tokens are minted with the platform `openssl`, which may be
//! LibreSSL or OpenSSL 1.1.1: certificates are built with `-sha256` and a named
//! curve (their SHA-1 and explicit-parameter defaults are outside what `webpki`
//! verifies), the CA serial lives in its own file (`-CAcreateserial` races in the
//! shared temp directory) and CA extensions come from a config section (1.1.1
//! refuses `-addext basicConstraints`, which it adds itself), while the tests
//! for SHA-1 and explicit parameters ask for those shapes on purpose. They are
//! signed with `-cades`, because the verifier requires the ESS
//! signing-certificate attribute and `cms -sign` leaves it out by default.

use std::path::{Path, PathBuf};
use std::process::Command;

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::Any;
use der::{Decode, Encode};
use git_time_core::imprint::{Alg, Digest, digest};
use git_time_core::store::TokenRecord;
use git_time_core::trust::AnchorStore;
use git_time_core::tsa::{self, RawResponse};
use git_time_core::verify::{self, Invalid, TokenVerdict};
use jiff::Timestamp;

/// The granted response; the token is extracted from it, as the pool does.
const GRANTED: &[u8] = include_bytes!("fixtures/resp_granted_freetsa.tsr");
/// The exact pre-image the token's imprint answers.
const PAYLOAD: &[u8] = include_bytes!("fixtures/payload.bin");
/// The pinned FreeTSA root.
const ROOT_PEM: &str = include_str!("fixtures/freetsa_root.pem");

/// The FreeTSA id every record carries.
const ID: &str = "freetsa";

/// The policy FreeTSA actually issued under.
const POLICY: &str = "1.2.3.4.1";

/// The nonce the fixture request carried, without its DER sign pad.
const NONCE: [u8; 8] = [0xc5, 0x24, 0xf1, 0x2c, 0x8b, 0xb3, 0xfb, 0xd1];

/// The token's genTime, 2026-11-18T05:38:12Z.
fn gen_time() -> Timestamp {
    "2026-11-18T05:38:12Z"
        .parse()
        .expect("fixture genTime is RFC 3339")
}

/// A time range comfortably around [`gen_time`].
fn wide_range() -> std::ops::Range<Timestamp> {
    Timestamp::MIN..Timestamp::MAX
}

/// The raw `timeStampToken` out of the granted response.
fn token() -> Vec<u8> {
    match tsa::parse_response(GRANTED).expect("fixture response parses") {
        RawResponse::Granted { token, .. } => token,
        RawResponse::Rejected { status, .. } => panic!("fixture rejected with status {status}"),
    }
}

/// The record a successful seal would have produced for this fixture.
fn record() -> TokenRecord {
    TokenRecord {
        id: ID.to_owned(),
        alg: Alg::Sha256,
        policy: Some(POLICY.to_owned()),
        nonce: NONCE.to_vec(),
        token: token(),
    }
}

/// The imprint of the untouched fixture pre-image.
fn imprint() -> Digest {
    Digest {
        alg: Alg::Sha256,
        bytes: digest(Alg::Sha256, PAYLOAD),
    }
}

/// A temporary directory holding a PEM bundle per test.
fn scratch() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("temp dir")
}

/// Write `bundle` under `name` in `dir` and return its path.
fn bundle(dir: &Path, name: &str, bundle: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bundle).expect("write anchor bundle");
    path
}

/// A store pinning the FreeTSA root for [`ID`].
fn anchors(dir: &Path) -> AnchorStore {
    let path = bundle(dir, "freetsa.pem", ROOT_PEM);
    AnchorStore::load(&[(ID.to_owned(), path)]).expect("fixture root loads")
}

/// A config file carrying the CA extensions.
///
/// `-addext basicConstraints` duplicates the extension OpenSSL 1.1.1 adds by
/// itself for `-x509`, and `webpki` refuses a duplicated extension; a config
/// section is written exactly once by every version.
fn ca_config(dir: &Path) -> PathBuf {
    let path = dir.join("ca.cnf");
    std::fs::write(
        &path,
        "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\ncommonName=Common Name\n\
         [v3_ca]\nbasicConstraints=critical,CA:TRUE\n\
         keyUsage=critical,keyCertSign,cRLSign\n",
    )
    .expect("write CA config");
    path
}

/// Generate a throwaway self-signed CA and return its certificate path.
fn throwaway_root(dir: &Path) -> PathBuf {
    let key = dir.join("throwaway-key.pem");
    let cert = dir.join("throwaway-ca.pem");
    let config = ca_config(dir);
    let status = Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-sha256")
        .arg("-newkey")
        .arg("rsa:2048")
        .arg("-nodes")
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .arg("-days")
        .arg("2")
        .arg("-subj")
        .arg("/CN=throwaway-ca")
        .arg("-config")
        .arg(&config)
        .args(["-extensions", "v3_ca"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl is available");
    assert!(status.success(), "openssl could not generate a CA");
    cert
}

#[test]
fn genuine_token_with_pinned_root_is_valid() {
    let dir = scratch();
    let anchors = anchors(dir.path());

    assert_eq!(
        verify::token(&record(), &imprint(), wide_range(), &anchors),
        TokenVerdict::Valid {
            gen_time: gen_time(),
            tsa: "www.freetsa.org".to_owned(),
            serial: "00c2e986160da8e9cd".to_owned(),
        }
    );
}

/// LibreSSL's `openssl ts -reply` signs SHA-1 whatever the query asks for, so a
/// token in the wild may name SHA-1 in its signer info. `ring` has no SHA-1
/// algorithm, and the token must still verify.
#[test]
fn a_sha1_signed_token_is_valid() {
    let dir = scratch();
    let (token, ca_pem) =
        throwaway_tsa_token_signed_with(dir.path(), "critical,timeStamping", "sha1");
    let anchors = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
    let record = TokenRecord {
        id: ID.to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: NONCE.to_vec(),
        token,
    };

    assert!(
        verify::token(&record, &imprint(), wide_range(), &anchors).is_valid(),
        "a SHA-1 signature is legal: {:?}",
        verify::token(&record, &imprint(), wide_range(), &anchors)
    );
}

/// RFC 5480 allows the EC parameters to be the full `SpecifiedECDomain`
/// instead of a named curve; LibreSSL writes exactly that by default. `webpki`
/// only looks at the point, so the token must verify without a curve OID.
#[test]
fn an_explicit_parameter_curve_is_valid() {
    let dir = scratch();
    let (token, ca_pem) =
        throwaway_tsa_token_with(dir.path(), "critical,timeStamping", "sha256", "explicit");
    let anchors = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
    let record = TokenRecord {
        id: ID.to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: NONCE.to_vec(),
        token,
    };

    assert!(
        verify::token(&record, &imprint(), wide_range(), &anchors).is_valid(),
        "explicit parameters are legal: {:?}",
        verify::token(&record, &imprint(), wide_range(), &anchors)
    );
}

#[test]
fn altered_pre_image_is_an_imprint_failure() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut altered = PAYLOAD.to_vec();
    altered[0] ^= 0x01;

    assert_eq!(
        verify::token(
            &record(),
            &Digest {
                alg: Alg::Sha256,
                bytes: digest(Alg::Sha256, &altered),
            },
            wide_range(),
            &anchors,
        ),
        TokenVerdict::Invalid(Invalid::Imprint)
    );
}

#[test]
fn wrong_nonce_is_a_nonce_failure() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut record = record();
    record.nonce[7] ^= 0x01;

    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Nonce)
    );
}

#[test]
fn no_anchor_is_untrusted() {
    let anchors = AnchorStore::load(&[]).expect("an empty store loads");

    assert_eq!(
        verify::token(&record(), &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Untrusted)
    );
}

#[test]
fn different_root_is_untrusted() {
    let dir = scratch();
    let path = throwaway_root(dir.path());
    let anchors = AnchorStore::load(&[(ID.to_owned(), path)]).expect("throwaway root loads");

    assert_eq!(
        verify::token(&record(), &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Untrusted)
    );
}

#[test]
fn gen_time_outside_the_range_is_cert_not_valid_at_gen_time() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let start = Timestamp::from_second(gen_time().as_second() + 1).expect("in range");

    assert_eq!(
        verify::token(&record(), &imprint(), start..Timestamp::MAX, &anchors),
        TokenVerdict::Invalid(Invalid::CertNotValidAtGenTime)
    );
}

#[test]
fn policy_mismatch_is_a_policy_failure() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut record = record();
    record.policy = Some("1.2.3".to_owned());

    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Policy)
    );
}

#[test]
fn absent_recorded_policy_still_verifies() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut record = record();
    record.policy = None;

    assert!(matches!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Valid { .. }
    ));
}

/// Write `length` as a DER length.
fn der_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(u8::try_from(length).expect("short length fits"));
        return;
    }
    let bytes: Vec<u8> = length
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    out.push(0x80 | u8::try_from(bytes.len()).expect("length of a length"));
    out.extend_from_slice(&bytes);
}

/// Read the DER length octets at `at`, returning the length and their count.
///
/// `at` points at the length, i.e. just past the tag byte.
fn der_len(bytes: &[u8], at: usize) -> (usize, usize) {
    let first = bytes[at];
    if first < 0x80 {
        return (usize::from(first), 1);
    }
    let octets = usize::from(first & 0x7f);
    let mut length = 0;
    for byte in &bytes[at + 1..at + 1 + octets] {
        length = (length << 8) | usize::from(*byte);
    }
    (length, 1 + octets)
}

/// Drop the mandatory `policy` field from a TSTInfo, keeping the DER valid.
fn without_policy_field(tst_info: &[u8]) -> Vec<u8> {
    assert_eq!(tst_info[0], 0x30, "TSTInfo is a SEQUENCE");
    let (sequence_len, sequence_length_octets) = der_len(tst_info, 1);
    let body_start = 1 + sequence_length_octets;
    assert_eq!(body_start + sequence_len, tst_info.len());

    let body = &tst_info[body_start..];
    assert_eq!(body[0], 0x02, "first field is the version");
    let (version_len, version_length_octets) = der_len(body, 1);
    let version_end = 1 + version_length_octets + version_len;

    assert_eq!(body[version_end], 0x06, "second field is the policy");
    let (policy_len, policy_length_octets) = der_len(body, version_end + 1);
    let tail = &body[version_end + 1 + policy_length_octets + policy_len..];

    let mut out = vec![0x30];
    der_length(&mut out, version_end + tail.len());
    out.extend_from_slice(&body[..version_end]);
    out.extend_from_slice(tail);
    out
}

/// Drop the `tsa` field from a TSTInfo, keeping the DER valid.
///
/// The throwaway tokens reuse the fixture's TSTInfo, which carries FreeTSA's
/// `tsa` name; under a throwaway signer that name is not the signer's and the
/// token would be refused as `tsa-name`. The field is the final one (`a0`, long
/// form), so it and anything after it — extensions in some replies, which are
/// informational — goes. The `SEQUENCE` length is written afresh instead of
/// patching its digits.
fn remove_tsa(tst: &mut Vec<u8>) {
    assert_eq!(tst[0], 0x30, "TSTInfo is a SEQUENCE");
    let (sequence_len, sequence_length_octets) = der_len(tst, 1);
    let body_start = 1 + sequence_length_octets;
    assert_eq!(body_start + sequence_len, tst.len());

    let start = tst
        .windows(2)
        .rposition(|window| window[0] == 0xa0 && window[1] == 0x82)
        .expect("the fixture TSTInfo carries a tsa name");
    let (tsa_len, tsa_length_octets) = der_len(tst, start + 1);
    assert_eq!(start + 1 + tsa_length_octets + tsa_len, tst.len());

    let mut body = tst[body_start..start].to_vec();
    let mut out = vec![0x30];
    der::Length::try_from(body.len())
        .expect("the body fits a DER length")
        .encode(&mut out)
        .expect("the length encodes");
    out.append(&mut body);
    *tst = out;
}

/// Re-encode `token` with its TSTInfo replaced by `transform` of the old one.
///
/// The CMS signature is left stale on purpose: a case that must be caught by
/// the signed-attribute binding would otherwise be caught by the signature.
fn rewrap_econtent(token: &[u8], transform: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut content_info = ContentInfo::from_der(token).expect("fixture token parses");
    let mut signed_data = SignedData::from_der(
        &content_info
            .content
            .to_der()
            .expect("SignedData re-encodes"),
    )
    .expect("fixture SignedData parses");
    let econtent = signed_data
        .encap_content_info
        .econtent
        .take()
        .expect("fixture carries a TSTInfo");
    // `econtent` is an OCTET STRING whose value is the TSTInfo DER.
    let rewritten = transform(econtent.value());
    let mut octets = vec![0x04];
    der_length(&mut octets, rewritten.len());
    octets.extend_from_slice(&rewritten);
    signed_data.encap_content_info.econtent =
        Some(Any::from_der(&octets).expect("econtent re-encodes"));
    content_info.content = Any::from_der(&signed_data.to_der().expect("SignedData re-encodes"))
        .expect("SignedData is a valid Any");
    content_info.to_der().expect("token re-encodes")
}

/// The TSTInfo DER a token carries.
fn tst_info(token: &[u8]) -> Vec<u8> {
    let content_info = ContentInfo::from_der(token).expect("fixture token parses");
    let signed_data = SignedData::from_der(
        &content_info
            .content
            .to_der()
            .expect("SignedData re-encodes"),
    )
    .expect("fixture SignedData parses");
    signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .expect("fixture carries a TSTInfo")
        .value()
        .to_vec()
}

/// The signed-attribute OIDs of the token's signer.
fn signed_attribute_oids(token: &[u8]) -> Vec<der::asn1::ObjectIdentifier> {
    let content_info = ContentInfo::from_der(token).expect("fixture token parses");
    let signed_data = SignedData::from_der(
        &content_info
            .content
            .to_der()
            .expect("SignedData re-encodes"),
    )
    .expect("fixture SignedData parses");
    signed_data
        .signer_infos
        .0
        .get(0)
        .expect("one signer")
        .signed_attrs
        .as_ref()
        .expect("signed attributes")
        .iter()
        .map(|attribute| attribute.oid)
        .collect()
}

/// Re-encode `token` with its signed attributes rewritten by `transform`.
///
/// The signature is stale afterwards; only cases answered before signature
/// verification (the attribute checks) may use this.
fn with_signed_attributes(
    token: &[u8],
    transform: impl FnOnce(Vec<x509_cert::attr::Attribute>) -> Vec<x509_cert::attr::Attribute>,
) -> Vec<u8> {
    let mut content_info = ContentInfo::from_der(token).expect("fixture token parses");
    let mut signed_data = SignedData::from_der(
        &content_info
            .content
            .to_der()
            .expect("SignedData re-encodes"),
    )
    .expect("fixture SignedData parses");
    let mut signer_infos = signed_data.signer_infos.clone().0.into_vec();
    let signer_info = signer_infos.get_mut(0).expect("one signer");
    let attributes = signer_info
        .signed_attrs
        .take()
        .expect("signed attributes")
        .into_vec();
    signer_info.signed_attrs =
        Some(der::asn1::SetOfVec::from_iter(transform(attributes)).expect("attributes re-encode"));
    signed_data.signer_infos = cms::signed_data::SignerInfos(
        der::asn1::SetOfVec::from_iter(signer_infos).expect("signer infos re-encode"),
    );
    content_info.content = Any::from_der(&signed_data.to_der().expect("SignedData re-encodes"))
        .expect("SignedData is a valid Any");
    content_info.to_der().expect("token re-encodes")
}

/// The offset of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
        .expect("needle is present")
}

/// DER `AlgorithmIdentifier` for SHA-256 plus the `OCTET STRING` header the
/// message imprint uses: the offset just past it is the first digest byte.
const SHA256_IMPRINT_HEADER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
    0x20,
];

#[test]
fn altered_tst_info_imprint_is_malformed() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut record = record();
    let trial = tst_info(&record.token);
    let digest_start = find(&trial, SHA256_IMPRINT_HEADER) + SHA256_IMPRINT_HEADER.len();
    record.token = rewrap_econtent(&record.token, |_| {
        let mut tst = trial.clone();
        tst[digest_start] ^= 0x01;
        tst
    });
    record.nonce = NONCE.to_vec();

    // The signature still covers the untouched signed attributes, so only the
    // messageDigest binding can notice that the TSTInfo moved.
    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Malformed)
    );
}

#[test]
fn shifted_gen_time_is_malformed() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut record = record();
    let trial = tst_info(&record.token);
    let gen_time_start = find(&trial, &[0x18, 0x0f]);
    let digits = &trial[gen_time_start + 2..gen_time_start + 16];
    assert!(
        digits.iter().all(u8::is_ascii_digit),
        "fixture genTime is a DER GeneralizedTime"
    );
    // The hour holds two digits at offset 8 of `YYYYMMDDHHMMSSZ`; its first
    // digit is `0`, `1` or `2`, so 1 keeps the date and the length.
    let hour = gen_time_start + 2 + 8;
    record.token = rewrap_econtent(&record.token, |_| {
        let mut tst = trial.clone();
        tst[hour] = b'1';
        tst
    });

    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Malformed)
    );
}

#[test]
fn removed_message_digest_attribute_is_malformed() {
    const OID_MESSAGE_DIGEST: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut record = record();
    let before = signed_attribute_oids(&record.token);
    assert!(
        before.contains(&OID_MESSAGE_DIGEST),
        "fixture carries a messageDigest"
    );
    record.token = with_signed_attributes(&record.token, |attributes| {
        attributes
            .into_iter()
            .filter(|attribute| attribute.oid != OID_MESSAGE_DIGEST)
            .collect()
    });
    let after = signed_attribute_oids(&record.token);
    assert_eq!(after.len() + 1, before.len());

    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Malformed)
    );
}

#[test]
fn misnamed_content_type_attribute_is_malformed() {
    const OID_CONTENT_TYPE: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
    const OID_DATA: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut record = record();
    assert!(signed_attribute_oids(&record.token).contains(&OID_CONTENT_TYPE));
    let data_der = OID_DATA.to_der().expect("OID encodes");
    record.token = with_signed_attributes(&record.token, |attributes| {
        attributes
            .into_iter()
            .map(|mut attribute| {
                if attribute.oid == OID_CONTENT_TYPE {
                    attribute.values = der::asn1::SetOfVec::from_iter([
                        Any::from_der(&data_der).expect("OID is a valid Any")
                    ])
                    .expect("one value re-encodes");
                }
                attribute
            })
            .collect()
    });

    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Malformed)
    );
}

#[test]
fn record_algorithm_disagreeing_with_imprint_is_an_imprint_failure() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut record = record();
    record.alg = Alg::Sha512;

    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Imprint)
    );
}

/// Mint a throwaway TSA (self-signed P-256 CA plus a P-256 leaf whose extended
/// key usage is `eku`), wrap the fixture's TSTInfo in a CMS signed by it and
/// return the token together with the CA certificate path.
///
/// The token carries its own CA certificate. Nothing about it chains to
/// FreeTSA.
fn throwaway_tsa_token(dir: &Path, eku: &str) -> (Vec<u8>, PathBuf) {
    throwaway_tsa_token_with(dir, eku, "sha256", "named_curve")
}

/// The same, signed with `digest` instead of SHA-256.
fn throwaway_tsa_token_signed_with(dir: &Path, eku: &str, digest: &str) -> (Vec<u8>, PathBuf) {
    throwaway_tsa_token_with(dir, eku, digest, "named_curve")
}

/// The same, with the key's curve written as `enc` (`named_curve` or the
/// `explicit` domain parameters LibreSSL writes by default).
fn throwaway_tsa_token_with(dir: &Path, eku: &str, digest: &str, enc: &str) -> (Vec<u8>, PathBuf) {
    throwaway_tsa_token_under(dir, eku, digest, enc, false)
}

/// A token whose signer hangs off an intermediate CA that carries no extended
/// key usage at all, with a critical `timeStamping` signer.
///
/// This is the shape of the DFN, Belgium and CESnet chains. RFC 5280 makes a
/// CA's EKU a restriction only when it is present, so the path must verify.
fn throwaway_chain_token(dir: &Path) -> (Vec<u8>, PathBuf) {
    throwaway_tsa_token_under(dir, "critical,timeStamping", "sha256", "named_curve", true)
}

fn throwaway_tsa_token_under(
    dir: &Path,
    eku: &str,
    digest: &str,
    enc: &str,
    intermediate: bool,
) -> (Vec<u8>, PathBuf) {
    let ca_key = dir.join("tsa-ca-key.pem");
    let ca_pem = dir.join("tsa-ca.pem");
    let int_key = dir.join("tsa-int-key.pem");
    let int_csr = dir.join("tsa-int.csr");
    let int_pem = dir.join("tsa-int.pem");
    let leaf_key = dir.join("tsa-leaf-key.pem");
    let leaf_csr = dir.join("tsa-leaf.csr");
    let leaf_pem = dir.join("tsa-leaf.pem");
    let leaf_ext = dir.join("tsa-leaf.ext");
    let config = ca_config(dir);

    let openssl = |args: &[&std::ffi::OsStr]| {
        let status = Command::new("openssl")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl is available");
        assert!(status.success(), "openssl {args:?} failed");
    };

    openssl(&[
        "req".as_ref(),
        "-x509".as_ref(),
        "-sha256".as_ref(),
        "-newkey".as_ref(),
        "ec".as_ref(),
        "-pkeyopt".as_ref(),
        "ec_paramgen_curve:P-256".as_ref(),
        "-pkeyopt".as_ref(),
        "ec_param_enc:named_curve".as_ref(),
        "-nodes".as_ref(),
        "-keyout".as_ref(),
        ca_key.as_os_str(),
        "-out".as_ref(),
        ca_pem.as_os_str(),
        "-days".as_ref(),
        "2".as_ref(),
        "-subj".as_ref(),
        "/CN=throwaway-tsa-ca".as_ref(),
        "-config".as_ref(),
        config.as_os_str(),
        "-extensions".as_ref(),
        "v3_ca".as_ref(),
    ]);

    if intermediate {
        openssl(&[
            "req".as_ref(),
            "-new".as_ref(),
            "-newkey".as_ref(),
            "ec".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_paramgen_curve:P-256".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_param_enc:named_curve".as_ref(),
            "-nodes".as_ref(),
            "-keyout".as_ref(),
            int_key.as_os_str(),
            "-out".as_ref(),
            int_csr.as_os_str(),
            "-subj".as_ref(),
            "/CN=throwaway-tsa-intermediate".as_ref(),
        ]);
        let int_serial = dir.join("tsa-int.srl");
        std::fs::write(&int_serial, "01\n").expect("write serial");
        // `v3_ca` carries `keyCertSign` and no EKU, which is the point.
        openssl(&[
            "x509".as_ref(),
            "-req".as_ref(),
            "-sha256".as_ref(),
            "-in".as_ref(),
            int_csr.as_os_str(),
            "-CA".as_ref(),
            ca_pem.as_os_str(),
            "-CAkey".as_ref(),
            ca_key.as_os_str(),
            "-CAserial".as_ref(),
            int_serial.as_os_str(),
            "-out".as_ref(),
            int_pem.as_os_str(),
            "-days".as_ref(),
            "2".as_ref(),
            "-extfile".as_ref(),
            config.as_os_str(),
            "-extensions".as_ref(),
            "v3_ca".as_ref(),
        ]);
    }

    openssl(&[
        "req".as_ref(),
        "-new".as_ref(),
        "-newkey".as_ref(),
        "ec".as_ref(),
        "-pkeyopt".as_ref(),
        "ec_paramgen_curve:P-256".as_ref(),
        "-pkeyopt".as_ref(),
        format!("ec_param_enc:{enc}").as_ref(),
        "-nodes".as_ref(),
        "-keyout".as_ref(),
        leaf_key.as_os_str(),
        "-out".as_ref(),
        leaf_csr.as_os_str(),
        "-subj".as_ref(),
        "/CN=throwaway-tsa".as_ref(),
    ]);
    let mut extensions =
        String::from("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n");
    if !eku.is_empty() {
        extensions.push_str(&format!("extendedKeyUsage={eku}\n"));
    }
    std::fs::write(&leaf_ext, extensions).expect("write leaf extensions");
    // LibreSSL's `-CAcreateserial` writes its serial into the shared temp
    // directory, not next to the CA, so parallel fixtures race on one file.
    // A distinct serial: the intermediate above shares the leaf's issuer
    // otherwise, and the parse drops the signer out of the intermediates by
    // serial alone.
    let serial_file = dir.join("tsa-leaf.srl");
    std::fs::write(&serial_file, "0B\n").expect("write serial");
    let (issuer_pem, issuer_key) = if intermediate {
        (&int_pem, &int_key)
    } else {
        (&ca_pem, &ca_key)
    };
    openssl(&[
        "x509".as_ref(),
        "-req".as_ref(),
        "-sha256".as_ref(),
        "-in".as_ref(),
        leaf_csr.as_os_str(),
        "-CA".as_ref(),
        issuer_pem.as_os_str(),
        "-CAkey".as_ref(),
        issuer_key.as_os_str(),
        "-CAserial".as_ref(),
        serial_file.as_os_str(),
        "-out".as_ref(),
        leaf_pem.as_os_str(),
        "-days".as_ref(),
        "2".as_ref(),
        "-extfile".as_ref(),
        leaf_ext.as_os_str(),
    ]);

    // The fixture's TSTInfo, signed by the throwaway TSA as a CMS `SignedData`.
    // `openssl ts -reply` cannot be used: it rejects any signer whose EKU is not
    // both critical and sole, which is exactly what the negative cases vary.
    // `openssl cms -sign` accepts them; `-certfile` puts the chain in the token.
    // `-cades` writes the ESS signing-certificate attribute the verifier
    // requires, which plain `cms -sign` leaves out.
    //
    // The certificates start "now", so the fixture's 05:38Z genTime would be
    // before their notBefore; the stamp is moved to now (same length) and only
    // then signed.
    let mut tst = tst_info(&token());
    // The fixture's `tsa` names FreeTSA and would not match the throwaway
    // signer; the ESS identifier below is written by openssl and does match.
    remove_tsa(&mut tst);
    let now = Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .datetime();
    let stamp = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        now.year(),
        u8::try_from(now.month()).expect("month fits"),
        u8::try_from(now.day()).expect("day fits"),
        u8::try_from(now.hour()).expect("hour fits"),
        u8::try_from(now.minute()).expect("minute fits"),
        u8::try_from(now.second()).expect("second fits"),
    );
    let gen_time_start = find(&tst, &[0x18, 0x0f]) + 2;
    tst[gen_time_start..gen_time_start + stamp.len()].copy_from_slice(stamp.as_bytes());
    let tst_path = dir.join("tst-info.der");
    std::fs::write(&tst_path, &tst).expect("write TSTInfo");
    let response = dir.join("throwaway-token.der");
    let chain = if intermediate { &int_pem } else { &ca_pem };
    openssl(&[
        "cms".as_ref(),
        "-sign".as_ref(),
        "-binary".as_ref(),
        "-nodetach".as_ref(),
        "-in".as_ref(),
        tst_path.as_os_str(),
        "-signer".as_ref(),
        leaf_pem.as_os_str(),
        "-inkey".as_ref(),
        leaf_key.as_os_str(),
        "-certfile".as_ref(),
        chain.as_os_str(),
        "-md".as_ref(),
        digest.as_ref(),
        "-cades".as_ref(),
        "-outform".as_ref(),
        "DER".as_ref(),
        "-econtent_type".as_ref(),
        "1.2.840.113549.1.9.16.1.4".as_ref(),
        "-out".as_ref(),
        response.as_os_str(),
    ]);

    let token = std::fs::read(&response).expect("read throwaway token");
    (token, ca_pem)
}

#[test]
fn token_cannot_supply_its_own_anchor() {
    let dir = scratch();
    let (token, ca_pem) = throwaway_tsa_token(dir.path(), "critical,timeStamping");
    let record = TokenRecord {
        id: ID.to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: NONCE.to_vec(),
        token: token.clone(),
    };

    // The FreeTSA root is pinned and the token brings a self-signed CA.
    let free_tsa = anchors(dir.path());
    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &free_tsa),
        TokenVerdict::Invalid(Invalid::Untrusted)
    );

    // The same bytes are evidence once *that* CA is pinned instead, so the
    // refusal above is the absent pin and not some other defect.
    let own = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
    assert!(
        verify::token(&record, &imprint(), wide_range(), &own).is_valid(),
        "throwaway token is otherwise well formed"
    );
}

#[test]
fn a_throwaway_token_carries_the_signer_identifier_and_verifies() {
    const OID_SIGNING_CERTIFICATE_V2: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

    let dir = scratch();
    let (token, ca_pem) = throwaway_tsa_token(dir.path(), "critical,timeStamping");
    let anchors = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
    let record = TokenRecord {
        id: ID.to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: NONCE.to_vec(),
        token,
    };

    assert!(
        signed_attribute_oids(&record.token).contains(&OID_SIGNING_CERTIFICATE_V2),
        "the token carries the identifier the verifier requires"
    );
    assert!(
        verify::token(&record, &imprint(), wide_range(), &anchors).is_valid(),
        "the identifier names the signer: {:?}",
        verify::token(&record, &imprint(), wide_range(), &anchors)
    );
}

#[test]
fn a_flipped_cert_hash_is_ess_mismatch_not_a_signature_error() {
    let dir = scratch();
    let (token, ca_pem) = throwaway_tsa_token(dir.path(), "critical,timeStamping");
    let anchors = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
    let mut record = TokenRecord {
        id: ID.to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: NONCE.to_vec(),
        token,
    };

    let signer = git_time_core::verify::signer_certificate(&record.token).expect("signer resolves");
    let hash = digest(Alg::Sha256, &signer);
    let at = find(&record.token, &hash);
    record.token[at] ^= 0x01;

    // Flipping the hash also breaks the signature over the attributes; the
    // identifier has to be judged first and say what actually moved.
    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::EssMismatch)
    );
}

#[test]
fn a_ca_without_eku_still_chains() {
    // RFC 5280 §4.2.1.12: a CA's EKU restricts the path only when it is present.
    // DFN, Belgium and CESnet issue from CAs that carry none, and `webpki`'s
    // strict `KeyUsage::required` refuses them; `required_if_present` must not.
    let dir = scratch();
    let (token, ca_pem) = throwaway_chain_token(dir.path());
    let anchors = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
    let record = TokenRecord {
        id: ID.to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: NONCE.to_vec(),
        token,
    };

    assert!(
        verify::token(&record, &imprint(), wide_range(), &anchors).is_valid(),
        "a CA without an EKU must not break the path"
    );
}

#[test]
fn a_signer_without_eku_is_untrusted() {
    // The signer is held to the strict rule even though CAs are not: with no
    // EKU there is nothing proving the certificate is a TSA and nothing else.
    let dir = scratch();
    let (token, ca_pem) = throwaway_tsa_token_under(dir.path(), "", "sha256", "named_curve", false);
    let anchors = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
    let record = TokenRecord {
        id: ID.to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: NONCE.to_vec(),
        token,
    };

    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Untrusted)
    );
}

#[test]
fn dual_purpose_or_non_critical_eku_is_untrusted() {
    // `webpki` accepts both: it only wants `timeStamping` somewhere in the EKU
    // and ignores the criticality flag. A pinned, otherwise complete chain
    // isolates the strict RFC 3161 §2.3 rule enforced here.
    for eku in ["critical,serverAuth,timeStamping", "timeStamping"] {
        let dir = scratch();
        let (token, ca_pem) = throwaway_tsa_token(dir.path(), eku);
        let anchors = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
        let record = TokenRecord {
            id: ID.to_owned(),
            alg: Alg::Sha256,
            policy: None,
            nonce: NONCE.to_vec(),
            token,
        };

        assert_eq!(
            verify::token(&record, &imprint(), wide_range(), &anchors),
            TokenVerdict::Invalid(Invalid::Untrusted),
            "{eku}"
        );
    }
}

/// Re-encode `token` with a TSTInfo that carries no policy.
///
/// The CMS signature is left stale on purpose: the verdict under test comes
/// before the signature is looked at.
fn token_without_policy(token: &[u8]) -> Vec<u8> {
    rewrap_econtent(token, without_policy_field)
}

#[test]
fn recorded_policy_without_tst_info_policy_is_a_policy_failure() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let mut record = record();
    record.token = token_without_policy(&record.token);

    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors),
        TokenVerdict::Invalid(Invalid::Policy)
    );
}

#[test]
fn truncated_tokens_are_malformed_without_panicking() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let token = token();
    let record = record();

    for end in 0..300 {
        assert_eq!(
            verify::token(
                &TokenRecord {
                    token: token[..end].to_vec(),
                    ..record.clone()
                },
                &imprint(),
                wide_range(),
                &anchors,
            ),
            TokenVerdict::Invalid(Invalid::Malformed),
            "prefix of {end} bytes"
        );
    }
}

#[test]
fn anchor_bundle_keeps_root_then_intermediates() {
    let dir = scratch();
    // The token's signer is the leaf; use it as the bundle's second entry.
    let record = record();
    let leaf = git_time_core::verify::signer_certificate(&record.token).expect("signer parses");
    let leaf_pem = sigstore_types::DerCertificate::new(leaf).to_pem();
    let path = bundle(
        dir.path(),
        "two-certs.pem",
        &format!("{ROOT_PEM}{leaf_pem}"),
    );

    let anchors = AnchorStore::load(&[(ID.to_owned(), path)]).expect("two certificates load");
    let anchor = anchors.anchor(ID).expect("the id is pinned");

    assert!(anchor.intermediates.len() == 1);
    assert_eq!(
        anchor.roots[0].as_bytes(),
        sigstore_types::DerCertificate::from_pem(ROOT_PEM)
            .expect("fixture root parses")
            .as_bytes()
    );
}

#[test]
fn a_bundle_starting_with_an_intermediate_still_finds_the_root() {
    let dir = scratch();
    let (_, ca_pem) =
        throwaway_tsa_token_signed_with(dir.path(), "critical,timeStamping", "sha256");
    let ca = std::fs::read_to_string(&ca_pem).expect("read CA");
    let leaf = std::fs::read_to_string(dir.path().join("tsa-leaf.pem")).expect("read leaf");
    // The leaf first, the CA second: the position must not decide.
    let path = bundle(dir.path(), "reversed.pem", &format!("{leaf}{ca}"));

    let store = AnchorStore::load(&[(ID.to_owned(), path)]).expect("the CA is still a root");
    let anchor = store.anchor(ID).expect("the id is pinned");
    assert_eq!(anchor.roots.len(), 1);
    assert_eq!(anchor.intermediates.len(), 1);
}

#[test]
fn a_bundle_without_a_self_signed_root_has_no_root() {
    let dir = scratch();
    let (_, _) = throwaway_tsa_token_signed_with(dir.path(), "critical,timeStamping", "sha256");
    let leaf = std::fs::read_to_string(dir.path().join("tsa-leaf.pem")).expect("read leaf");
    // Only the leaf: nothing in the bundle can end a chain.
    let path = bundle(dir.path(), "leaf-only.pem", &leaf);

    let error = AnchorStore::load(&[(ID.to_owned(), path.clone())]).expect_err("no root");
    assert!(
        matches!(error, git_time_core::trust::TrustError::NoRoot { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains(ID), "{error}");
    assert!(
        error.to_string().contains(&path.display().to_string()),
        "{error}"
    );
}

#[test]
fn appending_keeps_both_roots_and_dedupes() {
    // Both throwaway CAs have the same subject CN — this is the re-key case:
    // same name, different key. Both roots have to survive, the fingerprint
    // decides which one verifies.
    // The helper writes fixed file names, so each generation needs its own dir.
    let first_dir = scratch();
    let second_dir = scratch();
    let (_, first) =
        throwaway_tsa_token_signed_with(first_dir.path(), "critical,timeStamping", "sha256");
    let (_, second) =
        throwaway_tsa_token_signed_with(second_dir.path(), "critical,timeStamping", "sha256");
    let path = bundle(
        first_dir.path(),
        "one.pem",
        &std::fs::read_to_string(&first).unwrap(),
    );
    let mut store = AnchorStore::load(&[(ID.to_owned(), path)]).expect("first root");
    assert_eq!(store.anchor(ID).unwrap().roots.len(), 1);

    let appended = bundle(
        second_dir.path(),
        "two.pem",
        &std::fs::read_to_string(&second).unwrap(),
    );
    assert_eq!(store.append(ID, &appended).expect("append"), 1);
    assert_eq!(store.anchor(ID).unwrap().roots.len(), 2);
    assert_eq!(store.append(ID, &appended).expect("again"), 0);
    assert_eq!(store.anchor(ID).unwrap().roots.len(), 2);
}

#[test]
fn roots_at_respects_the_boundaries() {
    // Build a bundle from a throwaway CA, read its notBefore/notAfter, and
    // assert: a time before notBefore or after notAfter yields nothing, and a
    // time equal to either boundary yields the root.
    let dir = scratch();
    let (_, ca_pem) =
        throwaway_tsa_token_signed_with(dir.path(), "critical,timeStamping", "sha256");
    let pem = std::fs::read_to_string(&ca_pem).expect("read CA");
    let path = bundle(dir.path(), "root.pem", &pem);
    let store = AnchorStore::load(&[(ID.to_owned(), path)]).expect("root loads");
    let anchor = store.anchor(ID).expect("the id is pinned");

    let der = sigstore_types::DerCertificate::from_pem(&pem)
        .expect("CA parses")
        .as_bytes()
        .to_vec();
    let certificate = x509_cert::Certificate::from_der(&der).expect("CA is a certificate");
    let validity = &certificate.tbs_certificate.validity;
    let not_before = i64::try_from(validity.not_before.to_unix_duration().as_secs())
        .expect("notBefore fits a timestamp");
    let not_after = i64::try_from(validity.not_after.to_unix_duration().as_secs())
        .expect("notAfter fits a timestamp");
    let at = |second: i64| Timestamp::from_second(second).expect("second is in range");

    assert!(anchor.roots_at(at(not_before - 1)).is_empty(), "before");
    assert!(anchor.roots_at(at(not_after + 1)).is_empty(), "after");
    assert_eq!(anchor.roots_at(at(not_before)).len(), 1, "at notBefore");
    assert_eq!(anchor.roots_at(at(not_after)).len(), 1, "at notAfter");
}

#[test]
fn an_empty_bundle_is_empty_not_a_rootless_anchor() {
    let dir = scratch();
    let path = bundle(dir.path(), "empty.pem", "");

    let error = AnchorStore::load(&[(ID.to_owned(), path)]).expect_err("an empty bundle");
    assert!(
        matches!(error, git_time_core::trust::TrustError::Empty { .. }),
        "{error:?}"
    );
}

#[test]
fn non_pem_bundle_is_a_trust_error() {
    let dir = scratch();
    let path = bundle(dir.path(), "garbage.pem", "definitely not a certificate\n");

    let error = AnchorStore::load(&[(ID.to_owned(), path)]).expect_err("garbage is not an anchor");
    assert!(error.to_string().contains(ID), "{error}");
}
