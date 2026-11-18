//! Fail-closed verification of one RFC 3161 token against pinned anchors.
//!
//! Every case runs against the committed FreeTSA fixture, offline. The fixture
//! is only evidence once the FreeTSA root is pinned; with no anchor the very
//! same bytes are `Untrusted`.

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

/// Generate a throwaway self-signed CA and return its certificate path.
fn throwaway_root(dir: &Path) -> PathBuf {
    let key = dir.join("throwaway-key.pem");
    let cert = dir.join("throwaway-ca.pem");
    let status = Command::new("openssl")
        .arg("req")
        .arg("-x509")
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
        .arg("-addext")
        .arg("basicConstraints=critical,CA:TRUE")
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
        }
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
    let ca_key = dir.join("tsa-ca-key.pem");
    let ca_pem = dir.join("tsa-ca.pem");
    let leaf_key = dir.join("tsa-leaf-key.pem");
    let leaf_csr = dir.join("tsa-leaf.csr");
    let leaf_pem = dir.join("tsa-leaf.pem");
    let leaf_ext = dir.join("tsa-leaf.ext");

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
        "-newkey".as_ref(),
        "ec".as_ref(),
        "-pkeyopt".as_ref(),
        "ec_paramgen_curve:P-256".as_ref(),
        "-nodes".as_ref(),
        "-keyout".as_ref(),
        ca_key.as_os_str(),
        "-out".as_ref(),
        ca_pem.as_os_str(),
        "-days".as_ref(),
        "2".as_ref(),
        "-subj".as_ref(),
        "/CN=throwaway-tsa-ca".as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
        "-addext".as_ref(),
        "keyUsage=critical,keyCertSign,cRLSign".as_ref(),
    ]);
    openssl(&[
        "req".as_ref(),
        "-new".as_ref(),
        "-newkey".as_ref(),
        "ec".as_ref(),
        "-pkeyopt".as_ref(),
        "ec_paramgen_curve:P-256".as_ref(),
        "-nodes".as_ref(),
        "-keyout".as_ref(),
        leaf_key.as_os_str(),
        "-out".as_ref(),
        leaf_csr.as_os_str(),
        "-subj".as_ref(),
        "/CN=throwaway-tsa".as_ref(),
    ]);
    std::fs::write(
        &leaf_ext,
        format!(
            "basicConstraints=critical,CA:FALSE\n\
             keyUsage=critical,digitalSignature\n\
             extendedKeyUsage={eku}\n"
        ),
    )
    .expect("write leaf extensions");
    openssl(&[
        "x509".as_ref(),
        "-req".as_ref(),
        "-in".as_ref(),
        leaf_csr.as_os_str(),
        "-CA".as_ref(),
        ca_pem.as_os_str(),
        "-CAkey".as_ref(),
        ca_key.as_os_str(),
        "-CAcreateserial".as_ref(),
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
    // `openssl cms -sign` accepts them; `-certfile` puts the CA in the token.
    //
    // The certificates start "now", so the fixture's 05:38Z genTime would be
    // before their notBefore; the stamp is moved to now (same length) and only
    // then signed.
    let mut tst = tst_info(&token());
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
        ca_pem.as_os_str(),
        "-md".as_ref(),
        "sha256".as_ref(),
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
        anchor.root.as_bytes(),
        sigstore_types::DerCertificate::from_pem(ROOT_PEM)
            .expect("fixture root parses")
            .as_bytes()
    );
}

#[test]
fn non_pem_bundle_is_a_trust_error() {
    let dir = scratch();
    let path = bundle(dir.path(), "garbage.pem", "definitely not a certificate\n");

    let error = AnchorStore::load(&[(ID.to_owned(), path)]).expect_err("garbage is not an anchor");
    assert!(error.to_string().contains(ID), "{error}");
}
