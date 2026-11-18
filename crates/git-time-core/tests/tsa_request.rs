//! RFC 3161 request encoding and response status parsing.
//!
//! The request encoder is ours, so its DER is pinned byte for byte: a fixed
//! nonce must always produce the same bytes, and the decoder mirror below proves
//! the fields carry what RFC 3161 names them. The response parser is fed the two
//! real FreeTSA captures; the granted one must hand its token back untouched,
//! byte for byte as it sits in the fixture, because re-serialising CMS would
//! change what later verification hashes over.

use der::asn1::{ObjectIdentifier, OctetStringRef, UintRef};
use der::{Decode, Encode, Reader, SliceReader, Tag};
use git_time_core::imprint::{Alg, Digest};
use git_time_core::tsa::{RawResponse, StampRequest, TsaError, encode, parse_response};
use rand_core::TryRng;
use std::io::Write as _;
use std::process::Command;

/// The granted FreeTSA response, 4644 bytes.
const GRANTED: &[u8] = include_bytes!("fixtures/resp_granted_freetsa.tsr");
/// The FreeTSA rejection for an unserved policy, 50 bytes.
const REJECTED: &[u8] = include_bytes!("fixtures/resp_rejected_freetsa.tsr");

const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
const SHA512_OID: &str = "2.16.840.1.101.3.4.2.3";

/// The exact DER a request with imprint `00..1f`, nonce `01..08`, no policy and
/// `certReq = TRUE` must produce. Hand-composed from RFC 3161:
/// `30 41` (TimeStampReq, 65 bytes) `02 01 01` (version 1) `30 2f` (imprint)
/// `30 0b 06 09 <sha256 oid>` (algorithm, no parameters) `04 20 <32 bytes>`
/// `02 08 <nonce>` `01 01 ff` (certReq).
const GOLDEN: &str = "\
3041020101302f300b06096086480165030402010420\
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
02080102030405060708\
0101ff";

/// A test-only decoder mirror of `TimeStampReq`; absent optional fields decode
/// as `None`, which is exactly what the encoder must produce for them.
#[derive(Debug, der::Sequence)]
struct MirrorRequest<'a> {
    version: u8,
    message_imprint: MirrorImprint<'a>,
    #[asn1(optional = "true")]
    req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    nonce: Option<UintRef<'a>>,
    #[asn1(optional = "true")]
    cert_req: Option<bool>,
}

#[derive(Debug, der::Sequence)]
struct MirrorImprint<'a> {
    hash_algorithm: MirrorAlgorithm,
    hashed_message: OctetStringRef<'a>,
}

#[derive(Debug, der::Sequence)]
struct MirrorAlgorithm {
    algorithm: ObjectIdentifier,
}

/// A deterministic RNG: successive calls fill with incrementing bytes.
struct CountingRng(u8);

impl TryRng for CountingRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dst {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

fn imprint(alg: Alg, bytes: impl IntoIterator<Item = u8>) -> Digest {
    Digest {
        alg,
        bytes: bytes.into_iter().collect(),
    }
}

fn request(nonce: &[u8]) -> StampRequest {
    StampRequest {
        imprint: imprint(Alg::Sha256, 0..32),
        nonce: nonce.to_vec(),
        policy: None,
        cert_req: true,
    }
}

fn decode(request_bytes: &[u8]) -> MirrorRequest<'_> {
    MirrorRequest::from_der(request_bytes).expect("encoder produced unparsable DER")
}

#[test]
fn encoded_request_round_trips_through_the_decoder() {
    let imprint = imprint(Alg::Sha256, 0..32);
    let mut rng = CountingRng(1);
    let request = StampRequest::new(imprint, &mut rng)
        .expect("32-byte sha256 imprint")
        .with_policy(Some("1.2.3.4".to_owned()))
        .expect("valid policy");

    let encoded = encode(&request);
    let decoded = decode(&encoded);

    assert_eq!(decoded.version, 1);
    assert_eq!(
        decoded.message_imprint.hash_algorithm.algorithm,
        ObjectIdentifier::new(SHA256_OID).expect("valid OID")
    );
    assert_eq!(
        decoded.message_imprint.hashed_message.as_bytes(),
        (0..32u8).collect::<Vec<u8>>()
    );
    assert_eq!(
        decoded.req_policy,
        Some(ObjectIdentifier::new("1.2.3.4").expect("valid OID"))
    );
    assert_eq!(
        decoded.nonce.as_ref().map(UintRef::as_bytes),
        Some(&[1, 2, 3, 4, 5, 6, 7, 8][..])
    );
    assert_eq!(decoded.cert_req, Some(true));
}

#[test]
fn policy_is_absent_when_none() {
    let encoded = encode(&request(&[1]));
    let decoded = decode(&encoded);
    assert_eq!(decoded.req_policy, None);
}

#[test]
fn with_policy_can_also_clear_a_policy() {
    let with = StampRequest::new(imprint(Alg::Sha256, 0..32), &mut CountingRng(1))
        .expect("valid imprint")
        .with_policy(Some("1.2.3".to_owned()))
        .expect("valid policy");
    let cleared = with.with_policy(None).expect("clearing is valid");

    assert_eq!(cleared.policy, None);
    assert_eq!(decode(&encode(&cleared)).req_policy, None);
}

#[test]
fn a_policy_with_a_multi_octet_arc_round_trips() {
    // `99999` needs two base-128 octets, so the continuation bit is exercised.
    let policy = "1.3.6.1.4.1.99999.1";
    let request = StampRequest::new(imprint(Alg::Sha256, 0..32), &mut CountingRng(1))
        .expect("valid imprint")
        .with_policy(Some(policy.to_owned()))
        .expect("valid policy");

    let encoded = encode(&request);
    assert_eq!(
        decode(&encoded).req_policy,
        Some(ObjectIdentifier::new(policy).expect("valid OID"))
    );
}

#[test]
fn a_long_nonce_uses_a_long_form_length() {
    let nonce = [0xab; 140];
    let encoded = encode(&request(&nonce));
    let decoded = decode(&encoded);

    assert_eq!(
        decoded.nonce.as_ref().map(UintRef::as_bytes),
        Some(&nonce[..])
    );
}

#[test]
fn an_invalid_policy_is_rejected_with_the_offending_value() {
    for policy in [
        "",
        "not-an-oid",
        "1",
        "3.1",
        "1.40",
        "2.18446744073709551615",
        "1.2.+3",
        "1.2.3.",
        " 1.2",
    ] {
        let built = StampRequest::new(imprint(Alg::Sha256, 0..32), &mut CountingRng(1))
            .expect("valid imprint")
            .with_policy(Some(policy.to_owned()));

        assert_eq!(
            built,
            Err(TsaError::InvalidPolicy(policy.to_owned())),
            "{policy:?} must not be accepted"
        );
    }
}

#[test]
fn a_hand_written_invalid_policy_is_dropped_by_encode() {
    // The field is public, so the `with_policy` check can be gone around; the
    // policy then stays in the struct but never reaches the DER.
    let request = StampRequest {
        policy: Some("1.2.+3".to_owned()),
        ..request(&[1])
    };

    assert_eq!(request.policy.as_deref(), Some("1.2.+3"));
    assert_eq!(decode(&encode(&request)).req_policy, None);
}

#[test]
fn sha512_uses_its_own_algorithm_identifier() {
    let request = StampRequest {
        imprint: imprint(Alg::Sha512, 0..64),
        nonce: vec![7],
        policy: None,
        cert_req: true,
    };

    let encoded = encode(&request);
    let decoded = decode(&encoded);

    assert_eq!(
        decoded.message_imprint.hash_algorithm.algorithm,
        ObjectIdentifier::new(SHA512_OID).expect("valid OID")
    );
    assert_eq!(
        decoded.message_imprint.hashed_message.as_bytes(),
        (0..64u8).collect::<Vec<u8>>()
    );
}

#[test]
fn a_nonce_with_the_high_bit_set_gets_a_zero_prefix() {
    let encoded = encode(&request(&[0x80, 0x00]));

    assert!(
        encoded.ends_with(&[0x02, 0x03, 0x00, 0x80, 0x00, 0x01, 0x01, 0xff]),
        "nonce must be a positive INTEGER with a 0x00 prefix: {encoded:02x?}"
    );
    assert_eq!(
        decode(&encoded).nonce.as_ref().map(UintRef::as_bytes),
        Some(&[0x80, 0x00][..])
    );
}

#[test]
fn an_all_zero_nonce_encodes_as_integer_zero_and_is_not_omitted() {
    let encoded = encode(&request(&[0, 0, 0]));

    assert!(
        encoded.ends_with(&[0x02, 0x01, 0x00, 0x01, 0x01, 0xff]),
        "all-zero nonce must encode as INTEGER 0: {encoded:02x?}"
    );
    let decoded = decode(&encoded);
    assert!(decoded.nonce.is_some(), "nonce must not be omitted");
    assert_eq!(
        decoded.nonce.as_ref().map(UintRef::as_bytes),
        Some(&[0][..])
    );
}

#[test]
fn an_empty_nonce_is_omitted() {
    assert_eq!(decode(&encode(&request(&[]))).nonce, None);
}

#[test]
fn cert_req_false_is_omitted() {
    let request = StampRequest {
        cert_req: false,
        ..request(&[1])
    };
    assert_eq!(decode(&encode(&request)).cert_req, None);
}

#[test]
fn encoding_the_same_request_twice_is_byte_identical() {
    let request = request(&[0xa5; 8]);
    assert_eq!(encode(&request), encode(&request));
}

#[test]
fn a_fixed_request_has_a_golden_encoding() {
    assert_eq!(encode(&request(&[1, 2, 3, 4, 5, 6, 7, 8])), hex(GOLDEN));
}

#[test]
fn new_draws_an_eight_byte_nonce_and_asks_for_the_certificate() {
    let imprint = imprint(Alg::Sha512, 0..64);

    let request = StampRequest::new(imprint.clone(), &mut CountingRng(9)).expect("valid imprint");

    assert_eq!(request.imprint, imprint);
    assert_eq!(request.nonce, (9..17).collect::<Vec<u8>>());
    assert_eq!(request.policy, None);
    assert!(request.cert_req);
}

#[test]
fn new_rejects_an_imprint_that_is_not_its_algorithms_width() {
    let short = imprint(Alg::Sha256, 0..20);

    assert_eq!(
        StampRequest::new(short, &mut CountingRng(9)),
        Err(TsaError::InvalidImprint(
            "sha256 imprint is 20 bytes, not 32".to_owned()
        ))
    );
}

#[test]
fn the_golden_request_parses_with_openssl_asn1parse() {
    if !openssl_available() {
        println!("openssl not installed, skipping asn1parse cross-check");
        return;
    }

    let encoded = encode(&request(&[1, 2, 3, 4, 5, 6, 7, 8]));
    let mut file = tempfile::NamedTempFile::new().expect("temporary request file");
    file.write_all(&encoded).expect("write request");
    let parsed = Command::new("openssl")
        .args(["asn1parse", "-inform", "DER", "-i", "-in"])
        .arg(file.path())
        .output()
        .expect("run openssl asn1parse");

    assert!(
        parsed.status.success(),
        "openssl rejected the request: {}",
        String::from_utf8_lossy(&parsed.stderr)
    );
    let dump = String::from_utf8(parsed.stdout).expect("openssl output is ASCII");
    for needle in [
        "sha256",
        "OCTET STRING",
        "l=  32",
        "INTEGER           :01",
        "BOOLEAN           :255",
    ] {
        assert!(dump.contains(needle), "{needle:?} missing from:\n{dump}");
    }

    // `INTEGER :01` above is satisfied by the version, so the nonce needs its
    // own assertion: the value after each `INTEGER` proves the 8-byte width.
    let integers: Vec<&str> = dump
        .lines()
        .filter(|line| line.contains("INTEGER"))
        .filter_map(|line| line.rsplit_once(':'))
        .map(|(_, value)| value.trim())
        .collect();
    assert_eq!(
        integers,
        ["01", "0102030405060708"],
        "version and 8-byte nonce expected, got {integers:?} from:\n{dump}"
    );
}

/// Whether `openssl` can be run at all; the cross-check is skipped without it.
fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn the_real_granted_response_yields_its_token_untouched() {
    let response = parse_response(GRANTED).expect("granted response parses");
    let RawResponse::Granted { token, status_text } = response else {
        panic!("expected Granted, got {response:?}");
    };

    assert_eq!(status_text, None);
    assert!(
        token.len() >= 4000,
        "token is suspiciously short: {}",
        token.len()
    );
    assert_eq!(
        token.first(),
        Some(&0x30),
        "token must start with a SEQUENCE"
    );

    // The token is the `timeStampToken` ContentInfo (OID 1.2.840.113549.1.7.2).
    let header = [
        0x30, 0x82, 0x12, 0x17, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    let offset = find(GRANTED, &header).expect("CMS ContentInfo header in fixture");
    assert_eq!((offset, token.len()), (9, 4635));
    assert_eq!(GRANTED[offset..offset + token.len()], token[..]);
}

#[test]
fn the_real_rejected_response_names_the_reason() {
    let response = parse_response(REJECTED).expect("rejected response parses");

    assert_eq!(
        response,
        RawResponse::Rejected {
            status: 2,
            text: Some("Requested policy is not supported.".to_owned()),
        }
    );
}

#[test]
fn a_rejection_without_status_text_falls_back_to_the_fail_info_bit() {
    // `30 0a` TimeStampResp, `30 08` PKIStatusInfo, status 2 (rejected),
    // `03 03 00 00 01` failInfo with bit 15 (unacceptedPolicy) set.
    let response = [
        0x30, 0x0a, 0x30, 0x08, 0x02, 0x01, 0x02, 0x03, 0x03, 0x00, 0x00, 0x01,
    ];

    assert_eq!(
        parse_response(&response),
        Ok(RawResponse::Rejected {
            status: 2,
            text: Some("unacceptedPolicy".to_owned()),
        })
    );
}

#[test]
fn a_rejection_that_carries_a_token_stays_rejected() {
    let response = [
        0x30, 0x0a, // TimeStampResp, 10 content bytes
        0x30, 0x03, 0x02, 0x01, 0x02, // PKIStatusInfo, status 2
        0x30, 0x03, 0x02, 0x01, 0x09, // a token the parser keeps no byte of
    ];

    assert_eq!(
        parse_response(&response),
        Ok(RawResponse::Rejected {
            status: 2,
            text: None,
        })
    );
}

#[test]
fn a_latin1_teletex_string_survives_as_text() {
    // status 2, statusString TeletexString `e4`, "ä" in Latin-1, not UTF-8.
    let response = [
        0x30, 0x0a, // TimeStampResp, 10 content bytes
        0x30, 0x08, // PKIStatusInfo, 8 content bytes
        0x02, 0x01, 0x02, // status 2
        0x30, 0x03, 0x14, 0x01, 0xe4, // PKIFreeText with one TeletexString
    ];

    assert_eq!(
        parse_response(&response),
        Ok(RawResponse::Rejected {
            status: 2,
            text: Some("ä".to_owned()),
        })
    );
}

#[test]
fn fail_info_unused_bits_are_masked_off() {
    // failInfo `07 00 01`: 7 unused bits, so only the top bit of the last octet
    // means anything; a naive read calls the `01` bit 15.
    let noise = [
        0x30, 0x0a, // TimeStampResp, 10 content bytes
        0x30, 0x08, // PKIStatusInfo, 8 content bytes
        0x02, 0x01, 0x02, // status 2
        0x03, 0x03, 0x07, 0x00, 0x01, // failInfo, only unused-bit noise set
    ];
    assert_eq!(
        parse_response(&noise),
        Ok(RawResponse::Rejected {
            status: 2,
            text: Some("failInfo with no bit set".to_owned()),
        })
    );

    // The same shape with the meaningful top bit set: bit 8, unnamed here.
    let real = [
        0x30, 0x0a, // TimeStampResp, 10 content bytes
        0x30, 0x08, // PKIStatusInfo, 8 content bytes
        0x02, 0x01, 0x02, // status 2
        0x03, 0x03, 0x07, 0x00, 0x80, // failInfo, bit 8 set
    ];
    assert_eq!(
        parse_response(&real),
        Ok(RawResponse::Rejected {
            status: 2,
            text: Some("failInfo bit 8".to_owned()),
        })
    );
}

#[test]
fn an_empty_status_string_sequence_is_malformed() {
    let response = [
        0x30, 0x07, // TimeStampResp
        0x30, 0x05, // PKIStatusInfo
        0x02, 0x01, 0x02, // status 2
        0x30, 0x00, // empty PKIFreeText, but SIZE(1..MAX)
    ];

    assert!(matches!(
        parse_response(&response),
        Err(TsaError::Malformed(_))
    ));
}

#[test]
fn io_errors_keep_their_source() {
    let error = TsaError::from(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
    let same = TsaError::from(std::io::Error::from(std::io::ErrorKind::BrokenPipe));

    assert_eq!(error, same);
    assert!(
        std::error::Error::source(&error).is_some(),
        "the io::Error must stay reachable as the source"
    );
    assert!(error.to_string().contains("timestamp authority I/O failed"));
}

#[test]
fn several_status_strings_are_concatenated() {
    let response = [
        0x30, 0x11, // TimeStampResp
        0x30, 0x0f, // PKIStatusInfo
        0x02, 0x01, 0x02, // status 2
        0x30, 0x0a, // PKIFreeText
        0x0c, 0x03, b'o', b'n', b'e', // "one"
        0x0c, 0x03, b't', b'w', b'o', // "two"
    ];

    assert_eq!(
        parse_response(&response),
        Ok(RawResponse::Rejected {
            status: 2,
            text: Some("onetwo".to_owned()),
        })
    );
}

#[test]
fn status_strings_from_several_sequences_accumulate() {
    let response = [
        0x30, 0x13, // TimeStampResp
        0x30, 0x11, // PKIStatusInfo
        0x02, 0x01, 0x02, // status 2
        0x30, 0x05, 0x0c, 0x03, b'o', b'n', b'e', // PKIFreeText "one"
        0x30, 0x05, 0x0c, 0x03, b't', b'w', b'o', // PKIFreeText "two"
    ];

    assert_eq!(
        parse_response(&response),
        Ok(RawResponse::Rejected {
            status: 2,
            text: Some("onetwo".to_owned()),
        })
    );
}

#[test]
fn a_granted_status_text_never_falls_back_to_a_fail_info_bit() {
    let response = [
        0x30, 0x0f, // TimeStampResp
        0x30, 0x08, // PKIStatusInfo
        0x02, 0x01, 0x01, // status 1 (grantedWithMods)
        0x03, 0x03, 0x00, 0x00, 0x01, // failInfo bit 15, but no statusString
        0x30, 0x03, 0x02, 0x01, 0x09, // token
    ];

    assert_eq!(
        parse_response(&response),
        Ok(RawResponse::Granted {
            token: vec![0x30, 0x03, 0x02, 0x01, 0x09],
            status_text: None,
        })
    );
}

#[test]
fn a_truncated_granted_response_is_malformed() {
    assert!(matches!(
        parse_response(&GRANTED[..20]),
        Err(TsaError::Malformed(_))
    ));
}

#[test]
fn every_prefix_of_the_fixtures_parses_without_panicking() {
    for fixture in [GRANTED, REJECTED] {
        for length in 0..fixture.len() {
            let response = parse_response(&fixture[..length]);
            assert!(
                !matches!(response, Ok(RawResponse::Granted { .. })),
                "a {length}-byte prefix must not be granted"
            );
        }
    }
}

#[test]
fn a_granted_response_without_a_token_is_missing_its_token() {
    // The fixture's `PKIStatusInfo` (`30 03 02 01 00`) with the token stripped
    // and the outer length shortened to match: `30 05 ...`.
    let response = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];

    assert_eq!(parse_response(&response), Err(TsaError::MissingToken));
}

#[test]
fn granted_with_mods_is_granted() {
    // status 1 (`grantedWithMods`), statusString "mods", no token.
    let response = [
        0x30, 0x0d, // TimeStampResp
        0x30, 0x0b, // PKIStatusInfo
        0x02, 0x01, 0x01, // status 1
        0x30, 0x06, 0x0c, 0x04, b'm', b'o', b'd', b's', // statusString
    ];

    assert_eq!(
        parse_response(&response),
        Err(TsaError::MissingToken),
        "a granted status without token is MissingToken even for status 1"
    );
}

#[test]
fn trailing_bytes_are_malformed() {
    let mut response = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00].to_vec();
    response.push(0x00);

    assert!(matches!(
        parse_response(&response),
        Err(TsaError::Malformed(_))
    ));
}

#[test]
fn a_rejection_followed_by_trailing_bytes_is_malformed() {
    // A rejection is not granted, but that must not excuse bytes on the end.
    let mut response = [0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x02].to_vec();
    response.push(0x00);

    assert!(matches!(
        parse_response(&response),
        Err(TsaError::Malformed(_))
    ));
}

#[test]
fn garbage_and_empty_input_are_malformed() {
    for garbage in [&b""[..], &b"not der"[..], &[0x02, 0x01, 0x01][..]] {
        assert!(
            matches!(parse_response(garbage), Err(TsaError::Malformed(_))),
            "{garbage:02x?} must be malformed"
        );
    }
}

#[test]
fn a_response_status_must_be_a_single_byte_integer() {
    // status INTEGER with two bytes instead of one.
    let response = [0x30, 0x06, 0x30, 0x04, 0x02, 0x02, 0x00, 0x02];

    assert!(matches!(
        parse_response(&response),
        Err(TsaError::Malformed(_))
    ));
}

#[test]
fn reader_offsets_and_tags_are_what_the_parser_relies_on() {
    // Sanity check for the offset-tracking parser: the `der` reader reports
    // absolute offsets, and peeking the token header yields the length the
    // fixture declares (0x1217 content plus its 4-byte header).
    let mut reader = SliceReader::new(GRANTED).expect("reader");
    let outer = reader.peek_header().expect("outer header");
    assert_eq!(outer.tag, Tag::Sequence);
    let _ = reader
        .read_slice(outer.encoded_len().expect("header length"))
        .expect("outer header");
    let status = reader.peek_header().expect("status info");
    let status_len =
        (status.encoded_len().expect("header length") + status.length).expect("length");
    let _ = reader.read_slice(status_len).expect("status info");
    assert_eq!(
        u32::from(reader.offset()),
        u32::try_from(find(GRANTED, &[0x30, 0x82, 0x12, 0x17]).expect("token offset"))
            .expect("offset fits")
    );
}

/// The lowercase hex of `bytes`.
fn hex(bytes: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_bytes().as_chunks::<2>().0 {
        let text = std::str::from_utf8(pair).expect("hex pairs are ASCII");
        out.push(u8::from_str_radix(text, 16).expect("valid hex"));
    }
    out
}

/// The first index of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
