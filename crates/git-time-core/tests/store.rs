//! Trailer block codec: exact wire format, order-insensitive decoding,
//! forward-compatible unknown fields, and size accounting that degrades by
//! dropping the largest token instead of writing an over-long block.

use git_time_core::imprint::{Alg, Digest, digest};
use git_time_core::store::{
    DecodeError, EncodeError, FailureRecord, MAX_TOKEN_BYTES, TokenRecord, TrailerBlock, decode,
    encode,
};

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Tracks the largest single allocation made on the current thread, so the
/// bounded-decompression test can show that a frame is not inflated whole.
struct PeakAllocator;

thread_local! {
    static PEAK_ALLOC: Cell<usize> = const { Cell::new(0) };
}

fn record(size: usize) {
    let _ = PEAK_ALLOC.try_with(|peak| {
        if size > peak.get() {
            peak.set(size);
        }
    });
}

unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator;

fn peak_reset() {
    PEAK_ALLOC.with(|peak| peak.set(0));
}

fn peak() -> usize {
    PEAK_ALLOC.with(Cell::get)
}

const PREFIX: &str = "X-RFC3161-";

fn imprint() -> Digest {
    Digest {
        alg: Alg::Sha256,
        bytes: digest(Alg::Sha256, b"pre-image"),
    }
}

fn oid() -> String {
    "4f1c9e0".repeat(5) + "01234"
}

/// Deterministic pseudo-random bytes, so zstd cannot collapse them into a run.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    let mut state = u32::from(seed).wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 16) as u8
        })
        .collect()
}

fn token(id: &str, seed: u8, size: usize) -> TokenRecord {
    TokenRecord {
        id: id.to_owned(),
        alg: Alg::Sha256,
        policy: Some("1.2.3.4.1".to_owned()),
        nonce: vec![0x9c, 0x1f, 0x3a, 0xb2],
        token: payload(size, seed),
    }
}

fn block() -> TrailerBlock {
    TrailerBlock {
        imprint: imprint(),
        object: Some(oid()),
        anchors: BTreeMap::new(),
        tokens: vec![
            token("freetsa", 1, 300),
            token("digicert", 2, 300),
            token("sectigo", 3, 300),
        ],
        failures: Vec::new(),
        extra: Vec::new(),
    }
}

/// A fingerprint in its canonical spelling: 32 uppercase hex octets, colon
/// separated, exactly as `trust::fingerprint` prints one.
fn fp(octet: u8) -> String {
    vec![format!("{octet:02X}"); 32].join(":")
}

fn lines(block: &TrailerBlock) -> Vec<String> {
    String::from_utf8(encode(block, usize::MAX).expect("fits"))
        .expect("wire format is ASCII")
        .split('\n')
        .map(str::to_owned)
        .collect()
}

fn tst_of(line: &str) -> &str {
    line.split_once("tst=").expect("line has a tst").1
}

#[test]
fn three_tokens_round_trip() {
    let original = block();
    let encoded = encode(&original, usize::MAX).expect("fits");
    let decoded = decode(&encoded).expect("decodes").expect("has a block");
    assert_eq!(decoded, original);
    // Re-encoding the decoded block reproduces the bytes exactly.
    assert_eq!(encode(&decoded, usize::MAX).expect("fits"), encoded);
}

#[test]
fn wire_format_is_one_field_per_line_in_fixed_order() {
    let mut original = block();
    original.tokens.truncate(1);
    original.failures.push(FailureRecord {
        id: "sectigo".to_owned(),
        reason: "http-503".to_owned(),
    });
    original
        .extra
        .push(("Note".to_owned(), "kept verbatim".to_owned()));

    let encoded = String::from_utf8(encode(&original, usize::MAX).expect("fits")).expect("ASCII");
    let lines: Vec<&str> = encoded.split('\n').collect();

    assert_eq!(
        lines[0],
        format!("{PREFIX}Imprint: {}", original.imprint.to_trailer_value())
    );
    assert_eq!(lines[1], format!("{PREFIX}Object: {}", oid()));
    assert!(
        lines[2].starts_with(&format!(
            "{PREFIX}Token: ver=1; id=freetsa; alg=sha256; policy=1.2.3.4.1; nonce=9c1f3ab2; tst="
        )),
        "unexpected token line: {}",
        lines[2]
    );
    assert_eq!(
        lines[3],
        format!("{PREFIX}Fail: id=sectigo; reason=http-503")
    );
    assert_eq!(lines[4], format!("{PREFIX}Note: kept verbatim"));
    assert_eq!(lines.len(), 5);
    assert!(!encoded.ends_with('\n'), "encoder adds no trailing newline");
}

#[test]
fn encoding_a_block_without_tokens_is_the_imprint_line_only() {
    let mut original = block();
    original.tokens.clear();
    original.object = None;

    let encoded = encode(&original, usize::MAX).expect("fits");
    assert_eq!(
        String::from_utf8(encoded.clone()).expect("ASCII"),
        format!("{PREFIX}Imprint: {}", original.imprint.to_trailer_value())
    );

    let decoded = decode(&encoded).expect("decodes").expect("has a block");
    assert_eq!(decoded, original);
}

#[test]
fn a_policy_is_omitted_when_absent() {
    let mut original = block();
    original.tokens = vec![TokenRecord {
        policy: None,
        ..token("freetsa", 1, 40)
    }];
    let lines = lines(&original);
    assert!(
        lines[2].starts_with(&format!(
            "{PREFIX}Token: ver=1; id=freetsa; alg=sha256; nonce="
        )),
        "policy must not appear: {}",
        lines[2]
    );
    let decoded = decode(encode(&original, usize::MAX).expect("fits").as_slice())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded.tokens[0].policy, None);
}

#[test]
fn nonce_renders_as_lowercase_hex() {
    let mut original = block();
    original.tokens.truncate(1);
    let line = lines(&original).remove(2);
    assert!(line.contains("; nonce=9c1f3ab2; "), "{line}");
}

#[test]
fn decode_accepts_uppercase_nonce_hex() {
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Token: ver=1; id=x; alg=sha256; nonce=9C1F3AB2; tst=KLUv_SQAAQAAmenYUQ",
        imprint().to_trailer_value()
    );
    let decoded = decode(encoded.as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded.tokens[0].nonce, vec![0x9c, 0x1f, 0x3a, 0xb2]);
}

#[test]
fn an_anchor_line_round_trips_in_place() {
    let mut original = block();
    original.tokens.truncate(1);
    original
        .anchors
        .insert("freetsa".to_owned(), vec![fp(0xab), fp(0xcd)]);

    let encoded = String::from_utf8(encode(&original, usize::MAX).expect("fits")).expect("ASCII");
    let lines: Vec<&str> = encoded.split('\n').collect();
    assert_eq!(
        lines[2],
        format!(
            "{PREFIX}Anchor: id=freetsa; sha256={},{}",
            fp(0xab),
            fp(0xcd)
        )
    );
    assert!(
        lines[3].starts_with(&format!("{PREFIX}Token: ")),
        "the anchor must come before the token: {}",
        lines[3]
    );

    let decoded = decode(encoded.as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded, original);
}

#[test]
fn anchor_fingerprints_normalize_to_uppercase() {
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Anchor: id=x; sha256={}\n{PREFIX}Fail: id=x; reason=y\n",
        imprint().to_trailer_value(),
        fp(0xab).to_lowercase()
    );
    let decoded = decode(encoded.as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded.anchors["x"], vec![fp(0xab)]);
}

#[test]
fn an_anchor_line_naming_no_token_or_fail_rejects_the_block() {
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Anchor: id=ghost; sha256={}\n",
        imprint().to_trailer_value(),
        fp(1)
    );
    assert!(matches!(
        decode(encoded.as_bytes()),
        Err(DecodeError::InvalidField { .. })
    ));
}

#[test]
fn a_duplicate_anchor_line_rejects_the_block() {
    let anchor = format!("{PREFIX}Anchor: id=x; sha256={}", fp(1));
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{anchor}\n{anchor}\n{PREFIX}Fail: id=x; reason=y\n",
        imprint().to_trailer_value()
    );
    assert!(matches!(
        decode(encoded.as_bytes()),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn anchor_fingerprints_must_be_sha256_hex() {
    let sha1 = vec!["AB"; 20].join(":");
    for fingerprints in ["nothex", sha1.as_str(), ""] {
        let encoded = format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Anchor: id=x; sha256={fingerprints}\n{PREFIX}Fail: id=x; reason=y\n",
            imprint().to_trailer_value()
        );
        assert!(
            matches!(
                decode(encoded.as_bytes()),
                Err(DecodeError::InvalidField { ref field, .. }) if field == "anchor.sha256"
            ),
            "{fingerprints:?} must be rejected"
        );
    }
}

#[test]
fn an_empty_fingerprint_part_rejects_the_block() {
    for value in [format!("{},,{}", fp(1), fp(2)), format!("{},", fp(1))] {
        let encoded = format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Anchor: id=x; sha256={value}\n{PREFIX}Fail: id=x; reason=y\n",
            imprint().to_trailer_value()
        );
        assert!(
            matches!(
                decode(encoded.as_bytes()),
                Err(DecodeError::InvalidField { .. })
            ),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn anchor_fields_are_strictly_ordered() {
    let good = fp(1);
    for value in [
        format!("sha256={good}; id=x"),
        format!("id=x; algo=sha256; sha256={good}"),
        format!("id=x; sha256={good}; extra=1"),
    ] {
        let encoded = format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Anchor: {value}\n{PREFIX}Fail: id=x; reason=y\n",
            imprint().to_trailer_value()
        );
        assert!(
            matches!(
                decode(encoded.as_bytes()),
                Err(DecodeError::InvalidField { .. })
            ),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn a_repeated_fingerprint_on_one_line_collapses_to_one() {
    let fingerprint = fp(0xab);
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Anchor: id=x; sha256={fingerprint},{fingerprint}\n{PREFIX}Fail: id=x; reason=y\n",
        imprint().to_trailer_value()
    );
    let decoded = decode(encoded.as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded.anchors["x"], vec![fingerprint.clone()]);

    let re_encoded = String::from_utf8(encode(&decoded, usize::MAX).expect("fits")).expect("ASCII");
    let line = re_encoded
        .lines()
        .find(|line| line.starts_with(&format!("{PREFIX}Anchor:")))
        .expect("the anchor survives");
    assert_eq!(
        line,
        format!("{PREFIX}Anchor: id=x; sha256={fingerprint}"),
        "the repeat must be rendered once"
    );
}

#[test]
fn an_anchor_line_without_id_is_rejected() {
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Anchor: sha256={}\n{PREFIX}Fail: id=x; reason=y\n",
        imprint().to_trailer_value(),
        fp(1)
    );
    match decode(encoded.as_bytes()) {
        Err(DecodeError::InvalidField { field, .. }) => assert_eq!(field, "anchor.id"),
        other => panic!("expected a missing `id`, got {other:?}"),
    }
}

#[test]
fn thirty_two_non_hex_octets_are_rejected() {
    let value = vec!["GG"; 32].join(":");
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Anchor: id=x; sha256={value}\n{PREFIX}Fail: id=x; reason=y\n",
        imprint().to_trailer_value()
    );
    match decode(encoded.as_bytes()) {
        Err(DecodeError::InvalidField { field, .. }) => assert_eq!(field, "anchor.sha256"),
        other => panic!("expected an invalid fingerprint, got {other:?}"),
    }
}

#[test]
fn an_anchor_line_after_the_token_it_names_decodes() {
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Token: ver=1; id=x; alg=sha256; nonce=9c1f; tst=KLUv_SQAAQAAmenYUQ\n{PREFIX}Anchor: id=x; sha256={}\n",
        imprint().to_trailer_value(),
        fp(1)
    );
    let decoded = decode(encoded.as_bytes())
        .expect("line order does not decide the reference")
        .expect("has a block");
    assert_eq!(decoded.anchors["x"], vec![fp(1)]);
}

#[test]
fn encode_refuses_a_noncanonical_fingerprint_an_empty_list_and_a_ghost_id() {
    let mut lowercase = block();
    lowercase.tokens.truncate(1);
    lowercase
        .anchors
        .insert("freetsa".to_owned(), vec![fp(0xab).to_lowercase()]);
    match encode(&lowercase, usize::MAX) {
        Err(EncodeError::Invalid { field, .. }) => assert_eq!(field, "anchor.sha256"),
        other => panic!("expected an invalid fingerprint, got {other:?}"),
    }

    let mut empty = block();
    empty.tokens.truncate(1);
    empty.anchors.insert("freetsa".to_owned(), Vec::new());
    match encode(&empty, usize::MAX) {
        Err(EncodeError::Invalid { field, reason, .. }) => {
            assert_eq!(field, "anchor.sha256");
            assert!(reason.contains("at least one"), "{reason}");
        }
        other => panic!("expected an empty list, got {other:?}"),
    }

    let mut ghost = block();
    ghost.tokens.truncate(1);
    ghost.anchors.insert("ghost".to_owned(), vec![fp(1)]);
    match encode(&ghost, usize::MAX) {
        Err(EncodeError::Invalid { field, .. }) => assert_eq!(field, "anchor.id"),
        other => panic!("expected a ghost id, got {other:?}"),
    }
}

#[test]
fn decode_is_order_insensitive_and_accepts_imprint_after_token() {
    let base = lines(&block());
    let mut reordered = Vec::new();
    reordered.extend_from_slice(&base[2..]);
    reordered.push(base[0].clone());
    reordered.extend_from_slice(&base[1..2]);

    let decoded = decode(reordered.join("\n").as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded, block());
}

#[test]
fn an_unknown_field_is_preserved_in_order_and_re_emitted_last() {
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Future: one\n{PREFIX}Object: {}\n{PREFIX}Later: two\n",
        imprint().to_trailer_value(),
        oid()
    );
    let mut decoded = decode(encoded.as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(
        decoded.extra,
        vec![
            ("Future".to_owned(), "one".to_owned()),
            ("Later".to_owned(), "two".to_owned()),
        ]
    );

    let re_encoded = String::from_utf8(encode(&decoded, usize::MAX).expect("fits")).expect("ASCII");
    assert_eq!(
        re_encoded,
        format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Object: {}\n{PREFIX}Future: one\n{PREFIX}Later: two",
            imprint().to_trailer_value(),
            oid()
        )
    );

    decoded.extra.clear();
    let without_extra =
        String::from_utf8(encode(&decoded, usize::MAX).expect("fits")).expect("ASCII");
    assert!(!without_extra.contains("Future"));
}

#[test]
fn extra_values_keep_their_spacing() {
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Note:  two  spaces \n",
        imprint().to_trailer_value()
    );
    let decoded = decode(encoded.as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(
        decoded.extra,
        vec![("Note".to_owned(), " two  spaces ".to_owned())]
    );
    assert_eq!(
        String::from_utf8(encode(&decoded, usize::MAX).expect("fits")).expect("ASCII"),
        encoded.trim_end_matches('\n')
    );
}

#[test]
fn a_failure_reason_may_contain_spaces_on_decode() {
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Fail: id=tsa; reason=connection refused\n",
        imprint().to_trailer_value()
    );
    let decoded = decode(encoded.as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded.failures[0].reason, "connection refused");
}

#[test]
fn encoded_size_accounts_for_every_byte() {
    let mut original = block();
    original.tokens.truncate(1);
    let full = encode(&original, usize::MAX).expect("fits");

    assert_eq!(
        encode(&original, full.len()).expect("exact limit fits"),
        full
    );
}

#[test]
fn an_oversized_block_drops_the_largest_token_and_records_it() {
    let mut original = block();
    let largest = payload(900, 9);
    original.tokens.push(TokenRecord {
        id: "slow-ca".to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: vec![],
        token: largest,
    });
    let full = encode(&original, usize::MAX).expect("fits");
    let limit = full.len() - 20;

    let encoded = encode(&original, limit).expect("one drop is enough");
    assert!(encoded.len() <= limit, "{} > {limit}", encoded.len());

    let decoded = decode(&encoded).expect("decodes").expect("has a block");
    assert!(
        decoded.tokens.iter().all(|token| token.id != "slow-ca"),
        "largest dropped"
    );
    assert_eq!(decoded.tokens.len(), 3);
    assert_eq!(
        decoded.failures,
        vec![FailureRecord {
            id: "slow-ca".to_owned(),
            reason: "oversized".to_owned(),
        }]
    );
}

#[test]
fn with_every_token_dropped_and_still_too_large_the_block_fails() {
    let original = block();

    // The block as it looks after every token was dropped and recorded.
    let mut reduced = original.clone();
    reduced.tokens.clear();
    for id in ["freetsa", "digicert", "sectigo"] {
        reduced.failures.push(FailureRecord {
            id: id.to_owned(),
            reason: "oversized".to_owned(),
        });
    }
    let floor = encode(&reduced, usize::MAX).expect("fits").len();
    let limit = floor - 1;

    let err = encode(&original, limit).expect_err("nothing left to drop");
    let EncodeError::TooLarge { attempted, limit } = err else {
        panic!("expected TooLarge, got {err:?}");
    };
    assert_eq!(attempted, floor);
    assert!(attempted > limit);
}

#[test]
fn every_token_can_be_dropped_until_only_the_imprint_and_failures_remain() {
    let original = block();
    // Room for the imprint, the object and a failure line per dropped token.
    let mut dropped = original.clone();
    dropped.tokens.clear();
    for id in ["freetsa", "digicert", "sectigo"] {
        dropped.failures.push(FailureRecord {
            id: id.to_owned(),
            reason: "oversized".to_owned(),
        });
    }
    let limit = encode(&dropped, usize::MAX).expect("fits").len();

    let encoded = encode(&original, limit).expect("fits once all tokens are gone");
    let decoded = decode(&encoded).expect("decodes").expect("has a block");
    assert!(decoded.tokens.is_empty());
    assert_eq!(decoded.failures.len(), 3);
    assert!(
        decoded
            .failures
            .iter()
            .all(|failure| failure.reason == "oversized")
    );
}

#[test]
fn encode_rejects_values_with_spaces_semicolons_or_newlines() {
    let mut with_space = block();
    with_space.tokens.truncate(1);
    with_space.tokens[0].id = "two words".to_owned();
    assert!(matches!(
        encode(&with_space, usize::MAX),
        Err(EncodeError::Invalid { .. })
    ));

    let mut with_semicolon = block();
    with_semicolon.tokens.truncate(1);
    with_semicolon.tokens[0].id = "a;b".to_owned();
    assert!(matches!(
        encode(&with_semicolon, usize::MAX),
        Err(EncodeError::Invalid { .. })
    ));

    let mut with_newline = block();
    with_newline.failures.push(FailureRecord {
        id: "x".to_owned(),
        reason: "a\nb".to_owned(),
    });
    assert!(matches!(
        encode(&with_newline, usize::MAX),
        Err(EncodeError::Invalid { .. })
    ));
}

#[test]
fn encode_reports_which_token_index_is_invalid() {
    let mut original = block();
    original.tokens[1].id = "two words".to_owned();

    let Err(EncodeError::Invalid {
        field,
        token,
        reason,
    }) = encode(&original, usize::MAX)
    else {
        panic!("expected an invalid token id");
    };
    assert_eq!(field, "id");
    assert_eq!(token, Some(1), "the offending token must be named");
    assert_eq!(reason, "a value may not contain a space");
}

#[test]
fn an_extra_name_may_use_any_byte_but_colon_space_or_line_break() {
    let mut original = block();
    original.extra = vec![
        ("Future_v2".to_owned(), "underscore".to_owned()),
        ("A.b+c/d".to_owned(), "punctuation".to_owned()),
    ];
    let decoded = decode(encode(&original, usize::MAX).expect("fits").as_slice())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded, original);
}

#[test]
fn an_extra_name_with_a_space_is_rejected_both_ways() {
    let mut with_space = block();
    with_space.extra = vec![("Two Words".to_owned(), "x".to_owned())];
    match encode(&with_space, usize::MAX) {
        Err(EncodeError::Invalid {
            field,
            token,
            reason,
        }) => {
            assert_eq!(field, "extra.name");
            assert_eq!(token, None);
            assert!(reason.contains("space"), "{reason}");
        }
        other => panic!("expected an invalid extra name, got {other:?}"),
    }

    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Two Words: x\n",
        imprint().to_trailer_value()
    );
    assert!(matches!(
        decode(encoded.as_bytes()),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn decode_rejects_a_token_without_imprint() {
    let encoded =
        format!("{PREFIX}Token: ver=1; id=x; alg=sha256; nonce=9c; tst=KLUv_SQAAQAAmenYUQ\n");
    assert_eq!(
        decode(encoded.as_bytes()).unwrap_err(),
        DecodeError::MissingImprint
    );
}

#[test]
fn decode_rejects_a_block_without_imprint_but_with_failures() {
    let encoded = format!("{PREFIX}Fail: id=x; reason=y\n");
    assert_eq!(
        decode(encoded.as_bytes()).unwrap_err(),
        DecodeError::MissingImprint
    );
}

#[test]
fn decode_rejects_garbage_token_payloads() {
    let values = [
        "!!not-base64!!".to_owned(),
        "%%%%%%%%".to_owned(),
        "KLUv_SQAAQAAmenYUQ==".to_owned(), // padded, not unpadded base64url
    ];
    for value in values {
        let encoded = format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Token: ver=1; id=x; alg=sha256; nonce=9c1f; tst={value}\n",
            imprint().to_trailer_value()
        );
        assert!(
            matches!(
                decode(encoded.as_bytes()),
                Err(DecodeError::InvalidField { .. })
            ),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn decode_rejects_a_base64url_payload_that_is_not_a_zstd_frame() {
    use base64::Engine as _;
    let not_a_frame = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not a zstd frame");
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Token: ver=1; id=x; alg=sha256; nonce=9c1f; tst={not_a_frame}\n",
        imprint().to_trailer_value()
    );
    match decode(encoded.as_bytes()) {
        Err(DecodeError::InvalidField { field, reason }) => {
            assert_eq!(field, "tst");
            assert!(reason.contains("not a zstd frame"), "{reason}");
        }
        other => panic!("expected an invalid `tst`, got {other:?}"),
    }
}

#[test]
fn a_frame_announcing_more_than_the_cap_is_rejected_before_reading() {
    // One-shot compression writes the content size into the frame header, so
    // the cap can be enforced without inflating anything. Zeros keep the
    // compressed input tiny while the announcement is huge.
    let huge = vec![0_u8; 8 * 1024 * 1024];
    let compressed = zstd::bulk::compress(&huge, 19).expect("compresses");
    assert!(
        zstd::zstd_safe::get_frame_content_size(&compressed)
            .expect("valid frame")
            .is_some_and(|size| size > MAX_TOKEN_BYTES as u64)
    );
    assert!(compressed.len() < 64 * 1024, "{}", compressed.len());

    use base64::Engine as _;
    let tst = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Token: ver=1; id=x; alg=sha256; nonce=9c1f; tst={tst}\n",
        imprint().to_trailer_value()
    );

    peak_reset();
    let start = Instant::now();
    match decode(encoded.as_bytes()) {
        Err(DecodeError::InvalidField { field, reason }) => {
            assert_eq!(field, "tst");
            assert!(
                reason.contains("cap") && reason.contains("announces"),
                "{reason}"
            );
        }
        other => panic!("expected an oversized `tst`, got {other:?}"),
    }
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(
        peak() < MAX_TOKEN_BYTES,
        "peak {} shows the announced frame was read",
        peak()
    );
}

#[test]
fn a_streamed_frame_is_cut_off_at_the_cap_without_being_inflated_whole() {
    use std::io::Write as _;

    // A streamed frame carries no content size, so only the read path can
    // enforce the cap: 64 MiB of one repeated byte compresses into a few KB.
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 19).expect("encoder");
    let chunk = vec![0x5a_u8; 1024 * 1024];
    for _ in 0..64 {
        encoder.write_all(&chunk).expect("writes");
    }
    let compressed = encoder.finish().expect("finishes");
    assert_eq!(
        zstd::zstd_safe::get_frame_content_size(&compressed).expect("valid frame"),
        None,
        "the frame must not announce its size, or the header path would short-circuit"
    );

    use base64::Engine as _;
    let tst = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Token: ver=1; id=x; alg=sha256; nonce=9c1f; tst={tst}\n",
        imprint().to_trailer_value()
    );

    peak_reset();
    let start = Instant::now();
    match decode(encoded.as_bytes()) {
        Err(DecodeError::InvalidField { field, reason }) => {
            assert_eq!(field, "tst");
            assert!(reason.contains("cap"), "{reason}");
        }
        other => panic!("expected an oversized `tst`, got {other:?}"),
    }
    let elapsed = start.elapsed();
    let peak = peak();

    // Decoding the same frame whole would allocate 64 MiB.
    assert_eq!(
        zstd::stream::decode_all(compressed.as_slice())
            .expect("zstd")
            .len(),
        64 * 1024 * 1024
    );
    assert!(
        peak < 4 * MAX_TOKEN_BYTES,
        "peak single allocation {peak} is not bounded by the cap"
    );
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

#[test]
fn a_normal_token_still_round_trips_under_the_cap() {
    let mut original = block();
    original.tokens = vec![token("normal", 13, 5 * 1024)];
    let decoded = decode(encode(&original, usize::MAX).expect("fits").as_slice())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded, original);
    assert!(decoded.tokens[0].token.len() < MAX_TOKEN_BYTES);
}

#[test]
fn a_token_over_the_cap_is_dropped_with_a_failure_and_still_decodes() {
    let mut original = block();
    original.tokens.push(TokenRecord {
        id: "over-cap".to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: vec![0x11, 0x22],
        token: payload(MAX_TOKEN_BYTES + 1, 7),
    });

    let encoded = encode(&original, usize::MAX).expect("the rest fits");
    let wire = String::from_utf8(encoded.clone()).expect("ASCII");
    assert!(
        wire.lines()
            .filter(|line| line.starts_with("X-RFC3161-Token:"))
            .all(|line| !line.contains("id=over-cap")),
        "the over-cap token must not reach the block"
    );

    // The point of the rule: what encode wrote, its own decode accepts.
    let decoded = decode(&encoded)
        .expect("encode cannot produce a block decode rejects")
        .expect("has a block");
    assert_eq!(decoded.tokens.len(), 3);
    assert!(decoded.tokens.iter().all(|token| token.id != "over-cap"));
    assert_eq!(
        decoded.failures,
        vec![FailureRecord {
            id: "over-cap".to_owned(),
            reason: "oversized".to_owned(),
        }]
    );
}

#[test]
fn a_token_exactly_at_the_cap_still_round_trips() {
    let mut original = block();
    original.tokens = vec![TokenRecord {
        id: "at-cap".to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: vec![0x9c, 0x1f],
        token: payload(MAX_TOKEN_BYTES, 8),
    }];

    let decoded = decode(encode(&original, usize::MAX).expect("fits").as_slice())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded.tokens.len(), 1);
    assert_eq!(decoded.tokens[0].token.len(), MAX_TOKEN_BYTES);
    assert!(decoded.failures.is_empty());
}

#[test]
fn decode_rejects_an_empty_token_payload() {
    let encoded = format!(
        "{PREFIX}Imprint: {}\n{PREFIX}Token: ver=1; id=x; alg=sha256; nonce=9c1f; tst=\n",
        imprint().to_trailer_value()
    );
    assert!(matches!(
        decode(encoded.as_bytes()),
        Err(DecodeError::InvalidField { .. })
    ));
}

#[test]
fn ver_must_come_first_and_equal_one() {
    for value in [
        "ver=2; id=x; alg=sha256; nonce=9c1f; tst=KLUv_SQAAQAAmenYUQ",
        "id=x; ver=1; alg=sha256; nonce=9c1f; tst=KLUv_SQAAQAAmenYUQ",
        "ver=1; alg=sha256; id=x; nonce=9c1f; tst=KLUv_SQAAQAAmenYUQ",
        "ver=1; id=x; nonce=9c1f; alg=sha256; tst=KLUv_SQAAQAAmenYUQ",
        "ver=1; id=x; alg=sha256; nonce=9c1f; tst=KLUv_SQAAQAAmenYUQ; policy=1.2",
        "ver=1; id=x; alg=sha256; nonce=9c1f; tst=KLUv_SQAAQAAmenYUQ; extra=1",
        "ver=1; id=x; alg=sha256; nonce=9c1f; tst=KLUv_SQAAQAAmenYUQ; ",
    ] {
        let encoded = format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Token: {value}\n",
            imprint().to_trailer_value()
        );
        assert!(
            decode(encoded.as_bytes()).is_err(),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn decode_rejects_fields_without_exactly_one_equals_sign() {
    for value in [
        "ver=1; id; alg=sha256; nonce=9c1f; tst=KLUv_SQAAQAAmenYUQ",
        "ver=1; id=a=b; alg=sha256; nonce=9c1f; tst=KLUv_SQAAQAAmenYUQ",
        "ver=1; id=x; alg=sha256; =9c1f; tst=KLUv_SQAAQAAmenYUQ",
    ] {
        let encoded = format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Token: {value}\n",
            imprint().to_trailer_value()
        );
        assert!(
            matches!(
                decode(encoded.as_bytes()),
                Err(DecodeError::InvalidField { .. })
            ),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn decode_rejects_a_failure_line_without_exactly_two_fields() {
    for value in [
        "id=x",
        "id=x; reason=y; extra=z",
        "reason=y; id=x",
        "id x; reason y",
    ] {
        let encoded = format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Fail: {value}\n",
            imprint().to_trailer_value()
        );
        assert!(
            matches!(
                decode(encoded.as_bytes()),
                Err(DecodeError::InvalidField { .. })
            ),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn an_object_oid_must_be_lowercase_hex_of_40_or_64_digits() {
    let good = [oid(), "a".repeat(40), "b".repeat(64)];
    for value in good {
        let encoded = format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Object: {value}\n",
            imprint().to_trailer_value()
        );
        let decoded = decode(encoded.as_bytes()).expect("decodes");
        assert_eq!(decoded.and_then(|block| block.object), Some(value));
    }

    let bad = [
        oid().to_uppercase(),
        "a".repeat(39),
        "a".repeat(41),
        "a".repeat(63),
        "a".repeat(65),
        "g".repeat(40),
        String::new(),
    ];
    for value in bad {
        let encoded = format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Object: {value}\n",
            imprint().to_trailer_value()
        );
        assert!(
            matches!(
                decode(encoded.as_bytes()),
                Err(DecodeError::InvalidField { .. })
            ),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn decode_rejects_a_malformed_imprint() {
    for value in ["", "sha256", "sha256:00", "md5:00"] {
        let encoded = format!("{PREFIX}Imprint: {value}\n");
        assert!(
            matches!(decode(encoded.as_bytes()), Err(DecodeError::Malformed(_))),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn decode_rejects_a_duplicate_imprint_or_object() {
    let imprint_line = format!("{PREFIX}Imprint: {}", imprint().to_trailer_value());
    let duplicate_imprint = format!("{imprint_line}\n{imprint_line}\n");
    assert!(matches!(
        decode(duplicate_imprint.as_bytes()),
        Err(DecodeError::Malformed(_))
    ));

    let object_line = format!("{PREFIX}Object: {}", oid());
    let duplicate_object = format!("{imprint_line}\n{object_line}\n{object_line}\n");
    assert!(matches!(
        decode(duplicate_object.as_bytes()),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn decode_rejects_a_malformed_field_line() {
    for line in [
        format!("{PREFIX}Imprint:{}", imprint().to_trailer_value()),
        format!("{PREFIX}Object"),
        format!(
            "{PREFIX}Imprint: {}\n{PREFIX}Token ver=1",
            imprint().to_trailer_value()
        ),
    ] {
        assert!(
            matches!(decode(line.as_bytes()), Err(DecodeError::Malformed(_))),
            "{line:?} must be rejected"
        );
    }
}

#[test]
fn an_input_without_any_rfc3161_line_is_none() {
    assert_eq!(decode(b""), Ok(None));
    assert_eq!(decode(b"body\n"), Ok(None));
    assert_eq!(decode(b"Signed-off-by: x <x@example.com>\n"), Ok(None));
    assert_eq!(decode(b"X-RFC3161X-Imprint: sha256:00\n"), Ok(None));
}

#[test]
fn lines_with_other_prefixes_are_ignored_between_the_block_lines() {
    let mut encoded =
        String::from_utf8(encode(&block(), usize::MAX).expect("fits")).expect("ASCII");
    encoded.insert_str(0, "Signed-off-by: x <x@example.com>\n");
    let decoded = decode(encoded.as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded, block());
}

#[test]
fn token_bytes_are_never_utf8_converted() {
    // Byte sequences that are invalid UTF-8 survive through the codec.
    let mut original = block();
    original.tokens = vec![TokenRecord {
        token: vec![0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28],
        ..token("raw", 5, 6)
    }];
    let decoded = decode(encode(&original, usize::MAX).expect("fits").as_slice())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded, original);
}

#[test]
fn encoding_the_same_block_twice_is_deterministic() {
    let original = block();
    assert_eq!(
        encode(&original, usize::MAX).expect("fits"),
        encode(&original, usize::MAX).expect("fits")
    );
}

#[test]
fn tst_is_the_zstd_compressed_base64url_token() {
    // Highly compressible token bytes, so the level-19 compression is visible.
    let mut original = block();
    original.tokens = vec![TokenRecord {
        policy: None,
        token: vec![0x5a; 4096],
        ..token("zsty", 7, 0)
    }];
    let encoded = String::from_utf8(encode(&original, usize::MAX).expect("fits")).expect("ASCII");
    let wire = tst_of(encoded.split('\n').nth(2).expect("token line"));

    use base64::Engine as _;
    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(wire)
        .expect("base64url");
    let raw = zstd::stream::decode_all(compressed.as_slice()).expect("zstd");
    assert_eq!(raw, original.tokens[0].token);
    // Compression actually happened: 4096 identical bytes are not stored raw.
    assert!(compressed.len() < 100, "{} bytes", compressed.len());
}

#[test]
fn crlf_line_endings_are_tolerated() {
    let mut encoded =
        String::from_utf8(encode(&block(), usize::MAX).expect("fits")).expect("ASCII");
    encoded.push('\n');
    let encoded = encoded.replace('\n', "\r\n");
    let decoded = decode(encoded.as_bytes())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded, block());
}

#[test]
fn empty_ids_policies_and_nonces_round_trip() {
    let mut original = block();
    original.tokens = vec![TokenRecord {
        id: String::new(),
        policy: Some(String::new()),
        nonce: Vec::new(),
        ..token("", 3, 20)
    }];
    original.failures = vec![FailureRecord {
        id: String::new(),
        reason: String::new(),
    }];

    let decoded = decode(encode(&original, usize::MAX).expect("fits").as_slice())
        .expect("decodes")
        .expect("has a block");
    assert_eq!(decoded, original);
}
