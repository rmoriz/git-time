//! Composition is the exact inverse of parsing, and pre-images strip the
//! timestamp trailer plus every signature.

use git_time_core::object::{CommitObject, ParseError, PreImage};
use proptest::prelude::*;

const PREFIX: &str = "X-RFC3161-";

/// The trailer block's lines as `PreImage::trailer` reports them: verbatim, no
/// separating blank line, no trailing newline.
const TRAILER: &[u8] = b"X-RFC3161-Imprint: sha256:9f2c41\n\
X-RFC3161-Object: 4f1c9e0\n\
X-RFC3161-Token: ver=1; id=freetsa; tst=AA\n\
X-RFC3161-Fail: id=sectigo; reason=http-503";

/// Append a trailer block to an object: one `\n` (the separating blank line),
/// the block, and a final `\n`.
fn sealed(object: &[u8]) -> Vec<u8> {
    let mut out = object.to_vec();
    out.push(b'\n');
    out.extend_from_slice(TRAILER);
    out.push(b'\n');
    out
}

/// The documented rebuild rule: `bytes`, one `\n`, `trailer`, a final `\n`.
fn rebuilt(pre_image: &PreImage) -> Vec<u8> {
    let mut out = pre_image.bytes.clone();
    out.push(b'\n');
    out.extend_from_slice(pre_image.trailer.as_deref().expect("has a trailer"));
    out.push(b'\n');
    out
}

/// An object composed from `headers` (name, unfolded value) and `message`.
fn object(headers: &[(&str, &[u8])], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, (name, value)) in headers.iter().enumerate() {
        if index > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(name.as_bytes());
        out.push(b' ');
        for (part, line) in value.split(|byte| *byte == b'\n').enumerate() {
            if part > 0 {
                out.extend_from_slice(b"\n ");
            }
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(b"\n\n");
    out.extend_from_slice(message);
    out
}

fn base_headers() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("tree", b"4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
        ("parent", b"5a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b"),
        ("author", b"Ada <ada@example.org> 1700000000 +0100"),
        ("committer", b"Ada <ada@example.org> 1700000060 +0100"),
    ]
}

const SIGNATURE: &[u8] =
    b"-----BEGIN PGP SIGNATURE-----\n\niQIzBAABCAAdFiEEexample\n-----END PGP SIGNATURE-----";

/// Hostile and ordinary shapes a real object can take. Every one of them must
/// survive `parse` then `compose` byte for byte.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("plain", object(&base_headers(), b"subject\n\nbody\n")),
        (
            "signed",
            object(
                &{
                    let mut headers = base_headers();
                    headers.push(("gpgsig", SIGNATURE));
                    headers
                },
                b"signed subject\n",
            ),
        ),
        (
            "mergetag with a blank continuation line",
            object(
                &{
                    let mut headers = base_headers();
                    headers.push((
                        "mergetag",
                        b"object 1f2e3d4c5b6a7988aabbccddeeff001122334455\n\
type commit\ntag v1.0.0\n\ntag body\n-----BEGIN PGP SIGNATURE-----",
                    ));
                    headers
                },
                b"Merge tag 'v1.0.0'\n",
            ),
        ),
        (
            "encoding and a latin-1 message",
            object(
                &{
                    let mut headers = base_headers();
                    headers.push(("encoding", b"ISO-8859-1"));
                    headers
                },
                b"Merge branch 'topic'\nF\xE4hn\n",
            ),
        ),
        ("empty message", object(&base_headers(), b"")),
        (
            "trailing blank lines",
            object(&base_headers(), b"body\n\n\n\n"),
        ),
        (
            "trailing whitespace",
            object(&base_headers(), b"body \n\t\n"),
        ),
        ("no trailing newline", object(&base_headers(), b"body")),
        ("empty headers and empty message", object(&[], b"")),
        ("no headers, plain message", object(&[], b"body\n")),
        (
            "unknown header and gpgsig-sha256",
            object(
                &{
                    let mut headers = base_headers();
                    headers.push(("x-reviewed-by", b"Grace <grace@example.org>"));
                    headers.push(("gpgsig-sha256", b"-----BEGIN SSH SIGNATURE-----"));
                    headers
                },
                b"body\n",
            ),
        ),
    ]
}

#[test]
fn compose_round_trips_every_corpus_shape() {
    for (name, bytes) in corpus() {
        let parsed = CommitObject::parse(&bytes).unwrap_or_else(|error| {
            panic!("corpus case {name:?} must parse, got {error:?}");
        });
        assert_eq!(parsed.compose(), bytes, "corpus case {name:?} differs");
    }
}

#[test]
fn parse_is_the_inverse_of_compose() {
    for (name, bytes) in corpus() {
        let once = CommitObject::parse(&bytes).expect("corpus parses");
        let again = CommitObject::parse(&once.compose()).expect("composition parses");
        assert_eq!(again, once, "corpus case {name:?} differs");
    }
}

#[test]
fn compose_emits_continuations_with_a_single_folded_space() {
    let commit = CommitObject::parse(b"mergetag a\n b\n \n c\n\nbody\n").expect("parses");
    assert_eq!(commit.header("mergetag"), Some(b"a\nb\n\nc".as_slice()));
    assert_eq!(commit.compose(), b"mergetag a\n b\n \n c\n\nbody\n");
}

#[test]
fn compose_of_nothing_is_the_bare_separator() {
    let commit = CommitObject {
        headers: Vec::new(),
        message: Vec::new(),
    };
    assert_eq!(commit.compose(), b"\n\n");
    assert_eq!(CommitObject::parse(b"\n\n"), Ok(commit));
}

// A CRLF object is rejected on purpose: git writes LF, and a `\r` would end up
// inside the last header value / message instead of being normalised away.
#[test]
fn crlf_in_the_header_section_is_rejected_on_purpose() {
    assert_eq!(
        CommitObject::parse(b"tree 4b82\r\n\r\nbody\r\n").unwrap_err(),
        ParseError::MissingSeparator
    );
}

#[test]
fn crlf_in_the_message_is_preserved_verbatim() {
    let bytes = b"tree 4b82\n\nbody\r\nsubject\r\n";
    let commit = CommitObject::parse(bytes).expect("parses");
    assert_eq!(commit.message, b"body\r\nsubject\r\n");
    assert_eq!(commit.compose(), bytes);
}

#[test]
fn pre_image_reproduces_the_pre_seal_object() {
    let original = object(&base_headers(), b"subject\n\nbody\n");
    let sealed = sealed(&original);
    assert_ne!(sealed, original);

    let commit = CommitObject::parse(&sealed).expect("sealed object parses");
    let pre_image = commit.pre_image(PREFIX);

    assert_eq!(pre_image.bytes, original);
    assert_eq!(pre_image.trailer.as_deref(), Some(TRAILER));
    assert_eq!(rebuilt(&pre_image), sealed);
}

#[test]
fn pre_image_reports_the_trailer_verbatim_even_with_a_signature() {
    // A stripped `gpgsig` shifts every offset in the source object, so the block
    // has to travel as bytes rather than as a range.
    let original = object(
        &{
            let mut headers = base_headers();
            headers.push(("gpgsig", SIGNATURE));
            headers
        },
        b"body\n",
    );
    let sealed_signed = sealed(&original);
    let commit = CommitObject::parse(&sealed_signed).expect("parses");
    let pre_image = commit.pre_image(PREFIX);

    let expected = object(&base_headers(), b"body\n");
    assert_eq!(pre_image.bytes, expected);
    assert_eq!(pre_image.trailer.as_deref(), Some(TRAILER));
    // Rebuilding yields the signature-free object; the signature is re-created
    // separately after sealing.
    assert_eq!(rebuilt(&pre_image), sealed(&expected));

    // The block still sits at the end of the sealed object, but at an offset the
    // signature-stripped bytes no longer match.
    let trailer_at = sealed_signed.len() - TRAILER.len() - 1;
    assert_eq!(
        &sealed_signed[trailer_at..trailer_at + TRAILER.len()],
        TRAILER
    );
    assert_ne!(trailer_at, pre_image.bytes.len() + 1, "signature shifts");
}

#[test]
fn rebuilding_adds_the_separator_newline_although_bytes_ends_with_one() {
    // The common case: the message ends with `\n` and the block is its own
    // paragraph, so the blank line is the byte `pre_image` removed even though a
    // message newline is right before it.
    let original = object(&base_headers(), b"body\n");
    assert!(original.ends_with(b"\n"));
    let commit = CommitObject::parse(&sealed(&original)).expect("parses");
    assert_eq!(rebuilt(&commit.pre_image(PREFIX)), sealed(&original));
}

#[test]
fn a_block_that_starts_the_message_has_no_separator_to_strip() {
    // Hand-written shape (`git` itself always appends a `\n` first): the block is
    // the whole message, so there is no separator byte and `bytes` keeps the two
    // separator newlines of the object itself.
    let hand_written = b"tree 4b82\n\nX-RFC3161-Imprint: sha256:00\n";
    let commit = CommitObject::parse(hand_written).expect("parses");
    let pre_image = commit.pre_image(PREFIX);
    assert_eq!(pre_image.bytes, b"tree 4b82\n\n");
    assert_eq!(
        pre_image.trailer.as_deref(),
        Some(b"X-RFC3161-Imprint: sha256:00".as_slice())
    );
    assert_eq!(
        rebuilt(&pre_image),
        b"tree 4b82\n\n\nX-RFC3161-Imprint: sha256:00\n"
    );
}

#[test]
fn pre_image_preserves_trailing_newlines_of_the_message() {
    for tail in [&b"body\n"[..], b"body\n\n", b"body\n\n\n", b"body \n"] {
        let original = object(&base_headers(), tail);
        let commit = CommitObject::parse(&sealed(&original)).expect("parses");
        let pre_image = commit.pre_image(PREFIX);
        assert_eq!(pre_image.bytes, original, "tail {tail:?} must survive");
        assert_eq!(rebuilt(&pre_image), sealed(&original), "tail {tail:?}");
    }
}

#[test]
fn pre_image_of_a_sealed_empty_message_is_the_empty_message() {
    let original = object(&base_headers(), b"");
    let commit = CommitObject::parse(&sealed(&original)).expect("parses");
    let pre_image = commit.pre_image(PREFIX);
    assert_eq!(pre_image.bytes, original);
    assert_eq!(pre_image.trailer.as_deref(), Some(TRAILER));
    assert_eq!(rebuilt(&pre_image), sealed(&original));
}

#[test]
fn a_trailer_followed_by_a_trailing_blank_line_is_not_a_trailer() {
    // The block has to be the last paragraph, so a blank line after it makes the
    // last paragraph empty and nothing is stripped. Sealing again appends a
    // fresh block after it.
    let original = object(&base_headers(), b"body\n");
    let mut with_blank_after_trailer = sealed(&original);
    with_blank_after_trailer.push(b'\n');
    let commit = CommitObject::parse(&with_blank_after_trailer).expect("parses");
    let pre_image = commit.pre_image(PREFIX);
    assert_eq!(pre_image.trailer, None);
    assert_eq!(pre_image.bytes, with_blank_after_trailer);
}

#[test]
fn a_last_paragraph_mixing_prefix_and_other_lines_is_not_a_trailer() {
    let message = b"body\nX-RFC3161-Token: id=a\nnot a trailer\n";
    let original = object(&base_headers(), message);
    let commit = CommitObject::parse(&original).expect("parses");
    let pre_image = commit.pre_image(PREFIX);
    assert_eq!(pre_image.trailer, None);
    assert_eq!(pre_image.bytes, original);
}

#[test]
fn pre_image_reports_no_trailer_for_an_unsealed_object() {
    let original = object(&base_headers(), b"body\n");
    let commit = CommitObject::parse(&original).expect("parses");
    let pre_image = commit.pre_image(PREFIX);
    assert_eq!(pre_image.trailer, None);
    assert_eq!(pre_image.bytes, original);
}

#[test]
fn pre_image_keeps_a_trailer_looking_line_that_is_not_the_last_paragraph() {
    let original = object(&base_headers(), b"X-RFC3161-Token: id=mid\n\nbody\n");
    let commit = CommitObject::parse(&original).expect("parses");
    let pre_image = commit.pre_image(PREFIX);
    assert_eq!(pre_image.trailer, None);
    assert_eq!(pre_image.bytes, original);
}

#[test]
fn pre_image_keeps_the_first_of_two_trailer_blocks_in_the_message() {
    let stale = sealed(&object(&base_headers(), b"body\n"));
    let commit = CommitObject::parse(&sealed(&stale)).expect("parses");
    let pre_image = commit.pre_image(PREFIX);
    assert_eq!(pre_image.bytes, stale, "only the last block is stripped");
    assert_eq!(pre_image.trailer.as_deref(), Some(TRAILER));
}

#[test]
fn pre_image_drops_every_signature_header_with_its_continuations() {
    let sealed_signed = object(
        &{
            let mut headers = base_headers();
            headers.push(("gpgsig", SIGNATURE));
            headers.push(("x-reviewed-by", b"Grace <grace@example.org>"));
            headers.push(("gpgsig-sha256", b"-----BEGIN SSH SIGNATURE-----\nAAAA"));
            headers
        },
        &sealed(b"body\n"),
    );
    let commit = CommitObject::parse(&sealed_signed).expect("parses");

    let expected = object(
        &{
            let mut headers = base_headers();
            headers.push(("x-reviewed-by", b"Grace <grace@example.org>"));
            headers
        },
        b"body\n",
    );
    assert_eq!(commit.pre_image(PREFIX).bytes, expected);
}

#[test]
fn pre_image_strips_nothing_when_the_prefix_does_not_match() {
    let original = sealed(&object(&base_headers(), b"body\n"));
    let commit = CommitObject::parse(&original).expect("parses");
    let pre_image = commit.pre_image("X-Other-");
    assert_eq!(pre_image.trailer, None);
    assert_eq!(pre_image.bytes, original);
}

#[test]
fn without_signature_only_drops_signature_headers() {
    let bytes = object(
        &{
            let mut headers = base_headers();
            headers.push(("gpgsig", SIGNATURE));
            headers.push(("gpgsig-sha256", b"AAAA"));
            headers
        },
        b"body\n\n\n",
    );
    let commit = CommitObject::parse(&bytes).expect("parses");
    let stripped = commit.without_signature();

    let names: Vec<&[u8]> = stripped
        .headers
        .iter()
        .map(|(name, _)| name.as_slice())
        .collect();
    assert_eq!(
        names,
        vec![
            b"tree".as_slice(),
            b"parent".as_slice(),
            b"author".as_slice(),
            b"committer".as_slice(),
        ]
    );
    assert_eq!(stripped.message, commit.message);
    assert_eq!(stripped, commit.without_signature());
    assert_eq!(stripped.compose(), object(&base_headers(), b"body\n\n\n"));
}

#[test]
fn without_signature_keeps_an_already_unsigned_object_unchanged() {
    let commit = CommitObject::parse(&object(&base_headers(), b"body\n")).expect("parses");
    assert_eq!(commit.without_signature(), commit);
}

#[test]
fn without_signature_keeps_the_trailer_that_pre_image_strips() {
    let sealed = sealed(&object(&base_headers(), b"body\n"));
    let commit = CommitObject::parse(&sealed).expect("parses");
    assert_eq!(commit.without_signature().compose(), sealed);
    assert_eq!(
        commit.pre_image(PREFIX).bytes,
        object(&base_headers(), b"body\n")
    );
}

// -- literal oracle ---------------------------------------------------------

/// A `git cat-file commit` dump written out by hand — folded `mergetag`
/// continuations, an `encoding` header, a latin-1 message — so neither test
/// below depends on `compose`'s own join/fold logic.
const CAT_FILE: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
parent 5a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b\n\
parent 1f2e3d4c5b6a7988aabbccddeeff001122334455\n\
author Ada <ada@example.org> 1700000000 +0100\n\
committer Ada <ada@example.org> 1700000060 +0100\n\
mergetag object 1f2e3d4c5b6a7988aabbccddeeff001122334455\n\
\x20type commit\n\
\x20tag v1.0.0\n\
\x20tagger Grace <grace@example.org> 1699999000 +0100\n\
\x20\n\
\x20signed tag body\n\
\x20-----BEGIN PGP SIGNATURE-----\n\
\x20\n\
\x20iQIzBAABCAAdFiEEexample\n\
\x20-----END PGP SIGNATURE-----\n\
encoding ISO-8859-1\n\
\n\
Merge branch 'topic'\n\
F\xE4hn\n";

/// The same dump after sealing: one blank line, the block, a final newline.
const CAT_FILE_SEALED: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
parent 5a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b\n\
parent 1f2e3d4c5b6a7988aabbccddeeff001122334455\n\
author Ada <ada@example.org> 1700000000 +0100\n\
committer Ada <ada@example.org> 1700000060 +0100\n\
mergetag object 1f2e3d4c5b6a7988aabbccddeeff001122334455\n\
\x20type commit\n\
\x20tag v1.0.0\n\
\x20tagger Grace <grace@example.org> 1699999000 +0100\n\
\x20\n\
\x20signed tag body\n\
\x20-----BEGIN PGP SIGNATURE-----\n\
\x20\n\
\x20iQIzBAABCAAdFiEEexample\n\
\x20-----END PGP SIGNATURE-----\n\
encoding ISO-8859-1\n\
\n\
Merge branch 'topic'\n\
F\xE4hn\n\
\n\
X-RFC3161-Imprint: sha256:9f2c41\n\
X-RFC3161-Fail: id=sectigo; reason=http-503\n";

#[test]
fn compose_reproduces_a_literal_cat_file_dump() {
    assert_eq!(
        CommitObject::parse(CAT_FILE).expect("parses").compose(),
        CAT_FILE
    );
}

#[test]
fn pre_image_strips_a_literal_sealed_dump() {
    let commit = CommitObject::parse(CAT_FILE_SEALED).expect("parses");
    let pre_image = commit.pre_image(PREFIX);
    assert_eq!(pre_image.bytes, CAT_FILE);
    assert_eq!(
        pre_image.trailer.as_deref(),
        Some(
            b"X-RFC3161-Imprint: sha256:9f2c41\nX-RFC3161-Fail: id=sectigo; reason=http-503"
                .as_slice()
        )
    );
    assert_eq!(rebuilt(&pre_image), CAT_FILE_SEALED);
}

#[test]
fn pre_image_keeps_the_mergetag_and_encoding_of_a_literal_dump() {
    let commit = CommitObject::parse(CAT_FILE_SEALED).expect("parses");
    let stripped = CommitObject::parse(&commit.pre_image(PREFIX).bytes).expect("parses");
    assert_eq!(stripped.headers, commit.without_signature().headers);
    assert_eq!(stripped.header("encoding"), Some(b"ISO-8859-1".as_slice()));
    let mergetag = stripped.header("mergetag").expect("mergetag survives");
    assert!(mergetag.windows(2).any(|pair| pair == b"\n\n"));
    assert!(mergetag.ends_with(b"-----END PGP SIGNATURE-----"));
    assert!(mergetag.starts_with(b"object 1f2e"));
    assert_eq!(stripped.message, b"Merge branch 'topic'\nF\xE4hn\n");
}

// -- properties ------------------------------------------------------------

fn header_name() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            prop::char::range('a', 'z'),
            prop::char::range('0', '9'),
            Just('-'),
        ],
        1..12,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn header_value() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            prop::char::range('a', 'z'),
            Just('\n'),
            Just(' '),
            Just('\t'),
        ],
        0..40,
    )
    .prop_map(|chars| chars.into_iter().map(|byte| byte as u8).collect())
}

fn message() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            prop::char::range('a', 'z'),
            Just('\n'),
            Just(' '),
            Just('\t'),
            Just('X'),
        ],
        0..80,
    )
    .prop_map(|chars| chars.into_iter().map(|byte| byte as u8).collect())
}

fn commit_object() -> impl Strategy<Value = CommitObject> {
    (
        proptest::collection::vec((header_name(), header_value()), 0..6),
        message(),
    )
        .prop_map(|(headers, message)| CommitObject {
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into_bytes(), value))
                .collect(),
            message,
        })
}

proptest! {
    #[test]
    fn parse_round_trips_any_composed_object(commit in commit_object()) {
        let bytes = commit.compose();
        let parsed = CommitObject::parse(&bytes);
        prop_assert_eq!(parsed, Ok(commit.clone()));
    }

    #[test]
    fn composing_independently_parsed_copies_agrees(commit in commit_object()) {
        let first = CommitObject::parse(&commit.compose()).expect("composition parses");
        let second = CommitObject::parse(&first.compose()).expect("composition parses");
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(first.compose(), second.compose());
    }

    #[test]
    fn pre_image_round_trips_a_maybe_signed_object(
        headers in proptest::collection::vec((header_name(), header_value()), 0..6),
        message in message(),
        signature in proptest::option::of(Just(SIGNATURE.to_vec())),
        token_id in "[a-z]{1,8}",
    ) {
        let mut commit = CommitObject {
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into_bytes(), value))
                .collect(),
            message,
        };
        if let Some(signature) = signature {
            commit.headers.push((b"gpgsig".to_vec(), signature));
        }
        let unsigned = commit.without_signature().compose();

        let trailer = format!("{PREFIX}Token: id={token_id}");
        // Sealing appends one `\n`, the block and a final `\n`, and keeps any
        // signature the object already had.
        let sealed = {
            let mut bytes = commit.compose();
            bytes.push(b'\n');
            bytes.extend_from_slice(trailer.as_bytes());
            bytes.push(b'\n');
            bytes
        };
        let sealed_unsigned = {
            let mut bytes = unsigned.clone();
            bytes.push(b'\n');
            bytes.extend_from_slice(trailer.as_bytes());
            bytes.push(b'\n');
            bytes
        };

        let parsed = CommitObject::parse(&sealed).expect("sealed object parses");
        prop_assert_eq!(parsed.without_signature().compose(), sealed_unsigned.clone());

        let pre_image = parsed.pre_image(PREFIX);
        prop_assert_eq!(&pre_image.bytes, &unsigned);
        prop_assert_eq!(pre_image.trailer.as_deref(), Some(trailer.as_bytes()));
        prop_assert_eq!(rebuilt(&pre_image), sealed_unsigned);
    }

    #[test]
    fn a_pre_image_is_a_parseable_object(commit in commit_object()) {
        let pre_image = commit.pre_image(PREFIX);
        let parsed = CommitObject::parse(&pre_image.bytes).expect("pre-image parses");
        prop_assert_eq!(parsed.compose(), pre_image.bytes);
    }
}

#[test]
fn a_pre_image_has_no_trailer_and_no_signature_left() {
    let sealed_signed = sealed(&object(
        &{
            let mut headers = base_headers();
            headers.push(("gpgsig", SIGNATURE));
            headers
        },
        b"body\n",
    ));
    let commit = CommitObject::parse(&sealed_signed).expect("parses");
    let pre_image: PreImage = commit.pre_image(PREFIX);

    let parsed = CommitObject::parse(&pre_image.bytes).expect("pre-image parses");
    assert_eq!(parsed.header("gpgsig"), None);
    assert_eq!(parsed.pre_image(PREFIX).trailer, None);
    assert_eq!(
        parsed.compose(),
        object(&base_headers(), b"body\n"),
        "only the signature and the trailer are gone"
    );
    assert!(pre_image.trailer.is_some());
}
