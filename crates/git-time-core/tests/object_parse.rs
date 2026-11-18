//! Fail-closed parsing of raw git commit objects.

use git_time_core::object::{CommitObject, ParseError};

/// Folded value the `mergetag` header must yield: continuation lines lose their
/// leading fold space, embedded blank lines survive as empty lines.
const EXPECTED_MERGETAG: &[u8] = b"object 1f2e3d4c5b6a7988aabbccddeeff001122334455\n\
type commit\ntag v1.0.0\ntagger Grace <grace@example.org> 1699999000 +0100\n\n\
signed tag body\n-----BEGIN PGP SIGNATURE-----\n\niQIzBAABCAAdFiEEexample\n\
-----END PGP SIGNATURE-----";

/// A `git cat-file commit` dump of a merge of a signed tag: a `mergetag` header
/// with folded continuation lines, an unknown header, an `encoding` header and a
/// non-UTF-8 message. One element per line, the empty element is the separator.
fn fixture() -> Vec<u8> {
    let lines: &[&[u8]] = &[
        b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        b"parent 5a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b",
        b"parent 1f2e3d4c5b6a7988aabbccddeeff001122334455",
        b"author Ada <ada@example.org> 1700000000 +0100",
        b"committer Ada <ada@example.org> 1700000060 +0100",
        b"mergetag object 1f2e3d4c5b6a7988aabbccddeeff001122334455",
        b" type commit",
        b" tag v1.0.0",
        b" tagger Grace <grace@example.org> 1699999000 +0100",
        b" ",
        b" signed tag body",
        b" -----BEGIN PGP SIGNATURE-----",
        b" ",
        b" iQIzBAABCAAdFiEEexample",
        b" -----END PGP SIGNATURE-----",
        b"x-reviewed-by Grace <grace@example.org>",
        b"encoding ISO-8859-1",
        b"",
        b"Merge branch 'topic'",
        b"F\xE4hn",
    ];
    let mut bytes = lines.join(&b'\n');
    bytes.push(b'\n');
    bytes
}

#[test]
fn parses_headers_in_file_order_with_continuations_folded() {
    let commit = CommitObject::parse(&fixture()).expect("fixture parses");

    let names: Vec<&[u8]> = commit
        .headers
        .iter()
        .map(|(name, _)| name.as_slice())
        .collect();
    assert_eq!(
        names,
        vec![
            b"tree".as_slice(),
            b"parent".as_slice(),
            b"parent".as_slice(),
            b"author".as_slice(),
            b"committer".as_slice(),
            b"mergetag".as_slice(),
            b"x-reviewed-by".as_slice(),
            b"encoding".as_slice(),
        ]
    );

    let mergetag = commit.header("mergetag").expect("mergetag is present");
    assert_eq!(mergetag, EXPECTED_MERGETAG);
    assert!(
        mergetag.windows(2).any(|pair| pair == b"\n\n"),
        "the tag body's blank line must survive folding"
    );

    // Values stay raw bytes: no UTF-8 assumption, no trailing whitespace fiddling.
    assert_eq!(
        commit.header("tree"),
        Some(b"4b825dc642cb6eb9a060e54bf8d69288fbee4904".as_slice())
    );
    assert_eq!(
        commit.header("x-reviewed-by"),
        Some(b"Grace <grace@example.org>".as_slice())
    );
    assert_eq!(commit.header("encoding"), Some(b"ISO-8859-1".as_slice()));
    assert_eq!(commit.header("missing"), None);

    // The message is copied verbatim, latin-1 byte included.
    assert_eq!(commit.message, b"Merge branch 'topic'\nF\xE4hn\n");
}

#[test]
fn splits_only_at_the_first_blank_line() {
    let commit = CommitObject::parse(b"tree 4b82\n\nfirst\n\nsecond\n").expect("parses");
    assert_eq!(commit.headers.len(), 1);
    assert_eq!(commit.message, b"first\n\nsecond\n");
}

#[test]
fn accepts_an_empty_message() {
    let commit = CommitObject::parse(b"tree 4b82\n\n").expect("parses");
    assert_eq!(commit.headers.len(), 1);
    assert!(commit.message.is_empty());
}

#[test]
fn rejects_a_header_line_without_a_space() {
    assert_eq!(
        CommitObject::parse(b"tree\n\nmessage\n").unwrap_err(),
        ParseError::MalformedHeader
    );
    assert_eq!(
        CommitObject::parse(b"tree4b82\n\nmessage\n").unwrap_err(),
        ParseError::MalformedHeader
    );
}

#[test]
fn rejects_a_colon_separated_header() {
    // git commit headers are separated by a space, not by `: `.
    assert_eq!(
        CommitObject::parse(b"tree: 4b82\n\n").unwrap_err(),
        ParseError::MalformedHeader
    );
}

#[test]
fn rejects_an_out_of_charset_header_name() {
    assert_eq!(
        CommitObject::parse(b"tree_bad 4b82\n\n").unwrap_err(),
        ParseError::MalformedHeader
    );
    assert_eq!(
        CommitObject::parse(b" 4b82\n\n").unwrap_err(),
        ParseError::MalformedHeader
    );
}

#[test]
fn rejects_a_continuation_line_without_a_previous_header() {
    assert_eq!(
        CommitObject::parse(b" orphan\n\n").unwrap_err(),
        ParseError::MalformedHeader
    );
}

#[test]
fn rejects_a_message_without_a_blank_line_separator() {
    assert_eq!(
        CommitObject::parse(b"tree 4b82\nmessage\n").unwrap_err(),
        ParseError::MissingSeparator
    );
    assert_eq!(
        CommitObject::parse(b"tree 4b82\n").unwrap_err(),
        ParseError::MissingSeparator
    );
}

#[test]
fn rejects_empty_input() {
    assert_eq!(CommitObject::parse(b"").unwrap_err(), ParseError::Empty);
}

#[test]
fn accepts_an_empty_header_section_and_an_empty_message() {
    let commit = CommitObject::parse(b"\n\n").expect("parses");
    assert!(commit.headers.is_empty());
    assert!(commit.message.is_empty());
}

#[test]
fn rejects_crlf_object_termination_on_purpose() {
    // git writes LF. A CRLF blank line is not `\n\n`, so no separator is found
    // and the `\r` bytes are never normalised away.
    assert_eq!(
        CommitObject::parse(b"tree 4b82\r\n\r\nbody\r\n").unwrap_err(),
        ParseError::MissingSeparator
    );
}

#[test]
fn missing_separator_wins_over_a_malformed_header() {
    // The separator is located before any header line is inspected, so an
    // object that is both malformed and unseparated reports MissingSeparator.
    assert_eq!(
        CommitObject::parse(b"tree\nmessage\n").unwrap_err(),
        ParseError::MissingSeparator
    );
    assert_eq!(
        CommitObject::parse(b"tree_bad 4b82\nmessage\n").unwrap_err(),
        ParseError::MissingSeparator
    );
}
