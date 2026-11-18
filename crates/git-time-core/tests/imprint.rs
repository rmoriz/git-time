//! Imprint digests: golden hash vectors, trailer rendering and fail-closed
//! parsing of the `X-RFC3161-Imprint` value.

use git_time_core::imprint::{Alg, Digest, ParseError, digest};
use git_time_core::object::CommitObject;

/// SHA-256 of `abc`, from FIPS 180-4 / RFC 6234 test vectors.
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// SHA-512 of `abc`, from FIPS 180-4 / RFC 6234 test vectors.
const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

/// A byte string with a NUL and a non-ASCII byte, so the digest cannot be
/// UTF-8-converted on the way in.
const RAW: &[u8] = b"git-time\x00\xff\n";
const RAW_SHA256: &str = "081dc4d8820bcdad6d48df0d0a63c1c9273edd76dacf9e7305d439fad92a261c";
const RAW_SHA512: &str = "84e0229561589b8221866772078c6199a6d396c3737b171da33ec183b80fbd00c6\
751961cfaef32f2e8606e9118bc60d077ce902474637a8ee53730116d56241";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn sha256_matches_the_golden_vector() {
    assert_eq!(hex(&digest(Alg::Sha256, b"abc")), ABC_SHA256);
    assert_eq!(hex(&digest(Alg::Sha256, RAW)), RAW_SHA256);
}

#[test]
fn sha512_matches_the_golden_vector() {
    assert_eq!(hex(&digest(Alg::Sha512, b"abc")), ABC_SHA512);
    assert_eq!(hex(&digest(Alg::Sha512, RAW)), RAW_SHA512);
}

#[test]
fn digests_have_the_algorithm_width() {
    assert_eq!(digest(Alg::Sha256, b"").len(), 32);
    assert_eq!(digest(Alg::Sha512, b"").len(), 64);
}

#[test]
fn hashes_a_pre_image_byte_for_byte() {
    // `PreImage::bytes` is already the hashable pre-image; nothing is stripped.
    let commit = CommitObject::parse(b"tree 4b82\n\nbody\n\nX-RFC3161-Imprint: sha256:00\n")
        .expect("fixture parses");
    let pre_image = commit.pre_image("X-RFC3161-");
    assert_eq!(
        digest(Alg::Sha256, &pre_image.bytes),
        digest(Alg::Sha256, b"tree 4b82\n\nbody\n")
    );
}

#[test]
fn algorithms_round_trip_through_their_names() {
    for (alg, name) in [(Alg::Sha256, "sha256"), (Alg::Sha512, "sha512")] {
        assert_eq!(alg.as_str(), name);
        assert_eq!(name.parse::<Alg>(), Ok(alg));
    }
}

#[test]
fn algorithm_names_are_exact_and_lowercase() {
    for name in [
        "SHA256", "Sha512", "sha-256", "sha384", "md5", "", " sha256",
    ] {
        assert_eq!(
            name.parse::<Alg>(),
            Err(ParseError::UnknownAlg),
            "{name} must not resolve"
        );
    }
}

#[test]
fn renders_alg_and_lowercase_hex() {
    let value = Digest {
        alg: Alg::Sha256,
        bytes: digest(Alg::Sha256, b"abc"),
    }
    .to_trailer_value();
    assert_eq!(value, format!("sha256:{ABC_SHA256}"));
}

#[test]
fn a_rendered_digest_parses_back_to_itself() {
    for alg in [Alg::Sha256, Alg::Sha512] {
        let original = Digest {
            alg,
            bytes: digest(alg, RAW),
        };
        let parsed = Digest::parse(&original.to_trailer_value()).expect("round-trips");
        assert_eq!(parsed, original);
        assert_eq!(parsed.to_trailer_value(), original.to_trailer_value());
    }
}

#[test]
fn parse_accepts_uppercase_hex_and_renders_it_lowercase() {
    let parsed = Digest::parse(&format!("sha256:{}", ABC_SHA256.to_uppercase())).expect("parses");
    assert_eq!(parsed.alg, Alg::Sha256);
    assert_eq!(hex(&parsed.bytes), ABC_SHA256);
    assert_eq!(parsed.to_trailer_value(), format!("sha256:{ABC_SHA256}"));
}

#[test]
fn parse_rejects_an_unknown_algorithm() {
    assert_eq!(
        Digest::parse(&format!("md5:{ABC_SHA256}")).unwrap_err(),
        ParseError::UnknownAlg
    );
    assert_eq!(
        Digest::parse(&format!("SHA256:{ABC_SHA256}")).unwrap_err(),
        ParseError::UnknownAlg
    );
}

#[test]
fn parse_rejects_a_hex_length_that_does_not_match_the_algorithm() {
    for value in [
        format!("sha256:{}", &ABC_SHA256[..62]),
        format!("sha256:{}0", ABC_SHA256),
        format!("sha512:{}", &ABC_SHA512[..126]),
        format!("sha512:{}0", ABC_SHA512),
        "sha256:".to_owned(),
        "sha256:abc:def".to_owned(),
    ] {
        assert_eq!(
            Digest::parse(&value).unwrap_err(),
            ParseError::WrongLength,
            "{value} must be rejected"
        );
    }
}

#[test]
fn parse_rejects_non_hex_characters() {
    for value in [
        format!("sha256:{}", ABC_SHA256.replacen('b', "g", 1)),
        format!("sha256:{}", ABC_SHA256.replacen('a', " ", 1)),
        format!("sha512:{}", ABC_SHA512.replacen('d', ":", 1)),
    ] {
        assert_eq!(
            Digest::parse(&value).unwrap_err(),
            ParseError::NotHex,
            "{value} must be rejected"
        );
    }
}

#[test]
fn parse_rejects_a_malformed_shape() {
    for value in ["", "sha256", ":abcd"] {
        assert_eq!(
            Digest::parse(value).unwrap_err(),
            ParseError::Malformed,
            "{value:?} must be rejected"
        );
    }
}
