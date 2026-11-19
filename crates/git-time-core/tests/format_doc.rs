//! `docs/format.md` is a promise to other implementers, so it is checked
//! against the code rather than trusted.
//!
//! The document quotes one sealed commit in full as its appendix and that is
//! the artifact under test: it has to parse, its pre-image has to hash to the
//! `Imprint` it claims, the block has to decode to the records this file
//! expects, and the elided excerpt in the body has to agree with it line for
//! line. When the codec moves, one of those fails until the document does too.

use std::collections::BTreeMap;

use git_time_core::imprint::{Alg, Digest, digest};
use git_time_core::object::CommitObject;
use git_time_core::store::{self, FailureRecord, PREFIX};

const DOC: &str = include_str!("../../../docs/format.md");
const FIXTURE: &[u8] = include_bytes!("fixtures/format_example.commit");

/// The one anchor fingerprint the example names: freetsa's self-signed root.
const ROOT: &str = "A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC";

fn appendix() -> String {
    let begin = DOC
        .split_once("<!-- format-doc:begin -->\n")
        .expect("the appendix marker")
        .1;
    let (block, _) = begin
        .split_once("<!-- format-doc:end -->")
        .expect("the end marker");
    // The block is fenced; the fixture is what is inside the fence.
    let block = block.strip_prefix("\n```\n").expect("an opening fence");
    let block = block.strip_suffix("```\n").expect("a closing fence");
    block.to_owned()
}

/// The example, the appendix and the fixture are the same bytes.
#[test]
fn the_document_quotes_the_fixture_verbatim() {
    assert_eq!(appendix(), String::from_utf8_lossy(FIXTURE));
}

/// The body excerpt keeps the identifying lines true, with only `tst` elided.
#[test]
fn the_excerpt_agrees_with_the_fixture() {
    let object = String::from_utf8_lossy(FIXTURE);
    for line in DOC.lines().filter(|line| line.starts_with(PREFIX)) {
        // Everything before the first `…` is literal, and every line that
        // carries one is shortened there.
        let (head, shortened) = match line.split_once('…') {
            Some((head, _)) => (head, true),
            None => (line, false),
        };
        let held = if shortened {
            object.lines().any(|held| held.starts_with(head))
        } else {
            object.lines().any(|held| held == head)
        };
        assert!(held, "the excerpt line {line:?} is not in the fixture");
    }
}

/// The block decodes to what the document says a block holds.
#[test]
fn the_block_decodes() {
    let object = CommitObject::parse(FIXTURE).expect("the fixture parses");
    let block = store::decode(&object.message)
        .expect("the block decodes")
        .expect("there is a block");

    assert_eq!(
        block.imprint,
        Digest {
            alg: Alg::Sha256,
            bytes: digest(Alg::Sha256, &object.pre_image(PREFIX).bytes),
        }
    );
    assert_eq!(
        block.object.as_deref(),
        Some("9535462acdff0c2e98ff53c0d17a8b87a44ff64f")
    );

    assert_eq!(
        block.anchors,
        BTreeMap::from([("freetsa".to_owned(), vec![ROOT.to_owned()])]),
        "the block names the freetsa root"
    );
    // §3: the anchor line is rendered before the first token.
    let lines = String::from_utf8_lossy(&object.message);
    let anchor_line = lines
        .lines()
        .position(|line| line.starts_with("X-RFC3161-Anchor:"))
        .expect("an anchor line");
    let token_line = lines
        .lines()
        .position(|line| line.starts_with("X-RFC3161-Token:"))
        .expect("a token line");
    assert!(
        anchor_line < token_line,
        "the anchor comes before the token"
    );

    assert_eq!(block.tokens.len(), 1);
    let token = &block.tokens[0];
    assert_eq!(token.id, "freetsa");
    assert_eq!(token.alg, Alg::Sha256);
    assert_eq!(token.policy.as_deref(), Some("1.2.3.4.1"));
    assert_eq!(
        token.nonce,
        [0x2c, 0x6d, 0x49, 0xf0, 0x2c, 0x59, 0xae, 0xdf]
    );
    assert_eq!(
        token.token.first().copied(),
        Some(0x30),
        "the token is a DER SEQUENCE"
    );

    assert_eq!(
        block.failures,
        vec![
            FailureRecord {
                id: "dfn".to_owned(),
                reason: "invalid-untrusted".to_owned(),
            },
            FailureRecord {
                id: "belgium".to_owned(),
                reason: "invalid-untrusted".to_owned(),
            },
        ]
    );
}

/// The documented pre-image is the one the code derives, and it holds the
/// `Imprint` the block claims.
#[test]
fn the_pre_image_is_what_the_imprint_covers() {
    let object = CommitObject::parse(FIXTURE).expect("the fixture parses");
    let pre = object.pre_image(PREFIX);

    assert_eq!(
        Digest {
            alg: Alg::Sha256,
            bytes: digest(Alg::Sha256, &pre.bytes),
        },
        store::decode(&object.message)
            .expect("the block decodes")
            .expect("there is a block")
            .imprint
    );

    // No signature headers in the fixture, so the pre-image is the object
    // without the trailer; and the block is the message's last paragraph.
    assert_eq!(object.without_signature(), object);
    assert!(
        String::from_utf8_lossy(&pre.bytes).ends_with("now says why.\n"),
        "the message keeps its own trailing newline"
    );

    // §6: pre-image, one LF, the block, one LF reproduces the object.
    let mut rebuilt = pre.bytes.clone();
    rebuilt.push(b'\n');
    rebuilt.extend_from_slice(pre.trailer.as_deref().expect("a trailer"));
    rebuilt.push(b'\n');
    assert_eq!(rebuilt, FIXTURE);
}

/// The document's section between two headings.
fn section(heading: &str) -> &'static str {
    let start = DOC
        .split_once(heading)
        .unwrap_or_else(|| panic!("the section {heading:?}"))
        .1;
    let end = start.find("\n## ").unwrap_or(start.len());
    &start[..end]
}

/// `Anchor` is a first-class field with a fixed shape and a fixed place.
#[test]
fn the_anchor_line_is_documented_before_the_tokens() {
    let grammar = section("## 2. Grammar");
    assert!(
        grammar.contains(
            r#"anchor-value  = "id=" label "; " "sha256=" fingerprint *( "," fingerprint )"#
        ),
        "§2 does not give the anchor value its shape, one fingerprint allowed"
    );
    assert!(
        grammar.contains(r#"fingerprint   = hexdig 31( ":" hexdig )"#),
        "§2 does not say a fingerprint is 32 colon-separated octets"
    );
    assert!(
        grammar.contains(r#"name         = "Imprint" / "Object" / "Anchor" / "Token""#),
        "§2 does not put Anchor among the field names"
    );

    // The appendix's own line is a single fingerprint, so the production above
    // has to allow the zero-repetition form it uses.
    let block = appendix();
    let mut anchors = block
        .lines()
        .filter_map(|line| line.strip_prefix("X-RFC3161-Anchor: "));
    let line = anchors.next().expect("an anchor line in the appendix");
    assert!(anchors.next().is_none(), "more than one anchor line");
    let (_, list) = line.split_once("; sha256=").expect("the sha256 field");
    assert!(
        !list.contains(','),
        "the appendix names one fingerprint, so one must be legal"
    );
    let octets = list.split(':').collect::<Vec<_>>();
    assert_eq!(octets.len(), 32, "a fingerprint is 32 octets");
    assert!(octets.iter().all(|octet| octet.len() == 2));

    let order = section("## 3. Fields")
        .lines()
        .find(|line| line.contains("canonical rendering order"))
        .expect("§3 states the canonical order");
    let anchor = order.find("`Anchor*`").expect("Anchor in the order");
    let token = order.find("`Token*`").expect("Token in the order");
    assert!(
        anchor < token,
        "§3 puts Anchor at {anchor} and Token at {token}"
    );
}

/// Every refusal the verifier can report has a `reason` value.
#[test]
fn the_reason_table_lists_every_new_refusal() {
    let kinds = section("## 3. Fields")
        .lines()
        .find(|line| line.contains("`invalid-<kind>`"))
        .expect("the invalid-<kind> reason row");
    for kind in [
        "ess-missing",
        "ess-mismatch",
        "ess-malformed",
        "tsa-name",
        "no-root-at-gen-time",
        "anchor-not-pinned",
    ] {
        assert!(
            kinds.contains(&format!("`{kind}`")),
            "the reason table does not list `{kind}`"
        );
    }
}

/// §8 says which attribute, whose identifier and under which default.
#[test]
fn the_ess_rule_names_both_attributes_and_the_default() {
    let verify = section("## 8. Verifying a block");
    for needle in [
        "`SigningCertificate`",
        "`SigningCertificateV2`",
        "at least one",
        "`certs[0]`",
        "`sha256`",
        "or the token is `ess-mismatch`",
    ] {
        assert!(verify.contains(needle), "§8 does not contain {needle:?}");
    }
}

/// The fixture is small enough to quote and complete enough to be worth it.
#[test]
fn the_fixture_keeps_the_document_readable() {
    assert!(
        FIXTURE.len() < 8 * 1024,
        "a fixture of {} bytes is too big to quote",
        FIXTURE.len()
    );
}
