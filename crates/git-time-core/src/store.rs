//! The `X-RFC3161-*` trailer block: the exact lines an RFC 3161 seal appends to
//! a commit message, and the way back.
//!
//! The block is the artifact's proof side. It records the imprint (what was
//! timestamped), the root fingerprints each TSA's tokens were verified with
//! (`Anchor`, before the first `Token`), one line per TSA answer (`Token`), one
//! line per TSA that was asked and failed (`Fail`), and the object the tokens
//! were taken over. The wire format is fixed: one field per line, fields
//! separated by `; `, tokens in the order `ver`, `id`, `alg`, `policy`
//! (optional), `nonce`, `tst`.
//!
//! Encoding is fail-closed on values that would break the format (a `;`, a
//! space, a newline), and it honours a byte budget by dropping the single
//! largest token, recording the drop as a failure, and retrying. Tokens over
//! [`MAX_TOKEN_BYTES`] are dropped the same way before anything is rendered, so
//! encode cannot emit a block that its own decode refuses. A block that cannot
//! fit even with no tokens left is [`EncodeError::TooLarge`] rather than a
//! silently truncated artifact.
//!
//! Decoding is order-insensitive and forward compatible: unknown
//! `X-RFC3161-<Name>` fields are kept verbatim in [`TrailerBlock::extra`] and
//! re-emitted after the known ones. Anything malformed inside a known field is
//! an error, never a guess.
//!
//! An unknown field name is any non-empty UTF-8 name without a `:`, space, CR
//! or LF; encode and decode accept exactly that set, so every preserved foreign
//! field can be re-emitted.
//!
//! Token bytes are carried as zstd-19, base64url unpadded; the nonce as
//! lowercase hex. Neither is ever UTF-8 converted. [`MAX_TOKEN_BYTES`] bounds a
//! token in both directions: decode refuses to inflate past it and encode drops
//! a token over it. Decompression is additionally bounded by a fixed window log
//! capping what a crafted frame header can reserve.
//!
//! ```
//! use std::collections::BTreeMap;
//!
//! use git_time_core::imprint::{Alg, Digest, digest};
//! use git_time_core::store::{FailureRecord, TokenRecord, TrailerBlock, decode, encode};
//!
//! let block = TrailerBlock {
//!     imprint: Digest { alg: Alg::Sha256, bytes: digest(Alg::Sha256, b"pre-image") },
//!     object: None,
//!     anchors: BTreeMap::new(),
//!     tokens: vec![TokenRecord {
//!         id: "freetsa".to_owned(),
//!         alg: Alg::Sha256,
//!         policy: None,
//!         nonce: vec![0x9c, 0x1f],
//!         token: b"token bytes".to_vec(),
//!     }],
//!     failures: Vec::new(),
//!     extra: Vec::new(),
//! };
//!
//! let block_bytes = encode(&block, usize::MAX).unwrap();
//! assert_eq!(decode(&block_bytes).unwrap(), Some(block.clone()));
//!
//! // A tight budget drops the token and records why.
//! let dropped = decode(&encode(&block, block_bytes.len() - 1).unwrap())
//!     .unwrap()
//!     .unwrap();
//! assert!(dropped.tokens.is_empty());
//! assert_eq!(dropped.failures, vec![FailureRecord {
//!     id: "freetsa".to_owned(),
//!     reason: "oversized".to_owned(),
//! }]);
//! ```

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::imprint::{Alg, Digest};

/// The trailer prefix every block line carries.
pub const PREFIX: &str = "X-RFC3161-";

/// The only block version this codec speaks.
const VERSION: &str = "ver=1";

/// The field separator inside a `Token` or `Fail` value.
const SEPARATOR: &str = "; ";

/// The zstd level tokens are stored with: the artifact is read far more often
/// than it is written, and commit messages travel through mail and forges.
const ZSTD_LEVEL: i32 = 19;

/// The failure reason for a token that could not be carried: over
/// [`MAX_TOKEN_BYTES`] or over the byte budget.
const OVERSIZED: &str = "oversized";

/// The most bytes one token may have, in both directions.
///
/// A real RFC 3161 token is around 5 KB; a megabyte is two orders of magnitude
/// above that, and small enough that a hostile commit cannot make [`decode`]
/// allocate without bound.
///
/// The cap binds [`encode`] as well as [`decode`]: a token longer than this is
/// dropped before rendering and recorded as `X-RFC3161-Fail: id=<id>;
/// reason=oversized`, exactly like a token dropped for the byte budget. So
/// encode never emits a block its own decode would reject, and one pathological
/// TSA answer cannot keep the other answers from being sealed.
pub const MAX_TOKEN_BYTES: usize = 1024 * 1024;

/// The largest zstd window [`decode`] allows: 8 MiB.
///
/// A crafted frame header can ask for a far bigger window (up to ~128 MiB);
/// the cap keeps the decoder's reservation independent of the header.
const ZSTD_WINDOW_LOG_MAX: u32 = 23;

/// The pre-render result: tokens to render, each with its rendered nonce, plus
/// one `oversized` failure per dropped token.
type Validated<'a> = (Vec<(&'a TokenRecord, String)>, Vec<FailureRecord>);

/// One `key=value` field inside a `Token` or `Fail` value.
type Field<'a> = (&'a [u8], &'a [u8]);

/// A `sha256` or `sha512` hex string, at either git object id width.
const OBJECT_OID_LENS: [usize; 2] = [40, 64];

/// One TSA answer in a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    /// The configured TSA id.
    pub id: String,
    /// The imprint algorithm the request asked the TSA to use.
    pub alg: Alg,
    /// The TSA policy, when one was requested.
    pub policy: Option<String>,
    /// The request nonce, raw bytes; rendered as lowercase hex.
    pub nonce: Vec<u8>,
    /// The TSA response token, raw bytes; stored zstd-19 compressed.
    pub token: Vec<u8>,
}

/// A TSA that was asked and did not answer usefully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureRecord {
    /// The configured TSA id.
    pub id: String,
    /// Why it failed, e.g. `http-503` or `oversized`.
    pub reason: String,
}

/// A decoded trailer block.
///
/// `extra` holds `X-RFC3161-<Name>` fields this codec does not know, in file
/// order, so a newer writer's block survives a round trip through an older
/// reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailerBlock {
    /// The imprint the tokens answer.
    pub imprint: Digest,
    /// The commit object the tokens were taken over, when known.
    pub object: Option<String>,
    /// The trust-anchor fingerprints each id's tokens were verified with, by id.
    ///
    /// One `Anchor` line per id, rendered after `Object` and before the first
    /// `Token`: `X-RFC3161-Anchor: id=<id>; sha256=<FP>[,<FP>...]`. A
    /// fingerprint is 32 colon-separated hex octets in [`trust::fingerprint`]'s
    /// uppercase spelling; decode accepts either case and normalizes to upper.
    /// The fields are positional — `id` first, then `; `, then `sha256`, then
    /// the comma-separated list. An empty list part fails both ways, a repeated
    /// `Anchor` line for one id fails decode, and an id that names neither a
    /// [`TokenRecord`] nor a [`FailureRecord`] of the block fails both ways.
    ///
    /// [`trust::fingerprint`]: crate::trust::fingerprint
    pub anchors: BTreeMap<String, Vec<String>>,
    /// The TSA answers.
    pub tokens: Vec<TokenRecord>,
    /// The TSA failures.
    pub failures: Vec<FailureRecord>,
    /// Unknown fields, preserved verbatim and re-emitted last.
    pub extra: Vec<(String, String)>,
}

/// Encode `block`, dropping tokens that cannot be carried.
///
/// The result is the block alone: no leading blank line, no trailing newline.
/// A token over [`MAX_TOKEN_BYTES`] is dropped up front, because [`decode`]
/// would refuse it; after that, the largest remaining token is dropped until
/// the bytes fit `max_bytes`. Every dropped token leaves a [`FailureRecord`]
/// with reason `oversized`, so a short block stays gradeable. Dropping stops at
/// zero tokens; a block that still exceeds the budget is
/// [`EncodeError::TooLarge`] carrying the attempted and the allowed size.
pub fn encode(block: &TrailerBlock, max_bytes: usize) -> Result<Vec<u8>, EncodeError> {
    let (kept, oversized) = validate(block)?;
    // Only the kept tokens are compressed, so a dropped giant costs no zstd run.
    let mut tokens = kept
        .into_iter()
        .map(|(token, nonce)| Ok((token, token_value(token, &nonce)?)))
        .collect::<Result<Vec<_>, EncodeError>>()?;

    let mut failures = block.failures.clone();
    failures.extend(oversized);

    // Built once; only a dropped token changes the rendering.
    let mut lines = render(block, &tokens, &failures);
    loop {
        let encoded_len = joined_len(&lines);
        if encoded_len <= max_bytes {
            return Ok(lines.join("\n").into_bytes());
        }
        // The largest rendered token wins; ties drop the first of the largest.
        let Some(largest) = tokens
            .iter()
            .enumerate()
            .rev()
            .max_by_key(|(_, (_, value))| value.len())
            .map(|(index, _)| index)
        else {
            return Err(EncodeError::TooLarge {
                attempted: encoded_len,
                limit: max_bytes,
            });
        };
        let (token, _) = tokens.remove(largest);
        failures.push(FailureRecord {
            id: token.id.clone(),
            reason: OVERSIZED.to_owned(),
        });
        lines = render(block, &tokens, &failures);
    }
}

/// Decode a block from `bytes`.
///
/// Lines without [`PREFIX`] are skipped, so the whole trailer paragraph may be
/// handed in, and one trailing CR per line is ignored. `Ok(None)` means the
/// input has no `X-RFC3161-` line at all.
///
/// Fails closed on a malformed line, a malformed value, a duplicate `Imprint`,
/// `Object` or `Anchor`, an `Anchor` naming no token or failure of the block,
/// and on an `Imprint` that is missing altogether.
pub fn decode(bytes: &[u8]) -> Result<Option<TrailerBlock>, DecodeError> {
    let mut imprint: Option<Digest> = None;
    let mut object: Option<String> = None;
    let mut anchors: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut tokens = Vec::new();
    let mut failures = Vec::new();
    let mut extra: Vec<(String, String)> = Vec::new();
    let mut found = false;

    for line in bytes.split(|byte| *byte == b'\n') {
        // Tolerate CRLF input: the CR belongs to the line ending, not a value.
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(line) = line.strip_prefix(PREFIX.as_bytes()) else {
            continue;
        };
        found = true;

        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(DecodeError::Malformed(format!(
                "`{PREFIX}` line has no `: ` separator"
            )));
        };
        let name = &line[..colon];
        if name.is_empty() {
            return Err(DecodeError::Malformed(format!(
                "`{PREFIX}` line has an empty field name"
            )));
        }
        let Some(value) = line[colon + 1..].strip_prefix(b" ") else {
            return Err(DecodeError::Malformed(format!(
                "`{PREFIX}` line has no space after its `:`"
            )));
        };

        match name {
            b"Imprint" => {
                if imprint.is_some() {
                    return Err(DecodeError::Malformed(format!(
                        "duplicate `{PREFIX}Imprint` field"
                    )));
                }
                imprint = Some(parse_imprint(value)?);
            }
            b"Object" => {
                if object.is_some() {
                    return Err(DecodeError::Malformed(format!(
                        "duplicate `{PREFIX}Object` field"
                    )));
                }
                object = Some(parse_object(value)?);
            }
            b"Anchor" => {
                let (id, fingerprints) = parse_anchor(value)?;
                if anchors.insert(id, fingerprints).is_some() {
                    return Err(DecodeError::Malformed(format!(
                        "duplicate `{PREFIX}Anchor` field"
                    )));
                }
            }
            b"Token" => tokens.push(parse_token(value)?),
            b"Fail" => failures.push(parse_failure(value)?),
            _ => {
                if !is_extra_name(name) {
                    return Err(DecodeError::Malformed(format!(
                        "`{PREFIX}` field name must not contain `:`, space, CR or LF"
                    )));
                }
                extra.push((text(name, "name")?, text(value, "value")?));
            }
        }
    }

    if !found {
        return Ok(None);
    }
    let Some(imprint) = imprint else {
        return Err(DecodeError::MissingImprint);
    };
    // The reference is checked after the whole block, so line order does not
    // decide whether an anchor is a ghost.
    for id in anchors.keys() {
        if !tokens.iter().any(|token| &token.id == id)
            && !failures.iter().any(|failure| &failure.id == id)
        {
            return Err(DecodeError::InvalidField {
                field: "anchor.id".to_owned(),
                reason: format!("`{id}` names no Token or Fail in this block"),
            });
        }
    }

    Ok(Some(TrailerBlock {
        imprint,
        object,
        anchors,
        tokens,
        failures,
        extra,
    }))
}

/// Reject values the wire format cannot carry, and drop the tokens that
/// [`decode`] would refuse as over [`MAX_TOKEN_BYTES`].
///
/// Returns the tokens left to render, each with its rendered nonce so it is
/// computed once, plus one `oversized` [`FailureRecord`] per dropped token in
/// token order. Value checking comes first, so an invalid value still reports
/// even on a token that would be dropped.
fn validate(block: &TrailerBlock) -> Result<Validated<'_>, EncodeError> {
    if let Some(object) = &block.object
        && !is_object_oid(object)
    {
        return Err(EncodeError::Invalid {
            field: "object",
            token: None,
            reason: "expected 40 or 64 lowercase hex digits",
        });
    }
    let mut nonces = Vec::with_capacity(block.tokens.len());
    for (id, fingerprints) in &block.anchors {
        value_text("anchor.id", id, None)?;
        if fingerprints.is_empty() {
            return Err(EncodeError::Invalid {
                field: "anchor.sha256",
                token: None,
                reason: "expected at least one fingerprint",
            });
        }
        for value in fingerprints {
            check_fingerprint(value)?;
        }
        // An anchor that decode would call a ghost is unreadable, so it cannot
        // be rendered either.
        if !block.tokens.iter().any(|token| &token.id == id)
            && !block.failures.iter().any(|failure| &failure.id == id)
        {
            return Err(EncodeError::Invalid {
                field: "anchor.id",
                token: None,
                reason: "names no token or failure in this block",
            });
        }
    }
    for (index, token) in block.tokens.iter().enumerate() {
        let nonce = hex(&token.nonce);
        value_text("id", &token.id, Some(index))?;
        value_text("nonce", &nonce, Some(index))?;
        if let Some(policy) = &token.policy {
            value_text("policy", policy, Some(index))?;
        }
        nonces.push(nonce);
    }
    for failure in &block.failures {
        value_text("Fail.id", &failure.id, None)?;
        value_text("Fail.reason", &failure.reason, None)?;
    }
    for (name, value) in &block.extra {
        if !is_extra_name(name.as_bytes()) {
            return Err(EncodeError::Invalid {
                field: "extra.name",
                token: None,
                reason: "expected a non-empty name without `:`, space, CR or LF",
            });
        }
        if is_known_name(name) {
            return Err(EncodeError::Invalid {
                field: "extra.name",
                token: None,
                reason: "field name is one of the known fields",
            });
        }
        if value.bytes().any(|byte| byte == b'\n' || byte == b'\r') {
            return Err(EncodeError::Invalid {
                field: "extra.value",
                token: None,
                reason: "a value may not contain a newline",
            });
        }
    }

    // The cap is enforced here rather than left to the decoder: an over-cap
    // token is unreadable, so emitting it would make the block undecodable.
    let mut kept = Vec::with_capacity(block.tokens.len());
    let mut oversized = Vec::new();
    for (token, nonce) in block.tokens.iter().zip(nonces) {
        if token.token.len() > MAX_TOKEN_BYTES {
            oversized.push(FailureRecord {
                id: token.id.clone(),
                reason: OVERSIZED.to_owned(),
            });
        } else {
            kept.push((token, nonce));
        }
    }
    Ok((kept, oversized))
}

/// The field-name alphabet [`TrailerBlock::extra`] accepts: anything the wire
/// format can carry, so a rejected name is never one that would decode.
fn is_extra_name(name: &[u8]) -> bool {
    !name.is_empty()
        && !name
            .iter()
            .any(|byte| matches!(byte, b':' | b' ' | b'\r' | b'\n'))
}

fn is_known_name(name: &str) -> bool {
    matches!(name, "Imprint" | "Object" | "Anchor" | "Token" | "Fail")
}

fn value_text(field: &'static str, value: &str, token: Option<usize>) -> Result<(), EncodeError> {
    if let Some(byte) = value
        .bytes()
        .find(|byte| matches!(byte, b';' | b' ' | b'\n' | b'\r'))
    {
        let reason = match byte {
            b';' => "a value may not contain `;`",
            b' ' => "a value may not contain a space",
            _ => "a value may not contain a newline",
        };
        return Err(EncodeError::Invalid {
            field,
            token,
            reason,
        });
    }
    Ok(())
}

/// The `Token` field value, compression included: `ver=1; id=…; alg=…;
/// policy=…; nonce=…; tst=…`. `nonce` is already rendered hex.
fn token_value(token: &TokenRecord, nonce: &str) -> Result<String, EncodeError> {
    let compressed = zstd::stream::encode_all(token.token.as_slice(), ZSTD_LEVEL)
        .map_err(EncodeError::Compress)?;
    let tst = URL_SAFE_NO_PAD.encode(compressed);

    let mut value = String::new();
    let _ = write!(
        value,
        "{VERSION}{SEPARATOR}id={}{SEPARATOR}alg={}{SEPARATOR}",
        token.id,
        token.alg.as_str()
    );
    if let Some(policy) = &token.policy {
        let _ = write!(value, "policy={policy}{SEPARATOR}");
    }
    let _ = write!(value, "nonce={nonce}{SEPARATOR}tst={tst}");
    Ok(value)
}

/// Render the whole block as lines: known fields in wire order, unknown fields
/// last.
fn render(
    block: &TrailerBlock,
    tokens: &[(&TokenRecord, String)],
    failures: &[FailureRecord],
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::with_capacity(
        2 + block.anchors.len() + tokens.len() + failures.len() + block.extra.len(),
    );
    lines.push(format!(
        "{PREFIX}Imprint: {}",
        block.imprint.to_trailer_value()
    ));
    if let Some(object) = &block.object {
        lines.push(format!("{PREFIX}Object: {object}"));
    }
    for (id, fingerprints) in &block.anchors {
        lines.push(format!(
            "{PREFIX}Anchor: id={id}{SEPARATOR}sha256={}",
            fingerprints.join(",")
        ));
    }
    for (_, value) in tokens {
        lines.push(format!("{PREFIX}Token: {value}"));
    }
    for failure in failures {
        lines.push(format!(
            "{PREFIX}Fail: id={}{SEPARATOR}reason={}",
            failure.id, failure.reason
        ));
    }
    for (name, value) in &block.extra {
        lines.push(format!("{PREFIX}{name}: {value}"));
    }
    lines
}

/// The byte length [`render`]'s lines occupy once joined with `\n`.
fn joined_len(lines: &[String]) -> usize {
    lines.iter().map(String::len).sum::<usize>() + lines.len().saturating_sub(1)
}

fn parse_imprint(value: &[u8]) -> Result<Digest, DecodeError> {
    let value = text(value, "Imprint")?;
    Digest::parse(&value).map_err(|error| DecodeError::Malformed(error.to_string()))
}

fn parse_object(value: &[u8]) -> Result<String, DecodeError> {
    let object = text(value, "Object")?;
    if !is_object_oid(&object) {
        return Err(DecodeError::InvalidField {
            field: "Object".to_owned(),
            reason: "expected 40 or 64 lowercase hex digits".to_owned(),
        });
    }
    Ok(object)
}

/// Parse an `Anchor` value: `id=<id>; sha256=<FP>[,<FP>...]`.
///
/// The normalizer already returns the canonical spelling, so this is also the
/// only place a wire fingerprint becomes a field value.
fn parse_anchor(value: &[u8]) -> Result<(String, Vec<String>), DecodeError> {
    let fields = pairs(value, "Anchor")?;
    let mut cursor = 0;
    let id = text(
        require(&fields, &mut cursor, b"id").map_err(|_| DecodeError::InvalidField {
            field: "anchor.id".to_owned(),
            reason: "field missing or out of order".to_owned(),
        })?,
        "anchor.id",
    )?;
    let list = require(&fields, &mut cursor, b"sha256").map_err(|_| DecodeError::InvalidField {
        field: "anchor.sha256".to_owned(),
        reason: "field missing or out of order".to_owned(),
    })?;
    if cursor != fields.len() {
        return Err(DecodeError::InvalidField {
            field: "Anchor".to_owned(),
            reason: "unexpected trailing field".to_owned(),
        });
    }
    let mut fingerprints = Vec::new();
    for part in list.split(|byte| *byte == b',') {
        let value = fingerprint(part)?;
        // A repeat inside one line collapses; first-seen order is kept.
        if !fingerprints.contains(&value) {
            fingerprints.push(value);
        }
    }
    Ok((id, fingerprints))
}

/// Normalize one fingerprint to `trust::fingerprint`'s spelling: exactly 32
/// colon-separated hex octets, uppercase.
///
/// A SHA-1 fingerprint is 20 octets and is refused: the `sha256` field names
/// its own width.
fn fingerprint(value: &[u8]) -> Result<String, DecodeError> {
    let octets: Vec<&[u8]> = value.split(|byte| *byte == b':').collect();
    if octets.len() != 32
        || octets
            .iter()
            .any(|octet| octet.len() != 2 || octet.iter().any(|byte| nibble(*byte).is_none()))
    {
        return Err(DecodeError::InvalidField {
            field: "anchor.sha256".to_owned(),
            reason: "expected 32 colon-separated hex octets".to_owned(),
        });
    }
    Ok(String::from_utf8(value.to_ascii_uppercase()).expect("hex is ASCII"))
}

/// Reject a fingerprint the encoder would write in anything but the canonical
/// spelling, so one block always re-encodes to the same bytes.
fn check_fingerprint(value: &str) -> Result<(), EncodeError> {
    match fingerprint(value.as_bytes()) {
        Ok(canonical) if canonical == value => Ok(()),
        _ => Err(EncodeError::Invalid {
            field: "anchor.sha256",
            token: None,
            reason: "expected 32 colon-separated uppercase hex octets",
        }),
    }
}

fn parse_token(value: &[u8]) -> Result<TokenRecord, DecodeError> {
    let fields = pairs(value, "Token")?;
    let mut cursor = 0;

    let ver = require(&fields, &mut cursor, b"ver")?;
    if ver != b"1" {
        return Err(DecodeError::InvalidField {
            field: "ver".to_owned(),
            reason: "expected the block version `1` first".to_owned(),
        });
    }
    let id = text(require(&fields, &mut cursor, b"id")?, "id")?;
    let alg: Alg = text(require(&fields, &mut cursor, b"alg")?, "alg")?
        .parse()
        .map_err(|_| DecodeError::InvalidField {
            field: "alg".to_owned(),
            reason: "unknown algorithm".to_owned(),
        })?;
    let policy = take(&fields, &mut cursor, b"policy")?
        .map(|value| text(value, "policy"))
        .transpose()?;
    let nonce = unhex(require(&fields, &mut cursor, b"nonce")?, "nonce")?;
    let tst = require(&fields, &mut cursor, b"tst")?;
    let token = inflate(tst)?;

    if cursor != fields.len() {
        return Err(DecodeError::InvalidField {
            field: "Token".to_owned(),
            reason: "unexpected trailing field".to_owned(),
        });
    }

    Ok(TokenRecord {
        id,
        alg,
        policy,
        nonce,
        token,
    })
}

/// Inflate a base64url `tst` value under [`MAX_TOKEN_BYTES`] and
/// [`ZSTD_WINDOW_LOG_MAX`].
///
/// A frame that announces its decompressed size is rejected before any output
/// is produced; otherwise at most one byte past the cap is read, so neither a
/// crafted header nor an unknown size can force an unbounded `Vec`.
fn inflate(tst: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let invalid = |reason: String| DecodeError::InvalidField {
        field: "tst".to_owned(),
        reason,
    };

    let compressed = URL_SAFE_NO_PAD
        .decode(tst)
        .map_err(|error| invalid(format!("not unpadded base64url: {error}")))?;

    match zstd::zstd_safe::get_frame_content_size(&compressed) {
        Ok(Some(size)) if size > MAX_TOKEN_BYTES as u64 => {
            return Err(invalid(format!(
                "announces {size} bytes, over the {MAX_TOKEN_BYTES} byte cap"
            )));
        }
        Ok(_) => {}
        Err(error) => return Err(invalid(format!("not a zstd frame: {error}"))),
    }

    let mut decoder = zstd::stream::Decoder::new(compressed.as_slice())
        .map_err(|error| invalid(format!("not a zstd frame: {error}")))?;
    decoder
        .window_log_max(ZSTD_WINDOW_LOG_MAX)
        .map_err(|error| invalid(format!("not a zstd frame: {error}")))?;

    // One byte past the cap tells "exactly at the cap" from "over it".
    let mut token = Vec::new();
    decoder
        .take(MAX_TOKEN_BYTES as u64 + 1)
        .read_to_end(&mut token)
        .map_err(|error| invalid(format!("not a zstd frame: {error}")))?;
    if token.len() > MAX_TOKEN_BYTES {
        return Err(invalid(format!(
            "decompresses past the {MAX_TOKEN_BYTES} byte cap"
        )));
    }
    Ok(token)
}

fn parse_failure(value: &[u8]) -> Result<FailureRecord, DecodeError> {
    let fields = pairs(value, "Fail")?;
    let mut cursor = 0;
    let id = text(require(&fields, &mut cursor, b"id")?, "Fail.id")?;
    let reason = text(require(&fields, &mut cursor, b"reason")?, "Fail.reason")?;
    if cursor != fields.len() {
        return Err(DecodeError::InvalidField {
            field: "Fail".to_owned(),
            reason: "unexpected trailing field".to_owned(),
        });
    }
    Ok(FailureRecord { id, reason })
}

/// Split a `key=value; key=value` value into its fields, each split at exactly
/// one `=`.
fn pairs<'a>(value: &'a [u8], label: &str) -> Result<Vec<Field<'a>>, DecodeError> {
    let mut pairs = Vec::new();
    for field in value
        .split(|byte| *byte == b';')
        .map(|field| field.strip_prefix(b" ").unwrap_or(field))
    {
        let mut equals = field.iter().enumerate().filter(|(_, byte)| **byte == b'=');
        let Some((split, _)) = equals.next() else {
            return Err(DecodeError::InvalidField {
                field: label.to_owned(),
                reason: "a field has no `=`".to_owned(),
            });
        };
        if equals.next().is_some() {
            return Err(DecodeError::InvalidField {
                field: label.to_owned(),
                reason: "a field has more than one `=`".to_owned(),
            });
        }
        pairs.push((&field[..split], &field[split + 1..]));
    }
    Ok(pairs)
}

/// Take the field called `key` at `cursor`, if the next field is that one.
fn take<'a>(
    fields: &[(&'a [u8], &'a [u8])],
    cursor: &mut usize,
    key: &[u8],
) -> Result<Option<&'a [u8]>, DecodeError> {
    match fields.get(*cursor) {
        Some((name, value)) if *name == key => {
            *cursor += 1;
            Ok(Some(value))
        }
        _ => Ok(None),
    }
}

/// Like [`take`], but a field of another name at `cursor` is an error.
fn require<'a>(
    fields: &[(&'a [u8], &'a [u8])],
    cursor: &mut usize,
    key: &[u8],
) -> Result<&'a [u8], DecodeError> {
    take(fields, cursor, key)?.ok_or_else(|| DecodeError::InvalidField {
        field: String::from_utf8_lossy(key).into_owned(),
        reason: "field missing or out of order".to_owned(),
    })
}

fn text(value: &[u8], field: &str) -> Result<String, DecodeError> {
    String::from_utf8(value.to_vec()).map_err(|_| DecodeError::InvalidField {
        field: field.to_owned(),
        reason: "not UTF-8".to_owned(),
    })
}

fn unhex(value: &[u8], field: &str) -> Result<Vec<u8>, DecodeError> {
    // Safe to allocate up front: `value` is one hex field of one trailer line,
    // and a token's frame output is capped by `MAX_TOKEN_BYTES`.
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_chunks::<2>().0 {
        let (Some(high), Some(low)) = (nibble(pair[0]), nibble(pair[1])) else {
            return Err(DecodeError::InvalidField {
                field: field.to_owned(),
                reason: "not hex".to_owned(),
            });
        };
        bytes.push(high << 4 | low);
    }
    if !value.len().is_multiple_of(2) {
        return Err(DecodeError::InvalidField {
            field: field.to_owned(),
            reason: "odd hex length".to_owned(),
        });
    }
    Ok(bytes)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_object_oid(value: &str) -> bool {
    OBJECT_OID_LENS.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Why a block could not be encoded.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// Not even a block without tokens fits the budget.
    #[error("trailer block needs {attempted} bytes but only {limit} are allowed")]
    TooLarge {
        /// The size the block still has with every token dropped.
        attempted: usize,
        /// The size the caller allowed.
        limit: usize,
    },
    /// A value cannot be carried by the wire format.
    #[error("`{field}` cannot be encoded{}: {reason}", token.map(|index| format!(" at token {index}")).unwrap_or_default())]
    Invalid {
        /// The offending field.
        field: &'static str,
        /// The index of the offending token, when the field belongs to one.
        token: Option<usize>,
        /// Why it cannot be encoded.
        reason: &'static str,
    },
    /// zstd rejected the token bytes.
    #[error("token compression failed: {0}")]
    Compress(std::io::Error),
}

/// Why a block could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// A line or a known field is malformed.
    #[error("malformed trailer block: {0}")]
    Malformed(String),
    /// There is no `X-RFC3161-Imprint` line.
    #[error("trailer block has no imprint")]
    MissingImprint,
    /// A field's value is malformed.
    #[error("`{field}` is invalid: {reason}")]
    InvalidField {
        /// The offending field.
        field: String,
        /// Why its value is invalid.
        reason: String,
    },
}
