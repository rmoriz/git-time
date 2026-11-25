//! RFC 3161 timestamp requests and responses.
//!
//! [`req`] builds the `TimeStampReq`; [`parse_response`] reads a `TimeStampResp`
//! far enough to know whether the request was granted and, if so, hands the
//! `timeStampToken` back exactly as the TSA sent it. The token is not decoded or
//! re-encoded here: later verification hashes those exact bytes, and a CMS
//! round-trip would make them movable.
//!
//! Only the status fields are interpreted. Statuses 0 (`granted`) and 1
//! (`grantedWithMods`)
//! are granted and must carry a token; everything else is a rejection whose
//! `statusString` text, or failing that whose `failInfo` bit, is reported.
//! A granted response without a token is [`TsaError::MissingToken`], and input
//! that is not a well-formed `TimeStampResp` is [`TsaError::Malformed`].
//!
//! A request is validated while it is built, not while it is encoded: an
//! imprint whose width is not its algorithm's, or a policy that is not an OID,
//! is refused by [`StampRequest::new`]/[`StampRequest::with_policy`], so
//! [`encode`] never silently drops a policy configured that way. Only a request
//! whose public fields were written by hand skips the check.
//!
//! [`backend`] carries one authority over HTTP; [`pool`] asks many of them at
//! once and reports what came back without ever failing as a whole.

pub mod backend;
pub mod pool;
pub mod req;

pub use backend::HttpBackend;
pub use pool::{PoolOutcome, PoolPolicy, StampedToken};
pub use req::{NONCE_LEN, StampRequest, encode};

use async_trait::async_trait;
use der::{Encode, Header, Reader, SliceReader, Tag};
use std::str::from_utf8;

/// One timestamp authority.
///
/// An implementation turns a request into the raw `timeStampToken` DER; reading
/// the token back (imprint, nonce, chain) is verification's job, not the
/// transport's. Retry policy belongs to the implementation, because only it can
/// tell a retryable failure from a final one.
#[async_trait]
pub trait TsaBackend: Send + Sync {
    /// Ask the authority to stamp `request` and return the token bytes.
    ///
    /// # Errors
    ///
    /// [`TsaError`] for a transport failure, a non-2xx status, a rejection, or a
    /// response that does not parse.
    async fn stamp(&self, request: &StampRequest) -> Result<Vec<u8>, TsaError>;

    /// The configured identifier of the authority, as it appears in trailers
    /// and failure records.
    fn id(&self) -> &str;
}

/// A parsed `TimeStampResp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawResponse {
    /// The TSA granted the request.
    Granted {
        /// The `timeStampToken` ContentInfo, as the exact DER bytes of the
        /// response — header included.
        token: Vec<u8>,
        /// The TSA's `statusString` values, concatenated, when it sent any;
        /// a `failInfo` bit never lands here.
        status_text: Option<String>,
    },
    /// The TSA refused the request.
    ///
    /// RFC 3161 allows a rejection to carry a `timeStampToken`; it is read and
    /// dropped here, so a rejection stays a rejection.
    Rejected {
        /// The raw `PKIStatus`, always 2 or greater here.
        status: u8,
        /// The TSA's `statusString` values concatenated, or else the name of
        /// the first `failInfo` bit.
        text: Option<String>,
    },
}

/// Why a timestamp request could not be built or a timestamp response could
/// not be read or did not grant the request.
#[derive(Debug, thiserror::Error)]
pub enum TsaError {
    /// The bytes are not a well-formed DER `TimeStampResp`.
    #[error("malformed timestamp response: {0}")]
    Malformed(String),
    /// The status grants the request but no `timeStampToken` follows.
    #[error("granted timestamp response carries no token")]
    MissingToken,
    /// The TSA refused the request, for callers that treat a rejection as an
    /// error rather than as a [`RawResponse::Rejected`] value.
    #[error("timestamp authority rejected the request with status {status}")]
    Rejected {
        /// The raw `PKIStatus`.
        status: u8,
        /// The TSA's reason, when it gave one.
        text: Option<String>,
    },
    /// A `reqPolicy` is not a dotted-decimal OID; carries the offending value.
    #[error("timestamp policy {0:?} is not a dotted-decimal OID")]
    InvalidPolicy(String),
    /// An imprint digest is not the width its algorithm produces.
    #[error("invalid message imprint: {0}")]
    InvalidImprint(String),
    /// The authority answered with an HTTP status outside 2xx; the body is a
    /// short, lossy preview so a proxy's error page is still readable.
    #[error("http {status}: {body}")]
    Http {
        /// The HTTP status code as received.
        status: u16,
        /// A truncated, UTF-8-lossy preview of the response body.
        body: String,
    },
    /// The request never produced a response at all.
    #[error("timestamp authority request failed: {0}")]
    Transport(String),
    /// Talking to the authority failed.
    #[error("timestamp authority I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl TsaError {
    /// The one-line reason a failed fan-out records for this error.
    ///
    /// A rejection keeps its `statusString`/`failInfo` text, because "the TSA
    /// said no" is only useful with the authority's own words.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Rejected { status, text } => match text {
                Some(text) => format!("rejected (status {status}): {text}"),
                None => format!("rejected (status {status})"),
            },
            other => other.to_string(),
        }
    }
}

// `std::io::Error` is neither `Clone` nor `PartialEq`, so equality is written
// out; an `io::Error` compares by the kind and message a test can observe.
impl PartialEq for TsaError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Malformed(left), Self::Malformed(right)) => left == right,
            (Self::MissingToken, Self::MissingToken) => true,
            (
                Self::Rejected {
                    status: left,
                    text: left_text,
                },
                Self::Rejected {
                    status: right,
                    text: right_text,
                },
            ) => left == right && left_text == right_text,
            (Self::InvalidPolicy(left), Self::InvalidPolicy(right)) => left == right,
            (Self::InvalidImprint(left), Self::InvalidImprint(right)) => left == right,
            (
                Self::Http {
                    status: left,
                    body: left_body,
                },
                Self::Http {
                    status: right,
                    body: right_body,
                },
            ) => left == right && left_body == right_body,
            (Self::Transport(left), Self::Transport(right)) => left == right,
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind() && left.to_string() == right.to_string()
            }
            _ => false,
        }
    }
}

impl Eq for TsaError {}

/// Parse a DER `TimeStampResp`.
///
/// The outer value must be a `SEQUENCE` holding a `PKIStatusInfo` and, when the
/// status is granted, a `timeStampToken`. The token is returned byte for byte as
/// it appears in `bytes`, so no CMS value is rebuilt.
///
/// # Errors
///
/// [`TsaError::Malformed`] for truncated, trailing, or wrongly tagged input,
/// [`TsaError::MissingToken`] for a granted status without a token.
///
/// A rejection followed by bytes that are not one `SEQUENCE` is `Malformed`
/// rather than `Rejected`: RFC 3161 allows only the status info and the token
/// there, and a rejection may carry the token.
pub fn parse_response(bytes: &[u8]) -> Result<RawResponse, TsaError> {
    let mut outer = SliceReader::new(bytes).map_err(malformed)?;
    let body = read_tlv(&mut outer, Tag::Sequence)?;
    outer.finish().map_err(malformed)?;

    let mut response = SliceReader::new(body).map_err(malformed)?;
    let info = read_tlv(&mut response, Tag::Sequence)?;

    let mut status_info = SliceReader::new(info).map_err(malformed)?;
    let status_bytes = read_tlv(&mut status_info, Tag::Integer)?;
    let status = parse_status(status_bytes)?;

    let mut texts = Vec::new();
    let mut fail_info = None;
    while !status_info.is_finished() {
        let header = Header::peek(&status_info).map_err(malformed)?;
        match header.tag() {
            Tag::Sequence => texts.extend(parse_status_strings(&mut status_info)?),
            Tag::BitString => fail_info = Some(parse_fail_info(&mut status_info)?),
            other => {
                return Err(TsaError::Malformed(format!(
                    "unexpected {other} in PKIStatusInfo"
                )));
            }
        }
    }
    status_info.finish().map_err(malformed)?;

    let token = if response.is_finished() {
        None
    } else {
        Some(read_token(&mut response)?)
    };
    response.finish().map_err(malformed)?;

    // A grant reports only what the TSA wrote as text; the failInfo fallback is
    // what a rejection may use instead of a statusString.
    let status_text = if texts.is_empty() {
        None
    } else {
        Some(texts.concat())
    };

    match status {
        0 | 1 => token
            .map(|token| RawResponse::Granted { token, status_text })
            .ok_or(TsaError::MissingToken),
        status => Ok(RawResponse::Rejected {
            status,
            text: status_text.or(fail_info),
        }),
    }
}

/// Read the `timeStampToken` TLV, header included, byte for byte.
fn read_token(reader: &mut SliceReader<'_>) -> Result<Vec<u8>, TsaError> {
    Ok(read_tlv_full(reader, Tag::Sequence)?.to_vec())
}

/// Read a `PKIFreeText`: a non-empty `SEQUENCE OF` string, one text per value.
fn parse_status_strings(reader: &mut SliceReader<'_>) -> Result<Vec<String>, TsaError> {
    let body = read_tlv(reader, Tag::Sequence)?;

    let mut texts = Vec::new();
    let mut strings = SliceReader::new(body).map_err(malformed)?;
    while !strings.is_finished() {
        let string_header = Header::peek(&strings).map_err(malformed)?;
        let tag = match string_header.tag() {
            tag
            @ (Tag::Utf8String | Tag::PrintableString | Tag::TeletexString | Tag::Ia5String) => tag,
            other => {
                return Err(TsaError::Malformed(format!(
                    "statusString holds {other}, not a string"
                )));
            }
        };
        let string = read_tlv(&mut strings, tag)?;
        texts.push(if tag == Tag::TeletexString {
            decode_latin1(string)
        } else {
            from_utf8(string).map_err(|_| malformed_text())?.to_owned()
        });
    }
    if texts.is_empty() {
        return Err(TsaError::Malformed("empty statusString".to_owned()));
    }
    Ok(texts)
}

/// Decode a `TeletexString` as Latin-1: one `char` per byte, never failing, so
/// an odd encoding degrades to mojibake instead of losing the message.
fn decode_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| char::from(byte)).collect()
}

/// Name the first set bit of a `PKIFailureInfo`.
fn parse_fail_info(reader: &mut SliceReader<'_>) -> Result<String, TsaError> {
    let body = read_tlv(reader, Tag::BitString)?;

    let Some((&unused, bits)) = body.split_first() else {
        return Err(TsaError::Malformed("empty failInfo".to_owned()));
    };
    if unused > 7 {
        return Err(TsaError::Malformed(format!(
            "failInfo has {unused} unused bits"
        )));
    }
    let mask = 0xff << unused;

    for (byte_index, byte) in bits.iter().enumerate() {
        // The trailing `unused` bits of the last octet mean nothing.
        let byte = if byte_index + 1 == bits.len() {
            byte & mask
        } else {
            *byte
        };
        for bit in 0..8 {
            if byte & (0x80 >> bit) != 0 {
                let index = byte_index * 8 + bit;
                return Ok(fail_info_name(index));
            }
        }
    }
    Ok("failInfo with no bit set".to_owned())
}

/// The RFC 3161 `PKIFailureInfo` name of bit `index`.
fn fail_info_name(index: usize) -> String {
    let name = match index {
        0 => "badAlg",
        2 => "badRequest",
        5 => "badDataFormat",
        14 => "timeNotAvailable",
        15 => "unacceptedPolicy",
        16 => "unacceptedExtension",
        17 => "addInfoNotAvailable",
        25 => "systemFailure",
        _ => return format!("failInfo bit {index}"),
    };
    name.to_owned()
}

/// Read a small `PKIStatus`; only a single-octet positive `INTEGER` is accepted.
fn parse_status(bytes: &[u8]) -> Result<u8, TsaError> {
    match bytes {
        [status] => Ok(*status),
        _ => Err(TsaError::Malformed(format!(
            "status is {} bytes, not 1",
            bytes.len()
        ))),
    }
}

/// Read a whole tag-length-value triple.
fn read_tlv_full<'a>(reader: &mut SliceReader<'a>, tag: Tag) -> Result<&'a [u8], TsaError> {
    let header = Header::peek(&*reader).map_err(malformed)?;
    expect(&header, tag)?;
    let header_len = header.encoded_len().map_err(malformed)?;
    let total = (header_len + header.length()).map_err(malformed)?;
    reader.read_slice(total).map_err(malformed)
}

/// Read the content octets of a tag-length-value triple, header consumed.
fn read_tlv<'a>(reader: &mut SliceReader<'a>, tag: Tag) -> Result<&'a [u8], TsaError> {
    let header = Header::peek(&*reader).map_err(malformed)?;
    let header_len = header.encoded_len().map_err(malformed)?;
    let full = read_tlv_full(reader, tag)?;
    let header_len = usize::try_from(u32::from(header_len))
        .map_err(|_| TsaError::Malformed("length overflow".to_owned()))?;
    Ok(&full[header_len..])
}

/// Require `header` to carry `tag`.
fn expect(header: &Header, tag: Tag) -> Result<(), TsaError> {
    if header.tag() == tag {
        Ok(())
    } else {
        Err(TsaError::Malformed(format!(
            "expected {tag}, found {}",
            header.tag()
        )))
    }
}

/// Fold a `der` error into [`TsaError::Malformed`].
fn malformed(error: der::Error) -> TsaError {
    TsaError::Malformed(error.to_string())
}

/// The error for a `statusString` value that is not UTF-8.
fn malformed_text() -> TsaError {
    TsaError::Malformed("statusString is not UTF-8".to_owned())
}
