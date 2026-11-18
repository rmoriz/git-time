//! One timestamp authority over HTTP.
//!
//! The request goes out as `application/timestamp-query` and only the
//! `timeStampToken` comes back: this module is transport, so it does not look
//! inside the CMS value.
//!
//! Failures are split the way a caller must act on them. A transport error, a
//! 5xx and a 429 are worth exactly one retry; a rejection, any other 4xx and a
//! malformed body are final, because a second identical request would produce
//! the same answer. The retry sleeps briefly, jittered so a set of authorities
//! hit by the same outage does not come back in lockstep.
//!
//! A hostile or broken authority cannot grow the body past
//! [`MAX_RESPONSE_BYTES`]: an announced `Content-Length` over the cap is refused
//! before a body byte is read, and an undeclared body is counted while it
//! streams. Only a short head of an error body is ever turned into text.

use async_trait::async_trait;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{RawResponse, StampRequest, TsaBackend, TsaError, encode, parse_response};
use crate::store::MAX_TOKEN_BYTES;

/// The media type RFC 3161 assigns to a request body.
pub const MEDIA_TYPE: &str = "application/timestamp-query";

/// Room [`MAX_RESPONSE_BYTES`] gives a response around the token itself.
const RESPONSE_SLACK_BYTES: usize = 64 * 1024;

/// Upper bound on a response body: one token plus room for the `TimeStampResp`
/// it is wrapped in, its status text and a proxy's error page.
pub const MAX_RESPONSE_BYTES: usize = MAX_TOKEN_BYTES + RESPONSE_SLACK_BYTES;

/// How many body characters a non-2xx failure keeps.
const BODY_PREVIEW_CHARS: usize = 200;
/// How many body bytes a preview reads before it even builds a string, so a
/// large body is never copied in full.
const BODY_PREVIEW_BYTES: usize = 512;

/// Lower bound of the jittered retry delay, in milliseconds.
const RETRY_FLOOR_MS: u64 = 50;
/// Width of the jitter added to [`RETRY_FLOOR_MS`], in milliseconds.
const RETRY_JITTER_MS: u64 = 50;

/// A TSA reached over HTTP.
///
/// The fields are public so a caller can build one with a struct literal; the
/// HTTP client is created per [`stamp`](TsaBackend::stamp) call and shared by
/// that call's attempts, so there is no hidden field to fill in.
#[derive(Debug, Clone)]
pub struct HttpBackend {
    /// The authority's identifier, as it appears in trailers and failures.
    pub id: String,
    /// The endpoint a `POST` of the encoded request goes to.
    pub url: String,
    /// Per-attempt timeout; the pool applies its own, shorter deadline on top.
    pub timeout: Duration,
}

#[async_trait]
impl TsaBackend for HttpBackend {
    fn id(&self) -> &str {
        &self.id
    }

    async fn stamp(&self, request: &StampRequest) -> Result<Vec<u8>, TsaError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|error| TsaError::Transport(error.to_string()))?;
        let body = encode(request);

        match self.post(&client, &body).await {
            Err(error) if retryable(&error) => {
                tokio::time::sleep(retry_delay()).await;
                self.post(&client, &body).await
            }
            result => result,
        }
    }
}

impl HttpBackend {
    /// One attempt: send, bound the body, check the status, parse it.
    async fn post(&self, client: &reqwest::Client, body: &[u8]) -> Result<Vec<u8>, TsaError> {
        let mut response = client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, MEDIA_TYPE)
            .timeout(self.timeout)
            .body(body.to_vec())
            .send()
            .await
            .map_err(transport)?;

        let status = response.status();

        // An announced length over the cap never needs the body at all.
        let announced = response.content_length();
        if announced.is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
            return Err(oversize());
        }

        // One byte past the cap tells "exactly at the cap" from "over it"; the
        // reserve is the announced length when it is sane.
        const LIMIT: usize = MAX_RESPONSE_BYTES + 1;
        let reserve = announced.map_or(0, |length| {
            usize::try_from(length).unwrap_or(LIMIT).min(LIMIT)
        });
        let mut received = Vec::with_capacity(reserve);
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            let room = LIMIT - received.len();
            received.extend_from_slice(&chunk[..room.min(chunk.len())]);
            if received.len() == LIMIT {
                return Err(oversize());
            }
        }

        if !status.is_success() {
            return Err(TsaError::Http {
                status: status.as_u16(),
                body: preview(&received),
            });
        }

        match parse_response(&received)? {
            RawResponse::Granted { token, .. } => Ok(token),
            RawResponse::Rejected { status, text } => Err(TsaError::Rejected { status, text }),
        }
    }
}

/// Fold a `reqwest` error into [`TsaError::Transport`].
fn transport(error: reqwest::Error) -> TsaError {
    TsaError::Transport(error.to_string())
}

/// The error for a body over [`MAX_RESPONSE_BYTES`].
fn oversize() -> TsaError {
    TsaError::Transport(format!("response exceeded {MAX_RESPONSE_BYTES} bytes"))
}

/// Whether one more identical request could plausibly do better.
fn retryable(error: &TsaError) -> bool {
    match error {
        TsaError::Transport(_) => true,
        TsaError::Http { status, .. } => (500..600).contains(status) || *status == 429,
        _ => false,
    }
}

/// A short, jittered backoff: 50–99 ms.
fn retry_delay() -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    Duration::from_millis(RETRY_FLOOR_MS + u64::from(nanos) % RETRY_JITTER_MS)
}

/// A body preview for an error message: at most [`BODY_PREVIEW_BYTES`] bytes are
/// read, then at most [`BODY_PREVIEW_CHARS`] lossy characters are kept, marked
/// when either bound cut something. Large bodies are never copied in full.
fn preview(bytes: &[u8]) -> String {
    let head = &bytes[..bytes.len().min(BODY_PREVIEW_BYTES)];
    let text = String::from_utf8_lossy(head);

    let mut preview = String::new();
    let mut chars = text.chars();
    preview.extend(chars.by_ref().take(BODY_PREVIEW_CHARS));
    if chars.next().is_some() || bytes.len() > head.len() {
        preview.push('…');
    }
    preview
}

#[cfg(test)]
mod tests {
    use super::{MAX_RESPONSE_BYTES, preview, retryable};
    use crate::tsa::TsaError;

    #[test]
    fn only_transport_5xx_and_429_are_retryable() {
        assert!(retryable(&TsaError::Transport("reset".to_owned())));
        assert!(retryable(&TsaError::Http {
            status: 503,
            body: String::new(),
        }));
        assert!(retryable(&TsaError::Http {
            status: 599,
            body: String::new(),
        }));
        assert!(retryable(&TsaError::Http {
            status: 429,
            body: String::new(),
        }));

        assert!(!retryable(&TsaError::Http {
            status: 400,
            body: String::new(),
        }));
        assert!(!retryable(&TsaError::Http {
            status: 302,
            body: String::new(),
        }));
        assert!(!retryable(&TsaError::Malformed("x".to_owned())));
        assert!(!retryable(&TsaError::Rejected {
            status: 2,
            text: None,
        }));
    }

    #[test]
    fn a_preview_is_bounded_and_survives_bad_utf8() {
        assert_eq!(preview(b"unavailable"), "unavailable");
        assert_eq!(preview(b""), "");
        assert_eq!(preview(&[0xff, b'o', b'k']), "\u{fffd}ok");

        let long = "a".repeat(300);
        let preview = preview(long.as_bytes());
        assert_eq!(preview.chars().count(), 201);
        assert!(preview.ends_with('…'));
    }

    #[test]
    fn a_preview_reads_only_the_head_of_a_large_body() {
        // The rest of the body is never copied, and a character split by the
        // byte bound degrades to a replacement instead of panicking.
        let mut body = "a".repeat(511);
        body.push('é');
        body.push_str(&"a".repeat(2 * MAX_RESPONSE_BYTES));

        let text = preview(body.as_bytes());
        assert_eq!(text.chars().count(), 201);
        assert!(text.ends_with('…'));
        assert_eq!(&text[..200], "a".repeat(200));

        // Exactly at the byte bound is not a cut; one byte more is.
        assert_eq!(preview(&[b'a'; 511]), "a".repeat(200) + "…");
        assert_eq!(preview(&[b'a'; 200]), "a".repeat(200));
        assert_eq!(preview(&[b'a'; 201]), "a".repeat(200) + "…");
    }

    #[test]
    fn the_response_cap_leaves_room_over_a_token() {
        assert_eq!(
            MAX_RESPONSE_BYTES,
            crate::store::MAX_TOKEN_BYTES + 64 * 1024
        );
    }
}
