//! Fail-closed parsing, byte-exact composition and pre-image extraction for raw
//! git commit objects.
//!
//! A commit object is a header section, one blank line, then the message. Git
//! writes headers as `name value`; a header value may continue over several
//! lines, each continuation line starting with a single space. Anything else is
//! a malformed object, and this parser says so instead of guessing.
//!
//! Composition is the exact inverse of parsing, so a parsed object can be
//! reproduced byte for byte and rewritten object bytes stay auditable. A
//! pre-image is that reproduction with the signature headers and a trailing
//! timestamp trailer block removed — the bytes an RFC 3161 imprint is taken
//! over.
//!
//! Bytes are kept as bytes: no UTF-8 conversion happens here, and semantic
//! checks (which headers a commit must have, what their values mean) are left to
//! callers.

/// Header names whose values are commit signatures.
const SIGNATURE_HEADERS: [&str; 2] = ["gpgsig", "gpgsig-sha256"];

/// A raw commit object, split into headers and message.
///
/// `headers` preserves file order and stores unfolded values: the newline that
/// used to start a continuation line is kept, its leading space is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitObject {
    /// Headers in file order, each as `(name, value)`; values are unfolded.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Everything after the first blank line, verbatim.
    pub message: Vec<u8>,
}

/// What an RFC 3161 imprint is taken over, plus the trailer it leaves out.
///
/// `bytes` is exactly what gets hashed: the object with every signature header
/// and the trailing trailer block removed. `trailer` is the block's bytes as
/// they appeared — no blank line separating them from the message, no trailing
/// newline.
///
/// To rebuild the sealed object again, take `bytes`, then one `\n` (the byte
/// `pre_image` removed together with the block), then `trailer`, then the
/// message's final `\n`. Only a hand-written object whose block starts the
/// message has no separator to restore and gains one blank line too many:
///
/// ```
/// # use git_time_core::object::CommitObject;
/// let sealed = b"tree 4b82\n\nbody\n\nX-RFC3161-Imprint: sha256:00\n";
/// let pre_image = CommitObject::parse(sealed).unwrap().pre_image("X-RFC3161-");
///
/// let mut rebuilt = pre_image.bytes.clone();
/// rebuilt.push(b'\n');
/// rebuilt.extend_from_slice(pre_image.trailer.as_deref().unwrap());
/// rebuilt.push(b'\n');
/// assert_eq!(rebuilt, sealed);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreImage {
    /// The object bytes with every signature header and the trailer block
    /// removed, but with the message's trailing newlines untouched.
    pub bytes: Vec<u8>,
    /// The stripped trailer block's own bytes, without the separating blank line
    /// and without a trailing newline, or `None` when the object has none.
    pub trailer: Option<Vec<u8>>,
}

impl CommitObject {
    /// Parse a raw commit object.
    ///
    /// Fails closed: anything that is not `name value` with a name of
    /// `[a-zA-Z0-9-]+`, one space and a value, nor a continuation line, nor a
    /// separator, is rejected.
    ///
    /// The separator is located before any header line is inspected, so an
    /// object that is both unseparated and malformed reports
    /// [`ParseError::MissingSeparator`].
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(ParseError::Empty);
        }
        let split = bytes
            .windows(2)
            .position(|pair| pair == b"\n\n")
            .ok_or(ParseError::MissingSeparator)?;

        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let header_section = &bytes[..split];
        if !header_section.is_empty() {
            for line in header_section.split(|byte| *byte == b'\n') {
                if let Some(continued) = line.strip_prefix(b" ") {
                    let Some((_, value)) = headers.last_mut() else {
                        return Err(ParseError::MalformedHeader);
                    };
                    value.push(b'\n');
                    value.extend_from_slice(continued);
                    continue;
                }
                let Some(separator) = line.iter().position(|byte| *byte == b' ') else {
                    return Err(ParseError::MalformedHeader);
                };
                let (name, value) = line.split_at(separator);
                // A line starting with a space never reaches this point: it was
                // taken as a continuation line above, so `name` cannot be empty.
                if !name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
                {
                    return Err(ParseError::MalformedHeader);
                }
                headers.push((name.to_vec(), value[1..].to_vec()));
            }
        }

        Ok(Self {
            headers,
            message: bytes[split + 2..].to_vec(),
        })
    }

    /// Reproduce the exact bytes [`CommitObject::parse`] was given.
    ///
    /// Continuation lines are re-emitted with their single leading space, the
    /// blank line separator is written as `\n\n`, and the message is copied
    /// verbatim.
    ///
    /// The inverse only holds for header names `parse` accepts
    /// (`[a-zA-Z0-9-]+`, non-empty): an empty name composes to a line that
    /// parses back as a continuation line, and a name with a space or `:` in it
    /// moves the header boundary.
    #[must_use]
    pub fn compose(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (index, (name, value)) in self.headers.iter().enumerate() {
            if index > 0 {
                bytes.push(b'\n');
            }
            bytes.extend_from_slice(name);
            bytes.push(b' ');
            for (part, line) in value.split(|byte| *byte == b'\n').enumerate() {
                if part > 0 {
                    bytes.extend_from_slice(b"\n ");
                }
                bytes.extend_from_slice(line);
            }
        }
        bytes.extend_from_slice(b"\n\n");
        bytes.extend_from_slice(&self.message);
        bytes
    }

    /// The object with every `gpgsig` and `gpgsig-sha256` header, including its
    /// continuation lines, removed and nothing else changed.
    #[must_use]
    pub fn without_signature(&self) -> Self {
        Self {
            headers: self
                .headers
                .iter()
                .filter(|(name, _)| !is_signature_header(name))
                .cloned()
                .collect(),
            message: self.message.clone(),
        }
    }

    /// The bytes an imprint is taken over: this object without signatures and
    /// without the trailing trailer block whose lines start with `prefix`.
    ///
    /// Only the last paragraph of the message is a trailer, and only when every
    /// one of its lines starts with `prefix`. The byte separating that paragraph
    /// from the message goes with it; the remaining message's trailing newlines
    /// are preserved exactly. An empty `prefix` matches every line, so the whole
    /// message is treated as trailer.
    #[must_use]
    pub fn pre_image(&self, prefix: &str) -> PreImage {
        let stripped = self.without_signature();
        let mut bytes = stripped.compose();

        let Some(trailer_start) = trailer_start_in(&stripped.message, prefix.as_bytes()) else {
            return PreImage {
                bytes,
                trailer: None,
            };
        };

        // The message begins after its own two-byte separator, so an offset in
        // the message transfers to the object by this delta.
        let message_start = bytes.len() - stripped.message.len();
        let start = message_start + trailer_start;
        // A trailer line always starts a line, so the byte before it is the
        // `\n` that separated it from the message: either the newline the seal
        // appended after a message without a final newline, or the blank line's
        // own newline. Both go with the trailer; the message keeps every
        // newline that belonged to it.
        let end = start - usize::from(trailer_start > 0);
        bytes.truncate(end);

        PreImage {
            bytes,
            trailer: Some(block(&stripped.message[trailer_start..])),
        }
    }

    /// The unfolded value of the first header called `name`, if any.
    ///
    /// Name matching is exact and case sensitive; duplicate headers keep their
    /// order, so the first one wins.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        let name = name.as_bytes();
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_slice())
    }
}

fn is_signature_header(name: &[u8]) -> bool {
    SIGNATURE_HEADERS
        .iter()
        .any(|signature| signature.as_bytes() == name)
}

/// The offset where a trailing paragraph of `prefix` lines starts, if the
/// message ends with one.
///
/// The paragraph is the run of trailing lines that all start with `prefix`; a
/// blank line ends the run, and so does a line with another prefix.
fn trailer_start_in(message: &[u8], prefix: &[u8]) -> Option<usize> {
    if message.is_empty() {
        return None;
    }
    let mut cursor = message.len();
    let mut start = None;
    loop {
        let line_end = match message[cursor - 1] {
            b'\n' => cursor - 1,
            _ => cursor,
        };
        let line_start = message[..line_end]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |newline| newline + 1);
        if !message[line_start..line_end].starts_with(prefix) {
            return start;
        }
        start = Some(line_start);
        if line_start == 0 {
            return start;
        }
        cursor = line_start;
    }
}

/// The trailer block as a value: verbatim lines, minus one trailing newline.
fn block(lines: &[u8]) -> Vec<u8> {
    lines.strip_suffix(b"\n").unwrap_or(lines).to_vec()
}

/// Why a raw commit object could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The input had no bytes at all.
    #[error("empty commit object")]
    Empty,
    /// Headers and message are not separated by a blank line.
    #[error("commit object has no blank line between headers and message")]
    MissingSeparator,
    /// A header line was neither `name value` nor a continuation line.
    #[error("commit object has a malformed header line")]
    MalformedHeader,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_looking_names_are_rejected() {
        assert_eq!(
            CommitObject::parse("naïve 1\n\n".as_bytes()).unwrap_err(),
            ParseError::MalformedHeader
        );
    }

    #[test]
    fn a_value_may_be_empty() {
        let commit = CommitObject::parse(b"note \n\n").expect("parses");
        assert_eq!(commit.header("note"), Some(b"".as_slice()));
    }

    #[test]
    fn an_empty_prefix_treats_the_whole_message_as_trailer() {
        let commit = CommitObject::parse(b"tree 4b82\n\nbody\n").expect("parses");
        assert_eq!(commit.pre_image("").bytes, b"tree 4b82\n\n");
    }
}
