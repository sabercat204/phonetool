//! SIP wire format — a pure OPTIONS request builder and a total response parser.
//!
//! Threat note: a SIP response is **untrusted input from the remote being probed**.
//! Even under an authorized gate, the bytes on the wire are adversary-controlled
//! (a honeypot, a hostile PBX, a spoofed source). The parser is therefore *total*:
//! it never panics, never indexes unchecked, and maps every malformed, truncated,
//! or non-ASCII input to a `ParseError`. Both halves of this module are pure
//! functions of their inputs, so they are exhaustively testable with no socket.

use std::fmt::Write as _;

/// The parameters that make one OPTIONS request unique on the wire. Supplied by
/// the caller (the enumerate layer) so the builder stays a pure function — the
/// branch / tag / call-id are inputs, not internally-generated randomness, which
/// keeps the built message deterministic and testable.
#[derive(Debug, Clone)]
pub struct OptionsRequest<'a> {
    /// The authorized target host:port (from the `Grant`), e.g. "192.0.2.10:5060".
    pub target: &'a str,
    /// The extension/user being probed, forming the request URI `sip:<ext>@<host>`.
    pub extension: &'a str,
    /// The host part used in the request URI and To/From (the target's host).
    pub host: &'a str,
    /// Our own contactable address as the remote sees it (host:port).
    pub local_addr: &'a str,
    /// RFC 3261 Via branch; must begin `z9hG4bK`. Caller supplies a unique value.
    pub branch: &'a str,
    /// From-tag; caller supplies a unique value.
    pub tag: &'a str,
    /// Call-ID; caller supplies a unique value.
    pub call_id: &'a str,
    /// CSeq sequence number.
    pub cseq: u32,
    /// User-Agent string presented to the remote.
    pub user_agent: &'a str,
}

impl OptionsRequest<'_> {
    /// Serialize to the SIP/2.0 wire form (CRLF-terminated lines, blank-line end,
    /// `Content-Length: 0`). Pure; allocates one `String`.
    #[must_use]
    pub fn to_wire(&self) -> String {
        // A fixed set of writes to a String; `write!` to a String is infallible,
        // but we route through `let _ =` rather than unwrap to honor the no-panic
        // lint without asserting anything.
        let mut m = String::with_capacity(512);
        let _ = writeln!(m, "OPTIONS sip:{}@{} SIP/2.0\r", self.extension, self.host);
        let _ = writeln!(
            m,
            "Via: SIP/2.0/UDP {};branch={}\r",
            self.local_addr, self.branch
        );
        let _ = writeln!(m, "Max-Forwards: 70\r");
        let _ = writeln!(
            m,
            "From: <sip:probe@{}>;tag={}\r",
            self.local_addr, self.tag
        );
        let _ = writeln!(m, "To: <sip:{}@{}>\r", self.extension, self.host);
        let _ = writeln!(m, "Call-ID: {}\r", self.call_id);
        let _ = writeln!(m, "CSeq: {} OPTIONS\r", self.cseq);
        let _ = writeln!(m, "Contact: <sip:probe@{}>\r", self.local_addr);
        let _ = writeln!(m, "User-Agent: {}\r", self.user_agent);
        let _ = writeln!(m, "Accept: application/sdp\r");
        let _ = writeln!(m, "Content-Length: 0\r");
        let _ = write!(m, "\r\n");
        let _ = self.target; // target is used by the socket layer, not the wire URI
        m
    }
}

/// A parsed SIP response. Only the fields the enumerator needs; the full header
/// set is kept as `(name, value)` pairs for the fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The numeric status code (100–699 in practice; parser accepts 3 digits).
    pub status_code: u16,
    /// The reason phrase (may be empty).
    pub reason: String,
    /// Headers in order, names lowercased for case-insensitive lookup.
    pub headers: Vec<(String, String)>,
}

/// Why a candidate response could not be parsed. Every malformed input lands here
/// rather than panicking.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Zero bytes / no status line at all.
    #[error("empty response")]
    Empty,
    /// The first line was not a `SIP/2.0 <code> <reason>` status line.
    #[error("malformed status line")]
    BadStatusLine,
    /// The status token was not a 3-digit code.
    #[error("bad status code")]
    BadStatusCode,
}

impl Response {
    /// Parse a datagram into a [`Response`]. Total over arbitrary bytes: non-UTF-8
    /// is handled lossily, and any structural defect yields a [`ParseError`].
    ///
    /// # Errors
    /// [`ParseError`] on empty input, a non-SIP status line, or a non-numeric code.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(ParseError::Empty);
        }
        let text = String::from_utf8_lossy(bytes);
        // Split on CRLF or bare LF; tolerate either (hostile senders may use LF).
        let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));

        let status_line = lines.next().ok_or(ParseError::Empty)?;
        if status_line.trim().is_empty() {
            return Err(ParseError::Empty);
        }
        // "SIP/2.0 200 OK" → version, code, reason.
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("SIP/") {
            return Err(ParseError::BadStatusLine);
        }
        let code_str = parts.next().ok_or(ParseError::BadStatusLine)?;
        if code_str.len() != 3 || !code_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseError::BadStatusCode);
        }
        let status_code: u16 = code_str.parse().map_err(|_| ParseError::BadStatusCode)?;
        let reason = parts.next().unwrap_or_default().to_owned();

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break; // end of headers (blank line before the body)
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
            }
        }

        Ok(Self {
            status_code,
            reason,
            headers,
        })
    }

    /// Case-insensitive header lookup (names are stored lowercased).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let want = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == want)
            .map(|(_, v)| v.as_str())
    }
}

/// The verdict on one probed extension, inferred from the response status.
///
/// Classic SIP enumeration logic: a server that challenges auth (401/407) or
/// answers (200) is telling us the extension *exists*; a 404 says it does not; a
/// 403 or other 4xx is ambiguous (may exist but is refusing). No response at all
/// is handled one layer up as a timeout, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Extension exists (200 OK, or an auth challenge 401/407).
    Exists,
    /// Extension does not exist (404 Not Found).
    Absent,
    /// Present-but-refusing or otherwise inconclusive (403, other 4xx/5xx/6xx).
    Ambiguous,
}

/// Classify a status code into an enumeration [`Verdict`].
#[must_use]
pub fn classify(status_code: u16) -> Verdict {
    match status_code {
        200 | 401 | 407 => Verdict::Exists,
        404 => Verdict::Absent,
        _ => Verdict::Ambiguous,
    }
}
