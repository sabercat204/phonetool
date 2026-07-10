//! SIP wire format for origination — a pure `INVITE` builder (with an SDP audio
//! offer) and a total response parser.
//!
//! Threat note: a SIP response is **untrusted input from the far end**. Even under
//! an authorized gate the bytes on the wire are adversary-controlled (a honeypot
//! trunk, a hostile gateway, a spoofed source). The parser is therefore *total*:
//! it never panics, never indexes unchecked, and maps every malformed, truncated,
//! or non-ASCII input to a [`ParseError`]. Both halves are pure functions of their
//! inputs, so they are exhaustively testable with no socket.
//!
//! This duplicates phonetool-sip's parser posture rather than sharing a crate;
//! factoring a common SIP-message crate out of both is Open Question 7, a refactor
//! deliberately out of this build's scope.

use std::fmt::Write as _;

/// The parameters that make one `INVITE` unique on the wire. Supplied by the
/// caller (the originate layer) so the builder stays a pure function — the
/// branch / tag / call-id are inputs, not internally-generated randomness, which
/// keeps the built message deterministic and testable and adds no RNG dependency.
#[derive(Debug, Clone)]
pub struct InviteRequest<'a> {
    /// The authorized trunk/target `host:port` the socket layer sends to (from the
    /// grant-derived range). Not itself written into the request URI's host.
    pub target: &'a str,
    /// The DID being called, forming the request URI `sip:<did>@<host>`.
    pub did: &'a str,
    /// The host part used in the request URI and To (the trunk's host).
    pub host: &'a str,
    /// Our own contactable address as the far end sees it (`host:port`).
    pub local_addr: &'a str,
    /// The outbound caller-ID presented in the From header (from `TrunkConfig`).
    /// Attribution-bearing: it identifies the operator to the callee.
    pub caller_id: &'a str,
    /// RFC 3261 Via branch; must begin `z9hG4bK`. Caller supplies a unique value.
    pub branch: &'a str,
    /// From-tag; caller supplies a unique value.
    pub tag: &'a str,
    /// Call-ID; caller supplies a unique value.
    pub call_id: &'a str,
    /// CSeq sequence number.
    pub cseq: u32,
    /// User-Agent string presented to the far end.
    pub user_agent: &'a str,
}

impl InviteRequest<'_> {
    /// Serialize to the SIP/2.0 `INVITE` wire form with an SDP audio offer body.
    ///
    /// The SDP offer advertises a single audio media line with payload type 0
    /// (PCMU / G.711 µ-law, the RTP static type from RFC 3551) and the telephone-
    /// event type. **This is an offer only** — no RTP is ever received or decoded
    /// (no media path exists in the workbench; see the crate docs and Requirement
    /// 10). The `c=` connection address is our local host; a real answerer's RTP
    /// would arrive there *if* a media path existed to catch it.
    ///
    /// Pure; allocates one `String`. `write!` to a `String` is infallible but is
    /// routed through `let _ =` to honor the no-panic lint without asserting.
    #[must_use]
    pub fn to_wire(&self) -> String {
        // Build the SDP body first so we can set an accurate Content-Length.
        let local_host = self
            .local_addr
            .rsplit_once(':')
            .map_or(self.local_addr, |(h, _)| h);
        let mut sdp = String::with_capacity(256);
        let _ = writeln!(sdp, "v=0\r");
        let _ = writeln!(sdp, "o=phonetool 0 0 IN IP4 {local_host}\r");
        let _ = writeln!(sdp, "s=phonetool\r");
        let _ = writeln!(sdp, "c=IN IP4 {local_host}\r");
        let _ = writeln!(sdp, "t=0 0\r");
        // Offer PCMU (0) + telephone-event; we never actually decode the answer.
        let _ = writeln!(sdp, "m=audio 0 RTP/AVP 0 101\r");
        let _ = writeln!(sdp, "a=rtpmap:0 PCMU/8000\r");
        let _ = writeln!(sdp, "a=rtpmap:101 telephone-event/8000\r");

        let mut m = String::with_capacity(640);
        let _ = writeln!(m, "INVITE sip:{}@{} SIP/2.0\r", self.did, self.host);
        let _ = writeln!(
            m,
            "Via: SIP/2.0/UDP {};branch={}\r",
            self.local_addr, self.branch
        );
        let _ = writeln!(m, "Max-Forwards: 70\r");
        let _ = writeln!(
            m,
            "From: <sip:{}@{}>;tag={}\r",
            self.caller_id, self.host, self.tag
        );
        let _ = writeln!(m, "To: <sip:{}@{}>\r", self.did, self.host);
        let _ = writeln!(m, "Call-ID: {}\r", self.call_id);
        let _ = writeln!(m, "CSeq: {} INVITE\r", self.cseq);
        let _ = writeln!(m, "Contact: <sip:{}@{}>\r", self.caller_id, self.local_addr);
        let _ = writeln!(m, "User-Agent: {}\r", self.user_agent);
        let _ = writeln!(m, "Content-Type: application/sdp\r");
        let _ = writeln!(m, "Content-Length: {}\r", sdp.len());
        let _ = write!(m, "\r\n");
        let _ = m.write_str(&sdp);
        let _ = self.target; // target is used by the socket layer, not the wire URI
        m
    }
}

/// A minimal `ACK`/`BYE`/`CANCEL` teardown request line + headers, echoing the
/// dialog identifiers so the far end can correlate it. Used to tear a call down
/// after a final response (`ACK`+`BYE` on a `200 OK`, `CANCEL` before final) so a
/// sweep never leaves a dialog dangling — Requirement 4.1.
#[derive(Debug, Clone)]
pub struct TeardownRequest<'a> {
    /// The method: `"ACK"`, `"BYE"`, or `"CANCEL"`.
    pub method: &'a str,
    /// The DID (request-URI user part).
    pub did: &'a str,
    /// The trunk host.
    pub host: &'a str,
    /// Our local address.
    pub local_addr: &'a str,
    /// The caller-ID (From).
    pub caller_id: &'a str,
    /// The Via branch (must match the INVITE's for CANCEL).
    pub branch: &'a str,
    /// The From tag.
    pub tag: &'a str,
    /// The Call-ID.
    pub call_id: &'a str,
    /// The CSeq number (matches the INVITE for CANCEL; +1 for BYE).
    pub cseq: u32,
}

impl TeardownRequest<'_> {
    /// Serialize the teardown request. Pure; no body.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let mut m = String::with_capacity(384);
        let _ = writeln!(
            m,
            "{} sip:{}@{} SIP/2.0\r",
            self.method, self.did, self.host
        );
        let _ = writeln!(
            m,
            "Via: SIP/2.0/UDP {};branch={}\r",
            self.local_addr, self.branch
        );
        let _ = writeln!(m, "Max-Forwards: 70\r");
        let _ = writeln!(
            m,
            "From: <sip:{}@{}>;tag={}\r",
            self.caller_id, self.host, self.tag
        );
        let _ = writeln!(m, "To: <sip:{}@{}>\r", self.did, self.host);
        let _ = writeln!(m, "Call-ID: {}\r", self.call_id);
        let _ = writeln!(m, "CSeq: {} {}\r", self.cseq, self.method);
        let _ = writeln!(m, "Content-Length: 0\r");
        let _ = write!(m, "\r\n");
        m
    }
}

/// A parsed SIP response. Only the fields the classifier needs; the full header
/// set is kept as `(name, value)` pairs for the `Reason`/`Server` lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The numeric status code (100–699 in practice; parser accepts any 3 digits).
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn invite() -> InviteRequest<'static> {
        InviteRequest {
            target: "10.0.0.1:5060",
            did: "+15125550100",
            host: "trunk.example",
            local_addr: "192.0.2.5:5060",
            caller_id: "+15125550001",
            branch: "z9hG4bKdeadbeef0",
            tag: "sess-t0",
            call_id: "sess-0@phonetool",
            cseq: 1,
            user_agent: "phonetool-wardial-test",
        }
    }

    #[test]
    fn invite_wire_has_request_line_sdp_and_accurate_content_length() {
        let wire = invite().to_wire();
        assert!(wire.starts_with("INVITE sip:+15125550100@trunk.example SIP/2.0\r\n"));
        assert!(wire.contains("Content-Type: application/sdp\r\n"));
        assert!(wire.contains("m=audio 0 RTP/AVP 0 101\r\n"));
        assert!(wire.contains("a=rtpmap:0 PCMU/8000\r\n"));

        // Content-Length must equal the actual SDP body length.
        let (headers, body) = wire.split_once("\r\n\r\n").expect("header/body split");
        let declared: usize = headers
            .lines()
            .find_map(|l| l.trim_end().strip_prefix("Content-Length: "))
            .and_then(|v| v.parse().ok())
            .expect("content-length present");
        assert_eq!(declared, body.len(), "declared length matches SDP body");
    }

    #[test]
    fn invite_from_header_carries_caller_id() {
        // Attribution is explicit on the wire: the caller-ID identifies the operator.
        assert!(
            invite()
                .to_wire()
                .contains("From: <sip:+15125550001@trunk.example>;tag=sess-t0")
        );
    }

    #[test]
    fn teardown_wire_is_well_formed() {
        let bye = TeardownRequest {
            method: "BYE",
            did: "+15125550100",
            host: "trunk.example",
            local_addr: "192.0.2.5:5060",
            caller_id: "+15125550001",
            branch: "z9hG4bKdeadbeef0",
            tag: "sess-t0",
            call_id: "sess-0@phonetool",
            cseq: 2,
        }
        .to_wire();
        assert!(bye.starts_with("BYE sip:+15125550100@trunk.example SIP/2.0\r\n"));
        assert!(bye.contains("CSeq: 2 BYE\r\n"));
        assert!(bye.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parses_a_well_formed_response() {
        let r =
            Response::parse(b"SIP/2.0 486 Busy Here\r\nServer: pbx\r\nContent-Length: 0\r\n\r\n")
                .expect("valid");
        assert_eq!(r.status_code, 486);
        assert_eq!(r.reason, "Busy Here");
        assert_eq!(r.header("server"), Some("pbx"));
    }

    #[test]
    fn parse_tolerates_bare_lf_and_reads_reason_header() {
        let r =
            Response::parse(b"SIP/2.0 404 Not Found\nReason: Q.850;cause=1\n\n").expect("valid");
        assert_eq!(r.status_code, 404);
        assert_eq!(r.header("reason"), Some("Q.850;cause=1"));
    }

    #[test]
    fn hostile_inputs_map_to_parse_errors_never_panic() {
        assert_eq!(Response::parse(b""), Err(ParseError::Empty));
        assert_eq!(Response::parse(b"   \r\n"), Err(ParseError::Empty));
        assert_eq!(
            Response::parse(b"HTTP/1.1 200 OK\r\n"),
            Err(ParseError::BadStatusLine)
        );
        assert_eq!(
            Response::parse(b"SIP/2.0 20 Short\r\n"),
            Err(ParseError::BadStatusCode)
        );
        assert_eq!(
            Response::parse(b"SIP/2.0 abc Bad\r\n"),
            Err(ParseError::BadStatusCode)
        );
        // Non-UTF-8 and a giant blob must not panic.
        let _ = Response::parse(&[0xff, 0xfe, 0x00, 0x01]);
        let _ = Response::parse(&vec![b'A'; 100_000]);
    }
}
