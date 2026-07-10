//! Minimal, total `Identity`-header extractor from a SIP message or fragment.
//!
//! This does NOT parse the SIP grammar — it locates `Identity` header value(s)
//! only. Header-name match is ASCII-case-insensitive (RFC 3261 §7.3.1),
//! tolerant of CRLF and bare-LF line endings and of RFC 3261 line folding
//! (a continuation line begins with SP or HTAB and appends to the prior header).
//!
//! Threat note: the message is untrusted. Total — no panic, no unwrap, no
//! unchecked index; a message with zero `Identity` headers yields an empty
//! vec (a reportable "unsigned call"), never an error here.

/// Extract every `Identity` header value from a SIP message/fragment, in order.
/// Returns an empty vec when none are present.
#[must_use]
pub fn extract_identity_headers(input: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(input);
    // Unfold: join continuation lines (leading SP/HTAB) to the previous line.
    let logical = unfold(&text);

    let mut out = Vec::new();
    for line in logical {
        if let Some(value) = match_identity(&line) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_owned());
            }
        }
    }
    out
}

/// Does this input look like a SIP message at all (a request-line or a status
/// line, or at least one `Header: value` line)? Used to distinguish "a SIP
/// message with no Identity header" (reportable) from "not SIP at all"
/// (invalid input).
#[must_use]
pub fn looks_like_sip(input: &[u8]) -> bool {
    let text = String::from_utf8_lossy(input);
    for raw in text.split(['\n']) {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        // SIP request/status line, or any `Token: value` header line.
        if line.starts_with("SIP/") || line.contains("SIP/2.0") {
            return true;
        }
        if let Some((name, _)) = line.split_once(':') {
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return true;
            }
        }
    }
    false
}

/// Split into logical header lines, folding RFC 3261 continuation lines
/// (leading SP or HTAB) onto the previous line.
fn unfold(text: &str) -> Vec<String> {
    let mut logical: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        // A continuation line starts with whitespace and appends to the prior.
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = logical.last_mut() {
                last.push(' ');
                last.push_str(line.trim_start());
                continue;
            }
            // No prior line to fold into: treat as its own line.
        }
        logical.push(line.to_owned());
    }
    logical
}

/// If `line` is an `Identity:` header (ASCII-case-insensitive), return its value.
fn match_identity(line: &str) -> Option<&str> {
    let (name, value) = line.split_once(':')?;
    if name.trim().eq_ignore_ascii_case("Identity") {
        Some(value)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const MSG: &str = "INVITE sip:bob@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP host\r\n\
        Identity: eyJhbGciOiJFUzI1NiJ9.eyJhdHRlc3QiOiJBIn0.sig\r\n\
        To: <sip:bob@example.com>\r\n\r\n";

    #[test]
    fn extracts_single_identity() {
        let got = extract_identity_headers(MSG.as_bytes());
        assert_eq!(got.len(), 1);
        assert!(got[0].starts_with("eyJhbGci"));
    }

    #[test]
    fn case_insensitive_header_name() {
        let msg = "IDENTITY: token.a.b\r\nidentity: token.c.d\r\n";
        let got = extract_identity_headers(msg.as_bytes());
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn no_identity_header_is_empty_not_error() {
        let msg = "INVITE sip:x SIP/2.0\r\nVia: foo\r\nTo: bar\r\n\r\n";
        assert!(extract_identity_headers(msg.as_bytes()).is_empty());
    }

    #[test]
    fn bare_lf_tolerated() {
        let msg = "Via: foo\nIdentity: tok.en.sig\nTo: bar\n";
        let got = extract_identity_headers(msg.as_bytes());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], "tok.en.sig");
    }

    #[test]
    fn line_folding_joined() {
        // A folded Identity value continues on the next line (leading space).
        let msg = "Identity: aaa.bbb\r\n .ccc\r\nTo: x\r\n";
        let got = extract_identity_headers(msg.as_bytes());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], "aaa.bbb .ccc");
    }

    #[test]
    fn looks_like_sip_detects_message_and_headers() {
        assert!(looks_like_sip(MSG.as_bytes()));
        assert!(looks_like_sip(b"Contact: <sip:x>\r\n"));
        assert!(!looks_like_sip(
            b"just some random prose with no colon-headers"
        ));
        assert!(!looks_like_sip(b""));
    }

    #[test]
    fn non_utf8_does_not_panic() {
        let _ = extract_identity_headers(&[0xFF, 0x00, b'I', b'd', 0x80]);
        let _ = looks_like_sip(&[0xFF, 0xFE]);
    }
}
