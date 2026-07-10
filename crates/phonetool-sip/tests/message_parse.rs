//! Hostile-input tests for the SIP response parser.
//!
//! A SIP response is adversary-controlled bytes from the remote being probed —
//! even under an authorized gate, the sender may be a honeypot or a hostile PBX.
//! `Response::parse` is therefore **total**: every malformed, truncated, or
//! non-UTF-8 input must yield a `ParseError`, never a panic, an unchecked index,
//! or an unwrap. These tables exercise the failure surface and the accept surface.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use phonetool_sip::message::{ParseError, Response, Verdict, classify};

#[test]
fn hostile_inputs_error_and_never_panic() {
    // (label, raw bytes, expected error) — one row per way a datagram can be bad.
    let cases: &[(&str, &[u8], ParseError)] = &[
        ("empty datagram", b"", ParseError::Empty),
        ("only whitespace", b"   \r\n", ParseError::Empty),
        ("only CRLF", b"\r\n", ParseError::Empty),
        (
            "not a SIP version",
            b"HTTP/1.1 200 OK\r\n\r\n",
            ParseError::BadStatusLine,
        ),
        (
            "status line missing code",
            b"SIP/2.0\r\n\r\n",
            ParseError::BadStatusLine,
        ),
        (
            "non-numeric code",
            b"SIP/2.0 XYZ Bad\r\n\r\n",
            ParseError::BadStatusCode,
        ),
        (
            "two-digit code",
            b"SIP/2.0 20 OK\r\n\r\n",
            ParseError::BadStatusCode,
        ),
        (
            "four-digit code",
            b"SIP/2.0 2000 OK\r\n\r\n",
            ParseError::BadStatusCode,
        ),
        (
            "code with embedded letter",
            b"SIP/2.0 2O0 OK\r\n\r\n",
            ParseError::BadStatusCode,
        ),
    ];

    for (label, raw, expected) in cases {
        let got = Response::parse(raw);
        assert_eq!(
            got.as_ref().err(),
            Some(expected),
            "case {label:?}: expected {expected:?}, got {got:?}"
        );
    }
}

#[test]
fn non_utf8_and_giant_inputs_do_not_panic() {
    // Non-UTF-8 status line: handled lossily, still classified by structure.
    let non_utf8 = b"\xff\xfe garbage bytes here\r\n";
    assert!(
        Response::parse(non_utf8).is_err(),
        "invalid leading bytes reject"
    );

    // A valid status line followed by non-UTF-8 header bytes must still parse the
    // status without panicking on the lossy conversion.
    let mut mixed = b"SIP/2.0 200 OK\r\nServer: ".to_vec();
    mixed.extend_from_slice(&[0xff, 0xfe, 0x00]);
    mixed.extend_from_slice(b"\r\n\r\n");
    let resp = Response::parse(&mixed).expect("valid status line parses despite lossy header");
    assert_eq!(resp.status_code, 200);

    // A pathologically large header block: must terminate, not hang or overflow.
    let mut giant = b"SIP/2.0 200 OK\r\n".to_vec();
    for i in 0..5000 {
        giant.extend_from_slice(format!("X-Pad-{i}: {}\r\n", "A".repeat(64)).as_bytes());
    }
    giant.extend_from_slice(b"\r\n");
    let resp = Response::parse(&giant).expect("large but well-formed response parses");
    assert_eq!(resp.status_code, 200);
    assert!(resp.headers.len() >= 5000);
}

#[test]
fn accepts_well_formed_responses_with_crlf_and_bare_lf() {
    // Canonical CRLF form.
    let crlf = b"SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"x\"\r\n\r\n";
    let resp = Response::parse(crlf).expect("CRLF response parses");
    assert_eq!(resp.status_code, 401);
    assert_eq!(resp.reason, "Unauthorized");
    assert_eq!(
        resp.header("www-authenticate"),
        Some("Digest realm=\"x\""),
        "header lookup is case-insensitive"
    );

    // Bare-LF form (hostile / lenient senders): tolerated identically.
    let bare_lf = b"SIP/2.0 200 OK\nServer: Asterisk\nContent-Length: 0\n\n";
    let resp = Response::parse(bare_lf).expect("bare-LF response parses");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.header("server"), Some("Asterisk"));

    // Missing reason phrase is allowed (reason is optional).
    let no_reason = b"SIP/2.0 486\r\n\r\n";
    let resp = Response::parse(no_reason).expect("status line with no reason parses");
    assert_eq!(resp.status_code, 486);
    assert_eq!(resp.reason, "");
}

#[test]
fn classify_maps_status_codes_to_enumeration_verdicts() {
    // Exists: a 200, or an auth challenge (the server admits the extension is real).
    assert_eq!(classify(200), Verdict::Exists);
    assert_eq!(classify(401), Verdict::Exists);
    assert_eq!(classify(407), Verdict::Exists);
    // Absent: only a definitive 404.
    assert_eq!(classify(404), Verdict::Absent);
    // Ambiguous: present-but-refusing, and everything else.
    assert_eq!(classify(403), Verdict::Ambiguous);
    assert_eq!(classify(486), Verdict::Ambiguous);
    assert_eq!(classify(500), Verdict::Ambiguous);
    assert_eq!(classify(603), Verdict::Ambiguous);
    assert_eq!(classify(100), Verdict::Ambiguous);
}
