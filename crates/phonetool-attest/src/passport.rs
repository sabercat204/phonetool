//! Total, network-free parse of a SIP `Identity` header and its PASSporT.
//!
//! Grounding: RFC 8224 (`Identity` header), RFC 8225 (PASSporT / JWS compact
//! serialization), ATIS-1000074 (SHAKEN attestation levels A/B/C), RFC 4648 §5
//! (unpadded base64url).
//!
//! Threat note: the `Identity` header and the PASSporT it carries are 100%
//! adversary-controlled — a hostile caller crafts them to spoof caller-ID or to
//! break a naïve parser (oversized headers, huge base64 segments, non-UTF-8,
//! `alg`-confusion). Every function here is TOTAL: it never panics, never
//! unwraps, never indexes unchecked, and never trusts a remote-supplied length
//! as an allocation size. Uncertainty about attestation is never resolved in
//! the caller's favor — an unrecognized `attest` value is `Unknown { raw }`,
//! never a coerced level.

use serde_json::Value;

/// Maximum accepted `Identity` header length (bytes). A header longer than this
/// is rejected before any decode. **Provisional cap** — RFC 8224/8225 and
/// ATIS-1000074 constrain field *shapes*, not a normative byte ceiling; this
/// value is a defensive bound (a real SHAKEN `Identity` header is well under
/// 2 KiB in practice), NOT a spec-cited constant. Tune when a real-world
/// distribution is available (Open Question 2 in the spec).
pub const MAX_IDENTITY: usize = 8192;

/// Maximum accepted decoded segment length (bytes) for the JOSE header and the
/// claims. Same provisional-cap caveat as [`MAX_IDENTITY`].
pub const MAX_SEGMENT: usize = 4096;

/// A structural finding recorded during inspection — a real, reportable signal
/// (not an error). "This call is unsigned" / "this token used an unexpected
/// algorithm" is exactly the intelligence a spoof-hunt wants.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    /// The supplied SIP message carried no `Identity` header (unsigned call).
    NoIdentityHeader,
    /// The PASSporT parsed but carried no `attest` claim.
    NoAttestClaim,
    /// The JOSE `alg` was present and was not `ES256` (SHAKEN permits only ES256).
    UnexpectedAlg { raw: String },
    /// The JOSE `ppt` was present and was not `"shaken"`.
    UnexpectedPpt { raw: String },
}

/// The attestation level (ATIS-1000074). `Unknown`/`None` are first-class: the
/// tool never upgrades an uncertain value to a trusted level.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attestation {
    /// "A" — Full: originator authenticated AND authorized for the TN.
    Full,
    /// "B" — Partial: originator authenticated, TN not verified.
    Partial,
    /// "C" — Gateway: call entered from a gateway, originator not authenticated.
    Gateway,
    /// `attest` present but not A/B/C — the verbatim value, never coerced.
    Unknown { raw: String },
    /// No `attest` claim in the token.
    None,
}

impl Attestation {
    /// Classify a raw `attest` claim value (ATIS-1000074). Any value that is not
    /// exactly `A`/`B`/`C` is `Unknown { raw }` — never mapped to a valid level.
    #[must_use]
    pub fn classify(raw: &str) -> Self {
        match raw {
            "A" => Self::Full,
            "B" => Self::Partial,
            "C" => Self::Gateway,
            other => Self::Unknown {
                raw: other.to_owned(),
            },
        }
    }
}

/// The PASSporT's protected JOSE header. Every field is `Option` — absent is
/// reported as absent, never defaulted.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Jose {
    /// Signature algorithm. SHAKEN permits only `ES256`.
    pub alg: Option<String>,
    /// PASSporT type extension. SHAKEN uses `"shaken"`.
    pub ppt: Option<String>,
    /// The signing certificate's HTTPS URL (attacker-influenced on the online path).
    pub x5u: Option<String>,
    /// Token type, typically `"passport"`.
    pub typ: Option<String>,
}

/// The PASSporT claims (payload). Every field is `Option`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Claims {
    /// Originating telephone number / identity.
    pub orig: Option<String>,
    /// Destination TN(s). Surfaced verbatim (v1 does not normalize multi-dest).
    pub dest: Option<String>,
    /// Issued-at time (seconds since epoch).
    pub iat: Option<i64>,
    /// Origination identifier (a UUID).
    pub origid: Option<String>,
}

/// A parsed PASSporT: JOSE header, claims, attestation level, raw signature
/// bytes, and any structural findings recorded during parse.
#[derive(Debug, Clone)]
pub struct Passport {
    /// Parsed JOSE header.
    pub jose: Jose,
    /// Parsed claims.
    pub claims: Claims,
    /// Classified attestation level.
    pub attestation: Attestation,
    /// Raw signature bytes (base64url-decoded third segment).
    pub signature: Vec<u8>,
    /// The signing input `base64url(JOSE) "." base64url(claims)` verbatim — the
    /// bytes an ES256 verifier signs over (retained for the online path).
    pub signing_input: Vec<u8>,
    /// Structural findings (unexpected alg/ppt, etc.).
    pub findings: Vec<Finding>,
}

/// A typed parse failure. Every malformed input maps to exactly one of these —
/// never a panic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Input was empty or whitespace-only.
    #[error("empty input")]
    Empty,
    /// The PASSporT was not exactly three `.`-separated segments.
    #[error("malformed token: expected three base64url segments")]
    MalformedToken,
    /// A segment was not valid unpadded base64url.
    #[error("bad base64url in a PASSporT segment")]
    BadBase64,
    /// A decoded JOSE-header or claims segment was not valid JSON.
    #[error("bad JSON in a decoded PASSporT segment")]
    BadJson,
    /// The header or a decoded segment exceeded its cap.
    #[error("input exceeds size cap")]
    TooLarge,
}

/// The parsed `Identity` header: the PASSporT plus the raw header parameters
/// (`info`, `alg`, `ppt`) that RFC 8224 carries alongside it.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The parsed PASSporT.
    pub passport: Passport,
}

impl Identity {
    /// Parse a single `Identity` header value (the PASSporT + optional
    /// `;`-separated parameters) totally over untrusted bytes.
    ///
    /// # Errors
    /// Returns [`ParseError`] for empty, oversized, malformed-token,
    /// bad-base64url, or bad-JSON input. Never panics.
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() > MAX_IDENTITY {
            return Err(ParseError::TooLarge);
        }
        // UTF-8-lossy: a hostile header may carry non-UTF-8 bytes; we do not
        // panic, we degrade to replacement chars and let the structural checks
        // reject anything that matters.
        let text = String::from_utf8_lossy(input);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(ParseError::Empty);
        }

        // The RFC 8224 Identity header is `<passport> *( ";" param )`. Take the
        // token up to the first ';' (parameters like info=/alg=/ppt= follow it).
        let token = trimmed.split(';').next().unwrap_or(trimmed).trim();

        let passport = parse_passport(token)?;
        Ok(Self { passport })
    }
}

/// Parse the compact-serialization PASSporT `jose.claims.sig`.
fn parse_passport(token: &str) -> Result<Passport, ParseError> {
    // Exactly three '.'-separated segments (JWS compact serialization).
    let mut parts = token.split('.');
    let (jose_b64, claims_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(j), Some(c), Some(s), None) if !j.is_empty() && !c.is_empty() => (j, c, s),
            _ => return Err(ParseError::MalformedToken),
        };

    let jose_bytes = decode_segment(jose_b64)?;
    let claims_bytes = decode_segment(claims_b64)?;
    // The signature segment may legitimately be empty (an unsigned/`alg=none`
    // token); decode it but do not require content.
    let signature = decode_b64url(sig_b64).ok_or(ParseError::BadBase64)?;

    let jose_json: Value = serde_json::from_slice(&jose_bytes).map_err(|_| ParseError::BadJson)?;
    let claims_json: Value =
        serde_json::from_slice(&claims_bytes).map_err(|_| ParseError::BadJson)?;

    let mut findings = Vec::new();

    let jose = Jose {
        alg: str_field(&jose_json, "alg"),
        ppt: str_field(&jose_json, "ppt"),
        x5u: str_field(&jose_json, "x5u"),
        typ: str_field(&jose_json, "typ"),
    };

    // alg ≠ ES256 → finding, and NO verification is attempted for this token.
    if let Some(alg) = &jose.alg {
        if alg != "ES256" {
            findings.push(Finding::UnexpectedAlg { raw: alg.clone() });
        }
    }
    // ppt ≠ "shaken" → finding, but still report the parsed contents.
    if let Some(ppt) = &jose.ppt {
        if ppt != "shaken" {
            findings.push(Finding::UnexpectedPpt { raw: ppt.clone() });
        }
    }

    let claims = Claims {
        orig: tn_field(&claims_json, "orig"),
        dest: tn_field(&claims_json, "dest"),
        iat: claims_json.get("iat").and_then(Value::as_i64),
        origid: str_field(&claims_json, "origid"),
    };

    let attestation = match str_field(&claims_json, "attest") {
        Some(raw) => Attestation::classify(&raw),
        None => {
            findings.push(Finding::NoAttestClaim);
            Attestation::None
        }
    };

    // The signing input is the verbatim `jose.claims` (base64url), the exact
    // bytes an ES256 verifier signs over.
    let mut signing_input = Vec::with_capacity(jose_b64.len() + 1 + claims_b64.len());
    signing_input.extend_from_slice(jose_b64.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(claims_b64.as_bytes());

    Ok(Passport {
        jose,
        claims,
        attestation,
        signature,
        signing_input,
        findings,
    })
}

/// Decode a base64url segment, enforcing the segment cap.
fn decode_segment(seg: &str) -> Result<Vec<u8>, ParseError> {
    let bytes = decode_b64url(seg).ok_or(ParseError::BadBase64)?;
    if bytes.len() > MAX_SEGMENT {
        return Err(ParseError::TooLarge);
    }
    Ok(bytes)
}

/// Extract a JSON string field, cloned. Absent or non-string → `None`.
fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Extract an `orig`/`dest` claim. RFC 8225 wraps these as `{"tn": "..."}` or
/// `{"uri": [...]}`; accept a bare string, a `tn` string, or the verbatim JSON.
fn tn_field(v: &Value, key: &str) -> Option<String> {
    let field = v.get(key)?;
    if let Some(s) = field.as_str() {
        return Some(s.to_owned());
    }
    if let Some(tn) = field.get("tn").and_then(Value::as_str) {
        return Some(tn.to_owned());
    }
    // Surface the structure verbatim rather than fabricate a normalized form.
    Some(field.to_string())
}

/// Total unpadded-base64url decoder (RFC 4648 §5). Returns `None` on any invalid
/// character or an impossible length (a single leftover sextet). Accepts input
/// with or without `=` padding. Never panics.
fn decode_b64url(s: &str) -> Option<Vec<u8>> {
    // Map a base64url character to its 6-bit value.
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut sextets: usize = 0;

    for &c in s.as_bytes() {
        if c == b'=' {
            // Padding: valid only as a trailing run; stop consuming data.
            break;
        }
        let six = val(c)?;
        acc = (acc << 6) | u32::from(six);
        nbits += 6;
        sextets += 1;
        if nbits >= 8 {
            nbits -= 8;
            let byte = ((acc >> nbits) & 0xFF) as u8;
            out.push(byte);
        }
    }

    // A single leftover base64url character (sextets % 4 == 1) cannot encode a
    // whole byte — reject as malformed rather than silently drop it.
    if sextets % 4 == 1 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Encode bytes as unpadded base64url (test helper — inverse of the decoder).
    fn enc(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[(n & 63) as usize] as char);
            }
        }
        out
    }

    /// Build a well-formed PASSporT compact serialization from JOSE + claims JSON.
    fn make_passport(jose: &str, claims: &str, sig: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            enc(jose.as_bytes()),
            enc(claims.as_bytes()),
            enc(sig)
        )
    }

    fn shaken_a() -> String {
        make_passport(
            r#"{"alg":"ES256","typ":"passport","ppt":"shaken","x5u":"https://certs.example.com/c.pem"}"#,
            r#"{"attest":"A","orig":{"tn":"12155550100"},"dest":{"tn":["12155550111"]},"iat":1700000000,"origid":"abc-123"}"#,
            &[1, 2, 3, 4],
        )
    }

    #[test]
    fn parses_full_attestation() {
        let id = Identity::parse(shaken_a().as_bytes()).expect("valid");
        let p = &id.passport;
        assert_eq!(p.attestation, Attestation::Full);
        assert_eq!(p.jose.alg.as_deref(), Some("ES256"));
        assert_eq!(p.jose.ppt.as_deref(), Some("shaken"));
        assert_eq!(
            p.jose.x5u.as_deref(),
            Some("https://certs.example.com/c.pem")
        );
        assert_eq!(p.claims.orig.as_deref(), Some("12155550100"));
        assert_eq!(p.claims.iat, Some(1700000000));
        assert_eq!(p.claims.origid.as_deref(), Some("abc-123"));
        assert_eq!(p.signature, vec![1, 2, 3, 4]);
        assert!(p.findings.is_empty());
    }

    #[test]
    fn strips_header_parameters() {
        let with_params = format!(
            "{};info=<https://certs.example.com/c.pem>;alg=ES256;ppt=shaken",
            shaken_a()
        );
        let id = Identity::parse(with_params.as_bytes()).expect("valid with params");
        assert_eq!(id.passport.attestation, Attestation::Full);
    }

    #[test]
    fn classify_levels() {
        assert_eq!(Attestation::classify("A"), Attestation::Full);
        assert_eq!(Attestation::classify("B"), Attestation::Partial);
        assert_eq!(Attestation::classify("C"), Attestation::Gateway);
        assert_eq!(
            Attestation::classify("D"),
            Attestation::Unknown {
                raw: "D".to_owned()
            }
        );
        assert_eq!(
            Attestation::classify(""),
            Attestation::Unknown { raw: String::new() }
        );
    }

    #[test]
    fn unknown_attest_not_coerced() {
        let tok = make_passport(
            r#"{"alg":"ES256","ppt":"shaken"}"#,
            r#"{"attest":"D"}"#,
            &[0],
        );
        let id = Identity::parse(tok.as_bytes()).expect("valid");
        assert_eq!(
            id.passport.attestation,
            Attestation::Unknown {
                raw: "D".to_owned()
            }
        );
    }

    #[test]
    fn missing_attest_is_none_with_finding() {
        let tok = make_passport(r#"{"alg":"ES256"}"#, r#"{"orig":{"tn":"1"}}"#, &[0]);
        let id = Identity::parse(tok.as_bytes()).expect("valid");
        assert_eq!(id.passport.attestation, Attestation::None);
        assert!(id.passport.findings.contains(&Finding::NoAttestClaim));
    }

    #[test]
    fn unexpected_alg_finding_no_coercion() {
        let tok = make_passport(
            r#"{"alg":"RS256","ppt":"shaken"}"#,
            r#"{"attest":"A"}"#,
            &[0],
        );
        let id = Identity::parse(tok.as_bytes()).expect("parses");
        assert!(
            id.passport
                .findings
                .iter()
                .any(|f| matches!(f, Finding::UnexpectedAlg { raw } if raw == "RS256"))
        );
    }

    #[test]
    fn alg_none_confusion_recorded_not_trusted() {
        let tok = make_passport(r#"{"alg":"none"}"#, r#"{"attest":"A"}"#, &[]);
        let id = Identity::parse(tok.as_bytes()).expect("parses");
        assert!(
            id.passport
                .findings
                .iter()
                .any(|f| matches!(f, Finding::UnexpectedAlg { raw } if raw == "none"))
        );
    }

    #[test]
    fn unexpected_ppt_finding() {
        let tok = make_passport(r#"{"alg":"ES256","ppt":"div"}"#, r#"{"attest":"A"}"#, &[0]);
        let id = Identity::parse(tok.as_bytes()).expect("parses");
        assert!(
            id.passport
                .findings
                .iter()
                .any(|f| matches!(f, Finding::UnexpectedPpt { raw } if raw == "div"))
        );
    }

    #[test]
    fn empty_input_errors() {
        assert_eq!(Identity::parse(b"").unwrap_err(), ParseError::Empty);
        assert_eq!(Identity::parse(b"   \r\n ").unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn two_segment_token_malformed() {
        let tok = format!("{}.{}", enc(b"{}"), enc(b"{}"));
        assert_eq!(
            Identity::parse(tok.as_bytes()).unwrap_err(),
            ParseError::MalformedToken
        );
    }

    #[test]
    fn non_base64url_segment_errors() {
        // '*' is not in the base64url alphabet.
        let tok = format!("{}.**bad**.{}", enc(b"{}"), enc(b""));
        assert_eq!(
            Identity::parse(tok.as_bytes()).unwrap_err(),
            ParseError::BadBase64
        );
    }

    #[test]
    fn base64url_decoding_to_non_json_errors() {
        let tok = format!("{}.{}.{}", enc(b"not json"), enc(b"{}"), enc(b""));
        assert_eq!(
            Identity::parse(tok.as_bytes()).unwrap_err(),
            ParseError::BadJson
        );
    }

    #[test]
    fn oversized_header_rejected_before_decode() {
        let big = vec![b'A'; MAX_IDENTITY + 1];
        assert_eq!(Identity::parse(&big).unwrap_err(), ParseError::TooLarge);
    }

    #[test]
    fn oversized_segment_rejected() {
        // A segment that decodes to more than MAX_SEGMENT bytes.
        let payload = vec![0u8; MAX_SEGMENT + 16];
        let tok = format!("{}.{}.{}", enc(&payload), enc(b"{}"), enc(b""));
        // Header length is under MAX_IDENTITY but the decoded segment is over cap.
        assert!(tok.len() <= MAX_IDENTITY);
        assert_eq!(
            Identity::parse(tok.as_bytes()).unwrap_err(),
            ParseError::TooLarge
        );
    }

    #[test]
    fn non_utf8_bytes_do_not_panic() {
        let bytes = [0xFF, 0xFE, 0x2E, 0x80, 0x2E, 0x00];
        // Must return a typed error, never panic.
        let _ = Identity::parse(&bytes);
    }

    #[test]
    fn base64url_single_leftover_char_rejected() {
        // 5 sextets = 4+1: the trailing single char cannot form a byte.
        assert!(decode_b64url("AAAAA").is_none());
        // 4 sextets is fine (3 bytes).
        assert!(decode_b64url("AAAA").is_some());
    }

    #[test]
    fn decode_round_trips() {
        for sample in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            &[0u8, 255, 128, 1, 2],
        ] {
            let e = enc(sample);
            assert_eq!(
                decode_b64url(&e).as_deref(),
                Some(sample),
                "roundtrip {sample:?}"
            );
        }
    }
}
