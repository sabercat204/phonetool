//! Untrusted-artifact ingest boundary — the crate's front door.
//!
//! Threat note: the whole bundle is adversary-supplied. A scam caller who learns
//! the operator triages their footprint has every incentive to hand back a
//! bundle crafted to (a) make the tool fetch a URL (SSRF / a beacon that tells
//! them the victim is investigating), or (b) exhaust memory with a giant
//! transcript / IOC flood. This module answers only (b) and the parse-panic
//! surface; (a) is answered by the whole crate never dereferencing an artifact.
//!
//! Every value here is opaque data. `parse` is total over arbitrary bytes: a
//! `&str` arg that is empty, oversize, or not well-formed JSON becomes a typed
//! [`IngestError`], never a panic. The size caps are **engineering bounds chosen
//! for safety, not claims about any real scam campaign** — their values are
//! documented as tunable, not asserted as facts.

use serde::Deserialize;

/// Maximum accepted size of the whole `arg` bundle, in bytes. An engineering cap
/// against an unbounded allocation, not a protocol constant — tunable.
pub const MAX_BAIT_BYTES: usize = 256 * 1024;

/// Maximum accepted size of any single string field, in bytes. Bounds a hostile
/// megabyte-transcript before it reaches extraction. Engineering cap, tunable.
pub const MAX_FIELD_BYTES: usize = 64 * 1024;

/// Maximum number of indicators a single bundle may yield. Bounds the correlation
/// loop against an IOC flood (e.g. a transcript packed with fake numbers).
/// Engineering cap, tunable — enforced in [`crate::extract`], surfaced here as the
/// shared contract.
pub const MAX_IOCS: usize = 512;

/// The untrusted, deserialized input bundle. Every field is optional: an operator
/// supplies whatever artifacts they have. All values are opaque data — a `url`
/// is a string to normalize and compare, **never** a request target.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawBait {
    /// A phone number the caller used or claimed (any human format).
    #[serde(default)]
    pub phone: Option<String>,
    /// A claimed identity ("Officer Smith", "Microsoft Support").
    #[serde(default)]
    pub identity: Option<String>,
    /// A claimed agency/organization ("IRS", "Social Security Administration").
    #[serde(default)]
    pub agency_claim: Option<String>,
    /// Callback / payment / phishing URLs cited by the caller.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Crypto wallet addresses (opaque strings; no per-chain validation).
    #[serde(default)]
    pub wallets: Vec<String>,
    /// Email addresses.
    #[serde(default)]
    pub emails: Vec<String>,
    /// Gift-card rails demanded ("Apple", "Google Play", "Target").
    #[serde(default)]
    pub gift_card_rails: Vec<String>,
    /// Free-text transcript of the call (typed or pasted by the operator).
    #[serde(default)]
    pub transcript: Option<String>,
    /// Free-text email body.
    #[serde(default)]
    pub email_body: Option<String>,
    /// A path to a `CaptureRef { kind: CallAudio }` already on the timeline. Carried
    /// as footprint provenance only — the recording is NEVER opened or decoded here
    /// (audio→text is a future device-seam capability).
    #[serde(default)]
    pub source_capture: Option<String>,
}

/// Why a bundle was rejected at the ingest boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IngestError {
    /// The `arg` was empty or whitespace-only.
    #[error("empty bait bundle")]
    Empty,
    /// The `arg` did not deserialize into a well-formed bundle.
    #[error("malformed bait bundle: {0}")]
    Malformed(String),
    /// The `arg`, or a single field, exceeded its size cap.
    #[error("bait bundle too large: {0}")]
    TooLarge(String),
}

impl RawBait {
    /// Enforce the per-field size cap over every string field. A field longer than
    /// [`MAX_FIELD_BYTES`] is a boundary rejection, not a truncation — the operator
    /// should know a field was refused rather than have it silently clipped.
    fn check_field_bounds(&self) -> Result<(), IngestError> {
        let too_big = |name: &str, s: &str| -> Result<(), IngestError> {
            if s.len() > MAX_FIELD_BYTES {
                Err(IngestError::TooLarge(format!(
                    "field '{name}' is {} bytes (cap {MAX_FIELD_BYTES})",
                    s.len()
                )))
            } else {
                Ok(())
            }
        };

        for (name, opt) in [
            ("phone", &self.phone),
            ("identity", &self.identity),
            ("agency_claim", &self.agency_claim),
            ("transcript", &self.transcript),
            ("email_body", &self.email_body),
            ("source_capture", &self.source_capture),
        ] {
            if let Some(s) = opt {
                too_big(name, s)?;
            }
        }
        for (name, list) in [
            ("urls", &self.urls),
            ("wallets", &self.wallets),
            ("emails", &self.emails),
            ("gift_card_rails", &self.gift_card_rails),
        ] {
            for s in list {
                too_big(name, s)?;
            }
        }
        Ok(())
    }
}

/// Parse and bound the untrusted `arg` into a [`RawBait`].
///
/// Order matters for the threat model: the whole-`arg` size cap is checked
/// **before** deserialization so a hostile megabyte payload cannot force serde to
/// allocate it; per-field caps are checked after. Nothing in the bundle is ever
/// fetched, resolved, or opened — a URL is data.
///
/// # Errors
/// - [`IngestError::Empty`] — the arg is empty or whitespace-only.
/// - [`IngestError::TooLarge`] — the arg or a field exceeds its cap.
/// - [`IngestError::Malformed`] — the arg is not a well-formed bundle.
pub fn parse(arg: &str) -> Result<RawBait, IngestError> {
    if arg.trim().is_empty() {
        return Err(IngestError::Empty);
    }
    if arg.len() > MAX_BAIT_BYTES {
        return Err(IngestError::TooLarge(format!(
            "bundle is {} bytes (cap {MAX_BAIT_BYTES})",
            arg.len()
        )));
    }

    let bait: RawBait =
        serde_json::from_str(arg).map_err(|e| IngestError::Malformed(e.to_string()))?;
    bait.check_field_bounds()?;
    Ok(bait)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_whitespace_are_empty() {
        assert_eq!(parse(""), Err(IngestError::Empty));
        assert_eq!(parse("   \n\t "), Err(IngestError::Empty));
    }

    #[test]
    fn malformed_json_is_malformed_not_panic() {
        assert!(matches!(parse("{not json"), Err(IngestError::Malformed(_))));
        assert!(matches!(parse("[1,2,3]"), Err(IngestError::Malformed(_))));
    }

    #[test]
    fn unknown_field_is_rejected() {
        // deny_unknown_fields: a typo'd or injected field is a malformed bundle,
        // not silently ignored.
        assert!(matches!(
            parse(r#"{"phon":"+15125550100"}"#),
            Err(IngestError::Malformed(_))
        ));
    }

    #[test]
    fn oversize_arg_rejected_before_parse() {
        let giant = format!(r#"{{"transcript":"{}"}}"#, "a".repeat(MAX_BAIT_BYTES));
        assert!(matches!(parse(&giant), Err(IngestError::TooLarge(_))));
    }

    #[test]
    fn oversize_field_rejected() {
        // Under the arg cap, over the field cap.
        let field = "a".repeat(MAX_FIELD_BYTES + 1);
        let arg = format!(r#"{{"transcript":"{field}"}}"#);
        assert!(arg.len() <= MAX_BAIT_BYTES);
        assert!(matches!(parse(&arg), Err(IngestError::TooLarge(_))));
    }

    #[test]
    fn well_formed_bundle_parses() {
        let bait = parse(
            r#"{"phone":"+1 (512) 555-0100","urls":["http://evil.example"],
                "wallets":["bc1qXYZ"],"transcript":"pay in gift cards"}"#,
        )
        .expect("valid bundle");
        assert_eq!(bait.phone.as_deref(), Some("+1 (512) 555-0100"));
        assert_eq!(bait.urls.len(), 1);
        assert_eq!(bait.wallets, vec!["bc1qXYZ".to_owned()]);
    }

    #[test]
    fn empty_object_parses_to_all_none() {
        let bait = parse("{}").expect("empty object is well-formed");
        assert!(bait.phone.is_none());
        assert!(bait.urls.is_empty());
    }

    #[test]
    fn a_url_only_bundle_parses_but_nothing_is_fetched() {
        // Parsing a bundle whose only field is a URL must not contact it. This test
        // asserts parse succeeds and returns the URL as opaque data; the "never
        // fetched" property is proven end-to-end in tests/ingest.rs.
        let bait = parse(r#"{"urls":["http://127.0.0.1:1/beacon"]}"#).expect("valid");
        assert_eq!(bait.urls, vec!["http://127.0.0.1:1/beacon".to_owned()]);
    }
}
