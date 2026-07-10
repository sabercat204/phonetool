//! `phonetool-attest` — passive STIR/SHAKEN attestation inspection.
//!
//! Answers one question about a call: *what does it claim about its own origin,
//! and (online) does that claim cryptographically hold?* It parses the SIP
//! `Identity` header (RFC 8224) and the PASSporT inside it (RFC 8225), reports
//! the attestation level (A/B/C, ATIS-1000074), the claims, and a verification
//! verdict.
//!
//! **Passive, never gated.** Reading what a call asserts about itself is
//! observation/knowledge, on neither authorization axis — so `AttestInspect`
//! implements the plain [`Plugin`] trait and never receives a `Grant`, exactly
//! like numintel. The compiler guarantees it: there is no `dispatch_active`, so
//! no code path can be handed a gate token.
//!
//! **Offline default / online feature.** The default build performs total
//! STRUCTURAL inspection only and links **zero egress dependencies**. The
//! `online` feature (off by default) would add the `x5u` certificate fetch +
//! ES256 signature verification — network egress and an *attacker-influenced*
//! request. The `x5u` fetch leaks nothing about the operator (it retrieves a
//! public certificate the caller named), but it is still network I/O and an
//! SSRF surface, so it is fenced behind the feature — NOT "no network code".
//!
//! ## Online status (Sprint 11): declared seam, not yet built
//!
//! The `verify` module is a *declared seam only*. It is blocked on three
//! operator Open Questions the spec flags as prerequisites (see
//! `specs/attest/design.md` "Known architectural gap"):
//!   1. **Trust-anchor provisioning** — bundled snapshot vs. operator-provided
//!      file vs. online-only. Offline `Verified` can only ever mean "valid under
//!      a possibly-stale anchor, no revocation check".
//!   2. **`x5u` host allowlist vs. https-only + caps** — the SSRF containment
//!      policy.
//!   3. **Pure-Rust ES256 + X.509 crate choice** preserving `unsafe_code =
//!      forbid` and the static-musl build.
//! Until those are decided, enabling `online` changes only dependency wiring;
//! the verdict stays [`VerificationStatus::StructuralOnly`]. This is deliberate:
//! shipping a half-decided trust model would be worse than shipping none.
//!
//! ## Example (compile-fail proof: `AttestInspect` is NOT `ActivePlugin`)
//!
//! ```compile_fail
//! use phonetool_core::ActivePlugin;
//! use phonetool_attest::AttestInspect;
//! fn require_active(_p: &dyn ActivePlugin) {}
//! fn check(a: &AttestInspect) { require_active(a); }
//! ```

pub mod passport;
pub mod sipmsg;

use std::path::Path;

use phonetool_core::{CapabilityClass, Command, Event, Manifest, Plugin, PluginError, Transducer};
use serde_json::json;

use crate::passport::{Attestation, Finding, Identity, ParseError};

/// Whether — and how — the PASSporT signature was verified.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum VerificationStatus {
    /// Offline build (or online with no verification performed): the structure
    /// was parsed but the signature was NOT cryptographically checked. This is
    /// a status, never a disguised pass.
    StructuralOnly,
    /// Online: the ES256 signature validated against a trusted certificate.
    Verified,
    /// Online: verification was attempted and failed (bad signature, fetch
    /// failure, missing/invalid trust anchor, non-https `x5u`). A failure is
    /// never downgraded to `StructuralOnly`.
    Failed { reason: String },
}

/// The structured inspection result, serialized into the `Event` `data`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttestReport {
    /// The attestation level the call claims.
    pub attestation: Attestation,
    /// Parsed JOSE header (signing metadata), when a PASSporT was present.
    pub jose: Option<passport::Jose>,
    /// Parsed claims, when a PASSporT was present.
    pub claims: Option<passport::Claims>,
    /// The verification verdict.
    pub verification: VerificationStatus,
    /// Structural findings (unsigned call, unexpected alg/ppt, no attest claim).
    pub findings: Vec<Finding>,
}

/// Where an `Identity` header came from. The inline and file variants run
/// TODAY with no hardware; `LiveTap` is a declared seam for a future live
/// `Ip`/wireline capture and is intentionally unconstructed here.
#[derive(Debug, Clone)]
pub enum Source {
    /// An `Identity` header or a full SIP message supplied inline.
    Inline(String),
    /// A path to a file (or recorded capture) to read the SIP message from.
    File(std::path::PathBuf),
    /// FUTURE device seam: `Identity` headers off a live `Ip`/wireline tap.
    /// Unconstructed in Sprint 11 — the parser is ready; the tap lands with the
    /// capture/RF hardware layers. Not `dead_code`: it documents the seam and
    /// is matched exhaustively below.
    LiveTap,
}

/// The passive STIR/SHAKEN attestation-inspection plugin.
#[derive(Debug, Default)]
pub struct AttestInspect;

impl AttestInspect {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Resolve the command arg into a source. A leading `@` selects a file
    /// path; anything else is inline content.
    fn select_source(arg: &str) -> Source {
        if let Some(path) = arg.strip_prefix('@') {
            Source::File(Path::new(path).to_path_buf())
        } else {
            Source::Inline(arg.to_owned())
        }
    }

    /// Read the raw bytes to inspect from a source.
    fn read_source(source: &Source) -> Result<Vec<u8>, PluginError> {
        match source {
            Source::Inline(s) => Ok(s.clone().into_bytes()),
            Source::File(path) => std::fs::read(path)
                .map_err(|e| PluginError::Backend(format!("cannot read {}: {e}", path.display()))),
            Source::LiveTap => Err(PluginError::Unsupported(
                "live-tap capture source not yet wired (awaits the capture/RF hardware layer)"
                    .to_owned(),
            )),
        }
    }

    /// Inspect raw input bytes, applying the degenerate-case discipline.
    fn inspect_bytes(&self, raw: &[u8]) -> Result<Event, PluginError> {
        // Empty input: nothing to inspect.
        if raw.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(PluginError::Empty(
                "no input to inspect for attestation".to_owned(),
            ));
        }

        // Is this a bare Identity-header/PASSporT token, or a SIP message?
        // Try the header extractor first; if the input looks like SIP, use its
        // Identity headers; otherwise treat the whole input as a single token.
        let headers = sipmsg::extract_identity_headers(raw);
        let is_sip = sipmsg::looks_like_sip(raw);

        if is_sip && headers.is_empty() {
            // A SIP message with no Identity header → reportable unsigned call.
            return Ok(self.report_event(&AttestReport {
                attestation: Attestation::None,
                jose: None,
                claims: None,
                verification: VerificationStatus::StructuralOnly,
                findings: vec![Finding::NoIdentityHeader],
            }));
        }

        // Choose the token: the first extracted Identity header, or the whole
        // input as a bare token (inline PASSporT with no SIP framing).
        let token: Vec<u8> = match headers.first() {
            Some(h) => h.clone().into_bytes(),
            None => raw.to_vec(),
        };

        match Identity::parse(&token) {
            Ok(id) => {
                let p = id.passport;
                Ok(self.report_event(&AttestReport {
                    attestation: p.attestation,
                    jose: Some(p.jose),
                    claims: Some(p.claims),
                    // Offline: structural only. The online verdict would be
                    // computed by the (unbuilt) verify seam.
                    verification: VerificationStatus::StructuralOnly,
                    findings: p.findings,
                }))
            }
            Err(ParseError::Empty) => Err(PluginError::Empty(
                "no input to inspect for attestation".to_owned(),
            )),
            Err(e @ (ParseError::MalformedToken | ParseError::BadBase64 | ParseError::BadJson)) => {
                // Non-empty input that is neither a parseable token nor a SIP
                // message with an Identity header → invalid input.
                if is_sip {
                    // SIP-shaped but the Identity header we found is malformed:
                    // still invalid input (a broken token is not a clean call).
                    Err(PluginError::InvalidInput(format!(
                        "Identity header present but its PASSporT is malformed: {e}"
                    )))
                } else {
                    Err(PluginError::InvalidInput(format!(
                        "input is neither a SIP message nor a parseable PASSporT: {e}"
                    )))
                }
            }
            Err(e @ ParseError::TooLarge) => Err(PluginError::InvalidInput(e.to_string())),
        }
    }

    /// Assemble the `Event` from a report.
    fn report_event(&self, report: &AttestReport) -> Event {
        let summary = match (&report.attestation, report.findings.first()) {
            (Attestation::Full, _) => "attestation A (Full) — structural only".to_owned(),
            (Attestation::Partial, _) => "attestation B (Partial) — structural only".to_owned(),
            (Attestation::Gateway, _) => "attestation C (Gateway) — structural only".to_owned(),
            (Attestation::Unknown { raw }, _) => {
                format!("unknown attestation '{raw}' — structural only")
            }
            (Attestation::None, Some(Finding::NoIdentityHeader)) => {
                "unsigned call — no Identity header".to_owned()
            }
            (Attestation::None, _) => "no attestation claim in PASSporT".to_owned(),
        };

        Event {
            source: "attest".to_owned(),
            summary,
            data: json!({
                "verb": "inspect",
                "attestation": report.attestation,
                "jose": report.jose,
                "claims": report.claims,
                "verification": report.verification,
                "findings": report.findings,
            }),
        }
    }
}

impl Plugin for AttestInspect {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "attest".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::Ip,
            capability: CapabilityClass::Passive,
            summary: "STIR/SHAKEN attestation inspection (PASSporT/Identity, structural)"
                .to_owned(),
        }
    }

    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError> {
        match cmd.verb.as_str() {
            "inspect" => {
                let arg = cmd.arg.trim();
                if arg.is_empty() {
                    return Err(PluginError::Empty(
                        "attest inspect requires an Identity header, @file, or SIP message"
                            .to_owned(),
                    ));
                }
                let source = Self::select_source(arg);
                let raw = Self::read_source(&source)?;
                self.inspect_bytes(&raw)
            }
            other => Err(PluginError::Unsupported(format!(
                "verb '{other}' not supported (available: inspect)"
            ))),
        }
    }
}
