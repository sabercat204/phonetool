//! `phonetool-ss7` — passive, offline SS7/Diameter signalling analyzer.
//!
//! Decodes a **supplied** SS7/Diameter capture (a `.pcap` of SIGTRAN/Diameter over
//! SCTP, or a hex PDU dump) and flags the privacy-sensitive operations that make
//! SS7 infamous: location-disclosure (ATI, SRI-SM, SRI, PSI; Diameter ULR, IDR) and
//! intercept-enabling (MAP sendAuthenticationInfo/updateLocation; Diameter AIR).
//!
//! **Passive, never gated.** Decoding a capture the operator already holds is
//! observation — it transmits nothing — so `Ss7Analyzer` implements the plain
//! [`Plugin`] trait and is handed no `Grant`, exactly like numintel. This is the
//! load-bearing point of the two-trait split: the same crate that can *read* an
//! SRI-SM PDU has, by construction, no code path to *originate* one. Origination
//! lives in a different trait (`ActivePlugin`) that cannot be dispatched without a
//! gate-minted `Grant` **and** — the design records — a lawful signalling link.
//! That injector is out of scope here (Req 9); a compile-fail doctest proves this
//! analyzer is not `ActivePlugin`.
//!
//! **Flag presence, not intent.** The analyzer reports that a flagged operation is
//! *present in the capture*. It does not assert the operation was malicious,
//! unauthorized, or attributable — a ULR from a subscriber's own home network is
//! routine; a cross-boundary ATI is the abuse case, and the bytes cannot tell them
//! apart. Fabricating that accusation is exactly what this does not do.
//!
//! **Offline default.** The analysis path (hex + pcap) links zero egress
//! dependencies (`std` only). A live SIGTRAN/Diameter link is a carrier/hardware-
//! gated seam behind the off-by-default `live` feature (unbuilt) — so the offline
//! guarantee is "zero egress *dependencies* on the analysis path", not "no network
//! code" once that seam exists.
//!
//! ## Example (compile-fail proof: `Ss7Analyzer` is NOT `ActivePlugin`)
//!
//! ```compile_fail
//! use phonetool_core::ActivePlugin;
//! use phonetool_ss7::Ss7Analyzer;
//! fn require_active(_p: &dyn ActivePlugin) {}
//! fn check(a: &Ss7Analyzer) { require_active(a); }
//! ```

pub mod ber;
pub mod classify;
pub mod diameter;
pub mod source;
pub mod ss7;

use std::path::Path;

use phonetool_core::{CapabilityClass, Command, Event, Manifest, Plugin, PluginError, Transducer};
use serde::Serialize;
use serde_json::json;

use crate::classify::DisclosureClass;
use crate::source::{CaptureSource, HexDumpSource, PcapSource, SourceError};

/// The protocol family a finding decoded as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// SS7 (SCCP/TCAP/MAP).
    Ss7,
    /// Diameter (S6a).
    Diameter,
    /// Neither decoder recognized the PDU.
    Unknown,
}

/// The decoded outcome for one PDU.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Which protocol family decoded (or `Unknown`).
    pub protocol: Protocol,
    /// The named operation/command, when resolved (`"anyTimeInterrogation"`,
    /// `"Update-Location"`, `"unknown(200)"`, or absent if the PDU did not decode
    /// to an operation).
    pub operation: Option<String>,
    /// The privacy-sensitivity classification.
    pub disclosure_class: DisclosureClass,
    /// The subscriber-addressing the operation touched, when extractable (SCCP GT
    /// digits / SSN, or a Diameter User-Name/IMSI). Absent, never fabricated.
    pub addressing: Option<serde_json::Value>,
    /// Whether the PDU decoded far enough to be meaningful. `false` = a decode
    /// failure recorded for this PDU (the run continues).
    pub decoded: bool,
}

/// The passive SS7/Diameter capture analyzer.
#[derive(Debug, Default)]
pub struct Ss7Analyzer;

impl Ss7Analyzer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Resolve the command arg into a capture source. A `@`-prefixed arg (or a path
    /// ending in a pcap extension) selects a file; a leading `hex:` selects an
    /// inline hex dump; otherwise the arg is treated as a path to open (pcap if it
    /// parses as one, else read as a hex dump).
    fn analyze(&self, arg: &str) -> Result<Event, PluginError> {
        let arg = arg.trim();
        if arg.is_empty() {
            return Err(PluginError::InvalidInput(
                "ss7 analyze requires a capture source (path to .pcap or hex dump, or hex:<...>)"
                    .to_owned(),
            ));
        }

        let pdus = Self::load_pdus(arg)?;
        self.analyze_pdus(&pdus)
    }

    /// Load PDUs from the resolved source, mapping source errors to the trait-level
    /// `PluginError` (Req 3.3: missing/blank/bad-hex/bad-container → InvalidInput;
    /// genuine mid-read I/O → Backend).
    fn load_pdus(arg: &str) -> Result<Vec<Vec<u8>>, PluginError> {
        // Inline hex dump: `hex:<tokens>`.
        if let Some(hex) = arg.strip_prefix("hex:") {
            return HexDumpSource::new(hex).pdus().map_err(map_source_error);
        }

        // A path. Decide pcap vs hex-dump-file by extension; fall back to hex.
        let path = Path::new(arg);
        let is_pcap = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("pcap") || e.eq_ignore_ascii_case("pcapng"));

        if is_pcap {
            PcapSource::new(path).pdus().map_err(map_source_error)
        } else {
            // Read the file as a hex dump. A missing file is InvalidInput (Req 3.3).
            let text = std::fs::read_to_string(path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    PluginError::InvalidInput(format!("source not found: {arg}"))
                } else {
                    PluginError::Backend(format!("cannot read {arg}: {e}"))
                }
            })?;
            HexDumpSource::new(&text).pdus().map_err(map_source_error)
        }
    }

    /// Decode every PDU, classify, and apply the degenerate-case discipline.
    fn analyze_pdus(&self, pdus: &[Vec<u8>]) -> Result<Event, PluginError> {
        if pdus.is_empty() {
            // Empty-but-readable source: nothing to analyze is a bad input.
            return Err(PluginError::InvalidInput(
                "capture source held no PDUs".to_owned(),
            ));
        }

        let findings: Vec<Finding> = pdus.iter().map(|p| dispatch_pdu(p)).collect();
        let total = findings.len();
        let decoded = findings.iter().filter(|f| f.decoded).count();
        let flagged = findings
            .iter()
            .filter(|f| f.disclosure_class.is_flagged())
            .count();

        // Degenerate discipline: nothing decoded → the capture taught us nothing.
        if decoded == 0 {
            return Err(PluginError::Empty(format!(
                "no PDU decoded from the capture ({total} present, all undecodable)"
            )));
        }

        // A clean-but-benign capture (flagged == 0) is a real, reportable result.
        let flagged_ops: Vec<String> = findings
            .iter()
            .filter(|f| f.disclosure_class.is_flagged())
            .filter_map(|f| f.operation.clone())
            .collect();
        let summary = if flagged == 0 {
            format!("{decoded}/{total} PDU decoded — no location-disclosure traffic")
        } else {
            format!(
                "{flagged} flagged operation(s) in {decoded}/{total} decoded PDU: {}",
                flagged_ops.join(", ")
            )
        };

        Ok(Event {
            source: "ss7".to_owned(),
            summary,
            data: json!({
                "verb": "analyze",
                "total": total,
                "decoded": decoded,
                "flagged": flagged,
                "findings": findings,
            }),
        })
    }
}

/// Decode one PDU: try SS7 first, then Diameter; a PDU neither recognizes is a
/// `Finding { protocol: Unknown, decoded: false }`. A recognized-but-malformed PDU
/// is also `decoded: false`, never a run abort (Req 2.4).
fn dispatch_pdu(pdu: &[u8]) -> Finding {
    match ss7::decode(pdu) {
        Ok(d) => {
            let op = d.operation.as_ref();
            let disclosure_class = op.map_or(DisclosureClass::Unknown, classify::classify_map);
            let operation = op.map(op_name_map);
            // A finding "decoded" if we reached at least the TCAP layer.
            let decoded = d.tcap_type.is_some();
            let addressing = d
                .sccp
                .as_ref()
                .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null));
            return Finding {
                protocol: Protocol::Ss7,
                operation,
                disclosure_class,
                addressing,
                decoded,
            };
        }
        Err(ss7::Ss7DecodeError::Tcap(_)) => {
            // Recognized as SS7 but malformed inside → partial, decoded:false.
            return Finding {
                protocol: Protocol::Ss7,
                operation: None,
                disclosure_class: DisclosureClass::Unknown,
                addressing: None,
                decoded: false,
            };
        }
        Err(ss7::Ss7DecodeError::NotSs7) => { /* fall through to Diameter */ }
    }

    match diameter::decode(pdu) {
        Ok(d) => {
            let disclosure_class = classify::classify_diameter(&d.command);
            let operation = Some(op_name_diameter(&d.command, d.header.request));
            let addressing = d.user_name.as_ref().map(|imsi| json!({ "imsi": imsi }));
            Finding {
                protocol: Protocol::Diameter,
                operation,
                disclosure_class,
                addressing,
                decoded: true,
            }
        }
        Err(diameter::DiameterDecodeError::NotDiameter) => Finding {
            protocol: Protocol::Unknown,
            operation: None,
            disclosure_class: DisclosureClass::Unknown,
            addressing: None,
            decoded: false,
        },
    }
}

fn op_name_map(op: &ss7::MapOp) -> String {
    match op {
        ss7::MapOp::Named(n) => (*n).to_owned(),
        ss7::MapOp::Unknown(c) => format!("unknown({c})"),
    }
}

fn op_name_diameter(cmd: &diameter::S6aCommand, request: bool) -> String {
    let suffix = if request { "Request" } else { "Answer" };
    match cmd {
        diameter::S6aCommand::Named(n) => format!("{n}-{suffix}"),
        diameter::S6aCommand::Unknown(c) => format!("unknown({c})-{suffix}"),
    }
}

/// Map a source error to the trait-level `PluginError` (Req 3.3 / design error
/// handling): boundary-validation failures → `InvalidInput`; a genuine mid-read I/O
/// failure → `Backend`.
fn map_source_error(e: SourceError) -> PluginError {
    match e {
        SourceError::NotFound(m) => PluginError::InvalidInput(format!("not found: {m}")),
        SourceError::Empty(m) => PluginError::InvalidInput(format!("empty source: {m}")),
        SourceError::BadHex(m) => PluginError::InvalidInput(format!("bad hex: {m}")),
        SourceError::BadContainer(m) => PluginError::InvalidInput(format!("bad container: {m}")),
        SourceError::LiveUnavailable(m) => PluginError::Unsupported(m),
        SourceError::Unreadable(m) => PluginError::Backend(format!("I/O failure: {m}")),
    }
}

impl Plugin for Ss7Analyzer {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "ss7".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::Ip,
            capability: CapabilityClass::Passive,
            summary: "SS7/Diameter signalling analysis — SCCP/TCAP/MAP + S6a decode, \
                      location-disclosure flagging (passive, offline)"
                .to_owned(),
        }
    }

    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError> {
        match cmd.verb.as_str() {
            "analyze" => self.analyze(&cmd.arg),
            other => Err(PluginError::Unsupported(format!(
                "verb '{other}' not supported (available: analyze)"
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn analyzer() -> Ss7Analyzer {
        Ss7Analyzer::new()
    }

    fn cmd(verb: &str, arg: &str) -> Command {
        Command {
            verb: verb.to_owned(),
            arg: arg.to_owned(),
        }
    }

    /// Encode bytes to lowercase hex (test helper).
    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Build a TCAP Begin carrying one Invoke of the given local opcode, correctly
    /// length-prefixed, and return it as a `hex:`-prefixed analyze arg.
    fn tcap_invoke_hex(opcode: u8) -> String {
        let invoke_body = vec![0x02, 0x01, 0x01, 0x02, 0x01, opcode];
        let mut invoke = vec![0xa1, invoke_body.len() as u8];
        invoke.extend_from_slice(&invoke_body);
        let mut portion = vec![0x6c, invoke.len() as u8];
        portion.extend_from_slice(&invoke);
        let mut body = vec![0x48, 0x01, 0x01];
        body.extend_from_slice(&portion);
        let mut msg = vec![0x62, body.len() as u8];
        msg.extend_from_slice(&body);
        format!("hex:{}", to_hex(&msg))
    }

    /// A TCAP Begin carrying an ATI Invoke (opcode 71).
    fn ati_hex() -> String {
        tcap_invoke_hex(71)
    }

    #[test]
    fn unsupported_verb() {
        assert!(matches!(
            analyzer().dispatch(&cmd("decode", "hex:6200")),
            Err(PluginError::Unsupported(_))
        ));
    }

    #[test]
    fn empty_arg_invalid() {
        assert!(matches!(
            analyzer().dispatch(&cmd("analyze", "  ")),
            Err(PluginError::InvalidInput(_))
        ));
    }

    #[test]
    fn ati_flagged_location_disclosure() {
        let out = analyzer()
            .dispatch(&cmd("analyze", &ati_hex()))
            .expect("valid");
        assert_eq!(out.source, "ss7");
        assert_eq!(out.data["flagged"], json!(1));
        assert!(out.summary.contains("anyTimeInterrogation"));
    }

    #[test]
    fn all_undecodable_is_empty() {
        // Two PDUs that decode as neither SS7 nor Diameter.
        let out = analyzer().dispatch(&cmd("analyze", "hex:000102\n0a0b0c"));
        assert!(matches!(out, Err(PluginError::Empty(_))));
    }

    #[test]
    fn clean_but_benign_is_ok() {
        // A checkIMEI Invoke (opcode 43) — decodes, not flagged.
        let out = analyzer()
            .dispatch(&cmd("analyze", &tcap_invoke_hex(43)))
            .expect("valid");
        assert_eq!(out.data["flagged"], json!(0));
        assert!(out.summary.contains("no location-disclosure"));
    }

    #[test]
    fn missing_file_is_invalid_input() {
        let out = analyzer().dispatch(&cmd("analyze", "/nonexistent/path/x.pcap"));
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    }
}
