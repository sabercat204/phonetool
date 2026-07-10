//! `phonetool-cell-survey` — passive cellular survey + rogue-BTS / IMSI-catcher
//! detector.
//!
//! Decodes the broadcast / system-information channels every base station
//! transmits in the clear, builds a map of the visible cells and their advertised
//! neighbours, and flags the tells of a cell-site simulator. Receiving broadcast
//! cell info is observation-coded — clean under the operator's credo, legal on
//! the receive path near-universally — so `CellSurvey` is **passive**: it declares
//! `CapabilityClass::Passive`, holds `Transducer::RfRx`, implements the plain
//! [`Plugin`] trait, and is **never handed a gate**. The compiler guarantees it:
//! there is no `dispatch_active`, so no code path can receive a `Grant`.
//!
//! It is **advisory only** — it reports anomalies, it never answers on the air.
//! An active response to a detected rogue BTS would be an Axis-B transmit needing
//! a `&TxGrant`; no trait grants one, and it is out of scope for this layer.
//!
//! ## What is built today vs. the declared seams
//!
//! phonetool builds software ahead of hardware. This layer runs **today** over a
//! recorded **GSMTAP-over-pcap** capture, end-to-end (decode → cell map → anomaly
//! scan), with **no radio present**. Honest scope of Sprint (cell-survey):
//!
//!   * **GSM** decode is real and grounded: SI Type 3 identity (MCC/MNC/LAC/CID)
//!     and SI Type 2 neighbour ARFCNs (bit-map-0 format), transcribed from cited
//!     open-source references (libosmocore, Wireshark). Other neighbour-list
//!     formats are flagged *undecoded*, never fabricated.
//!   * **LTE / NR** decode is a **declared seam only** (`decode_lte` / `decode_nr`
//!     return `None`). Their identity lives in ASN.1-UPER SIB1 + PHY-layer sync;
//!     hand-rolling UPER from memory is the confabulation the project forbids, and
//!     Open Question 3 has not fixed a recorded LTE/NR source to prove a decoder
//!     against. The `LteCell`/`NrCell` types and the RAT dispatch exist so the
//!     decoders slot in unchanged when grounded.
//!   * The **live scan** (`LiveCaptureSource`) is the device seam behind the
//!     off-by-default `live` feature: a Tier-B `SubprocessPlugin` owning the SDR.
//!     That subprocess contract is DESIGN-ONLY and unbuilt.
//!   * Detection **thresholds are injected, not hardcoded** (Open Question 1):
//!     [`detect::Thresholds`] has no `Default`-value cutoffs; a category whose
//!     cited threshold is absent is skipped, never run against a guessed number.
//!
//! ## Example (compile-fail proof: `CellSurvey` is NOT `ActivePlugin`)
//!
//! ```compile_fail
//! use phonetool_core::ActivePlugin;
//! use phonetool_cell_survey::CellSurvey;
//! fn require_active(_p: &dyn ActivePlugin) {}
//! fn check(c: &CellSurvey) { require_active(c); }
//! ```

pub mod cellmap;
pub mod decode_gsm;
pub mod decode_lte;
pub mod decode_nr;
pub mod detect;
pub mod source;

use std::path::Path;

use phonetool_core::{CapabilityClass, Command, Event, Manifest, Plugin, PluginError, Transducer};
use serde_json::json;

use crate::detect::{Baseline, Thresholds};
use crate::source::{CaptureSource, FileCaptureSource, Rat, Segment, SourceError};

/// The passive cellular-survey plugin.
#[derive(Debug, Default)]
pub struct CellSurvey;

impl CellSurvey {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Run a survey over a recorded capture file: decode → map → detect. The
    /// baseline and thresholds default to empty/absent here (the CLI has no way
    /// to supply them yet — Open Questions 1 and 2). With an empty baseline and
    /// no injected thresholds, the survey still decodes and maps cells and emits
    /// the always-available structural flags (e.g. `DuplicateIdentity`); the
    /// baseline-relative and numeric checks stay dormant until fed cited inputs.
    fn survey_file(&self, path: &Path) -> Result<Event, PluginError> {
        let src = FileCaptureSource::new(path);
        let segments = src.segments().map_err(map_source_error)?;
        self.survey_segments(&segments, &path.display().to_string())
    }

    /// Decode a segment stream into an `Event`, applying the degenerate-case
    /// discipline. Split from I/O so it is unit-testable on synthetic segments.
    fn survey_segments(
        &self,
        segments: &[Segment],
        source_name: &str,
    ) -> Result<Event, PluginError> {
        // Per-RAT decode. A segment that does not decode is a decode miss — it is
        // counted but never fatal (one hostile transmitter cannot kill the scan).
        let mut gsm = Vec::new();
        let lte: Vec<decode_lte::LteCell> = Vec::new();
        let nr: Vec<decode_nr::NrCell> = Vec::new();
        let mut decode_misses = 0usize;

        for seg in segments {
            let decoded = match seg.rat {
                Rat::Gsm => decode_gsm::decode(seg).map(|c| {
                    gsm.push(c);
                }),
                // Seams: always a decode miss today (return None).
                Rat::Lte => decode_lte::decode(seg).map(|_| ()),
                Rat::Nr => decode_nr::decode(seg).map(|_| ()),
            };
            if decoded.is_none() {
                decode_misses += 1;
            }
        }

        let map = cellmap::build(&gsm, &lte, &nr);

        // Degenerate-case discipline: a survey that decoded zero cells is a
        // failure the operator sees, never an empty success misread as "clean".
        if map.distinct_cells() == 0 {
            return Err(PluginError::Empty(format!(
                "no cells decoded from {source_name} ({} segment(s), {decode_misses} decode miss(es))",
                segments.len()
            )));
        }

        // Baseline/thresholds are empty/absent until the operator can supply them
        // (Open Questions 1, 2). The scan still runs structural checks.
        let flags = detect::scan(&map, &Baseline::default(), &Thresholds::default());

        let summary = format!(
            "cell-survey: {} cell(s), {} observation(s), {} anomaly flag(s) from {source_name}",
            map.distinct_cells(),
            map.observation_count(),
            flags.len()
        );

        Ok(Event {
            source: "cell-survey".to_owned(),
            summary,
            data: json!({
                "verb": "survey",
                "source": source_name,
                "segments": segments.len(),
                "decode_misses": decode_misses,
                "distinct_cells": map.distinct_cells(),
                "observations": map.observation_count(),
                "cells": map.entries(),
                "neighbours": map.neighbours,
                "anomalies": flags,
                // Named so the operator sees the honest scope in the event itself.
                "rats_decoded": ["gsm"],
                "rats_seam_only": ["lte", "nr"],
            }),
        })
    }
}

/// Map a source-layer error to the plugin vocabulary. A missing/unreadable file
/// is invalid input from the operator; an I/O failure is a backend error; a live
/// source that is not wired is unsupported.
fn map_source_error(e: SourceError) -> PluginError {
    match e {
        SourceError::NotFound(p) => {
            PluginError::InvalidInput(format!("capture file not found: {p}"))
        }
        SourceError::Unreadable(m) => PluginError::InvalidInput(format!("unreadable capture: {m}")),
        SourceError::TooLarge(m) => PluginError::InvalidInput(format!("capture too large: {m}")),
        SourceError::LiveUnavailable(m) => PluginError::Unsupported(m),
    }
}

impl Plugin for CellSurvey {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "cell-survey".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::RfRx,
            capability: CapabilityClass::Passive,
            summary: "passive cellular survey + rogue-BTS detection (GSM today; LTE/NR seams)"
                .to_owned(),
        }
    }

    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError> {
        match cmd.verb.as_str() {
            "survey" => {
                let arg = cmd.arg.trim();
                if arg.is_empty() {
                    return Err(PluginError::InvalidInput(
                        "cell-survey survey requires a capture file path".to_owned(),
                    ));
                }
                self.survey_file(Path::new(arg))
            }
            other => Err(PluginError::Unsupported(format!(
                "verb '{other}' not supported (available: survey)"
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn gsm_si3_segment(arfcn: u16, cid: u16) -> Segment {
        // A minimal SI3: L3 header + cell identity + LAI (MCC 262 MNC 02 LAC 100).
        let body = [
            (cid >> 8) as u8,
            (cid & 0xff) as u8,
            0x62,
            0xf2,
            0x20, // PLMN 262-02
            0x00,
            100, // LAC 100
        ];
        let mut payload = vec![0x00, 0x06, 0x1b]; // L2 plen, PDISC_RR, SYSINFO_3
        payload.extend_from_slice(&body);
        Segment {
            rat: Rat::Gsm,
            channel: arfcn,
            signal_dbm: Some(-70),
            payload,
        }
    }

    #[test]
    fn manifest_is_passive_rfrx() {
        let m = CellSurvey::new().manifest();
        assert_eq!(m.name, "cell-survey");
        assert_eq!(m.transducer, Transducer::RfRx);
        assert_eq!(m.capability, CapabilityClass::Passive);
    }

    #[test]
    fn unsupported_verb_is_rejected() {
        let cs = CellSurvey::new();
        let err = cs
            .dispatch(&Command {
                verb: "scan".to_owned(),
                arg: "x".to_owned(),
            })
            .unwrap_err();
        assert!(matches!(err, PluginError::Unsupported(_)));
    }

    #[test]
    fn empty_arg_is_invalid_input() {
        let cs = CellSurvey::new();
        let err = cs
            .dispatch(&Command {
                verb: "survey".to_owned(),
                arg: "   ".to_owned(),
            })
            .unwrap_err();
        assert!(matches!(err, PluginError::InvalidInput(_)));
    }

    #[test]
    fn missing_file_is_invalid_input() {
        let cs = CellSurvey::new();
        let err = cs
            .dispatch(&Command {
                verb: "survey".to_owned(),
                arg: "/nonexistent/capture.pcap".to_owned(),
            })
            .unwrap_err();
        assert!(matches!(err, PluginError::InvalidInput(_)));
    }

    #[test]
    fn zero_decoded_cells_is_empty_failure() {
        let cs = CellSurvey::new();
        // A non-decodable segment (not RR): decode miss, zero cells → Empty.
        let seg = Segment {
            rat: Rat::Gsm,
            channel: 1,
            signal_dbm: None,
            payload: vec![0x00, 0x05, 0x00], // PDISC 5, not RR
        };
        let err = cs.survey_segments(&[seg], "test").unwrap_err();
        assert!(matches!(err, PluginError::Empty(_)));
    }

    #[test]
    fn one_decoded_cell_is_ok_event() {
        let cs = CellSurvey::new();
        let event = cs
            .survey_segments(&[gsm_si3_segment(10, 0x1234)], "test")
            .expect("one cell decodes");
        assert_eq!(event.source, "cell-survey");
        assert_eq!(event.data["distinct_cells"], 1);
        assert_eq!(event.data["rats_decoded"][0], "gsm");
    }

    #[test]
    fn lte_nr_segments_are_decode_misses_today() {
        let cs = CellSurvey::new();
        let lte = Segment {
            rat: Rat::Lte,
            channel: 0,
            signal_dbm: None,
            payload: vec![0xde, 0xad],
        };
        // LTE-only stream decodes nothing → Empty (honest: seam not built).
        let err = cs.survey_segments(&[lte], "test").unwrap_err();
        assert!(matches!(err, PluginError::Empty(_)));
    }

    #[test]
    fn event_carries_no_raw_samples() {
        // The event data must be bounded by cell count, not sample count: assert
        // no giant byte array leaked into it.
        let cs = CellSurvey::new();
        let event = cs
            .survey_segments(&[gsm_si3_segment(10, 1)], "test")
            .expect("ok");
        let serialized = serde_json::to_string(&event.data).expect("serialize");
        // The payload bytes themselves never appear in the event.
        assert!(!serialized.contains("payload"));
    }
}
