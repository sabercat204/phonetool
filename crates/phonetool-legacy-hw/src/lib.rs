//! `phonetool-legacy-hw` — the copper/lineman physical-I/O layer, passive half.
//!
//! Four observation/rendering verbs over supplied audio and traces, no hardware:
//!   - `decode` — DTMF/MF/2600 tones from a WAV (Goertzel, confident-match-or-nothing).
//!   - `cid` — Bell-202 Caller-ID FSK from a WAV (the decoded number is an
//!     **observation**, never a verified identity — Caller-ID is trivially spoofed).
//!   - `sense` — loop-current/line-voltage/ring/hook state from a recorded trace.
//!   - `synth` — DTMF/MF/2600-SF tones rendered to a WAV file (**inert** — writes
//!     samples only; there is no code path to a physical line).
//!
//! **Passive by construction — no gate.** `LineHw` implements only the plain
//! [`Plugin`] trait, declares `Wireline`/`Passive`, and never sees a `Grant`/
//! `TxGrant`/`WireGrant`. A compile-fail doctest proves it is not `ActivePlugin`.
//!
//! **Active injection is out of scope (the known gap).** Driving a live tip-and-ring
//! pair — loop seizure, tone/ring injection — fits neither the cyber (Axis A) nor
//! the spectrum (Axis B) authority. Sprint 17 landed the **third gate axis** for it:
//! [`WireGrant`](phonetool_core::WireGrant) via `Gate::request_wire`, consumed by the
//! new [`WirePlugin`](phonetool_core::WirePlugin) trait. But **no injector is built**:
//! it additionally requires the orthogonal hardware-safety interlock (line voltage is
//! a physical hazard) and the FFI-quarantine hardware crate, neither of which exists.
//! This crate has **no code path** that drives a pair (Req 7.1).
//!
//! **Synthesis is an inert payload.** The default binary *contains* the tone-
//! generation code a future injector would use as its payload — but that code is
//! line-inert (it can only write samples to a buffer/file), the copper analogue of
//! sip's always-compiled-but-gated active path.
//!
//! ## Example (compile-fail proof: `LineHw` is NOT `ActivePlugin`)
//!
//! ```compile_fail
//! use phonetool_core::ActivePlugin;
//! use phonetool_legacy_hw::LineHw;
//! fn require_active(_p: &dyn ActivePlugin) {}
//! fn check(a: &LineHw) { require_active(a); }
//! ```

pub mod dsp;
pub mod sense;
pub mod source;

use std::path::PathBuf;

use phonetool_core::{CapabilityClass, Command, Event, Manifest, Plugin, PluginError, Transducer};
use serde_json::json;

use crate::source::{LineSource, RecordedSenseSource, SourceError, WavFileSource};

/// Configuration for a render (synth) — WAV output path and tone timing.
#[derive(Debug, Clone)]
pub struct LineConfig {
    /// Where `synth` writes its rendered WAV.
    pub out_path: PathBuf,
    /// Output sample rate for synthesis (Hz).
    pub sample_rate: u32,
    /// Per-symbol tone duration (ms) for DTMF synthesis.
    pub tone_ms: f32,
    /// Inter-symbol gap (ms) for DTMF synthesis.
    pub gap_ms: f32,
    /// Sample rate assumed for a recorded sense trace (Hz).
    pub sense_rate: u32,
}

impl Default for LineConfig {
    fn default() -> Self {
        Self {
            out_path: PathBuf::from("line-synth.wav"),
            sample_rate: 8000,
            tone_ms: 70.0,
            gap_ms: 50.0,
            sense_rate: 8000,
        }
    }
}

/// The passive copper-layer plugin. Holds only render configuration — never a token.
pub struct LineHw {
    config: LineConfig,
}

impl Default for LineHw {
    fn default() -> Self {
        Self::new()
    }
}

impl LineHw {
    /// Build with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: LineConfig::default(),
        }
    }

    /// Build with explicit configuration (synth output path, timings).
    #[must_use]
    pub fn with_config(config: LineConfig) -> Self {
        Self { config }
    }

    /// `decode` — recover DTMF/MF/2600 tones from a WAV file.
    fn decode(&self, path: &str) -> Result<Event, PluginError> {
        let block = read_wav(path)?;
        let symbols = dsp::decode(&block.samples, block.sample_rate);
        // Degenerate: an empty/unreadable buffer is caught in `read_wav`. Here the
        // buffer analyzed cleanly — zero tones is a REAL result (Req 6.2), not Empty.
        let decoded: String = symbols.iter().map(|s| s.value.as_str()).collect();
        Ok(Event {
            source: "line".to_owned(),
            summary: if symbols.is_empty() {
                "decoded 0 tones — recording carries no DTMF/MF/SF".to_owned()
            } else {
                format!("decoded {} tone(s): {decoded}", symbols.len())
            },
            data: json!({
                "verb": "decode",
                "symbols": symbols,
                "count": symbols.len(),
                "truncated": block.truncated,
            }),
        })
    }

    /// `cid` — recover a Bell-202 Caller-ID frame from a WAV file.
    fn cid(&self, path: &str) -> Result<Event, PluginError> {
        let block = read_wav(path)?;
        match dsp::decode_cid(&block.samples, block.sample_rate) {
            Ok(frame) => Ok(Event {
                source: "line".to_owned(),
                summary: format!(
                    "CID observed: number={} checksum={} (UNTRUSTED — Caller-ID is spoofable)",
                    frame.number.as_deref().unwrap_or("<none>"),
                    if frame.checksum_ok { "ok" } else { "bad" },
                ),
                data: json!({
                    "verb": "cid",
                    "observed": frame,
                    "decoded": true,
                    "note": "fields are observed on the wire, NOT a verified identity",
                }),
            }),
            // No recoverable frame is a degenerate failure the operator sees.
            Err(_) => Err(PluginError::Empty(
                "no recoverable Caller-ID frame in the recording".to_owned(),
            )),
        }
    }

    /// `sense` — classify line electrical state from a recorded trace (the arg is
    /// the trace text: whitespace/comma-separated voltage samples).
    fn sense(&self, trace: &str) -> Result<Event, PluginError> {
        let block = RecordedSenseSource::new(trace, self.config.sense_rate)
            .read_block()
            .map_err(map_source_error)?;
        let state = sense::classify(&block)
            .ok_or_else(|| PluginError::InvalidInput("not a sense trace".to_owned()))?;
        Ok(Event {
            source: "line".to_owned(),
            summary: format!(
                "line state: {:?}{} (mean {:.1} V, pk-pk {:.1} V)",
                state.hook,
                if state.ringing { ", RINGING" } else { "" },
                state.mean_voltage,
                state.pk_pk,
            ),
            data: json!({
                "verb": "sense",
                "state": state,
                "truncated": block.truncated,
            }),
        })
    }

    /// `synth` — render a DTMF digit string (or `2600`) to a WAV file. Inert: writes
    /// samples only, no line path. Records the WAV as a `CaptureRef`-able artifact.
    fn synth(&self, spec: &str) -> Result<Event, PluginError> {
        let spec = spec.trim();
        let pcm = if spec.eq_ignore_ascii_case("2600") {
            dsp::synth_sf2600(self.config.sample_rate, 250.0)
                .map_err(|e| PluginError::InvalidInput(e.to_string()))?
        } else {
            dsp::synth_dtmf(
                spec,
                self.config.sample_rate,
                self.config.tone_ms,
                self.config.gap_ms,
            )
            .map_err(|e| PluginError::InvalidInput(e.to_string()))?
        };
        if pcm.is_empty() {
            return Err(PluginError::InvalidInput(
                "synthesis produced no samples".to_owned(),
            ));
        }
        let wav = dsp::to_wav(&pcm, self.config.sample_rate);
        std::fs::write(&self.config.out_path, &wav).map_err(|e| {
            PluginError::Backend(format!(
                "cannot write {}: {e}",
                self.config.out_path.display()
            ))
        })?;
        Ok(Event {
            source: "line".to_owned(),
            summary: format!(
                "synthesized {} sample(s) → {} (INERT — rendered to file, not a line)",
                pcm.len(),
                self.config.out_path.display(),
            ),
            data: json!({
                "verb": "synth",
                "samples": pcm.len(),
                "sample_rate": self.config.sample_rate,
                "path": self.config.out_path.display().to_string(),
                "emission": false,
            }),
        })
    }
}

/// Read + parse a WAV file into a sample block, mapping errors: missing file →
/// `InvalidInput`, I/O failure → `Backend`, empty/malformed → `InvalidInput`.
fn read_wav(path: &str) -> Result<crate::source::SampleBlock, PluginError> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PluginError::InvalidInput(format!("WAV not found: {path}"))
        } else {
            PluginError::Backend(format!("cannot read {path}: {e}"))
        }
    })?;
    WavFileSource::new(bytes)
        .read_block()
        .map_err(map_source_error)
}

/// Map a source error to the trait-level `PluginError`.
fn map_source_error(e: SourceError) -> PluginError {
    match e {
        SourceError::Empty(m) => PluginError::Empty(m),
        SourceError::Malformed(m) => PluginError::InvalidInput(format!("malformed: {m}")),
        SourceError::Unreadable(m) => PluginError::Backend(m),
        SourceError::LiveUnavailable(m) => PluginError::Unsupported(m),
    }
}

impl Plugin for LineHw {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "line".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::Wireline,
            capability: CapabilityClass::Passive,
            summary: "copper line I/O — DTMF/MF/CID decode, line sense, tone synth \
                      (passive, offline; injection is out of scope)"
                .to_owned(),
        }
    }

    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError> {
        match cmd.verb.as_str() {
            "decode" => self.decode(&cmd.arg),
            "cid" => self.cid(&cmd.arg),
            "sense" => self.sense(&cmd.arg),
            "synth" => self.synth(&cmd.arg),
            other => Err(PluginError::Unsupported(format!(
                "verb '{other}' not supported (available: decode, cid, sense, synth)"
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn cmd(verb: &str, arg: &str) -> Command {
        Command {
            verb: verb.to_owned(),
            arg: arg.to_owned(),
        }
    }

    #[test]
    fn unsupported_verb_rejected() {
        let out = LineHw::new().dispatch(&cmd("inject", "123"));
        assert!(matches!(out, Err(PluginError::Unsupported(_))));
    }

    #[test]
    fn synth_then_decode_via_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wav_path = dir.path().join("tones.wav");
        let plugin = LineHw::with_config(LineConfig {
            out_path: wav_path.clone(),
            ..Default::default()
        });
        // synth renders to the WAV.
        let synth = plugin.dispatch(&cmd("synth", "1234")).expect("synth");
        assert_eq!(synth.data["emission"], json!(false));
        assert!(wav_path.exists());
        // decode reads it back.
        let decoded = plugin
            .dispatch(&cmd("decode", wav_path.to_str().expect("utf8")))
            .expect("decode");
        assert!(decoded.summary.contains("1234"));
    }

    #[test]
    fn decode_missing_file_is_invalid_input() {
        let out = LineHw::new().dispatch(&cmd("decode", "/no/such.wav"));
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    }

    #[test]
    fn sense_idle_line_is_ok() {
        let out = LineHw::new()
            .dispatch(&cmd("sense", "48 48 48 48 48"))
            .expect("sense");
        assert_eq!(out.data["verb"], json!("sense"));
        assert_eq!(out.data["state"]["idle"], json!(true));
    }

    #[test]
    fn sense_empty_trace_is_empty() {
        let out = LineHw::new().dispatch(&cmd("sense", "   "));
        assert!(matches!(out, Err(PluginError::Empty(_))));
    }

    #[test]
    fn synth_unencodable_is_invalid_input() {
        let out = LineHw::new().dispatch(&cmd("synth", "12Z"));
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    }
}
