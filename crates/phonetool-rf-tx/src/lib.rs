//! `phonetool-rf-tx` — the workbench's transmit path and first Axis-B consumer.
//!
//! Modulates an operator payload (CW, AFSK/AX.25) into a waveform and renders it to
//! a file. It is the mirror of `phonetool-sdr-rx`: sdr-rx receives and is `Passive`
//! (never gated); rf-tx transmits and is **always** gated — every transmission
//! routes through `Gate::request_tx`, holds a `TxGrant`, and NEVER auto-repeats.
//!
//! **Two structural safety properties:**
//! 1. *The type prevents the wrong axis.* Transmit is reachable only through
//!    [`TxPlugin::dispatch_tx`], which takes `&TxGrant`. `Grant` (Axis A) and
//!    `TxGrant` (Axis B) are distinct types with no public constructor, so a cyber
//!    authorization physically cannot key a radio. A compile-fail doctest proves a
//!    fabricated `TxGrant` cannot reach the transmit path.
//! 2. *The default build cannot emit.* No device `TxSink` is compiled into the
//!    default graph — [`FileSink`](sink::FileSink) is the only sink, and it writes
//!    to disk with no emission. A real radio requires **both** the off-by-default
//!    `device` feature **and** a gate-minted token (a double lock). Selecting a
//!    device sink in the default build is a *compile* error, not a runtime one.
//!
//! **Authority from the grant, parameters from the command.** The authorized band,
//! power, and license basis are read from `grant.band()` / `grant.power_dbm()` /
//! `grant.license_basis()` — never the command. The command's `arg` carries the
//! operation parameters: a JSON envelope `{"freq_hz": <u64>, "payload": "<text>"}`
//! (the payload is the CW text or, for AFSK, `"SRC>DEST:info"`). The requested
//! frequency is *validated against* the grant's band by [`bandplan`], never trusted
//! as authority (design Open Question 8 resolved: a fail-closed JSON envelope, no
//! core `Command` change).
//!
//! **Grounded, offline, partial by design.** CW (ITU M.1677-1 timing) and AFSK
//! (Bell-202 / AX.25 v2.2) ship fully grounded; FM/SSB are declared seams. The band
//! plan is US FCC Part 97 (unlisted band → fail closed). Zero egress deps.
//!
//! ## Example (compile-fail proof: a fabricated `TxGrant` cannot reach transmit)
//!
//! ```compile_fail
//! use phonetool_authgate::TxGrant;
//! // `TxGrant` has private fields and no public constructor — this does not compile.
//! let forged = TxGrant { band: "2m".into(), power_dbm: 30.0, license_basis: "".into() };
//! ```

pub mod bandplan;
pub mod modulate;
pub mod payload;
pub mod sink;

use std::path::PathBuf;

use phonetool_authgate::TxGrant;
use phonetool_core::{
    CapabilityClass, Command, Event, Manifest, PluginError, Transducer, TxPlugin,
};
use serde::Deserialize;
use serde_json::json;

use crate::modulate::ModConfig;
use crate::sink::{FileSink, TxSink, Waveform, WaveformDomain};

/// Configuration for the plugin: modulation settings + the output path the default
/// `FileSink` renders to.
#[derive(Debug, Clone)]
pub struct TxConfig {
    /// Modulation config (WPM, sample rate, sample cap).
    pub modulation: ModConfig,
    /// Where `FileSink` writes the rendered waveform.
    pub out_path: PathBuf,
}

impl Default for TxConfig {
    fn default() -> Self {
        Self {
            modulation: ModConfig::default(),
            out_path: PathBuf::from("rf-tx-render.cf32"),
        }
    }
}

/// The RF transmit-path plugin. Holds only render configuration — never a token
/// (the `TxGrant` arrives per-transmission through `dispatch_tx`).
pub struct RfTx {
    config: TxConfig,
}

impl Default for RfTx {
    fn default() -> Self {
        Self::new()
    }
}

impl RfTx {
    /// Build with default render configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: TxConfig::default(),
        }
    }

    /// Build with an explicit render configuration (output path, WPM, caps).
    #[must_use]
    pub fn with_config(config: TxConfig) -> Self {
        Self { config }
    }
}

/// The command `arg` envelope: the operation parameters that are NOT regulatory
/// authority. `freq_hz` is validated against the grant's band; `payload` is the CW
/// text or the AFSK frame spec `"SRC>DEST:info"`.
#[derive(Debug, Deserialize)]
struct TxRequest {
    /// The requested transmit frequency in Hz (validated against the grant's band).
    freq_hz: u64,
    /// The scheme payload: CW text, or `"SRC>DEST:info"` for AFSK.
    payload: String,
}

impl RfTx {
    /// Parse the JSON arg envelope. Total/fail-closed: malformed JSON or a missing
    /// field is `InvalidInput`, never a panic.
    fn parse_request(arg: &str) -> Result<TxRequest, PluginError> {
        let arg = arg.trim();
        if arg.is_empty() {
            return Err(PluginError::InvalidInput(
                "rf-tx requires a JSON arg: {\"freq_hz\":<hz>,\"payload\":\"<...>\"}".to_owned(),
            ));
        }
        serde_json::from_str(arg)
            .map_err(|e| PluginError::InvalidInput(format!("malformed rf-tx request: {e}")))
    }

    /// Modulate per scheme. CW/AFSK are built; FM/SSB are declared seams.
    fn modulate_for(&self, scheme: &str, req: &TxRequest) -> Result<Waveform, PluginError> {
        match scheme {
            "cw" => {
                let elements = payload::cw_elements(&req.payload)
                    .map_err(|e| PluginError::InvalidInput(e.to_string()))?;
                modulate::cw(&elements, &self.config.modulation).map_err(map_mod_error)
            }
            "afsk" => {
                let frame = parse_afsk_payload(&req.payload)?;
                modulate::afsk(&frame, &self.config.modulation).map_err(map_mod_error)
            }
            "fm" | "ssb" => modulate::audio_scheme(scheme).map_err(map_mod_error),
            other => Err(PluginError::Unsupported(format!(
                "scheme '{other}' not supported (available: cw, afsk; fm/ssb are declared seams)"
            ))),
        }
    }
}

/// Parse an AFSK payload of the form `"SRC>DEST:info text"` into a validated
/// AX.25 UI frame. Fail-closed on a missing separator or a bad callsign.
fn parse_afsk_payload(spec: &str) -> Result<payload::Ax25Frame, PluginError> {
    let (route, info) = spec.split_once(':').ok_or_else(|| {
        PluginError::InvalidInput("afsk payload needs 'SRC>DEST:info'".to_owned())
    })?;
    let (src, dest) = route
        .split_once('>')
        .ok_or_else(|| PluginError::InvalidInput("afsk route needs 'SRC>DEST'".to_owned()))?;
    payload::Ax25Frame::new_ui(src.trim(), dest.trim(), info.as_bytes())
        .map_err(|e| PluginError::InvalidInput(e.to_string()))
}

fn map_mod_error(e: modulate::ModError) -> PluginError {
    match e {
        modulate::ModError::Unsupported(m) => PluginError::Unsupported(m),
        modulate::ModError::TooLong(_) => PluginError::InvalidInput(e.to_string()),
        modulate::ModError::BadConfig(m) => PluginError::InvalidInput(m),
    }
}

impl TxPlugin for RfTx {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "rf-tx".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::RfTx,
            capability: CapabilityClass::RfTx,
            summary: "RF transmit — CW/AFSK modulation rendered to file (Axis-B gated; \
                      no device sink in the default build)"
                .to_owned(),
        }
    }

    fn dispatch_tx(&self, cmd: &Command, grant: &TxGrant) -> Result<Event, PluginError> {
        // Authority from the grant, NEVER the command.
        let band = grant.band();
        let power_dbm = grant.power_dbm();

        let req = Self::parse_request(&cmd.arg)?;

        // Band-vs-license + power ceiling BEFORE any modulation or sink work (Req 5).
        // A refused transmission never reaches a sink, even a device one.
        let envelope = bandplan::check(band, req.freq_hz, power_dbm)
            .map_err(|e| PluginError::InvalidInput(e.to_string()))?;

        // Modulate (pure, grant-free). The verb is the scheme.
        let waveform = self.modulate_for(&cmd.verb, &req)?;

        // Degenerate discipline: a zero-sample render is a failure the operator
        // sees — never key a sink with a dead carrier (Req 9).
        if waveform.is_empty() {
            return Err(PluginError::Empty(format!(
                "scheme '{}' produced no samples (nothing to transmit)",
                cmd.verb
            )));
        }

        // Default sink: FileSink. No device sink exists in this build — emission is
        // structurally impossible (Req 3). Rendering to a file is not an emission.
        let sink = FileSink::new(&self.config.out_path);
        sink.accept(&waveform)
            .map_err(|e| PluginError::Backend(e.to_string()))?;

        Ok(Event {
            source: "rf-tx".to_owned(),
            summary: format!(
                "rendered {} waveform: {} samples, {:.3}s @ {} Hz → {} (freq {} Hz, ≤{:.2} dBm, band '{}')",
                cmd.verb,
                waveform.len(),
                waveform.duration_secs(),
                waveform.sample_rate,
                sink.kind(),
                envelope.freq_hz,
                envelope.ceiling_dbm,
                band,
            ),
            data: json!({
                "scheme": cmd.verb,
                "band": band,
                "freq_hz": envelope.freq_hz,
                "power_ceiling_dbm": envelope.ceiling_dbm,
                "license_basis": grant.license_basis(),
                "samples": waveform.len(),
                "duration_secs": waveform.duration_secs(),
                "sample_rate": waveform.sample_rate,
                "domain": match waveform.domain {
                    WaveformDomain::Iq => "iq",
                    WaveformDomain::Audio => "audio",
                },
                "sink": sink.kind(),
                "emission": false,
            }),
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use phonetool_authgate::{Gate, NullConsentLog, TxAuthorization};

    /// Mint a real TxGrant the only legal way — through Gate::request_tx.
    fn grant(band: &str, power_dbm: f64) -> TxGrant {
        let log = NullConsentLog;
        let gate = Gate::new(&log);
        gate.request_tx(TxAuthorization {
            band: band.to_owned(),
            power_dbm,
            license_basis: "test license".to_owned(),
        })
        .expect("valid authorization")
    }

    fn rf_tx_to(path: &std::path::Path) -> RfTx {
        RfTx::with_config(TxConfig {
            out_path: path.to_path_buf(),
            ..Default::default()
        })
    }

    fn cmd(verb: &str, arg: &str) -> Command {
        Command {
            verb: verb.to_owned(),
            arg: arg.to_owned(),
        }
    }

    #[test]
    fn cw_render_writes_file_and_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cw.cf32");
        let plugin = rf_tx_to(&path);
        let g = grant("2m", 40.0);
        let event = plugin
            .dispatch_tx(&cmd("cw", r#"{"freq_hz":146520000,"payload":"CQ"}"#), &g)
            .expect("render");
        assert_eq!(event.source, "rf-tx");
        assert_eq!(event.data["emission"], json!(false));
        assert!(event.data["samples"].as_u64().expect("samples") > 0);
        assert!(path.exists());
    }

    #[test]
    fn afsk_render_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("afsk.cf32");
        let g = grant("2m", 40.0);
        let event = rf_tx_to(&path)
            .dispatch_tx(
                &cmd(
                    "afsk",
                    r#"{"freq_hz":144390000,"payload":"N0CALL>APRS:>beacon"}"#,
                ),
                &g,
            )
            .expect("render");
        assert_eq!(event.data["scheme"], json!("afsk"));
    }

    #[test]
    fn freq_out_of_band_refused_before_render() {
        // 70cm grant, 2m frequency → InvalidInput, no file written.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("never.cf32");
        let g = grant("70cm", 30.0);
        let out =
            rf_tx_to(&path).dispatch_tx(&cmd("cw", r#"{"freq_hz":146000000,"payload":"E"}"#), &g);
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
        assert!(!path.exists(), "no sink work on a refused transmission");
    }

    #[test]
    fn over_power_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = grant("20m", 70.0); // over the 61.76 dBm ceiling
        let out = rf_tx_to(&dir.path().join("x"))
            .dispatch_tx(&cmd("cw", r#"{"freq_hz":14200000,"payload":"E"}"#), &g);
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    }

    #[test]
    fn unknown_band_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = grant("11m CB", 4.0);
        let out = rf_tx_to(&dir.path().join("x"))
            .dispatch_tx(&cmd("cw", r#"{"freq_hz":27185000,"payload":"E"}"#), &g);
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    }

    #[test]
    fn empty_cw_text_is_degenerate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.cf32");
        let g = grant("2m", 40.0);
        let out =
            rf_tx_to(&path).dispatch_tx(&cmd("cw", r#"{"freq_hz":146520000,"payload":"   "}"#), &g);
        assert!(matches!(out, Err(PluginError::Empty(_))));
        assert!(!path.exists(), "no sink keyed with a zero-sample waveform");
    }

    #[test]
    fn unencodable_cw_char_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = grant("2m", 40.0);
        let out = rf_tx_to(&dir.path().join("x"))
            .dispatch_tx(&cmd("cw", r#"{"freq_hz":146520000,"payload":"hi~"}"#), &g);
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    }

    #[test]
    fn unsupported_scheme_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = grant("2m", 40.0);
        let out = rf_tx_to(&dir.path().join("x"))
            .dispatch_tx(&cmd("psk31", r#"{"freq_hz":146520000,"payload":"E"}"#), &g);
        assert!(matches!(out, Err(PluginError::Unsupported(_))));
    }

    #[test]
    fn fm_ssb_are_declared_seams() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = grant("2m", 40.0);
        let out = rf_tx_to(&dir.path().join("x"))
            .dispatch_tx(&cmd("fm", r#"{"freq_hz":146520000,"payload":"x"}"#), &g);
        assert!(matches!(out, Err(PluginError::Unsupported(_))));
    }

    #[test]
    fn malformed_json_arg_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = grant("2m", 40.0);
        let out = rf_tx_to(&dir.path().join("x")).dispatch_tx(&cmd("cw", "not json"), &g);
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    }
}
