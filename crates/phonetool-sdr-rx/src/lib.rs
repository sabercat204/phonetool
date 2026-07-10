//! `phonetool-sdr-rx` — passive SDR receive plugin.
//!
//! Sweep (power vs frequency), identify (energy detect + classify), and demod
//! (FM/AM/SSB → audio; digital → bits). Implements the plain `Plugin` trait
//! (never `ActivePlugin` or `TxPlugin`) — receiving is observation, never gated.
//!
//! The load-bearing seam is [`SdrSource`](source::SdrSource): device-agnostic,
//! RX-only (no transmit method), with [`IqFileSource`](source::IqFileSource) as
//! the ahead-of-hardware default. The entire pipeline runs today against a
//! recorded/synthetic IQ file with no radio attached.
//!
//! ## Example (compile-fail proof: `SdrRx` is NOT `ActivePlugin`)
//!
//! ```compile_fail
//! // A passive plugin cannot be dispatched as an active one — the type system
//! // prevents it: `SdrRx` does not implement `ActivePlugin`.
//! use phonetool_core::ActivePlugin;
//! use phonetool_sdr_rx::SdrRx;
//! fn require_active(_p: &dyn ActivePlugin) {}
//! fn check(s: &SdrRx) { require_active(s); }
//! ```

pub mod classify;
pub mod dsp;
pub mod source;

use std::path::Path;

use phonetool_core::{CapabilityClass, Command, Event, Manifest, Plugin, PluginError, Transducer};
use serde_json::json;

use crate::dsp::demod::{DemodMode, DemodOutput, demodulate};
use crate::dsp::identify::{BandwidthClassifier, detect};
use crate::dsp::sweep::periodogram;
use crate::source::{DEFAULT_SAMPLE_CAP, IqFileSource, SdrSource};

/// Configuration for the SDR RX plugin. All numeric thresholds are
/// parameterized — no confabulated constants.
#[derive(Debug, Clone)]
pub struct RxConfig {
    /// Maximum samples to read from any source (head-truncate on exceed).
    pub sample_cap: usize,
    /// FFT size for sweep (periodogram bin count).
    pub fft_size: usize,
    /// Energy detection threshold in dB. Bins above this are "signal."
    pub threshold_db: f64,
    /// Sample rate declared for the IQ source (Hz). Operator-supplied.
    pub sample_rate: f64,
    /// Center frequency declared for the IQ source (Hz). Operator-supplied.
    pub center_freq: f64,
    /// Bandwidth classifier thresholds.
    pub classifier: BandwidthClassifier,
}

impl Default for RxConfig {
    fn default() -> Self {
        Self {
            sample_cap: DEFAULT_SAMPLE_CAP,
            fft_size: 1024,
            threshold_db: -40.0,
            sample_rate: 2_048_000.0,
            center_freq: 100_000_000.0,
            classifier: BandwidthClassifier::default(),
        }
    }
}

/// The passive SDR receive plugin.
pub struct SdrRx {
    config: RxConfig,
}

impl SdrRx {
    /// Create with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: RxConfig::default(),
        }
    }

    /// Create with explicit configuration.
    #[must_use]
    pub fn with_config(config: RxConfig) -> Self {
        Self { config }
    }

    fn do_sweep(&self, path: &Path) -> Result<Event, PluginError> {
        let mut source = IqFileSource::open(
            path,
            self.config.sample_rate,
            self.config.center_freq,
            self.config.sample_cap,
        )?;
        let block = source.read_block(self.config.sample_cap)?;
        if block.samples.is_empty() {
            return Err(PluginError::Empty("zero samples in IQ file".to_owned()));
        }

        let bins = periodogram(&block, self.config.fft_size);
        let bin_data: Vec<serde_json::Value> = bins
            .iter()
            .map(|b| json!({"freq_hz": b.freq_hz, "power_db": b.power_db}))
            .collect();

        Ok(Event {
            source: "sdr".to_owned(),
            summary: format!(
                "swept {:.3} MHz, {} bins",
                self.config.center_freq / 1e6,
                bins.len()
            ),
            data: json!({
                "verb": "sweep",
                "sample_rate": block.sample_rate,
                "center_freq": block.center_freq,
                "samples_read": block.samples.len(),
                "truncated": block.truncated,
                "fft_size": self.config.fft_size,
                "bins": bin_data.len(),
            }),
        })
    }

    fn do_identify(&self, path: &Path) -> Result<Event, PluginError> {
        let mut source = IqFileSource::open(
            path,
            self.config.sample_rate,
            self.config.center_freq,
            self.config.sample_cap,
        )?;
        let block = source.read_block(self.config.sample_cap)?;
        if block.samples.is_empty() {
            return Err(PluginError::Empty("zero samples in IQ file".to_owned()));
        }

        let bins = periodogram(&block, self.config.fft_size);
        let signals = detect(&bins, self.config.threshold_db, &self.config.classifier);

        let findings: Vec<serde_json::Value> = signals
            .iter()
            .map(|s| {
                json!({
                    "center_hz": s.center_hz,
                    "bandwidth_hz": s.bandwidth_hz,
                    "power_db": s.power_db,
                    "modulation": s.modulation,
                })
            })
            .collect();

        Ok(Event {
            source: "sdr".to_owned(),
            summary: format!(
                "identified {} signal(s) at {:.3} MHz",
                signals.len(),
                self.config.center_freq / 1e6,
            ),
            data: json!({
                "verb": "identify",
                "sample_rate": block.sample_rate,
                "center_freq": block.center_freq,
                "samples_read": block.samples.len(),
                "truncated": block.truncated,
                "threshold_db": self.config.threshold_db,
                "detected": signals.len(),
                "signals": findings,
            }),
        })
    }

    fn do_demod(&self, path: &Path, mode_str: &str) -> Result<Event, PluginError> {
        let mode = DemodMode::parse(mode_str)?;
        let mut source = IqFileSource::open(
            path,
            self.config.sample_rate,
            self.config.center_freq,
            self.config.sample_cap,
        )?;
        let block = source.read_block(self.config.sample_cap)?;
        if block.samples.is_empty() {
            return Err(PluginError::Empty("zero samples in IQ file".to_owned()));
        }

        let output = demodulate(&block.samples, mode)?;
        let (output_type, output_len) = match &output {
            DemodOutput::Audio(a) => ("audio", a.len()),
            DemodOutput::Bits(b) => ("bits", b.len()),
        };

        Ok(Event {
            source: "sdr".to_owned(),
            summary: format!("demod {mode_str}: {output_len} {output_type} samples"),
            data: json!({
                "verb": "demod",
                "mode": mode_str,
                "sample_rate": block.sample_rate,
                "center_freq": block.center_freq,
                "samples_read": block.samples.len(),
                "truncated": block.truncated,
                "output_type": output_type,
                "output_len": output_len,
            }),
        })
    }
}

impl Default for SdrRx {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for SdrRx {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "sdr".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::RfRx,
            capability: CapabilityClass::Passive,
            summary: "SDR receive: sweep, identify, demod from IQ files".to_owned(),
        }
    }

    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError> {
        match cmd.verb.as_str() {
            "sweep" => {
                let path = parse_path(&cmd.arg)?;
                self.do_sweep(path)
            }
            "identify" => {
                let path = parse_path(&cmd.arg)?;
                self.do_identify(path)
            }
            "demod" => {
                let (path_str, mode) = parse_demod_arg(&cmd.arg)?;
                let path = Path::new(path_str);
                if path_str.is_empty() {
                    return Err(PluginError::InvalidInput(
                        "demod requires <file> <mode>".to_owned(),
                    ));
                }
                self.do_demod(path, mode)
            }
            other => Err(PluginError::Unsupported(format!(
                "verb '{other}' not supported (available: sweep, identify, demod)"
            ))),
        }
    }
}

fn parse_path(arg: &str) -> Result<&Path, PluginError> {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return Err(PluginError::InvalidInput("file path required".to_owned()));
    }
    Ok(Path::new(trimmed))
}

fn parse_demod_arg(arg: &str) -> Result<(&str, &str), PluginError> {
    let trimmed = arg.trim();
    let (file, mode) = trimmed.split_once(' ').ok_or_else(|| {
        PluginError::InvalidInput(
            "demod requires '<file> <mode>' (e.g. 'capture.iq fm')".to_owned(),
        )
    })?;
    if file.is_empty() || mode.trim().is_empty() {
        return Err(PluginError::InvalidInput(
            "demod requires '<file> <mode>' (e.g. 'capture.iq fm')".to_owned(),
        ));
    }
    Ok((file, mode.trim()))
}
