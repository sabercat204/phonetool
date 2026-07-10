//! The `SdrSource` trait — device-agnostic RX-only sample producer — and the
//! `IqFileSource` ahead-of-hardware implementation.
//!
//! Threat note: an IQ file is untrusted input. Its header/length can lie about
//! sample count; its samples can be pathological. The source reads into a
//! `SAMPLE_CAP`-bounded buffer, truncates rather than allocating to a declared
//! count, and maps every I/O or format error to `PluginError::Backend`.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use num_complex::Complex;
use phonetool_core::PluginError;

/// A bounded owned buffer of complex IQ samples plus the context needed to
/// interpret them (sample rate and center frequency).
#[derive(Debug, Clone)]
pub struct SampleBlock {
    /// The IQ samples (interleaved I/Q as `Complex<f32>`).
    pub samples: Vec<Complex<f32>>,
    /// Sample rate in Hz.
    pub sample_rate: f64,
    /// Center frequency in Hz.
    pub center_freq: f64,
    /// Whether the source was truncated to the sample cap.
    pub truncated: bool,
}

/// The default sample cap: 16M complex samples (≈64 MB of cf32). Configurable
/// per `RxConfig`; this is the fallback when no config overrides it.
pub const DEFAULT_SAMPLE_CAP: usize = 16 * 1024 * 1024;

/// RX-only sample producer. Has **no transmit method** — compiler-enforced.
/// A TX-capable radio driven RX-only still implements only this trait for its
/// receive path; its transmit capability is unreachable through this seam.
pub trait SdrSource: Send + Sync {
    /// Read up to `max_samples` complex samples from the source into a
    /// `SampleBlock`. Returns the block (which may be shorter than requested
    /// if the source is exhausted) or a `PluginError::Backend` on I/O failure.
    ///
    /// # Errors
    /// `PluginError::Backend` on any I/O or format error.
    fn read_block(&mut self, max_samples: usize) -> Result<SampleBlock, PluginError>;

    /// The source's current tuning: `(sample_rate_hz, center_freq_hz)`.
    fn tuned(&self) -> (f64, f64);
}

/// A pure-Rust `SdrSource` that reads raw interleaved cf32 (pairs of little-endian
/// `f32`) from a file. This is the ahead-of-hardware default, not a test double.
pub struct IqFileSource {
    sample_rate: f64,
    center_freq: f64,
    data: Vec<Complex<f32>>,
    position: usize,
    truncated_at_open: bool,
}

impl IqFileSource {
    /// Open an IQ file at `path` with the given sample rate and center frequency.
    /// Reads the entire file (bounded by `sample_cap`) into memory eagerly.
    ///
    /// # Errors
    /// `PluginError::Backend` if the file cannot be opened or read.
    pub fn open(
        path: &Path,
        sample_rate: f64,
        center_freq: f64,
        sample_cap: usize,
    ) -> Result<Self, PluginError> {
        let mut file = File::open(path).map_err(|e| {
            PluginError::Backend(format!("cannot open IQ file {}: {e}", path.display()))
        })?;

        let byte_cap = sample_cap.saturating_mul(8); // 2 × f32 = 8 bytes per sample
        let mut raw = Vec::new();
        file.read_to_end(&mut raw).map_err(|e| {
            PluginError::Backend(format!("cannot read IQ file {}: {e}", path.display()))
        })?;

        let truncated_at_open = raw.len() > byte_cap;
        if truncated_at_open {
            raw.truncate(byte_cap);
        }

        // Discard trailing bytes that don't form a complete sample (8 bytes each).
        let usable = raw.len() - (raw.len() % 8);

        let samples: Vec<Complex<f32>> = raw
            .get(..usable)
            .unwrap_or_default()
            .chunks_exact(8)
            .filter_map(|chunk| {
                let (i_bytes, q_bytes) = chunk.split_at(4);
                let i = f32::from_le_bytes(i_bytes.try_into().ok()?);
                let q = f32::from_le_bytes(q_bytes.try_into().ok()?);
                Some(Complex::new(i, q))
            })
            .collect();

        Ok(Self {
            sample_rate,
            center_freq,
            data: samples,
            position: 0,
            truncated_at_open,
        })
    }
}

impl SdrSource for IqFileSource {
    fn read_block(&mut self, max_samples: usize) -> Result<SampleBlock, PluginError> {
        let remaining = self.data.len().saturating_sub(self.position);
        let count = remaining.min(max_samples);
        let end = self.position.saturating_add(count);
        let samples = self
            .data
            .get(self.position..end)
            .unwrap_or_default()
            .to_vec();
        let truncated = remaining > max_samples || self.truncated_at_open;
        self.position = end;

        Ok(SampleBlock {
            samples,
            sample_rate: self.sample_rate,
            center_freq: self.center_freq,
            truncated,
        })
    }

    fn tuned(&self) -> (f64, f64) {
        (self.sample_rate, self.center_freq)
    }
}
