//! The `Waveform` type and the transmit-only `TxSink` seam.
//!
//! `TxSink` is the mirror of sdr-rx's `SdrSource`: `SdrSource` receives and has no
//! transmit method, so an RX plugin cannot energize a TX path; `TxSink` transmits
//! and has no receive method, and no RX-only device (RTL-SDR) implements it — a
//! transmit is impossible on a receive-only radio, by construction rather than a
//! runtime guard.
//!
//! Only [`FileSink`] exists in the default build. It writes the rendered waveform
//! to a file and performs **no emission** — rendering to disk is the shipping
//! behavior until a radio arrives. Device sinks (`HackRfTxSink`/…) live in a
//! separate off-by-default FFI-quarantine crate and are the only place `unsafe` is
//! permitted; their key path additionally takes a `&TxGrant` (a double lock:
//! feature AND token). None is present here.

use std::path::{Path, PathBuf};

/// The domain of a rendered waveform's samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WaveformDomain {
    /// Complex baseband IQ (for a device that up-converts). Recorded as
    /// `CaptureKind::Iq`.
    Iq,
    /// Real audio samples (an AF stage feeding a transmitter). Recorded as
    /// `CaptureKind::CallAudio`.
    Audio,
}

/// A rendered, bounded buffer of samples plus its metadata. The product of the
/// pure `modulate` step — it touches no socket, radio, or gate.
///
/// IQ samples are stored interleaved (`i0, q0, i1, q1, …`) as `f32`; audio samples
/// are stored as mono `f32`. The interleaving keeps the on-disk `FileSink` format a
/// bare little-endian `f32` stream (`cf32` for IQ) with no framing.
#[derive(Debug, Clone, PartialEq)]
pub struct Waveform {
    /// The sample domain (IQ or audio).
    pub domain: WaveformDomain,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// The samples: interleaved I/Q for [`WaveformDomain::Iq`], mono for
    /// [`WaveformDomain::Audio`]. `f32` little-endian on disk.
    pub samples: Vec<f32>,
}

impl Waveform {
    /// The number of complex (IQ) or real (audio) samples — i.e. the logical
    /// length, which for IQ is half the `samples` vector length.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.domain {
            WaveformDomain::Iq => self.samples.len() / 2,
            WaveformDomain::Audio => self.samples.len(),
        }
    }

    /// Whether the waveform carries no samples (a dead carrier — the degenerate
    /// case the plugin turns into `PluginError::Empty`, never keying a sink).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Duration in seconds, derived from the logical sample count and rate.
    #[must_use]
    pub fn duration_secs(&self) -> f64 {
        if self.sample_rate == 0 {
            return 0.0;
        }
        self.len() as f64 / f64::from(self.sample_rate)
    }
}

/// Why a sink could not accept a waveform.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// The output path could not be written.
    #[error("sink write failed: {0}")]
    Write(String),
    /// A device sink was selected but the device is absent/unavailable. (Only
    /// reachable with the off-by-default `device` feature.)
    #[error("device unavailable: {0}")]
    DeviceUnavailable(String),
}

/// The transmit-only sink seam. A sink accepts one bounded waveform and either
/// writes it (file) or keys it (device). There is deliberately **no receive
/// method** — the mirror of sdr-rx's RX-only `SdrSource`.
pub trait TxSink {
    /// A short label for the `Event` metadata (e.g. `"file"`).
    fn kind(&self) -> &'static str;

    /// Accept and emit one bounded waveform. For [`FileSink`] this writes the
    /// samples to disk (no emission); a device sink would key the radio.
    ///
    /// # Errors
    /// [`SinkError`] on a write/device failure. Never panics.
    fn accept(&self, waveform: &Waveform) -> Result<(), SinkError>;
}

/// The ahead-of-hardware sink: writes the rendered waveform to a file as a bare
/// little-endian `f32` sample stream (`cf32` for IQ). Pure Rust, no feature flag,
/// no device, **no emission** — the default.
pub struct FileSink {
    path: PathBuf,
}

impl FileSink {
    /// A file sink writing to `path`.
    #[must_use]
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    /// The path this sink writes to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl TxSink for FileSink {
    fn kind(&self) -> &'static str {
        "file"
    }

    fn accept(&self, waveform: &Waveform) -> Result<(), SinkError> {
        // Serialize as a bare little-endian f32 stream — no framing, so the file is
        // a raw cf32 (IQ) or f32 (audio) dump an external tool can read directly.
        let mut bytes = Vec::with_capacity(waveform.samples.len() * 4);
        for s in &waveform.samples {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        std::fs::write(&self.path, &bytes)
            .map_err(|e| SinkError::Write(format!("{}: {e}", self.path.display())))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn iq_len_is_half_sample_count() {
        let w = Waveform {
            domain: WaveformDomain::Iq,
            sample_rate: 48_000,
            samples: vec![0.0; 8],
        };
        assert_eq!(w.len(), 4);
        assert!(!w.is_empty());
    }

    #[test]
    fn audio_len_is_sample_count() {
        let w = Waveform {
            domain: WaveformDomain::Audio,
            sample_rate: 48_000,
            samples: vec![0.0; 480],
        };
        assert_eq!(w.len(), 480);
        assert!((w.duration_secs() - 0.01).abs() < 1e-9);
    }

    #[test]
    fn empty_waveform_detected() {
        let w = Waveform {
            domain: WaveformDomain::Iq,
            sample_rate: 48_000,
            samples: vec![],
        };
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn file_sink_writes_le_f32() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wave.cf32");
        let sink = FileSink::new(&path);
        let w = Waveform {
            domain: WaveformDomain::Iq,
            sample_rate: 8000,
            samples: vec![1.0, 0.0, -1.0, 0.0],
        };
        sink.accept(&w).expect("write");
        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(bytes.len(), 16); // 4 f32
        assert_eq!(&bytes[0..4], &1.0f32.to_le_bytes());
    }

    #[test]
    fn file_sink_kind_is_file() {
        let sink = FileSink::new(Path::new("/tmp/x"));
        assert_eq!(sink.kind(), "file");
    }
}
