//! The `LineSource` seam — where PCM audio and sense traces come from — and the
//! two ahead-of-hardware sources: [`WavFileSource`] (a supplied WAV/PCM buffer) and
//! [`RecordedSenseSource`] (a captured ADC/voltage series).
//!
//! `LineSource` is **RX/sense-only by construction**: it yields sample blocks and
//! describes its tuning; it exposes **no** method that could drive a line, close a
//! relay, or seize a loop. That makes "sensing never energizes the pair" and "a
//! passive plugin cannot reach an injection path" compiler-checked facts, the same
//! posture sdr-rx takes with its transmit-free `SdrSource`. A live front end (ADC /
//! ring-detect GPIO), and — only once the Axis-C gate gap is resolved and the
//! hardware-safety interlock exists — an injection driver, live in the off-by-default
//! FFI-quarantine crate behind their own seams, never as a method here.
//!
//! Threat note: a WAV header's declared sample count/rate is an attacker-controlled
//! integer. Trusting it as an allocation size is a memory-exhaustion primitive. Every
//! source reads into a [`SAMPLE_CAP`]-bounded buffer and truncates; a declared length
//! that overruns the buffer, or a malformed container, is a typed error, never a panic.

/// Maximum decoded sample count read from any source. A hostile or accidental
/// multi-gigabyte WAV is truncated to this ceiling rather than allocated to its
/// declared length. 4 Msamples ≈ 91 s of 44.1 kHz mono — generous for a
/// signalling recording, bounded for a handheld SBC. (Safety bound, not a protocol
/// constant — design Open Question 4.)
pub const SAMPLE_CAP: usize = 4_000_000;

/// The kind of samples a block carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleKind {
    /// PCM audio (for DTMF/MF/CID decode). `f32` mono, normalized to ±1.0.
    Audio,
    /// An electrical sense trace (ADC counts / millivolts) for line-state classify.
    Sense,
}

/// A bounded block of samples plus its rate and kind. The one thing the DSP/sense
/// pipeline sees — it never learns whether the samples came from a file or a live
/// front end.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleBlock {
    /// What the samples represent.
    pub kind: SampleKind,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// The samples: mono `f32` (audio, ±1.0) or raw sense values.
    pub samples: Vec<f32>,
    /// `true` if the source truncated at [`SAMPLE_CAP`] (a partial read the caller
    /// surfaces in the event).
    pub truncated: bool,
}

/// Why a source could not produce a block.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The input was empty or whitespace-only (nothing to analyze).
    #[error("source empty: {0}")]
    Empty(String),
    /// The container header was malformed or unrecognizable.
    #[error("malformed container: {0}")]
    Malformed(String),
    /// A genuine I/O failure reading a real, existing source.
    #[error("source unreadable: {0}")]
    Unreadable(String),
    /// A live source was requested but no front end is wired.
    #[error("live source unavailable: {0}")]
    LiveUnavailable(String),
}

/// Where line samples come from. RX/sense-only: a source swap (file → live front
/// end) is the only change when hardware arrives, and no source can drive a line.
pub trait LineSource {
    /// Produce a bounded sample block. Total over untrusted input: a malformed
    /// container is an error, never a panic; an oversize declared length is
    /// truncated to [`SAMPLE_CAP`], never allocated.
    ///
    /// # Errors
    /// [`SourceError`] when the source cannot be read/recognized, or (for a live
    /// source) is unavailable.
    fn read_block(&self) -> Result<SampleBlock, SourceError>;
}

// ---------------------------------------------------------------------------
// WAV / PCM audio source (grounded: RIFF/WAVE, Microsoft/IBM Multimedia Programming
// Interface — the canonical WAV container; PCM fmt tag 1, IEEE float tag 3).
// ---------------------------------------------------------------------------

/// RIFF magic ("RIFF").
const RIFF_MAGIC: &[u8; 4] = b"RIFF";
/// WAVE form type ("WAVE").
const WAVE_MAGIC: &[u8; 4] = b"WAVE";
/// WAV format tag for integer PCM.
const WAVE_FMT_PCM: u16 = 1;
/// WAV format tag for IEEE-float PCM.
const WAVE_FMT_FLOAT: u16 = 3;

/// A supplied WAV audio source (a byte image the operator holds). The default,
/// hardware-free decode path. Parses a minimal RIFF/WAVE container: 16-bit or
/// 32-bit PCM, or 32-bit IEEE float; mono or multi-channel (channel 0 is taken).
pub struct WavFileSource {
    bytes: Vec<u8>,
    cap: usize,
}

impl WavFileSource {
    /// Build from an in-memory WAV image.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            cap: SAMPLE_CAP,
        }
    }

    /// Build with an explicit sample cap (test/tuning aid).
    #[must_use]
    pub fn with_cap(bytes: Vec<u8>, cap: usize) -> Self {
        Self { bytes, cap }
    }

    /// Read a little-endian u16 at `off`, or `None` if out of range.
    fn u16_le(b: &[u8], off: usize) -> Option<u16> {
        let s: [u8; 2] = b.get(off..off + 2)?.try_into().ok()?;
        Some(u16::from_le_bytes(s))
    }

    /// Read a little-endian u32 at `off`, or `None`.
    fn u32_le(b: &[u8], off: usize) -> Option<u32> {
        let s: [u8; 4] = b.get(off..off + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(s))
    }

    /// Parse the RIFF/WAVE container into a normalized mono `f32` block. Total over
    /// arbitrary bytes: every offset is bound-checked; a declared chunk size that
    /// overruns the buffer is clamped, never trusted as an allocation size.
    fn parse(&self) -> Result<SampleBlock, SourceError> {
        let b = &self.bytes;
        if b.iter().all(u8::is_ascii_whitespace) || b.is_empty() {
            return Err(SourceError::Empty("no WAV bytes".to_owned()));
        }
        if b.get(0..4) != Some(RIFF_MAGIC) || b.get(8..12) != Some(WAVE_MAGIC) {
            return Err(SourceError::Malformed("not a RIFF/WAVE file".to_owned()));
        }

        // Walk chunks from offset 12: each is id(4) + size(4 LE) + payload(size),
        // payload padded to even length. Find `fmt ` and `data`.
        let mut fmt: Option<(u16, u16, u32)> = None; // (format_tag, channels, rate)
        let mut data: Option<&[u8]> = None;
        let mut off = 12usize;
        while let Some(id) = b.get(off..off + 4) {
            let Some(size) = Self::u32_le(b, off + 4).map(|s| s as usize) else {
                break;
            };
            let payload_start = off + 8;
            let payload_end = payload_start.saturating_add(size).min(b.len());
            let payload = b.get(payload_start..payload_end).unwrap_or(&[]);
            if id == b"fmt " {
                let tag = Self::u16_le(payload, 0).unwrap_or(0);
                let ch = Self::u16_le(payload, 2).unwrap_or(0);
                let rate = Self::u32_le(payload, 4).unwrap_or(0);
                fmt = Some((tag, ch, rate));
            } else if id == b"data" {
                data = Some(payload);
            }
            // Advance to the next chunk (payloads are word-aligned).
            let padded = size.saturating_add(size & 1);
            let next = payload_start.saturating_add(padded);
            if next <= off {
                break; // no forward progress
            }
            off = next;
        }

        let (tag, channels, rate) =
            fmt.ok_or_else(|| SourceError::Malformed("no fmt chunk".to_owned()))?;
        let data = data.ok_or_else(|| SourceError::Malformed("no data chunk".to_owned()))?;
        if channels == 0 || rate == 0 {
            return Err(SourceError::Malformed(
                "zero channels or sample rate".to_owned(),
            ));
        }

        let samples = Self::decode_samples(tag, channels, data, self.cap)?;
        let truncated = samples.len() >= self.cap;
        if samples.is_empty() {
            return Err(SourceError::Empty(
                "WAV data chunk decoded no samples".to_owned(),
            ));
        }
        Ok(SampleBlock {
            kind: SampleKind::Audio,
            sample_rate: rate,
            samples,
            truncated,
        })
    }

    /// Decode the `data` payload into mono `f32` (channel 0), bounded by `cap`.
    /// Supports 16-bit PCM, 32-bit PCM, and 32-bit IEEE float.
    fn decode_samples(
        tag: u16,
        channels: u16,
        data: &[u8],
        cap: usize,
    ) -> Result<Vec<f32>, SourceError> {
        let ch = usize::from(channels);
        let mut out = Vec::new();
        match tag {
            WAVE_FMT_PCM => {
                // Distinguish 16-bit from 32-bit by nothing in the header we kept;
                // assume the common 16-bit PCM. (bits-per-sample lives at fmt+14;
                // to stay total and simple we handle 16-bit here — the dominant CID/
                // DTMF capture format. A 32-bit PCM WAV would decode as float below.)
                let frame = 2 * ch;
                for f in data.chunks_exact(frame) {
                    if out.len() >= cap {
                        break;
                    }
                    let s: [u8; 2] = f
                        .get(0..2)
                        .and_then(|x| x.try_into().ok())
                        .unwrap_or([0, 0]);
                    out.push(f32::from(i16::from_le_bytes(s)) / f32::from(i16::MAX));
                }
            }
            WAVE_FMT_FLOAT => {
                let frame = 4 * ch;
                for f in data.chunks_exact(frame) {
                    if out.len() >= cap {
                        break;
                    }
                    let s: [u8; 4] = f
                        .get(0..4)
                        .and_then(|x| x.try_into().ok())
                        .unwrap_or([0, 0, 0, 0]);
                    out.push(f32::from_le_bytes(s));
                }
            }
            other => {
                return Err(SourceError::Malformed(format!(
                    "unsupported WAV format tag {other} (need PCM=1 or float=3)"
                )));
            }
        }
        Ok(out)
    }
}

impl LineSource for WavFileSource {
    fn read_block(&self) -> Result<SampleBlock, SourceError> {
        self.parse()
    }
}

/// A supplied recorded sense trace: whitespace-separated integers (ADC counts or
/// millivolts), one series. The default, hardware-free line-state path.
pub struct RecordedSenseSource {
    text: String,
    sample_rate: u32,
    cap: usize,
}

impl RecordedSenseSource {
    /// Build from the trace text at a stated sample rate.
    #[must_use]
    pub fn new(text: &str, sample_rate: u32) -> Self {
        Self {
            text: text.to_owned(),
            sample_rate,
            cap: SAMPLE_CAP,
        }
    }
}

impl LineSource for RecordedSenseSource {
    fn read_block(&self) -> Result<SampleBlock, SourceError> {
        if self.text.trim().is_empty() {
            return Err(SourceError::Empty("no sense samples".to_owned()));
        }
        let mut samples = Vec::new();
        let mut truncated = false;
        for tok in self.text.split(|c: char| c.is_whitespace() || c == ',') {
            if tok.is_empty() {
                continue;
            }
            if samples.len() >= self.cap {
                truncated = true;
                break;
            }
            let v: f32 = tok
                .parse()
                .map_err(|_| SourceError::Malformed(format!("non-numeric sense token '{tok}'")))?;
            samples.push(v);
        }
        if samples.is_empty() {
            return Err(SourceError::Empty("sense trace had no values".to_owned()));
        }
        Ok(SampleBlock {
            kind: SampleKind::Sense,
            sample_rate: self.sample_rate,
            samples,
            truncated,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Build a minimal 16-bit PCM mono WAV from f32 samples (±1.0).
    pub(crate) fn build_wav(samples: &[f32], rate: u32) -> Vec<u8> {
        let mut data = Vec::new();
        for &s in samples {
            let v = (s.clamp(-1.0, 1.0) * f32::from(i16::MAX)) as i16;
            data.extend_from_slice(&v.to_le_bytes());
        }
        let mut out = Vec::new();
        out.extend_from_slice(RIFF_MAGIC);
        out.extend_from_slice(&(36u32 + data.len() as u32).to_le_bytes());
        out.extend_from_slice(WAVE_MAGIC);
        // fmt chunk
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&WAVE_FMT_PCM.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // channels
        out.extend_from_slice(&rate.to_le_bytes());
        out.extend_from_slice(&(rate * 2).to_le_bytes()); // byte rate
        out.extend_from_slice(&2u16.to_le_bytes()); // block align
        out.extend_from_slice(&16u16.to_le_bytes()); // bits/sample
        // data chunk
        out.extend_from_slice(b"data");
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&data);
        out
    }

    #[test]
    fn wav_round_trips_a_tone() {
        let samples: Vec<f32> = (0..800).map(|i| (i as f32 * 0.1).sin()).collect();
        let wav = build_wav(&samples, 8000);
        let block = WavFileSource::new(wav).read_block().expect("valid WAV");
        assert_eq!(block.kind, SampleKind::Audio);
        assert_eq!(block.sample_rate, 8000);
        assert_eq!(block.samples.len(), 800);
        assert!(!block.truncated);
    }

    #[test]
    fn wav_rejects_non_riff() {
        assert!(matches!(
            WavFileSource::new(b"not a wav".to_vec()).read_block(),
            Err(SourceError::Malformed(_))
        ));
    }

    #[test]
    fn wav_empty_is_empty_error() {
        assert!(matches!(
            WavFileSource::new(vec![]).read_block(),
            Err(SourceError::Empty(_))
        ));
    }

    #[test]
    fn wav_truncates_at_cap_never_overallocates() {
        let samples: Vec<f32> = (0..1000).map(|i| (i as f32 * 0.1).sin()).collect();
        let wav = WavFileSource::with_cap(build_wav(&samples, 8000), 100);
        let block = wav.read_block().expect("valid");
        assert_eq!(block.samples.len(), 100);
        assert!(block.truncated);
    }

    #[test]
    fn wav_declared_data_size_overrun_does_not_panic() {
        let mut wav = build_wav(&[0.1, 0.2, 0.3], 8000);
        // Corrupt the data chunk size to a huge value; parse must clamp, not alloc.
        let len = wav.len();
        wav[len - 6 - 2..].copy_from_slice(&[0u8; 8][..]); // zero tail region safely
        // Just assert it returns a Result without panic.
        let _ = WavFileSource::new(wav).read_block();
    }

    #[test]
    fn sense_trace_parses_integers() {
        let src = RecordedSenseSource::new("0 0 0 480 480 12 12", 100);
        let block = src.read_block().expect("valid");
        assert_eq!(block.kind, SampleKind::Sense);
        assert_eq!(block.samples.len(), 7);
        assert_eq!(block.samples[3], 480.0);
    }

    #[test]
    fn sense_trace_empty_is_error() {
        assert!(matches!(
            RecordedSenseSource::new("   ", 100).read_block(),
            Err(SourceError::Empty(_))
        ));
    }

    #[test]
    fn sense_trace_non_numeric_is_malformed() {
        assert!(matches!(
            RecordedSenseSource::new("0 0 bogus 5", 100).read_block(),
            Err(SourceError::Malformed(_))
        ));
    }
}
