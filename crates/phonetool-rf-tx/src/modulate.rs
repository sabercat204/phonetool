//! Pure, sink-free, grant-free modulation — the ahead-of-hardware core.
//!
//! `modulate` turns a validated payload into a bounded [`Waveform`]. It touches no
//! socket, no radio, and no gate: modulation correctness is a property of a pure
//! function, exhaustively verifiable offline by rendering to a file and comparing
//! against a reference. A live radio changes nothing here — it only swaps the sink
//! downstream. Keeping this grant-free is deliberate: a rendered file is not an
//! emission and must not require a token (the gate lives at the sink boundary).
//!
//! Two schemes ship this sprint, both fully grounded from open specs:
//!   - **CW** (`cw`) — on-off-keyed carrier at ITU timing (1 dit : dah=3 : intra=1 :
//!     inter-letter=3 : word=7), WPM via the PARIS standard (50 dit-units/word).
//!   - **AFSK** (`afsk`) — Bell-202 1200-baud mark(1200 Hz)/space(2200 Hz) audio,
//!     carrying an AX.25 UI frame (see [`crate::payload`] for framing).
//!
//! FM and SSB are declared seams (need an input-audio reader + grounded filter
//! params) — [`modulate`] returns `Unsupported` for them until built.
//!
//! Grounding:
//!   - CW timing ratios — ITU-R M.1677-1 (International Morse Code), PARIS WPM.
//!   - AFSK tones + baud — Bell 202 (1200 Hz mark / 2200 Hz space, 1200 baud).
//!   - AX.25 framing — AX.25 v2.2 (handled in `payload`; this module keys the bits).

use core::f32::consts::PI;

use crate::payload::Ax25Frame;
use crate::sink::{Waveform, WaveformDomain};

/// Maximum rendered logical sample count. A safety bound (design Open Question 7),
/// not a protocol constant: it caps a runaway render on a handheld SBC. 480_000
/// samples = 10 s at 48 kHz — generous for a beacon/message, bounded for memory.
pub const SAMPLE_CAP: usize = 480_000;

/// Audio sample rate for the rendered waveforms (Hz). 48 kHz comfortably resolves
/// the Bell-202 2200 Hz space tone and the CW keying envelope.
pub const SAMPLE_RATE: u32 = 48_000;

// --- CW (ITU / PARIS) grounded constants ---

/// The reference word "PARIS" is 50 dit-units long (ITU convention), so
/// dit_seconds = 60 / (50 * wpm). This is the standard WPM→timing derivation.
const PARIS_UNITS_PER_WORD: f64 = 50.0;

/// CW carrier tone in the audio domain (Hz). A conventional sidetone/keying pitch;
/// for a file render it is the OOK envelope's carrier. (Not a regulated value — the
/// on-air RF frequency is set by the transmitter, gated by the band plan.)
const CW_TONE_HZ: f32 = 600.0;

// --- Bell-202 AFSK grounded constants ---

/// Bell-202 mark tone (binary 1), Hz.
const AFSK_MARK_HZ: f32 = 1200.0;
/// Bell-202 space tone (binary 0), Hz.
const AFSK_SPACE_HZ: f32 = 2200.0;
/// Bell-202 signalling rate, baud.
const AFSK_BAUD: u32 = 1200;

/// Configuration for a render. `wpm` applies to CW; the sample rate and cap are
/// shared. Test-friendly `Default`.
#[derive(Debug, Clone, Copy)]
pub struct ModConfig {
    /// CW speed in words per minute (PARIS standard).
    pub wpm: u32,
    /// Output sample rate in Hz.
    pub sample_rate: u32,
    /// Maximum logical sample count before the render is refused.
    pub sample_cap: usize,
}

impl Default for ModConfig {
    fn default() -> Self {
        Self {
            wpm: 20,
            sample_rate: SAMPLE_RATE,
            sample_cap: SAMPLE_CAP,
        }
    }
}

/// Why modulation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModError {
    /// The scheme verb is not one this module renders.
    #[error("unsupported scheme: {0}")]
    Unsupported(String),
    /// The render would exceed the configured sample cap.
    #[error("waveform would exceed the sample cap ({0} samples)")]
    TooLong(usize),
    /// A configuration value was degenerate (zero rate, zero wpm).
    #[error("invalid modulation config: {0}")]
    BadConfig(String),
}

/// The Morse timing schedule in dit-units (ITU-R M.1677-1): a dit is 1 unit, a dah
/// 3, intra-character gap 1, inter-character gap 3, word gap 7.
mod cw_timing {
    pub const DIT_UNITS: f64 = 1.0;
    pub const DAH_UNITS: f64 = 3.0;
    pub const INTRA_GAP_UNITS: f64 = 1.0;
    pub const INTER_CHAR_GAP_UNITS: f64 = 3.0;
    pub const WORD_GAP_UNITS: f64 = 7.0;
}

/// Render a CW (on-off-keyed) audio waveform from Morse elements. `elements` is the
/// dit/dah/gap sequence produced by [`crate::payload::cw_elements`]. Grant-free and
/// pure.
///
/// # Errors
/// [`ModError::BadConfig`] on a zero wpm/rate; [`ModError::TooLong`] if the render
/// exceeds `cfg.sample_cap`.
pub fn cw(elements: &[CwElement], cfg: &ModConfig) -> Result<Waveform, ModError> {
    if cfg.wpm == 0 || cfg.sample_rate == 0 {
        return Err(ModError::BadConfig(
            "wpm and sample_rate must be > 0".to_owned(),
        ));
    }
    let dit_secs = 60.0 / (PARIS_UNITS_PER_WORD * f64::from(cfg.wpm));
    let units_to_samples =
        |units: f64| -> usize { (units * dit_secs * f64::from(cfg.sample_rate)).round() as usize };

    let mut samples: Vec<f32> = Vec::new();
    let phase_step = 2.0 * PI * CW_TONE_HZ / cfg.sample_rate as f32;

    for el in elements {
        let (units, keyed) = match el {
            CwElement::Dit => (cw_timing::DIT_UNITS, true),
            CwElement::Dah => (cw_timing::DAH_UNITS, true),
            CwElement::IntraGap => (cw_timing::INTRA_GAP_UNITS, false),
            CwElement::CharGap => (cw_timing::INTER_CHAR_GAP_UNITS, false),
            CwElement::WordGap => (cw_timing::WORD_GAP_UNITS, false),
        };
        let n = units_to_samples(units);
        if samples.len().saturating_add(n) > cfg.sample_cap {
            return Err(ModError::TooLong(samples.len().saturating_add(n)));
        }
        for i in 0..n {
            // Continuous phase relative to the element start is fine for a keyed
            // tone; a click-free envelope would ramp, but a rectangular OOK key is
            // the textbook CW render and keeps the reference deterministic.
            let phase = phase_step * i as f32;
            samples.push(if keyed { phase.sin() } else { 0.0 });
        }
    }

    Ok(Waveform {
        domain: WaveformDomain::Audio,
        sample_rate: cfg.sample_rate,
        samples,
    })
}

/// One CW keying element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CwElement {
    /// A dit (1 unit, keyed).
    Dit,
    /// A dah (3 units, keyed).
    Dah,
    /// Intra-character gap (1 unit, silent).
    IntraGap,
    /// Inter-character gap (3 units, silent).
    CharGap,
    /// Word gap (7 units, silent).
    WordGap,
}

/// Render a Bell-202 1200-baud AFSK audio waveform from a framed AX.25 bit stream.
/// Each bit occupies one baud period; a 1 is the mark tone, a 0 the space tone.
/// Continuous-phase FSK (the phase carries across bit boundaries) — the correct,
/// click-free Bell-202 render. Grant-free and pure.
///
/// # Errors
/// [`ModError::BadConfig`] on a zero rate; [`ModError::TooLong`] past the cap.
pub fn afsk(frame: &Ax25Frame, cfg: &ModConfig) -> Result<Waveform, ModError> {
    if cfg.sample_rate == 0 {
        return Err(ModError::BadConfig("sample_rate must be > 0".to_owned()));
    }
    let bits = frame.nrzi_bits();
    let samples_per_bit = (f64::from(cfg.sample_rate) / f64::from(AFSK_BAUD)).round() as usize;
    if samples_per_bit == 0 {
        return Err(ModError::BadConfig(
            "sample rate too low for 1200 baud".to_owned(),
        ));
    }
    let total = bits.len().saturating_mul(samples_per_bit);
    if total > cfg.sample_cap {
        return Err(ModError::TooLong(total));
    }

    let mut samples: Vec<f32> = Vec::with_capacity(total);
    let mut phase: f32 = 0.0;
    for &bit in &bits {
        let tone = if bit { AFSK_MARK_HZ } else { AFSK_SPACE_HZ };
        let step = 2.0 * PI * tone / cfg.sample_rate as f32;
        for _ in 0..samples_per_bit {
            samples.push(phase.sin());
            phase += step;
            // Keep phase bounded to avoid f32 precision drift over long frames.
            if phase > 2.0 * PI {
                phase -= 2.0 * PI;
            }
        }
    }

    Ok(Waveform {
        domain: WaveformDomain::Audio,
        sample_rate: cfg.sample_rate,
        samples,
    })
}

/// The declared FM/SSB seam: needs an input-audio reader + grounded filter params
/// (design OQ3/OQ6). Returns `Unsupported` until built — named, not faked.
///
/// # Errors
/// Always [`ModError::Unsupported`] this sprint.
pub fn audio_scheme(scheme: &str) -> Result<Waveform, ModError> {
    Err(ModError::Unsupported(format!(
        "{scheme} needs an input-audio reader + grounded filter params (declared seam)"
    )))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::payload;

    #[test]
    fn cw_single_dit_has_expected_length() {
        // "E" = one dit. At 20 wpm, dit = 60/(50*20) = 0.06 s → 2880 samples @48k.
        let elements = payload::cw_elements("E").expect("valid");
        let w = cw(&elements, &ModConfig::default()).expect("render");
        assert_eq!(w.len(), 2880);
        assert_eq!(w.domain, WaveformDomain::Audio);
        // The dit is keyed (non-zero energy).
        assert!(w.samples.iter().any(|&s| s.abs() > 0.1));
    }

    #[test]
    fn cw_wpm_scales_inversely() {
        let e = payload::cw_elements("E").expect("valid");
        let fast = cw(
            &e,
            &ModConfig {
                wpm: 40,
                ..Default::default()
            },
        )
        .expect("render");
        let slow = cw(
            &e,
            &ModConfig {
                wpm: 20,
                ..Default::default()
            },
        )
        .expect("render");
        // Double the wpm → half the samples.
        assert_eq!(slow.len(), fast.len() * 2);
    }

    #[test]
    fn cw_zero_wpm_is_bad_config() {
        let e = payload::cw_elements("E").expect("valid");
        assert!(matches!(
            cw(
                &e,
                &ModConfig {
                    wpm: 0,
                    ..Default::default()
                }
            ),
            Err(ModError::BadConfig(_))
        ));
    }

    #[test]
    fn cw_respects_sample_cap() {
        let e = payload::cw_elements("PARIS PARIS").expect("valid");
        let cfg = ModConfig {
            sample_cap: 100,
            ..Default::default()
        };
        assert!(matches!(cw(&e, &cfg), Err(ModError::TooLong(_))));
    }

    #[test]
    fn afsk_frame_renders_at_1200_baud() {
        let frame = payload::Ax25Frame::new_ui("N0CALL", "APRS", b">test").expect("frame");
        let w = afsk(&frame, &ModConfig::default()).expect("render");
        assert_eq!(w.domain, WaveformDomain::Audio);
        // samples_per_bit @48k/1200 = 40; length is bits*40.
        assert_eq!(w.len() % 40, 0);
        assert!(!w.is_empty());
    }

    #[test]
    fn afsk_respects_sample_cap() {
        let frame = payload::Ax25Frame::new_ui("N0CALL", "APRS", b">test").expect("frame");
        let cfg = ModConfig {
            sample_cap: 10,
            ..Default::default()
        };
        assert!(matches!(afsk(&frame, &cfg), Err(ModError::TooLong(_))));
    }

    #[test]
    fn fm_ssb_are_declared_seams() {
        assert!(matches!(audio_scheme("fm"), Err(ModError::Unsupported(_))));
        assert!(matches!(audio_scheme("ssb"), Err(ModError::Unsupported(_))));
    }
}
