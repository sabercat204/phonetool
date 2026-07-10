//! Demodulation: IQ → audio (FM/AM/SSB) or raw bits (digital).
//!
//! Threat note: demodulated content is attacker-shaped structure. The output
//! audio samples and raw bits are bounded and treated as untrusted downstream.

use num_complex::Complex;
use phonetool_core::PluginError;

/// Demodulated output from one of the supported modes.
#[derive(Debug, Clone)]
pub enum DemodOutput {
    /// Audio samples (mono, normalized to [-1.0, 1.0]).
    Audio(Vec<f32>),
    /// Raw bits from a digital demod (bounded, no protocol decode).
    Bits(Vec<u8>),
}

/// The demodulation mode requested by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemodMode {
    Fm,
    Am,
    Ssb,
    Digital,
}

impl DemodMode {
    /// Parse a mode string from the command. Case-insensitive.
    ///
    /// # Errors
    /// `PluginError::Unsupported` for unknown modes.
    pub fn parse(s: &str) -> Result<Self, PluginError> {
        match s.to_ascii_lowercase().as_str() {
            "fm" => Ok(Self::Fm),
            "am" => Ok(Self::Am),
            "ssb" => Ok(Self::Ssb),
            "digital" => Ok(Self::Digital),
            other => Err(PluginError::Unsupported(format!(
                "demod mode '{other}' not supported (available: fm, am, ssb, digital)"
            ))),
        }
    }
}

/// Demodulate IQ samples according to the specified mode.
///
/// # Errors
/// - `PluginError::Empty` if samples is empty (degenerate case).
/// - `PluginError::Unsupported` should not occur here (mode already parsed),
///   but defensive.
pub fn demodulate(samples: &[Complex<f32>], mode: DemodMode) -> Result<DemodOutput, PluginError> {
    if samples.is_empty() {
        return Err(PluginError::Empty("no samples to demodulate".to_owned()));
    }

    match mode {
        DemodMode::Fm => Ok(DemodOutput::Audio(demod_fm(samples))),
        DemodMode::Am => Ok(DemodOutput::Audio(demod_am(samples))),
        DemodMode::Ssb => Ok(DemodOutput::Audio(demod_ssb(samples))),
        DemodMode::Digital => Ok(DemodOutput::Bits(demod_digital(samples))),
    }
}

/// FM demodulation via quadrature (instantaneous frequency from phase
/// difference between consecutive samples).
fn demod_fm(samples: &[Complex<f32>]) -> Vec<f32> {
    if samples.len() < 2 {
        return vec![0.0; samples.len()];
    }

    samples
        .windows(2)
        .map(|pair| {
            let prev = pair.first().copied().unwrap_or_default();
            let curr = pair.last().copied().unwrap_or_default();
            let product = curr * prev.conj();
            product.im.atan2(product.re) / std::f32::consts::PI
        })
        .collect()
}

/// AM demodulation via envelope detection (magnitude of each sample).
fn demod_am(samples: &[Complex<f32>]) -> Vec<f32> {
    let magnitudes: Vec<f32> = samples.iter().map(|s| s.norm()).collect();
    // Remove DC offset (mean) and normalize.
    let mean = magnitudes.iter().sum::<f32>() / magnitudes.len() as f32;
    let max_dev = magnitudes
        .iter()
        .map(|m| (m - mean).abs())
        .fold(0.0_f32, f32::max);
    let scale = if max_dev > 0.0 { 1.0 / max_dev } else { 1.0 };
    magnitudes.iter().map(|m| (m - mean) * scale).collect()
}

/// SSB demodulation via frequency shift (simple baseband shift). This is a
/// minimal implementation — shifts the signal to audio baseband by taking the
/// real component (equivalent to a product detector with a zero-offset LO).
fn demod_ssb(samples: &[Complex<f32>]) -> Vec<f32> {
    // For a basic SSB demod, the real part of the analytic signal after
    // frequency correction gives the audio. Without a proper BFO offset,
    // we take the real part directly (adequate for file-proof verification).
    let max_abs = samples.iter().map(|s| s.re.abs()).fold(0.0_f32, f32::max);
    let scale = if max_abs > 0.0 { 1.0 / max_abs } else { 1.0 };
    samples.iter().map(|s| s.re * scale).collect()
}

/// Digital demodulation: hard-decision on the sign of the real component
/// after quadrature demod (BPSK-like). Bounded output.
fn demod_digital(samples: &[Complex<f32>]) -> Vec<u8> {
    let fm = demod_fm(samples);
    fm.iter().map(|&s| if s >= 0.0 { 1 } else { 0 }).collect()
}
