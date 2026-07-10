//! A dependency-free Goertzel single-bin tone detector over PCM.
//!
//! Goertzel is a single-bin DFT: it computes the energy at one target frequency
//! far more cheaply than a full FFT. The recurrence is standard textbook DSP
//! (Goertzel, 1958; see any DSP reference) — it is *math*, not a confabulation-
//! risky physical constant, so the algorithm ships today.
//!
//! **What deliberately does NOT ship: the tone targets.** SIT segment
//! frequencies/durations (Telcordia / ITU-T), fax CNG (T.30, ~1100 Hz), and CED /
//! answer tone (V.25 / V.8, ~2100 Hz) carry specific frequencies, tolerances,
//! durations, cadences, and a detection-confidence threshold that MUST be grounded
//! in the governing standards at build time (Requirement 6.3, Open Question 4).
//! Stating them from memory risks confabulation, so this module exposes only the
//! detector primitive; the numbers that configure it are supplied by the caller.
//! There is no substrate feeding this yet regardless — no media path receives RTP
//! (see the crate docs).

/// A single-bin Goertzel detector configured for one target frequency, sample
/// rate, and analysis block length. Pure DSP; holds no baked-in tone constants.
#[derive(Debug, Clone, Copy)]
pub struct Goertzel {
    coeff: f32,
    sample_rate: f32,
    block_len: usize,
}

/// The readout of one Goertzel analysis over a PCM block.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ToneEnergy {
    /// Normalized energy at the target frequency, in `[0, ~1]` for a pure tone at
    /// full scale. This is `raw_power / (block_len/2 * signal_energy)`-shaped; the
    /// caller compares it against a *grounded* confidence threshold (OQ4).
    pub normalized: f32,
    /// The number of samples actually analyzed (may be shorter than `block_len`
    /// if the input was shorter — never longer, never out of bounds).
    pub samples: usize,
}

impl Goertzel {
    /// Configure a detector. `target_hz` is the frequency to look for; the caller
    /// supplies it (a grounded SIT/CNG/CED frequency, or a test tone) — this
    /// constructor invents nothing.
    ///
    /// Returns `None` if the configuration is degenerate (non-positive sample
    /// rate, zero block length, or a target at/above Nyquist), so a bad config is
    /// a typed refusal, never a NaN or a panic.
    #[must_use]
    pub fn new(target_hz: f32, sample_rate: f32, block_len: usize) -> Option<Self> {
        // Reject degenerate configs, including NaN (which fails every comparison):
        // require finite, positive sample rate and target, and a non-zero block.
        if !sample_rate.is_finite()
            || sample_rate <= 0.0
            || block_len == 0
            || !target_hz.is_finite()
            || target_hz <= 0.0
        {
            return None;
        }
        if target_hz >= sample_rate / 2.0 {
            return None; // at or above Nyquist — not detectable
        }
        // k = round(block_len * target/fs); omega = 2π k / block_len; coeff = 2cos(omega).
        let k = (block_len as f32 * target_hz / sample_rate).round();
        let omega = 2.0 * std::f32::consts::PI * k / block_len as f32;
        let coeff = 2.0 * omega.cos();
        Some(Self {
            coeff,
            sample_rate,
            block_len,
        })
    }

    /// The sample rate this detector was configured for.
    #[must_use]
    pub fn sample_rate(&self) -> f32 {
        self.sample_rate
    }

    /// Run the Goertzel recurrence over up to `block_len` samples of `pcm` and
    /// return the normalized energy at the target frequency. Total: reads at most
    /// `block_len` samples, never indexes out of bounds, and returns a finite
    /// number (0.0 for empty or all-zero input).
    #[must_use]
    pub fn analyze(&self, pcm: &[f32]) -> ToneEnergy {
        let n = pcm.len().min(self.block_len);
        let mut s_prev: f32 = 0.0;
        let mut s_prev2: f32 = 0.0;
        let mut signal_energy: f32 = 0.0;
        for &x in pcm.iter().take(n) {
            let s = x + self.coeff * s_prev - s_prev2;
            s_prev2 = s_prev;
            s_prev = s;
            signal_energy += x * x;
        }
        // Goertzel power at the bin.
        let power = s_prev2 * s_prev2 + s_prev * s_prev - self.coeff * s_prev * s_prev2;

        // Normalize against total signal energy so the readout is roughly the
        // fraction of energy at the target bin, comparable across block sizes and
        // amplitudes. Guard the divide: silence → 0.0, never NaN.
        let normalized = if signal_energy > f32::EPSILON && n > 0 {
            // power scales ~ (n/2)^2 * A^2 for a pure tone of amplitude A, whose
            // signal_energy ~ n * A^2/2. The ratio power / ((n/2) * signal_energy)
            // lands near 1.0 for a matched pure tone, near 0 for out-of-band.
            let denom = (n as f32 / 2.0) * signal_energy;
            if denom > f32::EPSILON {
                (power / denom).clamp(0.0, f32::MAX)
            } else {
                0.0
            }
        } else {
            0.0
        };

        ToneEnergy {
            normalized,
            samples: n,
        }
    }
}

/// Generate a pure sine tone into a PCM buffer — a **test/fixture helper**, not a
/// wire path. Public so integration tests can build synthetic tones without an
/// RNG or a fixture file.
#[must_use]
pub fn synth_tone(freq_hz: f32, sample_rate: f32, samples: usize, amplitude: f32) -> Vec<f32> {
    let mut out = Vec::with_capacity(samples);
    for i in 0..samples {
        let t = i as f32 / sample_rate;
        out.push(amplitude * (2.0 * std::f32::consts::PI * freq_hz * t).sin());
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const FS: f32 = 8000.0; // G.711 rate — the band the wardial's tones live in
    const BLOCK: usize = 800; // 100 ms

    #[test]
    fn detects_a_matched_tone_and_rejects_an_off_band_one() {
        // A detector tuned to 1000 Hz should light up on a 1000 Hz tone and stay
        // quiet on a 300 Hz tone. (Frequencies chosen for the TEST — not asserted
        // as any standard's SIT/CNG/CED value.)
        let det = Goertzel::new(1000.0, FS, BLOCK).expect("valid config");
        let on = det.analyze(&synth_tone(1000.0, FS, BLOCK, 0.9));
        let off = det.analyze(&synth_tone(300.0, FS, BLOCK, 0.9));
        assert!(
            on.normalized > off.normalized * 5.0,
            "matched {on:?} should dominate off-band {off:?}"
        );
    }

    #[test]
    fn silence_reads_zero_energy_never_nan() {
        let det = Goertzel::new(1000.0, FS, BLOCK).expect("valid");
        let e = det.analyze(&vec![0.0; BLOCK]);
        assert_eq!(e.normalized, 0.0);
        assert!(e.normalized.is_finite());
    }

    #[test]
    fn empty_input_is_zero_not_a_panic() {
        let det = Goertzel::new(1000.0, FS, BLOCK).expect("valid");
        let e = det.analyze(&[]);
        assert_eq!(e.samples, 0);
        assert_eq!(e.normalized, 0.0);
    }

    #[test]
    fn input_longer_than_block_is_truncated_not_overread() {
        let det = Goertzel::new(1000.0, FS, BLOCK).expect("valid");
        let e = det.analyze(&synth_tone(1000.0, FS, BLOCK * 4, 0.5));
        assert_eq!(e.samples, BLOCK, "analyzes at most block_len samples");
    }

    #[test]
    fn degenerate_configs_are_refused() {
        assert!(Goertzel::new(1000.0, 0.0, BLOCK).is_none());
        assert!(Goertzel::new(1000.0, FS, 0).is_none());
        assert!(Goertzel::new(0.0, FS, BLOCK).is_none());
        assert!(
            Goertzel::new(5000.0, FS, BLOCK).is_none(),
            "at/above Nyquist"
        );
    }
}
