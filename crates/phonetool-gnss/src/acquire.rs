//! GPS L1 C/A acquisition: coarse search over PRN × Doppler × code-phase.
//!
//! Detects which satellites are present in an IQ block and estimates each one's
//! code phase, Doppler shift, and carrier-to-noise density (C/N0).

use num_complex::Complex;
use rustfft::FftPlanner;

use crate::constants::{CA_CHIP_RATE, CA_CODE_LEN};
use crate::gold;
use phonetool_sdr_rx::source::SampleBlock;

/// One acquired satellite.
#[derive(Debug, Clone)]
pub struct AcquiredSv {
    /// PRN number (1–32).
    pub prn: u8,
    /// Estimated code phase in chips (0..1023).
    pub code_phase: f64,
    /// Estimated Doppler shift in Hz.
    pub doppler_hz: f64,
    /// Estimated carrier-to-noise density in dB-Hz.
    pub cn0_dbhz: f64,
}

/// Acquisition configuration.
#[derive(Debug, Clone)]
pub struct AcquireConfig {
    /// Doppler search range (±Hz from nominal). Typical: ±5000 Hz.
    pub doppler_range_hz: f64,
    /// Doppler search step (Hz). Typical: 500 Hz.
    pub doppler_step_hz: f64,
    /// Acquisition threshold: peak/mean ratio above which a PRN is detected.
    pub threshold: f64,
    /// Which PRNs to search (1–32).
    pub prns: Vec<u8>,
}

impl Default for AcquireConfig {
    fn default() -> Self {
        Self {
            doppler_range_hz: 5000.0,
            doppler_step_hz: 500.0,
            threshold: 2.5,
            prns: (1..=32).collect(),
        }
    }
}

/// Acquire GPS L1 C/A satellites in the given sample block.
/// Returns SVs whose correlation peak exceeds the configured threshold.
pub fn acquire(block: &SampleBlock, config: &AcquireConfig) -> Vec<AcquiredSv> {
    if block.samples.is_empty() {
        return Vec::new();
    }

    let fs = block.sample_rate;
    let n = block.samples.len().min(fs as usize); // use up to 1ms worth of samples
    if n < 2 {
        return Vec::new();
    }

    let mut results = Vec::new();
    let mut planner = FftPlanner::<f32>::new();
    let fft_fwd = planner.plan_fft_forward(n);
    let fft_inv = planner.plan_fft_inverse(n);

    for &prn in &config.prns {
        let code = match gold::generate_ca_code(prn) {
            Some(c) => c,
            None => continue,
        };

        // Resample the C/A code to match the sample rate (samples per chip).
        let code_sampled = resample_code(&code, fs, n);

        // FFT of the code (conjugated for correlation).
        let mut code_fft: Vec<Complex<f32>> =
            code_sampled.iter().map(|&c| Complex::new(c, 0.0)).collect();
        fft_fwd.process(&mut code_fft);
        for c in &mut code_fft {
            *c = c.conj();
        }

        let mut best_peak = 0.0_f64;
        let mut best_doppler = 0.0_f64;
        let mut best_code_phase = 0.0_f64;
        let mut best_mean = 1.0_f64;

        // Search Doppler bins.
        let steps = (config.doppler_range_hz / config.doppler_step_hz) as i32;
        for d in -steps..=steps {
            let doppler = d as f64 * config.doppler_step_hz;

            // Wipe the Doppler from the signal.
            let wiped: Vec<Complex<f32>> = block
                .samples
                .iter()
                .take(n)
                .enumerate()
                .map(|(i, &s)| {
                    let t = i as f64 / fs;
                    let phase = -2.0 * std::f64::consts::PI * doppler * t;
                    let rot = Complex::new(phase.cos() as f32, phase.sin() as f32);
                    s * rot
                })
                .collect();

            // FFT of the wiped signal.
            let mut sig_fft = wiped;
            fft_fwd.process(&mut sig_fft);

            // Circular correlation = IFFT(sig_fft * conj(code_fft)).
            let mut corr: Vec<Complex<f32>> = sig_fft
                .iter()
                .zip(code_fft.iter())
                .map(|(s, c)| s * c)
                .collect();
            fft_inv.process(&mut corr);

            // Find peak magnitude.
            let scale = 1.0 / n as f64;
            let magnitudes: Vec<f64> = corr.iter().map(|c| c.norm() as f64 * scale).collect();
            let sum: f64 = magnitudes.iter().sum();
            let mean = sum / magnitudes.len() as f64;

            let (peak_idx, &peak_val) = magnitudes
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or((0, &0.0));

            if peak_val > best_peak {
                best_peak = peak_val;
                best_doppler = doppler;
                best_code_phase = peak_idx as f64 * (CA_CODE_LEN as f64 / n as f64);
                best_mean = mean;
            }
        }

        // Check against threshold.
        let ratio = if best_mean > 0.0 {
            best_peak / best_mean
        } else {
            0.0
        };

        if ratio >= config.threshold {
            let cn0 = if best_mean > 0.0 {
                10.0 * (best_peak / best_mean).log10() + 30.0 // rough estimate
            } else {
                0.0
            };

            results.push(AcquiredSv {
                prn,
                code_phase: best_code_phase,
                doppler_hz: best_doppler,
                cn0_dbhz: cn0,
            });
        }
    }

    results
}

/// Resample a 1023-chip C/A code to `n` samples at sample rate `fs`.
fn resample_code(code: &[i8], fs: f64, n: usize) -> Vec<f32> {
    let samples_per_chip = fs / CA_CHIP_RATE;
    (0..n)
        .map(|i| {
            let chip_idx = ((i as f64 / samples_per_chip) as usize) % CA_CODE_LEN;
            code.get(chip_idx).copied().unwrap_or(1) as f32
        })
        .collect()
}
