//! PSD/periodogram: magnitude-squared FFT bins → `Vec<(freq_hz, power_db)>`.

use num_complex::Complex;
use rustfft::FftPlanner;

use crate::source::SampleBlock;

/// One bin of the power spectral density estimate.
#[derive(Debug, Clone, Copy)]
pub struct PsdBin {
    /// Center frequency of this bin in Hz.
    pub freq_hz: f64,
    /// Power in dB (10 * log10 of magnitude squared, normalized).
    pub power_db: f64,
}

/// Compute the power spectral density of a sample block using a periodogram
/// (single FFT, magnitude-squared). Returns one `PsdBin` per FFT bin, ordered
/// from the lowest frequency to the highest (DC-centered via FFT shift).
///
/// `fft_size` controls resolution; if the block has fewer samples, the block
/// length is used. Returns an empty vec only if samples is empty (caller should
/// check for the degenerate case before calling).
pub fn periodogram(block: &SampleBlock, fft_size: usize) -> Vec<PsdBin> {
    if block.samples.is_empty() {
        return Vec::new();
    }

    let n = fft_size.min(block.samples.len());
    let mut planner = FftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(n);

    let mut buffer: Vec<Complex<f32>> = block.samples.iter().take(n).copied().collect();
    fft.process(&mut buffer);

    let norm = 1.0 / (n as f64);
    let sample_rate = block.sample_rate;
    let center = block.center_freq;
    let bin_width = sample_rate / n as f64;

    // FFT shift: reorder so DC is in the center → lowest freq first.
    let mut bins = Vec::with_capacity(n);
    for i in 0..n {
        let fft_idx = (i + n / 2) % n;
        let sample = buffer.get(fft_idx).copied().unwrap_or_default();
        let mag_sq = (sample.re as f64).powi(2) + (sample.im as f64).powi(2);
        let power_db = if mag_sq > 0.0 {
            10.0 * (mag_sq * norm).log10()
        } else {
            -200.0
        };
        let freq_offset = (i as f64 - n as f64 / 2.0) * bin_width;
        bins.push(PsdBin {
            freq_hz: center + freq_offset,
            power_db,
        });
    }

    bins
}
