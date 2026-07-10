//! Energy detection over sweep bins: signals above a threshold →
//! `Vec<DetectedSignal>`.

use crate::classify::Modulation;
use crate::dsp::sweep::PsdBin;

/// One detected emission in the swept band.
#[derive(Debug, Clone)]
pub struct DetectedSignal {
    /// Estimated center frequency in Hz.
    pub center_hz: f64,
    /// Estimated occupied bandwidth in Hz.
    pub bandwidth_hz: f64,
    /// Peak power in dB.
    pub power_db: f64,
    /// Modulation estimate (may be `Unknown`).
    pub modulation: Modulation,
}

/// Detect signals above `threshold_db` in the PSD bins. Groups adjacent
/// above-threshold bins into a single detected signal. Returns an empty vec
/// when the band is quiet (a real observation, not a failure).
pub fn detect(
    bins: &[PsdBin],
    threshold_db: f64,
    classify_bw: &BandwidthClassifier,
) -> Vec<DetectedSignal> {
    if bins.is_empty() {
        return Vec::new();
    }

    let mut signals = Vec::new();
    let mut run_start: Option<usize> = None;

    for (i, bin) in bins.iter().enumerate() {
        if bin.power_db >= threshold_db {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start.take() {
            signals.push(signal_from_run(bins, start, i, classify_bw));
        }
    }
    // Close any trailing run.
    if let Some(start) = run_start {
        signals.push(signal_from_run(bins, start, bins.len(), classify_bw));
    }

    signals
}

fn signal_from_run(
    bins: &[PsdBin],
    start: usize,
    end: usize,
    classify_bw: &BandwidthClassifier,
) -> DetectedSignal {
    let slice = bins.get(start..end).unwrap_or_default();
    let peak = slice
        .iter()
        .map(|b| b.power_db)
        .fold(f64::NEG_INFINITY, f64::max);
    let lo = slice.first().map_or(0.0, |b| b.freq_hz);
    let hi = slice.last().map_or(0.0, |b| b.freq_hz);
    let bandwidth_hz = hi - lo;
    let center_hz = (lo + hi) / 2.0;
    let modulation = classify_bw.classify(bandwidth_hz);

    DetectedSignal {
        center_hz,
        bandwidth_hz,
        power_db: peak,
        modulation,
    }
}

/// Bandwidth-based modulation classifier. All thresholds are configuration,
/// not hardcoded literals.
#[derive(Debug, Clone)]
pub struct BandwidthClassifier {
    /// Signals narrower than this (Hz) are classified as AM/CW.
    pub am_max_bw: f64,
    /// Signals between am_max_bw and this are classified as SSB.
    pub ssb_max_bw: f64,
    /// Signals between ssb_max_bw and this are classified as FM.
    pub fm_max_bw: f64,
}

impl Default for BandwidthClassifier {
    fn default() -> Self {
        Self {
            am_max_bw: 10_000.0,
            ssb_max_bw: 4_000.0,
            fm_max_bw: 200_000.0,
        }
    }
}

impl BandwidthClassifier {
    /// Classify a signal by its occupied bandwidth. Returns `Unknown` when the
    /// bandwidth doesn't fit any confident category.
    pub fn classify(&self, bandwidth_hz: f64) -> Modulation {
        if bandwidth_hz <= 0.0 {
            return Modulation::Unknown;
        }
        if bandwidth_hz <= self.ssb_max_bw {
            Modulation::Ssb
        } else if bandwidth_hz <= self.am_max_bw {
            Modulation::Am
        } else if bandwidth_hz <= self.fm_max_bw {
            Modulation::Fm
        } else {
            Modulation::Unknown
        }
    }
}
