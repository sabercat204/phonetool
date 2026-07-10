//! Per-SV tracking: code/carrier loops producing observables.
//!
//! Produces the time-series data that both PVT and integrity consume:
//! correlator outputs (E/P/L), carrier phase, and C/N0 over time.

use crate::acquire::AcquiredSv;

/// Per-SV tracking observables over a tracking interval.
#[derive(Debug, Clone)]
pub struct TrackingObservables {
    /// PRN of the tracked satellite.
    pub prn: u8,
    /// C/N0 time series (dB-Hz) — one sample per tracking epoch.
    pub cn0_series: Vec<f64>,
    /// Carrier phase accumulation (cycles).
    pub carrier_phase: f64,
    /// Code phase at end of tracking (chips).
    pub code_phase: f64,
    /// Prompt correlator magnitude (for SQM).
    pub prompt_magnitude: f64,
    /// Early-minus-late normalized discriminator (for SQM distortion detection).
    pub eml_discriminator: f64,
    /// Whether tracking was lost during the interval.
    pub lock_lost: bool,
}

/// Track acquired SVs through the provided samples.
///
/// This is a simplified tracking model sufficient for the file-proof path:
/// it produces the observables the integrity detectors need (C/N0 series,
/// carrier phase, correlator metrics) from the acquisition results and
/// sample statistics. A full DLL/PLL implementation ships with Tier-B or
/// a later native build.
pub fn track(
    acquired: &[AcquiredSv],
    sample_count: usize,
    sample_rate: f64,
) -> Vec<TrackingObservables> {
    if acquired.is_empty() || sample_count == 0 {
        return Vec::new();
    }

    let integration_ms = (sample_count as f64 / sample_rate * 1000.0) as usize;
    let epochs = integration_ms.max(1);

    acquired
        .iter()
        .map(|sv| {
            // Model tracking observables from acquisition C/N0.
            // In the file-proof path, the acquisition C/N0 is propagated as the
            // tracking C/N0 (a real DLL/PLL would refine it).
            let cn0_series = vec![sv.cn0_dbhz; epochs];
            let carrier_phase = sv.doppler_hz * (sample_count as f64 / sample_rate);
            let prompt_magnitude = 10.0_f64.powf(sv.cn0_dbhz / 20.0);
            let eml_discriminator = 0.0; // centered when tracking is nominal

            TrackingObservables {
                prn: sv.prn,
                cn0_series,
                carrier_phase,
                code_phase: sv.code_phase,
                prompt_magnitude,
                eml_discriminator,
                lock_lost: false,
            }
        })
        .collect()
}
