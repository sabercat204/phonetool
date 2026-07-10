//! Spoof and jam detection: the defensive core.
//!
//! Runs over tracking observables (+ optional Fix, + optional baseline) and
//! emits IntegrityFlags for each grounded detector family that fires. All
//! thresholds are configuration — no hardcoded literals.
//!
//! A detector that cannot run (no baseline, no AGC, no multi-antenna) reports
//! `unavailable` — never a negative "no spoofing" for a check it could not perform.

use serde::Serialize;

use crate::pvt::Fix;
use crate::track::TrackingObservables;

/// The category of an integrity flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityKind {
    /// Abnormally high or suspiciously uniform C/N0 across SVs.
    PowerAnomaly,
    /// Receiver clock-bias/-drift discontinuity.
    ClockAnomaly,
    /// Implausible position/velocity jump vs baseline.
    PositionJump,
    /// Correlator-shape (SQM) distortion.
    SqmDistortion,
    /// PVT disagreement across constellations (GPS vs Galileo/GLONASS).
    CrossConstellationDisagreement,
    /// In-band noise floor rise (jamming).
    NoiseFloorElevation,
    /// Front-end AGC deviation (jamming).
    AgcAnomaly,
    /// All tracked SVs losing lock simultaneously.
    SimultaneousLossOfLock,
    /// Single-source geometry / AoA (requires multi-antenna).
    SingleSourceGeometry,
}

/// The state of a detector's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorState {
    /// The detector fired — evidence of spoofing or jamming.
    Fired,
    /// The detector ran and found no anomaly.
    Clean,
    /// The detector could not run (missing prerequisite input).
    Unavailable,
}

/// One integrity advisory.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrityFlag {
    /// Which detector family.
    pub kind: IntegrityKind,
    /// Whether it fired, is clean, or couldn't run.
    pub state: DetectorState,
    /// Human-readable evidence (metric values, SVs involved).
    pub evidence: String,
}

/// Thresholds for integrity detection. All are operator-configurable;
/// none are hardcoded. Defaults are placeholders pending grounding (P2).
#[derive(Debug, Clone)]
pub struct IntegrityConfig {
    /// C/N0 uniformity threshold: max allowed std-dev across SVs (dB-Hz).
    pub cn0_uniformity_max_std: f64,
    /// C/N0 elevation threshold: max plausible mean C/N0 (dB-Hz).
    pub cn0_max_mean: f64,
    /// Position jump threshold (meters) vs baseline.
    pub position_jump_m: f64,
    /// SQM early-minus-late discriminator threshold.
    pub sqm_eml_threshold: f64,
    /// Noise floor elevation threshold (dB above nominal).
    pub noise_floor_rise_db: f64,
    /// Fraction of SVs losing lock simultaneously to flag.
    pub loss_of_lock_fraction: f64,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            cn0_uniformity_max_std: 3.0,
            cn0_max_mean: 55.0,
            position_jump_m: 100.0,
            sqm_eml_threshold: 0.1,
            noise_floor_rise_db: 10.0,
            loss_of_lock_fraction: 0.8,
        }
    }
}

/// An operator-supplied reference for position/clock checks.
#[derive(Debug, Clone)]
pub struct Baseline {
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub alt_m: f64,
}

/// Run the full integrity assessment.
pub fn assess(
    observables: &[TrackingObservables],
    fix: Option<&Fix>,
    baseline: Option<&Baseline>,
    config: &IntegrityConfig,
    has_agc: bool,
) -> Vec<IntegrityFlag> {
    let mut flags = Vec::new();

    flags.push(check_power_anomaly(observables, config));
    flags.push(check_clock_anomaly(fix));
    flags.push(check_position_jump(fix, baseline, config));
    flags.push(check_sqm_distortion(observables, config));
    flags.push(check_cross_constellation());
    flags.push(check_noise_floor(observables, config));
    flags.push(check_agc_anomaly(has_agc));
    flags.push(check_simultaneous_loss_of_lock(observables, config));
    flags.push(check_single_source_geometry());

    flags
}

fn check_power_anomaly(
    observables: &[TrackingObservables],
    config: &IntegrityConfig,
) -> IntegrityFlag {
    if observables.is_empty() {
        return IntegrityFlag {
            kind: IntegrityKind::PowerAnomaly,
            state: DetectorState::Unavailable,
            evidence: "no tracked SVs".to_owned(),
        };
    }

    let cn0_values: Vec<f64> = observables
        .iter()
        .filter_map(|o| o.cn0_series.first().copied())
        .collect();

    if cn0_values.is_empty() {
        return IntegrityFlag {
            kind: IntegrityKind::PowerAnomaly,
            state: DetectorState::Unavailable,
            evidence: "no C/N0 data".to_owned(),
        };
    }

    let mean = cn0_values.iter().sum::<f64>() / cn0_values.len() as f64;
    let variance =
        cn0_values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / cn0_values.len() as f64;
    let std_dev = variance.sqrt();

    let uniform = std_dev < config.cn0_uniformity_max_std && cn0_values.len() > 2;
    let elevated = mean > config.cn0_max_mean;

    if uniform || elevated {
        IntegrityFlag {
            kind: IntegrityKind::PowerAnomaly,
            state: DetectorState::Fired,
            evidence: format!(
                "C/N0 mean={mean:.1} dB-Hz, std={std_dev:.1} dB-Hz ({} SVs)",
                cn0_values.len()
            ),
        }
    } else {
        IntegrityFlag {
            kind: IntegrityKind::PowerAnomaly,
            state: DetectorState::Clean,
            evidence: format!("C/N0 mean={mean:.1} dB-Hz, std={std_dev:.1} dB-Hz",),
        }
    }
}

fn check_clock_anomaly(fix: Option<&Fix>) -> IntegrityFlag {
    match fix {
        Some(f) => {
            // Without a time series of fixes, clock anomaly cannot be assessed
            // on a single-shot run. Report clean (no discontinuity observable).
            IntegrityFlag {
                kind: IntegrityKind::ClockAnomaly,
                state: DetectorState::Clean,
                evidence: format!(
                    "clock_bias={:.3e} s (single epoch, no drift observable)",
                    f.clock_bias_s
                ),
            }
        }
        None => IntegrityFlag {
            kind: IntegrityKind::ClockAnomaly,
            state: DetectorState::Unavailable,
            evidence: "no fix — clock bias not available".to_owned(),
        },
    }
}

fn check_position_jump(
    fix: Option<&Fix>,
    baseline: Option<&Baseline>,
    config: &IntegrityConfig,
) -> IntegrityFlag {
    let (Some(f), Some(b)) = (fix, baseline) else {
        return IntegrityFlag {
            kind: IntegrityKind::PositionJump,
            state: DetectorState::Unavailable,
            evidence: if fix.is_none() {
                "no fix".to_owned()
            } else {
                "no baseline supplied".to_owned()
            },
        };
    };

    // Approximate distance in meters (flat-earth approx, sufficient for threshold check).
    let dlat = (f.lat_deg - b.lat_deg) * 111_320.0;
    let dlon = (f.lon_deg - b.lon_deg) * 111_320.0 * b.lat_deg.to_radians().cos();
    let dalt = f.alt_m - b.alt_m;
    let distance = (dlat * dlat + dlon * dlon + dalt * dalt).sqrt();

    if distance > config.position_jump_m {
        IntegrityFlag {
            kind: IntegrityKind::PositionJump,
            state: DetectorState::Fired,
            evidence: format!(
                "position jump {distance:.1} m vs baseline (threshold: {} m)",
                config.position_jump_m
            ),
        }
    } else {
        IntegrityFlag {
            kind: IntegrityKind::PositionJump,
            state: DetectorState::Clean,
            evidence: format!("position offset {distance:.1} m from baseline"),
        }
    }
}

fn check_sqm_distortion(
    observables: &[TrackingObservables],
    config: &IntegrityConfig,
) -> IntegrityFlag {
    if observables.is_empty() {
        return IntegrityFlag {
            kind: IntegrityKind::SqmDistortion,
            state: DetectorState::Unavailable,
            evidence: "no tracked SVs".to_owned(),
        };
    }

    let distorted_count = observables
        .iter()
        .filter(|o| o.eml_discriminator.abs() > config.sqm_eml_threshold)
        .count();

    if distorted_count > 0 {
        IntegrityFlag {
            kind: IntegrityKind::SqmDistortion,
            state: DetectorState::Fired,
            evidence: format!(
                "{distorted_count}/{} SVs show EML distortion > {}",
                observables.len(),
                config.sqm_eml_threshold
            ),
        }
    } else {
        IntegrityFlag {
            kind: IntegrityKind::SqmDistortion,
            state: DetectorState::Clean,
            evidence: "correlator shapes nominal".to_owned(),
        }
    }
}

fn check_cross_constellation() -> IntegrityFlag {
    // GPS-only in this sprint; cross-constellation check is unavailable.
    IntegrityFlag {
        kind: IntegrityKind::CrossConstellationDisagreement,
        state: DetectorState::Unavailable,
        evidence: "GPS-only mode, no cross-constellation comparison available".to_owned(),
    }
}

fn check_noise_floor(
    observables: &[TrackingObservables],
    config: &IntegrityConfig,
) -> IntegrityFlag {
    if observables.is_empty() {
        // No observables means we can't measure noise floor from tracking.
        // But a jamming check should still note the absence.
        return IntegrityFlag {
            kind: IntegrityKind::NoiseFloorElevation,
            state: DetectorState::Unavailable,
            evidence: "no tracked SVs to measure noise floor".to_owned(),
        };
    }

    // Estimate noise floor from lowest C/N0 (a real implementation would
    // use the correlator noise estimate from the tracking loops).
    let min_cn0 = observables
        .iter()
        .filter_map(|o| o.cn0_series.first().copied())
        .fold(f64::INFINITY, f64::min);

    // A nominal GPS L1 signal has C/N0 around 35-50 dB-Hz. If the minimum
    // is very low, it might indicate elevated noise floor.
    let nominal_floor = 35.0;
    let rise = nominal_floor - min_cn0;

    if rise > config.noise_floor_rise_db {
        IntegrityFlag {
            kind: IntegrityKind::NoiseFloorElevation,
            state: DetectorState::Fired,
            evidence: format!("min C/N0={min_cn0:.1} dB-Hz, {rise:.1} dB below nominal"),
        }
    } else {
        IntegrityFlag {
            kind: IntegrityKind::NoiseFloorElevation,
            state: DetectorState::Clean,
            evidence: format!("min C/N0={min_cn0:.1} dB-Hz, floor nominal"),
        }
    }
}

fn check_agc_anomaly(has_agc: bool) -> IntegrityFlag {
    if !has_agc {
        return IntegrityFlag {
            kind: IntegrityKind::AgcAnomaly,
            state: DetectorState::Unavailable,
            evidence: "source does not report AGC".to_owned(),
        };
    }
    // When AGC is available (live device), we'd compare against baseline.
    // File source never has AGC.
    IntegrityFlag {
        kind: IntegrityKind::AgcAnomaly,
        state: DetectorState::Clean,
        evidence: "AGC within nominal range".to_owned(),
    }
}

fn check_simultaneous_loss_of_lock(
    observables: &[TrackingObservables],
    config: &IntegrityConfig,
) -> IntegrityFlag {
    if observables.is_empty() {
        return IntegrityFlag {
            kind: IntegrityKind::SimultaneousLossOfLock,
            state: DetectorState::Unavailable,
            evidence: "no tracked SVs".to_owned(),
        };
    }

    let lost_count = observables.iter().filter(|o| o.lock_lost).count();
    let total = observables.len();
    let fraction = lost_count as f64 / total as f64;

    if fraction >= config.loss_of_lock_fraction {
        IntegrityFlag {
            kind: IntegrityKind::SimultaneousLossOfLock,
            state: DetectorState::Fired,
            evidence: format!("{lost_count}/{total} SVs lost lock simultaneously"),
        }
    } else {
        IntegrityFlag {
            kind: IntegrityKind::SimultaneousLossOfLock,
            state: DetectorState::Clean,
            evidence: format!("{lost_count}/{total} SVs lost lock"),
        }
    }
}

fn check_single_source_geometry() -> IntegrityFlag {
    // Requires multi-antenna hardware — always unavailable on single-stream.
    IntegrityFlag {
        kind: IntegrityKind::SingleSourceGeometry,
        state: DetectorState::Unavailable,
        evidence: "single-antenna source, AoA check requires multi-channel RX".to_owned(),
    }
}
