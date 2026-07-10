//! `phonetool-gnss` — passive GNSS receive + spoof/jam integrity plugin.
//!
//! Acquires GPS L1 C/A, decodes nav message, solves PVT, and qualifies every
//! fix with a spoof/jam integrity verdict. The integrity assessment is the
//! defensive payload — it runs even when no fix is obtained.
//!
//! Runs today on `IqFileSource` (no antenna). The full pipeline is:
//! acquire → track → (decode) → PVT → integrity.
//!
//! ## Example (compile-fail proof: `GnssRx` is NOT `ActivePlugin`)
//!
//! ```compile_fail
//! use phonetool_core::ActivePlugin;
//! use phonetool_gnss::GnssRx;
//! fn require_active(_p: &dyn ActivePlugin) {}
//! fn check(g: &GnssRx) { require_active(g); }
//! ```

pub mod acquire;
pub mod constants;
pub mod gold;
pub mod integrity;
pub mod navmsg;
pub mod navsync;
pub mod pvt;
pub mod track;

use std::path::Path;

use phonetool_core::{CapabilityClass, Command, Event, Manifest, Plugin, PluginError, Transducer};
use phonetool_sdr_rx::source::{IqFileSource, SdrSource};
use serde_json::json;

use crate::acquire::{AcquireConfig, AcquiredSv, acquire};
use crate::integrity::{Baseline, DetectorState, IntegrityConfig, assess};
use crate::navmsg::{Ephemeris, decode_subframe};
use crate::navsync::{
    correlate_prompts, demod_navbits, estimate_bit_phase, find_preambles, subframe_bits,
};
use crate::pvt::solve;
use crate::track::track;
use phonetool_sdr_rx::source::SampleBlock;

/// Configuration for the GNSS plugin.
#[derive(Debug, Clone)]
pub struct GnssConfig {
    /// Maximum samples to read from source.
    pub sample_cap: usize,
    /// Expected sample rate for GPS L1 (Hz). Default: 2.048 MHz.
    pub sample_rate: f64,
    /// Expected center frequency (Hz). Default: L1 = 1575.42 MHz.
    pub center_freq: f64,
    /// Acquisition configuration.
    pub acquire: AcquireConfig,
    /// Integrity detection thresholds.
    pub integrity: IntegrityConfig,
    /// Optional operator-supplied baseline for position-jump detection.
    pub baseline: Option<Baseline>,
}

impl Default for GnssConfig {
    fn default() -> Self {
        Self {
            sample_cap: 16 * 1024 * 1024,
            sample_rate: 2_048_000.0,
            center_freq: crate::constants::L1_CARRIER_HZ,
            acquire: AcquireConfig::default(),
            integrity: IntegrityConfig::default(),
            baseline: None,
        }
    }
}

/// The passive GNSS receive + integrity plugin.
pub struct GnssRx {
    config: GnssConfig,
}

impl GnssRx {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: GnssConfig::default(),
        }
    }

    #[must_use]
    pub fn with_config(config: GnssConfig) -> Self {
        Self { config }
    }

    fn do_fix(&self, path: &Path) -> Result<Event, PluginError> {
        let mut source = IqFileSource::open(
            path,
            self.config.sample_rate,
            self.config.center_freq,
            self.config.sample_cap,
        )?;
        let block = source.read_block(self.config.sample_cap)?;
        if block.samples.is_empty() {
            return Err(PluginError::Empty(format!(
                "zero samples in GNSS capture: {}",
                path.display()
            )));
        }

        // Acquire: search for GPS L1 C/A satellites.
        let acquired = acquire(&block, &self.config.acquire);

        // Track: produce per-SV observables.
        let observables = track(&acquired, block.samples.len(), block.sample_rate);

        // Nav recovery: bit sync → demod → frame sync → parity-gated decode.
        // On the file-proof path (short fixtures) this honestly yields nothing;
        // a capture spanning multiple subframes produces a real ephemeris.
        let nav = decode_nav(&block, &acquired);

        // PVT solve. If nav recovered a complete ephemeris, a full position
        // solve becomes possible once pseudoranges are wired (still pending);
        // until then the observable-only path returns an honest None.
        let fix = solve(&observables);

        // Integrity: run spoof/jam assessment over observables + fix + baseline.
        let flags = assess(
            &observables,
            fix.as_ref(),
            self.config.baseline.as_ref(),
            &self.config.integrity,
            false, // IqFileSource never has AGC
        );

        // Degenerate discipline: nothing observed = failure.
        let has_flags = flags.iter().any(|f| f.state == DetectorState::Fired);
        if acquired.is_empty() && fix.is_none() && !has_flags {
            return Err(PluginError::Empty(format!(
                "no satellites acquired, no fix, no integrity signal from: {}",
                path.display()
            )));
        }

        // Build the event.
        let sv_list: Vec<serde_json::Value> = acquired
            .iter()
            .map(|sv| {
                json!({
                    "prn": sv.prn,
                    "code_phase": sv.code_phase,
                    "doppler_hz": sv.doppler_hz,
                    "cn0_dbhz": sv.cn0_dbhz,
                })
            })
            .collect();

        let flag_list: Vec<serde_json::Value> = flags
            .iter()
            .map(|f| {
                json!({
                    "kind": f.kind,
                    "state": f.state,
                    "evidence": f.evidence,
                })
            })
            .collect();

        let fix_json = fix.as_ref().map(|f| {
            json!({
                "lat_deg": f.lat_deg,
                "lon_deg": f.lon_deg,
                "alt_m": f.alt_m,
                "clock_bias_s": f.clock_bias_s,
                "sv_count": f.sv_count,
                "gdop": f.gdop,
            })
        });

        let summary = if let Some(f) = &fix {
            let fired_count = flags
                .iter()
                .filter(|f| f.state == DetectorState::Fired)
                .count();
            if fired_count > 0 {
                format!(
                    "fix ({} SVs, GDOP {:.1}) — {} integrity flag(s) FIRED",
                    f.sv_count, f.gdop, fired_count
                )
            } else {
                format!(
                    "fix ({} SVs, GDOP {:.1}) — integrity clean",
                    f.sv_count, f.gdop
                )
            }
        } else if has_flags {
            let fired: Vec<&str> = flags
                .iter()
                .filter(|f| f.state == DetectorState::Fired)
                .map(|f| match f.kind {
                    integrity::IntegrityKind::NoiseFloorElevation => "noise_floor",
                    integrity::IntegrityKind::SimultaneousLossOfLock => "loss_of_lock",
                    integrity::IntegrityKind::PowerAnomaly => "power_anomaly",
                    _ => "anomaly",
                })
                .collect();
            format!("no fix — integrity detected: {}", fired.join(", "))
        } else {
            format!("{} SVs acquired, no fix", acquired.len())
        };

        Ok(Event {
            source: "gnss".to_owned(),
            summary,
            data: json!({
                "verb": "fix",
                "acquired_svs": acquired.len(),
                "svs": sv_list,
                "fix": fix_json,
                "integrity": flag_list,
                "nav": {
                    "svs_bit_synced": nav.svs_bit_synced,
                    "preambles_found": nav.preambles_found,
                    "subframes_parity_ok": nav.subframes_parity_ok,
                    "ephemeris_fields": nav.ephemeris.as_ref().map(ephemeris_field_count).unwrap_or(0),
                    "ephemeris_complete": nav
                        .ephemeris
                        .as_ref()
                        .and_then(Ephemeris::to_orbital_elements)
                        .is_some(),
                },
                "samples_read": block.samples.len(),
                "truncated": block.truncated,
            }),
        })
    }
}

/// Outcome of attempting nav-message recovery across all acquired SVs.
struct NavDecodeResult {
    /// How many SVs produced enough prompts to attempt bit sync.
    svs_bit_synced: usize,
    /// How many confirmed TLM preambles were located across all SVs.
    preambles_found: usize,
    /// How many subframes decoded with all words passing parity.
    subframes_parity_ok: usize,
    /// The most-complete ephemeris recovered (merged across parity-OK
    /// subframes of a single SV), if any orbital field was decoded at all.
    ephemeris: Option<Ephemeris>,
}

/// Run the full nav-recovery chain — prompt correlation → bit sync → nav-bit
/// demod → frame sync → parity-gated subframe decode — over every acquired SV,
/// merging parity-OK subframes into a per-SV ephemeris and returning the most
/// complete one.
///
/// Honest by construction: on the file-proof path a 1 ms fixture yields too few
/// prompts to bit-sync, so every counter stays zero and `ephemeris` is `None` —
/// no fabricated bits, preambles, or fields. Only a capture long enough to span
/// multiple subframes produces a decoded ephemeris here.
fn decode_nav(block: &SampleBlock, acquired: &[AcquiredSv]) -> NavDecodeResult {
    let mut result = NavDecodeResult {
        svs_bit_synced: 0,
        preambles_found: 0,
        subframes_parity_ok: 0,
        ephemeris: None,
    };
    let mut best_field_count = 0usize;

    for sv in acquired {
        let prompts = correlate_prompts(block, sv.prn, sv.code_phase, sv.doppler_hz);
        let phase = match estimate_bit_phase(&prompts) {
            Some(p) => p,
            None => continue,
        };
        result.svs_bit_synced += 1;

        let bits = demod_navbits(&prompts, phase);
        let hits = find_preambles(&bits);
        result.preambles_found += hits.len();

        // Merge parity-OK subframes of this SV into one ephemeris.
        let mut sv_eph = Ephemeris::default();
        for hit in &hits {
            let Some(sf_bits) = subframe_bits(&bits, *hit) else {
                continue;
            };
            let decoded = decode_subframe(&sf_bits);
            if decoded.parity_ok {
                result.subframes_parity_ok += 1;
                merge_ephemeris(&mut sv_eph, &decoded.ephemeris);
            }
        }

        let field_count = ephemeris_field_count(&sv_eph);
        if field_count > best_field_count {
            best_field_count = field_count;
            result.ephemeris = Some(sv_eph);
        }
    }

    result
}

/// Overlay any `Some` fields of `src` onto `dst` (later subframes fill in
/// fields earlier ones lacked). Never overwrites a present field with `None`.
fn merge_ephemeris(dst: &mut Ephemeris, src: &Ephemeris) {
    macro_rules! take {
        ($f:ident) => {
            if src.$f.is_some() {
                dst.$f = src.$f;
            }
        };
    }
    take!(week);
    take!(toe);
    take!(sqrt_a);
    take!(eccentricity);
    take!(delta_n);
    take!(i0);
    take!(idot);
    take!(omega0);
    take!(omega);
    take!(m0);
    take!(omega_dot);
    take!(cuc);
    take!(cus);
    take!(crc);
    take!(crs);
    take!(cic);
    take!(cis);
    take!(af0);
    take!(af1);
    take!(af2);
    take!(toc);
}

/// Count how many ephemeris fields were decoded — the completeness metric used
/// to pick the best SV's ephemeris.
fn ephemeris_field_count(e: &Ephemeris) -> usize {
    let mut c = 0;
    c += usize::from(e.sqrt_a.is_some());
    c += usize::from(e.eccentricity.is_some());
    c += usize::from(e.m0.is_some());
    c += usize::from(e.delta_n.is_some());
    c += usize::from(e.i0.is_some());
    c += usize::from(e.idot.is_some());
    c += usize::from(e.omega0.is_some());
    c += usize::from(e.omega.is_some());
    c += usize::from(e.omega_dot.is_some());
    c += usize::from(e.toe.is_some());
    c
}

impl Default for GnssRx {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for GnssRx {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "gnss".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::RfRx,
            capability: CapabilityClass::Passive,
            summary: "GNSS receive + spoof/jam integrity (GPS L1 C/A, file-proof)".to_owned(),
        }
    }

    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError> {
        match cmd.verb.as_str() {
            "fix" => {
                let trimmed = cmd.arg.trim();
                if trimmed.is_empty() {
                    return Err(PluginError::InvalidInput(
                        "gnss fix requires a path to an IQ capture file".to_owned(),
                    ));
                }
                self.do_fix(Path::new(trimmed))
            }
            other => Err(PluginError::Unsupported(format!(
                "verb '{other}' not supported (available: fix)"
            ))),
        }
    }
}
