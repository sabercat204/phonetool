//! Pure, advisory rogue-BTS / IMSI-catcher anomaly detection.
//!
//! Takes a decoded [`CellMap`], an operator-supplied [`Baseline`] ("what should
//! be present"), and injected [`Thresholds`], and emits [`AnomalyFlag`]s. It
//! **reports only** — no on-air action, ever (that would be an Axis-B transmit
//! needing a `&TxGrant`, which no trait grants; design Gap 3).
//!
//! ## Grounding discipline (Open Question 1)
//!
//! The anomaly *categories* here (`UnexpectedPlmn`, `ForcedReregistration`,
//! `RatDowngrade`, `MissingNeighbours`, `SignalGeometryImplausible`,
//! `DuplicateIdentity`) name the classes of cell-site-simulator tell documented
//! in public IMSI-catcher-detection research (SnoopSnitch / SRLabs, AIMSICD, the
//! academic literature). The **numeric thresholds** that some of them need are
//! **not invented here.** They are fields of [`Thresholds`], which has **no
//! `Default`**: the operator must supply cited values. A category whose
//! threshold is absent is **skipped** (and the omission is observable), never run
//! against a fabricated dBm cutoff. This honors the constant-confabulation rule:
//! a guessed threshold we cannot cite is worse than a deferred one.
//!
//! The categorical detectors (`UnexpectedPlmn`, `ForcedReregistration`,
//! `MissingNeighbours`, `DuplicateIdentity`) need **no** magic number — they are
//! pure set/consistency logic against the baseline — so they run today.
//! `SignalGeometryImplausible` and `RatDowngrade` need thresholds/context and run
//! only when the operator provides them.

use std::collections::BTreeMap;

use crate::cellmap::{CellMap, CellObservation};

/// A rogue-BTS anomaly category. Advisory; each carries its own evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AnomalyKind {
    /// A cell advertises a PLMN not in the operator's baseline.
    UnexpectedPlmn {
        /// The offending (MCC, MNC).
        mcc: u16,
        /// ...
        mnc: u16,
    },
    /// A cell advertises a LAC/TAC that differs from the baseline for its PLMN in
    /// a way that would force the handset to re-register.
    ForcedReregistration {
        /// PLMN.
        mcc: u16,
        /// PLMN.
        mnc: u16,
        /// The location code seen on air.
        seen: u32,
        /// The location code(s) the baseline expected for this PLMN.
        expected: Vec<u32>,
    },
    /// A cell of an older RAT appears where the baseline expected only newer RATs
    /// for that PLMN (a downgrade-to-2G tell).
    RatDowngrade {
        /// PLMN.
        mcc: u16,
        /// PLMN.
        mnc: u16,
    },
    /// A cell advertises no neighbours where the baseline expects some.
    MissingNeighbours {
        /// The ARFCN with the empty neighbour list.
        arfcn: u16,
    },
    /// A cell's received level is implausible given expected geometry (needs a
    /// threshold; runs only when supplied).
    SignalGeometryImplausible {
        /// The ARFCN.
        arfcn: u16,
        /// The measured level in dBm.
        signal_dbm: i8,
    },
    /// The same cell identity was observed with inconsistent parameters (a
    /// parameter flip between sightings).
    DuplicateIdentity {
        /// A human-readable identity key.
        identity: String,
    },
}

/// An advisory flag: a category, free-text evidence, and an optional confidence
/// in `[0.0, 1.0]`. Confidence is `None` unless the operator supplied a scoring
/// weight for the category (Open Question 1) — never a fabricated score.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AnomalyFlag {
    /// The anomaly category and its structured evidence.
    pub kind: AnomalyKind,
    /// Human-readable supporting evidence.
    pub evidence: String,
    /// Confidence in `[0,1]`, present only when a cited weight was injected.
    pub confidence: Option<f64>,
}

/// The operator-supplied reference: what SHOULD be visible. Its provenance
/// (prior clean survey, OpenCellID/MLS, regulator PLMN list, hand-entry) is Open
/// Question 2; this type just holds it. An empty baseline yields no baseline-
/// relative flags (you cannot call a PLMN "unexpected" with nothing to compare).
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    /// Expected PLMNs as (MCC, MNC). A PLMN outside this set → `UnexpectedPlmn`.
    pub expected_plmns: Vec<(u16, u16)>,
    /// Expected location codes (LAC/TAC) per PLMN. A seen code absent from a
    /// non-empty expected set → `ForcedReregistration`.
    pub expected_lac_by_plmn: BTreeMap<(u16, u16), Vec<u32>>,
    /// PLMNs for which neighbours are expected; a cell of such a PLMN advertising
    /// none → `MissingNeighbours`.
    pub plmns_expecting_neighbours: Vec<(u16, u16)>,
    /// The lowest RAT generation (2/4/5) the baseline expects per PLMN. A lower
    /// generation seen → `RatDowngrade`. Absent → the check is skipped.
    pub min_rat_generation_by_plmn: BTreeMap<(u16, u16), u8>,
}

/// Injected numeric thresholds. **No `Default` on purpose** (Open Question 1):
/// every numeric field is `Option` and a `None` disables its check. The operator
/// supplies cited values; an un-cited value is left `None`, not guessed.
#[derive(Debug, Clone, Default)]
pub struct Thresholds {
    /// Max plausible received level in dBm. A cell stronger than this is
    /// geometrically implausible (a too-close simulator). `None` → check skipped.
    pub max_plausible_dbm: Option<i8>,
    /// Per-category confidence weight in `[0,1]`. A category absent here yields a
    /// flag with `confidence: None` rather than a fabricated score.
    pub confidence_by_category: BTreeMap<String, f64>,
}

/// The RAT generation number (2G/4G/5G) of an observation, for the downgrade
/// check.
fn generation(obs: &CellObservation) -> u8 {
    match obs {
        CellObservation::Gsm(_) => 2,
        CellObservation::Lte(_) => 4,
        CellObservation::Nr(_) => 5,
    }
}

/// Extract (MCC, MNC) from an observation if it decoded one.
fn plmn_of(obs: &CellObservation) -> Option<(u16, u16)> {
    match obs {
        CellObservation::Gsm(c) => Some((c.mcc?, c.mnc?)),
        CellObservation::Lte(c) => c.plmn.map(|(mcc, mnc, _)| (mcc, mnc)),
        CellObservation::Nr(c) => c.plmn.map(|(mcc, mnc, _)| (mcc, mnc)),
    }
}

/// Scan a [`CellMap`] against a baseline and thresholds. Pure and advisory:
/// returns flags, takes no action. Deterministic ordering (map iteration is over
/// a `BTreeMap`).
#[must_use]
pub fn scan(map: &CellMap, baseline: &Baseline, thresholds: &Thresholds) -> Vec<AnomalyFlag> {
    let mut flags = Vec::new();

    for (id, observations) in &map.cells {
        // --- DuplicateIdentity: >1 retained observation of one identity ---
        // cellmap only retains a second observation when it differs (identical
        // ones are deduped), so >1 here already means inconsistent parameters.
        if observations.len() > 1 {
            flags.push(flag(
                AnomalyKind::DuplicateIdentity {
                    identity: format!("{id:?}"),
                },
                format!(
                    "{} inconsistent observations of one cell identity",
                    observations.len()
                ),
                thresholds,
                "duplicate_identity",
            ));
        }

        for obs in observations {
            let Some((mcc, mnc)) = plmn_of(obs) else {
                continue; // no PLMN decoded → no baseline-relative check possible
            };

            // --- UnexpectedPlmn ---
            if !baseline.expected_plmns.is_empty() && !baseline.expected_plmns.contains(&(mcc, mnc))
            {
                flags.push(flag(
                    AnomalyKind::UnexpectedPlmn { mcc, mnc },
                    format!("PLMN {mcc}-{mnc} is not in the operator baseline"),
                    thresholds,
                    "unexpected_plmn",
                ));
            }

            // --- ForcedReregistration ---
            if let Some(seen_lac) = location_code(obs)
                && let Some(expected) = baseline.expected_lac_by_plmn.get(&(mcc, mnc))
                && !expected.is_empty()
                && !expected.contains(&seen_lac)
            {
                flags.push(flag(
                    AnomalyKind::ForcedReregistration {
                        mcc,
                        mnc,
                        seen: seen_lac,
                        expected: expected.clone(),
                    },
                    format!(
                        "PLMN {mcc}-{mnc} advertises location code {seen_lac}, \
                         not in the expected set {expected:?} — forces re-registration"
                    ),
                    thresholds,
                    "forced_reregistration",
                ));
            }

            // --- RatDowngrade (needs baseline min-generation for this PLMN) ---
            if let Some(&min_gen) = baseline.min_rat_generation_by_plmn.get(&(mcc, mnc))
                && generation(obs) < min_gen
            {
                flags.push(flag(
                    AnomalyKind::RatDowngrade { mcc, mnc },
                    format!(
                        "PLMN {mcc}-{mnc} seen on {}G where baseline expects ≥{min_gen}G",
                        generation(obs)
                    ),
                    thresholds,
                    "rat_downgrade",
                ));
            }

            // --- MissingNeighbours (GSM only in v1; needs baseline expectation) ---
            if let CellObservation::Gsm(c) = obs {
                let expects = baseline.plmns_expecting_neighbours.contains(&(mcc, mnc));
                if expects && !c.neighbours_undecoded && c.neighbours.is_empty() {
                    flags.push(flag(
                        AnomalyKind::MissingNeighbours { arfcn: c.arfcn },
                        format!(
                            "ARFCN {} (PLMN {mcc}-{mnc}) advertises no neighbours where the \
                             baseline expects some",
                            c.arfcn
                        ),
                        thresholds,
                        "missing_neighbours",
                    ));
                }
            }

            // --- SignalGeometryImplausible (needs an injected dBm threshold) ---
            if let Some(max_dbm) = thresholds.max_plausible_dbm
                && let Some(sig) = signal_of(obs)
                && sig > max_dbm
                && let CellObservation::Gsm(c) = obs
            {
                flags.push(flag(
                    AnomalyKind::SignalGeometryImplausible {
                        arfcn: c.arfcn,
                        signal_dbm: sig,
                    },
                    format!(
                        "ARFCN {} level {sig} dBm exceeds the plausible max {max_dbm} dBm",
                        c.arfcn
                    ),
                    thresholds,
                    "signal_geometry_implausible",
                ));
            }
        }
    }

    flags
}

/// The location code (LAC/TAC) an observation decoded, widened to u32.
fn location_code(obs: &CellObservation) -> Option<u32> {
    match obs {
        CellObservation::Gsm(c) => c.lac.map(u32::from),
        CellObservation::Lte(c) => c.tac,
        CellObservation::Nr(c) => c.tac,
    }
}

/// The received signal level an observation carried (GSM only today).
fn signal_of(obs: &CellObservation) -> Option<i8> {
    match obs {
        CellObservation::Gsm(c) => c.signal_dbm,
        CellObservation::Lte(_) | CellObservation::Nr(_) => None,
    }
}

/// Build a flag, attaching an injected confidence weight if the operator gave
/// one for this category (else `None` — never a fabricated score).
fn flag(
    kind: AnomalyKind,
    evidence: String,
    thresholds: &Thresholds,
    category: &str,
) -> AnomalyFlag {
    AnomalyFlag {
        kind,
        evidence,
        confidence: thresholds.confidence_by_category.get(category).copied(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::cellmap;
    use crate::decode_gsm::GsmCell;

    fn gsm(arfcn: u16, mcc: u16, mnc: u16, lac: u16, cid: u16) -> GsmCell {
        GsmCell {
            mcc: Some(mcc),
            mnc: Some(mnc),
            mnc_digits: Some(2),
            lac: Some(lac),
            cid: Some(cid),
            arfcn,
            signal_dbm: Some(-70),
            neighbours: vec![1, 2, 3],
            neighbours_undecoded: false,
        }
    }

    #[test]
    fn clean_map_against_matching_baseline_yields_no_flags() {
        let map = cellmap::build(&[gsm(10, 262, 2, 100, 1)], &[], &[]);
        let baseline = Baseline {
            expected_plmns: vec![(262, 2)],
            ..Baseline::default()
        };
        let flags = scan(&map, &baseline, &Thresholds::default());
        assert!(flags.is_empty(), "got {flags:?}");
    }

    #[test]
    fn flags_unexpected_plmn() {
        let map = cellmap::build(&[gsm(10, 999, 99, 100, 1)], &[], &[]);
        let baseline = Baseline {
            expected_plmns: vec![(262, 2)],
            ..Baseline::default()
        };
        let flags = scan(&map, &baseline, &Thresholds::default());
        assert!(
            flags
                .iter()
                .any(|f| matches!(f.kind, AnomalyKind::UnexpectedPlmn { mcc: 999, mnc: 99 }))
        );
    }

    #[test]
    fn empty_baseline_does_not_flag_unexpected_plmn() {
        // Cannot call a PLMN unexpected with nothing to compare against.
        let map = cellmap::build(&[gsm(10, 999, 99, 100, 1)], &[], &[]);
        let flags = scan(&map, &Baseline::default(), &Thresholds::default());
        assert!(
            !flags
                .iter()
                .any(|f| matches!(f.kind, AnomalyKind::UnexpectedPlmn { .. }))
        );
    }

    #[test]
    fn flags_forced_reregistration() {
        let map = cellmap::build(&[gsm(10, 262, 2, 500, 1)], &[], &[]);
        let mut expected_lac = BTreeMap::new();
        expected_lac.insert((262u16, 2u16), vec![100u32, 101]);
        let baseline = Baseline {
            expected_plmns: vec![(262, 2)],
            expected_lac_by_plmn: expected_lac,
            ..Baseline::default()
        };
        let flags = scan(&map, &baseline, &Thresholds::default());
        assert!(
            flags
                .iter()
                .any(|f| matches!(f.kind, AnomalyKind::ForcedReregistration { seen: 500, .. }))
        );
    }

    #[test]
    fn flags_missing_neighbours() {
        let mut c = gsm(10, 262, 2, 100, 1);
        c.neighbours = Vec::new(); // advertises none
        let map = cellmap::build(&[c], &[], &[]);
        let baseline = Baseline {
            expected_plmns: vec![(262, 2)],
            plmns_expecting_neighbours: vec![(262, 2)],
            ..Baseline::default()
        };
        let flags = scan(&map, &baseline, &Thresholds::default());
        assert!(
            flags
                .iter()
                .any(|f| matches!(f.kind, AnomalyKind::MissingNeighbours { arfcn: 10 }))
        );
    }

    #[test]
    fn undecoded_neighbours_do_not_trigger_missing() {
        let mut c = gsm(10, 262, 2, 100, 1);
        c.neighbours = Vec::new();
        c.neighbours_undecoded = true; // present but unsupported format
        let map = cellmap::build(&[c], &[], &[]);
        let baseline = Baseline {
            plmns_expecting_neighbours: vec![(262, 2)],
            ..Baseline::default()
        };
        let flags = scan(&map, &baseline, &Thresholds::default());
        assert!(
            !flags
                .iter()
                .any(|f| matches!(f.kind, AnomalyKind::MissingNeighbours { .. }))
        );
    }

    #[test]
    fn flags_duplicate_identity_on_parameter_flip() {
        let mut a = gsm(10, 262, 2, 100, 1);
        let mut b = gsm(10, 262, 2, 100, 1);
        a.signal_dbm = Some(-70);
        b.signal_dbm = Some(-30); // same identity key, different params
        let map = cellmap::build(&[a, b], &[], &[]);
        let flags = scan(&map, &Baseline::default(), &Thresholds::default());
        assert!(
            flags
                .iter()
                .any(|f| matches!(f.kind, AnomalyKind::DuplicateIdentity { .. }))
        );
    }

    #[test]
    fn signal_geometry_skipped_without_threshold() {
        let mut c = gsm(10, 262, 2, 100, 1);
        c.signal_dbm = Some(0); // very strong
        let map = cellmap::build(&[c], &[], &[]);
        // No max_plausible_dbm injected → the check must not run (no fabricated cutoff).
        let flags = scan(&map, &Baseline::default(), &Thresholds::default());
        assert!(
            !flags
                .iter()
                .any(|f| matches!(f.kind, AnomalyKind::SignalGeometryImplausible { .. }))
        );
    }

    #[test]
    fn signal_geometry_flags_when_threshold_injected() {
        let mut c = gsm(10, 262, 2, 100, 1);
        c.signal_dbm = Some(-10);
        let map = cellmap::build(&[c], &[], &[]);
        let thresholds = Thresholds {
            max_plausible_dbm: Some(-40), // operator-supplied cited value
            ..Thresholds::default()
        };
        let flags = scan(&map, &Baseline::default(), &thresholds);
        assert!(
            flags
                .iter()
                .any(|f| matches!(f.kind, AnomalyKind::SignalGeometryImplausible { .. }))
        );
    }

    #[test]
    fn confidence_is_none_without_injected_weight_and_set_with_it() {
        let map = cellmap::build(&[gsm(10, 999, 99, 100, 1)], &[], &[]);
        let baseline = Baseline {
            expected_plmns: vec![(262, 2)],
            ..Baseline::default()
        };
        let flags = scan(&map, &baseline, &Thresholds::default());
        assert!(flags.iter().all(|f| f.confidence.is_none()));

        let mut weights = BTreeMap::new();
        weights.insert("unexpected_plmn".to_owned(), 0.9);
        let thresholds = Thresholds {
            confidence_by_category: weights,
            ..Thresholds::default()
        };
        let flags = scan(&map, &baseline, &thresholds);
        assert!(
            flags
                .iter()
                .filter(|f| matches!(f.kind, AnomalyKind::UnexpectedPlmn { .. }))
                .all(|f| f.confidence == Some(0.9))
        );
    }
}
