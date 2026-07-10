//! Correlation, classification, and reuse-index maintenance — the store layer.
//!
//! Exact-match lookups against the offline [`IntelStore`] under three namespaces,
//! honest confidence derivation, scam-pattern classification against operator-
//! seeded signatures, and an idempotent reuse write-back. Owns no gate logic —
//! there is none; baittriage is passive by construction.
//!
//! ## Two doctrine points, both inherited from shipped crates
//!
//! **Confidence is counted, never asserted; cutoffs are injected, not invented.**
//! Following cell-survey's threshold discipline (Sprint 12): the `Low`→`Medium`→
//! `High` graduation cutoffs are operator-tunable policy grounded in real triage
//! experience, so they are **injected** via [`ConfidenceCutoffs`] (which has no
//! `Default`), never hardcoded. Absent injected cutoffs the grade stays at the
//! `Low` floor and the raw [`Footprint::corroboration_count`] is surfaced instead —
//! the corroboration is real and visible, but its grading is honestly deferred
//! (design Open Question 1). The one boundary the design *does* fix — zero
//! corroboration is `Low` — holds unconditionally.
//!
//! **Exact-match reuse only, and its limit is explicit.** `IntelStore` offers only
//! exact-key `get`/`put` with no similarity index and no atomic read-modify-write.
//! So reuse detection is exact-match today, and the reuse write is a plain `put`
//! keyed by a content hash of the bait for idempotency, not a race-free append.
//! Fuzzy/near-duplicate reuse and a concurrency-safe counter are the known
//! architectural gap (design §"known architectural gap"), deferred to a future
//! Tier-B analyzer — flagged here, not silently faked.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use serde::Serialize;

use phonetool_core::{IntelStore, StoreError};

use crate::extract::Ioc;

/// Store namespace for operator-curated known-bad indicators.
pub const KNOWN_BAD_NS: &str = "baittriage_known_bad";
/// Store namespace for the reuse index (indicators seen in prior triaged baits).
pub const REUSE_NS: &str = "baittriage_reuse";
/// Store namespace for scam-pattern signatures (indicator value → pattern name).
pub const SIGNATURE_NS: &str = "baittriage_signature";

/// A store-backed correlation found for an indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Correlation {
    /// The indicator matched an operator-curated known-bad entry.
    KnownBad { ioc: String },
    /// The indicator was recorded by a *prior, different* triaged bait.
    PriorCase { ioc: String, case_ref: String },
}

/// The classified scam pattern. Classification matches extracted indicators
/// against **store-backed signatures the operator seeds** (`SIGNATURE_NS`), never
/// against hardcoded keyword lists — an unseeded store returns [`Unknown`]
/// honestly (design Open Question 2 owns the taxonomy + seed provenance).
///
/// [`Unknown`]: ScamPattern::Unknown
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScamPattern {
    /// IRS / Social Security Administration impersonation.
    IrsSsaImpersonation,
    /// Tech-support scam.
    TechSupport,
    /// Romance scam.
    Romance,
    /// "Pig butchering" investment scam.
    PigButchering,
    /// No seeded signature matched.
    Unknown,
}

impl ScamPattern {
    /// Map a stored signature's pattern-name string to a variant. An unrecognized
    /// name is NOT coerced — it yields `None`, so a garbage/typo'd seed does not
    /// silently classify as some pattern.
    fn from_signature_name(name: &str) -> Option<Self> {
        match name {
            "irs_ssa_impersonation" => Some(Self::IrsSsaImpersonation),
            "tech_support" => Some(Self::TechSupport),
            "romance" => Some(Self::Romance),
            "pig_butchering" => Some(Self::PigButchering),
            _ => None,
        }
    }
}

/// The ordinal assessment strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Thin or uncorroborated — the floor. Zero corroboration is always `Low`.
    Low,
    /// Some corroboration (only reachable with injected cutoffs).
    Medium,
    /// Strong corroboration (only reachable with injected cutoffs).
    High,
}

/// Operator-tunable graduation cutoffs for [`Confidence`]. Deliberately has **no
/// `Default`**: the cutoffs are policy grounded in real triage experience (design
/// Open Question 1), so a build that does not inject them cannot silently grade
/// above `Low`. `medium_at`/`high_at` are the minimum corroboration counts for
/// each grade.
#[derive(Debug, Clone, Copy)]
pub struct ConfidenceCutoffs {
    /// Minimum corroboration count to reach `Medium`.
    pub medium_at: usize,
    /// Minimum corroboration count to reach `High`.
    pub high_at: usize,
}

impl ConfidenceCutoffs {
    /// Grade a corroboration count. Monotone and floored: zero is always `Low`;
    /// more corroboration never lowers the grade.
    fn grade(self, count: usize) -> Confidence {
        if count >= self.high_at && self.high_at > 0 {
            Confidence::High
        } else if count >= self.medium_at && self.medium_at > 0 {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }
}

/// The structured triage product.
#[derive(Debug, Clone, Serialize)]
pub struct Footprint {
    /// The extracted indicators.
    pub iocs: Vec<Ioc>,
    /// Store-backed correlations found.
    pub correlations: Vec<Correlation>,
    /// The classified scam pattern (`Unknown` when no signature matched).
    pub pattern: ScamPattern,
    /// The graded confidence. Floored at `Low`; only rises with injected cutoffs.
    pub confidence: Confidence,
    /// The raw count of independent corroborating indicators — always reported, so
    /// the corroboration is visible even when `confidence` is not graded.
    pub corroboration_count: usize,
    /// Whether `confidence` was graded by injected cutoffs. `false` means the grade
    /// is the honest `Low` floor and `corroboration_count` is the signal to read.
    pub confidence_graded: bool,
    /// `true` when at least one indicator was extracted but nothing correlated — an
    /// honest thin-but-real result, distinct from an empty input (which is an error).
    pub no_prior_correlation: bool,
    /// Provenance: a `CaptureRef { kind: CallAudio }` path this bait cited, if any.
    /// Carried by path only — the recording is never opened here.
    pub provenance: Option<String>,
    /// Whether reuse-index maintenance succeeded. `false` means the assessment is
    /// complete but the reuse write failed (the assessment is still returned).
    pub reuse_index_ok: bool,
}

/// A stable content hash of the extracted indicator set, used as the reuse-index
/// case reference so re-triaging the same bait is idempotent. Not cryptographic —
/// it only needs to be stable within a deployment for dedup/idempotency.
#[must_use]
pub fn bait_hash(iocs: &[Ioc]) -> String {
    // `iocs` is already sorted+deduped by extract::iocs, so the hash is order-stable.
    let mut hasher = DefaultHasher::new();
    for ioc in iocs {
        (ioc.kind as u8).hash(&mut hasher);
        ioc.value.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// Correlate indicators against the store, classify, and derive confidence.
///
/// Read-only over the store (the reuse write-back is a separate step, so a
/// caller can assess without mutating). Per the design: exact-match `get` against
/// `KNOWN_BAD_NS` and `REUSE_NS`; a reuse hit whose stored `case_ref` equals this
/// bait's own hash is **self**, not an independent prior case (keeps re-triage
/// idempotent). Classification reads `SIGNATURE_NS`. Confidence is counted and
/// floored; graded only when `cutoffs` is `Some`.
///
/// # Errors
/// Returns [`StoreError`] if the backing store fails on any lookup.
pub fn assess(
    store: &dyn IntelStore,
    iocs: &[Ioc],
    cutoffs: Option<ConfidenceCutoffs>,
) -> Result<Footprint, StoreError> {
    let self_hash = bait_hash(iocs);
    let mut correlations = Vec::new();
    let mut corroborating: usize = 0;

    for ioc in iocs {
        let mut this_ioc_corroborated = false;

        if store.get(KNOWN_BAD_NS, &ioc.value)?.is_some() {
            correlations.push(Correlation::KnownBad {
                ioc: ioc.value.clone(),
            });
            this_ioc_corroborated = true;
        }

        if let Some(case_ref) = store.get(REUSE_NS, &ioc.value)? {
            // A reuse entry written by *this same* bait is not an independent
            // prior case — skip it so re-triaging the same bundle does not
            // manufacture a self-correlation.
            if case_ref != self_hash {
                correlations.push(Correlation::PriorCase {
                    ioc: ioc.value.clone(),
                    case_ref,
                });
                this_ioc_corroborated = true;
            }
        }

        if this_ioc_corroborated {
            corroborating += 1;
        }
    }

    let (pattern, signature_matched) = classify(store, iocs)?;
    // A signature match is independent corroboration on top of per-IOC hits.
    let corroboration_count = corroborating + usize::from(signature_matched);

    let (confidence, confidence_graded) = match cutoffs {
        Some(c) => (c.grade(corroboration_count), true),
        // No injected cutoffs: honest floor. The count carries the real signal.
        None => (Confidence::Low, false),
    };

    Ok(Footprint {
        iocs: iocs.to_vec(),
        correlations,
        pattern,
        confidence,
        corroboration_count,
        confidence_graded,
        no_prior_correlation: corroboration_count == 0,
        provenance: None,
        reuse_index_ok: true,
    })
}

/// Classify against operator-seeded signatures. Returns the matched pattern (or
/// `Unknown`) and whether any signature matched. An empty `SIGNATURE_NS` yields
/// `(Unknown, false)` — never a fabricated classification.
fn classify(store: &dyn IntelStore, iocs: &[Ioc]) -> Result<(ScamPattern, bool), StoreError> {
    for ioc in iocs {
        // A stored-but-unrecognized signature name is not coerced into a pattern
        // (`from_signature_name` returns `None`); keep scanning for a valid one.
        if let Some(name) = store.get(SIGNATURE_NS, &ioc.value)?
            && let Some(pattern) = ScamPattern::from_signature_name(&name)
        {
            return Ok((pattern, true));
        }
    }
    Ok((ScamPattern::Unknown, false))
}

/// Write each extracted indicator into the reuse index, keyed by the IOC value,
/// with this bait's content hash as the value. Idempotent: re-triaging the same
/// bait writes the same `(key, value)` pairs (INSERT OR REPLACE), so reuse counts
/// are not inflated.
///
/// # Errors
/// Returns [`StoreError`] on the first failed write. The caller treats this as a
/// non-fatal reuse-maintenance failure (the assessment is still returned).
pub fn record_reuse(store: &dyn IntelStore, iocs: &[Ioc]) -> Result<(), StoreError> {
    let hash = bait_hash(iocs);
    for ioc in iocs {
        store.put(REUSE_NS, &ioc.value, &hash)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::extract::IocKind;
    use phonetool_core::SqliteStore;

    fn ioc(kind: IocKind, value: &str) -> Ioc {
        Ioc {
            kind,
            value: value.to_owned(),
        }
    }

    #[test]
    fn no_correlation_is_low_and_marked() {
        let store = SqliteStore::open_in_memory().expect("store");
        let iocs = vec![ioc(IocKind::Wallet, "bc1qxyz")];
        let fp = assess(&store, &iocs, None).expect("assess");
        assert_eq!(fp.confidence, Confidence::Low);
        assert_eq!(fp.corroboration_count, 0);
        assert!(fp.no_prior_correlation);
        assert!(fp.correlations.is_empty());
        assert_eq!(fp.pattern, ScamPattern::Unknown);
    }

    #[test]
    fn known_bad_hit_is_correlation_and_counts() {
        let store = SqliteStore::open_in_memory().expect("store");
        store
            .put(KNOWN_BAD_NS, "bc1qxyz", "seized wallet")
            .expect("seed");
        let iocs = vec![ioc(IocKind::Wallet, "bc1qxyz")];
        let fp = assess(&store, &iocs, None).expect("assess");
        assert_eq!(fp.corroboration_count, 1);
        assert!(!fp.no_prior_correlation);
        assert!(matches!(fp.correlations[0], Correlation::KnownBad { .. }));
    }

    #[test]
    fn prior_case_from_different_bait() {
        let store = SqliteStore::open_in_memory().expect("store");
        // A prior, different bait recorded this IOC under a different hash.
        store
            .put(REUSE_NS, "bc1qxyz", "deadbeefdeadbeef")
            .expect("seed");
        let iocs = vec![ioc(IocKind::Wallet, "bc1qxyz")];
        let fp = assess(&store, &iocs, None).expect("assess");
        assert_eq!(fp.corroboration_count, 1);
        assert!(matches!(
            &fp.correlations[0],
            Correlation::PriorCase { case_ref, .. } if case_ref == "deadbeefdeadbeef"
        ));
    }

    #[test]
    fn own_reuse_write_is_not_a_prior_case() {
        let store = SqliteStore::open_in_memory().expect("store");
        let iocs = vec![ioc(IocKind::Wallet, "bc1qxyz")];
        // Simulate a first triage's reuse write.
        record_reuse(&store, &iocs).expect("record");
        // Re-triage the same bait: the reuse hit is self, not a prior case.
        let fp = assess(&store, &iocs, None).expect("assess");
        assert!(fp.correlations.is_empty());
        assert_eq!(fp.corroboration_count, 0);
    }

    #[test]
    fn cutoffs_grade_above_low_when_injected() {
        let store = SqliteStore::open_in_memory().expect("store");
        store.put(KNOWN_BAD_NS, "a", "x").expect("seed");
        store.put(KNOWN_BAD_NS, "b", "x").expect("seed");
        let iocs = vec![ioc(IocKind::Wallet, "a"), ioc(IocKind::Wallet, "b")];
        let cutoffs = ConfidenceCutoffs {
            medium_at: 1,
            high_at: 2,
        };
        let fp = assess(&store, &iocs, Some(cutoffs)).expect("assess");
        assert_eq!(fp.corroboration_count, 2);
        assert_eq!(fp.confidence, Confidence::High);
        assert!(fp.confidence_graded);
    }

    #[test]
    fn without_cutoffs_confidence_stays_low_even_with_corroboration() {
        let store = SqliteStore::open_in_memory().expect("store");
        store.put(KNOWN_BAD_NS, "a", "x").expect("seed");
        let iocs = vec![ioc(IocKind::Wallet, "a")];
        let fp = assess(&store, &iocs, None).expect("assess");
        assert_eq!(fp.corroboration_count, 1);
        assert_eq!(fp.confidence, Confidence::Low);
        assert!(!fp.confidence_graded);
    }

    #[test]
    fn signature_classifies_and_unrecognized_does_not() {
        let store = SqliteStore::open_in_memory().expect("store");
        store
            .put(
                SIGNATURE_NS,
                "irsagent@evil.example",
                "irs_ssa_impersonation",
            )
            .expect("seed");
        let iocs = vec![ioc(IocKind::Email, "irsagent@evil.example")];
        let (pattern, matched) = classify(&store, &iocs).expect("classify");
        assert_eq!(pattern, ScamPattern::IrsSsaImpersonation);
        assert!(matched);

        // A garbage signature name is not coerced.
        store
            .put(SIGNATURE_NS, "x@evil.example", "not_a_pattern")
            .expect("seed");
        let iocs2 = vec![ioc(IocKind::Email, "x@evil.example")];
        let (pattern2, matched2) = classify(&store, &iocs2).expect("classify");
        assert_eq!(pattern2, ScamPattern::Unknown);
        assert!(!matched2);
    }

    #[test]
    fn empty_signature_store_is_unknown() {
        let store = SqliteStore::open_in_memory().expect("store");
        let iocs = vec![ioc(IocKind::Wallet, "bc1qxyz")];
        let (pattern, matched) = classify(&store, &iocs).expect("classify");
        assert_eq!(pattern, ScamPattern::Unknown);
        assert!(!matched);
    }

    #[test]
    fn bait_hash_is_stable_and_order_independent_of_input_repeats() {
        let a = vec![
            ioc(IocKind::Wallet, "a"),
            ioc(IocKind::Phone, "+15125550100"),
        ];
        let b = a.clone();
        assert_eq!(bait_hash(&a), bait_hash(&b));
        assert_ne!(bait_hash(&a), bait_hash(&[ioc(IocKind::Wallet, "c")]));
    }

    #[test]
    fn reuse_write_is_idempotent() {
        let store = SqliteStore::open_in_memory().expect("store");
        let iocs = vec![ioc(IocKind::Wallet, "bc1qxyz")];
        record_reuse(&store, &iocs).expect("first");
        let first = store
            .get(REUSE_NS, "bc1qxyz")
            .expect("get")
            .expect("present");
        record_reuse(&store, &iocs).expect("second");
        let second = store
            .get(REUSE_NS, "bc1qxyz")
            .expect("get")
            .expect("present");
        assert_eq!(first, second); // same hash, no inflation
    }
}
