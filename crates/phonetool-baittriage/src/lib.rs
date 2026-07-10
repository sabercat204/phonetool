//! `phonetool-baittriage` — passive fraud-caller footprint triage.
//!
//! Given a bundle of operator-supplied artifacts about a scam/vishing caller — a
//! phone number, a claimed identity, callback URLs, wallets, gift-card rails, a
//! transcript, an email — this plugin triages them into a structured *footprint*
//! and a confidence-scored risk assessment. It is **defense of others** and
//! observation-coded: extracting indicators from artifacts the operator was handed
//! is knowledge work, clean under the operator's credo (ingestion ≠ theft).
//!
//! **Passive by construction — no gate.** baittriage implements the plain
//! [`Plugin`] trait and is constructed with only an `Arc<dyn IntelStore>`. It is
//! never handed a `Gate` and has no code path that mints or consumes a
//! `Grant`/`TxGrant`. Triaging a caller's own footprint touches no third-party
//! infrastructure, so gating it would be the safety theater the operator directive
//! forbids ("do not narc-jump"). The dual-use line runs through the *active* crates
//! (sip, wardial), not here. The compiler enforces it: there is no `dispatch_active`.
//!
//! **Artifacts are data, never destinations.** The single hardest rule in the
//! crate: nothing in an artifact — most sharply a URL — is ever fetched, resolved,
//! opened, or executed on any path. A URL is a string to normalize and compare; it
//! is never a request target. This keeps a crafted bundle from turning the bench
//! into an SSRF gadget or a beacon that tells the scammer their victim is
//! investigating.
//!
//! **Offline default.** The default build correlates against the local
//! [`IntelStore`] with no network call and links zero egress dependencies. The
//! `online` feature is a DECLARED SEAM (provider enrichment, numintel's model) —
//! reserved but not built in Sprint 14; the provider Open Question is unresolved.
//!
//! ## Example (compile-fail proof: `BaitTriage` is NOT `ActivePlugin`)
//!
//! ```compile_fail
//! use phonetool_core::ActivePlugin;
//! use phonetool_baittriage::BaitTriage;
//! fn require_active(_p: &dyn ActivePlugin) {}
//! fn check(a: &BaitTriage) { require_active(a); }
//! ```

pub mod correlate;
pub mod extract;
pub mod ingest;

use std::sync::Arc;

use phonetool_core::{
    CapabilityClass, Command, Event, IntelStore, Manifest, Plugin, PluginError, StoreError,
    Transducer,
};
use serde_json::json;

use crate::correlate::{ConfidenceCutoffs, Footprint};
use crate::ingest::IngestError;

/// The passive fraud-caller footprint-triage plugin. Holds a handle to the shared
/// offline store and, optionally, injected confidence cutoffs.
pub struct BaitTriage {
    store: Arc<dyn IntelStore>,
    /// Injected [`Confidence`](correlate::Confidence) graduation cutoffs. `None`
    /// (the default) keeps confidence at the honest `Low` floor while surfacing the
    /// raw corroboration count — the cutoffs are operator policy, not invented here.
    cutoffs: Option<ConfidenceCutoffs>,
}

impl BaitTriage {
    /// Build the plugin over a shared intel store, with no confidence cutoffs
    /// injected (confidence stays at the `Low` floor; the corroboration count is
    /// the signal to read).
    #[must_use]
    pub fn new(store: Arc<dyn IntelStore>) -> Self {
        Self {
            store,
            cutoffs: None,
        }
    }

    /// Build the plugin with operator-supplied confidence cutoffs injected, so the
    /// assessment grades `Low`→`Medium`→`High` per the operator's policy.
    #[must_use]
    pub fn with_cutoffs(store: Arc<dyn IntelStore>, cutoffs: ConfidenceCutoffs) -> Self {
        Self {
            store,
            cutoffs: Some(cutoffs),
        }
    }

    /// Run one triage over a validated bundle argument.
    fn triage(&self, arg: &str) -> Result<Event, PluginError> {
        // Boundary: empty/whitespace before any parse (Req 2.2).
        if arg.trim().is_empty() {
            return Err(PluginError::InvalidInput(
                "baittriage triage requires a non-empty artifact bundle (JSON)".to_owned(),
            ));
        }

        // Ingest: bounded, total over untrusted bytes. Never fetches an artifact.
        let bait = ingest::parse(arg).map_err(map_ingest_error)?;

        // Extract: pure normalization, per-artifact resilient.
        let iocs = extract::iocs(&bait);

        // Tier 1 of the degenerate discipline: zero extractable indicators is a
        // failure the operator sees, not an empty success.
        if iocs.is_empty() {
            return Err(PluginError::Empty(
                "no indicator could be extracted from the supplied artifacts".to_owned(),
            ));
        }

        // Correlate against the offline store.
        let mut footprint =
            correlate::assess(self.store.as_ref(), &iocs, self.cutoffs).map_err(map_store_error)?;

        // Carry the cited call-audio capture as provenance — by path only. The
        // recording is NEVER opened here (audio→text is a future device seam).
        footprint.provenance = bait.source_capture.clone();

        // Reuse-index write-back. A failure here is non-fatal: the assessment is
        // complete and returned, but index maintenance is marked failed (Req 8.3).
        if let Err(e) = correlate::record_reuse(self.store.as_ref(), &iocs) {
            tracing::warn!("baittriage reuse-index write failed: {e}");
            footprint.reuse_index_ok = false;
        }

        Ok(self.footprint_event(&footprint))
    }

    /// Assemble the `Event` from a footprint.
    fn footprint_event(&self, fp: &Footprint) -> Event {
        // Tier 2 of the degenerate discipline: ≥1 indicator, nothing correlated is
        // an honest thin-but-real result — say so in the summary, never dress it up.
        let summary = if fp.no_prior_correlation {
            format!(
                "{} indicator(s), no prior correlation — pattern {:?}, confidence {:?}",
                fp.iocs.len(),
                fp.pattern,
                fp.confidence
            )
        } else {
            format!(
                "{} indicator(s), {} correlation(s) — pattern {:?}, confidence {:?} ({})",
                fp.iocs.len(),
                fp.correlations.len(),
                fp.pattern,
                fp.confidence,
                if fp.confidence_graded {
                    "graded"
                } else {
                    "count only — cutoffs not injected"
                },
            )
        };

        Event {
            source: "baittriage".to_owned(),
            summary,
            data: json!({
                "verb": "triage",
                "iocs": fp.iocs,
                "correlations": fp.correlations,
                "pattern": fp.pattern,
                "confidence": fp.confidence,
                "corroboration_count": fp.corroboration_count,
                "confidence_graded": fp.confidence_graded,
                "no_prior_correlation": fp.no_prior_correlation,
                "provenance": fp.provenance,
                "reuse_index_ok": fp.reuse_index_ok,
            }),
        }
    }
}

impl Plugin for BaitTriage {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "baittriage".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::Ip,
            capability: CapabilityClass::Passive,
            summary: "fraud-caller footprint triage — IOC extraction + offline correlation \
                      (passive, ungated)"
                .to_owned(),
        }
    }

    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError> {
        match cmd.verb.as_str() {
            "triage" => self.triage(&cmd.arg),
            other => Err(PluginError::Unsupported(format!(
                "verb '{other}' not supported (available: triage)"
            ))),
        }
    }
}

/// Map an ingest boundary error to the trait-level [`PluginError`]. `Empty` maps to
/// `InvalidInput` (an empty *arg* is malformed input, distinct from the extraction-
/// yielded-nothing `Empty` degenerate case, which is a different, later condition).
fn map_ingest_error(e: IngestError) -> PluginError {
    match e {
        IngestError::Empty => PluginError::InvalidInput("empty artifact bundle".to_owned()),
        IngestError::Malformed(m) => PluginError::InvalidInput(format!("malformed bundle: {m}")),
        IngestError::TooLarge(m) => PluginError::InvalidInput(format!("bundle too large: {m}")),
    }
}

/// Map a store failure to [`PluginError::Backend`].
fn map_store_error(e: StoreError) -> PluginError {
    PluginError::Backend(e.to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use phonetool_core::SqliteStore;

    fn plugin() -> BaitTriage {
        let store: Arc<dyn IntelStore> =
            Arc::new(SqliteStore::open_in_memory().expect("in-memory store"));
        BaitTriage::new(store)
    }

    fn cmd(verb: &str, arg: &str) -> Command {
        Command {
            verb: verb.to_owned(),
            arg: arg.to_owned(),
        }
    }

    #[test]
    fn unsupported_verb_rejected() {
        let out = plugin().dispatch(&cmd("lookup", "{}"));
        assert!(matches!(out, Err(PluginError::Unsupported(_))));
    }

    #[test]
    fn empty_arg_is_invalid_input() {
        let out = plugin().dispatch(&cmd("triage", "   "));
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    }

    #[test]
    fn malformed_bundle_is_invalid_input() {
        let out = plugin().dispatch(&cmd("triage", "{not json"));
        assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    }

    #[test]
    fn zero_iocs_is_empty_degenerate() {
        // A well-formed bundle whose only content does not normalize to any IOC.
        let out = plugin().dispatch(&cmd("triage", r#"{"phone":"!!!"}"#));
        assert!(matches!(out, Err(PluginError::Empty(_))));
    }

    #[test]
    fn empty_object_is_empty_degenerate() {
        let out = plugin().dispatch(&cmd("triage", "{}"));
        assert!(matches!(out, Err(PluginError::Empty(_))));
    }

    #[test]
    fn thin_result_is_ok_low_no_correlation() {
        let out = plugin()
            .dispatch(&cmd("triage", r#"{"wallets":["bc1qXYZ"]}"#))
            .expect("thin but real");
        assert_eq!(out.source, "baittriage");
        assert_eq!(out.data["no_prior_correlation"], serde_json::json!(true));
        assert_eq!(out.data["confidence"], serde_json::json!("low"));
        assert!(out.summary.contains("no prior correlation"));
    }

    #[test]
    fn provenance_carried_by_path_never_read() {
        let out = plugin()
            .dispatch(&cmd(
                "triage",
                r#"{"wallets":["bc1qXYZ"],"source_capture":"/tmp/call-0001.wav"}"#,
            ))
            .expect("ok");
        assert_eq!(
            out.data["provenance"],
            serde_json::json!("/tmp/call-0001.wav")
        );
    }
}
