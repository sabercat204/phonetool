//! Correlation + degenerate discipline against a seeded store, plus the
//! backend-failure path and reuse idempotency, exercised through the plugin.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;

use phonetool_baittriage::BaitTriage;
use phonetool_baittriage::correlate::{ConfidenceCutoffs, KNOWN_BAD_NS, REUSE_NS, SIGNATURE_NS};
use phonetool_core::{Command, Event, IntelStore, Plugin, PluginError, SqliteStore, StoreError};

fn dispatch(store: Arc<dyn IntelStore>, arg: &str) -> Result<Event, PluginError> {
    BaitTriage::new(store).dispatch(&Command {
        verb: "triage".to_owned(),
        arg: arg.to_owned(),
    })
}

#[test]
fn known_bad_hit_correlates() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("store"));
    store
        .put(KNOWN_BAD_NS, "bc1qxyz", "seized 2026-01")
        .expect("seed");
    let event = dispatch(store, r#"{"wallets":["bc1qXYZ"]}"#).expect("ok");
    assert_eq!(event.data["no_prior_correlation"], serde_json::json!(false));
    assert_eq!(event.data["corroboration_count"], serde_json::json!(1));
    let corr = event.data["correlations"].as_array().expect("array");
    assert_eq!(corr[0]["kind"], serde_json::json!("known_bad"));
}

#[test]
fn prior_case_reuse_hit_correlates() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("store"));
    // A prior, different bait recorded this number under its own hash.
    store
        .put(REUSE_NS, "+15125550100", "aaaabbbbccccdddd")
        .expect("seed");
    let event = dispatch(store, r#"{"phone":"+15125550100"}"#).expect("ok");
    let corr = event.data["correlations"].as_array().expect("array");
    assert_eq!(corr[0]["kind"], serde_json::json!("prior_case"));
    assert_eq!(corr[0]["case_ref"], serde_json::json!("aaaabbbbccccdddd"));
}

#[test]
fn zero_iocs_is_empty_error() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("store"));
    assert!(matches!(
        dispatch(store, r#"{"phone":"not-a-number"}"#),
        Err(PluginError::Empty(_))
    ));
}

#[test]
fn thin_result_is_low_without_corroboration() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("store"));
    let event = dispatch(store, r#"{"wallets":["bc1qXYZ"]}"#).expect("ok");
    assert_eq!(event.data["confidence"], serde_json::json!("low"));
    assert_eq!(event.data["no_prior_correlation"], serde_json::json!(true));
    // No cutoffs injected → not graded; count is the honest signal.
    assert_eq!(event.data["confidence_graded"], serde_json::json!(false));
}

#[test]
fn injected_cutoffs_grade_above_low() {
    let store: Arc<dyn IntelStore> = Arc::new(SqliteStore::open_in_memory().expect("store"));
    store.put(KNOWN_BAD_NS, "bc1qxyz", "x").expect("seed");
    store.put(KNOWN_BAD_NS, "0xdead", "x").expect("seed");
    let plugin = BaitTriage::with_cutoffs(
        Arc::clone(&store),
        ConfidenceCutoffs {
            medium_at: 1,
            high_at: 2,
        },
    );
    let event = plugin
        .dispatch(&Command {
            verb: "triage".to_owned(),
            arg: r#"{"wallets":["bc1qXYZ","0xDEAD"]}"#.to_owned(),
        })
        .expect("ok");
    assert_eq!(event.data["confidence"], serde_json::json!("high"));
    assert_eq!(event.data["confidence_graded"], serde_json::json!(true));
}

#[test]
fn signature_seed_classifies_pattern() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("store"));
    // Email local parts are case-sensitive (RFC 5321), only the domain folds — so
    // the seed's local part must match the artifact's exactly; the domain may differ
    // in case. This asserts that normalization discipline end-to-end.
    store
        .put(
            SIGNATURE_NS,
            "agent@irs.evil.example",
            "irs_ssa_impersonation",
        )
        .expect("seed");
    let event = dispatch(store, r#"{"emails":["agent@IRS.evil.example"]}"#).expect("ok");
    assert_eq!(
        event.data["pattern"],
        serde_json::json!("irs_ssa_impersonation")
    );
}

#[test]
fn reuse_write_back_is_idempotent_across_retriage() {
    let store: Arc<dyn IntelStore> = Arc::new(SqliteStore::open_in_memory().expect("store"));
    let arg = r#"{"wallets":["bc1qXYZ"]}"#;

    // First triage writes the reuse index; result has no prior correlation.
    let first = dispatch(Arc::clone(&store), arg).expect("first");
    assert_eq!(first.data["no_prior_correlation"], serde_json::json!(true));

    // Re-triage the SAME bait: the reuse entry is self (same hash), NOT a prior
    // case, so it does not manufacture a correlation or inflate the count.
    let second = dispatch(Arc::clone(&store), arg).expect("second");
    assert_eq!(second.data["no_prior_correlation"], serde_json::json!(true));
    assert_eq!(second.data["corroboration_count"], serde_json::json!(0));
}

/// A store that fails every operation — proves a backend failure surfaces as
/// `PluginError::Backend`, never a panic or a silently-empty success.
struct FailingStore;

impl IntelStore for FailingStore {
    fn get(&self, _ns: &str, _key: &str) -> Result<Option<String>, StoreError> {
        Err(StoreError::Backend("simulated read failure".to_owned()))
    }
    fn put(&self, _ns: &str, _key: &str, _value: &str) -> Result<(), StoreError> {
        Err(StoreError::Backend("simulated write failure".to_owned()))
    }
}

#[test]
fn store_backend_failure_surfaces_as_backend_error() {
    let store: Arc<dyn IntelStore> = Arc::new(FailingStore);
    assert!(matches!(
        dispatch(store, r#"{"wallets":["bc1qXYZ"]}"#),
        Err(PluginError::Backend(_))
    ));
}
