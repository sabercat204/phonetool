//! Degenerate-case discipline for the numintel plugin.
//!
//! The bar: a technically-correct-but-useless result must FAIL, not pass. A
//! lookup that finds nothing is an error the operator sees, not an empty success
//! they mistake for "this number is clean."
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;

use phonetool_core::{
    CapabilityClass, Command, IntelStore, Plugin, PluginError, PluginRegistry, SqliteStore,
    Transducer,
};
use phonetool_numintel::{NumIntel, lookup, number::Number};

fn store() -> Arc<dyn IntelStore> {
    Arc::new(SqliteStore::open_in_memory().expect("in-memory store"))
}

fn lookup_cmd(number: &str) -> Command {
    Command {
        verb: "lookup".to_owned(),
        arg: number.to_owned(),
    }
}

#[test]
fn empty_lookup_fails_not_silently_ok() {
    let plugin = NumIntel::new(store());
    // A well-formed number with nothing cached: must be an Empty error.
    let err = plugin
        .dispatch(&lookup_cmd("+15125550100"))
        .expect_err("a cache miss must fail, not return an empty success");
    assert!(matches!(err, PluginError::Empty(_)));
}

#[test]
fn cache_hit_returns_offline_with_no_egress() {
    let store = store();
    // Seed the cache directly (the offline path), then look it up.
    let n = Number::parse("+15125550100").expect("valid E.164");
    store
        .put(
            lookup::NAMESPACE,
            n.as_e164(),
            r#"{"carrier":"TestCo","line":"mobile"}"#,
        )
        .expect("seed");

    let plugin = NumIntel::new(Arc::clone(&store));
    // Same number, human-separated international form → same E.164 key.
    let event = plugin
        .dispatch(&lookup_cmd("+1 (512) 555-0100"))
        .expect("cached number resolves offline");
    assert_eq!(event.source, "numintel");
    assert_eq!(event.data["carrier"], "TestCo");
    // No network was touched: the default build has no HTTP client compiled in,
    // and the plugin only consulted the store. (Enforced structurally by the
    // `online` feature being off — this test runs in the air-gapped build.)
}

#[test]
fn malformed_number_rejected_at_boundary() {
    let plugin = NumIntel::new(store());
    let err = plugin
        .dispatch(&lookup_cmd("+1-512-EVIL-URL"))
        .expect_err("illegal characters must be rejected before any lookup");
    assert!(matches!(err, PluginError::InvalidInput(_)));
}

#[test]
fn oversized_number_rejected() {
    let plugin = NumIntel::new(store());
    // 16 digits exceeds E.164's 15-digit maximum.
    let err = plugin
        .dispatch(&lookup_cmd("+1234567890123456"))
        .expect_err("over-length number rejected");
    assert!(matches!(err, PluginError::InvalidInput(_)));
}

#[test]
fn unsupported_verb_rejected() {
    let plugin = NumIntel::new(store());
    let err = plugin
        .dispatch(&Command {
            verb: "enumerate".to_owned(),
            arg: "+15125550100".to_owned(),
        })
        .expect_err("numintel only handles lookup");
    assert!(matches!(err, PluginError::Unsupported(_)));
}

#[test]
fn numintel_is_passive_and_registers_on_ip_transducer() {
    let plugin = NumIntel::new(store());
    let m = plugin.manifest();
    // Passive by construction: numintel is never handed a gate.
    assert_eq!(m.capability, CapabilityClass::Passive);
    assert_eq!(m.transducer, Transducer::Ip);
    assert_eq!(m.name, "numintel");
}

#[test]
fn registry_loads_and_dispatches_one_plugin() {
    let store = store();
    let n = Number::parse("+15125550100").expect("valid");
    store
        .put(lookup::NAMESPACE, n.as_e164(), r#"{"carrier":"TestCo"}"#)
        .expect("seed");

    let mut registry = PluginRegistry::new();
    registry
        .register(Arc::new(NumIntel::new(Arc::clone(&store))))
        .expect("first registration succeeds");
    assert_eq!(registry.manifests().len(), 1);

    let event = registry
        .dispatch("numintel", &lookup_cmd("+15125550100"))
        .expect("dispatch through the registry resolves");
    assert_eq!(event.source, "numintel");
}

#[test]
fn registry_rejects_duplicate_registration() {
    let store = store();
    let mut registry = PluginRegistry::new();
    registry
        .register(Arc::new(NumIntel::new(Arc::clone(&store))))
        .expect("first numintel registers");
    // Registering the same plugin again is refused at wiring time.
    let second = registry.register(Arc::new(NumIntel::new(store)));
    assert!(second.is_err());
}
