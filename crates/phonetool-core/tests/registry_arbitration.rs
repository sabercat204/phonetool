//! The registry arbitrates shared physical hardware: two distinct plugins cannot
//! both hold the same exclusive transducer (one SDR TX chain, one wireline tap).
//! `Store` is shareable and exempt.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;

use phonetool_core::{
    CapabilityClass, Command, DispatchError, Event, Gate, Manifest, NullConsentLog, Plugin,
    PluginError, PluginRegistry, RegisterError, Transducer, TxAuthorization, TxGrant, TxPlugin,
    WireAuthorization, WireGrant, WirePlugin,
};

/// A minimal mock plugin that claims a chosen transducer.
struct Mock {
    name: &'static str,
    transducer: Transducer,
}

impl Plugin for Mock {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: self.name.to_owned(),
            version: "0.0.0".to_owned(),
            transducer: self.transducer,
            capability: CapabilityClass::Passive,
            summary: "mock".to_owned(),
        }
    }
    fn dispatch(&self, _cmd: &Command) -> Result<Event, PluginError> {
        Err(PluginError::Unsupported("mock".to_owned()))
    }
}

/// A mock transmit plugin. Its `dispatch_tx` echoes the band from the `TxGrant`,
/// so a test can prove the Axis-B token actually reached the plugin.
struct TxMock {
    name: &'static str,
}

impl TxPlugin for TxMock {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: self.name.to_owned(),
            version: "0.0.0".to_owned(),
            transducer: Transducer::RfTx,
            capability: CapabilityClass::RfTx,
            summary: "tx mock".to_owned(),
        }
    }
    fn dispatch_tx(&self, _cmd: &Command, grant: &TxGrant) -> Result<Event, PluginError> {
        Ok(Event {
            source: self.name.to_owned(),
            summary: format!("transmitted on {}", grant.band()),
            data: serde_json::json!({ "band": grant.band(), "power_dbm": grant.power_dbm() }),
        })
    }
}

/// Mint a `TxGrant` the only legal way — through the gate. Used by the transmit
/// dispatch tests, which cannot fabricate a token (`TxGrant` has no public
/// constructor; the `compile_fail` doctest in authgate proves that half).
fn mint_tx_grant() -> TxGrant {
    let log = NullConsentLog;
    let gate = Gate::new(&log);
    gate.request_tx(TxAuthorization {
        band: "70cm".to_owned(),
        power_dbm: 30.0,
        license_basis: "amateur license (test)".to_owned(),
    })
    .expect("well-formed transmit authorization is granted")
}

#[test]
fn two_plugins_cannot_both_claim_rftx() {
    let mut reg = PluginRegistry::new();
    reg.register(Arc::new(Mock {
        name: "tx-a",
        transducer: Transducer::RfTx,
    }))
    .expect("first RfTx claim succeeds");

    let clash = reg.register(Arc::new(Mock {
        name: "tx-b",
        transducer: Transducer::RfTx,
    }));
    assert!(matches!(
        clash,
        Err(RegisterError::TransducerClaimed(Transducer::RfTx, _))
    ));
}

#[test]
fn store_transducer_is_shareable() {
    let mut reg = PluginRegistry::new();
    reg.register(Arc::new(Mock {
        name: "store-a",
        transducer: Transducer::Store,
    }))
    .expect("first Store plugin");
    // A second Store-only plugin is fine — the data layer is not exclusive.
    reg.register(Arc::new(Mock {
        name: "store-b",
        transducer: Transducer::Store,
    }))
    .expect("second Store plugin coexists");
    assert_eq!(reg.manifests().len(), 2);
}

#[test]
fn ip_transducer_is_shareable() {
    // `Ip` is the shared kernel network stack, not a scarce physical port:
    // numintel (cache/HTTP) and SIP recon both declare `Ip` and must coexist.
    let mut reg = PluginRegistry::new();
    reg.register(Arc::new(Mock {
        name: "numintel",
        transducer: Transducer::Ip,
    }))
    .expect("first Ip plugin");
    reg.register(Arc::new(Mock {
        name: "sip",
        transducer: Transducer::Ip,
    }))
    .expect("second Ip plugin coexists");
    assert_eq!(reg.manifests().len(), 2);
}

#[test]
fn rfrx_transducer_is_shareable() {
    // `RfRx` is the logical "SDR receive" medium, not the one physical dongle:
    // sdr-rx, gnss, and cell-survey are all passive RX layers that must
    // co-register and run on the same recorded IQ — above all on the
    // hardware-free IqFileSource path, where no device is contended at all.
    // (Physical-radio arbitration, when a live SDR exists, lives in the Tier-B
    // subprocess host that holds the device 1:1, not in this logical index.)
    let mut reg = PluginRegistry::new();
    for name in ["sdr-rx", "gnss", "cell-survey"] {
        reg.register(Arc::new(Mock {
            name,
            transducer: Transducer::RfRx,
        }))
        .expect("passive RfRx layers co-register");
    }
    assert_eq!(reg.manifests().len(), 3);
}

#[test]
fn two_plugins_cannot_both_claim_wireline() {
    // `Wireline` stays exclusive: the bench has one physical loop tap.
    let mut reg = PluginRegistry::new();
    reg.register(Arc::new(Mock {
        name: "line-a",
        transducer: Transducer::Wireline,
    }))
    .expect("first Wireline claim succeeds");
    let clash = reg.register(Arc::new(Mock {
        name: "line-b",
        transducer: Transducer::Wireline,
    }));
    assert!(matches!(
        clash,
        Err(RegisterError::TransducerClaimed(Transducer::Wireline, _))
    ));
}

#[test]
fn register_tx_shares_the_name_namespace_and_the_rftx_port() {
    // A TxPlugin routes through the same `claim`: it dup-checks against the
    // passive/active maps and holds the exclusive `RfTx` port.
    let mut reg = PluginRegistry::new();
    reg.register(Arc::new(Mock {
        name: "numintel",
        transducer: Transducer::Ip,
    }))
    .expect("passive plugin");
    reg.register_tx(Arc::new(TxMock { name: "rf-tx" }))
        .expect("first RfTx plugin claims the transmit port");

    // A second name collision across maps is refused.
    let dup = reg.register(Arc::new(Mock {
        name: "rf-tx",
        transducer: Transducer::Store,
    }));
    assert!(matches!(dup, Err(RegisterError::DuplicateName(_))));

    // A second TX plugin cannot co-hold the exclusive RfTx port.
    let clash = reg.register_tx(Arc::new(TxMock { name: "rf-tx-2" }));
    assert!(matches!(
        clash,
        Err(RegisterError::TransducerClaimed(Transducer::RfTx, _))
    ));

    // Both registered plugins appear in the unified listing, in order.
    assert_eq!(reg.manifests().len(), 2);
}

#[test]
fn dispatch_tx_carries_the_txgrant_to_the_plugin() {
    let mut reg = PluginRegistry::new();
    reg.register_tx(Arc::new(TxMock { name: "rf-tx" }))
        .expect("register transmit plugin");

    let grant = mint_tx_grant();
    let cmd = Command {
        verb: "transmit".to_owned(),
        arg: "cw".to_owned(),
    };
    let event = reg
        .dispatch_tx("rf-tx", &cmd, &grant)
        .expect("dispatch reaches the transmit plugin");
    // The plugin read band/power off the TxGrant — proof the token arrived.
    assert_eq!(event.data["band"], "70cm");
    assert_eq!(event.data["power_dbm"], 30.0);
}

#[test]
fn dispatch_tx_rejects_an_unknown_plugin() {
    let reg = PluginRegistry::new();
    let grant = mint_tx_grant();
    let cmd = Command {
        verb: "transmit".to_owned(),
        arg: "cw".to_owned(),
    };
    let err = reg
        .dispatch_tx("nope", &cmd, &grant)
        .expect_err("no such transmit plugin");
    assert!(matches!(err, DispatchError::NoSuchPlugin(_)));
}

#[test]
fn dispatch_paths_are_isolated_by_class() {
    // A transmit plugin is unreachable through the passive dispatch path: the
    // three maps are separate, so a name in `tx` is not in `passive`.
    let mut reg = PluginRegistry::new();
    reg.register_tx(Arc::new(TxMock { name: "rf-tx" }))
        .expect("register transmit plugin");
    let cmd = Command {
        verb: "transmit".to_owned(),
        arg: "cw".to_owned(),
    };
    let err = reg
        .dispatch("rf-tx", &cmd)
        .expect_err("a TX plugin is not reachable via the ungated passive path");
    assert!(matches!(err, DispatchError::NoSuchPlugin(_)));
}

/// A mock active-wireline plugin. Its `dispatch_wire` echoes the line-ID from the
/// `WireGrant`, proving the Axis-C token reached the plugin.
struct WireMock {
    name: &'static str,
}

impl WirePlugin for WireMock {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: self.name.to_owned(),
            version: "0.0.0".to_owned(),
            transducer: Transducer::Wireline,
            capability: CapabilityClass::ActiveWire,
            summary: "wire mock".to_owned(),
        }
    }
    fn dispatch_wire(&self, _cmd: &Command, grant: &WireGrant) -> Result<Event, PluginError> {
        Ok(Event {
            source: self.name.to_owned(),
            summary: format!("drove {}", grant.line_id()),
            data: serde_json::json!({ "line_id": grant.line_id() }),
        })
    }
}

fn mint_wire_grant() -> WireGrant {
    let log = NullConsentLog;
    let gate = Gate::new(&log);
    gate.request_wire(WireAuthorization {
        line_id: "lab-loop-3".to_owned(),
        plant_basis: "owned bench loop (test)".to_owned(),
    })
    .expect("well-formed wire authorization is granted")
}

#[test]
fn dispatch_wire_carries_the_wiregrant_to_the_plugin() {
    let mut reg = PluginRegistry::new();
    reg.register_wire(Arc::new(WireMock { name: "line" }))
        .expect("register wireline plugin");
    let grant = mint_wire_grant();
    let cmd = Command {
        verb: "seize".to_owned(),
        arg: String::new(),
    };
    let event = reg
        .dispatch_wire("line", &cmd, &grant)
        .expect("dispatch reaches the wireline plugin");
    // The plugin read the line-ID off the WireGrant — proof the token arrived.
    assert_eq!(event.data["line_id"], "lab-loop-3");
}

#[test]
fn a_wire_plugin_holds_the_exclusive_wireline_port() {
    // Two wireline plugins cannot co-hold the single pair of clips.
    let mut reg = PluginRegistry::new();
    reg.register_wire(Arc::new(WireMock { name: "line-a" }))
        .expect("first wireline plugin claims the port");
    let err = reg
        .register_wire(Arc::new(WireMock { name: "line-b" }))
        .expect_err("second wireline plugin cannot co-hold Wireline");
    assert!(matches!(err, RegisterError::TransducerClaimed(_, _)));
}

#[test]
fn a_wire_grant_cannot_reach_a_tx_plugin_and_vice_versa() {
    // The maps are isolated by class: a wireline name is not in the tx map.
    let mut reg = PluginRegistry::new();
    reg.register_wire(Arc::new(WireMock { name: "line" }))
        .expect("register wireline plugin");
    let cmd = Command {
        verb: "seize".to_owned(),
        arg: String::new(),
    };
    let err = reg
        .dispatch_tx("line", &cmd, &mint_tx_grant())
        .expect_err("a wireline plugin is not reachable via the transmit path");
    assert!(matches!(err, DispatchError::NoSuchPlugin(_)));
}
