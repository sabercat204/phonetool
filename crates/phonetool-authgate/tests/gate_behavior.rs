//! Behavioral tests for the gate's fail-closed contract and consent logging.
//!
//! The compile-time guarantee (an active op is unrepresentable without a token)
//! is covered by the `compile_fail` doctest in `lib.rs`. These tests cover the
//! runtime half: refusal on absent/malformed authorization, and that *every*
//! decision — grant and refusal — is logged.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Mutex;

use phonetool_authgate::{
    Capability, ConsentLog, ConsentRecord, Decision, Denied, Gate, IpAuthorization,
    TxAuthorization, WireAuthorization,
};

/// A consent log that captures records, so tests can assert on what was logged.
#[derive(Default)]
struct CapturingLog {
    records: Mutex<Vec<ConsentRecord>>,
}

impl CapturingLog {
    fn records(&self) -> Vec<ConsentRecord> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

impl ConsentLog for CapturingLog {
    fn record(&self, record: ConsentRecord) {
        if let Ok(mut r) = self.records.lock() {
            r.push(record);
        }
    }
}

#[test]
fn ip_grant_succeeds_with_target_and_basis() {
    let log = CapturingLog::default();
    let gate = Gate::new(&log);
    let grant = gate
        .request_ip(IpAuthorization {
            target: "lab-pbx.local".to_owned(),
            basis: "owned test bench".to_owned(),
        })
        .expect("well-formed authorization should be granted");
    assert_eq!(grant.target(), "lab-pbx.local");
    assert_eq!(grant.basis(), "owned test bench");

    let recs = log.records();
    assert_eq!(recs.len(), 1, "one decision logged");
    assert_eq!(recs[0].decision, Decision::Granted);
}

#[test]
fn ip_request_fails_closed_on_empty_target() {
    let log = CapturingLog::default();
    let gate = Gate::new(&log);
    let err = gate
        .request_ip(IpAuthorization {
            target: "   ".to_owned(),
            basis: "some basis".to_owned(),
        })
        .expect_err("empty target must be refused");
    assert_eq!(err, Denied::NoTarget);

    // A refusal is logged just as deliberately as a grant.
    let recs = log.records();
    assert_eq!(recs.len(), 1);
    assert!(matches!(recs[0].decision, Decision::Refused { .. }));
}

#[test]
fn ip_request_fails_closed_on_empty_basis() {
    let log = CapturingLog::default();
    let gate = Gate::new(&log);
    let err = gate
        .request_ip(IpAuthorization {
            target: "remote.example".to_owned(),
            basis: String::new(),
        })
        .expect_err("empty basis must be refused");
    assert_eq!(err, Denied::NoBasis);
}

#[test]
fn tx_request_fails_closed_on_nonfinite_power() {
    let log = CapturingLog::default();
    let gate = Gate::new(&log);
    let err = gate
        .request_tx(TxAuthorization {
            band: "70cm amateur".to_owned(),
            power_dbm: f64::NAN,
            license_basis: "Part 97, callsign KX0XXX".to_owned(),
        })
        .expect_err("non-finite power must be refused");
    assert!(matches!(err, Denied::Invalid(_)));
}

#[test]
fn tx_grant_carries_regulatory_basis() {
    let log = CapturingLog::default();
    let gate = Gate::new(&log);
    let tx = gate
        .request_tx(TxAuthorization {
            band: "70cm amateur".to_owned(),
            power_dbm: 30.0,
            license_basis: "Part 97, callsign KX0XXX".to_owned(),
        })
        .expect("well-formed TX authorization should be granted");
    assert_eq!(tx.band(), "70cm amateur");
    assert!((tx.power_dbm() - 30.0).abs() < f64::EPSILON);
    assert_eq!(tx.license_basis(), "Part 97, callsign KX0XXX");
}

#[test]
fn wire_grant_succeeds_with_line_and_basis() {
    let log = CapturingLog::default();
    let gate = Gate::new(&log);
    let wire = gate
        .request_wire(WireAuthorization {
            line_id: "lab-loop-3".to_owned(),
            plant_basis: "owned bench loop simulator".to_owned(),
        })
        .expect("well-formed wire authorization should be granted");
    assert_eq!(wire.line_id(), "lab-loop-3");
    assert_eq!(wire.plant_basis(), "owned bench loop simulator");

    let recs = log.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, Decision::Granted);
    // The decision is logged under the Wireline (Axis-C) capability, not miscoded
    // as an ActiveIp — the consent log is honest about which authority was asserted.
    assert!(matches!(recs[0].capability, Capability::Wireline { .. }));
}

#[test]
fn wire_request_fails_closed_on_empty_line_id() {
    let log = CapturingLog::default();
    let gate = Gate::new(&log);
    let err = gate
        .request_wire(WireAuthorization {
            line_id: "  ".to_owned(),
            plant_basis: "basis".to_owned(),
        })
        .expect_err("empty line-ID must be refused");
    assert_eq!(err, Denied::NoTarget);
    assert!(matches!(
        log.records()[0].decision,
        Decision::Refused { .. }
    ));
}

#[test]
fn wire_request_fails_closed_on_empty_plant_basis() {
    let log = CapturingLog::default();
    let gate = Gate::new(&log);
    let err = gate
        .request_wire(WireAuthorization {
            line_id: "lab-loop-3".to_owned(),
            plant_basis: String::new(),
        })
        .expect_err("empty plant basis must be refused");
    assert_eq!(err, Denied::NoBasis);
}
