//! Gate-only end-to-end: mint a TxGrant the ONLY legal way (through the real
//! Gate::request_tx on a consent log), then drive dispatch_tx with the default
//! FileSink. Rendering to a file is not an emission. Also asserts the fail-closed
//! gate refusals and the band/power enforcement occur before any sink work.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Mutex;

use phonetool_authgate::{
    Capability, ConsentLog, ConsentRecord, Decision, Gate, TxAuthorization, TxGrant,
};
use phonetool_core::{Command, PluginError, TxPlugin};
use phonetool_rf_tx::{RfTx, TxConfig};

/// A consent log that captures records, so a test can assert the gate logged a
/// grant or a refusal.
#[derive(Default)]
struct RecordingLog {
    records: Mutex<Vec<ConsentRecord>>,
}

impl ConsentLog for RecordingLog {
    fn record(&self, record: ConsentRecord) {
        self.records.lock().expect("lock").push(record);
    }
}

fn mint(log: &dyn ConsentLog, band: &str, power_dbm: f64, license: &str) -> Result<TxGrant, ()> {
    Gate::new(log)
        .request_tx(TxAuthorization {
            band: band.to_owned(),
            power_dbm,
            license_basis: license.to_owned(),
        })
        .map_err(|_| ())
}

fn rf_tx(path: &std::path::Path) -> RfTx {
    RfTx::with_config(TxConfig {
        out_path: path.to_path_buf(),
        ..Default::default()
    })
}

#[test]
fn gate_grant_then_render_writes_file_and_logs_grant() {
    let log = RecordingLog::default();
    let grant = mint(&log, "2m", 40.0, "K0TEST general").expect("granted");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cw.cf32");
    let event = rf_tx(&path)
        .dispatch_tx(
            &Command {
                verb: "cw".to_owned(),
                arg: r#"{"freq_hz":146520000,"payload":"CQ CQ"}"#.to_owned(),
            },
            &grant,
        )
        .expect("render");

    assert_eq!(event.source, "rf-tx");
    assert!(path.exists(), "FileSink wrote the waveform");
    // The gate logged exactly one Granted decision for an RfTx capability.
    let records = log.records.lock().expect("lock");
    assert_eq!(records.len(), 1);
    assert!(matches!(records[0].decision, Decision::Granted));
    assert!(matches!(records[0].capability, Capability::RfTx { .. }));
}

#[test]
fn empty_band_is_fail_closed_refusal_no_grant() {
    let log = RecordingLog::default();
    // An empty band → Denied; no TxGrant minted, so no transmit is representable.
    assert!(mint(&log, "", 40.0, "license").is_err());
    let records = log.records.lock().expect("lock");
    assert_eq!(records.len(), 1);
    assert!(matches!(records[0].decision, Decision::Refused { .. }));
}

#[test]
fn empty_license_is_fail_closed_refusal() {
    let log = RecordingLog::default();
    assert!(mint(&log, "2m", 40.0, "").is_err());
    let records = log.records.lock().expect("lock");
    assert!(matches!(records[0].decision, Decision::Refused { .. }));
}

#[test]
fn wrong_band_frequency_refused_before_sink() {
    // A 70cm grant with a 2m frequency → InvalidInput, no file written.
    let log = RecordingLog::default();
    let grant = mint(&log, "70cm", 30.0, "license").expect("granted");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("never.cf32");
    let out = rf_tx(&path).dispatch_tx(
        &Command {
            verb: "cw".to_owned(),
            arg: r#"{"freq_hz":146000000,"payload":"E"}"#.to_owned(),
        },
        &grant,
    );
    assert!(matches!(out, Err(PluginError::InvalidInput(_))));
    assert!(!path.exists(), "refused transmission reaches no sink");
}

#[test]
fn empty_payload_never_keys_sink() {
    let log = RecordingLog::default();
    let grant = mint(&log, "2m", 40.0, "license").expect("granted");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("empty.cf32");
    let out = rf_tx(&path).dispatch_tx(
        &Command {
            verb: "cw".to_owned(),
            arg: r#"{"freq_hz":146520000,"payload":""}"#.to_owned(),
        },
        &grant,
    );
    assert!(matches!(out, Err(PluginError::Empty(_))));
    assert!(!path.exists(), "no sink keyed with a zero-sample waveform");
}

#[test]
fn afsk_end_to_end_via_gate() {
    let log = RecordingLog::default();
    let grant = mint(&log, "2m", 40.0, "license").expect("granted");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("aprs.cf32");
    let event = rf_tx(&path)
        .dispatch_tx(
            &Command {
                verb: "afsk".to_owned(),
                arg: r#"{"freq_hz":144390000,"payload":"N0CALL-9>APRS:!4903.50N/07201.75W-"}"#
                    .to_owned(),
            },
            &grant,
        )
        .expect("render");
    assert_eq!(event.data["scheme"], serde_json::json!("afsk"));
    assert!(path.exists());
}
