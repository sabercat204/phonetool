//! End-to-end integration: a recorded GSMTAP-over-pcap capture driven through
//! `CellSurvey::dispatch` → decode → cell map → anomaly scan, with no radio.
//! Also exercises the degenerate-case discipline and the passive-plugin posture.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::Write as _;

use phonetool_cell_survey::CellSurvey;
use phonetool_core::{Command, Plugin, PluginError};

// --- pcap/GSMTAP builders (mirror the grounded on-wire format) ---

const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
const LINKTYPE_GSMTAP_UM: u32 = 217;
const GSMTAP_HDR_LEN: usize = 16;
const GSMTAP_VERSION: u8 = 0x02;
const GSMTAP_TYPE_UM: u8 = 0x01;

fn pcap_global_header() -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes());
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&65535u32.to_le_bytes());
    h.extend_from_slice(&LINKTYPE_GSMTAP_UM.to_le_bytes());
    h
}

fn gsmtap_frame(arfcn: u16, signal_dbm: i8, l3: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; GSMTAP_HDR_LEN];
    frame[0] = GSMTAP_VERSION;
    frame[1] = (GSMTAP_HDR_LEN / 4) as u8;
    frame[2] = GSMTAP_TYPE_UM;
    frame[4..6].copy_from_slice(&arfcn.to_be_bytes());
    frame[6] = signal_dbm as u8;
    frame.extend_from_slice(l3);
    frame
}

fn pcap_record(payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    r.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    r.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // incl_len
    r.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // orig_len
    r.extend_from_slice(payload);
    r
}

/// SI Type 3 L3 message: header + cell identity + LAI (MCC 262 MNC 02, LAC).
fn si3(cid: u16, lac: u16) -> Vec<u8> {
    let mut m = vec![0x00, 0x06, 0x1b]; // L2 plen, PDISC_RR, SYSINFO_3
    m.extend_from_slice(&cid.to_be_bytes());
    m.extend_from_slice(&[0x62, 0xf2, 0x20]); // PLMN 262-02 (2-digit MNC)
    m.extend_from_slice(&lac.to_be_bytes());
    m
}

fn write_capture(frames: &[Vec<u8>]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("temp file");
    let mut buf = pcap_global_header();
    for frame in frames {
        buf.extend_from_slice(&pcap_record(frame));
    }
    f.write_all(&buf).expect("write capture");
    f.flush().expect("flush");
    f
}

fn survey(path: &std::path::Path) -> Result<phonetool_core::Event, PluginError> {
    CellSurvey::new().dispatch(&Command {
        verb: "survey".to_owned(),
        arg: path.display().to_string(),
    })
}

#[test]
fn decodes_a_recorded_capture_end_to_end() {
    let cap = write_capture(&[
        gsmtap_frame(10, -70, &si3(0x1234, 100)),
        gsmtap_frame(20, -80, &si3(0x5678, 100)),
    ]);
    let event = survey(cap.path()).expect("survey succeeds");
    assert_eq!(event.source, "cell-survey");
    assert_eq!(event.data["distinct_cells"], 2);
    assert_eq!(event.data["segments"], 2);
    // Honest scope surfaced in the event.
    assert_eq!(event.data["rats_decoded"][0], "gsm");
    assert_eq!(event.data["rats_seam_only"][0], "lte");
}

#[test]
fn a_capture_that_decodes_nothing_is_empty_failure() {
    // A GSMTAP frame carrying a non-RR L3 message: decode miss, zero cells.
    let non_rr = vec![0x00, 0x05, 0x00, 0xaa]; // PDISC 5 (MM), not RR
    let cap = write_capture(&[gsmtap_frame(10, -70, &non_rr)]);
    let err = survey(cap.path()).unwrap_err();
    assert!(matches!(err, PluginError::Empty(_)), "got {err:?}");
    // The Empty message names the source (degenerate-case discipline).
    assert!(err.to_string().contains("no cells decoded"));
}

#[test]
fn missing_file_is_invalid_input_not_a_panic() {
    let err = CellSurvey::new()
        .dispatch(&Command {
            verb: "survey".to_owned(),
            arg: "/no/such/capture.pcap".to_owned(),
        })
        .unwrap_err();
    assert!(matches!(err, PluginError::InvalidInput(_)));
}

#[test]
fn garbage_file_is_invalid_input() {
    let mut f = tempfile::NamedTempFile::new().expect("temp");
    f.write_all(b"this is not a pcap file").expect("write");
    f.flush().expect("flush");
    let err = survey(f.path()).unwrap_err();
    assert!(matches!(err, PluginError::InvalidInput(_)));
}

#[test]
fn event_data_carries_decoded_cells_not_raw_samples() {
    let cap = write_capture(&[gsmtap_frame(10, -70, &si3(1, 100))]);
    let event = survey(cap.path()).expect("ok");
    let json = serde_json::to_string(&event.data).expect("serialize");
    // Bounded by cell count: the decoded cells are present, raw payload is not.
    assert!(json.contains("cells"));
    assert!(!json.contains("payload"));
}

#[test]
fn manifest_lists_as_passive_rfrx() {
    let m = CellSurvey::new().manifest();
    assert_eq!(m.name, "cell-survey");
    assert_eq!(
        format!("{:?}/{:?}", m.transducer, m.capability),
        "RfRx/Passive"
    );
}
