//! End-to-end analysis through the `Plugin` boundary: a fixture corpus (one PDU
//! per flagged operation + a benign control), the hostile-input table, and the
//! degenerate-case discipline. Fixtures are operator-authored bytes, not a live
//! capture — no network, runs today.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use phonetool_core::{Command, Event, Plugin, PluginError};
use phonetool_ss7::Ss7Analyzer;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Build a TCAP Begin carrying one MAP Invoke of `opcode`.
fn map_invoke(opcode: u8) -> Vec<u8> {
    let invoke_body = vec![0x02, 0x01, 0x01, 0x02, 0x01, opcode];
    let mut invoke = vec![0xa1, invoke_body.len() as u8];
    invoke.extend_from_slice(&invoke_body);
    let mut portion = vec![0x6c, invoke.len() as u8];
    portion.extend_from_slice(&invoke);
    let mut body = vec![0x48, 0x01, 0x01];
    body.extend_from_slice(&portion);
    let mut msg = vec![0x62, body.len() as u8];
    msg.extend_from_slice(&body);
    msg
}

/// Build a Diameter S6a message of `cmd_code` (request).
fn diameter_msg(cmd: u32) -> Vec<u8> {
    let total = 20u32;
    let mut m = Vec::new();
    m.push(1); // version
    m.extend_from_slice(&total.to_be_bytes()[1..4]);
    m.push(0x80); // request
    m.extend_from_slice(&cmd.to_be_bytes()[1..4]);
    m.extend_from_slice(&16_777_251u32.to_be_bytes()); // S6a app-id
    m.extend_from_slice(&0u32.to_be_bytes());
    m.extend_from_slice(&0u32.to_be_bytes());
    m
}

fn analyze(arg: &str) -> Result<Event, PluginError> {
    Ss7Analyzer::new().dispatch(&Command {
        verb: "analyze".to_owned(),
        arg: arg.to_owned(),
    })
}

fn analyze_hex(pdus: &[Vec<u8>]) -> Result<Event, PluginError> {
    let lines: Vec<String> = pdus.iter().map(|p| to_hex(p)).collect();
    analyze(&format!("hex:{}", lines.join("\n")))
}

#[test]
fn fixture_corpus_flags_every_sensitive_op() {
    // (opcode, expected operation name, expected to be flagged)
    let map_cases: &[(u8, &str)] = &[
        (71, "anyTimeInterrogation"),   // location-disclosure
        (45, "sendRoutingInfoForSM"),   // location-disclosure
        (22, "sendRoutingInfo"),        // location-disclosure
        (70, "provideSubscriberInfo"),  // location-disclosure
        (56, "sendAuthenticationInfo"), // intercept-enabling
        (2, "updateLocation"),          // intercept-enabling
    ];
    for (opcode, name) in map_cases {
        let event = analyze_hex(&[map_invoke(*opcode)]).expect("valid");
        assert_eq!(event.data["flagged"], serde_json::json!(1), "{name}");
        let findings = event.data["findings"].as_array().expect("findings");
        assert_eq!(findings[0]["operation"], serde_json::json!(name));
    }
}

#[test]
fn diameter_air_and_ulr_flagged() {
    let air = analyze_hex(&[diameter_msg(318)]).expect("valid AIR");
    assert_eq!(air.data["flagged"], serde_json::json!(1));
    assert!(air.summary.contains("Authentication-Information"));

    let ulr = analyze_hex(&[diameter_msg(316)]).expect("valid ULR");
    assert_eq!(ulr.data["flagged"], serde_json::json!(1));
}

#[test]
fn benign_control_is_ok_zero_flagged() {
    // checkIMEI (43) decodes but is not flagged.
    let event = analyze_hex(&[map_invoke(43)]).expect("valid");
    assert_eq!(event.data["flagged"], serde_json::json!(0));
    assert_eq!(event.data["decoded"], serde_json::json!(1));
    assert!(event.summary.contains("no location-disclosure"));
}

#[test]
fn mixed_capture_counts_correctly() {
    // Two flagged (ATI + AIR) + one benign (checkIMEI) + one garbage.
    let pdus = vec![
        map_invoke(71),
        diameter_msg(318),
        map_invoke(43),
        vec![0x00, 0x11, 0x22], // undecodable
    ];
    let event = analyze_hex(&pdus).expect("valid");
    assert_eq!(event.data["total"], serde_json::json!(4));
    assert_eq!(event.data["decoded"], serde_json::json!(3));
    assert_eq!(event.data["flagged"], serde_json::json!(2));
}

// --- hostile-input table ---

#[test]
fn hostile_inputs_never_panic() {
    // empty arg
    assert!(matches!(analyze(""), Err(PluginError::InvalidInput(_))));
    assert!(matches!(analyze("   "), Err(PluginError::InvalidInput(_))));
    // bad hex
    assert!(matches!(
        analyze("hex:zzzz"),
        Err(PluginError::InvalidInput(_))
    ));
    assert!(matches!(
        analyze("hex:6"),
        Err(PluginError::InvalidInput(_))
    ));
    // comment-only dump → empty source
    assert!(matches!(
        analyze("hex:# just a comment"),
        Err(PluginError::InvalidInput(_))
    ));
    // truncated TCAP (Begin tag, length overruns) → undecodable → Empty
    assert!(matches!(
        analyze("hex:6240480101"),
        Err(PluginError::Empty(_))
    ));
    // all-garbage → Empty
    assert!(matches!(
        analyze("hex:000102\n0a0b0c"),
        Err(PluginError::Empty(_))
    ));
}

#[test]
fn pathological_ber_body_returns_a_result_never_panics() {
    // A large run of constructed-SEQUENCE headers as a TCAP Begin body. The BER
    // reader is bounded (definite-length only; a depth cap on descent) and the
    // decoder descends a fixed number of levels — so this cannot exhaust the stack.
    // The guarantee under test: analysis TERMINATES with a Result, never a panic or
    // a hang, on adversarial nesting.
    let mut nested = Vec::new();
    for _ in 0..4000 {
        nested.push(0x30); // SEQUENCE header
        nested.push(0x00); // zero-length (definite) — well-formed, deeply repeated
    }
    let mut msg = vec![0x62, 0x82];
    msg.extend_from_slice(&(nested.len() as u16).to_be_bytes());
    msg.extend_from_slice(&nested);
    // Either an Ok(Event) (Begin with no resolvable component) or an Err — both are
    // acceptable; the point is it returns without panicking.
    let r = analyze(&format!("hex:{}", to_hex(&msg)));
    assert!(r.is_ok() || matches!(r, Err(PluginError::Empty(_))));
}

#[test]
fn missing_pcap_file_is_invalid_input() {
    assert!(matches!(
        analyze("/no/such/capture.pcap"),
        Err(PluginError::InvalidInput(_))
    ));
}

#[test]
fn pcap_roundtrip_via_tempfile() {
    use std::io::Write as _;
    // Build a LINKTYPE_SCTP pcap with one DATA chunk carrying an ATI TCAP.
    let tcap = map_invoke(71);
    let chunk_len = 16 + tcap.len();
    let mut chunk = vec![0u8; 16];
    chunk[0] = 0; // DATA
    chunk[2..4].copy_from_slice(&(chunk_len as u16).to_be_bytes());
    chunk.extend_from_slice(&tcap);
    while !chunk.len().is_multiple_of(4) {
        chunk.push(0);
    }
    let mut sctp = vec![0u8; 12];
    sctp.extend_from_slice(&chunk);

    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic (bytes 0..4)
    pcap.extend_from_slice(&[0u8; 20]); // header body to byte 24
    pcap[20..24].copy_from_slice(&248u32.to_le_bytes()); // LINKTYPE_SCTP (bytes 20..24)
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&(sctp.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&(sctp.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&sctp);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("s6.pcap");
    std::fs::File::create(&path)
        .expect("create")
        .write_all(&pcap)
        .expect("write");

    let event = analyze(path.to_str().expect("utf8 path")).expect("valid pcap");
    assert_eq!(event.data["flagged"], serde_json::json!(1));
    assert!(event.summary.contains("anyTimeInterrogation"));
}
