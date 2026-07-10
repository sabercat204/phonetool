//! Integration tests for the passive attest plugin: degenerate discipline,
//! input-sourcing equivalence, and the passive/no-gate invariant.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::Write;

use phonetool_attest::AttestInspect;
use phonetool_core::{CapabilityClass, Command, Plugin, PluginError, Transducer};

/// A valid SHAKEN-A PASSporT compact serialization (built with unpadded
/// base64url of the JOSE header, claims, and a stub signature).
fn shaken_a_token() -> String {
    fn enc(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(A[((n >> 18) & 63) as usize] as char);
            out.push(A[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(A[((n >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(A[(n & 63) as usize] as char);
            }
        }
        out
    }
    format!(
        "{}.{}.{}",
        enc(br#"{"alg":"ES256","typ":"passport","ppt":"shaken","x5u":"https://c.example/c.pem"}"#),
        enc(br#"{"attest":"A","orig":{"tn":"12155550100"},"iat":1700000000}"#),
        enc(&[9, 9, 9])
    )
}

fn inspect(arg: &str) -> Result<phonetool_core::Event, PluginError> {
    AttestInspect::new().dispatch(&Command {
        verb: "inspect".to_owned(),
        arg: arg.to_owned(),
    })
}

#[test]
fn manifest_is_passive_ip() {
    let m = AttestInspect::new().manifest();
    assert_eq!(m.name, "attest");
    assert_eq!(m.transducer, Transducer::Ip);
    assert_eq!(m.capability, CapabilityClass::Passive);
}

#[test]
fn unsupported_verb_rejected() {
    let err = AttestInspect::new()
        .dispatch(&Command {
            verb: "verify".to_owned(),
            arg: "x".to_owned(),
        })
        .expect_err("unsupported");
    assert!(matches!(err, PluginError::Unsupported(_)));
}

#[test]
fn empty_arg_is_empty_error() {
    let err = inspect("   ").expect_err("empty");
    assert!(matches!(err, PluginError::Empty(_)));
}

#[test]
fn inline_token_reports_full_structural_only() {
    let event = inspect(&shaken_a_token()).expect("valid token");
    assert_eq!(event.source, "attest");
    assert_eq!(event.data["attestation"], "full");
    assert_eq!(event.data["verification"]["status"], "structural_only");
}

#[test]
fn sip_message_without_identity_is_unsigned_finding() {
    let msg = "INVITE sip:bob@ex SIP/2.0\r\nVia: foo\r\nTo: <sip:bob@ex>\r\n\r\n";
    let event = inspect(msg).expect("SIP without Identity is a reportable result");
    assert_eq!(event.data["attestation"], "none");
    let findings = event.data["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f == "no_identity_header"));
}

#[test]
fn sip_message_with_identity_parses() {
    let msg = format!(
        "INVITE sip:bob@ex SIP/2.0\r\nVia: foo\r\nIdentity: {}\r\nTo: <sip:bob@ex>\r\n\r\n",
        shaken_a_token()
    );
    let event = inspect(&msg).expect("Identity header extracted + parsed");
    assert_eq!(event.data["attestation"], "full");
}

#[test]
fn inline_and_file_sources_are_equivalent() {
    let token = shaken_a_token();
    let inline = inspect(&token).expect("inline");

    // Write the token to a temp file and inspect via @path.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("phonetool_attest_{}.txt", std::process::id()));
    let mut f = std::fs::File::create(&path).expect("create");
    f.write_all(token.as_bytes()).expect("write");
    let from_file = inspect(&format!("@{}", path.display())).expect("file");

    assert_eq!(inline.data["attestation"], from_file.data["attestation"]);
    assert_eq!(inline.data["claims"], from_file.data["claims"]);
    std::fs::remove_file(&path).ok();
}

#[test]
fn missing_file_is_backend_error() {
    let err = inspect("@/nonexistent/attest.txt").expect_err("missing file");
    assert!(matches!(err, PluginError::Backend(_)));
}

#[test]
fn garbage_non_sip_non_token_is_invalid_input() {
    let err = inspect("this is not a sip message and not a passport").expect_err("garbage");
    assert!(matches!(err, PluginError::InvalidInput(_)));
}

#[test]
fn unknown_attest_value_not_coerced() {
    // Build a token with attest "Z".
    let token = {
        fn enc(b: &[u8]) -> String {
            const A: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut o = String::new();
            for c in b.chunks(3) {
                let n = ((c[0] as u32) << 16)
                    | ((*c.get(1).unwrap_or(&0) as u32) << 8)
                    | (*c.get(2).unwrap_or(&0) as u32);
                o.push(A[((n >> 18) & 63) as usize] as char);
                o.push(A[((n >> 12) & 63) as usize] as char);
                if c.len() > 1 {
                    o.push(A[((n >> 6) & 63) as usize] as char);
                }
                if c.len() > 2 {
                    o.push(A[(n & 63) as usize] as char);
                }
            }
            o
        }
        format!(
            "{}.{}.{}",
            enc(br#"{"alg":"ES256"}"#),
            enc(br#"{"attest":"Z"}"#),
            enc(&[0])
        )
    };
    let event = inspect(&token).expect("parses");
    assert_eq!(event.data["attestation"]["unknown"]["raw"], "Z");
}
