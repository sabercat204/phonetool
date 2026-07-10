//! End-to-end tests for the first active capability.
//!
//! The point these prove: an enumeration is reachable **only** through a real
//! gate-minted `Grant`. The happy-path test does not fabricate a token (it
//! cannot — `Grant` has no public constructor; the `compile_fail` doctest in
//! `lib.rs` proves that half). It mints one the legal way, via
//! [`Gate::request_ip`], then drives [`SipRecon::dispatch_active`] against a
//! loopback SIP responder on `127.0.0.1` — operator-owned, so building and firing
//! here touches nothing external.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::HashSet;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use phonetool_core::{
    ActivePlugin, CaptureBus, CaptureRecord, Command, Decision, Denied, Gate, IpAuthorization,
    PluginError,
};
use phonetool_sip::{SipRecon, enumerate::EnumConfig};

/// A minted grant against a chosen target, for the tests that exercise the plugin
/// past the gate. The gate is not the thing under test in those cases — reaching
/// `dispatch_active` at all already required a real `Grant` — so this keeps them
/// terse. Uses a throwaway bus; the decision is logged there and discarded.
fn granted(bus: &CaptureBus, target: &str) -> phonetool_core::Grant {
    Gate::new(bus)
        .request_ip(IpAuthorization {
            target: target.to_owned(),
            basis: "loopback lab (operator-owned)".to_owned(),
        })
        .expect("well-formed authorization is granted")
}

fn fast_cfg() -> EnumConfig {
    EnumConfig {
        bind: "127.0.0.1:0".to_owned(),
        timeout: Duration::from_millis(300),
        user_agent: "phonetool-sip-test".to_owned(),
    }
}

/// Pull the probed extension out of an OPTIONS request's first line:
/// `OPTIONS sip:<ext>@<host> SIP/2.0`. Returns `None` on anything unexpected so
/// the responder never panics on a stray datagram.
fn extension_from_request(datagram: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(datagram);
    let first = text.lines().next()?;
    let uri = first.split_whitespace().nth(1)?; // sip:<ext>@<host>
    let after = uri.strip_prefix("sip:")?;
    let ext = after.split('@').next()?;
    Some(ext.to_owned())
}

/// A minimal loopback SIP endpoint: answers `200 OK` (with a `Server` header for
/// the fingerprint assertion) to extensions in `seeded`, `404 Not Found` to the
/// rest. Bounded by both the probe count and a read timeout, so it always exits.
fn spawn_responder(
    socket: UdpSocket,
    seeded: HashSet<String>,
    expected_probes: usize,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for _ in 0..expected_probes {
            let mut buf = [0u8; 2048];
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    let ext = extension_from_request(&buf[..len]).unwrap_or_default();
                    let reply: &[u8] = if seeded.contains(&ext) {
                        b"SIP/2.0 200 OK\r\nServer: test-pbx\r\nContent-Length: 0\r\n\r\n"
                    } else {
                        b"SIP/2.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                    };
                    let _ = socket.send_to(reply, src);
                }
                Err(_) => break, // read timeout / transport error: stop cleanly
            }
        }
    })
}

#[test]
fn enumerates_against_a_loopback_responder_via_a_minted_grant() {
    // Bind the responder first: the kernel buffers datagrams on a bound socket
    // even before the thread calls recv, so no probe can be lost to a startup race.
    let responder = UdpSocket::bind("127.0.0.1:0").expect("bind loopback responder");
    let target = responder
        .local_addr()
        .expect("responder local addr")
        .to_string();
    responder
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("responder read timeout");

    let seeded: HashSet<String> = ["100", "200"].into_iter().map(str::to_owned).collect();
    let probes = ["100", "200", "404", "999"];
    let handle = spawn_responder(responder, seeded.clone(), probes.len());

    // The ONLY way to a Grant: through the gate. Mint it against the loopback
    // target with a real basis; the decision is logged to the production bus.
    let bus = CaptureBus::new();
    let gate = Gate::new(&bus);
    let grant = gate
        .request_ip(IpAuthorization {
            target: target.clone(),
            basis: "loopback lab (operator-owned 127.0.0.1)".to_owned(),
        })
        .expect("well-formed authorization is granted");

    let cfg = EnumConfig {
        bind: "127.0.0.1:0".to_owned(),
        timeout: Duration::from_millis(500),
        user_agent: "phonetool-sip-test".to_owned(),
    };
    let plugin = SipRecon::with_config(cfg);
    let cmd = Command {
        verb: "enum".to_owned(),
        arg: probes.join(","),
    };

    let event = plugin
        .dispatch_active(&cmd, &grant)
        .expect("enumeration with responses is a real result");

    handle.join().expect("responder thread joins");

    // Aggregate shape: every probe answered; the two seeded extensions exist.
    assert_eq!(event.source, "sip");
    assert_eq!(event.data["target"], target);
    assert_eq!(event.data["probed"], 4);
    assert_eq!(event.data["responded"], 4);
    assert_eq!(event.data["exists"], 2);

    // Per-extension verdicts + the 200's server fingerprint.
    let findings = event.data["findings"]
        .as_array()
        .expect("findings is an array");
    assert_eq!(findings.len(), 4);
    for f in findings {
        let ext = f["extension"].as_str().expect("extension string");
        assert_eq!(f["responded"], true);
        if seeded.contains(ext) {
            assert_eq!(f["verdict"], "exists", "seeded ext {ext} should exist");
            assert_eq!(f["status_code"], 200);
            assert_eq!(f["fingerprint"], "test-pbx");
        } else {
            assert_eq!(
                f["verdict"], "absent",
                "unseeded ext {ext} should be absent"
            );
            assert_eq!(f["status_code"], 404);
        }
    }
}

#[test]
fn gate_refuses_empty_basis_and_records_it_on_the_production_bus() {
    // Mirrors the CLI's `sip enum` guard: an empty basis is a fail-closed refusal,
    // and the refusal is logged to the same CaptureBus timeline as any grant.
    // (Authgate proves gate behavior in isolation with a mock log; this proves it
    // against the real consent sink the workbench actually wires in.)
    let bus = CaptureBus::new();
    let gate = Gate::new(&bus);

    let denied = gate
        .request_ip(IpAuthorization {
            target: "127.0.0.1:5099".to_owned(),
            basis: String::new(),
        })
        .expect_err("empty basis must be refused");
    assert_eq!(denied, Denied::NoBasis);

    let records = bus.records();
    assert_eq!(records.len(), 1, "exactly one decision recorded");
    match records.first() {
        Some(CaptureRecord::Consent(record)) => {
            assert!(
                matches!(record.decision, Decision::Refused { .. }),
                "the recorded decision is a refusal"
            );
        }
        other => panic!("expected a Consent refusal record, got {other:?}"),
    }
}

#[test]
fn no_listener_is_an_empty_failure_not_an_empty_success() {
    // The degenerate-case discipline on the active path: a probe that reaches a
    // dead target got authorized and ran, but produced nothing useful — that is a
    // *failure* the operator sees, not an empty-but-OK result. Bind a port, drop
    // it, and enumerate the now-dead address on loopback (deterministic: nothing
    // is listening, so every probe times out).
    let dead = {
        let s = UdpSocket::bind("127.0.0.1:0").expect("bind to reserve a dead port");
        s.local_addr().expect("addr").to_string()
    };
    let bus = CaptureBus::new();
    let grant = granted(&bus, &dead);

    let plugin = SipRecon::with_config(fast_cfg());
    let cmd = Command {
        verb: "enum".to_owned(),
        arg: "100,101".to_owned(),
    };
    let err = plugin
        .dispatch_active(&cmd, &grant)
        .expect_err("no response across all probes must be an Empty failure");
    assert!(matches!(err, PluginError::Empty(_)), "got {err:?}");

    // Even a failed op leaves the authorization on the timeline: the grant is there.
    assert_eq!(bus.records().len(), 1, "the grant decision was recorded");
}

#[test]
fn illegal_extension_is_rejected_at_the_boundary_before_any_packet() {
    // A grant is minted (authorization is fine), but an injection-shaped extension
    // is refused at the plugin's input boundary — before a datagram leaves the box.
    let bus = CaptureBus::new();
    let grant = granted(&bus, "127.0.0.1:9"); // discard port; never actually hit
    let plugin = SipRecon::with_config(fast_cfg());
    let cmd = Command {
        verb: "enum".to_owned(),
        arg: "100,ad min@evil".to_owned(),
    };
    let err = plugin
        .dispatch_active(&cmd, &grant)
        .expect_err("illegal characters in an extension are rejected");
    assert!(matches!(err, PluginError::InvalidInput(_)), "got {err:?}");
}

#[test]
fn unsupported_verb_is_rejected() {
    let bus = CaptureBus::new();
    let grant = granted(&bus, "127.0.0.1:9");
    let plugin = SipRecon::with_config(fast_cfg());
    let cmd = Command {
        verb: "brute".to_owned(), // only "enum" is supported
        arg: "100".to_owned(),
    };
    let err = plugin
        .dispatch_active(&cmd, &grant)
        .expect_err("unsupported verb is rejected");
    assert!(matches!(err, PluginError::Unsupported(_)), "got {err:?}");
}

#[test]
fn empty_extension_list_is_invalid_input() {
    let bus = CaptureBus::new();
    let grant = granted(&bus, "127.0.0.1:9");
    let plugin = SipRecon::with_config(fast_cfg());
    let cmd = Command {
        verb: "enum".to_owned(),
        arg: "  , ,".to_owned(), // separators only — no real extension
    };
    let err = plugin
        .dispatch_active(&cmd, &grant)
        .expect_err("a list with no real extensions is InvalidInput");
    assert!(matches!(err, PluginError::InvalidInput(_)), "got {err:?}");
}
