//! End-to-end tests for the workbench's second active capability.
//!
//! The point these prove: an origination is reachable **only** through a real
//! gate-minted `Grant`. The happy-path test does not fabricate a token (it cannot
//! — `Grant` has no public constructor; the `compile_fail` doctest in `lib.rs`
//! proves that half). It mints one the legal way, via [`Gate::request_ip`], then
//! drives [`WarDial::dispatch_active`] against a loopback SIP responder on
//! `127.0.0.1` — operator-owned, so building and firing here rings no one and
//! costs nothing. (Firing at loopback ≠ originating onto the PSTN, which requires
//! a real `TrunkConfig` this test never supplies.)
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::HashSet;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use phonetool_core::{
    ActivePlugin, CaptureBus, CaptureRecord, Command, Decision, Denied, Gate, IpAuthorization,
    PluginError,
};
use phonetool_wardial::WarDial;
use phonetool_wardial::originate::SweepConfig;

/// Fast, loopback-bound sweep config: short deadline, no pacing delay (the
/// default 1 call/sec would make a multi-DID test needlessly slow; pacing is
/// unit-tested elsewhere).
fn fast_cfg() -> SweepConfig {
    SweepConfig {
        bind: "127.0.0.1:0".to_owned(),
        per_call_deadline: Duration::from_millis(400),
        min_call_interval: Duration::ZERO,
        max_range: 32,
        recv_cap: 16 * 1024,
        user_agent: "phonetool-wardial-test".to_owned(),
    }
}

/// Mint a grant the only legal way — through the real gate — against a loopback
/// DID range. The decision is logged to `bus`.
fn granted(bus: &CaptureBus, range: &str) -> phonetool_core::Grant {
    Gate::new(bus)
        .request_ip(IpAuthorization {
            target: range.to_owned(),
            basis: "loopback lab (operator-owned); billing+attribution acknowledged".to_owned(),
        })
        .expect("well-formed authorization is granted")
}

/// Pull the DID from an INVITE's first line: `INVITE sip:<did>@<host> SIP/2.0`.
fn did_from_invite(datagram: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(datagram);
    let first = text.lines().next()?;
    if !first.starts_with("INVITE ") {
        return None; // ignore ACK/BYE/CANCEL teardown traffic
    }
    let uri = first.split_whitespace().nth(1)?; // sip:<did>@<host>
    let after = uri.strip_prefix("sip:")?;
    Some(after.split('@').next()?.to_owned())
}

/// A minimal loopback SIP endpoint. For each INVITE it receives, replies with a
/// scripted final status code chosen by the DID: DIDs in `answered` get 200 OK,
/// DIDs in `busy` get 486, everything else 404. Ignores ACK/BYE/CANCEL. Bounded
/// by a read timeout so it always exits.
fn spawn_responder(
    socket: UdpSocket,
    answered: HashSet<String>,
    busy: HashSet<String>,
    invites_expected: usize,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut seen = 0;
        while seen < invites_expected {
            let mut buf = [0u8; 4096];
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    let Some(did) = did_from_invite(&buf[..len]) else {
                        continue; // teardown or junk — not an INVITE
                    };
                    seen += 1;
                    let reply: &[u8] = if answered.contains(&did) {
                        b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"
                    } else if busy.contains(&did) {
                        b"SIP/2.0 486 Busy Here\r\nContent-Length: 0\r\n\r\n"
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
fn sweeps_a_loopback_range_via_a_minted_grant() {
    let responder = UdpSocket::bind("127.0.0.1:0").expect("bind loopback responder");
    let target = responder.local_addr().expect("addr").to_string();
    responder
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("responder timeout");

    // Range +1512555:0100-0103 → DIDs 0100..0103. Script: 0100 answers, 0101 busy,
    // rest 404. (The range lives in the GRANT; the responder keys off the DID.)
    let answered: HashSet<String> = ["+15125550100".to_owned()].into_iter().collect();
    let busy: HashSet<String> = ["+15125550101".to_owned()].into_iter().collect();
    let handle = spawn_responder(responder, answered.clone(), busy.clone(), 4);

    let bus = CaptureBus::new();
    let grant = granted(&bus, "+1512555:0100-0103");

    // No trunk → loopback origination against the operator-owned responder.
    let plugin = WarDial::with_loopback(fast_cfg(), target.clone());
    let cmd = Command {
        verb: "sweep".to_owned(),
        arg: String::new(), // range is in the grant, never the command
    };

    let event = plugin
        .dispatch_active(&cmd, &grant)
        .expect("a sweep with responses is a real result");

    handle.join().expect("responder joins");

    assert_eq!(event.source, "wardial");
    assert_eq!(event.data["range"], "+1512555:0100-0103");
    assert_eq!(event.data["placed"], 4);
    assert_eq!(event.data["reached"], 4);
    assert_eq!(event.data["answered"], 1);

    // Per-DID SIP dispositions; media is NotAnalyzed (no media path).
    let results = event.data["results"].as_array().expect("results array");
    assert_eq!(results.len(), 4);
    for r in results {
        let did = r["did"].as_str().expect("did");
        assert_eq!(r["reached"], true);
        assert_eq!(r["outcome"]["media"], "not_analyzed");
        if answered.contains(did) {
            assert_eq!(r["outcome"]["sip"], "answered");
            assert_eq!(r["sip_code"], 200);
        } else if busy.contains(did) {
            assert_eq!(r["outcome"]["sip"], "busy");
            assert_eq!(r["sip_code"], 486);
        } else {
            assert_eq!(r["outcome"]["sip"], "rejected"); // 404 → Rejected at SIP granularity
        }
    }
}

#[test]
fn a_silent_target_is_an_empty_failure_not_an_empty_success() {
    // Degenerate discipline on the active path: reserve a loopback port, drop it,
    // and sweep the now-dead address. Every call times out → nothing reached →
    // Empty, never an empty-but-OK result.
    let dead = {
        let s = UdpSocket::bind("127.0.0.1:0").expect("reserve a dead port");
        s.local_addr().expect("addr").to_string()
    };
    let bus = CaptureBus::new();
    let grant = granted(&bus, "+1512555:0100-0101");

    let plugin = WarDial::with_loopback(fast_cfg(), dead);
    let cmd = Command {
        verb: "sweep".to_owned(),
        arg: String::new(),
    };
    let err = plugin
        .dispatch_active(&cmd, &grant)
        .expect_err("no DID reached must be an Empty failure");
    assert!(matches!(err, PluginError::Empty(_)), "got {err:?}");

    // The grant decision is still on the timeline even though the op failed.
    assert_eq!(bus.records().len(), 1, "the grant decision was recorded");
}

#[test]
fn gate_refuses_empty_basis_and_records_it_on_the_production_bus() {
    // Mirrors the CLI guard: an empty basis is a fail-closed refusal, logged to
    // the same CaptureBus timeline as any grant.
    let bus = CaptureBus::new();
    let gate = Gate::new(&bus);

    let denied = gate
        .request_ip(IpAuthorization {
            target: "+15125550100".to_owned(),
            basis: String::new(),
        })
        .expect_err("empty basis must be refused");
    assert_eq!(denied, Denied::NoBasis);

    match bus.records().first() {
        Some(CaptureRecord::Consent(record)) => {
            assert!(matches!(record.decision, Decision::Refused { .. }));
        }
        other => panic!("expected a Consent refusal record, got {other:?}"),
    }
}

#[test]
fn unsupported_verb_is_rejected() {
    let bus = CaptureBus::new();
    let grant = granted(&bus, "+15125550100");
    let plugin = WarDial::with_loopback(fast_cfg(), "127.0.0.1:9".to_owned());
    let cmd = Command {
        verb: "brute".to_owned(),
        arg: String::new(),
    };
    let err = plugin
        .dispatch_active(&cmd, &grant)
        .expect_err("only 'sweep' is supported");
    assert!(matches!(err, PluginError::Unsupported(_)), "got {err:?}");
}

#[test]
fn a_malformed_range_in_the_grant_is_invalid_input_before_any_socket() {
    let bus = CaptureBus::new();
    let grant = granted(&bus, "+1512;drop-table"); // illegal DID chars
    let plugin = WarDial::with_loopback(fast_cfg(), "127.0.0.1:9".to_owned());
    let cmd = Command {
        verb: "sweep".to_owned(),
        arg: String::new(),
    };
    let err = plugin
        .dispatch_active(&cmd, &grant)
        .expect_err("a malformed range is rejected before any call");
    assert!(matches!(err, PluginError::InvalidInput(_)), "got {err:?}");
}

#[test]
fn without_a_trunk_a_non_loopback_target_is_refused() {
    // The inert-without-a-trunk guarantee, proven at the plugin boundary: a
    // default WarDial (no trunk, no loopback target) refuses to originate.
    let bus = CaptureBus::new();
    let grant = granted(&bus, "+15125550100");
    let plugin = WarDial::new(); // no trunk, no loopback
    let cmd = Command {
        verb: "sweep".to_owned(),
        arg: String::new(),
    };
    let err = plugin
        .dispatch_active(&cmd, &grant)
        .expect_err("no trunk configured must refuse origination");
    assert!(matches!(err, PluginError::Backend(_)), "got {err:?}");
}
