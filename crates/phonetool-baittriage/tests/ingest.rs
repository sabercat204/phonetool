//! Hostile-input ingest boundary + the crate's single hardest guarantee: an
//! artifact URL is NEVER contacted on any path.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use phonetool_baittriage::BaitTriage;
use phonetool_core::{Command, IntelStore, Plugin, PluginError, SqliteStore};

fn plugin() -> BaitTriage {
    let store: Arc<dyn IntelStore> = Arc::new(SqliteStore::open_in_memory().expect("store"));
    BaitTriage::new(store)
}

fn triage(arg: &str) -> Result<phonetool_core::Event, PluginError> {
    plugin().dispatch(&Command {
        verb: "triage".to_owned(),
        arg: arg.to_owned(),
    })
}

#[test]
fn hostile_inputs_map_to_typed_errors_never_panic() {
    // (input, predicate on the error) — every one is a value, none a panic.
    assert!(matches!(triage(""), Err(PluginError::InvalidInput(_))));
    assert!(matches!(triage("   \n"), Err(PluginError::InvalidInput(_))));
    assert!(matches!(
        triage("{not json"),
        Err(PluginError::InvalidInput(_))
    ));
    assert!(matches!(
        triage("[1,2,3]"),
        Err(PluginError::InvalidInput(_))
    ));
    // Unknown field (typo / injection) is rejected by deny_unknown_fields.
    assert!(matches!(
        triage(r#"{"evil":"x"}"#),
        Err(PluginError::InvalidInput(_))
    ));
    // Well-formed but yields no indicator → Empty (the degenerate discipline).
    assert!(matches!(triage("{}"), Err(PluginError::Empty(_))));
    assert!(matches!(
        triage(r#"{"phone":"!!!not a number"}"#),
        Err(PluginError::Empty(_))
    ));
}

#[test]
fn non_utf8_bytes_do_not_panic() {
    // The arg reaches the plugin as a String at the CLI boundary, but exercise a
    // lossy-decoded byte soup to prove normalization is total over odd content.
    let bytes = [0xff, 0xfe, 0x00, 0x7b, 0x7d]; // includes "{}" tail
    let lossy = String::from_utf8_lossy(&bytes).into_owned();
    // Whatever this decodes to, the result is a typed Result, never a panic.
    let _ = triage(&lossy);
}

#[test]
fn oversize_bundle_rejected() {
    let giant = format!(r#"{{"transcript":"{}"}}"#, "a".repeat(300 * 1024));
    assert!(matches!(triage(&giant), Err(PluginError::InvalidInput(_))));
}

/// The load-bearing test: a bundle carrying a URL that points at a live local
/// listener must NOT cause any connection to that listener. We bind a real socket,
/// triage a bundle naming it, and assert the socket never accepted a connection.
#[test]
fn artifact_url_is_never_contacted() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    listener
        .set_nonblocking(true)
        .expect("nonblocking so accept does not park the test");

    let url = format!("http://{addr}/beacon");
    let bundle = format!(r#"{{"urls":["{url}"],"transcript":"visit {url} to pay"}}"#);

    // Triage succeeds (the URL is a valid indicator) but must not dial the socket.
    let event = triage(&bundle).expect("thin-but-real result");
    assert_eq!(event.source, "baittriage");

    // Give any (erroneous) outbound connection a moment to land, then assert the
    // accept queue is still empty. A non-blocking accept returns WouldBlock when
    // nothing connected — that is the pass condition.
    std::thread::sleep(Duration::from_millis(50));
    match listener.accept() {
        Ok((mut stream, _)) => {
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf);
            panic!("baittriage contacted an artifact URL — SSRF/beacon leak: {buf:?}");
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { /* pass: nothing connected */ }
        Err(e) => panic!("unexpected accept error: {e}"),
    }
}
