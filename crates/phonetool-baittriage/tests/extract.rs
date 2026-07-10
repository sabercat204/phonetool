//! Indicator extraction + normalization at the plugin boundary.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;

use phonetool_baittriage::BaitTriage;
use phonetool_core::{Command, Event, IntelStore, Plugin, SqliteStore};

fn triage(arg: &str) -> Event {
    let store: Arc<dyn IntelStore> = Arc::new(SqliteStore::open_in_memory().expect("store"));
    BaitTriage::new(store)
        .dispatch(&Command {
            verb: "triage".to_owned(),
            arg: arg.to_owned(),
        })
        .expect("valid bundle yields a result")
}

fn ioc_values(event: &Event, kind: &str) -> Vec<String> {
    event.data["iocs"]
        .as_array()
        .expect("iocs array")
        .iter()
        .filter(|i| i["kind"] == serde_json::json!(kind))
        .map(|i| i["value"].as_str().expect("value").to_owned())
        .collect()
}

#[test]
fn phone_three_ways_normalizes_to_one_e164() {
    for raw in ["+1 (512) 555-0100", "+1.512.555.0100", "+15125550100"] {
        let bundle = format!(r#"{{"phone":"{raw}"}}"#);
        let event = triage(&bundle);
        assert_eq!(ioc_values(&event, "phone"), vec!["+15125550100".to_owned()]);
    }
}

#[test]
fn bad_artifact_skipped_rest_extracted() {
    // Invalid phone drops; wallet + url survive.
    let event =
        triage(r#"{"phone":"garbage!!!","wallets":["bc1qXYZ"],"urls":["http://evil.example/x"]}"#);
    assert!(ioc_values(&event, "phone").is_empty());
    assert_eq!(ioc_values(&event, "wallet"), vec!["bc1qxyz".to_owned()]);
    assert_eq!(
        ioc_values(&event, "url"),
        vec!["http://evil.example/x".to_owned()]
    );
}

#[test]
fn transcript_lifts_url_and_email_but_not_prose_numbers() {
    let event = triage(
        r#"{"transcript":"call 5125550100 or visit http://evil.example/pay, email a@evil.example"}"#,
    );
    assert!(!ioc_values(&event, "url").is_empty());
    assert!(!ioc_values(&event, "email").is_empty());
    // A number embedded in prose is NOT fabricated into a phone IOC.
    assert!(ioc_values(&event, "phone").is_empty());
}

#[test]
fn duplicate_indicator_across_fields_deduped() {
    let event =
        triage(r#"{"emails":["a@evil.example"],"email_body":"reach me at a@evil.example"}"#);
    assert_eq!(ioc_values(&event, "email").len(), 1);
}

#[test]
fn many_indicators_bounded() {
    // 600 distinct wallets → capped at MAX_IOCS (512), still a successful result.
    let wallets: Vec<String> = (0..600).map(|i| format!("\"w{i}\"")).collect();
    let bundle = format!(r#"{{"wallets":[{}]}}"#, wallets.join(","));
    let event = triage(&bundle);
    let count = event.data["iocs"].as_array().expect("iocs").len();
    assert_eq!(count, 512);
}
