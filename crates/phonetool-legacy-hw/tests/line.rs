//! End-to-end through the `Plugin` boundary: the synth→decode round-trip (the
//! ahead-of-hardware correctness proof), CID observe-not-trust, sense classification,
//! and the degenerate-case discipline. All offline, no hardware.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use phonetool_core::{Command, Event, Plugin, PluginError};
use phonetool_legacy_hw::{LineConfig, LineHw};

fn cmd(verb: &str, arg: &str) -> Command {
    Command {
        verb: verb.to_owned(),
        arg: arg.to_owned(),
    }
}

fn dispatch(plugin: &LineHw, verb: &str, arg: &str) -> Result<Event, PluginError> {
    plugin.dispatch(&cmd(verb, arg))
}

#[test]
fn synth_decode_round_trip_via_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wav = dir.path().join("dtmf.wav");
    let plugin = LineHw::with_config(LineConfig {
        out_path: wav.clone(),
        ..Default::default()
    });

    // synth "18005551234" → WAV (inert, emission:false).
    let synth = dispatch(&plugin, "synth", "18005551234").expect("synth");
    assert_eq!(synth.data["emission"], serde_json::json!(false));
    assert!(wav.exists());

    // decode it back → exactly the digits.
    let decoded = dispatch(&plugin, "decode", wav.to_str().expect("utf8")).expect("decode");
    assert!(decoded.summary.contains("18005551234"));
    assert_eq!(decoded.data["verb"], serde_json::json!("decode"));
}

#[test]
fn decode_clean_but_toneless_is_ok_zero() {
    // A WAV of silence decodes cleanly with zero tones — a real result, not Empty.
    let dir = tempfile::tempdir().expect("tempdir");
    let wav = dir.path().join("silence.wav");
    // Render a 2600 tone then decode a *different* silent buffer: build silence WAV
    // via synth of a short tone then... simpler: synth writes tones, so instead
    // decode a hand-built silent WAV through the plugin by writing it out.
    let silent = phonetool_legacy_hw::dsp::to_wav(&vec![0.0f32; 4000], 8000);
    std::fs::write(&wav, &silent).expect("write");
    let plugin = LineHw::new();
    let out = dispatch(&plugin, "decode", wav.to_str().expect("utf8")).expect("decode");
    assert_eq!(out.data["count"], serde_json::json!(0));
    assert!(out.summary.contains("0 tones"));
}

#[test]
fn decode_missing_file_is_invalid_input() {
    let out = dispatch(&LineHw::new(), "decode", "/no/such/file.wav");
    assert!(matches!(out, Err(PluginError::InvalidInput(_))));
}

#[test]
fn sense_idle_vs_offhook() {
    let plugin = LineHw::new();
    let idle = dispatch(&plugin, "sense", "48 48 48 48 48 48").expect("idle");
    assert_eq!(idle.data["state"]["idle"], serde_json::json!(true));

    let offhook = dispatch(&plugin, "sense", "6 6 6 6 6 6").expect("offhook");
    assert_eq!(offhook.data["state"]["hook"], serde_json::json!("off_hook"));
}

#[test]
fn sense_empty_trace_is_empty() {
    assert!(matches!(
        dispatch(&LineHw::new(), "sense", "   "),
        Err(PluginError::Empty(_))
    ));
}

#[test]
fn synth_unencodable_char_rejected() {
    assert!(matches!(
        dispatch(&LineHw::new(), "synth", "12Z34"),
        Err(PluginError::InvalidInput(_))
    ));
}

#[test]
fn unsupported_verb_rejected() {
    // Crucially, there is no "seize"/"inject" verb — active injection is not built.
    assert!(matches!(
        dispatch(&LineHw::new(), "seize", "line-3"),
        Err(PluginError::Unsupported(_))
    ));
}

#[test]
fn synth_2600_and_decode_detects_sf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wav = dir.path().join("sf.wav");
    let plugin = LineHw::with_config(LineConfig {
        out_path: wav.clone(),
        ..Default::default()
    });
    dispatch(&plugin, "synth", "2600").expect("synth 2600");
    let decoded = dispatch(&plugin, "decode", wav.to_str().expect("utf8")).expect("decode");
    // The 2600 SF tone is decoded as a symbol.
    let symbols = decoded.data["symbols"].as_array().expect("symbols");
    assert!(symbols.iter().any(|s| s["value"] == "2600"));
}
