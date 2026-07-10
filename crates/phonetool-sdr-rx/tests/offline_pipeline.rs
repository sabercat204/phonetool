//! Offline pipeline tests for phonetool-sdr-rx.
//!
//! These prove the full sweep/identify/demod pipeline against synthesized IQ
//! files — the ahead-of-hardware file-proof path. No radio, no network, no
//! hardware. The synthesized signals are known, so assertions are exact.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use num_complex::Complex;
use phonetool_core::{Command, Plugin, PluginError};
use phonetool_sdr_rx::source::{DEFAULT_SAMPLE_CAP, IqFileSource, SdrSource};
use phonetool_sdr_rx::{RxConfig, SdrRx};

static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write a cf32 IQ file containing `samples` to a unique temp path.
fn write_iq_file(samples: &[Complex<f32>]) -> PathBuf {
    let id = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir();
    let path = dir.join(format!("phonetool_test_{}_{id}.iq", std::process::id()));
    let mut file = std::fs::File::create(&path).expect("create temp IQ file");
    for s in samples {
        file.write_all(&s.re.to_le_bytes()).expect("write I");
        file.write_all(&s.im.to_le_bytes()).expect("write Q");
    }
    path
}

/// Generate a pure tone at `freq_hz` offset from center, at sample rate `fs`.
fn tone(freq_hz: f64, fs: f64, n: usize) -> Vec<Complex<f32>> {
    (0..n)
        .map(|i| {
            let t = i as f64 / fs;
            let phase = 2.0 * std::f64::consts::PI * freq_hz * t;
            Complex::new(phase.cos() as f32, phase.sin() as f32)
        })
        .collect()
}

#[test]
fn iq_file_source_reads_a_synthesized_tone() {
    let samples = tone(10_000.0, 48_000.0, 1024);
    let path = write_iq_file(&samples);

    let mut source =
        IqFileSource::open(&path, 48_000.0, 100e6, DEFAULT_SAMPLE_CAP).expect("open IQ file");
    let block = source.read_block(DEFAULT_SAMPLE_CAP).expect("read block");
    assert_eq!(block.samples.len(), 1024);
    assert!(!block.truncated);
    assert_eq!(block.sample_rate, 48_000.0);
    assert_eq!(block.center_freq, 100e6);

    std::fs::remove_file(&path).ok();
}

#[test]
fn iq_file_source_truncates_beyond_sample_cap() {
    let samples = tone(1_000.0, 48_000.0, 200);
    let path = write_iq_file(&samples);

    let cap = 100;
    let mut source = IqFileSource::open(&path, 48_000.0, 100e6, cap).expect("open");
    let block = source.read_block(cap).expect("read");
    assert_eq!(block.samples.len(), cap);
    assert!(block.truncated);

    std::fs::remove_file(&path).ok();
}

#[test]
fn iq_file_source_missing_file_is_backend_error() {
    let result = IqFileSource::open(
        std::path::Path::new("/nonexistent/path.iq"),
        48_000.0,
        100e6,
        DEFAULT_SAMPLE_CAP,
    );
    assert!(matches!(result, Err(PluginError::Backend(_))));
}

#[test]
fn iq_file_source_empty_file_yields_zero_samples() {
    let path = write_iq_file(&[]);
    let mut source = IqFileSource::open(&path, 48_000.0, 100e6, DEFAULT_SAMPLE_CAP).expect("open");
    let block = source.read_block(DEFAULT_SAMPLE_CAP).expect("read");
    assert!(block.samples.is_empty());

    std::fs::remove_file(&path).ok();
}

#[test]
fn iq_file_source_truncated_bytes_are_discarded() {
    // Write 1024 samples plus 3 extra bytes (not a full sample).
    let samples = tone(1_000.0, 48_000.0, 1024);
    let path = {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("phonetool_trunc_{}.iq", std::process::id()));
        let mut file = std::fs::File::create(&p).expect("create");
        for s in &samples {
            file.write_all(&s.re.to_le_bytes()).expect("write");
            file.write_all(&s.im.to_le_bytes()).expect("write");
        }
        // Extra trailing bytes that don't form a complete sample.
        file.write_all(&[0xDE, 0xAD, 0xBE]).expect("write trailing");
        p
    };

    let mut source = IqFileSource::open(&path, 48_000.0, 100e6, DEFAULT_SAMPLE_CAP).expect("open");
    let block = source.read_block(DEFAULT_SAMPLE_CAP).expect("read");
    assert_eq!(block.samples.len(), 1024, "partial sample discarded");

    std::fs::remove_file(&path).ok();
}

#[test]
fn sweep_finds_power_in_the_tone_bin() {
    // A pure tone at +10 kHz from center should show up as a peak in the sweep.
    let fs = 48_000.0;
    let center = 100e6;
    let tone_offset = 10_000.0;
    let samples = tone(tone_offset, fs, 4096);
    let path = write_iq_file(&samples);

    let config = RxConfig {
        sample_cap: DEFAULT_SAMPLE_CAP,
        fft_size: 1024,
        threshold_db: -80.0,
        sample_rate: fs,
        center_freq: center,
        ..RxConfig::default()
    };
    let plugin = SdrRx::with_config(config);
    let cmd = Command {
        verb: "sweep".to_owned(),
        arg: path.to_string_lossy().to_string(),
    };
    let event = plugin.dispatch(&cmd).expect("sweep succeeds");
    assert_eq!(event.source, "sdr");
    assert_eq!(event.data["verb"], "sweep");
    assert_eq!(event.data["samples_read"], 4096);
    assert_eq!(event.data["truncated"], false);

    std::fs::remove_file(&path).ok();
}

#[test]
fn identify_detects_a_tone() {
    let fs = 48_000.0;
    let center = 100e6;
    let tone_offset = 5_000.0;
    let samples = tone(tone_offset, fs, 4096);
    let path = write_iq_file(&samples);

    let config = RxConfig {
        sample_cap: DEFAULT_SAMPLE_CAP,
        fft_size: 1024,
        threshold_db: -60.0,
        sample_rate: fs,
        center_freq: center,
        ..RxConfig::default()
    };
    let plugin = SdrRx::with_config(config);
    let cmd = Command {
        verb: "identify".to_owned(),
        arg: path.to_string_lossy().to_string(),
    };
    let event = plugin.dispatch(&cmd).expect("identify succeeds");
    assert_eq!(event.source, "sdr");
    assert_eq!(event.data["verb"], "identify");
    let detected = event.data["detected"].as_u64().expect("detected count");
    assert!(detected >= 1, "should detect at least one signal");

    std::fs::remove_file(&path).ok();
}

#[test]
fn identify_on_silence_returns_zero_detections() {
    // Silence = all zeros, below any threshold → zero detections but Ok (not Empty).
    let samples: Vec<Complex<f32>> = vec![Complex::new(0.0, 0.0); 1024];
    let path = write_iq_file(&samples);

    let config = RxConfig {
        sample_cap: DEFAULT_SAMPLE_CAP,
        fft_size: 1024,
        threshold_db: -40.0,
        sample_rate: 48_000.0,
        center_freq: 100e6,
        ..RxConfig::default()
    };
    let plugin = SdrRx::with_config(config);
    let cmd = Command {
        verb: "identify".to_owned(),
        arg: path.to_string_lossy().to_string(),
    };
    let event = plugin.dispatch(&cmd).expect("silence is Ok, not Empty");
    assert_eq!(event.data["detected"], 0, "quiet band has zero detections");

    std::fs::remove_file(&path).ok();
}

#[test]
fn demod_fm_produces_audio() {
    let fs = 48_000.0;
    let samples = tone(1_000.0, fs, 2048);
    let path = write_iq_file(&samples);

    let config = RxConfig {
        sample_rate: fs,
        center_freq: 100e6,
        ..RxConfig::default()
    };
    let plugin = SdrRx::with_config(config);
    let cmd = Command {
        verb: "demod".to_owned(),
        arg: format!("{} fm", path.to_string_lossy()),
    };
    let event = plugin.dispatch(&cmd).expect("demod fm succeeds");
    assert_eq!(event.data["output_type"], "audio");
    assert!(event.data["output_len"].as_u64().unwrap() > 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn demod_digital_produces_bits() {
    let fs = 48_000.0;
    let samples = tone(2_000.0, fs, 2048);
    let path = write_iq_file(&samples);

    let config = RxConfig {
        sample_rate: fs,
        center_freq: 100e6,
        ..RxConfig::default()
    };
    let plugin = SdrRx::with_config(config);
    let cmd = Command {
        verb: "demod".to_owned(),
        arg: format!("{} digital", path.to_string_lossy()),
    };
    let event = plugin.dispatch(&cmd).expect("demod digital succeeds");
    assert_eq!(event.data["output_type"], "bits");
    assert!(event.data["output_len"].as_u64().unwrap() > 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn demod_unsupported_mode_rejected() {
    let samples = tone(1_000.0, 48_000.0, 256);
    let path = write_iq_file(&samples);

    let plugin = SdrRx::new();
    let cmd = Command {
        verb: "demod".to_owned(),
        arg: format!("{} cw", path.to_string_lossy()),
    };
    let err = plugin.dispatch(&cmd).expect_err("unsupported mode");
    assert!(matches!(err, PluginError::Unsupported(_)));

    std::fs::remove_file(&path).ok();
}

#[test]
fn zero_samples_is_empty_not_success() {
    let path = write_iq_file(&[]);

    let plugin = SdrRx::new();
    for verb in ["sweep", "identify"] {
        let cmd = Command {
            verb: verb.to_owned(),
            arg: path.to_string_lossy().to_string(),
        };
        let err = plugin.dispatch(&cmd).expect_err("zero samples must fail");
        assert!(
            matches!(err, PluginError::Empty(_)),
            "verb '{verb}' with zero samples should be Empty, got {err:?}"
        );
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn unsupported_verb_rejected() {
    let plugin = SdrRx::new();
    let cmd = Command {
        verb: "transmit".to_owned(),
        arg: "/tmp/x.iq".to_owned(),
    };
    let err = plugin.dispatch(&cmd).expect_err("unsupported verb");
    assert!(matches!(err, PluginError::Unsupported(_)));
}

#[test]
fn empty_arg_is_invalid_input() {
    let plugin = SdrRx::new();
    let cmd = Command {
        verb: "sweep".to_owned(),
        arg: "  ".to_owned(),
    };
    let err = plugin.dispatch(&cmd).expect_err("empty path");
    assert!(matches!(err, PluginError::InvalidInput(_)));
}

#[test]
fn manifest_is_passive_rfrx() {
    let plugin = SdrRx::new();
    let m = plugin.manifest();
    assert_eq!(m.name, "sdr");
    assert_eq!(m.transducer, phonetool_core::Transducer::RfRx);
    assert_eq!(m.capability, phonetool_core::CapabilityClass::Passive);
}
