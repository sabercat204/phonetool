//! The capture bus — unified logging + capture sink for the whole workbench.
//!
//! Every artifact the bench produces flows through one sink: plugin events
//! (call-log now; IQ/pcap capture records stubbed for the RF/wireline layers),
//! and — crucially — every auth-gate decision. The bus implements the gate's
//! [`ConsentLog`], so consent and refusal records land in the same ordered
//! stream as the operations they authorize. One bus, one timeline.
//!
//! Sprint 1 keeps records in memory and mirrors them to `tracing`. Durable sinks
//! (a capture file, a rotating call-log) slot in behind [`CaptureBus`] without
//! touching plugins or the gate.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use phonetool_authgate::{ConsentLog, ConsentRecord};

use crate::plugin::Event;

/// One entry in the capture timeline: either a plugin event or a gate decision.
#[derive(Debug, Clone, serde::Serialize)]
pub enum CaptureRecord {
    /// A plugin produced a result.
    PluginEvent(Event),
    /// The auth gate made a decision (grant or refusal).
    Consent(ConsentRecord),
    /// A reference to a bulk out-of-band capture (IQ / pcap / call audio). The
    /// RF and wireline layers produce these; recorded via
    /// [`record_capture`](CaptureBus::record_capture). Carries the on-disk path
    /// of the capture, never the samples themselves — bulk data stays out of the
    /// timeline by reference.
    CaptureRef { kind: CaptureKind, path: String },
}

/// The medium a bulk capture came from. Stubbed for the future RF/wireline paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CaptureKind {
    /// SDR IQ samples.
    Iq,
    /// Packet capture.
    Pcap,
    /// Raw call/loop audio.
    CallAudio,
}

/// The unified sink. Owns the record timeline; the gate and the shell both write
/// to it. Optionally backed by a durable JSONL file (append-only).
pub struct CaptureBus {
    records: Mutex<Vec<CaptureRecord>>,
    file_sink: Mutex<Option<File>>,
}

impl Default for CaptureBus {
    fn default() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            file_sink: Mutex::new(None),
        }
    }
}

impl CaptureBus {
    /// A fresh, empty bus (in-memory only).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A bus backed by a durable JSONL file. Every record is appended as one
    /// JSON line. The file is created (or opened for append) at `path`.
    /// Falls back to in-memory-only if the file cannot be opened.
    #[must_use]
    pub fn with_file(path: &Path) -> Self {
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        if file.is_some() {
            tracing::info!(path = %path.display(), "capture sink: durable JSONL file opened");
        } else {
            tracing::warn!(path = %path.display(), "capture sink: could not open file, falling back to memory-only");
        }
        Self {
            records: Mutex::new(Vec::new()),
            file_sink: Mutex::new(file),
        }
    }

    /// Record a plugin event.
    pub fn record_event(&self, event: Event) {
        tracing::info!(source = %event.source, summary = %event.summary, "plugin event");
        self.push(CaptureRecord::PluginEvent(event));
    }

    /// Record a reference to a bulk out-of-band capture (IQ samples, a pcap, or
    /// call/loop audio) by its on-disk `path`. The samples themselves never enter
    /// the timeline — only the reference does, so a multi-gigabyte IQ dump costs
    /// one path string here. The single public writer every bulk-artifact
    /// producer (RF RX/TX, cell survey, GNSS, SS7, wireline) uses; the caller
    /// owns writing the actual bytes to `path`.
    pub fn record_capture(&self, kind: CaptureKind, path: impl Into<String>) {
        let path = path.into();
        tracing::info!(?kind, %path, "bulk capture reference");
        self.push(CaptureRecord::CaptureRef { kind, path });
    }

    /// All records captured so far, in order.
    #[must_use]
    pub fn records(&self) -> Vec<CaptureRecord> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }

    fn push(&self, record: CaptureRecord) {
        if let Ok(mut sink) = self.file_sink.lock() {
            if let Some(file) = sink.as_mut() {
                if let Ok(json) = serde_json::to_string(&record) {
                    let _ = writeln!(file, "{json}");
                }
            }
        }
        if let Ok(mut r) = self.records.lock() {
            r.push(record);
        }
    }
}

/// The bus is the gate's consent sink: authorization decisions share the capture
/// timeline with the operations they gate.
impl ConsentLog for CaptureBus {
    fn record(&self, record: ConsentRecord) {
        tracing::info!(?record.decision, "gate decision");
        self.push(CaptureRecord::Consent(record));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn file_sink_persists_records_as_jsonl() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "phonetool_capture_test_{}.jsonl",
            std::process::id()
        ));
        let bus = CaptureBus::with_file(&path);

        bus.record_event(Event {
            source: "test".to_owned(),
            summary: "hello".to_owned(),
            data: serde_json::json!({"key": "value"}),
        });
        bus.record_capture(CaptureKind::Iq, "/tmp/test.iq");
        drop(bus);

        let content = std::fs::read_to_string(&path).expect("read capture file");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "two records written as two lines");

        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON line 1");
        assert!(first.get("PluginEvent").is_some());

        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("valid JSON line 2");
        assert!(second.get("CaptureRef").is_some());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn record_capture_appends_a_reference_not_the_samples() {
        let bus = CaptureBus::new();
        bus.record_capture(CaptureKind::Iq, "/tmp/capture-0001.iq");

        let records = bus.records();
        assert_eq!(records.len(), 1, "one record written");
        match &records[0] {
            CaptureRecord::CaptureRef { kind, path } => {
                assert_eq!(*kind, CaptureKind::Iq);
                assert_eq!(path, "/tmp/capture-0001.iq");
            }
            other => panic!("expected a CaptureRef, got {other:?}"),
        }
    }

    #[test]
    fn bulk_references_share_the_timeline_with_events_in_order() {
        let bus = CaptureBus::new();
        bus.record_event(Event {
            source: "sdr-rx".to_owned(),
            summary: "swept 88-108 MHz".to_owned(),
            data: serde_json::Value::Null,
        });
        bus.record_capture(CaptureKind::Pcap, "/tmp/ss7.pcap");
        bus.record_capture(CaptureKind::CallAudio, "/tmp/call.wav");

        let records = bus.records();
        assert_eq!(records.len(), 3, "one bus, one ordered timeline");
        assert!(matches!(records[0], CaptureRecord::PluginEvent(_)));
        assert!(matches!(
            records[1],
            CaptureRecord::CaptureRef {
                kind: CaptureKind::Pcap,
                ..
            }
        ));
        assert!(matches!(
            records[2],
            CaptureRecord::CaptureRef {
                kind: CaptureKind::CallAudio,
                ..
            }
        ));
    }
}
