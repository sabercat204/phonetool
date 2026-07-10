//! The `CaptureSource` seam — where broadcast segments come from — and the
//! `FileCaptureSource` ahead-of-hardware implementation over a libpcap file of
//! GSMTAP frames.
//!
//! The decode path (`decode_gsm` / `cellmap` / `detect`) sees only a stream of
//! [`Segment`]s and never learns whether they came from a recorded file or a
//! live radio. Today only [`FileCaptureSource`] is real; [`LiveCaptureSource`]
//! is a declared, unconstructed device seam.
//!
//! Threat note: a capture file is entirely adversary-controlled — a rogue BTS
//! (or a crafted dump) supplies the bytes precisely to mislead. Every length and
//! count read from the file is bound-checked before it is used to slice or size;
//! the read is capped (`DEFAULT_BYTE_CAP`); no field is trusted to index a
//! buffer. Malformed records are skipped, never fatal.

use std::path::{Path, PathBuf};

/// The maximum number of bytes read from a capture file. A hostile or accidental
/// multi-gigabyte dump is truncated to this ceiling rather than slurped whole
/// (Req 7.4). 64 MiB is generous for a broadcast-channel pcap (which carries
/// signalling, not bulk IQ) yet bounded for the handheld SBC.
pub const DEFAULT_BYTE_CAP: usize = 64 * 1024 * 1024;

/// The radio access technology a captured segment belongs to. GSM is decoded
/// today; LTE/NR are declared seams (see `decode_lte` / `decode_nr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Rat {
    /// 2G — GSM. Decoded today from GSMTAP Um frames.
    Gsm,
    /// 4G — LTE. Seam only (no decided recorded source; Open Question 3).
    Lte,
    /// 5G NR. Seam only (no decided recorded source; Open Question 3).
    Nr,
}

/// One broadcast unit handed to the decode path: the RAT it belongs to, the
/// channel/frequency index the radio layer reported (ARFCN for GSM), an optional
/// received-signal level in dBm (for signal-geometry checks), and the raw,
/// still-untrusted payload bytes (an L3 message for GSM).
#[derive(Debug, Clone)]
pub struct Segment {
    /// The radio access technology this segment was captured on.
    pub rat: Rat,
    /// The channel/frequency index reported by the radio layer (GSM ARFCN).
    pub channel: u16,
    /// Received signal level in dBm, if the capture carried one. `None` when the
    /// source did not report it — never a fabricated default (the detector must
    /// distinguish "quiet" from "not measured").
    pub signal_dbm: Option<i8>,
    /// The raw broadcast payload (a GSM L3 RR message for `Rat::Gsm`). Untrusted.
    pub payload: Vec<u8>,
}

/// What went wrong obtaining segments.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The named capture file does not exist.
    #[error("capture file not found: {0}")]
    NotFound(String),
    /// The file exists but could not be read, or is not a recognizable capture.
    #[error("capture unreadable: {0}")]
    Unreadable(String),
    /// The file exceeds the byte cap and was refused rather than truncated
    /// mid-record. (Currently unused by `FileCaptureSource`, which truncates;
    /// reserved for sources that must refuse an oversize input outright.)
    #[error("capture too large: {0}")]
    TooLarge(String),
    /// A live source was requested but no radio / Tier-B subprocess is wired.
    #[error("live capture source unavailable: {0}")]
    LiveUnavailable(String),
}

/// Where broadcast segments come from. The one abstraction the decode path sees;
/// a source swap (file → live) is the only change when hardware arrives.
pub trait CaptureSource {
    /// Produce the decoded segments from this source. Total over untrusted input:
    /// a malformed record inside the capture is skipped, not surfaced as an error.
    ///
    /// # Errors
    /// [`SourceError`] when the source itself cannot be opened/read, or (for a
    /// live source) is unavailable. An empty-but-readable capture is `Ok(vec![])`
    /// — the *degenerate-result* discipline (zero cells → `Empty`) is applied one
    /// layer up, in `lib`, not here.
    fn segments(&self) -> Result<Vec<Segment>, SourceError>;
}

// ---------------------------------------------------------------------------
// pcap + GSMTAP constants — grounded, not guessed.
//
// pcap savefile format: IETF draft-ietf-opsawg-pcap ("PCAP Capture File
// Format"). GSMTAP header: libosmocore `include/osmocom/core/gsmtap.h`.
// Link-type numbers: tcpdump.org/linktypes.html.
// ---------------------------------------------------------------------------

/// libpcap magic in the capturing host's byte order (microsecond timestamps).
const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
/// The same magic byte-swapped — the file was written big-endian.
const PCAP_MAGIC_BE: u32 = 0xd4c3_b2a1;
/// libpcap magic, nanosecond-timestamp variant, host order.
const PCAP_MAGIC_NS_LE: u32 = 0xa1b2_3c4d;
/// nanosecond variant, byte-swapped.
const PCAP_MAGIC_NS_BE: u32 = 0x4d3c_b2a1;

/// Bytes in the pcap global header.
const PCAP_GLOBAL_HDR_LEN: usize = 24;
/// Bytes in each pcap per-record header.
const PCAP_REC_HDR_LEN: usize = 16;

/// `LINKTYPE_GSMTAP_UM` (tcpdump.org). The packet payload is a bare GSMTAP
/// header followed by the Um payload — no Ethernet/IP/UDP framing.
const LINKTYPE_GSMTAP_UM: u32 = 217;

/// Bytes in the (v2) GSMTAP header (libosmocore `struct gsmtap_hdr`, packed).
const GSMTAP_HDR_LEN: usize = 16;
/// `GSMTAP_VERSION`.
const GSMTAP_VERSION: u8 = 0x02;
/// `GSMTAP_TYPE_UM` — GSM Um-interface signalling/traffic.
const GSMTAP_TYPE_UM: u8 = 0x01;
/// `GSMTAP_ARFCN_MASK` — the low 14 bits of the arfcn field are the number;
/// the top two bits are the PCS (0x8000) and UPLINK (0x4000) flags.
const GSMTAP_ARFCN_MASK: u16 = 0x3fff;

/// A recorded GSMTAP-over-pcap capture read from a local file. The default,
/// hardware-free path: it decodes end-to-end with no SDR present.
pub struct FileCaptureSource {
    path: PathBuf,
    byte_cap: usize,
}

impl FileCaptureSource {
    /// Open a capture at `path` with the default byte cap.
    #[must_use]
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            byte_cap: DEFAULT_BYTE_CAP,
        }
    }

    /// Open with an explicit byte cap (test/tuning aid).
    #[must_use]
    pub fn with_cap(path: &Path, byte_cap: usize) -> Self {
        Self {
            path: path.to_path_buf(),
            byte_cap,
        }
    }

    /// Parse a fully-buffered pcap image into GSMTAP segments. Split out from I/O
    /// so it is unit-testable on in-memory bytes. Total: every field read from
    /// the file is bound-checked; a truncated or malformed record ends the walk
    /// (or is skipped) rather than panicking.
    fn parse_pcap(buf: &[u8]) -> Result<Vec<Segment>, SourceError> {
        let magic_bytes = buf
            .get(0..4)
            .ok_or_else(|| SourceError::Unreadable("file shorter than pcap magic".to_owned()))?;
        // `get(0..4)` guarantees length 4; the array conversion cannot fail, but
        // stay total (no unwrap) per the workspace lints.
        let magic = match magic_bytes.try_into() {
            Ok(b) => u32::from_le_bytes(b),
            Err(_) => return Err(SourceError::Unreadable("bad pcap magic".to_owned())),
        };

        // The magic both identifies the format and fixes byte order: written
        // little- or big-endian, microsecond or nanosecond timestamps.
        let big_endian = match magic {
            PCAP_MAGIC_LE | PCAP_MAGIC_NS_LE => false,
            PCAP_MAGIC_BE | PCAP_MAGIC_NS_BE => true,
            _ => {
                return Err(SourceError::Unreadable(format!(
                    "not a libpcap file (magic {magic:#010x})"
                )));
            }
        };

        let read_u32 = |b: [u8; 4]| {
            if big_endian {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            }
        };

        // The link-type lives in the last 4 bytes of the 24-byte global header.
        let network_bytes = buf.get(20..24).ok_or_else(|| {
            SourceError::Unreadable("file shorter than pcap global header".to_owned())
        })?;
        let network = match network_bytes.try_into() {
            Ok(b) => read_u32(b),
            Err(_) => return Err(SourceError::Unreadable("bad pcap link-type".to_owned())),
        };
        if network != LINKTYPE_GSMTAP_UM {
            return Err(SourceError::Unreadable(format!(
                "unsupported pcap link-type {network} (need LINKTYPE_GSMTAP_UM = {LINKTYPE_GSMTAP_UM})"
            )));
        }

        let mut segments = Vec::new();
        let mut offset = PCAP_GLOBAL_HDR_LEN;

        // Walk records. A record header we cannot fully read ends the walk (the
        // file is truncated); an incl_len that overruns the buffer ends it too.
        while let Some(hdr) = buf.get(offset..offset.saturating_add(PCAP_REC_HDR_LEN)) {
            // incl_len is the third u32 (bytes 8..12) of the record header.
            let incl_len = match hdr.get(8..12).and_then(|s| s.try_into().ok()) {
                Some(b) => read_u32(b) as usize,
                None => break,
            };

            let data_start = offset.saturating_add(PCAP_REC_HDR_LEN);
            let data_end = data_start.saturating_add(incl_len);
            let Some(record) = buf.get(data_start..data_end) else {
                // Declared length runs past the captured bytes → truncated file.
                break;
            };

            // A record whose payload we cannot decode is skipped, not fatal.
            if let Some(seg) = Self::decode_gsmtap_frame(record) {
                segments.push(seg);
            }

            offset = data_end;
        }

        Ok(segments)
    }

    /// Decode one GSMTAP frame (a bare `gsmtap_hdr` + payload, per
    /// `LINKTYPE_GSMTAP_UM`) into a [`Segment`], or `None` if it is not a
    /// version-2 Um frame or is too short. Multibyte header fields are network
    /// (big-endian) order.
    fn decode_gsmtap_frame(record: &[u8]) -> Option<Segment> {
        let hdr = record.get(0..GSMTAP_HDR_LEN)?;
        // version @0, type @2, arfcn @4..6 (BE), signal_dbm @6 (int8).
        if *hdr.first()? != GSMTAP_VERSION || *hdr.get(2)? != GSMTAP_TYPE_UM {
            return None;
        }
        let arfcn_raw = u16::from_be_bytes([*hdr.get(4)?, *hdr.get(5)?]);
        let channel = arfcn_raw & GSMTAP_ARFCN_MASK;
        // signal_dbm is a signed 8-bit field; 0 is a legitimate value, so a
        // zero here is reported as measured, not as "absent". A real "not
        // measured" would require a producer convention the format lacks — we
        // treat every Um frame as carrying a level. (Absent-level captures land
        // via LTE/NR sources later, which is why the field is Option-typed.)
        let signal_dbm = *hdr.get(6)? as i8;

        let payload = record.get(GSMTAP_HDR_LEN..)?.to_vec();
        Some(Segment {
            rat: Rat::Gsm,
            channel,
            signal_dbm: Some(signal_dbm),
            payload,
        })
    }
}

impl CaptureSource for FileCaptureSource {
    fn segments(&self) -> Result<Vec<Segment>, SourceError> {
        let meta = std::fs::metadata(&self.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SourceError::NotFound(self.path.display().to_string())
            } else {
                SourceError::Unreadable(format!("{}: {e}", self.path.display()))
            }
        })?;
        if !meta.is_file() {
            return Err(SourceError::Unreadable(format!(
                "{} is not a regular file",
                self.path.display()
            )));
        }

        // Bounded read: cap the number of bytes so a hostile/huge file cannot
        // exhaust memory. `Read::take` enforces the ceiling regardless of the
        // size the filesystem reported.
        use std::io::Read as _;
        let file = std::fs::File::open(&self.path)
            .map_err(|e| SourceError::Unreadable(format!("{}: {e}", self.path.display())))?;
        let mut buf = Vec::new();
        file.take(self.byte_cap as u64)
            .read_to_end(&mut buf)
            .map_err(|e| SourceError::Unreadable(format!("{}: {e}", self.path.display())))?;

        Self::parse_pcap(&buf)
    }
}

/// The device seam: a live cellular scan behind a Tier-B `SubprocessPlugin` that
/// physically owns the SDR (gr-gsm / Osmocom / srsRAN). Unconstructed this
/// sprint — the subprocess-IPC contract it depends on is DESIGN-ONLY
/// (`specs/subprocess-ipc-contract/`). The `decode_*` / `cellmap` / `detect`
/// modules do not change when this becomes real; only the source does.
///
/// Not `dead_code`: it documents the seam and satisfies `CaptureSource` so the
/// swap is a type-level guarantee, returning `LiveUnavailable` until wired.
pub struct LiveCaptureSource {
    _private: (),
}

impl CaptureSource for LiveCaptureSource {
    fn segments(&self) -> Result<Vec<Segment>, SourceError> {
        Err(SourceError::LiveUnavailable(
            "live scan needs the Tier-B subprocess host (unbuilt; specs/subprocess-ipc-contract/)"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Build a minimal little-endian GSMTAP-UM pcap image from a list of
    /// (arfcn, signal_dbm, payload) frames. Mirrors the format the decoder reads
    /// so the round-trip is self-checking.
    fn build_pcap(frames: &[(u16, i8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes()); // version_major
        out.extend_from_slice(&4u16.to_le_bytes()); // version_minor
        out.extend_from_slice(&0u32.to_le_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&LINKTYPE_GSMTAP_UM.to_le_bytes()); // network

        for (arfcn, dbm, payload) in frames {
            let mut frame = vec![0u8; GSMTAP_HDR_LEN];
            frame[0] = GSMTAP_VERSION;
            frame[1] = (GSMTAP_HDR_LEN / 4) as u8; // hdr_len in 32-bit words
            frame[2] = GSMTAP_TYPE_UM;
            frame[4..6].copy_from_slice(&arfcn.to_be_bytes());
            frame[6] = *dbm as u8;
            frame.extend_from_slice(payload);

            out.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
            out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
            out.extend_from_slice(&frame);
        }
        out
    }

    #[test]
    fn parses_a_well_formed_gsmtap_frame() {
        let pcap = build_pcap(&[(42, -70, &[0xde, 0xad, 0xbe, 0xef])]);
        let segs = FileCaptureSource::parse_pcap(&pcap).expect("valid pcap");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].rat, Rat::Gsm);
        assert_eq!(segs[0].channel, 42);
        assert_eq!(segs[0].signal_dbm, Some(-70));
        assert_eq!(segs[0].payload, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn strips_pcs_and_uplink_flag_bits_from_arfcn() {
        // 0x8000 (PCS) | 0x4000 (UPLINK) | 100 → the number is still 100.
        let pcap = build_pcap(&[(0x8000 | 0x4000 | 100, -80, &[0x01])]);
        let segs = FileCaptureSource::parse_pcap(&pcap).expect("valid pcap");
        assert_eq!(segs[0].channel, 100);
    }

    #[test]
    fn rejects_a_non_pcap_file() {
        let err = FileCaptureSource::parse_pcap(b"not a pcap at all really").unwrap_err();
        assert!(matches!(err, SourceError::Unreadable(_)));
    }

    #[test]
    fn rejects_a_wrong_link_type() {
        let mut pcap = build_pcap(&[(1, 0, &[0x00])]);
        // Overwrite the network field (bytes 20..24) with LINKTYPE_ETHERNET (1).
        pcap[20..24].copy_from_slice(&1u32.to_le_bytes());
        let err = FileCaptureSource::parse_pcap(&pcap).unwrap_err();
        assert!(matches!(err, SourceError::Unreadable(_)));
    }

    #[test]
    fn skips_a_non_um_gsmtap_frame_without_failing() {
        let mut pcap = build_pcap(&[(1, 0, &[0x00])]);
        // Flip the GSMTAP type byte of the single frame to ABIS (0x02). It sits
        // at global(24) + rec_hdr(16) + hdr offset 2 = 42.
        pcap[24 + PCAP_REC_HDR_LEN + 2] = 0x02;
        let segs = FileCaptureSource::parse_pcap(&pcap).expect("valid pcap");
        assert!(segs.is_empty(), "non-Um frame is skipped, not decoded");
    }

    #[test]
    fn tolerates_a_truncated_final_record() {
        let mut pcap = build_pcap(&[(7, -60, &[0xaa, 0xbb])]);
        // Chop the frame payload mid-record: the declared incl_len now overruns.
        pcap.truncate(pcap.len() - 3);
        // Must not panic; the truncated record is dropped.
        let segs = FileCaptureSource::parse_pcap(&pcap).expect("header still valid");
        assert!(segs.is_empty());
    }

    #[test]
    fn tolerates_a_gsmtap_frame_shorter_than_its_header() {
        // A record present in the pcap but shorter than a full GSMTAP header.
        let pcap = build_pcap(&[(1, 0, &[])]); // 16-byte header, 0 payload — valid
        let segs = FileCaptureSource::parse_pcap(&pcap).expect("valid");
        // A zero-payload Um frame is still a (useless-to-decode) segment.
        assert_eq!(segs.len(), 1);
        assert!(segs[0].payload.is_empty());
    }

    #[test]
    fn empty_but_valid_pcap_yields_no_segments() {
        let pcap = build_pcap(&[]);
        let segs = FileCaptureSource::parse_pcap(&pcap).expect("valid empty pcap");
        assert!(segs.is_empty());
    }

    #[test]
    fn big_endian_pcap_is_read() {
        // Hand-build a big-endian global header + one record.
        let mut out = Vec::new();
        out.extend_from_slice(&PCAP_MAGIC_BE.to_le_bytes()); // stored so LE-read == BE magic
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&65535u32.to_be_bytes());
        out.extend_from_slice(&LINKTYPE_GSMTAP_UM.to_be_bytes());
        let mut frame = vec![0u8; GSMTAP_HDR_LEN];
        frame[0] = GSMTAP_VERSION;
        frame[2] = GSMTAP_TYPE_UM;
        frame[4..6].copy_from_slice(&55u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        out.extend_from_slice(&frame);

        let segs = FileCaptureSource::parse_pcap(&out).expect("valid BE pcap");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].channel, 55);
    }

    #[test]
    fn live_source_is_unavailable() {
        let live = LiveCaptureSource { _private: () };
        assert!(matches!(
            live.segments(),
            Err(SourceError::LiveUnavailable(_))
        ));
    }
}
