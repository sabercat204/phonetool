//! The `CaptureSource` seam — where PDUs come from — and the two ahead-of-hardware
//! implementations: [`HexDumpSource`] (hex-encoded PDUs) and [`PcapSource`] (a
//! `.pcap` file of SIGTRAN/Diameter-over-SCTP traffic).
//!
//! The decode/flag layers (`ss7`, `diameter`, `classify`) see only a `Vec<Vec<u8>>`
//! of PDUs and never learn whether they came from a hex dump, a file, or a future
//! live link. Today only the two file/text sources are real; [`LiveLinkSource`] is
//! a declared, carrier/hardware-gated seam behind the off-by-default `live` feature.
//!
//! Threat note: a capture is adversary-authored bytes. Every length and offset read
//! from the pcap container or an SCTP chunk header is bound-checked before it slices
//! or sizes; the file read is capped ([`DEFAULT_BYTE_CAP`]); a malformed record ends
//! the walk or is skipped, never panics.
//!
//! Grounding: pcap savefile format — IETF `draft-ietf-opsawg-pcap`. SCTP packet /
//! chunk framing — RFC 4960 §3 (common header 12 bytes; chunk header: type 1B,
//! flags 1B, length 2B BE; DATA chunk type = 0, 16-byte fixed header before user
//! data; 4-byte chunk padding). Link-type numbers — tcpdump.org/linktypes.html.

use std::path::{Path, PathBuf};

/// The maximum number of bytes read from a capture file. A hostile or accidental
/// multi-gigabyte dump is truncated to this ceiling rather than slurped whole.
/// 64 MiB is generous for a signalling capture yet bounded for a handheld SBC.
/// (Safety bound, not a protocol constant — design Open Question 6.)
pub const DEFAULT_BYTE_CAP: usize = 64 * 1024 * 1024;

/// Maximum number of PDUs extracted from one capture. Bounds the decode loop
/// against a capture packed with millions of tiny chunks. Safety bound (OQ6).
pub const MAX_PDUS: usize = 100_000;

/// Where PDUs come from. The one abstraction the decode path sees; a source swap
/// (file → live link) is the only change when a lawful signalling link exists.
pub trait CaptureSource {
    /// Produce the raw, still-untrusted PDUs from this source. Total over hostile
    /// input: a malformed record inside the capture is skipped, not surfaced as an
    /// error.
    ///
    /// # Errors
    /// [`SourceError`] when the source itself cannot be opened/read/recognized, or
    /// (for a live source) is unavailable. An empty-but-readable capture is
    /// `Ok(vec![])`; the degenerate-result discipline (zero PDUs → `Empty`) is
    /// applied one layer up, in `lib`.
    fn pdus(&self) -> Result<Vec<Vec<u8>>, SourceError>;
}

/// What went wrong obtaining PDUs.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The named source path does not exist (or was blank/absent).
    #[error("capture source not found: {0}")]
    NotFound(String),
    /// The source exists but a genuine I/O failure occurred mid-read.
    #[error("capture unreadable: {0}")]
    Unreadable(String),
    /// The source was empty or whitespace-only (nothing to analyze).
    #[error("capture source empty: {0}")]
    Empty(String),
    /// A hex-dump token was not valid hexadecimal.
    #[error("bad hex in dump: {0}")]
    BadHex(String),
    /// The pcap/pcapng container framing was unrecognizable or corrupt.
    #[error("bad capture container: {0}")]
    BadContainer(String),
    /// A live source was requested but no signalling link is wired.
    #[error("live link source unavailable: {0}")]
    LiveUnavailable(String),
}

// ---------------------------------------------------------------------------
// Hex-dump source
// ---------------------------------------------------------------------------

/// A hex PDU dump: one or more whitespace/newline-separated hex-encoded PDUs, each
/// decoded as one PDU. Runs today with zero egress dependency. A `#`-prefixed line
/// is a comment (so fixture files can annotate PDUs).
pub struct HexDumpSource {
    text: String,
}

impl HexDumpSource {
    /// Build from the dump text (the command arg or a file's contents).
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self {
            text: text.to_owned(),
        }
    }

    /// Decode one hex token to bytes. Total: an odd-length or non-hex token is a
    /// [`SourceError::BadHex`].
    fn decode_token(token: &str) -> Result<Vec<u8>, SourceError> {
        if !token.len().is_multiple_of(2) {
            return Err(SourceError::BadHex(format!("odd-length token '{token}'")));
        }
        let raw = token.as_bytes();
        raw.chunks_exact(2)
            .map(|pair| {
                let (hi, lo) = (pair.first().copied(), pair.get(1).copied());
                hi.zip(lo)
                    .and_then(|(h, l)| Some((hex_nibble(h)? << 4) | hex_nibble(l)?))
                    .ok_or_else(|| SourceError::BadHex(format!("non-hex in token '{token}'")))
            })
            .collect()
    }
}

/// Map an ASCII hex digit to its nibble value, or `None` if not a hex digit.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl CaptureSource for HexDumpSource {
    fn pdus(&self) -> Result<Vec<Vec<u8>>, SourceError> {
        if self.text.trim().is_empty() {
            return Err(SourceError::Empty("hex dump has no tokens".to_owned()));
        }
        let mut pdus = Vec::new();
        for line in self.text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Each non-comment, non-blank line is one PDU (whitespace within a line
            // is stripped so hex may be grouped: "62 1a 48 04 ...").
            let compact: String = line.split_whitespace().collect();
            if compact.is_empty() {
                continue;
            }
            pdus.push(Self::decode_token(&compact)?);
            if pdus.len() >= MAX_PDUS {
                break;
            }
        }
        // A dump that was all comments/blank lines carries no PDU — an empty source,
        // not a silently-Ok empty vector (the degenerate discipline starts here).
        if pdus.is_empty() {
            return Err(SourceError::Empty("hex dump has no PDU lines".to_owned()));
        }
        Ok(pdus)
    }
}

// ---------------------------------------------------------------------------
// pcap + SCTP constants — grounded, not guessed.
// ---------------------------------------------------------------------------

/// libpcap magic, little-endian host order, microsecond timestamps.
const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
/// The same magic byte-swapped (file written big-endian).
const PCAP_MAGIC_BE: u32 = 0xd4c3_b2a1;
/// libpcap magic, nanosecond-timestamp variant, host order.
const PCAP_MAGIC_NS_LE: u32 = 0xa1b2_3c4d;
/// nanosecond variant, byte-swapped.
const PCAP_MAGIC_NS_BE: u32 = 0x4d3c_b2a1;

/// Bytes in the pcap global header.
const PCAP_GLOBAL_HDR_LEN: usize = 24;
/// Bytes in each pcap per-record header.
const PCAP_REC_HDR_LEN: usize = 16;

/// `LINKTYPE_SCTP` (tcpdump.org) — the packet payload is a bare SCTP packet with no
/// L2/L3 framing. This is the container a SIGTRAN/Diameter signalling capture uses
/// when recorded at the SCTP layer.
const LINKTYPE_SCTP: u32 = 248;

/// SCTP common header length (RFC 4960 §3.1): source port, dest port, verification
/// tag, checksum — 12 bytes.
const SCTP_COMMON_HDR_LEN: usize = 12;
/// SCTP DATA chunk type (RFC 4960 §3.3.1).
const SCTP_CHUNK_DATA: u8 = 0;
/// SCTP DATA chunk fixed header before user data (RFC 4960 §3.3.1): chunk
/// type/flags/length (4) + TSN (4) + stream id (2) + stream seq (2) + PPID (4) = 16.
const SCTP_DATA_HDR_LEN: usize = 16;

/// A `.pcap` file of SCTP-carried signalling. Reads the container, reassembles the
/// user data of each SCTP DATA chunk, and yields one PDU per DATA chunk. The
/// MTP3-User (M3UA) or Diameter payload inside is handed to the decoders unchanged.
pub struct PcapSource {
    path: PathBuf,
    byte_cap: usize,
}

impl PcapSource {
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

    /// Parse a fully-buffered pcap image into PDUs. Split from I/O so it is
    /// unit-testable on in-memory bytes. Total: every field is bound-checked; a
    /// truncated or malformed record ends the walk.
    fn parse_pcap(buf: &[u8]) -> Result<Vec<Vec<u8>>, SourceError> {
        let magic_bytes = buf
            .get(0..4)
            .ok_or_else(|| SourceError::BadContainer("file shorter than pcap magic".to_owned()))?;
        let magic = match magic_bytes.try_into() {
            Ok(b) => u32::from_le_bytes(b),
            Err(_) => return Err(SourceError::BadContainer("bad pcap magic".to_owned())),
        };
        let big_endian = match magic {
            PCAP_MAGIC_LE | PCAP_MAGIC_NS_LE => false,
            PCAP_MAGIC_BE | PCAP_MAGIC_NS_BE => true,
            _ => {
                return Err(SourceError::BadContainer(format!(
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

        let network_bytes = buf.get(20..24).ok_or_else(|| {
            SourceError::BadContainer("file shorter than pcap global header".to_owned())
        })?;
        let network = match network_bytes.try_into() {
            Ok(b) => read_u32(b),
            Err(_) => return Err(SourceError::BadContainer("bad pcap link-type".to_owned())),
        };
        if network != LINKTYPE_SCTP {
            return Err(SourceError::BadContainer(format!(
                "unsupported pcap link-type {network} (need LINKTYPE_SCTP = {LINKTYPE_SCTP})"
            )));
        }

        let mut pdus = Vec::new();
        let mut offset = PCAP_GLOBAL_HDR_LEN;
        while let Some(hdr) = buf.get(offset..offset.saturating_add(PCAP_REC_HDR_LEN)) {
            let incl_len = match hdr.get(8..12).and_then(|s| s.try_into().ok()) {
                Some(b) => read_u32(b) as usize,
                None => break,
            };
            let data_start = offset.saturating_add(PCAP_REC_HDR_LEN);
            let data_end = data_start.saturating_add(incl_len);
            let Some(record) = buf.get(data_start..data_end) else {
                break; // declared length overruns captured bytes → truncated file
            };
            Self::extract_sctp_data(record, &mut pdus);
            if pdus.len() >= MAX_PDUS {
                break;
            }
            offset = data_end;
        }
        Ok(pdus)
    }

    /// Extract the user data of every SCTP DATA chunk in one SCTP packet, pushing
    /// each as a PDU. Total: a chunk length that overruns the packet ends the walk
    /// for this packet. A packet that is not SCTP (too short) contributes nothing.
    fn extract_sctp_data(packet: &[u8], out: &mut Vec<Vec<u8>>) {
        // Skip the 12-byte SCTP common header; chunks follow.
        let Some(mut rest) = packet.get(SCTP_COMMON_HDR_LEN..) else {
            return;
        };
        let mut chunk_off = 0usize; // guards against a zero-length chunk loop
        loop {
            // Chunk header: type(1) flags(1) length(2 BE).
            let Some(chunk_hdr) = rest.get(0..4) else {
                break;
            };
            let chunk_type = chunk_hdr.first().copied().unwrap_or(0);
            let len_bytes = match chunk_hdr.get(2..4).and_then(|s| s.try_into().ok()) {
                Some(b) => b,
                None => break,
            };
            let chunk_len = usize::from(u16::from_be_bytes(len_bytes));
            // A chunk length < 4 is invalid (must at least cover its header); stop.
            if chunk_len < 4 {
                break;
            }
            let Some(chunk) = rest.get(0..chunk_len) else {
                break; // declared chunk length overruns the packet
            };

            if chunk_type == SCTP_CHUNK_DATA {
                // User data begins after the 16-byte DATA fixed header.
                if let Some(user_data) = chunk.get(SCTP_DATA_HDR_LEN..)
                    && !user_data.is_empty()
                {
                    out.push(user_data.to_vec());
                }
            }

            // Advance past this chunk, padded to a 4-byte boundary (RFC 4960 §3.2).
            let padded = chunk_len.saturating_add(3) & !3usize;
            chunk_off = chunk_off.saturating_add(padded);
            let Some(next) = rest.get(padded..) else {
                break;
            };
            if next.len() >= rest.len() {
                break; // no forward progress → stop (defensive against 0-advance)
            }
            rest = next;
            let _ = chunk_off;
        }
    }
}

impl CaptureSource for PcapSource {
    fn pdus(&self) -> Result<Vec<Vec<u8>>, SourceError> {
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

/// The device/carrier seam: a live SIGTRAN/Diameter peer source. Behind the
/// off-by-default `live` feature and unconstructed — it requires a provisioned SS7
/// point code / Diameter peering the operator does not possess by building this
/// crate. The decode/flag layers do not change when this becomes real; only the
/// source does.
#[cfg(feature = "live")]
pub struct LiveLinkSource {
    _private: (),
}

#[cfg(feature = "live")]
impl CaptureSource for LiveLinkSource {
    fn pdus(&self) -> Result<Vec<Vec<u8>>, SourceError> {
        Err(SourceError::LiveUnavailable(
            "live SIGTRAN/Diameter link needs a provisioned point code / peering (unbuilt)"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // --- hex dump ---

    #[test]
    fn hex_dump_one_pdu_per_line() {
        let src = HexDumpSource::new("6204aabbccdd\n# comment\n040101");
        let pdus = src.pdus().expect("valid");
        assert_eq!(pdus.len(), 2);
        assert_eq!(pdus[0], vec![0x62, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(pdus[1], vec![0x04, 0x01, 0x01]);
    }

    #[test]
    fn hex_dump_tolerates_grouped_hex() {
        let src = HexDumpSource::new("62 04 aa bb");
        let pdus = src.pdus().expect("valid");
        assert_eq!(pdus[0], vec![0x62, 0x04, 0xaa, 0xbb]);
    }

    #[test]
    fn hex_dump_empty_is_empty_error() {
        assert!(matches!(
            HexDumpSource::new("   \n # only a comment\n").pdus(),
            Err(SourceError::Empty(_))
        ));
    }

    #[test]
    fn hex_dump_bad_hex_rejected() {
        assert!(matches!(
            HexDumpSource::new("62zz").pdus(),
            Err(SourceError::BadHex(_))
        ));
        assert!(matches!(
            HexDumpSource::new("620").pdus(),
            Err(SourceError::BadHex(_))
        ));
    }

    // --- pcap / SCTP ---

    /// Build a minimal little-endian LINKTYPE_SCTP pcap with one SCTP packet
    /// carrying the given DATA-chunk user payloads.
    fn build_sctp_pcap(payloads: &[&[u8]]) -> Vec<u8> {
        // One SCTP packet: 12-byte common header + one DATA chunk per payload.
        let mut sctp = vec![0u8; SCTP_COMMON_HDR_LEN];
        for p in payloads {
            let chunk_len = SCTP_DATA_HDR_LEN + p.len();
            let mut chunk = vec![0u8; SCTP_DATA_HDR_LEN];
            chunk[0] = SCTP_CHUNK_DATA;
            chunk[2..4].copy_from_slice(&(chunk_len as u16).to_be_bytes());
            chunk.extend_from_slice(p);
            // pad to 4-byte boundary
            while !chunk.len().is_multiple_of(4) {
                chunk.push(0);
            }
            sctp.extend_from_slice(&chunk);
        }

        let mut out = Vec::new();
        out.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&LINKTYPE_SCTP.to_le_bytes());
        // one record
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        out.extend_from_slice(&(sctp.len() as u32).to_le_bytes()); // incl_len
        out.extend_from_slice(&(sctp.len() as u32).to_le_bytes()); // orig_len
        out.extend_from_slice(&sctp);
        out
    }

    #[test]
    fn pcap_extracts_one_pdu_per_data_chunk() {
        let pcap = build_sctp_pcap(&[&[0x62, 0x1a, 0x48], &[0x01, 0x00, 0x00, 0x14]]);
        let pdus = PcapSource::parse_pcap(&pcap).expect("valid");
        assert_eq!(pdus.len(), 2);
        assert_eq!(pdus[0], vec![0x62, 0x1a, 0x48]);
        assert_eq!(pdus[1], vec![0x01, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn pcap_rejects_non_pcap() {
        assert!(matches!(
            PcapSource::parse_pcap(b"nope not a pcap file"),
            Err(SourceError::BadContainer(_))
        ));
    }

    #[test]
    fn pcap_rejects_wrong_link_type() {
        let mut pcap = build_sctp_pcap(&[&[0x62]]);
        pcap[20..24].copy_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
        assert!(matches!(
            PcapSource::parse_pcap(&pcap),
            Err(SourceError::BadContainer(_))
        ));
    }

    #[test]
    fn pcap_tolerates_truncated_final_record() {
        let mut pcap = build_sctp_pcap(&[&[0xaa, 0xbb, 0xcc]]);
        pcap.truncate(pcap.len() - 2);
        // Must not panic; truncated record dropped.
        let pdus = PcapSource::parse_pcap(&pcap).expect("header valid");
        assert!(pdus.is_empty());
    }

    #[test]
    fn pcap_chunk_length_overrun_does_not_overread() {
        let mut pcap = build_sctp_pcap(&[&[0xaa, 0xbb]]);
        // The DATA chunk length field sits at: global(24)+rec(16)+common(12)+2.
        let len_off = PCAP_GLOBAL_HDR_LEN + PCAP_REC_HDR_LEN + SCTP_COMMON_HDR_LEN + 2;
        pcap[len_off..len_off + 2].copy_from_slice(&0xffffu16.to_be_bytes());
        // Must not panic; the overrunning chunk is dropped.
        let pdus = PcapSource::parse_pcap(&pcap).expect("header valid");
        assert!(pdus.is_empty());
    }

    #[test]
    fn pcap_empty_but_valid_yields_nothing() {
        let pcap = build_sctp_pcap(&[]);
        let pdus = PcapSource::parse_pcap(&pcap).expect("valid empty");
        assert!(pdus.is_empty());
    }

    #[test]
    fn pcap_skips_non_data_chunk() {
        // A SACK chunk (type 3) carries no user PDU.
        let mut sctp = vec![0u8; SCTP_COMMON_HDR_LEN];
        let mut chunk = vec![0u8; 8];
        chunk[0] = 3; // SACK
        chunk[2..4].copy_from_slice(&8u16.to_be_bytes());
        sctp.extend_from_slice(&chunk);
        let mut out = Vec::new();
        out.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes()); // 4
        out.extend_from_slice(&[0u8; 16]); // version/zone/sigfigs/snaplen (bytes 4..20)
        out.extend_from_slice(&LINKTYPE_SCTP.to_le_bytes()); // network (bytes 20..24)
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(sctp.len() as u32).to_le_bytes());
        out.extend_from_slice(&(sctp.len() as u32).to_le_bytes());
        out.extend_from_slice(&sctp);
        let pdus = PcapSource::parse_pcap(&out).expect("valid");
        assert!(pdus.is_empty());
    }
}
