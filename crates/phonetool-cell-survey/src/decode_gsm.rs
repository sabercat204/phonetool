//! Total GSM BCCH / System-Information decoder.
//!
//! Decodes the two System Information messages that carry cell identity and
//! neighbours:
//!   * **SI Type 3** → Location Area Identification (MCC/MNC/LAC) + Cell Identity.
//!   * **SI Type 2** → the advertised neighbour ARFCN list (bit-map-0 format).
//!
//! Grounding (constants and layouts are cited, not guessed):
//!   * L3 RR header, message-type constants, and the SI3 field order come from
//!     libosmocore `include/osmocom/gsm/protocol/gsm_04_08.h`
//!     (`GSM48_PDISC_RR = 0x06`, `GSM48_MT_RR_SYSINFO_3 = 0x1b`,
//!     `..._2 = 0x1a`; SI3 = 3-byte header, `cell_identity` u16, then `lai`).
//!   * PLMN (MCC/MNC) BCD nibble packing follows 3GPP TS 24.008 §10.5.1.3, as
//!     implemented by libosmocore's PLMN-BCD routines.
//!   * The neighbour bit-map-0 extraction (start ARFCN 125, decrement before the
//!     bit test, 4 bits in the first octet then 8/octet, ARFCN range 1..124) is
//!     transcribed from Wireshark's `dissect_arfcn_list_core` in
//!     `epan/dissectors/packet-gsm_a_rr.c`. Only bit-map-0 is decoded; the
//!     1024/512/256/128-range and variable-bitmap formats are recorded as
//!     "present but undecoded", never fabricated into ARFCNs.
//!
//! Threat note: every byte here is adversary-controlled (a rogue BTS crafts its
//! broadcasts to mislead and to break naive parsers). The decoder is total: no
//! `unwrap`/`expect`/panic, no unchecked index, no air-supplied value used to
//! size or index without a bound check. A field that does not decode is recorded
//! absent — never defaulted or guessed (a fabricated neighbour list would mask a
//! `MissingNeighbours` anomaly).

use crate::source::Segment;

/// L3 RR protocol discriminator (`GSM48_PDISC_RR`), low nibble of octet 1.
const PDISC_RR: u8 = 0x06;
/// SI Type 2 message type (`GSM48_MT_RR_SYSINFO_2`).
const MT_SYSINFO_2: u8 = 0x1a;
/// SI Type 3 message type (`GSM48_MT_RR_SYSINFO_3`).
const MT_SYSINFO_3: u8 = 0x1b;

/// A single decoded observation from one GSM SI message. One message rarely
/// carries every field, so all network-identity fields are optional and
/// `cellmap` merges observations sharing an ARFCN. The ARFCN itself always comes
/// from the radio layer (GSMTAP), so it is not optional.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GsmCell {
    /// Mobile Country Code (0..999), if an SI3/SI4 LAI decoded.
    pub mcc: Option<u16>,
    /// Mobile Network Code (0..999), if decoded.
    pub mnc: Option<u16>,
    /// Number of MNC digits (2 or 3) — needed to render the PLMN unambiguously
    /// (MNC 5 with 2 digits is "05", with 3 is "005"): distinct operators.
    pub mnc_digits: Option<u8>,
    /// Location Area Code, if an SI3/SI4 LAI decoded.
    pub lac: Option<u16>,
    /// Cell Identity, if an SI3 decoded it.
    pub cid: Option<u16>,
    /// The ARFCN this cell was observed on (from GSMTAP). Always present.
    pub arfcn: u16,
    /// Received signal level in dBm, if the capture reported one.
    pub signal_dbm: Option<i8>,
    /// Advertised neighbour ARFCNs (from SI2 bit-map-0). Empty is meaningful: it
    /// distinguishes "no neighbours advertised" (a `MissingNeighbours` tell) from
    /// "neighbour list present but in an unsupported format" — see
    /// `neighbours_undecoded`.
    pub neighbours: Vec<u16>,
    /// True when an SI2 neighbour list was present but in a format this decoder
    /// does not decode (a range/variable format). Keeps an empty `neighbours`
    /// from being misread as "no neighbours advertised".
    pub neighbours_undecoded: bool,
}

impl GsmCell {
    /// A bare observation carrying only the ARFCN (and signal) — the starting
    /// point every SI message refines.
    fn bare(arfcn: u16, signal_dbm: Option<i8>) -> Self {
        Self {
            mcc: None,
            mnc: None,
            mnc_digits: None,
            lac: None,
            cid: None,
            arfcn,
            signal_dbm,
            neighbours: Vec::new(),
            neighbours_undecoded: false,
        }
    }
}

/// Decode one GSM broadcast segment into a [`GsmCell`] observation, or `None`
/// if the segment is not a decodable SI2/SI3 message (a decode miss — the caller
/// counts it and continues; it is never fatal).
#[must_use]
pub fn decode(segment: &Segment) -> Option<GsmCell> {
    let payload = &segment.payload;

    // L3 RR header: octet 0 = L2 pseudo-length (unused here), octet 1 =
    // skip-indicator(high nibble)|protocol-discriminator(low nibble), octet 2 =
    // message type. Bound-check each read; a short message is a decode miss.
    let pdisc_octet = *payload.get(1)?;
    if pdisc_octet & 0x0f != PDISC_RR {
        return None; // not RR — not our message
    }
    let msg_type = *payload.get(2)?;
    // The L3 body starts after the 3-octet header.
    let body = payload.get(3..)?;

    match msg_type {
        MT_SYSINFO_3 => decode_si3(segment, body),
        MT_SYSINFO_2 => decode_si2(segment, body),
        _ => None, // SI1/SI4/other — not decoded in v1 (decode miss, not error)
    }
}

/// SI Type 3 body: `cell_identity` (u16, big-endian) then the 5-octet LAI
/// (3 BCD PLMN octets + u16 big-endian LAC). Everything after is ignored.
fn decode_si3(segment: &Segment, body: &[u8]) -> Option<GsmCell> {
    let mut cell = GsmCell::bare(segment.channel, segment.signal_dbm);

    // Cell Identity: body[0..2], big-endian.
    if let Some(ci) = body.get(0..2).and_then(|s| s.try_into().ok()) {
        cell.cid = Some(u16::from_be_bytes(ci));
    }

    // LAI: body[2..7] = 3 PLMN-BCD octets + 2 LAC octets (big-endian).
    if let Some([o0, o1, o2, lac_hi, lac_lo]) =
        body.get(2..7).and_then(|s| <[u8; 5]>::try_from(s).ok())
    {
        if let Some((mcc, mnc, mnc_digits)) = decode_plmn(o0, o1, o2) {
            cell.mcc = Some(mcc);
            cell.mnc = Some(mnc);
            cell.mnc_digits = Some(mnc_digits);
        }
        cell.lac = Some(u16::from_be_bytes([lac_hi, lac_lo]));
    }

    Some(cell)
}

/// Decode a 3-octet PLMN (TS 24.008 §10.5.1.3) into `(mcc, mnc, mnc_digits)`.
///
/// Octet 0: MCC digit 1 (low nibble) | MCC digit 2 (high nibble).
/// Octet 1: MCC digit 3 (low nibble) | MNC digit 3 or 0xf filler (high nibble).
/// Octet 2: MNC digit 1 (low nibble) | MNC digit 2 (high nibble).
///
/// Returns `None` if a required digit nibble is not a decimal digit (0..9) —
/// an undecodable PLMN is recorded absent, never guessed.
fn decode_plmn(o0: u8, o1: u8, o2: u8) -> Option<(u16, u16, u8)> {
    let mcc_d1 = digit(o0 & 0x0f)?;
    let mcc_d2 = digit(o0 >> 4)?;
    let mcc_d3 = digit(o1 & 0x0f)?;
    let mcc = mcc_d1 as u16 * 100 + mcc_d2 as u16 * 10 + mcc_d3 as u16;

    let mnc_d1 = digit(o2 & 0x0f)?;
    let mnc_d2 = digit(o2 >> 4)?;
    let mnc_d3_nibble = o1 >> 4;

    if mnc_d3_nibble == 0x0f {
        // Two-digit MNC (0xf filler in the high nibble of octet 1).
        Some((mcc, mnc_d1 as u16 * 10 + mnc_d2 as u16, 2))
    } else {
        let mnc_d3 = digit(mnc_d3_nibble)?;
        Some((
            mcc,
            mnc_d1 as u16 * 100 + mnc_d2 as u16 * 10 + mnc_d3 as u16,
            3,
        ))
    }
}

/// Validate a BCD nibble is a decimal digit; `None` for the 0xf filler or any
/// out-of-range value.
fn digit(nibble: u8) -> Option<u8> {
    (nibble <= 9).then_some(nibble)
}

/// SI Type 2 body: a 16-octet Neighbour Cell Description IE (fixed), then NCC
/// Permitted and RACH control (ignored here). Decodes only the bit-map-0 format.
fn decode_si2(segment: &Segment, body: &[u8]) -> Option<GsmCell> {
    let mut cell = GsmCell::bare(segment.channel, segment.signal_dbm);

    // The Neighbour Cell Description IE is the first 16 octets of the body.
    let Some(ncd) = body.get(0..16) else {
        // Truncated — the neighbour list is present-but-undecodable.
        cell.neighbours_undecoded = true;
        return Some(cell);
    };

    match decode_neighbours_bitmap0(ncd) {
        Some(neighbours) => cell.neighbours = neighbours,
        // A non-bit-map-0 format (range / variable): we do NOT fabricate ARFCNs.
        None => cell.neighbours_undecoded = true,
    }
    Some(cell)
}

/// Decode the bit-map-0 frequency-list format of a Neighbour Cell Description.
///
/// Format identifier: bit-map-0 iff the top two bits of the first octet are 00
/// (`(octet0 & 0xc0) == 0`) — Wireshark `dissect_arfcn_list_core`. For a
/// Neighbour Cell Description those two bits are EXT-IND and BA-IND; requiring
/// them zero means an EXT-IND-set list is (safely) treated as undecoded rather
/// than mis-decoded.
///
/// Returns the set ARFCNs, or `None` if the format is not bit-map-0.
fn decode_neighbours_bitmap0(ncd: &[u8]) -> Option<Vec<u16>> {
    let first = *ncd.first()?;
    if first & 0xc0 != 0x00 {
        return None; // range or variable-bitmap format — not decoded
    }

    // Transcribed from Wireshark: start ARFCN 125, decrement *before* the bit
    // test; the first octet contributes its low 4 bits (ARFCN 124..121), each
    // subsequent octet contributes all 8 bits, down to ARFCN 1.
    let mut arfcns = Vec::new();
    let mut arfcn: i32 = 125;
    let mut bits_in_octet = 4u8; // first octet: low nibble only
    for &octet in ncd {
        let mut bit = bits_in_octet;
        while bit != 0 {
            bit -= 1;
            arfcn -= 1;
            if arfcn >= 1 && (octet >> bit) & 1 == 1 {
                // ARFCN 0 is not represented in bit-map-0; guard the lower bound.
                if let Ok(a) = u16::try_from(arfcn) {
                    arfcns.push(a);
                }
            }
        }
        bits_in_octet = 8; // every octet after the first
    }
    Some(arfcns)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::source::Rat;

    /// Build an L3 RR message: header (L2 plen, pdisc/skip, msg type) + body.
    fn l3(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![0x00, PDISC_RR, msg_type];
        m.extend_from_slice(body);
        m
    }

    fn seg(payload: Vec<u8>) -> Segment {
        Segment {
            rat: Rat::Gsm,
            channel: 42,
            signal_dbm: Some(-75),
            payload,
        }
    }

    #[test]
    fn decodes_si3_identity() {
        // Cell Identity 0x1234; PLMN = MCC 262 MNC 02 (Germany, 2-digit):
        //   o0 = MCC d1|d2 = 2 | (6<<4) = 0x62
        //   o1 = MCC d3 | 0xf filler = 2 | 0xf0 = 0xf2
        //   o2 = MNC d1|d2 = 0 | (2<<4) = 0x20
        // LAC 0xABCD.
        let body = [0x12, 0x34, 0x62, 0xf2, 0x20, 0xAB, 0xCD];
        let cell = decode(&seg(l3(MT_SYSINFO_3, &body))).expect("si3 decodes");
        assert_eq!(cell.cid, Some(0x1234));
        assert_eq!(cell.mcc, Some(262));
        assert_eq!(cell.mnc, Some(2));
        assert_eq!(cell.mnc_digits, Some(2));
        assert_eq!(cell.lac, Some(0xABCD));
        assert_eq!(cell.arfcn, 42);
    }

    #[test]
    fn decodes_three_digit_mnc() {
        // MCC 310 MNC 260 (T-Mobile US, 3-digit):
        //   o0 = 3 | (1<<4) = 0x13; o1 = 0 (MCC d3) | (0<<4 MNC d3=0) = 0x00;
        //   o2 = MNC d1=2 | (MNC d2=6 <<4) = 0x62.
        let body = [0x00, 0x01, 0x13, 0x00, 0x62, 0x00, 0x01];
        let cell = decode(&seg(l3(MT_SYSINFO_3, &body))).expect("si3 decodes");
        assert_eq!(cell.mcc, Some(310));
        assert_eq!(cell.mnc, Some(260));
        assert_eq!(cell.mnc_digits, Some(3));
    }

    #[test]
    fn invalid_bcd_nibble_leaves_plmn_absent() {
        // o0 low nibble = 0xf (not a digit) → PLMN undecodable, recorded absent,
        // but CID and LAC still decode.
        let body = [0x00, 0x05, 0x6f, 0xf2, 0x20, 0x00, 0x0a];
        let cell = decode(&seg(l3(MT_SYSINFO_3, &body))).expect("si3 decodes");
        assert_eq!(cell.mcc, None);
        assert_eq!(cell.mnc, None);
        assert_eq!(cell.cid, Some(0x0005));
        assert_eq!(cell.lac, Some(0x000a));
    }

    #[test]
    fn truncated_si3_does_not_panic() {
        // Body shorter than cell identity + LAI → decodes what it can, no panic.
        let cell = decode(&seg(l3(MT_SYSINFO_3, &[0x12]))).expect("still a cell");
        assert_eq!(cell.cid, None);
        assert_eq!(cell.mcc, None);
    }

    #[test]
    fn non_rr_message_is_a_decode_miss() {
        // Protocol discriminator 0x05 (MM), not RR.
        let payload = vec![0x00, 0x05, MT_SYSINFO_3, 0x12, 0x34];
        assert!(decode(&seg(payload)).is_none());
    }

    #[test]
    fn unknown_message_type_is_a_decode_miss() {
        assert!(decode(&seg(l3(0x21, &[0x00; 20]))).is_none());
    }

    #[test]
    fn decodes_si2_bitmap0_neighbours() {
        // 16-octet Neighbour Cell Description, bit-map-0 (top 2 bits of octet0
        // are 00). Set octet0 bit0 (=1): that is the 4th bit tested in the first
        // octet → ARFCN 121. Set octet1 bit7 (0x80): first bit of octet1 →
        // ARFCN 120.
        let mut ncd = [0u8; 16];
        ncd[0] = 0b0000_0001; // low nibble bit0 → ARFCN 121
        ncd[1] = 0b1000_0000; // high bit → ARFCN 120
        let cell = decode(&seg(l3(MT_SYSINFO_2, &ncd))).expect("si2 decodes");
        assert!(!cell.neighbours_undecoded);
        assert!(cell.neighbours.contains(&121), "got {:?}", cell.neighbours);
        assert!(cell.neighbours.contains(&120), "got {:?}", cell.neighbours);
    }

    #[test]
    fn empty_si2_bitmap0_yields_no_neighbours_not_undecoded() {
        // All-zero bit-map-0: a genuine "no neighbours advertised" — distinct
        // from an unsupported format.
        let ncd = [0u8; 16];
        let cell = decode(&seg(l3(MT_SYSINFO_2, &ncd))).expect("si2 decodes");
        assert!(cell.neighbours.is_empty());
        assert!(!cell.neighbours_undecoded);
    }

    #[test]
    fn si2_range_format_is_flagged_undecoded_not_fabricated() {
        // Top two bits = 10 → a range format. We must NOT invent ARFCNs.
        let mut ncd = [0u8; 16];
        ncd[0] = 0b1000_0000;
        let cell = decode(&seg(l3(MT_SYSINFO_2, &ncd))).expect("si2 decodes");
        assert!(cell.neighbours.is_empty());
        assert!(cell.neighbours_undecoded);
    }

    #[test]
    fn truncated_si2_neighbour_ie_is_flagged_undecoded() {
        // Fewer than 16 octets of Neighbour Cell Description.
        let cell = decode(&seg(l3(MT_SYSINFO_2, &[0u8; 5]))).expect("still a cell");
        assert!(cell.neighbours_undecoded);
    }

    #[test]
    fn hostile_inputs_never_panic() {
        // Empty, header-only, giant, and random-ish payloads all return without
        // panicking (a decode miss or a partial cell).
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x00, PDISC_RR],
            vec![0x00, PDISC_RR, MT_SYSINFO_3],
            vec![0xff; 4096],
            l3(MT_SYSINFO_2, &[0xff; 3]),
            l3(MT_SYSINFO_3, &[0xff; 2]),
        ];
        for c in cases {
            let _ = decode(&seg(c)); // must not panic
        }
    }
}
