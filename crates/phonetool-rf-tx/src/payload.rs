//! Per-scheme payload validation and framing — total, panic-free boundary parsing.
//!
//! Two payload kinds this sprint:
//!   - **CW** — text → Morse elements ([`cw_elements`]). An unencodable character is
//!     an error before any render (Req 6.1).
//!   - **AX.25** — an AX.25 v2.2 UI frame ([`Ax25Frame`]) with validated callsigns,
//!     the standard framing (address + control + PID + info), a CRC-16/X.25 FCS, and
//!     HDLC bit-stuffing + flags applied when the bit stream is produced.
//!
//! Everything here is total: an over-long callsign, a non-encodable character, or an
//! empty field is a typed error, never a panic (Req 6.5).
//!
//! Grounding:
//!   - Morse code table — ITU-R M.1677-1.
//!   - AX.25 UI frame layout, address encoding (callsign shifted left 1 bit, SSID
//!     octet, HDLC address extension bit), control=0x03 (UI), PID=0xF0 (no L3) —
//!     AX.25 v2.2 §6.
//!   - FCS: CRC-16/X.25 (poly 0x1021 reflected → 0x8408, init 0xFFFF, xorout
//!     0xFFFF), transmitted LSB-first — AX.25 v2.2 §6.4 / ISO 3309 HDLC.
//!   - Flag 0x7E, bit-stuffing after five consecutive 1s — HDLC / AX.25 v2.2 §3.

use crate::modulate::CwElement;

/// Maximum callsign length in characters (base callsign, excluding SSID). AX.25
/// addresses are 6 characters, space-padded.
const AX25_CALL_LEN: usize = 6;
/// AX.25 UI control field (unnumbered information).
const AX25_CONTROL_UI: u8 = 0x03;
/// AX.25 PID for "no layer-3 protocol".
const AX25_PID_NONE: u8 = 0xF0;
/// HDLC flag octet.
const HDLC_FLAG: u8 = 0x7E;

/// Why a payload failed boundary validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// A character has no Morse encoding.
    #[error("character '{0}' is not encodable in Morse")]
    UnencodableChar(char),
    /// A callsign is empty, too long, or has illegal characters.
    #[error("invalid AX.25 callsign: {0}")]
    BadCallsign(String),
    /// An SSID outside 0–15.
    #[error("SSID {0} out of range 0-15")]
    BadSsid(u8),
    /// The payload was empty (no encodable content).
    #[error("empty payload")]
    Empty,
}

// ---------------------------------------------------------------------------
// CW / Morse
// ---------------------------------------------------------------------------

/// The Morse code table (ITU-R M.1677-1): each entry maps an uppercase character to
/// its dit(`.`)/dah(`-`) pattern. Grounded, not invented.
const MORSE: &[(char, &str)] = &[
    ('A', ".-"),
    ('B', "-..."),
    ('C', "-.-."),
    ('D', "-.."),
    ('E', "."),
    ('F', "..-."),
    ('G', "--."),
    ('H', "...."),
    ('I', ".."),
    ('J', ".---"),
    ('K', "-.-"),
    ('L', ".-.."),
    ('M', "--"),
    ('N', "-."),
    ('O', "---"),
    ('P', ".--."),
    ('Q', "--.-"),
    ('R', ".-."),
    ('S', "..."),
    ('T', "-"),
    ('U', "..-"),
    ('V', "...-"),
    ('W', ".--"),
    ('X', "-..-"),
    ('Y', "-.--"),
    ('Z', "--.."),
    ('0', "-----"),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
    // Punctuation / prosigns (ITU-R M.1677-1 §3).
    ('.', ".-.-.-"),
    (',', "--..--"),
    ('?', "..--.."),
    ('/', "-..-."),
    ('=', "-...-"),
    ('+', ".-.-."),
    ('-', "-....-"),
    (':', "---..."),
    ('\'', ".----."),
    ('(', "-.--."),
    (')', "-.--.-"),
    ('@', ".--.-."),
];

/// Look up a character's Morse pattern (case-insensitive). `None` if unencodable.
fn morse_for(c: char) -> Option<&'static str> {
    let up = c.to_ascii_uppercase();
    MORSE.iter().find(|(m, _)| *m == up).map(|(_, p)| *p)
}

/// Encode text into a sequence of CW keying elements (dits, dahs, and the ITU
/// inter-element / inter-character / inter-word gaps). A space separates words. An
/// unencodable character is a boundary error (Req 6.1); an all-whitespace or empty
/// input yields no elements → the caller's degenerate `Empty`.
///
/// # Errors
/// [`PayloadError::UnencodableChar`] for a character with no Morse encoding.
pub fn cw_elements(text: &str) -> Result<Vec<CwElement>, PayloadError> {
    let mut out = Vec::new();
    let mut first_word = true;

    for word in text.split_whitespace() {
        if !first_word {
            out.push(CwElement::WordGap);
        }
        first_word = false;

        for (ci, c) in word.chars().enumerate() {
            if ci > 0 {
                out.push(CwElement::CharGap);
            }
            let pattern = morse_for(c).ok_or(PayloadError::UnencodableChar(c))?;
            for (ei, sym) in pattern.chars().enumerate() {
                if ei > 0 {
                    out.push(CwElement::IntraGap);
                }
                match sym {
                    '.' => out.push(CwElement::Dit),
                    '-' => out.push(CwElement::Dah),
                    // MORSE table only contains '.'/'-', so this is unreachable in
                    // practice; stay total rather than unwrap.
                    _ => return Err(PayloadError::UnencodableChar(sym)),
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// AX.25 UI frame
// ---------------------------------------------------------------------------

/// A validated AX.25 v2.2 UI frame (the APRS-carrying frame). Holds the destination
/// and source callsigns (+SSIDs) and the information field; produces the framed,
/// FCS-appended, bit-stuffed, flag-delimited bit stream for the modulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ax25Frame {
    dest: Callsign,
    source: Callsign,
    info: Vec<u8>,
}

/// A validated AX.25 callsign: 1–6 uppercase-alphanumeric characters + an SSID 0–15.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Callsign {
    call: String,
    ssid: u8,
}

impl Callsign {
    /// Parse a callsign string of the form `CALL` or `CALL-SSID`.
    fn parse(s: &str) -> Result<Self, PayloadError> {
        let (call, ssid) = match s.split_once('-') {
            Some((c, sid)) => {
                let n: u8 = sid
                    .parse()
                    .map_err(|_| PayloadError::BadCallsign(s.to_owned()))?;
                if n > 15 {
                    return Err(PayloadError::BadSsid(n));
                }
                (c, n)
            }
            None => (s, 0),
        };
        if call.is_empty() || call.len() > AX25_CALL_LEN {
            return Err(PayloadError::BadCallsign(s.to_owned()));
        }
        if !call
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return Err(PayloadError::BadCallsign(s.to_owned()));
        }
        Ok(Self {
            call: call.to_owned(),
            ssid,
        })
    }

    /// Encode the 7-octet AX.25 address field. Each callsign character is shifted
    /// left one bit; the field is space-padded to 6 chars; the 7th octet carries the
    /// SSID (bits 1–4), with reserved bits set and the HDLC extension bit `last`
    /// marking the final address in the field (AX.25 v2.2 §6.2).
    fn encode_address(&self, last: bool) -> [u8; 7] {
        let mut out = [0u8; 7];
        let bytes = self.call.as_bytes();
        // Space-pad to 6 chars; shift left 1 — the low bit is the HDLC
        // address-extension bit.
        for (slot, i) in out.iter_mut().zip(0..AX25_CALL_LEN) {
            *slot = bytes.get(i).copied().unwrap_or(b' ') << 1;
        }
        // SSID octet: 0b0110_0000 reserved bits set | ssid<<1 | extension bit.
        let ext = if last { 1 } else { 0 };
        out[6] = 0b0110_0000 | (self.ssid << 1) | ext;
        out
    }
}

impl Ax25Frame {
    /// Build a UI frame from a destination, source, and information field.
    ///
    /// # Errors
    /// [`PayloadError`] on an invalid callsign/SSID. An empty info field is allowed
    /// here (the frame still has content); the degenerate check is at the render.
    pub fn new_ui(source: &str, dest: &str, info: &[u8]) -> Result<Self, PayloadError> {
        Ok(Self {
            dest: Callsign::parse(dest)?,
            source: Callsign::parse(source)?,
            info: info.to_vec(),
        })
    }

    /// Assemble the un-stuffed frame octets: address (dest then source), control
    /// (UI = 0x03), PID (0xF0), info. FCS and flags are applied in [`Self::nrzi_bits`].
    fn frame_octets(&self) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&self.dest.encode_address(false));
        f.extend_from_slice(&self.source.encode_address(true)); // last address
        f.push(AX25_CONTROL_UI);
        f.push(AX25_PID_NONE);
        f.extend_from_slice(&self.info);
        f
    }

    /// The complete transmit bit stream: opening flag, bit-stuffed
    /// frame+FCS, closing flag — as NRZI-ready logical bits (`true` = 1). The
    /// modulator maps each bit to a mark/space tone. Flags are NOT bit-stuffed;
    /// the frame body and FCS are.
    #[must_use]
    pub fn nrzi_bits(&self) -> Vec<bool> {
        let mut body = self.frame_octets();
        let fcs = crc_x25(&body);
        // FCS is transmitted low byte first, LSB-first within each byte (see
        // bits_lsb_first); append the two FCS octets to the body.
        body.push((fcs & 0xff) as u8);
        body.push((fcs >> 8) as u8);

        // Convert body to LSB-first bits, then bit-stuff (insert a 0 after five
        // consecutive 1s), then frame with un-stuffed flags.
        let raw_bits = bits_lsb_first(&body);
        let stuffed = bit_stuff(&raw_bits);

        let mut out = Vec::new();
        push_flag(&mut out);
        out.extend_from_slice(&stuffed);
        push_flag(&mut out);
        out
    }
}

/// Append one HDLC flag (0x7E) as LSB-first bits (not bit-stuffed).
fn push_flag(out: &mut Vec<bool>) {
    for b in bits_lsb_first(&[HDLC_FLAG]) {
        out.push(b);
    }
}

/// Expand bytes to a bit vector, least-significant-bit first (AX.25/HDLC order).
fn bits_lsb_first(bytes: &[u8]) -> Vec<bool> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for i in 0..8 {
            out.push((b >> i) & 1 == 1);
        }
    }
    out
}

/// HDLC bit-stuffing: after five consecutive 1 bits, insert a 0 (AX.25 v2.2 §3.6).
fn bit_stuff(bits: &[bool]) -> Vec<bool> {
    let mut out = Vec::with_capacity(bits.len());
    let mut ones = 0u8;
    for &bit in bits {
        out.push(bit);
        if bit {
            ones += 1;
            if ones == 5 {
                out.push(false);
                ones = 0;
            }
        } else {
            ones = 0;
        }
    }
    out
}

/// CRC-16/X.25 (poly 0x1021 reflected = 0x8408, init 0xFFFF, xorout 0xFFFF) — the
/// AX.25 FCS. Grounded against ISO 3309 / AX.25 v2.2 §6.4.
fn crc_x25(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn cw_encodes_sos() {
        // S=... O=--- S=...  → 3 dits, chargap, 3 dahs, chargap, 3 dits.
        let e = cw_elements("SOS").expect("valid");
        let dits = e.iter().filter(|x| **x == CwElement::Dit).count();
        let dahs = e.iter().filter(|x| **x == CwElement::Dah).count();
        assert_eq!(dits, 6);
        assert_eq!(dahs, 3);
        assert_eq!(e.iter().filter(|x| **x == CwElement::CharGap).count(), 2);
    }

    #[test]
    fn cw_word_gap_between_words() {
        let e = cw_elements("E E").expect("valid");
        assert_eq!(e.iter().filter(|x| **x == CwElement::WordGap).count(), 1);
    }

    #[test]
    fn cw_case_insensitive() {
        assert_eq!(cw_elements("e").unwrap(), cw_elements("E").unwrap());
    }

    #[test]
    fn cw_unencodable_char_rejected() {
        assert_eq!(
            cw_elements("hi~there"),
            Err(PayloadError::UnencodableChar('~'))
        );
    }

    #[test]
    fn cw_empty_yields_no_elements() {
        assert!(cw_elements("").expect("ok").is_empty());
        assert!(cw_elements("   ").expect("ok").is_empty());
    }

    #[test]
    fn callsign_parse_with_ssid() {
        let c = Callsign::parse("N0CALL-7").expect("valid");
        assert_eq!(c.call, "N0CALL");
        assert_eq!(c.ssid, 7);
    }

    #[test]
    fn callsign_rejects_bad() {
        assert!(matches!(
            Callsign::parse("toolongcall"),
            Err(PayloadError::BadCallsign(_))
        ));
        assert!(matches!(
            Callsign::parse(""),
            Err(PayloadError::BadCallsign(_))
        ));
        assert!(matches!(
            Callsign::parse("N0CALL-99"),
            Err(PayloadError::BadSsid(_))
        ));
        assert!(matches!(
            Callsign::parse("lower"),
            Err(PayloadError::BadCallsign(_))
        ));
    }

    #[test]
    fn address_encoding_shifts_left() {
        let c = Callsign::parse("AB1CD").expect("valid");
        let addr = c.encode_address(false);
        // 'A' = 0x41 << 1 = 0x82.
        assert_eq!(addr[0], 0x41 << 1);
        // extension bit clear (not last).
        assert_eq!(addr[6] & 1, 0);
        let last = c.encode_address(true);
        assert_eq!(last[6] & 1, 1);
    }

    #[test]
    fn crc_x25_known_vector() {
        // CRC-16/X.25 of "123456789" is 0x906E (check value, catalogue of CRC algs).
        assert_eq!(crc_x25(b"123456789"), 0x906E);
    }

    #[test]
    fn bit_stuffing_inserts_zero_after_five_ones() {
        // Six 1s → after five, a 0 is inserted: 1 1 1 1 1 0 1.
        let bits = vec![true; 6];
        let stuffed = bit_stuff(&bits);
        assert_eq!(stuffed.len(), 7);
        assert!(!stuffed[5]); // inserted 0
        assert!(stuffed[6]); // the sixth 1
    }

    #[test]
    fn ui_frame_bits_are_flag_delimited() {
        let frame = Ax25Frame::new_ui("N0CALL", "APRS", b">hi").expect("frame");
        let bits = frame.nrzi_bits();
        // Opening flag 0x7E LSB-first = 0 1 1 1 1 1 1 0.
        let flag: Vec<bool> = super::bits_lsb_first(&[HDLC_FLAG]);
        assert_eq!(&bits[0..8], &flag[..]);
        assert_eq!(&bits[bits.len() - 8..], &flag[..]);
        assert!(bits.len() > 16);
    }

    #[test]
    fn ax25_frame_rejects_bad_callsign() {
        assert!(Ax25Frame::new_ui("waytoolong", "APRS", b"x").is_err());
    }
}
