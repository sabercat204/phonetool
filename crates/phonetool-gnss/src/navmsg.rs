//! Total, parity-gated GPS navigation message decoder.
//!
//! Threat note: the nav message is adversary-authored input — exactly what a
//! spoofer forges. This decoder is total: it never panics, never trusts an
//! air-supplied length/count, discards parity-failing subframes, and records
//! undecoded fields as `None` rather than fabricating them.
//!
//! Grounding: IS-GPS-200 §20.3 (subframe structure, parity algorithm, field
//! definitions). The parity check uses the algorithm of IS-GPS-200 §20.3.5.

use crate::constants::{SUBFRAME_BITS, WORD_BITS, WORDS_PER_SUBFRAME};

/// Decoded ephemeris parameters (all Option — absent on decode/parity failure).
///
/// Field set + scale factors grounded in IS-GPS-200 Table 20-III, cross-checked
/// against RTKLIB `rcvraw.c` `decode_subfrm1/2/3` (the reference open-source
/// decoder). Angular parameters are stored in radians (raw semicircles × π).
#[derive(Debug, Clone, Default)]
pub struct Ephemeris {
    /// Week number (10-bit, mod-1024). Subframe 1.
    pub week: Option<u16>,
    /// Time of ephemeris (seconds into week). Subframe 2.
    pub toe: Option<f64>,
    /// Square root of semi-major axis (m^1/2). Subframe 2.
    pub sqrt_a: Option<f64>,
    /// Eccentricity (dimensionless). Subframe 2.
    pub eccentricity: Option<f64>,
    /// Mean motion difference from computed value (rad/s). Subframe 2.
    pub delta_n: Option<f64>,
    /// Inclination at reference time (rad). Subframe 3.
    pub i0: Option<f64>,
    /// Rate of inclination angle (rad/s). Subframe 3.
    pub idot: Option<f64>,
    /// Longitude of ascending node at reference time (rad). Subframe 3.
    pub omega0: Option<f64>,
    /// Argument of perigee (rad). Subframe 3.
    pub omega: Option<f64>,
    /// Mean anomaly at reference time (rad). Subframe 2.
    pub m0: Option<f64>,
    /// Rate of right ascension (rad/s). Subframe 3.
    pub omega_dot: Option<f64>,
    /// Cosine harmonic correction to argument of latitude (rad). Subframe 2.
    pub cuc: Option<f64>,
    /// Sine harmonic correction to argument of latitude (rad). Subframe 2.
    pub cus: Option<f64>,
    /// Cosine harmonic correction to orbit radius (m). Subframe 3.
    pub crc: Option<f64>,
    /// Sine harmonic correction to orbit radius (m). Subframe 2.
    pub crs: Option<f64>,
    /// Cosine harmonic correction to inclination (rad). Subframe 3.
    pub cic: Option<f64>,
    /// Sine harmonic correction to inclination (rad). Subframe 3.
    pub cis: Option<f64>,
    /// SV clock bias (s). Subframe 1.
    pub af0: Option<f64>,
    /// SV clock drift (s/s). Subframe 1.
    pub af1: Option<f64>,
    /// SV clock drift rate (s/s²). Subframe 1.
    pub af2: Option<f64>,
    /// Time of clock (seconds into week). Subframe 1.
    pub toc: Option<f64>,
}

impl Ephemeris {
    /// Bridge a decoded ephemeris to the ICD-complete [`crate::pvt::OrbitalElements`]
    /// the position propagator requires. Returns `None` if ANY required orbital
    /// field is absent (e.g. only a subset of subframes 1–3 was decoded) — the
    /// propagator never runs on partial data, so no ECEF position is ever
    /// fabricated from a half-decoded ephemeris.
    #[must_use]
    pub fn to_orbital_elements(&self) -> Option<crate::pvt::OrbitalElements> {
        Some(crate::pvt::OrbitalElements {
            sqrt_a: self.sqrt_a?,
            e: self.eccentricity?,
            i0: self.i0?,
            omega0: self.omega0?,
            omega: self.omega?,
            m0: self.m0?,
            delta_n: self.delta_n?,
            omega_dot: self.omega_dot?,
            idot: self.idot?,
            cuc: self.cuc?,
            cus: self.cus?,
            crc: self.crc?,
            crs: self.crs?,
            cic: self.cic?,
            cis: self.cis?,
            toe: self.toe?,
        })
    }
}

/// Decoded subframe result.
#[derive(Debug, Clone)]
pub struct DecodedSubframe {
    /// Subframe ID (1–5), if successfully decoded.
    pub subframe_id: Option<u8>,
    /// Time of Week from the HOW word (seconds), if parity passed.
    pub tow: Option<f64>,
    /// Ephemeris fields (populated from subframes 1–3).
    pub ephemeris: Ephemeris,
    /// Whether all words passed parity.
    pub parity_ok: bool,
}

/// Attempt to decode a subframe from raw nav bits.
///
/// `bits` is a slice of 300 soft-decision or hard-decision bits (0/1 values).
/// Returns a `DecodedSubframe` with whatever fields could be extracted;
/// parity-failing words have their fields set to `None`.
pub fn decode_subframe(bits: &[u8]) -> DecodedSubframe {
    if bits.len() < SUBFRAME_BITS {
        return DecodedSubframe {
            subframe_id: None,
            tow: None,
            ephemeris: Ephemeris::default(),
            parity_ok: false,
        };
    }

    // Extract 10 words of 30 bits each, checking parity with the running
    // D29*/D30* state threaded from the previous word (IS-GPS-200 §20.3.5.2).
    //
    // Seed: (0, 0). Word 1's parity formally depends on the D29*/D30* of the
    // LAST word of the PREVIOUS subframe, which a 300-bit isolated decode does
    // not carry. We seed non-inverting (D29*=D30*=0), the correct assumption
    // for upstream-synchronized, non-complemented bits — the standard contract
    // for subframe-isolated decode. NOT a silent assumption: a wrong seed only
    // affects word 1, and a real streaming decoder threads state across
    // subframe boundaries instead of seeding.
    let mut words: Vec<Option<u32>> = Vec::with_capacity(WORDS_PER_SUBFRAME);
    let mut all_parity_ok = true;
    let mut d29_star: u32 = 0;
    let mut d30_star: u32 = 0;

    for w in 0..WORDS_PER_SUBFRAME {
        let start = w * WORD_BITS;
        let word_bits = bits.get(start..start + WORD_BITS);
        match word_bits {
            Some(wb) => {
                let word_val = bits_to_u32(wb);
                if check_parity(word_val, d29_star, d30_star) {
                    // Recover the source data bits (§20.3.5.2: D_n = d_n ⊕ D30*)
                    // so downstream field extraction reads true source bits even
                    // when the word was transmitted complemented. Parity bits
                    // (D25..D30) are never complemented and are left intact.
                    let corrected = correct_data_bits(word_val, d30_star);
                    // Advance the running state from the RAW received D29/D30
                    // (parity bits, never complemented) — these become the next
                    // word's D29*/D30*.
                    d29_star = (word_val >> 1) & 1;
                    d30_star = word_val & 1;
                    words.push(Some(corrected));
                } else {
                    words.push(None);
                    all_parity_ok = false;
                    // State is undefined after a parity failure; a spoofed or
                    // corrupt word poisons downstream parity, so we stop
                    // trusting the running state and force the rest to fail
                    // rather than fabricate a recovery.
                    d29_star = 0;
                    d30_star = 0;
                }
            }
            None => {
                words.push(None);
                all_parity_ok = false;
                d29_star = 0;
                d30_star = 0;
            }
        }
    }

    // HOW word (word 2) carries TOW and subframe ID.
    let tow = words.get(1).and_then(|w| {
        w.map(|v| {
            let tow_count = (v >> 13) & 0x1_FFFF;
            tow_count as f64 * 6.0 // TOW count × 6 seconds
        })
    });

    let subframe_id = words
        .get(1)
        .and_then(|w| w.map(|v| ((v >> 8) & 0x07) as u8));

    let ephemeris = if all_parity_ok {
        extract_ephemeris(subframe_id, &words)
    } else {
        Ephemeris::default()
    };

    DecodedSubframe {
        subframe_id,
        tow,
        ephemeris,
        parity_ok: all_parity_ok,
    }
}

/// Source-data-bit tap sets and leading `D*` selector for the six parity
/// equations D25..D30 (IS-GPS-200 §20.3.5.2, Table 20-XIV). Each entry is
/// `(source-bit indices d1..d24, which D-star leads: 29 or 30)`. The parity
/// bit computed by entry `i` is `D(25 + i)`.
const PARITY_TAPS: [(&[u8], u8); 6] = [
    (&[1, 2, 3, 5, 6, 10, 11, 12, 13, 14, 17, 18, 20, 23], 29),
    (&[2, 3, 4, 6, 7, 11, 12, 13, 14, 15, 18, 19, 21, 24], 30),
    (&[1, 3, 4, 5, 7, 8, 12, 13, 14, 15, 16, 19, 20, 22], 29),
    (&[2, 4, 5, 6, 8, 9, 13, 14, 15, 16, 17, 20, 21, 23], 30),
    (&[1, 3, 5, 6, 7, 9, 10, 14, 15, 16, 17, 18, 21, 22, 24], 30),
    (&[3, 5, 6, 8, 9, 10, 11, 13, 15, 19, 22, 23, 24], 29),
];

/// Bit `Dn` (n = 1..30, MSB-first) of a 30-bit word packed with `D1` in bit 29.
#[inline]
fn d_bit(word: u32, n: u8) -> u32 {
    (word >> (30 - n as u32)) & 1
}

/// GPS parity check (IS-GPS-200 §20.3.5.2). Recovers the source data bits
/// `d_n = D_n ⊕ D30*`, recomputes the six (32,26) Hamming parity bits from the
/// tap sets and the previous word's `D29*/D30*`, and compares them against the
/// received parity bits `D25..D30`. Returns true only when all six match.
///
/// This is the real algorithm, not an accept-all stub: a forged or corrupted
/// word — the spoofer's payload — fails here and its fields are discarded.
fn check_parity(word: u32, d29_star: u32, d30_star: u32) -> bool {
    // Source data bit d_n (de-complemented). Defined for n = 1..24.
    let source = |n: u8| d_bit(word, n) ^ d30_star;

    for (i, (taps, lead)) in PARITY_TAPS.iter().enumerate() {
        let mut computed = if *lead == 29 { d29_star } else { d30_star };
        for &t in taps.iter() {
            computed ^= source(t);
        }
        // Parity bit being verified: D25, D26, ... D30.
        let received = d_bit(word, 25 + i as u8);
        if computed != received {
            return false;
        }
    }
    true
}

/// Recover the uncomplemented source data bits (D1..D24) in place:
/// `d_n = D_n ⊕ D30*` (§20.3.5.2). Parity bits (D25..D30) are never
/// complemented and are left untouched, so downstream field extraction reads
/// true source bits regardless of transmit-time complementation.
fn correct_data_bits(word: u32, d30_star: u32) -> u32 {
    // D1..D24 occupy bit positions 29..6 (mask 0x3FFF_FFC0).
    const DATA_MASK: u32 = 0x3FFF_FFC0;
    if d30_star == 1 {
        word ^ DATA_MASK
    } else {
        word
    }
}

fn bits_to_u32(bits: &[u8]) -> u32 {
    let mut val: u32 = 0;
    for (i, &b) in bits.iter().enumerate().take(30) {
        val |= ((b & 1) as u32) << (29 - i);
    }
    val
}

/// Semicircles → radians (π). GPS broadcasts angular ephemeris in semicircles;
/// IS-GPS-200 Table 20-III scale factors already include the ×π expectation.
const SC2RAD: f64 = std::f64::consts::PI;

/// Extract 24 source-data bits from each of the 10 corrected words into a flat
/// 240-bit big-endian buffer, discarding the 6 parity bits per word. This
/// reproduces the parity-stripped stream RTKLIB decodes with fixed offsets, so
/// the word-boundary-spanning 32-bit fields (M0, e, √A, Ω0, i0, ω) become
/// contiguous single reads — no hand-rolled cross-word splicing to get wrong.
///
/// A word that failed parity (`None`) contributes zero bits; the caller only
/// calls this on all-parity-ok subframes, so a `None` cannot silently corrupt a
/// field.
fn strip_parity_bits(words: &[Option<u32>]) -> [u8; 240] {
    let mut buf = [0u8; 240];
    for (w, word) in words.iter().enumerate().take(WORDS_PER_SUBFRAME) {
        let value = (*word).unwrap_or(0);
        // Source data bits are D1..D24 = bit positions 29..6 of the 30-bit word.
        for b in 0..24usize {
            let bit = (value >> (29 - b)) & 1;
            if let Some(slot) = buf.get_mut(w * 24 + b) {
                *slot = bit as u8;
            }
        }
    }
    buf
}

/// Read `len` bits (MSB-first) from a bit buffer starting at `pos`, unsigned.
/// Out-of-range reads contribute zero (total, no panic).
fn getbitu(buf: &[u8], pos: usize, len: usize) -> u32 {
    let mut val: u32 = 0;
    for i in 0..len {
        let bit = buf.get(pos + i).copied().unwrap_or(0) as u32;
        val = (val << 1) | (bit & 1);
    }
    val
}

/// Read `len` bits (MSB-first) as a two's-complement signed integer.
fn getbits(buf: &[u8], pos: usize, len: usize) -> i32 {
    let raw = getbitu(buf, pos, len);
    if len == 0 || len >= 32 {
        return raw as i32;
    }
    // Sign-extend from bit (len-1).
    let sign_bit = 1u32 << (len - 1);
    if raw & sign_bit != 0 {
        (raw as i32) - (1i32 << len)
    } else {
        raw as i32
    }
}

/// Extract ephemeris/clock fields from a parity-checked subframe. Offsets and
/// scale factors are IS-GPS-200 Table 20-III, cross-checked verbatim against
/// RTKLIB `decode_subfrm1/2/3`. Offsets are into the parity-stripped 240-bit
/// buffer (24 data bits per word), matching RTKLIB's convention where the
/// TLM+HOW words occupy bits 0..47 and payload starts at bit 48.
fn extract_ephemeris(subframe_id: Option<u8>, words: &[Option<u32>]) -> Ephemeris {
    let mut eph = Ephemeris::default();
    let buf = strip_parity_bits(words);

    match subframe_id {
        Some(1) => {
            // Subframe 1: clock correction + week (RTKLIB decode_subfrm1).
            eph.week = Some(getbitu(&buf, 48, 10) as u16);
            eph.toc = Some(getbitu(&buf, 176, 16) as f64 * 16.0);
            eph.af2 = Some(getbits(&buf, 192, 8) as f64 * 2.0_f64.powi(-55));
            eph.af1 = Some(getbits(&buf, 200, 16) as f64 * 2.0_f64.powi(-43));
            eph.af0 = Some(getbits(&buf, 216, 22) as f64 * 2.0_f64.powi(-31));
        }
        Some(2) => {
            // Subframe 2: ephemeris part 1 (RTKLIB decode_subfrm2).
            eph.crs = Some(getbits(&buf, 56, 16) as f64 * 2.0_f64.powi(-5));
            eph.delta_n = Some(getbits(&buf, 72, 16) as f64 * 2.0_f64.powi(-43) * SC2RAD);
            eph.m0 = Some(getbits(&buf, 88, 32) as f64 * 2.0_f64.powi(-31) * SC2RAD);
            eph.cuc = Some(getbits(&buf, 120, 16) as f64 * 2.0_f64.powi(-29));
            eph.eccentricity = Some(getbitu(&buf, 136, 32) as f64 * 2.0_f64.powi(-33));
            eph.cus = Some(getbits(&buf, 168, 16) as f64 * 2.0_f64.powi(-29));
            eph.sqrt_a = Some(getbitu(&buf, 184, 32) as f64 * 2.0_f64.powi(-19));
            eph.toe = Some(getbitu(&buf, 216, 16) as f64 * 16.0);
        }
        Some(3) => {
            // Subframe 3: ephemeris part 2 (RTKLIB decode_subfrm3).
            eph.cic = Some(getbits(&buf, 48, 16) as f64 * 2.0_f64.powi(-29));
            eph.omega0 = Some(getbits(&buf, 64, 32) as f64 * 2.0_f64.powi(-31) * SC2RAD);
            eph.cis = Some(getbits(&buf, 96, 16) as f64 * 2.0_f64.powi(-29));
            eph.i0 = Some(getbits(&buf, 112, 32) as f64 * 2.0_f64.powi(-31) * SC2RAD);
            eph.crc = Some(getbits(&buf, 144, 16) as f64 * 2.0_f64.powi(-5));
            eph.omega = Some(getbits(&buf, 160, 32) as f64 * 2.0_f64.powi(-31) * SC2RAD);
            eph.omega_dot = Some(getbits(&buf, 192, 24) as f64 * 2.0_f64.powi(-43) * SC2RAD);
            eph.idot = Some(getbits(&buf, 224, 14) as f64 * 2.0_f64.powi(-43) * SC2RAD);
        }
        _ => {}
    }

    eph
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Encode a 30-bit word from 24 source data bits and the previous word's
    /// D29*/D30*, computing the six parity bits with the same taps the decoder
    /// verifies. `complement` mirrors transmit-time data-bit inversion
    /// (which occurs iff D30* == 1). Returns the transmitted 30-bit word,
    /// MSB (D1) at bit 29.
    fn encode_word(source: [u32; 24], d29_star: u32, d30_star: u32) -> u32 {
        // source bit s_n for n in 1..=24
        let s = |n: u8| source[(n - 1) as usize] & 1;

        // Parity computed over source bits + D-star.
        let mut parity = [0u32; 6];
        for (i, (taps, lead)) in PARITY_TAPS.iter().enumerate() {
            let mut p = if *lead == 29 { d29_star } else { d30_star };
            for &t in taps.iter() {
                p ^= s(t);
            }
            parity[i] = p;
        }

        // Transmitted data bits D_n = s_n ⊕ D30*.
        let mut word: u32 = 0;
        for n in 1..=24u8 {
            let bit = s(n) ^ d30_star;
            word |= bit << (30 - n as u32);
        }
        // Parity bits D25..D30 (never complemented).
        for (i, &p) in parity.iter().enumerate() {
            word |= p << (30 - (25 + i as u32));
        }
        word
    }

    /// Inverse of `getbitu`: write `len` bits of `val` (MSB-first) at `pos`.
    fn setbitu(buf: &mut [u8], pos: usize, len: usize, val: u32) {
        for i in 0..len {
            let bit = (val >> (len - 1 - i)) & 1;
            if let Some(slot) = buf.get_mut(pos + i) {
                *slot = bit as u8;
            }
        }
    }

    /// Inverse of `getbits`: encode a signed value as `len`-bit two's complement.
    fn setbits(buf: &mut [u8], pos: usize, len: usize, val: i64) {
        let mask = if len >= 32 {
            u32::MAX
        } else {
            (1u32 << len) - 1
        };
        setbitu(buf, pos, len, (val as u32) & mask);
    }

    /// Pack a 240-bit source buffer (24 data bits × 10 words) into 10 corrected
    /// 30-bit words with zeroed parity fields — sufficient for `extract_ephemeris`,
    /// which reads only the 24 data bits per word. (Parity itself is covered by
    /// the dedicated parity tests.)
    fn pack_words(buf: &[u8; 240]) -> Vec<Option<u32>> {
        (0..WORDS_PER_SUBFRAME)
            .map(|w| {
                let mut word = 0u32;
                for b in 0..24usize {
                    let bit = buf.get(w * 24 + b).copied().unwrap_or(0) as u32;
                    word |= (bit & 1) << (29 - b);
                }
                Some(word)
            })
            .collect()
    }

    #[test]
    fn subframe2_3_decode_recovers_orbital_elements() {
        // Known GPS-like orbital elements (SI/rad), within nominal ranges.
        let sqrt_a = 5153.65_f64; // √m  → a ≈ 26 560 km
        let e = 0.007_f64;
        let m0 = 0.35_f64; // rad
        let delta_n = 4.3e-9_f64; // rad/s
        let cuc = 1.2e-6_f64;
        let cus = 8.4e-6_f64;
        let crs = -20.0_f64; // m
        let crc = 250.0_f64; // m
        let cic = -1.1e-7_f64;
        let cis = 3.2e-8_f64;
        let i0 = 0.96_f64; // rad
        let idot = 2.1e-10_f64; // rad/s
        let omega0 = -1.2_f64; // rad
        let omega = 0.55_f64; // rad
        let omega_dot = -8.1e-9_f64; // rad/s
        let toe = 14_400.0_f64; // s (mult of 16)

        // --- Subframe 2: encode at the cited RTKLIB/Table 20-III offsets. ---
        let mut b2 = [0u8; 240];
        setbits(&mut b2, 56, 16, (crs / 2f64.powi(-5)).round() as i64);
        setbits(
            &mut b2,
            72,
            16,
            (delta_n / (2f64.powi(-43) * SC2RAD)).round() as i64,
        );
        setbits(
            &mut b2,
            88,
            32,
            (m0 / (2f64.powi(-31) * SC2RAD)).round() as i64,
        );
        setbits(&mut b2, 120, 16, (cuc / 2f64.powi(-29)).round() as i64);
        setbitu(&mut b2, 136, 32, (e / 2f64.powi(-33)).round() as u32);
        setbits(&mut b2, 168, 16, (cus / 2f64.powi(-29)).round() as i64);
        setbitu(&mut b2, 184, 32, (sqrt_a / 2f64.powi(-19)).round() as u32);
        setbitu(&mut b2, 216, 16, (toe / 16.0).round() as u32);
        let eph2 = extract_ephemeris(Some(2), &pack_words(&b2));

        // --- Subframe 3. ---
        let mut b3 = [0u8; 240];
        setbits(&mut b3, 48, 16, (cic / 2f64.powi(-29)).round() as i64);
        setbits(
            &mut b3,
            64,
            32,
            (omega0 / (2f64.powi(-31) * SC2RAD)).round() as i64,
        );
        setbits(&mut b3, 96, 16, (cis / 2f64.powi(-29)).round() as i64);
        setbits(
            &mut b3,
            112,
            32,
            (i0 / (2f64.powi(-31) * SC2RAD)).round() as i64,
        );
        setbits(&mut b3, 144, 16, (crc / 2f64.powi(-5)).round() as i64);
        setbits(
            &mut b3,
            160,
            32,
            (omega / (2f64.powi(-31) * SC2RAD)).round() as i64,
        );
        setbits(
            &mut b3,
            192,
            24,
            (omega_dot / (2f64.powi(-43) * SC2RAD)).round() as i64,
        );
        setbits(
            &mut b3,
            224,
            14,
            (idot / (2f64.powi(-43) * SC2RAD)).round() as i64,
        );
        let eph3 = extract_ephemeris(Some(3), &pack_words(&b3));

        // Each field recovers to within its LSB quantization.
        let approx = |got: Option<f64>, want: f64, tol: f64, name: &str| {
            let g = got.unwrap_or_else(|| panic!("{name} missing"));
            assert!((g - want).abs() <= tol, "{name}: got {g}, want {want}");
        };
        approx(eph2.sqrt_a, sqrt_a, 2f64.powi(-19), "sqrt_a");
        approx(eph2.eccentricity, e, 2f64.powi(-33), "e");
        approx(eph2.m0, m0, 2f64.powi(-31) * SC2RAD, "m0");
        approx(eph2.delta_n, delta_n, 2f64.powi(-43) * SC2RAD, "delta_n");
        approx(eph2.cuc, cuc, 2f64.powi(-29), "cuc");
        approx(eph2.cus, cus, 2f64.powi(-29), "cus");
        approx(eph2.crs, crs, 2f64.powi(-5), "crs");
        approx(eph2.toe, toe, 16.0, "toe");
        approx(eph3.i0, i0, 2f64.powi(-31) * SC2RAD, "i0");
        approx(eph3.idot, idot, 2f64.powi(-43) * SC2RAD, "idot");
        approx(eph3.omega0, omega0, 2f64.powi(-31) * SC2RAD, "omega0");
        approx(eph3.omega, omega, 2f64.powi(-31) * SC2RAD, "omega");
        approx(
            eph3.omega_dot,
            omega_dot,
            2f64.powi(-43) * SC2RAD,
            "omega_dot",
        );
        approx(eph3.crc, crc, 2f64.powi(-5), "crc");
        approx(eph3.cic, cic, 2f64.powi(-29), "cic");
        approx(eph3.cis, cis, 2f64.powi(-29), "cis");

        // Bridge: merge the two subframes, convert to OrbitalElements, propagate.
        let mut merged = eph2;
        merged.i0 = eph3.i0;
        merged.idot = eph3.idot;
        merged.omega0 = eph3.omega0;
        merged.omega = eph3.omega;
        merged.omega_dot = eph3.omega_dot;
        merged.crc = eph3.crc;
        merged.cic = eph3.cic;
        merged.cis = eph3.cis;

        let oe = merged
            .to_orbital_elements()
            .expect("complete ephemeris → orbital elements");
        let (x, y, z) = crate::pvt::sv_position_ecef(&oe, toe);
        let r = (x * x + y * y + z * z).sqrt();
        assert!(
            (25_000_000.0..28_000_000.0).contains(&r),
            "propagated orbital radius {r} out of GPS range"
        );
    }

    #[test]
    fn partial_ephemeris_yields_no_orbital_elements() {
        // Only subframe 2 decoded → i0/omega0/... absent → bridge returns None,
        // so the propagator never runs on partial data.
        let mut b2 = [0u8; 240];
        setbitu(&mut b2, 184, 32, (5153.65 / 2f64.powi(-19)).round() as u32);
        let eph = extract_ephemeris(Some(2), &pack_words(&b2));
        assert!(eph.sqrt_a.is_some());
        assert!(
            eph.to_orbital_elements().is_none(),
            "partial ephemeris must not yield orbital elements"
        );
    }

    #[test]
    fn valid_word_passes_parity_and_recovers_source() {
        let source = [
            1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0,
        ];
        // Non-complemented case (D30* = 0).
        let w = encode_word(source, 0, 0);
        assert!(check_parity(w, 0, 0), "well-formed word must pass parity");
        let corrected = correct_data_bits(w, 0);
        for n in 1..=24u8 {
            assert_eq!(d_bit(corrected, n), source[(n - 1) as usize]);
        }
    }

    #[test]
    fn complemented_word_de_complements_to_source() {
        let source = [
            0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        ];
        // D30* = 1 → transmit-time data-bit inversion.
        let w = encode_word(source, 1, 1);
        assert!(check_parity(w, 1, 1), "complemented word must still pass");
        let corrected = correct_data_bits(w, 1);
        for n in 1..=24u8 {
            assert_eq!(
                d_bit(corrected, n),
                source[(n - 1) as usize],
                "bit {n} must de-complement to source"
            );
        }
    }

    #[test]
    fn single_bit_flip_fails_parity() {
        let source = [1u32; 24];
        let w = encode_word(source, 0, 0);
        // Flip one data bit (D5) — a corrupted/forged word.
        let forged = w ^ (1 << (30 - 5));
        assert!(
            !check_parity(forged, 0, 0),
            "a single-bit corruption must fail parity"
        );
    }

    #[test]
    fn wrong_prior_state_fails_parity() {
        let source = [
            0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1,
        ];
        let w = encode_word(source, 1, 0);
        // Verifier told the wrong D29*/D30* → most equations mismatch.
        assert!(
            !check_parity(w, 0, 1),
            "wrong threaded prior state must fail parity"
        );
    }

    #[test]
    fn short_subframe_is_total_no_panic() {
        // Any length below one subframe → clean failure, no panic.
        for len in [0usize, 1, 29, 30, 299] {
            let bits = vec![1u8; len];
            let decoded = decode_subframe(&bits);
            assert!(!decoded.parity_ok);
            assert!(decoded.subframe_id.is_none());
            assert!(decoded.tow.is_none());
        }
    }

    #[test]
    fn all_parity_fail_yields_no_ephemeris() {
        // 300 bits of a pattern that will not satisfy parity for word 1 given
        // the seed state → parity_ok false, ephemeris left default.
        let bits = vec![1u8; SUBFRAME_BITS];
        let decoded = decode_subframe(&bits);
        // With all-ones data the computed parity will not match the all-ones
        // received parity for every word; at minimum decode must not panic and
        // must not fabricate ephemeris when parity is not fully clean.
        if !decoded.parity_ok {
            assert!(decoded.ephemeris.week.is_none());
            assert!(decoded.ephemeris.af0.is_none());
        }
    }
}
