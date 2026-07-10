//! GPS L1 C/A Gold-code generation.
//!
//! Grounding: IS-GPS-200 Rev N, Section 3.3.2.3 — the C/A code is the modulo-2
//! sum of G1 and G2 (with a PRN-specific phase selection on G2). G1 and G2 are
//! 10-stage LFSRs with specified feedback polynomials and a specified phase
//! assignment table (Table 3-Ia). Code length = 1023 chips.
//!
//! The G2 phase-select tap pairs below are from IS-GPS-200 Table 3-Ia. Each PRN
//! (1–32) selects two taps of G2 whose XOR is added to G1 to form the C/A code.

/// GPS L1 C/A code length: 1023 chips (IS-GPS-200 §3.3.2.3).
pub const CODE_LEN: usize = 1023;

/// G2 tap-select pairs for PRN 1–32 (IS-GPS-200 Table 3-Ia).
/// Index 0 = PRN 1. Each pair is (tap1, tap2) where taps are 1-indexed
/// into the G2 register.
const G2_TAPS: [(usize, usize); 32] = [
    (2, 6),
    (3, 7),
    (4, 8),
    (5, 9),
    (1, 9),
    (2, 10),
    (1, 8),
    (2, 9),
    (3, 10),
    (2, 3),
    (3, 4),
    (5, 6),
    (6, 7),
    (7, 8),
    (8, 9),
    (9, 10),
    (1, 4),
    (2, 5),
    (3, 6),
    (4, 7),
    (5, 8),
    (6, 9),
    (1, 3),
    (4, 6),
    (5, 7),
    (6, 8),
    (7, 9),
    (8, 10),
    (1, 6),
    (2, 7),
    (3, 8),
    (4, 9),
];

/// Generate the C/A Gold code for a given PRN (1–32).
/// Returns a 1023-chip sequence of +1/-1 values (as `i8`).
/// Returns `None` for PRN outside 1–32.
pub fn generate_ca_code(prn: u8) -> Option<Vec<i8>> {
    if prn == 0 || prn > 32 {
        return None;
    }

    let (tap1, tap2) = G2_TAPS.get((prn - 1) as usize)?;
    let tap1 = *tap1;
    let tap2 = *tap2;

    let mut g1: u16 = 0x3FF; // all-ones initial state (10 bits)
    let mut g2: u16 = 0x3FF;

    let mut code = Vec::with_capacity(CODE_LEN);

    for _ in 0..CODE_LEN {
        // G1 output = bit 10 (MSB of the 10-bit register)
        let g1_out = (g1 >> 9) & 1;
        // G2 output = XOR of the two selected taps (1-indexed)
        let g2_out = ((g2 >> (tap1 - 1)) ^ (g2 >> (tap2 - 1))) & 1;
        // C/A chip = G1 XOR G2(taps), mapped to +1/-1
        let chip = g1_out ^ g2_out;
        code.push(if chip == 0 { 1 } else { -1 });

        // Clock G1: feedback = bit10 XOR bit3 (polynomial x^10 + x^3 + 1)
        let g1_fb = ((g1 >> 9) ^ (g1 >> 2)) & 1;
        g1 = ((g1 << 1) | g1_fb) & 0x3FF;

        // Clock G2: feedback = bit10 XOR bit9 XOR bit8 XOR bit6 XOR bit3 XOR bit2
        // (polynomial x^10 + x^9 + x^8 + x^6 + x^3 + x^2 + 1)
        let g2_fb = ((g2 >> 9) ^ (g2 >> 8) ^ (g2 >> 7) ^ (g2 >> 5) ^ (g2 >> 2) ^ (g2 >> 1)) & 1;
        g2 = ((g2 << 1) | g2_fb) & 0x3FF;
    }

    Some(code)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn code_length_is_1023() {
        for prn in 1..=32 {
            let code = generate_ca_code(prn).unwrap();
            assert_eq!(code.len(), CODE_LEN, "PRN {prn} code length");
        }
    }

    #[test]
    fn code_values_are_plus_minus_one() {
        let code = generate_ca_code(1).unwrap();
        assert!(code.iter().all(|&c| c == 1 || c == -1));
    }

    #[test]
    fn invalid_prn_returns_none() {
        assert!(generate_ca_code(0).is_none());
        assert!(generate_ca_code(33).is_none());
    }

    #[test]
    fn different_prns_produce_different_codes() {
        let c1 = generate_ca_code(1).unwrap();
        let c2 = generate_ca_code(2).unwrap();
        assert_ne!(c1, c2);
    }
}
