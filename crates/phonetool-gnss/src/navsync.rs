//! Bit synchronization and 50 bps navigation-bit demodulation.
//!
//! Bridges the tracking-loop prompt correlators to the [`crate::navmsg`]
//! decoder: prompt series → bit-edge sync → nav bits → frame sync (TLM
//! preamble) → 300-bit subframes. This is the stage that lets a *real* IQ
//! capture reach decoded ephemeris, closing the loop the propagator has been
//! waiting on.
//!
//! Grounding: IS-GPS-200 §20.3.2 (20 C/A periods per nav bit, 50 bps),
//! §20.3.3.1 (TLM preamble 0b10001011). No timing constant is invented.
//!
//! Threat note: the prompt series and the bit stream are derived from adversary
//! RF. Every stage is total — no panic, no unchecked index, no trust in an
//! air-supplied count — and reports honest absence (empty / `None`) rather than
//! fabricating a bit, an edge, or a preamble that is not there.

use num_complex::Complex;

use crate::constants::{CA_CHIP_RATE, CA_CODE_LEN, TLM_PREAMBLE};
use crate::gold;
use phonetool_sdr_rx::source::SampleBlock;

/// Number of C/A code periods integrated per navigation bit (IS-GPS-200
/// §20.3.3.2: 50 bps over 1 kHz code repetition = 20 periods/bit).
pub const PERIODS_PER_BIT: usize = 20;

/// Length of the TLM preamble in bits (IS-GPS-200 §20.3.3.1).
pub const PREAMBLE_BITS: usize = 8;

/// Bits per subframe — one preamble repeat interval.
pub const SUBFRAME_BITS: usize = crate::constants::SUBFRAME_BITS;

/// A located preamble in a bit stream, with the polarity that matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreambleHit {
    /// Bit index where the preamble starts.
    pub bit_index: usize,
    /// `true` if the stream matched the *inverted* preamble — i.e. the whole
    /// bit stream is polarity-flipped relative to source (a PLL 180° ambiguity).
    pub inverted: bool,
}

/// Correlate a sample block into a series of prompt correlator outputs, one per
/// 1 ms C/A code period, applying carrier (Doppler) wipeoff and code wipeoff at
/// the given acquisition estimates. The real part carries the BPSK nav-bit sign.
///
/// Returns an empty series if the PRN is invalid, the block is empty, or fewer
/// than one full code period is present. Total: never panics, never indexes
/// out of range.
#[must_use]
pub fn correlate_prompts(
    block: &SampleBlock,
    prn: u8,
    code_phase_chips: f64,
    doppler_hz: f64,
) -> Vec<f32> {
    let code = match gold::generate_ca_code(prn) {
        Some(c) => c,
        None => return Vec::new(),
    };
    let fs = block.sample_rate;
    if fs <= 0.0 || block.samples.is_empty() {
        return Vec::new();
    }

    let samples_per_chip = fs / CA_CHIP_RATE;
    if samples_per_chip <= 0.0 {
        return Vec::new();
    }
    // Samples in one 1 ms code period.
    let period_samples = (samples_per_chip * CA_CODE_LEN as f64).round() as usize;
    if period_samples == 0 {
        return Vec::new();
    }

    let n_periods = block.samples.len() / period_samples;
    let mut prompts = Vec::with_capacity(n_periods);

    // Sample offset of the acquired code phase, applied within each period.
    let phase_off = (code_phase_chips * samples_per_chip).round() as i64;

    for p in 0..n_periods {
        let base = p * period_samples;
        let mut acc = Complex::<f64>::new(0.0, 0.0);
        for i in 0..period_samples {
            let s = match block.samples.get(base + i) {
                Some(s) => *s,
                None => break,
            };
            // Carrier wipeoff at the acquired Doppler.
            let t = (base + i) as f64 / fs;
            let phase = -2.0 * std::f64::consts::PI * doppler_hz * t;
            let carrier = Complex::new(phase.cos(), phase.sin());
            // Code replica chip for this in-period sample (with acquired phase).
            let chip_pos = (i as i64 + phase_off).rem_euclid(period_samples as i64);
            let chip_idx = ((chip_pos as f64 / samples_per_chip) as usize) % CA_CODE_LEN;
            let chip = code.get(chip_idx).copied().unwrap_or(1) as f64;
            let s64 = Complex::new(s.re as f64, s.im as f64);
            acc += s64 * carrier * chip;
        }
        prompts.push(acc.re as f32);
    }

    prompts
}

/// Estimate the bit-edge phase (0..`PERIODS_PER_BIT`) from a prompt series by
/// choosing the alignment that maximizes total in-bit coherent energy. Within a
/// correctly-aligned 20-period window the prompts add constructively; a
/// misaligned window straddles a data-bit transition and partially cancels.
///
/// Returns `None` if there are not at least two full bits of prompts (an edge
/// is not observable from less).
#[must_use]
pub fn estimate_bit_phase(prompts: &[f32]) -> Option<usize> {
    if prompts.len() < 2 * PERIODS_PER_BIT {
        return None;
    }

    let mut best_phase = 0usize;
    let mut best_energy = f64::NEG_INFINITY;

    for phase in 0..PERIODS_PER_BIT {
        let mut energy = 0.0_f64;
        let mut idx = phase;
        while idx + PERIODS_PER_BIT <= prompts.len() {
            let mut sum = 0.0_f64;
            for k in 0..PERIODS_PER_BIT {
                sum += *prompts.get(idx + k).unwrap_or(&0.0) as f64;
            }
            energy += sum * sum; // coherent power of this bit window
            idx += PERIODS_PER_BIT;
        }
        if energy > best_energy {
            best_energy = energy;
            best_phase = phase;
        }
    }

    Some(best_phase)
}

/// Demodulate hard navigation bits from a prompt series at the given bit phase.
/// Each bit is the sign of the sum of its `PERIODS_PER_BIT` prompts (BPSK). A
/// non-negative sum → bit 1, negative → bit 0. The absolute polarity is
/// ambiguous (resolved downstream by preamble matching).
///
/// A bit window with an exactly-zero sum (no signal) is emitted as 0; such a
/// stream will simply fail to frame-sync rather than fabricate structure.
#[must_use]
pub fn demod_navbits(prompts: &[f32], bit_phase: usize) -> Vec<u8> {
    if bit_phase >= PERIODS_PER_BIT || prompts.len() < bit_phase + PERIODS_PER_BIT {
        return Vec::new();
    }
    let mut bits = Vec::new();
    let mut idx = bit_phase;
    while idx + PERIODS_PER_BIT <= prompts.len() {
        let mut sum = 0.0_f64;
        for k in 0..PERIODS_PER_BIT {
            sum += *prompts.get(idx + k).unwrap_or(&0.0) as f64;
        }
        bits.push(u8::from(sum >= 0.0));
        idx += PERIODS_PER_BIT;
    }
    bits
}

/// Locate TLM-preamble occurrences in a bit stream, in both polarities. A hit
/// is a position where the 8-bit preamble (or its inverse) matches AND a second
/// preamble of the *same* polarity appears exactly one subframe (300 bits)
/// later — the two-preamble confirmation rejects the many chance 8-bit matches
/// a raw stream throws up.
///
/// Returns hits in ascending position order. Empty when the stream is too short
/// or no confirmed preamble exists (honest absence).
#[must_use]
pub fn find_preambles(bits: &[u8]) -> Vec<PreambleHit> {
    let mut hits = Vec::new();
    if bits.len() < SUBFRAME_BITS + PREAMBLE_BITS {
        return hits;
    }

    let preamble: [u8; PREAMBLE_BITS] = {
        let mut p = [0u8; PREAMBLE_BITS];
        for (i, slot) in p.iter_mut().enumerate() {
            *slot = (TLM_PREAMBLE >> (PREAMBLE_BITS - 1 - i)) & 1;
        }
        p
    };

    let matches_at = |start: usize, inverted: bool| -> bool {
        for (i, &pb) in preamble.iter().enumerate() {
            let want = if inverted { pb ^ 1 } else { pb };
            match bits.get(start + i) {
                Some(&b) if b == want => {}
                _ => return false,
            }
        }
        true
    };

    let last_start = bits.len() - SUBFRAME_BITS - PREAMBLE_BITS;
    for start in 0..=last_start {
        for inverted in [false, true] {
            if matches_at(start, inverted) && matches_at(start + SUBFRAME_BITS, inverted) {
                hits.push(PreambleHit {
                    bit_index: start,
                    inverted,
                });
            }
        }
    }
    hits
}

/// Extract the source bits of one subframe beginning at a confirmed preamble
/// hit, de-inverting the stream polarity so the returned bits are source-true
/// (ready for [`crate::navmsg::decode_subframe`], which re-checks parity).
///
/// Returns `None` if a full subframe is not present at the hit.
#[must_use]
pub fn subframe_bits(bits: &[u8], hit: PreambleHit) -> Option<Vec<u8>> {
    let end = hit.bit_index.checked_add(SUBFRAME_BITS)?;
    let slice = bits.get(hit.bit_index..end)?;
    let out = slice
        .iter()
        .map(|&b| if hit.inverted { b ^ 1 } else { b })
        .collect();
    Some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Build a prompt series from a bit pattern: each bit becomes 20 prompts of
    /// magnitude `amp` with the bit's sign, offset by `phase` leading periods.
    fn prompts_from_bits(bits: &[i8], amp: f32, phase: usize) -> Vec<f32> {
        let mut p = vec![0.0f32; phase];
        for &b in bits {
            let v = amp * b as f32;
            for _ in 0..PERIODS_PER_BIT {
                p.push(v);
            }
        }
        p
    }

    /// Build a small IQ block: `n_periods` C/A code periods, each carrying a
    /// nav-bit sign, at a low sample rate (fast to correlate). PRN code aligned
    /// at code phase 0, zero Doppler.
    fn iq_block_with_bits(prn: u8, bit_signs: &[i8], fs: f64) -> SampleBlock {
        let code = gold::generate_ca_code(prn).expect("valid prn");
        let samples_per_chip = fs / CA_CHIP_RATE;
        let period_samples = (samples_per_chip * CA_CODE_LEN as f64).round() as usize;
        let mut samples = Vec::new();
        for &sign in bit_signs {
            for _ in 0..PERIODS_PER_BIT {
                for i in 0..period_samples {
                    let chip_idx = ((i as f64 / samples_per_chip) as usize) % CA_CODE_LEN;
                    let chip = code[chip_idx] as f32;
                    let v = chip * sign as f32;
                    samples.push(Complex::new(v, 0.0));
                }
            }
        }
        SampleBlock {
            samples,
            sample_rate: fs,
            center_freq: 0.0,
            truncated: false,
        }
    }

    #[test]
    fn correlate_prompts_recovers_bit_signs_from_iq() {
        // Low fs so period_samples is small: 1.023 MHz → 1000 samples/period.
        let fs = 1_023_000.0;
        let bits: Vec<i8> = [1, -1, -1, 1].to_vec();
        let block = iq_block_with_bits(5, &bits, fs);
        let prompts = correlate_prompts(&block, 5, 0.0, 0.0);
        // 4 bits × 20 periods = 80 prompts.
        assert_eq!(prompts.len(), bits.len() * PERIODS_PER_BIT);
        // Each 20-prompt window must carry the bit's sign.
        for (b, &sign) in bits.iter().enumerate() {
            let window = &prompts[b * PERIODS_PER_BIT..(b + 1) * PERIODS_PER_BIT];
            let sum: f32 = window.iter().sum();
            assert!(
                (sum > 0.0) == (sign > 0),
                "bit {b} sign mismatch: sum {sum}, sign {sign}"
            );
        }
        // And the demod chain recovers the bits end-to-end from IQ.
        let phase = estimate_bit_phase(&prompts).expect("phase");
        let navbits = demod_navbits(&prompts, phase);
        for (got, &sign) in navbits.iter().zip(bits.iter()) {
            assert_eq!(*got, u8::from(sign > 0));
        }
    }

    #[test]
    fn correlate_prompts_wrong_prn_is_uncorrelated() {
        let fs = 1_023_000.0;
        let bits: Vec<i8> = [1, 1, 1, 1].to_vec();
        let block = iq_block_with_bits(5, &bits, fs);
        // Correlate against a DIFFERENT PRN: near-zero prompts (codes orthogonal).
        let prompts = correlate_prompts(&block, 12, 0.0, 0.0);
        let signal = correlate_prompts(&block, 5, 0.0, 0.0);
        let wrong_energy: f32 = prompts.iter().map(|p| p * p).sum();
        let right_energy: f32 = signal.iter().map(|p| p * p).sum();
        assert!(
            right_energy > 10.0 * wrong_energy,
            "matched PRN energy {right_energy} must dominate mismatched {wrong_energy}"
        );
    }

    #[test]
    fn correlate_prompts_invalid_prn_empty() {
        let block = SampleBlock {
            samples: vec![Complex::new(1.0, 0.0); 1000],
            sample_rate: 1_023_000.0,
            center_freq: 0.0,
            truncated: false,
        };
        assert!(correlate_prompts(&block, 0, 0.0, 0.0).is_empty());
        assert!(correlate_prompts(&block, 33, 0.0, 0.0).is_empty());
    }

    #[test]
    fn bit_phase_recovers_known_offset() {
        let pattern: Vec<i8> = [1, -1, 1, 1, -1, -1, 1, -1, -1, 1].to_vec();
        for phase in [0usize, 3, 7, 13, 19] {
            let prompts = prompts_from_bits(&pattern, 100.0, phase);
            let est = estimate_bit_phase(&prompts).expect("enough prompts");
            assert_eq!(est, phase, "bit phase must recover offset {phase}");
        }
    }

    #[test]
    fn demod_recovers_bits_up_to_polarity() {
        let pattern: Vec<i8> = [1, -1, -1, 1, 1, -1, 1, 1, -1, 1].to_vec();
        let prompts = prompts_from_bits(&pattern, 50.0, 0);
        let bits = demod_navbits(&prompts, 0);
        assert_eq!(bits.len(), pattern.len());
        for (i, (&got, &want)) in bits.iter().zip(pattern.iter()).enumerate() {
            let want_bit = u8::from(want >= 0);
            assert_eq!(got, want_bit, "bit {i}");
        }
    }

    #[test]
    fn insufficient_prompts_no_phase() {
        assert!(estimate_bit_phase(&[1.0; 10]).is_none());
        assert!(demod_navbits(&[1.0; 5], 0).is_empty());
    }

    /// Build a full two-subframe bit stream with the TLM preamble at the start
    /// of each subframe, then confirm frame sync finds it (both polarities).
    fn stream_with_preamble(inverted: bool) -> Vec<u8> {
        let preamble = [1u8, 0, 0, 0, 1, 0, 1, 1]; // 0x8B MSB-first
        let mut bits = vec![0u8; 2 * SUBFRAME_BITS + PREAMBLE_BITS];
        for sf in 0..3 {
            let base = sf * SUBFRAME_BITS;
            if base + PREAMBLE_BITS > bits.len() {
                break;
            }
            for (i, &pb) in preamble.iter().enumerate() {
                bits[base + i] = if inverted { pb ^ 1 } else { pb };
            }
        }
        bits
    }

    #[test]
    fn frame_sync_finds_confirmed_preamble() {
        let bits = stream_with_preamble(false);
        let hits = find_preambles(&bits);
        assert!(
            hits.iter().any(|h| h.bit_index == 0 && !h.inverted),
            "must find non-inverted preamble at 0"
        );
    }

    #[test]
    fn frame_sync_finds_inverted_preamble() {
        let bits = stream_with_preamble(true);
        let hits = find_preambles(&bits);
        assert!(
            hits.iter().any(|h| h.bit_index == 0 && h.inverted),
            "must find inverted preamble at 0"
        );
    }

    #[test]
    fn no_preamble_in_zero_stream_is_empty() {
        // All-zeros: the preamble 10001011 cannot match either polarity fully
        // enough to confirm at a 300-bit repeat with real content... but an
        // all-zero stream DOES match the inverted preamble nowhere (inverted =
        // 01110100, not all-zero). Confirm honest absence.
        let bits = vec![0u8; 2 * SUBFRAME_BITS + PREAMBLE_BITS];
        let hits = find_preambles(&bits);
        assert!(hits.is_empty(), "zero stream must not confirm a preamble");
    }

    #[test]
    fn subframe_bits_de_inverts() {
        let bits = stream_with_preamble(true);
        let sf = subframe_bits(
            &bits,
            PreambleHit {
                bit_index: 0,
                inverted: true,
            },
        )
        .unwrap();
        // De-inverted preamble should read source-true 0x8B.
        assert_eq!(&sf[..PREAMBLE_BITS], &[1, 0, 0, 0, 1, 0, 1, 1]);
    }

    #[test]
    fn short_stream_frame_sync_empty() {
        assert!(find_preambles(&[1, 0, 0, 0, 1, 0, 1, 1]).is_empty());
    }
}
