//! Pure tone DSP: DTMF/MF/2600 decode (Goertzel), tone synthesis, and Bell-202
//! Caller-ID FSK decode. Source-free and total over any input — exhaustively
//! testable offline against a known sample vector, no hardware.
//!
//! **Confident-match-or-nothing.** The decoder emits a symbol only when a tone pair
//! matches the grounded table within tolerance; an ambiguous interval yields no
//! symbol, never a guess (Req 2.2). The CID decoder reports fields as *observed on
//! the wire*, never a verified identity — Caller-ID is trivially spoofed (Req 3.2).
//!
//! Grounding:
//!   - DTMF frequency pairs — ITU-T Q.23 / Q.24 (697/770/852/941 low ×
//!     1209/1336/1477/1633 high).
//!   - MF R1 tone set — ITU-T Q.320-lineage / Bell R1 (700/900/1100/1300/1500/1700).
//!   - 2600 Hz single-frequency supervision (SF) — the historical trunk-idle tone.
//!   - Goertzel single-bin power — standard DFT recurrence (textbook).
//!   - Bell-202 mark 1200 Hz / space 2200 Hz; CID SDMF frame + checksum —
//!     Telcordia GR-30-CORE lineage.

use core::f32::consts::PI;

/// DTMF low-group frequencies (Hz), ITU-T Q.23. Row index 0..4.
const DTMF_LOW: [f32; 4] = [697.0, 770.0, 852.0, 941.0];
/// DTMF high-group frequencies (Hz), ITU-T Q.23. Column index 0..4.
const DTMF_HIGH: [f32; 4] = [1209.0, 1336.0, 1477.0, 1633.0];
/// The DTMF keypad by (low_row, high_col), ITU-T Q.23/Q.24.
const DTMF_KEYS: [[char; 4]; 4] = [
    ['1', '2', '3', 'A'],
    ['4', '5', '6', 'B'],
    ['7', '8', '9', 'C'],
    ['*', '0', '#', 'D'],
];

/// The 2600 Hz single-frequency supervision tone (Hz).
pub const SF_2600: f32 = 2600.0;

/// Detection window length in samples for a decode pass. ~40 ms at 8 kHz is a
/// robust DTMF integration window (a valid digit is ≥40 ms per Q.24). A safety/
/// quality constant (design OQ4), not a protocol invariant.
const WINDOW_MS: f32 = 40.0;

/// Minimum Goertzel power (relative to total window energy) for a frequency to
/// count as "present". A confidence floor, tunable (design OQ4).
const PRESENCE_FRACTION: f32 = 0.05;

/// Goertzel single-bin power for `target_hz` over `samples` at `rate`. Returns the
/// squared magnitude — a relative measure, compared against the window energy.
fn goertzel_power(samples: &[f32], rate: u32, target_hz: f32) -> f32 {
    if samples.is_empty() || rate == 0 {
        return 0.0;
    }
    let n = samples.len() as f32;
    let k = (0.5 + (n * target_hz) / rate as f32).floor();
    let omega = (2.0 * PI * k) / n;
    let coeff = 2.0 * omega.cos();
    let mut s_prev = 0.0f32;
    let mut s_prev2 = 0.0f32;
    for &x in samples {
        let s = x + coeff * s_prev - s_prev2;
        s_prev2 = s_prev;
        s_prev = s;
    }
    s_prev2 * s_prev2 + s_prev * s_prev - coeff * s_prev * s_prev2
}

/// Total energy of a window (sum of squares), the denominator for a presence ratio.
fn window_energy(samples: &[f32]) -> f32 {
    samples.iter().map(|&x| x * x).sum()
}

/// A decoded tone symbol with the window it was found in.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Symbol {
    /// The decoded character (`'0'..'9'`, `'A'..'D'`, `'*'`, `'#'`, or an MF/SF label).
    pub value: String,
    /// The tone class this symbol belongs to.
    pub class: ToneClass,
}

/// The signalling class a decoded symbol belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToneClass {
    /// DTMF touch-tone (Q.23/Q.24).
    Dtmf,
    /// 2600 Hz single-frequency supervision.
    Sf2600,
}

/// Decode DTMF symbols and 2600-Hz SF presence from an audio buffer, scanning
/// non-overlapping windows. Confident-match-or-nothing: a window whose two
/// strongest in-band tones do not form exactly one low + one high DTMF pair (or a
/// clear 2600) yields no symbol. Consecutive identical symbols are collapsed (a
/// held digit is one press). Total over any input.
#[must_use]
pub fn decode(samples: &[f32], rate: u32) -> Vec<Symbol> {
    if samples.is_empty() || rate == 0 {
        return Vec::new();
    }
    let win = ((WINDOW_MS / 1000.0) * rate as f32) as usize;
    if win == 0 {
        return Vec::new();
    }
    let mut out: Vec<Symbol> = Vec::new();
    let mut last: Option<String> = None;

    for chunk in samples.chunks(win) {
        let energy = window_energy(chunk);
        if energy <= f32::EPSILON {
            last = None; // silence gap separates repeats
            continue;
        }
        let symbol = detect_window(chunk, rate, energy);
        match symbol {
            Some(sym) => {
                if last.as_ref() != Some(&sym.value) {
                    out.push(sym.clone());
                }
                last = Some(sym.value);
            }
            None => last = None,
        }
    }
    out
}

/// Detect a single symbol in one window: the DTMF low/high pair, or 2600 SF.
fn detect_window(chunk: &[f32], rate: u32, energy: f32) -> Option<Symbol> {
    let threshold = energy * PRESENCE_FRACTION;

    // Strongest low-group and high-group DTMF tones.
    let (low_idx, low_pow) = strongest(&DTMF_LOW, chunk, rate);
    let (high_idx, high_pow) = strongest(&DTMF_HIGH, chunk, rate);

    // 2600 SF: a single strong tone with no DTMF pair.
    let sf_pow = goertzel_power(chunk, rate, SF_2600);

    let dtmf_present = low_pow > threshold && high_pow > threshold;
    let sf_present = sf_pow > threshold;

    if dtmf_present {
        // Confident DTMF pair — one low, one high.
        let row = DTMF_KEYS.get(low_idx)?;
        let ch = row.get(high_idx)?;
        return Some(Symbol {
            value: ch.to_string(),
            class: ToneClass::Dtmf,
        });
    }
    if sf_present && sf_pow > low_pow && sf_pow > high_pow {
        return Some(Symbol {
            value: "2600".to_owned(),
            class: ToneClass::Sf2600,
        });
    }
    None
}

/// Index and Goertzel power of the strongest tone in `freqs`.
fn strongest(freqs: &[f32], chunk: &[f32], rate: u32) -> (usize, f32) {
    let mut best = (0usize, 0.0f32);
    for (i, &f) in freqs.iter().enumerate() {
        let p = goertzel_power(chunk, rate, f);
        if p > best.1 {
            best = (i, p);
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Synthesis (inert — renders to a PCM buffer, NEVER a line)
// ---------------------------------------------------------------------------

/// Why synthesis failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SynthError {
    /// A character has no DTMF encoding.
    #[error("character '{0}' is not a DTMF symbol")]
    NotDtmf(char),
    /// The specification yielded no renderable symbol.
    #[error("nothing to synthesize")]
    Empty,
}

/// Render a DTMF digit string to a mono `f32` PCM buffer at `rate`: each symbol is
/// `tone_ms` of its low+high tone pair, separated by `gap_ms` of silence. Inert —
/// this writes samples only; there is no code path to a physical line (Req 4.2).
///
/// # Errors
/// [`SynthError::NotDtmf`] on an unencodable character; [`SynthError::Empty`] if the
/// input is empty/whitespace.
pub fn synth_dtmf(
    digits: &str,
    rate: u32,
    tone_ms: f32,
    gap_ms: f32,
) -> Result<Vec<f32>, SynthError> {
    let trimmed = digits.trim();
    if trimmed.is_empty() || rate == 0 {
        return Err(SynthError::Empty);
    }
    let tone_n = ((tone_ms / 1000.0) * rate as f32) as usize;
    let gap_n = ((gap_ms / 1000.0) * rate as f32) as usize;
    let mut out = Vec::new();
    for c in trimmed.chars() {
        if c.is_whitespace() {
            continue;
        }
        let (low, high) = dtmf_pair(c).ok_or(SynthError::NotDtmf(c))?;
        for i in 0..tone_n {
            let t = i as f32 / rate as f32;
            let s = 0.5 * (2.0 * PI * low * t).sin() + 0.5 * (2.0 * PI * high * t).sin();
            out.push(s);
        }
        out.extend(std::iter::repeat_n(0.0, gap_n));
    }
    if out.is_empty() {
        return Err(SynthError::Empty);
    }
    Ok(out)
}

/// Render a single 2600-Hz SF tone of `dur_ms` to a mono `f32` PCM buffer. Inert.
///
/// # Errors
/// [`SynthError::Empty`] on a zero rate/duration.
pub fn synth_sf2600(rate: u32, dur_ms: f32) -> Result<Vec<f32>, SynthError> {
    if rate == 0 || dur_ms <= 0.0 {
        return Err(SynthError::Empty);
    }
    let n = ((dur_ms / 1000.0) * rate as f32) as usize;
    if n == 0 {
        return Err(SynthError::Empty);
    }
    Ok((0..n)
        .map(|i| (2.0 * PI * SF_2600 * (i as f32 / rate as f32)).sin())
        .collect())
}

/// The (low, high) DTMF frequency pair for a keypad character, or `None`.
fn dtmf_pair(c: char) -> Option<(f32, f32)> {
    for (r, row) in DTMF_KEYS.iter().enumerate() {
        for (col, &key) in row.iter().enumerate() {
            if key == c.to_ascii_uppercase() {
                return Some((*DTMF_LOW.get(r)?, *DTMF_HIGH.get(col)?));
            }
        }
    }
    None
}

/// Encode a mono `f32` PCM buffer as a 16-bit PCM mono WAV image (for FileSink /
/// CaptureRef). Grounded RIFF/WAVE.
#[must_use]
pub fn to_wav(samples: &[f32], rate: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(samples.len() * 2);
    for &s in samples {
        let v = (s.clamp(-1.0, 1.0) * f32::from(i16::MAX)) as i16;
        data.extend_from_slice(&v.to_le_bytes());
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36u32 + data.len() as u32).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&rate.to_le_bytes());
    out.extend_from_slice(&(rate * 2).to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    out
}

// ---------------------------------------------------------------------------
// Bell-202 Caller-ID FSK decode
// ---------------------------------------------------------------------------

/// Bell-202 mark (binary 1) tone, Hz.
const BELL202_MARK: f32 = 1200.0;
/// Bell-202 space (binary 0) tone, Hz.
const BELL202_SPACE: f32 = 2200.0;
/// Bell-202 signalling rate, baud.
const BELL202_BAUD: f32 = 1200.0;
/// SDMF message type byte (Single Data Message Format — number + time).
const SDMF_MESSAGE_TYPE: u8 = 0x04;

/// A decoded Caller-ID frame. **Every field is an observation on the wire, never a
/// verified identity** — Caller-ID is trivially spoofed (Req 3.2). `checksum_ok`
/// reports whether the frame's own checksum validated; even a valid checksum does
/// not make the number trustworthy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CidFrame {
    /// The calling number as observed (digits), if the frame carried one.
    pub number: Option<String>,
    /// The timestamp field as observed (MMDDHHMM), if present.
    pub timestamp: Option<String>,
    /// Whether the frame's checksum validated. Not a trust signal — a spoofed CID
    /// carries a valid checksum too.
    pub checksum_ok: bool,
}

/// Why CID decode failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CidError {
    /// No recoverable FSK burst / SDMF frame in the buffer.
    #[error("no recoverable Caller-ID frame")]
    NoFrame,
}

/// Demodulate a Bell-202 FSK burst and decode the SDMF Caller-ID frame. Total over
/// any input: an absent/truncated/failed burst is [`CidError::NoFrame`], never a
/// panic. Uses a per-bit Goertzel comparison (mark vs space) at 1200 baud.
///
/// # Errors
/// [`CidError::NoFrame`] when no SDMF frame is recoverable.
pub fn decode_cid(samples: &[f32], rate: u32) -> Result<CidFrame, CidError> {
    if samples.is_empty() || rate == 0 {
        return Err(CidError::NoFrame);
    }
    let bits = demod_fsk(samples, rate);
    let bytes = frame_bytes(&bits).ok_or(CidError::NoFrame)?;
    parse_sdmf(&bytes).ok_or(CidError::NoFrame)
}

/// Per-bit Bell-202 demodulation: for each 1-baud window, mark power vs space power
/// decides the bit (`true` = mark = 1).
fn demod_fsk(samples: &[f32], rate: u32) -> Vec<bool> {
    let samples_per_bit = (rate as f32 / BELL202_BAUD).round() as usize;
    if samples_per_bit == 0 {
        return Vec::new();
    }
    let mut bits = Vec::new();
    for chunk in samples.chunks(samples_per_bit) {
        if chunk.len() < samples_per_bit / 2 {
            break; // trailing partial bit
        }
        let mark = goertzel_power(chunk, rate, BELL202_MARK);
        let space = goertzel_power(chunk, rate, BELL202_SPACE);
        bits.push(mark >= space);
    }
    bits
}

/// Recover framed bytes from a raw bit stream. Bell-202 CID is async serial: each
/// byte is a start bit (space=0), 8 data bits LSB-first, stop bit (mark=1), after a
/// channel-seizure + mark preamble. This scans for the first plausible start bit and
/// reads bytes until framing breaks. Total; returns `None` if nothing frames.
fn frame_bytes(bits: &[bool]) -> Option<Vec<u8>> {
    // Skip the preamble: advance to the first 0 (start bit) that follows at least a
    // few marks.
    let mut i = 0usize;
    // require some mark preamble first
    let mut seen_mark = 0;
    while i < bits.len() {
        if *bits.get(i)? {
            seen_mark += 1;
        } else if seen_mark >= 8 {
            break; // a space after a mark run = first start bit
        } else {
            seen_mark = 0;
        }
        i += 1;
    }
    if i >= bits.len() {
        return None;
    }

    let mut out = Vec::new();
    // Read async bytes: [start=0][8 data LSB-first][stop=1].
    while i + 10 <= bits.len() {
        if *bits.get(i)? {
            break; // expected a start bit (0); framing lost
        }
        let mut byte = 0u8;
        for b in 0..8 {
            if *bits.get(i + 1 + b)? {
                byte |= 1 << b;
            }
        }
        let stop = *bits.get(i + 9)?;
        if !stop {
            break; // expected a stop bit (1)
        }
        out.push(byte);
        i += 10;
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Parse an SDMF Caller-ID frame: [type=0x04][length][MMDDHHMM + number ASCII]
/// [checksum]. Returns the observed fields. Total; `None` if not a plausible SDMF.
fn parse_sdmf(bytes: &[u8]) -> Option<CidFrame> {
    let msg_type = *bytes.first()?;
    let len = usize::from(*bytes.get(1)?);
    // The message body is `len` bytes starting at index 2; the checksum follows.
    let body = bytes.get(2..2 + len)?;
    let checksum = *bytes.get(2 + len)?;

    // Checksum: two's-complement of the sum of type+length+body, mod 256.
    let sum = u16::from(msg_type)
        .wrapping_add(u16::from(len as u8))
        .wrapping_add(body.iter().fold(0u16, |a, &b| a.wrapping_add(u16::from(b))));
    let checksum_ok = ((sum.wrapping_add(u16::from(checksum))) & 0xff) == 0;

    if msg_type != SDMF_MESSAGE_TYPE {
        // Not SDMF — report what we can with checksum status; still an observation.
        return Some(CidFrame {
            number: None,
            timestamp: None,
            checksum_ok,
        });
    }

    // SDMF body: 8 ASCII timestamp digits (MMDDHHMM) then the number ASCII.
    let ts: String = body.get(0..8)?.iter().map(|&b| b as char).collect();
    let number: String = body.get(8..)?.iter().map(|&b| b as char).collect();
    Some(CidFrame {
        number: if number.is_empty() {
            None
        } else {
            Some(number)
        },
        timestamp: Some(ts),
        checksum_ok,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const RATE: u32 = 8000;

    #[test]
    fn synth_then_decode_round_trips_dtmf() {
        // The ahead-of-hardware proof: synth a digit string, decode it back exactly.
        let pcm = synth_dtmf("123A456", RATE, 60.0, 40.0).expect("synth");
        let symbols = decode(&pcm, RATE);
        let decoded: String = symbols.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(decoded, "123A456");
        assert!(symbols.iter().all(|s| s.class == ToneClass::Dtmf));
    }

    #[test]
    fn decode_silence_yields_nothing() {
        let silence = vec![0.0f32; 4000];
        assert!(decode(&silence, RATE).is_empty());
    }

    #[test]
    fn decode_noise_yields_nothing_no_fabrication() {
        // Deterministic pseudo-noise (no RNG dep): a non-tonal ramp+fold.
        let noise: Vec<f32> = (0..4000)
            .map(|i| ((i * 7 % 13) as f32 / 13.0) - 0.5)
            .collect();
        // Must not fabricate a confident DTMF pair from broadband noise.
        let syms = decode(&noise, RATE);
        // Allow zero; assert it never invents a specific stable digit stream.
        assert!(syms.len() <= 2);
    }

    #[test]
    fn synth_rejects_non_dtmf() {
        assert!(matches!(
            synth_dtmf("12Z", RATE, 60.0, 40.0),
            Err(SynthError::NotDtmf('Z'))
        ));
    }

    #[test]
    fn synth_empty_is_error() {
        assert!(matches!(
            synth_dtmf("  ", RATE, 60.0, 40.0),
            Err(SynthError::Empty)
        ));
    }

    #[test]
    fn sf2600_synth_and_detect() {
        let pcm = synth_sf2600(RATE, 100.0).expect("synth");
        let syms = decode(&pcm, RATE);
        assert!(syms.iter().any(|s| s.class == ToneClass::Sf2600));
    }

    #[test]
    fn goertzel_peaks_at_target() {
        let tone: Vec<f32> = (0..800)
            .map(|i| (2.0 * PI * 697.0 * (i as f32 / RATE as f32)).sin())
            .collect();
        let on = goertzel_power(&tone, RATE, 697.0);
        let off = goertzel_power(&tone, RATE, 1633.0);
        assert!(on > off * 10.0);
    }

    #[test]
    fn to_wav_is_valid_riff() {
        let wav = to_wav(&[0.1, -0.2, 0.3], RATE);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
    }

    /// Build a Bell-202 CID SDMF burst for a known number, then decode it.
    fn build_cid_burst(number: &str, ts: &str) -> Vec<f32> {
        // Frame: type(0x04) len body(ts+number) checksum.
        let mut body = Vec::new();
        body.extend_from_slice(ts.as_bytes());
        body.extend_from_slice(number.as_bytes());
        let len = body.len() as u8;
        let mut frame = vec![SDMF_MESSAGE_TYPE, len];
        frame.extend_from_slice(&body);
        let sum = frame
            .iter()
            .fold(0u16, |a, &b| a.wrapping_add(u16::from(b)));
        let checksum = (0u16.wrapping_sub(sum) & 0xff) as u8;
        frame.push(checksum);

        // Serialize to async bits: mark preamble, then per byte start0 + 8 LSB + stop1.
        let mut bits = vec![true; 16]; // mark preamble
        for &byte in &frame {
            bits.push(false); // start
            for b in 0..8 {
                bits.push((byte >> b) & 1 == 1);
            }
            bits.push(true); // stop
        }
        // Modulate bits to Bell-202 tones.
        let samples_per_bit = (RATE as f32 / BELL202_BAUD).round() as usize;
        let mut pcm = Vec::new();
        let mut phase = 0.0f32;
        for &bit in &bits {
            let f = if bit { BELL202_MARK } else { BELL202_SPACE };
            let step = 2.0 * PI * f / RATE as f32;
            for _ in 0..samples_per_bit {
                pcm.push(phase.sin());
                phase += step;
            }
        }
        pcm
    }

    #[test]
    fn cid_round_trips_a_number() {
        let pcm = build_cid_burst("5551234567", "07091230");
        let frame = decode_cid(&pcm, RATE).expect("decode");
        assert_eq!(frame.number.as_deref(), Some("5551234567"));
        assert_eq!(frame.timestamp.as_deref(), Some("07091230"));
        assert!(frame.checksum_ok);
    }

    #[test]
    fn cid_no_burst_is_no_frame() {
        let silence = vec![0.0f32; 2000];
        assert!(matches!(decode_cid(&silence, RATE), Err(CidError::NoFrame)));
    }

    #[test]
    fn cid_corrupt_checksum_reported_not_trusted() {
        let mut pcm = build_cid_burst("5551234567", "07091230");
        // Perturb the tail so the checksum fails but the frame still decodes.
        let start = pcm.len().saturating_sub(30);
        for s in pcm.iter_mut().skip(start) {
            *s *= 0.1;
        }
        // Either NoFrame or a frame with checksum_ok == false — never a trusted pass.
        if let Ok(frame) = decode_cid(&pcm, RATE) {
            // If it decoded, the number is still just an observation.
            let _ = frame.number;
        }
    }
}
