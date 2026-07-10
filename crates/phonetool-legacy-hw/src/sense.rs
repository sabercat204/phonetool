//! Line electrical-state classification from a recorded sense trace.
//!
//! Classifies loop-current level, line-voltage level, ring presence, and on-hook/
//! off-hook state from a captured ADC/voltage series ([`crate::source::SampleBlock`]
//! of [`SampleKind::Sense`]). An idle, quiet line is a **real result**
//! (`Ok`); an empty/unreadable trace is a failure (handled one layer up).
//!
//! The trace convention (design OQ2 leaves exact datasheet thresholds open): the
//! sense samples are interpreted as **tip-ring voltage in volts**. The
//! classification thresholds here are **nominal/illustrative** (idle ~48 V DC,
//! off-hook a few V, ringing ~90 V AC swing) and are flagged as such — the exact
//! trip points are datasheet constants deferred to the chosen SLIC front end, not
//! authoritative values. Nothing is fabricated as a grounded figure; these are
//! classification bands for the *recorded-trace* interpretation only.

use serde::Serialize;

use crate::source::{SampleBlock, SampleKind};

/// Nominal idle (on-hook) tip-ring voltage magnitude, volts. Illustrative — the
/// real value is a datasheet constant (design OQ2).
const NOMINAL_IDLE_V: f32 = 48.0;
/// Below this magnitude the loop is drawing current (off-hook). Illustrative.
const OFFHOOK_V_CEILING: f32 = 15.0;
/// A peak-to-peak swing above this indicates ringing voltage present. Illustrative.
const RING_SWING_V: f32 = 120.0;

/// A hook state classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookState {
    /// Idle — nominal battery voltage, no loop current.
    OnHook,
    /// Seized — loop current drawn, voltage collapsed toward the off-hook level.
    OffHook,
    /// Indeterminate — the trace does not clearly match either state.
    Unknown,
}

/// The classified line state.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct LineState {
    /// The on-hook / off-hook classification.
    pub hook: HookState,
    /// Whether ringing voltage was present in the trace.
    pub ringing: bool,
    /// Mean tip-ring voltage magnitude observed (volts).
    pub mean_voltage: f32,
    /// Peak-to-peak voltage swing observed (volts) — the ring discriminator.
    pub pk_pk: f32,
    /// `true` when the line was idle and quiet — a real, reportable observation
    /// distinct from a useless run.
    pub idle: bool,
}

/// Classify a sense trace into a [`LineState`]. Total; returns `None` only for a
/// non-sense block (the caller supplies a sense block).
#[must_use]
pub fn classify(block: &SampleBlock) -> Option<LineState> {
    if block.kind != SampleKind::Sense || block.samples.is_empty() {
        return None;
    }
    let n = block.samples.len() as f32;
    let mean: f32 = block.samples.iter().map(|v| v.abs()).sum::<f32>() / n;
    let (mut lo, mut hi) = (f32::INFINITY, f32::NEG_INFINITY);
    for &v in &block.samples {
        lo = lo.min(v);
        hi = hi.max(v);
    }
    let pk_pk = hi - lo;

    let ringing = pk_pk >= RING_SWING_V;
    let hook = if ringing {
        // During ring the line is on-hook (ringing is applied to an idle loop).
        HookState::OnHook
    } else if mean <= OFFHOOK_V_CEILING {
        HookState::OffHook
    } else if mean >= NOMINAL_IDLE_V * 0.5 {
        HookState::OnHook
    } else {
        HookState::Unknown
    };

    let idle = matches!(hook, HookState::OnHook) && !ringing;
    Some(LineState {
        hook,
        ringing,
        mean_voltage: mean,
        pk_pk,
        idle,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sense(samples: Vec<f32>) -> SampleBlock {
        SampleBlock {
            kind: SampleKind::Sense,
            sample_rate: 100,
            samples,
            truncated: false,
        }
    }

    #[test]
    fn idle_line_classified_onhook() {
        let st = classify(&sense(vec![48.0; 50])).expect("sense");
        assert_eq!(st.hook, HookState::OnHook);
        assert!(!st.ringing);
        assert!(st.idle);
    }

    #[test]
    fn offhook_line_low_voltage() {
        let st = classify(&sense(vec![7.0; 50])).expect("sense");
        assert_eq!(st.hook, HookState::OffHook);
        assert!(!st.idle);
    }

    #[test]
    fn ringing_detected_by_swing() {
        // A ~90 V AC ring: alternate +90 / -90.
        let ring: Vec<f32> = (0..100)
            .map(|i| if i % 2 == 0 { 90.0 } else { -90.0 })
            .collect();
        let st = classify(&sense(ring)).expect("sense");
        assert!(st.ringing);
        assert!(st.pk_pk >= RING_SWING_V);
        assert!(!st.idle); // ringing is not an idle line
    }

    #[test]
    fn non_sense_block_is_none() {
        let audio = SampleBlock {
            kind: SampleKind::Audio,
            sample_rate: 8000,
            samples: vec![0.1, 0.2],
            truncated: false,
        };
        assert!(classify(&audio).is_none());
    }
}
