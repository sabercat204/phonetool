//! Modulation classification types.

use serde::Serialize;

/// The modulation family of a detected signal. Returns `Unknown` rather than
/// guessing — a technically-correct-but-useless label is not a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Modulation {
    /// Frequency modulation (broadcast FM, narrow FM).
    Fm,
    /// Amplitude modulation.
    Am,
    /// Single sideband (USB/LSB).
    Ssb,
    /// A digital mode (protocol-specific decode not in scope this sprint).
    Digital,
    /// Cannot confidently classify — returned rather than fabricating a label.
    Unknown,
}
