//! 5G NR broadcast decode — **declared seam, not built this sprint.**
//!
//! Same honest gap as `decode_lte`, one generation on:
//!   * **PCI** and **GSCN** are physical-layer quantities from SSB
//!     (PSS/SSS/PBCH) correlation, not packet bytes.
//!   * **PLMN** and **TAC** live in **SIB1**, ASN.1 **UPER**-encoded under a
//!     *different* schema (3GPP TS 38.331). And per Open Question 3, no recorded
//!     NR source format is decided, and Open Question 8 leaves SA-vs-NSA and
//!     FR1-vs-FR2 scope open.
//!
//! Rather than fabricate a UPER decoder or a scope decision, this module ships
//! the **`NrCell` type and the decode boundary only**; `decode` returns [`None`].
//! `cellmap`/`detect` consume `NrCell` unchanged when the real decoder (grounded,
//! or Tier-B via srsRAN) lands.

use crate::source::Segment;

/// A decoded 5G NR cell. All fields optional (PHY vs. SIB1 origin), populated by
/// the future decoder.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NrCell {
    /// Physical Cell Identity (0..1007), from SSB correlation.
    pub pci: Option<u16>,
    /// Global Synchronization Channel Number (SSB frequency index).
    pub gscn: Option<u32>,
    /// PLMN as (MCC, MNC, mnc_digits), from SIB1.
    pub plmn: Option<(u16, u16, u8)>,
    /// Tracking Area Code, from SIB1.
    pub tac: Option<u32>,
}

/// Decode a 5G NR broadcast segment. **Always `None` this sprint** — unbuilt
/// (SIB1 is ASN.1 UPER; OQ3/OQ8 unresolved). Present for exhaustive RAT dispatch.
#[must_use]
pub fn decode(_segment: &Segment) -> Option<NrCell> {
    None
}
