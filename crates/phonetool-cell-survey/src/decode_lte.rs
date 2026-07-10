//! LTE broadcast decode — **declared seam, not built this sprint.**
//!
//! An `LteCell`'s identity fields split across two very different layers:
//!   * **PCI** and **EARFCN** are physical-layer quantities recovered by
//!     correlating the PSS/SSS synchronization signals against the received IQ —
//!     they are not bytes in a message and cannot be decoded from a packet dump.
//!   * **PLMN**, **TAC**, and the operating band live in **SIB1**, which is
//!     ASN.1 **UPER**-encoded (3GPP TS 36.331). A bit-exact UPER decoder is a
//!     substantial, error-prone artifact, and — per the spec's Open Question 3 —
//!     **no recorded LTE source format has been decided** to prove such a decoder
//!     against before hardware exists.
//!
//! Hand-rolling UPER from memory is exactly the constant/format confabulation the
//! project forbids (a plausible-looking wrong offset is worse than an honest
//! gap). So this module ships the **`LteCell` type and the decode boundary
//! only**; `decode` returns [`None`] (a decode miss) until (a) OQ3 fixes a
//! recorded LTE source and (b) a grounded UPER path or a Tier-B decoder is built.
//! When it lands, `cellmap`/`detect` consume `LteCell` unchanged.

use crate::source::Segment;

/// A decoded LTE cell. Fields are optional because they arrive from different
/// layers (PHY sync vs. SIB1) and any may be absent. Populated by the future
/// decoder; the type is fixed now so downstream modules are RAT-complete.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LteCell {
    /// Physical Cell Identity (0..503), from PSS/SSS correlation.
    pub pci: Option<u16>,
    /// E-UTRA Absolute Radio Frequency Channel Number.
    pub earfcn: Option<u32>,
    /// Tracking Area Code, from SIB1.
    pub tac: Option<u32>,
    /// PLMN as (MCC, MNC, mnc_digits), from SIB1.
    pub plmn: Option<(u16, u16, u8)>,
    /// Operating band, from SIB1 / EARFCN mapping.
    pub band: Option<u16>,
}

/// Decode an LTE broadcast segment. **Always `None` this sprint** — the decoder
/// is unbuilt (see the module docs: SIB1 is ASN.1 UPER and OQ3 has not fixed a
/// recorded source). Present so the RAT dispatch in `lib` is exhaustive and the
/// seam is a compile-time reality, not a silent omission.
#[must_use]
pub fn decode(_segment: &Segment) -> Option<LteCell> {
    None
}
