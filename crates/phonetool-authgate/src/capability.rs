//! What an operation *is*, and the evidence an operator supplies to authorize it.
//!
//! Two orthogonal axes, deliberately distinct because they answer to different
//! authorities:
//!
//! - **Axis A — `ActiveIp`**: target-ownership / authorization. The cyber axis.
//!   SIP enum, wardial origination, signalling injection against a remote.
//! - **Axis B — `RfTx`**: band / power / license. A *regulatory* (FCC/ISED) axis.
//!   Transmitting on licensed spectrum without authority is a regulatory offense,
//!   not cybercrime — a different wrong, so a different axis and a different token.
//! - **Axis C — `Wireline`**: physical-plant ownership over a copper line/pair. A
//!   *plant* axis. Driving a tip-and-ring pair the operator does not own is theft
//!   of service and physical trespass — neither cybercrime (Axis A) nor a spectrum
//!   offense (Axis B), a third distinct wrong, so a third distinct token.
//!
//! `Passive` (numintel, RX, knowledge) is on neither axis: it never touches the
//! gate. Observation is not theft (operator credo), so the recon path carries no
//! friction by construction.

use serde::Serialize;

/// A description of an operation's authorization class, used for logging and
/// human-facing display. This is the *label*; the enforced capability is the
/// token type ([`crate::Grant`] / [`crate::TxGrant`]) the gate mints, not this.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Capability {
    /// Observation / RX / knowledge. Never gated; routes around the gate.
    Passive,
    /// Axis A — an active IP operation against `target`.
    ActiveIp { target: String },
    /// Axis B — an RF transmission on `band` at `power_dbm`, under `license_basis`.
    RfTx {
        band: String,
        power_dbm: f64,
        license_basis: String,
    },
    /// Axis C — an active physical-line operation on `line_id`, under `plant_basis`.
    Wireline { line_id: String },
}

/// Operator-supplied evidence to authorize an **Axis A** (IP) active operation.
///
/// Both fields are load-bearing and validated fail-closed: an empty `target` or
/// an empty `basis` is a refusal, never a silent pass. `basis` is free text on
/// purpose — it is the human's assertion of *why this is authorized* (owned
/// infrastructure, a named pentest engagement, self-defense) and lands verbatim
/// in the consent log as the accountable record of intent.
#[derive(Debug, Clone)]
pub struct IpAuthorization {
    /// The remote this operation will touch (host, number, extension range).
    pub target: String,
    /// Why the operator asserts this is authorized. Logged verbatim.
    pub basis: String,
}

/// Operator-supplied evidence to authorize an **Axis B** (RF TX) transmission.
///
/// `band` and `license_basis` are validated fail-closed. `license_basis` is the
/// regulatory justification (a callsign + service, Part 97, a license-free ISM
/// allocation) — the RF analogue of `IpAuthorization::basis`, on the regulatory
/// axis rather than the cyber one.
#[derive(Debug, Clone)]
pub struct TxAuthorization {
    /// The band / allocation being transmitted on (e.g. "70cm amateur").
    pub band: String,
    /// Intended transmit power in dBm.
    pub power_dbm: f64,
    /// The regulatory basis for transmitting. Logged verbatim.
    pub license_basis: String,
}

/// Operator-supplied evidence to authorize an **Axis C** (physical wireline)
/// active operation — loop seizure, tone/ring injection onto a live pair.
///
/// `line_id` and `plant_basis` are validated fail-closed. `plant_basis` is the
/// physical-plant-ownership justification (owned line, a named lab loop, a
/// contracted engagement) — the copper analogue of `IpAuthorization::basis`, on
/// the plant axis rather than the cyber one.
///
/// **The token is necessary but not sufficient.** A future injector additionally
/// requires the orthogonal hardware-safety interlock (line voltage can injure the
/// operator or destroy the front end); neither the grant nor the interlock
/// satisfies the other. This crate mints the *authorization*; the interlock lives
/// in the hardware layer.
#[derive(Debug, Clone)]
pub struct WireAuthorization {
    /// The physical line / pair identifier this operation will drive.
    pub line_id: String,
    /// Why the operator asserts they own or may drive this plant. Logged verbatim.
    pub plant_basis: String,
}
