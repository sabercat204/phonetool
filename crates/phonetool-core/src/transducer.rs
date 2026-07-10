//! What physical/logical port a plugin needs from the bench.
//!
//! The device *is* the workbench; the "ports" are its capability. A plugin
//! declares the transducer it requires, and the [`PluginRegistry`] indexes by it
//! so the shell can arbitrate access to shared hardware (one SDR, one wireline
//! tap) rather than letting two plugins grab the same antenna at once.
//!
//! [`Registry`]: crate::registry::PluginRegistry

use serde::Serialize;

/// A port/medium a plugin binds to. RF splits RX from TX because they gate
/// differently (RX is near-universally legal; TX is regulated — see the auth
/// gate's Axis B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Transducer {
    /// IP networking (SIP/VoIP, HTTP lookups). numintel's port.
    Ip,
    /// Wireline / physical loop tap (butt-set, tone gen, loop-current sensing).
    Wireline,
    /// SDR receive path (RTL-SDR and up). Observation; never gated.
    RfRx,
    /// SDR transmit path (HackRF/LimeSDR). Regulated — Axis B of the gate.
    RfTx,
    /// The local data layer only (cache reads, offline intel DB). No external port.
    Store,
}

/// The authorization class a plugin's operations fall under, declared in its
/// manifest so the shell knows — before dispatch — whether the plugin can run on
/// the recon path alone or will demand a gate token.
///
/// Mirrors the payload-carrying `Capability` in `phonetool-authgate` as a
/// lightweight, payload-free label suitable for a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum CapabilityClass {
    /// Observation / RX / knowledge. Never gated.
    Passive,
    /// Axis A — active IP operations (require a `Grant`).
    ActiveIp,
    /// Axis B — RF transmission (requires a `TxGrant`).
    RfTx,
    /// Axis C — active physical-wireline operations (require a `WireGrant`).
    ActiveWire,
}
