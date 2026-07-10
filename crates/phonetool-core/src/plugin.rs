//! The `Plugin` trait — the one contract every capability implements — and the
//! command/event types that cross the shell boundary.
//!
//! One trait spans both tiers of the plugin model. A **Tier-A** plugin (numintel,
//! and future IP / hardware-I/O plugins) implements this in-process, natively. A
//! future **Tier-B** plugin (GNU Radio, Osmocom, any Python capability) will
//! implement the *same* trait by proxying to a subprocess — so the registry and
//! the shell never learn which tier a plugin is. That subprocess seam, not the
//! shell's language, is the load-bearing polyglot decision; it is specified in
//! `specs/subprocess-ipc-contract/` and not built in this sprint.
//!
//! Dispatch is total: a plugin reports malformed/invalid input as an
//! [`Err(PluginError)`] value, never a panic. The whole workbench eats adversary
//! input (spoofed caller-ID, hostile HLR data, malformed SIP) and must not fall
//! over on it.

use serde::{Deserialize, Serialize};

use phonetool_authgate::{Grant, TxGrant, WireGrant};

use crate::transducer::{CapabilityClass, Transducer};

/// A plugin's self-description, read by the registry at registration time.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Manifest {
    /// Unique plugin name (the registry key, and the CLI subcommand).
    pub name: String,
    /// Plugin semver, independent of the workbench version.
    pub version: String,
    /// The port/medium this plugin binds to. The registry arbitrates by it.
    pub transducer: Transducer,
    /// The authorization class of this plugin's operations. `Passive` here is a
    /// promise, enforced by the fact that a passive plugin is handed no gate.
    pub capability: CapabilityClass,
    /// One-line human description for `phonetool plugins`.
    pub summary: String,
}

/// A command dispatched to a plugin. Free-form key/value args keep the trait
/// stable as plugins grow; each plugin validates its own args (at the boundary).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Command {
    /// The verb (e.g. "lookup").
    pub verb: String,
    /// Positional/primary argument (e.g. the number to look up).
    pub arg: String,
}

/// What a plugin emits: a normalized, serializable result plus a human summary.
/// The shell records this to the capture bus and renders `summary` to the CLI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// The plugin that produced this event.
    pub source: String,
    /// One-line human-readable outcome.
    pub summary: String,
    /// Structured payload (plugin-defined shape).
    pub data: serde_json::Value,
}

/// A plugin failure. Malformed input and empty/useless results are **errors**,
/// not silent successes — a technically-correct-but-useless lookup must fail.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// The command's argument failed boundary validation.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The command's verb is not handled by this plugin.
    #[error("unsupported command: {0}")]
    Unsupported(String),
    /// The operation produced no usable result (e.g. empty lookup). A refusal,
    /// not a success — see the degenerate-case discipline.
    #[error("no usable result: {0}")]
    Empty(String),
    /// A backing store or I/O failure.
    #[error("backend error: {0}")]
    Backend(String),
}

/// The contract every capability implements. Object-safe: the registry holds
/// `Arc<dyn Plugin>` and dispatches through a vtable (zero-cost, statically
/// linked for Tier-A).
pub trait Plugin: Send + Sync {
    /// This plugin's manifest. Cheap; may be called repeatedly.
    fn manifest(&self) -> Manifest;

    /// Execute one command. Total over its input — reports bad input as an
    /// [`Err`], never a panic.
    ///
    /// # Errors
    /// Returns [`PluginError`] for invalid input, unsupported verbs, empty
    /// results, or backend failures.
    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError>;
}

/// The contract for a plugin that performs an **active** (Axis-A / IP) operation
/// against a remote it does not own by default.
///
/// The gate's compile-time guarantee is carried into the plugin layer here:
/// [`dispatch_active`](ActivePlugin::dispatch_active) takes a `&Grant`, and a
/// `Grant` has no public constructor — the only source is a successful
/// [`Gate::request_ip`](phonetool_authgate::Gate::request_ip). So an active
/// operation is *unrepresentable* without the gate having authorized it, the same
/// property the gate itself has, now extended one layer out.
///
/// **The target lives in the `Grant`, not the [`Command`].** An `ActivePlugin`
/// reads [`Grant::target`](phonetool_authgate::Grant::target) for the remote it
/// may touch, so it physically cannot act against anything the gate did not
/// authorize — the command carries the *operation's* parameters (which extensions,
/// what timeout), never a second, unchecked target.
///
/// This is a distinct trait from [`Plugin`] on purpose: the passive recon path
/// implements only `Plugin` and never sees a `Grant`, so it carries zero
/// authorization friction, while an active capability cannot be dispatched at all
/// without one.
pub trait ActivePlugin: Send + Sync {
    /// This plugin's manifest. Its [`Manifest::capability`] must be an active
    /// class (`ActiveIp`); the registry does not gate on it, the type does.
    fn manifest(&self) -> Manifest;

    /// Execute one active operation, authorized by `grant`. Total over its input —
    /// reports bad input, an unreachable/again-hostile remote, or an empty result
    /// as an [`Err`], never a panic. The remote acted upon is
    /// [`grant.target()`](phonetool_authgate::Grant::target); `cmd` carries only
    /// the operation's own parameters.
    ///
    /// # Errors
    /// Returns [`PluginError`] for invalid input, unsupported verbs, empty
    /// results, or backend/transport failures.
    fn dispatch_active(&self, cmd: &Command, grant: &Grant) -> Result<Event, PluginError>;
}

/// The contract for a plugin that performs an **RF transmission** (Axis B).
///
/// This is the transmit twin of [`ActivePlugin`], but it gates on a different
/// authority. Transmitting on regulated spectrum without a license is an
/// FCC/ISED offense, *not* cybercrime — a distinct wrong, so it carries a
/// distinct token. [`dispatch_tx`](TxPlugin::dispatch_tx) takes a `&TxGrant`
/// (band / power / license), which has no public constructor: the only source is
/// a successful [`Gate::request_tx`](phonetool_authgate::Gate::request_tx). An RF
/// transmission is therefore *unrepresentable* without the regulatory gate having
/// authorized it.
///
/// **`TxGrant` and `Grant` are deliberately non-interchangeable.** A `TxPlugin`
/// takes only `&TxGrant`; it cannot be handed a cyber-authorization `&Grant`, and
/// an `ActivePlugin` cannot be handed a `&TxGrant`. "A transmit license is not an
/// intrusion authorization" is a compile-checked fact at the dispatch boundary,
/// the same property the two token types have at the mint boundary — no runtime
/// `match` on an axis tag.
///
/// The transmit parameters an op is authorized for — band, power, license basis —
/// live in the `TxGrant`, read via its accessors, never in the [`Command`]. A
/// `TxGrant` is not `Clone`/`Copy` and is minted per transmission: the plugin
/// holds `&TxGrant` for one send and cannot loop, schedule, or re-key from it.
pub trait TxPlugin: Send + Sync {
    /// This plugin's manifest. Its [`Manifest::capability`] must be
    /// [`CapabilityClass::RfTx`]; as with the active path, the type enforces the
    /// gate, not the label.
    fn manifest(&self) -> Manifest;

    /// Execute one RF transmission, authorized by `grant`. Total over its input —
    /// reports bad input, a rejected/out-of-plan transmit, or an empty result as
    /// an [`Err`], never a panic. The band/power/license acted under come from the
    /// [`TxGrant`] accessors; `cmd` carries only the operation's own parameters
    /// (waveform, payload). Performs exactly one transmit and returns.
    ///
    /// # Errors
    /// Returns [`PluginError`] for invalid input, unsupported verbs, empty
    /// results, or backend/transport failures.
    fn dispatch_tx(&self, cmd: &Command, grant: &TxGrant) -> Result<Event, PluginError>;
}

/// The contract for a plugin that performs an **active physical-wireline
/// operation** (Axis C) — loop seizure, tone/ring injection onto a live pair.
///
/// The third gate axis. Driving a copper pair the operator does not own is theft
/// of service and physical trespass on carrier plant — neither cybercrime (Axis A)
/// nor a spectrum offense (Axis B), a distinct wrong with a distinct hazard (line
/// voltage). So it carries a distinct token: [`dispatch_wire`](WirePlugin::dispatch_wire)
/// takes a `&WireGrant` (line-ID / plant basis), which has no public constructor —
/// the only source is a successful
/// [`Gate::request_wire`](phonetool_authgate::Gate::request_wire). A physical-line
/// operation is therefore *unrepresentable* without the plant gate having
/// authorized it.
///
/// **`WireGrant`, `Grant`, and `TxGrant` are deliberately non-interchangeable.** A
/// `WirePlugin` takes only `&WireGrant`; a cyber `&Grant` or a transmit `&TxGrant`
/// cannot be handed to it, and vice versa. "A cyber authorization does not
/// authorize seizing a physical loop" is a compile-checked fact at the dispatch
/// boundary — no runtime axis tag.
///
/// The line-ID an operation is authorized for lives in the `WireGrant`, read via
/// its accessor, never in the [`Command`] — the active-plugin target invariant
/// carried to the wireline case. **The token is necessary but not sufficient:** a
/// real injector additionally requires the orthogonal hardware-safety interlock,
/// which lives in the off-by-default FFI-quarantine hardware layer, not here.
pub trait WirePlugin: Send + Sync {
    /// This plugin's manifest. Its [`Manifest::capability`] must be
    /// [`CapabilityClass::Wireline`]; the type enforces the gate, not the label.
    fn manifest(&self) -> Manifest;

    /// Execute one active wireline operation, authorized by `grant`. Total over its
    /// input — reports bad input, a rejected operation, or an empty result as an
    /// [`Err`], never a panic. The line acted upon is
    /// [`grant.line_id()`](phonetool_authgate::WireGrant::line_id); `cmd` carries
    /// only the operation's own parameters.
    ///
    /// # Errors
    /// Returns [`PluginError`] for invalid input, unsupported verbs, empty results,
    /// or backend/hardware failures.
    fn dispatch_wire(&self, cmd: &Command, grant: &WireGrant) -> Result<Event, PluginError>;
}
