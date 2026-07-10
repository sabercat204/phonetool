//! The consent ledger.
//!
//! Every gate decision — grant AND refusal — appends one immutable record here.
//! The record is the accountable artifact: it captures *what* was requested,
//! *why* the operator claimed authority, and *what the gate decided*. A refusal
//! is logged as deliberately as a grant, so an attempt to run an active op
//! without authorization leaves a trace rather than vanishing.
//!
//! This trait is the seam to `phonetool-core`'s capture bus: the gate depends
//! only on this small interface, not on the shell, so the spine stays free of
//! upward dependencies. A [`NullConsentLog`] is provided for tests and for the
//! Passive-only path that never actually reaches the gate.

use crate::capability::Capability;

/// One decision the gate made. Immutable once constructed.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ConsentRecord {
    /// The operation's authorization class.
    pub capability: Capability,
    /// Whether the gate minted a token.
    pub decision: Decision,
    /// The operator's stated basis (IP `basis` / RF `license_basis`), verbatim.
    /// Empty only when the request carried none — which is itself a refusal.
    pub basis: String,
}

/// The gate's verdict on a request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Decision {
    /// A token was minted.
    Granted,
    /// The request was refused; `reason` is the human-facing cause.
    Refused { reason: String },
}

/// Sink for consent records. Implemented by the shell's capture bus.
///
/// Intentionally infallible: a logging failure must not become a reason to let
/// an unlogged active op proceed, nor to abort one already authorized. Durability
/// is the sink's concern; the gate's contract is only that it *always calls* this
/// on every decision.
pub trait ConsentLog: Send + Sync {
    /// Record one gate decision. Called for every grant and every refusal.
    fn record(&self, record: ConsentRecord);
}

/// A consent log that discards records. For tests and the Passive path.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullConsentLog;

impl ConsentLog for NullConsentLog {
    fn record(&self, _record: ConsentRecord) {}
}
