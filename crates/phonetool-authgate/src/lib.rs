//! `phonetool-authgate` — the spine of the workbench.
//!
//! phonetool is dual-use: the legal/illegal line in telecom tooling is defined by
//! **authorization and target scope, not by code**. This crate makes that line a
//! compile-time property. Active operations (IP intrusion, RF transmission) are
//! *unrepresentable* without an unforgeable token that only [`Gate`] can mint,
//! and the gate is **fail-closed** — absence of authorization is a refusal, never
//! a default-allow.
//!
//! Two orthogonal axes, because they answer to different authorities:
//! - **Axis A** ([`Grant`], via [`Gate::request_ip`]) — target-ownership /
//!   authorization. The cyber axis.
//! - **Axis B** ([`TxGrant`], via [`Gate::request_tx`]) — band / power / license.
//!   The regulatory (FCC/ISED) axis. Illegal transmission is not cybercrime; it
//!   is a distinct wrong, so it carries a distinct token.
//!
//! The **Passive** path (numintel, RX, knowledge) never constructs a gate: it is
//! observation-coded, clean under the operator's credo, and carries no friction
//! by construction. This is the code-level expression of the standing directive —
//! no illegal cybercrime except self-defense / defense of others — and of the
//! "do not narc-jump" rule: the gate reserves its friction for genuinely active
//! operations and stays out of the way of defense, recon, and knowledge.
//!
//! ## Why an active op cannot compile without authorization
//!
//! ```compile_fail
//! # use phonetool_authgate::Grant;
//! // An active op is written to require proof of authorization:
//! fn sip_enumerate(_grant: &Grant, _target: &str) { /* ... */ }
//!
//! // You cannot fabricate the proof — `Grant` has no public constructor:
//! let forged = Grant { target: "victim".into(), basis: "".into() };
//! sip_enumerate(&forged, "victim");
//! ```
//!
//! The same holds for the regulatory axis — an RF transmission cannot compile
//! without a `TxGrant`, whose fields are private and which has no public
//! constructor:
//!
//! ```compile_fail
//! # use phonetool_authgate::TxGrant;
//! // A transmit op requires proof of a band/power/license authorization:
//! fn transmit(_grant: &TxGrant) { /* ... */ }
//!
//! // You cannot fabricate it — `TxGrant` has no public constructor:
//! let forged = TxGrant { band: "70cm".into(), power_dbm: 30.0, license_basis: "".into() };
//! transmit(&forged);
//! ```
//!
//! The only way to obtain a `Grant` or a `TxGrant` is through the gate, which
//! logs and may refuse. The Passive path needs no such proof and calls nothing
//! here.

pub mod capability;
pub mod consent;
pub mod gate;

pub use capability::{Capability, IpAuthorization, TxAuthorization, WireAuthorization};
pub use consent::{ConsentLog, ConsentRecord, Decision, NullConsentLog};
pub use gate::{Denied, Gate, Grant, TxGrant, WireGrant};
