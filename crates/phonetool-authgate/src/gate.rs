//! The gate, and the three unforgeable tokens it mints.
//!
//! The enforcement mechanism is the type system, not a runtime flag. `Grant`
//! (Axis A), `TxGrant` (Axis B), and `WireGrant` (Axis C) have **private fields
//! and no public constructor** — the only way to obtain one is [`Gate::request_ip`]
//! / [`Gate::request_tx`] / [`Gate::request_wire`], and an active operation takes
//! `&Grant` / `&TxGrant` / `&WireGrant` as a parameter. Therefore an unauthorized
//! active op is not a bug you can commit and catch in review; it fails to compile
//! because you cannot name the token.
//!
//! The three are separate types on purpose: an IP grant can never be passed where
//! a TX grant is required, a transmit license can never authorize seizing a copper
//! pair, and so on — so "an SS7 authorization is not a transmit license, and
//! neither is a plant-ownership assertion" is enforced by the compiler. None is
//! `Clone` or `Copy` — a token is minted per authorized operation, not reused.

use crate::capability::{Capability, IpAuthorization, TxAuthorization, WireAuthorization};
use crate::consent::{ConsentLog, ConsentRecord, Decision};

/// Why the gate refused. Fail-closed: absence of evidence is a refusal, not a
/// pass, so these are the only ways past `request_*` other than a token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    /// The authorization carried no target / band.
    #[error("refused: no target/band supplied (fail-closed)")]
    NoTarget,
    /// The authorization carried no basis / license justification.
    #[error("refused: no authorization basis supplied (fail-closed)")]
    NoBasis,
    /// A field was structurally invalid (e.g. non-finite TX power).
    #[error("refused: {0}")]
    Invalid(String),
}

/// An unforgeable authorization for an **Axis A** (IP) active operation.
///
/// Construct only via [`Gate::request_ip`]. Fields are private; there is no
/// public constructor. Hold `&Grant` to prove an IP active op is authorized.
#[derive(Debug)]
pub struct Grant {
    target: String,
    basis: String,
}

impl Grant {
    /// The target this grant authorizes. Read-only.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The operator's stated basis for this grant. Read-only.
    #[must_use]
    pub fn basis(&self) -> &str {
        &self.basis
    }
}

/// An unforgeable authorization for an **Axis B** (RF TX) transmission.
///
/// Construct only via [`Gate::request_tx`]. Distinct from [`Grant`] so a cyber
/// authorization can never stand in for a transmit license.
#[derive(Debug)]
pub struct TxGrant {
    band: String,
    power_dbm: f64,
    license_basis: String,
}

impl TxGrant {
    /// The band this grant authorizes transmission on.
    #[must_use]
    pub fn band(&self) -> &str {
        &self.band
    }

    /// The authorized transmit power in dBm.
    #[must_use]
    pub fn power_dbm(&self) -> f64 {
        self.power_dbm
    }

    /// The regulatory basis for this transmission.
    #[must_use]
    pub fn license_basis(&self) -> &str {
        &self.license_basis
    }
}

/// An unforgeable authorization for an **Axis C** (physical wireline) active
/// operation — loop seizure, tone/ring injection onto a live pair.
///
/// Construct only via [`Gate::request_wire`]. Distinct from [`Grant`] and
/// [`TxGrant`] so a cyber authorization or a transmit license can never stand in
/// for physical-plant ownership: "a cyber grant does not authorize seizing a
/// physical loop" is a compiler-checked fact, the third instance of the crate's
/// distinct-wrongs-get-distinct-tokens thesis.
///
/// Holding a `WireGrant` proves *authorization*; it does NOT satisfy the
/// hardware-safety interlock that any real injection additionally requires (line
/// voltage is a physical hazard orthogonal to who owns the line). Neither the grant
/// nor the interlock satisfies the other.
#[derive(Debug)]
pub struct WireGrant {
    line_id: String,
    plant_basis: String,
}

impl WireGrant {
    /// The physical line / pair this grant authorizes driving. Read-only.
    #[must_use]
    pub fn line_id(&self) -> &str {
        &self.line_id
    }

    /// The operator's stated plant-ownership basis for this grant. Read-only.
    #[must_use]
    pub fn plant_basis(&self) -> &str {
        &self.plant_basis
    }
}

/// The authorization gate. Every active/TX operation routes through one instance.
///
/// The gate borrows a [`ConsentLog`]; it records every decision — grant and
/// refusal alike — before returning. Passive operations do not construct or
/// consult a gate at all.
pub struct Gate<'log> {
    log: &'log dyn ConsentLog,
}

impl<'log> Gate<'log> {
    /// Build a gate that records decisions to `log`.
    #[must_use]
    pub fn new(log: &'log dyn ConsentLog) -> Self {
        Self { log }
    }

    /// Request authorization for an **Axis A** (IP) active operation.
    ///
    /// Fail-closed: an empty target or empty basis is [`Denied`], logged as a
    /// refusal. On success, logs the grant and returns the only [`Grant`] the
    /// operator can obtain for this operation.
    ///
    /// # Errors
    /// Returns [`Denied`] when the authorization is absent or malformed.
    pub fn request_ip(&self, auth: IpAuthorization) -> Result<Grant, Denied> {
        let outcome = Self::validate_ip(&auth);
        self.log.record(ConsentRecord {
            capability: Capability::ActiveIp {
                target: auth.target.clone(),
            },
            decision: match &outcome {
                Ok(()) => Decision::Granted,
                Err(e) => Decision::Refused {
                    reason: e.to_string(),
                },
            },
            basis: auth.basis.clone(),
        });
        outcome.map(|()| Grant {
            target: auth.target,
            basis: auth.basis,
        })
    }

    /// Request authorization for an **Axis B** (RF TX) transmission.
    ///
    /// Fail-closed on empty band, empty license basis, or non-finite power. Logs
    /// every decision; returns the only [`TxGrant`] obtainable for this TX.
    ///
    /// # Errors
    /// Returns [`Denied`] when the authorization is absent or malformed.
    pub fn request_tx(&self, auth: TxAuthorization) -> Result<TxGrant, Denied> {
        let outcome = Self::validate_tx(&auth);
        self.log.record(ConsentRecord {
            capability: Capability::RfTx {
                band: auth.band.clone(),
                power_dbm: auth.power_dbm,
                license_basis: auth.license_basis.clone(),
            },
            decision: match &outcome {
                Ok(()) => Decision::Granted,
                Err(e) => Decision::Refused {
                    reason: e.to_string(),
                },
            },
            basis: auth.license_basis.clone(),
        });
        outcome.map(|()| TxGrant {
            band: auth.band,
            power_dbm: auth.power_dbm,
            license_basis: auth.license_basis,
        })
    }

    /// Request authorization for an **Axis C** (physical wireline) active
    /// operation.
    ///
    /// Fail-closed on an empty line-ID or empty plant basis. Logs every decision;
    /// returns the only [`WireGrant`] obtainable for this operation. The returned
    /// grant is *necessary but not sufficient* for injection — the hardware-safety
    /// interlock is an orthogonal precondition this gate does not model.
    ///
    /// # Errors
    /// Returns [`Denied`] when the authorization is absent or malformed.
    pub fn request_wire(&self, auth: WireAuthorization) -> Result<WireGrant, Denied> {
        let outcome = Self::validate_wire(&auth);
        self.log.record(ConsentRecord {
            capability: Capability::Wireline {
                line_id: auth.line_id.clone(),
            },
            decision: match &outcome {
                Ok(()) => Decision::Granted,
                Err(e) => Decision::Refused {
                    reason: e.to_string(),
                },
            },
            basis: auth.plant_basis.clone(),
        });
        outcome.map(|()| WireGrant {
            line_id: auth.line_id,
            plant_basis: auth.plant_basis,
        })
    }

    fn validate_ip(auth: &IpAuthorization) -> Result<(), Denied> {
        if auth.target.trim().is_empty() {
            return Err(Denied::NoTarget);
        }
        if auth.basis.trim().is_empty() {
            return Err(Denied::NoBasis);
        }
        Ok(())
    }

    fn validate_tx(auth: &TxAuthorization) -> Result<(), Denied> {
        if auth.band.trim().is_empty() {
            return Err(Denied::NoTarget);
        }
        if auth.license_basis.trim().is_empty() {
            return Err(Denied::NoBasis);
        }
        if !auth.power_dbm.is_finite() {
            return Err(Denied::Invalid("transmit power is not finite".to_owned()));
        }
        Ok(())
    }

    fn validate_wire(auth: &WireAuthorization) -> Result<(), Denied> {
        if auth.line_id.trim().is_empty() {
            return Err(Denied::NoTarget);
        }
        if auth.plant_basis.trim().is_empty() {
            return Err(Denied::NoBasis);
        }
        Ok(())
    }
}
