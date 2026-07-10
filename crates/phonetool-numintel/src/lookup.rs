//! The lookup itself: offline cache read (always) and the online path (feature).
//!
//! ## Threat note (the one non-air-gapped path in this plugin)
//!
//! An online lookup transmits the target number **off-box** to whatever provider
//! it queries. That provider learns who the operator is investigating, and may
//! retain or resell the query. This is the single boundary the operator's own
//! opsec cares about, so:
//! - the online path is behind an **off-by-default** Cargo feature (`online`);
//!   the default build cannot make this call at all;
//! - no provider is hardcoded into the core — the endpoint is supplied at call
//!   time, so a no-retain/no-resell source can be chosen per deployment;
//! - a successful online result **write-throughs** to the cache, so the number
//!   leaks off-box at most once.

use phonetool_core::IntelStore;

use crate::number::Number;

/// Namespace for numintel entries in the shared intel store.
pub const NAMESPACE: &str = "numintel";

/// Read a cached intelligence record for `number`, if one exists. Never touches
/// the network — this is the survival-critical, air-gapped path.
///
/// # Errors
/// Propagates a [`StoreError`](phonetool_core::StoreError) backend failure.
pub fn cached(
    store: &dyn IntelStore,
    number: &Number,
) -> Result<Option<String>, phonetool_core::StoreError> {
    store.get(NAMESPACE, number.as_e164())
}

/// Perform a live lookup against `endpoint`, write the result through to the
/// cache, and return it. Compiled only under the `online` feature.
///
/// `endpoint` is a URL template containing `{number}`, which is replaced with the
/// validated E.164 number. Supplying the endpoint at call time keeps any specific
/// provider out of the codebase (see the threat note).
///
/// # Errors
/// Returns [`OnlineError`] on a malformed endpoint, a transport failure, or a
/// non-success HTTP status.
#[cfg(feature = "online")]
pub fn online(
    store: &dyn IntelStore,
    number: &Number,
    endpoint: &str,
) -> Result<String, OnlineError> {
    let url = endpoint.replace("{number}", number.as_e164());
    // The number has already passed E.164 boundary validation, so it cannot carry
    // characters that would reshape the URL.
    let client = reqwest::blocking::Client::builder()
        .build()
        .map_err(|e| OnlineError::Transport(e.to_string()))?;
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| OnlineError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(OnlineError::Status(resp.status().as_u16()));
    }
    let body = resp
        .text()
        .map_err(|e| OnlineError::Transport(e.to_string()))?;

    // Write-through: the number leaks off-box at most once.
    store
        .put(NAMESPACE, number.as_e164(), &body)
        .map_err(|e| OnlineError::Cache(e.to_string()))?;
    Ok(body)
}

/// A failure on the online path.
#[cfg(feature = "online")]
#[derive(Debug, thiserror::Error)]
pub enum OnlineError {
    /// A network/transport-level failure.
    #[error("transport: {0}")]
    Transport(String),
    /// The provider returned a non-success status code.
    #[error("provider returned HTTP {0}")]
    Status(u16),
    /// The result could not be written to the cache.
    #[error("cache write: {0}")]
    Cache(String),
}
