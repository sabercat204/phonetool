//! `phonetool-numintel` — the first plugin, and the proof that the socket works.
//!
//! Number intelligence: given a phone number, return what is known about it
//! (carrier, line type, region). It exists in Sprint 1 to prove a plugin can snap
//! into the shell end-to-end, not to be complete.
//!
//! **Passive by construction.** numintel is observation/knowledge-coded — clean
//! under the operator's credo (ingestion ≠ theft) — so it declares
//! [`CapabilityClass::Passive`] and is handed no gate. It cannot perform an active
//! operation because it is never given a [`Grant`](phonetool_core::Grant); the
//! recon path carries zero authorization friction, by design.
//!
//! Offline is the default: the plugin reads the shared intel store and makes no
//! network call. The one non-air-gapped path — a live provider lookup — is behind
//! the off-by-default `online` feature (see [`lookup`]'s threat note).

pub mod lookup;
pub mod number;

use std::sync::Arc;

use phonetool_core::{
    CapabilityClass, Command, Event, IntelStore, Manifest, Plugin, PluginError, Transducer,
};

use crate::number::Number;

/// The number-intelligence plugin. Holds a handle to the shared offline store.
pub struct NumIntel {
    store: Arc<dyn IntelStore>,
}

impl NumIntel {
    /// Build the plugin over a shared intel store.
    #[must_use]
    pub fn new(store: Arc<dyn IntelStore>) -> Self {
        Self { store }
    }
}

impl Plugin for NumIntel {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "numintel".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::Ip,
            capability: CapabilityClass::Passive,
            summary: "number intelligence — carrier/line-type/region lookup (offline cache; online opt-in)".to_owned(),
        }
    }

    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError> {
        if cmd.verb != "lookup" {
            return Err(PluginError::Unsupported(cmd.verb.clone()));
        }

        // Boundary validation: constrain untrusted input to canonical E.164
        // before it can reach a cache key (or, under `online`, a URL).
        let number =
            Number::parse(&cmd.arg).map_err(|e| PluginError::InvalidInput(e.to_string()))?;

        let cached = lookup::cached(self.store.as_ref(), &number)
            .map_err(|e| PluginError::Backend(e.to_string()))?;

        // Degenerate-case discipline: a miss is a *failure*, not an empty success.
        // A technically-correct-but-useless "found nothing" must not pass as OK.
        let Some(record) = cached else {
            return Err(PluginError::Empty(format!(
                "no cached intelligence for {} (offline); enable `online` to query a provider",
                number.as_e164()
            )));
        };

        let data: serde_json::Value = serde_json::from_str(&record)
            .unwrap_or_else(|_| serde_json::Value::String(record.clone()));
        Ok(Event {
            source: "numintel".to_owned(),
            summary: format!("cached intelligence for {}", number.as_e164()),
            data,
        })
    }
}
