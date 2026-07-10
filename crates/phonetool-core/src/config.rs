//! Shell configuration.
//!
//! Deliberately minimal in Sprint 1 — enough to place the offline data store and
//! nothing speculative. Grows as plugins need it; it does not pre-invent slots.

use std::path::PathBuf;

/// Workbench configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Path to the offline intel store. `None` = in-memory (ephemeral session).
    pub store_path: Option<PathBuf>,
}
