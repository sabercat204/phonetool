//! `phonetool-core` — the workbench shell.
//!
//! The load-bearing unit of phonetool is not any single capability but the shell
//! that hosts them: a plugin registry, an offline-first data layer, a unified
//! capture/consent bus, and config. Each telecom capability (numintel now; SIP,
//! RF, wireline later) is a [`Plugin`] that snaps into this shell.
//!
//! Two invariants define the crate:
//! - **Offline-first.** The core links no network egress. The default build is
//!   air-gapped; the [`store`] layer is the default source of truth. "Online" is
//!   a plugin-level mode (an off-by-default Cargo feature on a plugin), never a
//!   core dependency.
//! - **Closed under capability addition.** Adding a plugin is one
//!   [`PluginRegistry::register`] call; nothing in this crate changes. (The
//!   in-house registry idiom.)
//!
//! The auth gate lives in its own crate (`phonetool-authgate`) and is the spine;
//! this crate's [`CaptureBus`] is the gate's consent sink, so authorization
//! decisions and the operations they gate share one timeline.

pub mod capture;
pub mod config;
pub mod plugin;
pub mod registry;
pub mod store;
pub mod transducer;

pub use capture::{CaptureBus, CaptureKind, CaptureRecord};
pub use config::Config;
pub use plugin::{
    ActivePlugin, Command, Event, Manifest, Plugin, PluginError, TxPlugin, WirePlugin,
};
pub use registry::{DispatchError, PluginRegistry, RegisterError};
pub use store::{IntelStore, SqliteStore, StoreError};
pub use transducer::{CapabilityClass, Transducer};

// Re-export the gate surface so plugins and the CLI depend on `phonetool_core`
// for the whole workbench vocabulary rather than reaching across crates.
pub use phonetool_authgate::{
    Capability, ConsentLog, ConsentRecord, Decision, Denied, Gate, Grant, IpAuthorization,
    NullConsentLog, TxAuthorization, TxGrant, WireAuthorization, WireGrant,
};
