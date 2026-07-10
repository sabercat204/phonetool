//! The plugin registry and dispatch.
//!
//! Mirrors a prior in-house `Registry` idiom: registration is data-driven from
//! each plugin's own [`Manifest`], indexed by the [`Transducer`] it declares, so
//! **adding a capability is one `register(...)` call and changes nothing here**.
//! The shell arbitrates the shared physical hardware by that index — the bench
//! has one SDR and one wireline tap, so two plugins cannot both hold `RfTx`.

use std::collections::HashMap;
use std::sync::Arc;

use phonetool_authgate::{Grant, TxGrant, WireGrant};

use crate::plugin::{
    ActivePlugin, Command, Event, Manifest, Plugin, PluginError, TxPlugin, WirePlugin,
};
use crate::transducer::Transducer;

/// Why registration was refused. The bench arbitrates shared ports up front
/// rather than discovering a conflict mid-operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// A plugin with this name is already registered.
    #[error("duplicate plugin name: {0}")]
    DuplicateName(String),
    /// Another plugin already holds this exclusive transducer.
    #[error("transducer {0:?} already claimed by plugin '{1}'")]
    TransducerClaimed(Transducer, String),
}

/// Registry of plugins, keyed by name, with an index of which plugin holds each
/// exclusive transducer.
///
/// Passive plugins ([`Plugin`]), active IP plugins ([`ActivePlugin`]), and RF
/// transmit plugins ([`TxPlugin`]) live in three separate maps but share **one
/// name namespace and one transducer-ownership index**, so plugins of different
/// classes cannot collide on a name or fight over an exclusive port. Which map a
/// name is in decides which dispatch path is legal — and which token, if any, it
/// demands: [`dispatch`](Self::dispatch) reaches only passive plugins (no token),
/// [`dispatch_active`](Self::dispatch_active) only active ones (a `&Grant`),
/// [`dispatch_tx`](Self::dispatch_tx) only transmit ones (a `&TxGrant`). You
/// cannot run an active op through the ungated path, drive a transmit with a
/// cyber authorization, or vice versa. The three dispatch paths mirror the three
/// [`CapabilityClass`](crate::transducer::CapabilityClass) variants.
#[derive(Default, Clone)]
pub struct PluginRegistry {
    passive: HashMap<String, Arc<dyn Plugin>>,
    active: HashMap<String, Arc<dyn ActivePlugin>>,
    tx: HashMap<String, Arc<dyn TxPlugin>>,
    wire: HashMap<String, Arc<dyn WirePlugin>>,
    /// Registration order, for stable `plugins` listing (spans all four maps).
    order: Vec<String>,
    /// Exclusive-port holders. `Store`/`Ip`/`RfRx` are shareable logical media
    /// and are not tracked here; only `Wireline` and `RfTx` are.
    transducer_owner: HashMap<Transducer, String>,
}

impl PluginRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a passive plugin. Indexes it by name and, for exclusive
    /// transducers, records it as the port's owner. Adding a capability = one
    /// call here.
    ///
    /// # Errors
    /// Returns [`RegisterError`] on a duplicate name or a contended exclusive
    /// transducer, so hardware contention is caught at wiring time.
    pub fn register(&mut self, plugin: Arc<dyn Plugin>) -> Result<(), RegisterError> {
        let manifest = plugin.manifest();
        self.claim(&manifest)?;
        self.passive.insert(manifest.name, plugin);
        Ok(())
    }

    /// Register an active plugin. Same name/transducer arbitration as
    /// [`register`](Self::register), into the active map. An active plugin can
    /// only ever be dispatched with a `Grant`.
    ///
    /// # Errors
    /// Returns [`RegisterError`] on a duplicate name or a contended exclusive
    /// transducer.
    pub fn register_active(&mut self, plugin: Arc<dyn ActivePlugin>) -> Result<(), RegisterError> {
        let manifest = plugin.manifest();
        self.claim(&manifest)?;
        self.active.insert(manifest.name, plugin);
        Ok(())
    }

    /// Register an RF-transmit plugin. Same name/transducer arbitration as
    /// [`register`](Self::register), into the transmit map. A `TxPlugin` can only
    /// ever be dispatched with a `TxGrant` — the regulatory (Axis-B) token — and
    /// the exclusive `RfTx` port admits exactly one holder.
    ///
    /// # Errors
    /// Returns [`RegisterError`] on a duplicate name or a contended exclusive
    /// transducer.
    pub fn register_tx(&mut self, plugin: Arc<dyn TxPlugin>) -> Result<(), RegisterError> {
        let manifest = plugin.manifest();
        self.claim(&manifest)?;
        self.tx.insert(manifest.name, plugin);
        Ok(())
    }

    /// Register an active-wireline plugin. Same name/transducer arbitration as
    /// [`register`](Self::register), into the wireline map. A `WirePlugin` can only
    /// ever be dispatched with a `WireGrant` — the physical-plant (Axis-C) token —
    /// and the exclusive `Wireline` port admits exactly one holder (one pair of clips).
    ///
    /// # Errors
    /// Returns [`RegisterError`] on a duplicate name or a contended exclusive
    /// transducer.
    pub fn register_wire(&mut self, plugin: Arc<dyn WirePlugin>) -> Result<(), RegisterError> {
        let manifest = plugin.manifest();
        self.claim(&manifest)?;
        self.wire.insert(manifest.name, plugin);
        Ok(())
    }

    /// Validate a manifest against the shared name namespace and exclusive-port
    /// index, recording ownership on success. The one arbitration path for
    /// passive, active, and transmit registration.
    fn claim(&mut self, manifest: &Manifest) -> Result<(), RegisterError> {
        if self.passive.contains_key(&manifest.name)
            || self.active.contains_key(&manifest.name)
            || self.tx.contains_key(&manifest.name)
            || self.wire.contains_key(&manifest.name)
        {
            return Err(RegisterError::DuplicateName(manifest.name.clone()));
        }
        if is_exclusive(manifest.transducer) {
            if let Some(owner) = self.transducer_owner.get(&manifest.transducer) {
                return Err(RegisterError::TransducerClaimed(
                    manifest.transducer,
                    owner.clone(),
                ));
            }
            self.transducer_owner
                .insert(manifest.transducer, manifest.name.clone());
        }
        self.order.push(manifest.name.clone());
        Ok(())
    }

    /// Look up a passive plugin by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Plugin>> {
        self.passive.get(name)
    }

    /// Manifests of every registered plugin (passive, active, and transmit), in
    /// registration order, for the `plugins` command.
    #[must_use]
    pub fn manifests(&self) -> Vec<Manifest> {
        self.order
            .iter()
            .filter_map(|n| {
                self.passive
                    .get(n)
                    .map(|p| p.manifest())
                    .or_else(|| self.active.get(n).map(|p| p.manifest()))
                    .or_else(|| self.tx.get(n).map(|p| p.manifest()))
                    .or_else(|| self.wire.get(n).map(|p| p.manifest()))
            })
            .collect()
    }

    /// Dispatch a command to a named **passive** plugin.
    ///
    /// # Errors
    /// [`DispatchError::NoSuchPlugin`] if no passive plugin has this name;
    /// otherwise the plugin's own [`PluginError`].
    pub fn dispatch(&self, plugin: &str, cmd: &Command) -> Result<Event, DispatchError> {
        let Some(p) = self.passive.get(plugin) else {
            return Err(DispatchError::NoSuchPlugin(plugin.to_owned()));
        };
        p.dispatch(cmd).map_err(DispatchError::Plugin)
    }

    /// Dispatch an active command to a named **active** plugin, authorized by
    /// `grant`. The grant is minted by the gate; the target the plugin acts on is
    /// carried in it, so this path cannot touch anything unauthorized.
    ///
    /// # Errors
    /// [`DispatchError::NoSuchPlugin`] if no active plugin has this name;
    /// otherwise the plugin's own [`PluginError`].
    pub fn dispatch_active(
        &self,
        plugin: &str,
        cmd: &Command,
        grant: &Grant,
    ) -> Result<Event, DispatchError> {
        let Some(p) = self.active.get(plugin) else {
            return Err(DispatchError::NoSuchPlugin(plugin.to_owned()));
        };
        p.dispatch_active(cmd, grant).map_err(DispatchError::Plugin)
    }

    /// Dispatch a transmit command to a named **transmit** plugin, authorized by
    /// `grant`. The `TxGrant` is minted by the gate's Axis-B path; the band,
    /// power, and license the plugin transmits under are carried in it, so this
    /// path cannot key up outside the authorized envelope.
    ///
    /// # Errors
    /// [`DispatchError::NoSuchPlugin`] if no transmit plugin has this name;
    /// otherwise the plugin's own [`PluginError`].
    pub fn dispatch_tx(
        &self,
        plugin: &str,
        cmd: &Command,
        grant: &TxGrant,
    ) -> Result<Event, DispatchError> {
        let Some(p) = self.tx.get(plugin) else {
            return Err(DispatchError::NoSuchPlugin(plugin.to_owned()));
        };
        p.dispatch_tx(cmd, grant).map_err(DispatchError::Plugin)
    }

    /// Dispatch a wireline command to a named **active-wireline** plugin,
    /// authorized by `grant`. The `WireGrant` is minted by the gate's Axis-C path;
    /// the line-ID the plugin drives is carried in it, so this path cannot touch a
    /// pair the operator did not assert ownership of.
    ///
    /// # Errors
    /// [`DispatchError::NoSuchPlugin`] if no wireline plugin has this name;
    /// otherwise the plugin's own [`PluginError`].
    pub fn dispatch_wire(
        &self,
        plugin: &str,
        cmd: &Command,
        grant: &WireGrant,
    ) -> Result<Event, DispatchError> {
        let Some(p) = self.wire.get(plugin) else {
            return Err(DispatchError::NoSuchPlugin(plugin.to_owned()));
        };
        p.dispatch_wire(cmd, grant).map_err(DispatchError::Plugin)
    }
}

/// A dispatch failure: either an unknown plugin or the plugin's own error.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// No plugin registered under this name.
    #[error("no such plugin: {0}")]
    NoSuchPlugin(String),
    /// The plugin ran and reported a failure.
    #[error(transparent)]
    Plugin(#[from] PluginError),
}

/// Whether a transducer is an exclusive physical resource.
///
/// The registry index arbitrates a *logical medium*, not a specific piece of
/// hardware. A transducer is exclusive only when the medium itself admits one
/// holder: the single `Wireline` tap, and the single `RfTx` chain (which is also
/// the Axis-B–gated transmit port — one radio keys at a time).
///
/// `Store` (local data) and `Ip` (the shared kernel network stack) are not scarce
/// — many plugins hold them at once (numintel's cache-fed HTTP, SIP recon, a
/// future SS7 client all share `Ip`). `RfRx` joins them: SDR *receive* is
/// observation, and several passive RX layers (`sdr-rx`, `gnss`, `cell-survey`)
/// must co-register and run on the same recorded IQ — most importantly on the
/// hardware-free `IqFileSource` path, where there is no device to contend for at
/// all. Marking `RfRx` exclusive would make the second RX plugin fail
/// registration against the first — the same category error the `Ip` fix
/// corrected: `RfRx` is a logical medium, not the one physical dongle.
///
/// Arbitration of the *physical* radio (when a live SDR exists) does not belong
/// in this logical index in either regime: on the file path there is no device;
/// on the live path the Tier-B subprocess host that opens the SDR holds it 1:1
/// for the child's lifetime (see `specs/cell-survey` Gap 2, `specs/gnss` Q5).
/// That seam owns device identity; this function owns logical-medium contention.
fn is_exclusive(t: Transducer) -> bool {
    matches!(t, Transducer::Wireline | Transducer::RfTx)
}
