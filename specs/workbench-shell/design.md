# Design Document — phonetool-core (workbench shell)

## Overview

`phonetool-core` is the host that plugins snap into. It is designed around a prior in-house
registry idiom (a `Dissector` trait + a `Registry`, there; a `Plugin` trait + a
`PluginRegistry`, here): registration is data-driven from each plugin's own manifest, so the
set of capabilities is open while the shell stays closed. The crate carries two hard
invariants — no network egress in any build config, and "adding a plugin touches nothing
here" — plus one responsibility the analyzer domain does not have: arbitrating shared
physical hardware, because the workbench is a single device with a finite set of ports.

## Architecture

```
        CLI / shell composition
                │  register(Arc<dyn Plugin>)
                ▼
        ┌──────────────────────────┐
        │      PluginRegistry       │  by_name: HashMap<String, Arc<dyn Plugin>>
        │                           │  order:   Vec<String>          (stable listing)
        │  arbitrates transducers   │  transducer_owner: HashMap<Transducer, String>
        └──────────┬───────────────┘
                dispatch(name, &Command)
                    │
                    ▼
             Arc<dyn Plugin> ──► Event | PluginError
                    │
                    ▼
             CaptureBus  ◄── ConsentLog (gate decisions)
                    │
                    ▼
             IntelStore (SqliteStore, bundled)   ← offline source of truth
```

## Modules

- **`plugin`** — `Plugin` trait, `Manifest`, `Command`, `Event`, `PluginError`. The shell
  boundary; all four types are `Serialize`/`Deserialize` as appropriate so a future Tier-B
  proxy can move them across a subprocess seam unchanged.
- **`registry`** — `PluginRegistry`, `RegisterError`, `DispatchError`, and the private
  `is_exclusive(Transducer)` helper. Registration validates name-uniqueness and
  exclusive-port ownership up front.
- **`transducer`** — `Transducer` (the port) and `CapabilityClass` (the manifest-level
  authorization label mirroring authgate's `Capability`).
- **`store`** — `IntelStore` trait, `StoreError`, `SqliteStore` (bundled rusqlite).
- **`capture`** — `CaptureBus`, `CaptureRecord`, `CaptureKind`. Implements `ConsentLog`.
- **`config`** — `Config` (store path). Minimal by intent; grows as plugins need it.

The `lib.rs` re-exports the authgate surface (`Gate`, `Grant`, `TxGrant`, `Capability`, …)
so plugins and the CLI depend on `phonetool_core` for the whole workbench vocabulary rather
than reaching across crates.

## Design decisions

### Registry indexes by transducer, arbitrates exclusivity

`register` reads the manifest, rejects a duplicate name, and — for exclusive transducers —
records the plugin as the port's owner or rejects the contention. `is_exclusive` returns
`true` only for the single-instance physical ports `Wireline` and `RfTx`; `Store`, `Ip`, and
`RfRx` are shareable logical media (the data layer, the kernel network stack, and SDR-receive —
each admits many plugins, and RX layers run together on recorded IQ with no device to contend
for). This puts genuine hardware contention at wiring time without blocking co-resident logical
users. `RfRx` and `RfTx` are split because they gate differently (RX is observation, never
gated and shareable; TX is Axis B of the authgate and exclusive). Physical single-SDR
arbitration, when a live radio exists, lives in the Tier-B subprocess host that opens the
device, not in this logical index.

### `Command`/`Event` are free-form at the edge

`Command` is `{ verb, arg }` and `Event` carries a `serde_json::Value` payload, so the trait
stays stable as plugins grow richer args. Each plugin validates its own args at its boundary
(the degenerate-case discipline lives in the plugin, not the shell).

### Degenerate results are errors

`PluginError::Empty` exists so a plugin can report "ran fine, found nothing useful" as a
*failure*. The registry propagates it as `DispatchError::Plugin`; the CLI turns it into a
nonzero exit. A technically-correct-but-useless result must not read as success.

### `SqliteStore` uses `Mutex<Connection>`

`rusqlite::Connection` is `Send` but not `Sync` (its statement cache is a `RefCell`), while
the store is shared as `Arc<dyn IntelStore>`. A `Mutex` is the right tool at Sprint-1 query
volume; the private `lock()` maps a poisoned mutex to `StoreError` rather than unwrapping
(the crate forbids `unwrap`/`expect`). A connection pool is a later optimization if
contention shows. Bundled sqlite keeps the artifact self-contained on the SBC — verified to
cross-compile clean for `aarch64-unknown-linux-musl`.

### One bus, one timeline

`CaptureBus` owns a `Mutex<Vec<CaptureRecord>>` and implements `ConsentLog`, so gate
decisions and plugin events interleave in one ordered stream. Sprint 1 keeps records in
memory and mirrors to `tracing`; a durable sink slots in behind the bus without touching
plugins or the gate. `CaptureRef { kind, path }` is stubbed for the RF/wireline layers and
stores only the on-disk path of an out-of-band capture, never IQ/pcap samples inline.

## Error handling

Three error enums, all `thiserror`, no panics: `PluginError` (plugin-level),
`RegisterError` (wiring-time), `DispatchError` (`#[from] PluginError` + `NoSuchPlugin`),
`StoreError` (`#[from] rusqlite::Error`). Mutex poisoning degrades to a typed error (store)
or a dropped operation (bus) rather than a panic. Compiles under `unsafe_code = forbid`.

## Testing strategy

- **`tests/registry_arbitration.rs`** (2 tests): registry loads and dispatches one plugin;
  a contended exclusive transducer is refused at registration.
- Store, capture bus, and dispatch error paths are additionally exercised through the
  numintel degenerate-case suite and the CLI end-to-end run.

## Future layers (behind the same traits)

Signal fingerprints and switch profiles add tables behind `IntelStore`. IQ/pcap/call-audio
bulk capture flows through the stubbed `CaptureRef`. A Tier-B `SubprocessPlugin` implements
`Plugin` by proxying to a child process — the registry never learns the difference.
