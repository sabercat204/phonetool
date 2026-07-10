# Requirements Document — phonetool-core (workbench shell)

## Introduction

`phonetool-core` is the workbench shell — the load-bearing unit of phonetool. The tool's
value is not any single capability but the shell that hosts them: a plugin registry, an
offline-first local data layer, a unified capture/consent bus, and configuration. Each
telecom capability (numintel now; SIP, RF, wireline later) is a `Plugin` that snaps into
this shell without modifying it.

Two invariants define the crate. **Offline-first**: the core links no network egress; the
default build is air-gapped and the local store is the default source of truth. "Online" is
a plugin-level mode (an off-by-default Cargo feature on a plugin), never a core dependency —
this is the OTG/SHTF stance, where survival-critical paths must run without a network.
**Closed under capability addition**: adding a plugin is one `register` call and changes
nothing else in the crate (the in-house registry idiom).

The shell also owns hardware arbitration. The device *is* the workbench; its "ports" (one
SDR RX, one SDR TX, one wireline tap, IP) are a shared, partly-exclusive resource. Plugins
declare the transducer they bind to, and the registry arbitrates so two plugins cannot both
claim the same exclusive port.

## Glossary

- **phonetool-core**: The crate under specification; the workbench shell.
- **Shell**: The composition of registry + store + capture bus + config.
- **`Plugin`**: The one trait every capability implements — `manifest()` +
  `dispatch(&Command) -> Result<Event, PluginError>`. Object-safe; `Send + Sync`.
- **`Manifest`**: A plugin's self-description — name, version, transducer, capability class,
  summary. Read by the registry at registration.
- **Tier A / Tier B**: A Tier-A plugin implements `Plugin` in-process, natively. A future
  Tier-B plugin implements the *same* trait by proxying to a subprocess. The registry and
  shell never learn which tier a plugin is (see `specs/subprocess-ipc-contract/`).
- **`Command` / `Event`**: The verb+arg dispatched to a plugin, and the normalized
  serializable result (source, summary, data) it emits.
- **`PluginError`**: `InvalidInput` / `Unsupported` / `Empty` / `Backend`. An empty/useless
  result is an error, not a silent success (degenerate-case discipline).
- **`PluginRegistry`**: Holds `Arc<dyn Plugin>` keyed by name, preserves registration order,
  and indexes exclusive-transducer ownership.
- **`Transducer`**: The port/medium a plugin binds to — `Ip`, `Wireline`, `RfRx`, `RfTx`,
  `Store`. `Store`, `Ip`, and `RfRx` are shareable logical media (many plugins may hold each);
  `Wireline` and `RfTx` are exclusive single-instance physical ports.
- **`CapabilityClass`**: The manifest-level authorization label (`Passive` / `ActiveIp` /
  `RfTx`) — a payload-free mirror of the authgate `Capability`.
- **`RegisterError` / `DispatchError`**: Registration refusals (duplicate name, contended
  transducer) and dispatch failures (no such plugin, or the plugin's own error).
- **`IntelStore`**: The offline-first key/value data-layer trait — `get`/`put` over
  `(namespace, key)`. `SqliteStore` is the bundled-sqlite implementation.
- **`CaptureBus`**: The unified sink — plugin events + gate consent records on one ordered
  timeline; stubs for future bulk IQ/pcap capture references.
- **`Config`**: Minimal shell configuration (store path).
- **Operator**: The human invoking phonetool.

## Requirements

### Requirement 1: One plugin contract, tier-agnostic

**User Story:** As a plugin author, I want a single trait to implement, so a capability
snaps into the shell without the shell knowing whether it runs in-process or via subprocess.

#### Acceptance Criteria

1. THE core SHALL define `Plugin` as an object-safe `Send + Sync` trait with `manifest()`
   and `dispatch(&Command) -> Result<Event, PluginError>`.
2. THE core SHALL hold plugins as `Arc<dyn Plugin>` and dispatch through the trait object.
3. THE `dispatch` contract SHALL be total over its input: a plugin SHALL report malformed
   or invalid input as `Err(PluginError)`, never a panic.
4. THE core SHALL NOT expose or require any tier discriminator on the trait.

### Requirement 2: Closed under capability addition

**User Story:** As a maintainer, I want adding a plugin to be one call, so the shell stays
stable as capabilities grow.

#### Acceptance Criteria

1. WHEN a new plugin is added, THE core SHALL require only a `PluginRegistry::register`
   call and no change to `phonetool-core` itself.
2. THE registry SHALL index plugins by the `name` in their manifest.
3. THE registry SHALL preserve registration order for the `plugins()` listing.

### Requirement 3: Hardware arbitration by transducer

**User Story:** As the operator, I want the shell to refuse two plugins claiming the same
exclusive port, so hardware contention is caught at wiring time, not mid-operation.

#### Acceptance Criteria

1. WHEN `register` is called with a plugin whose `name` is already registered, THE registry
   SHALL return `Err(RegisterError::DuplicateName)`.
2. WHEN `register` is called with a plugin declaring an exclusive transducer already held by
   another plugin, THE registry SHALL return `Err(RegisterError::TransducerClaimed)` naming
   the current owner.
3. THE registry SHALL treat `Transducer::Store`, `Transducer::Ip`, and `Transducer::RfRx` as
   shareable — multiple plugins MAY declare each without contention (shared data layer, shared
   kernel network stack, and shared SDR-receive medium respectively).
4. THE registry SHALL treat `Wireline` and `RfTx` as exclusive single-instance physical ports.

### Requirement 4: Dispatch

**User Story:** As the CLI, I want to dispatch a command to a named plugin and receive its
event or a typed error.

#### Acceptance Criteria

1. WHEN `dispatch` is called with an unregistered plugin name, THE registry SHALL return
   `Err(DispatchError::NoSuchPlugin)`.
2. WHEN `dispatch` is called with a registered name, THE registry SHALL invoke that plugin's
   `dispatch` and return its `Event` on success.
3. WHEN the invoked plugin returns `Err(PluginError)`, THE registry SHALL surface it as
   `DispatchError::Plugin`.

### Requirement 5: Offline-first data layer, no core egress

**User Story:** As the operator on an air-gapped SBC, I want the default build to make no
network call, so survival-critical paths run offline.

#### Acceptance Criteria

1. THE core SHALL link no network-egress dependency in any build configuration.
2. THE core SHALL provide `IntelStore` (`get`/`put` over `(namespace, key)`) as the data
   abstraction the shell and plugins depend on.
3. WHEN a key is absent, THE `IntelStore::get` SHALL return `Ok(None)` — a miss is not a
   backend error.
4. WHEN the backend fails, THE store SHALL return `Err(StoreError::Backend)`, never panic.
5. THE `SqliteStore` SHALL use bundled sqlite so the binary needs no system libsqlite and
   stays a self-contained static artifact.
6. WHERE the sqlite connection mutex is poisoned, THE store SHALL return `StoreError`
   rather than unwrap-panicking.

### Requirement 6: Unified capture + consent timeline

**User Story:** As the operator, I want plugin results and authorization decisions on one
ordered timeline, so consent and the operations it gates share a single record.

#### Acceptance Criteria

1. THE `CaptureBus` SHALL record plugin `Event`s and implement the authgate `ConsentLog`,
   so gate decisions land in the same ordered stream.
2. WHEN a plugin event or consent record is pushed, THE bus SHALL mirror it to `tracing`.
3. THE bus SHALL expose the records in order.
4. THE `CaptureRecord` type SHALL carry a stubbed `CaptureRef { kind, path }` variant for
   future bulk IQ/pcap/call-audio captures, storing the on-disk path, never samples inline.
5. WHERE the record mutex is poisoned, the bus SHALL degrade to an empty read / dropped
   push rather than panic.

### Requirement 7: Hardened

#### Acceptance Criteria

1. THE core SHALL compile under `unsafe_code = forbid` and the workspace no-panic
   deny-lints.
2. THE core SHALL depend on `phonetool-authgate` (downward) and SHALL NOT be depended on by
   it.
