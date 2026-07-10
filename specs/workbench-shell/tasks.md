# Tasks — phonetool-core (workbench shell)

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

- [x] 1. `plugin` module: `Plugin` trait (object-safe, `Send + Sync`), `Manifest`,
  `Command`, `Event`, `PluginError` (`InvalidInput`/`Unsupported`/`Empty`/`Backend`).
  _(Req 1)_
- [x] 2. `transducer` module: `Transducer` (`Ip`/`Wireline`/`RfRx`/`RfTx`/`Store`),
  `CapabilityClass` mirroring authgate `Capability`.
  _(Req 3)_
- [x] 3. `registry` module: `PluginRegistry` (`by_name` + `order` + `transducer_owner`),
  `register` with duplicate-name and exclusive-transducer arbitration, `get`, `plugins`,
  `dispatch`; `RegisterError`, `DispatchError`, private `is_exclusive`.
  _(Req 2, 3, 4)_
- [x] 4. `store` module: `IntelStore` trait (`get`/`put`, miss = `Ok(None)`), `StoreError`
  (`#[from] rusqlite::Error`), `SqliteStore` (bundled sqlite, `Mutex<Connection>`, poison →
  `StoreError`), `open`/`open_in_memory`/`init`.
  _(Req 5)_
- [x] 5. `capture` module: `CaptureBus` (`Mutex<Vec<CaptureRecord>>`), `record_event`,
  `records`, `impl ConsentLog`; `CaptureRecord` (`PluginEvent`/`Consent`/stubbed
  `CaptureRef`), `CaptureKind` (`Iq`/`Pcap`/`CallAudio`); `tracing` mirror.
  _(Req 6)_
- [x] 6. `config` module: minimal `Config { store_path }`.
  _(Req 5)_
- [x] 7. `lib.rs`: module wiring + re-export of the authgate surface so downstream depends
  only on `phonetool_core`.
  _(Req 1, 7)_
- [x] 8. Tests (`tests/registry_arbitration.rs`): load+dispatch one plugin; contended
  transducer refused. **2 tests pass.**
  _(Req 2, 3, 4)_
- [x] 9. Compile clean under `unsafe_code = forbid` + no-panic deny-lints; verify **zero
  network egress** in `cargo tree -e no-dev` default graph.
  _(Req 5, 7)_

## Deferred (not Sprint 1)

- Durable capture sink (capture file / rotating call-log) behind `CaptureBus`.
- Connection pool for `SqliteStore` if lock contention is measured.
- Config loader (file/env) once a plugin needs more than the store path.
- Bulk-capture write path for `CaptureRef` when the RF/wireline layers land.
