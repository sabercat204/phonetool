# Tasks — phonetool-authgate

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

- [x] 1. `capability` module: `Capability` enum (`Passive` / `ActiveIp` / `RfTx`),
  `IpAuthorization`, `TxAuthorization`; `Serialize` on `Capability`.
  _(Req 1, 5)_
- [x] 2. `consent` module: `ConsentLog` (infallible sink trait), `ConsentRecord`,
  `Decision`, `NullConsentLog`.
  _(Req 4, 5)_
- [x] 3. `gate` module — token types: `Grant` and `TxGrant` with private fields,
  read-only accessors, no `Clone`/`Copy`, no public constructor.
  _(Req 1)_
- [x] 4. `gate` module — `Gate<'log>` borrowing `&dyn ConsentLog`; `Gate::new`.
  _(Req 4)_
- [x] 5. `request_ip`: fail-closed `validate_ip` (empty target → `NoTarget`, empty basis
  → `NoBasis`, target-before-basis), record decision, return `Grant`/`Denied`.
  _(Req 2, 4)_
- [x] 6. `request_tx`: fail-closed `validate_tx` (empty band → `NoTarget`, empty license
  → `NoBasis`, non-finite power → `Invalid`), record decision, return `TxGrant`/`Denied`.
  _(Req 3, 4)_
- [x] 7. `Denied` error enum (`thiserror`); crate `lib.rs` re-exports and module docs.
  _(Req 2, 3)_
- [x] 8. Compile-fail doctest: active op unrepresentable without a `Grant`.
  _(Req 1)_
- [x] 9. Behavioral tests (`tests/gate_behavior.rs`): refusals, grants, non-finite power,
  one-record-per-decision, verbatim basis. **5 tests pass.**
  _(Req 2, 3, 4)_
- [x] 10. Compile clean under `unsafe_code = forbid` + workspace deny-lints; `fmt` clean.
  _(Req 6)_

## Deferred (not Sprint 1)

- Durable consent sink (rotating log / signed ledger) — currently the capture bus keeps
  records in memory + mirrors to `tracing`. The `ConsentLog` seam already supports it.
- Grant expiry / scope narrowing (per-target, per-time-window tokens) — the token today
  authorizes the operation it was minted for; finer scoping lands with active plugins.
