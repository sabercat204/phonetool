# Design Document — phonetool-authgate

## Overview

`phonetool-authgate` converts a policy ("no active operation without authorization") into
a property the compiler enforces. The mechanism is type-state: an active operation is
written to take a token (`&Grant` for IP, `&TxGrant` for RF TX) as a parameter, the token
types have private fields and no public constructor, and the only way to obtain one is a
successful call to the gate. Therefore an unauthorized active op is not a runtime check
that can be forgotten or bypassed — it fails to compile because the caller cannot name the
token.

The crate is deliberately tiny and has no upward dependency: it defines the small
`ConsentLog` trait it needs and nothing more, so the spine never learns about the shell.
The shell's capture bus implements `ConsentLog`, which is how consent records join the
capture timeline (that wiring lives in `phonetool-core`, not here).

## Architecture

```
                 IpAuthorization                       TxAuthorization
                 { target, basis }                     { band, power_dbm, license_basis }
                        │                                       │
                        ▼                                       ▼
                 Gate::request_ip                        Gate::request_tx
                        │  validate_ip (fail-closed)             │  validate_tx (fail-closed)
                        │                                        │
        ┌───────────────┴───────────┐            ┌───────────────┴───────────┐
        │ record ConsentRecord       │            │ record ConsentRecord       │
        │  (Granted | Refused)  ─────┼──► ConsentLog ◄─┼── (Granted | Refused)  │
        └───────────────┬───────────┘            └───────────────┬───────────┘
                        ▼                                         ▼
                 Ok(Grant) | Err(Denied)                  Ok(TxGrant) | Err(Denied)
                        │                                         │
                        ▼                                         ▼
        fn active_ip_op(&Grant, …)                fn rf_tx_op(&TxGrant, …)
        (unrepresentable without the token)       (distinct token; A ≠ B)
```

## Modules

- **`capability`** — `Capability` (the payload-carrying label: `Passive`,
  `ActiveIp { target }`, `RfTx { band, power_dbm, license_basis }`), plus the operator's
  evidence structs `IpAuthorization` and `TxAuthorization`. `Capability` derives `Serialize`
  for logging/display. It is the *label*, not the enforcement — the token type is.
- **`gate`** — `Gate<'log>` (borrows `&dyn ConsentLog`), the two token types `Grant` and
  `TxGrant` (private fields, read-only accessors, no `Clone`/`Copy`), `request_ip` /
  `request_tx`, the private `validate_ip` / `validate_tx`, and `Denied`.
- **`consent`** — `ConsentLog` (the sink seam), `ConsentRecord`, `Decision`, and
  `NullConsentLog`.

## Design decisions

### Two token types, not one enum

`Grant` and `TxGrant` are separate structs rather than variants of one type. This makes "an
SS7/IP authorization is not a transmit license" a compiler-checked fact: a function that
requires `&TxGrant` cannot be called with a `Grant`. Collapsing them into one type would
push that distinction back to a runtime `match`, which is exactly the convention the crate
exists to eliminate.

### Fail-closed validation, target-before-basis

`validate_ip`/`validate_tx` reject empty/whitespace fields and (for TX) non-finite power.
The order is fixed (target/band → basis → power) so the `Denied` reason is deterministic
and testable. Trimming means whitespace-only evidence is treated as absent — a refusal, not
a technically-non-empty pass.

### Log before return, on every path

Both `request_*` compute the outcome, then record exactly one `ConsentRecord` (mapping
`Ok`→`Granted`, `Err`→`Refused { reason }`), then return. Recording happens on the refusal
path too, so an unauthorized attempt is evidence, not a silent no-op. `basis` is copied into
the record before the token consumes the authorization by-value.

### Infallible `ConsentLog`

The sink is `fn record(&self, ConsentRecord)` with no `Result`. A logging failure must not
be a lever to (a) let an unlogged op proceed or (b) abort an already-authorized op.
Durability is the sink's concern; the gate's only contract is that it *always* calls
`record` on every decision.

### `Gate` borrows the log

`Gate<'log>` holds `&'log dyn ConsentLog` rather than owning it, so one log (the capture
bus) backs both axes and outlives any single gate instance.

## Error handling

`Denied` is a `thiserror` enum with three variants (`NoTarget`, `NoBasis`,
`Invalid(String)`). There are no panics: the crate compiles under `unsafe_code = forbid`
and the workspace `unwrap_used`/`expect_used`/`indexing_slicing = deny` lints.

## Testing strategy

- **Compile-fail doctest** (in `lib.rs`) proving an active op cannot be written without a
  `Grant` — fabricating one via a struct literal does not compile.
- **Behavioral tests** (`tests/gate_behavior.rs`): empty target refused; empty basis
  refused; well-formed request granted; non-finite TX power refused; every path records
  exactly one consent record with the correct decision and verbatim basis.
- Tests carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]` since the
  no-panic discipline binds library code, not assertions.
