# Design Document — phonetool-sip

## Overview

`phonetool-sip` performs SIP extension enumeration over UDP: for each candidate
extension it sends one `OPTIONS sip:<ext>@<host>` request and infers, from the
response status, whether the extension exists. It is the first capability that
transmits, so it is the first to implement `ActivePlugin` and the first to be
reachable only through a gate-minted `Grant`.

The design has three seams, each with a single job:

- **`message`** — pure, socket-free SIP wire format. An `OptionsRequest::to_wire`
  builder (a pure function of caller-supplied fields) and a **total**
  `Response::parse` over untrusted bytes. Exhaustively testable with no network.
- **`enumerate`** — the socket layer. One bounded UDP probe per extension, with
  per-probe timeout and receive cap; owns no gate logic on purpose.
- **`lib` (`SipRecon`)** — the `ActivePlugin` boundary. Reads the target from the
  grant, validates the extension list, drives `enumerate::run`, and applies the
  degenerate-case discipline.

## Architecture

```
   CLI: sip enum <target> <exts> --basis <why>
        │
        ▼
   Gate::request_ip { target, basis }   ──► ConsentLog (CaptureBus): Granted | Refused
        │  Ok(Grant)                          (refusal ends the flow here)
        ▼
   registry.dispatch_active("sip", &cmd, &grant)
        │
        ▼
   SipRecon::dispatch_active(cmd, grant)
        │  target ← grant.target()   (NEVER cmd)      verb guard: "enum"
        │  extensions ← parse_extensions(cmd.arg)     boundary char-validation
        │  session ← FNV-1a(target + basis)           RNG-free transaction ids
        ▼
   enumerate::run(target, host, exts, session, cfg)
        │  bounds: MAX_EXTENSIONS, BadTarget shape, one UdpSocket, read timeout
        │  per ext → probe_one:
        │     OptionsRequest::to_wire → send_to → recv_from(timeout, RECV_CAP)
        │     Response::parse → classify → Finding
        │     (timeout/transport err → Finding{responded:false}; never aborts)
        ▼
   Vec<Finding>
        │  responded == 0 → PluginError::Empty   (degenerate = failure)
        │  else → Event { summary, data: {target, probed, responded, exists, findings} }
        ▼
   CaptureBus.record_event(event)
```

## Modules

- **`message`** — `OptionsRequest<'a>` (borrowed fields; `to_wire` allocates one
  `String` via infallible `write!`, routed through `let _ =` to honor the no-panic
  lint without asserting). `Response { status_code, reason, headers }` with a
  case-insensitive `header` lookup. `ParseError` (`Empty`/`BadStatusLine`/
  `BadStatusCode`). `Verdict` (`Serialize`, snake_case) and `classify`.
- **`enumerate`** — `EnumConfig { bind, timeout, user_agent }` (with a
  test-friendly `Default`), `Finding` (`Serialize`), `EnumError`
  (`BadTarget`/`Socket`/`TooMany`/`NoExtensions`), `run`, and the private
  `probe_one`. Constants `RECV_CAP = 8192`, `MAX_EXTENSIONS = 4096`.
- **`lib`** — `SipRecon { cfg }` (`new` / `with_config`), its `ActivePlugin` impl,
  and the private helpers `parse_extensions`, `short_session`, `map_enum_error`.

## Design decisions

### Target from the Grant, not the Command

`dispatch_active` reads `grant.target()` for the remote it may touch; the command's
`arg` is only the extension list. This closes the second-target-injection hole by
construction — there is no code path by which the plugin acts on a remote the gate
did not name. Any future active plugin must follow this invariant.

### A separate `ActivePlugin` trait, not a flag on `Plugin`

The passive recon path (numintel) implements only `Plugin` and never sees a
`Grant`, so it carries zero authorization friction. An active capability implements
`ActivePlugin`, whose `dispatch_active` cannot be called without a `Grant`. The
gate's compile-time guarantee is thereby extended one layer out from authgate into
the plugin layer.

### Total parser over untrusted bytes

`Response::parse` is deliberately total: it converts non-UTF-8 lossily, tolerates
CRLF or bare-LF, and maps every structural defect to a `ParseError` — no `unwrap`,
no `buf[i]`. The workspace deny-lints enforce this on library code, but the intent
is explicit because the input is adversary-controlled even under an authorized gate.

### RNG-free session token

Per-transaction SIP identifiers (branch/tag/call-id) are derived from an FNV-1a
hash over the grant's target+basis (`short_session`), not from an RNG. This adds no
`rand`/`getrandom` dependency, preserving the pure-Rust static-musl build.
Deterministic-per-grant is acceptable: a grant is minted per authorized operation
and is not reused, so overlapping runs get distinct seeds.

### Degenerate = failure, per-probe = resilient

Two different disciplines, deliberately at two layers. Within a run, one dead
extension is a `Finding { responded: false }`, never a run-aborting error — a slow
or hostile remote cannot kill the whole enumeration. Across the run, if *nothing*
answered, the op returns `PluginError::Empty`: a probe that learned nothing is a
failure the operator sees, not an empty success mistaken for "target is clean".

### Always-compiled, gate-only (operator decision) and its honesty caveat

SIP is a normal dependency of the CLI and ships in the default binary; the only
lock is the runtime `Grant` (the operator rejected an off-by-default `sip` Cargo
feature as a redundant second lock). The consequence, stated honestly: the default
binary *contains* an active-op code path — inert without a `Grant`, but present.
The offline claim therefore narrows to "**zero egress dependencies**" (SIP uses
`std::net`; `cargo tree -e no-dev` still shows zero `reqwest`), NOT "no active
code". The docs must not overclaim "air-gapped default binary".

## Error handling

Two error enums at two boundaries. `EnumError` (`thiserror`) is the socket layer's
vocabulary; `map_enum_error` maps it to the trait-level `PluginError`
(`NoExtensions`/`TooMany`/`BadTarget` → `InvalidInput`; `Socket` → `Backend`).
`ParseError` never escapes `probe_one` — a parse failure becomes a
`responded: true` no-verdict `Finding`. No panics: the crate compiles under
`unsafe_code = forbid` and the workspace `unwrap_used`/`expect_used`/
`indexing_slicing = deny` lints.

## Testing strategy

- **Compile-fail doctest** (in `lib.rs`, on `SipRecon`): fabricating a `Grant`
  struct literal to reach `dispatch_active` does not compile — the plugin-layer
  mirror of authgate's own doctest.
- **End-to-end** (`tests/active_enum.rs`): a loopback UDP responder on `127.0.0.1`
  (operator-owned) answers 200 for seeded extensions and 404 otherwise. The `Grant`
  is minted the only legal way — through the real `Gate` — then drives
  `dispatch_active`; asserts verdicts, status codes, `responded`, and the 200's
  server fingerprint. A second test asserts an empty basis is a `Denied::NoBasis`
  refusal recorded on the production `CaptureBus`. (Building and firing ≠ firing at
  a third party: the responder is loopback.)
- **Parser hostile-input** (`tests/message_parse.rs`, table-driven): empty,
  whitespace, non-SIP version, missing/non-numeric/wrong-length code, non-UTF-8,
  bare-LF, and a giant header block — each maps to the exact `ParseError` or parses
  without panic. Plus `classify` status→verdict coverage.
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]`
  since the no-panic discipline binds library code, not assertions.
