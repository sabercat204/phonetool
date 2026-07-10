# Tasks — subprocess IPC contract (Tier-B)

> **DESIGN-ONLY. NOT BUILT IN SPRINT 1.** Every task below is deferred; none is started.
> This file exists so the seam has a task list ready when the RF/polyglot layer lands.

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress · `[-]` deferred.

- [-] 1. `SubprocessPlugin` crate/module: spawn + own child lifecycle, reap on drop.
  _(Req 4)_
- [-] 2. Length-prefixed JSON framing: `u32` BE length + UTF-8 JSON body; max-frame bound
  (fail-closed on oversize); response deadline.
  _(Req 2)_
- [-] 3. `Command` → request frame; response frame → `Event` | error object → `PluginError`.
  _(Req 1, 2)_
- [-] 4. Out-of-band data channel: handle passed via `Event`, recorded as
  `CaptureRef { kind, path }`; choose concrete transport (FIFO / mmap / ZeroMQ) at build.
  _(Req 3)_
- [-] 5. Gate integration: active/RF-TX Tier-B ops acquire `Grant`/`TxGrant` on the Rust
  side before driving the child — no subprocess gate bypass.
  _(Req 4)_
- [-] 6. Untrusted-frame handling: validate bound, deserialize in `Result`, map all failure
  to `PluginError::Backend`; no panic, no hang.
  _(Req 2, 4)_
- [-] 7. Conformance harness: a reference echo-child (any language) proving a Tier-B plugin
  is indistinguishable from Tier-A at the registry.
  _(Req 1)_

## Trigger to un-defer

Build this when the first polyglot/RF capability (GNU Radio, Osmocom) is added — the roadmap's
RF/air-interface layer. Until then the contract is frozen at the design level only.
