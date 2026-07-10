# Design Document — subprocess IPC contract (Tier-B)

> **DESIGN-ONLY. NOT BUILT IN SPRINT 1.** Fixes the wire contract now so the shell is
> stable when the first polyglot capability lands. No code implements this yet.

## Overview

The Tier-B seam lets an out-of-process, any-language capability implement the same `Plugin`
trait as a native one. A future `SubprocessPlugin` (Rust) spawns and owns a child process,
proxies `dispatch` to it over a **length-prefixed JSON control channel**, and moves bulk IQ
samples over a **separate out-of-band channel** referenced by handle. Splitting control from
bulk data is the central decision: DSP sample rates (MS/s of IQ) would swamp a JSON path, so
JSON carries only commands, results, and *references* to bulk captures.

The point of writing this before building it: the `Plugin` trait, `Command`, `Event`, and
the `CaptureRef { kind, path }` capture variant already exist in `phonetool-core` and are
serde-ready. Tier B needs no new shell-side types — it is purely a proxy behind the trait.

## Architecture

```
  phonetool-core (unchanged)
        │  Arc<dyn Plugin>::dispatch(&Command)
        ▼
  SubprocessPlugin  ─────────────── owns child lifecycle ───────────────► child process
        │                                                                  (GNU Radio /
        │  CONTROL: length-prefixed JSON over Unix socket (or stdio)        Osmocom /
        │    ─► frame: [u32 BE len][ JSON(Command) ]                        any language)
        │    ◄─ frame: [u32 BE len][ JSON(Event | ErrorObj) ]
        │                                                                  produces IQ/pcap
        │  DATA (out-of-band, by handle): FIFO path | mmap id | ZeroMQ  ◄──┘
        ▼
  CaptureBus records CaptureRef{ kind, path }   ← bulk capture referenced, never inlined
```

## Wire contract

### Control frames

- **Framing**: `[ 4-byte big-endian u32 length ][ length bytes of UTF-8 JSON ]`.
- **Request**: JSON serialization of `Command { verb, arg }`.
- **Response**: exactly one frame — either a JSON `Event { source, summary, data }` or an
  error object shaped `{ "error": { "kind": "...", "message": "..." } }` mapping onto
  `PluginError`.
- **Bounds**: a maximum frame length is enforced; a length prefix exceeding it is a
  fail-closed `PluginError::Backend`, so a hostile prefix cannot force an unbounded alloc.
- **Deadline**: a response deadline bounds a hung child → `PluginError::Backend`.

### Data channel

Bulk IQ/pcap never enters a control frame. The child writes samples to an out-of-band
transport and returns, in its `Event`, a handle to it; the shell records that as a
`CaptureRef { kind, path }`. Candidate transports (not frozen): a named pipe (FIFO), a shared
`mmap` region, or — where the child is GNU Radio — GR's native ZeroMQ blocks. The control
contract is independent of which is chosen.

## Design decisions

### Control/data split

JSON is fine for commands and metadata and terrible for MS/s IQ. Separating them keeps the
control path human-debuggable and small while the bulk path stays zero-copy-friendly. This
mirrors how GNU Radio already externalizes streams (ZeroMQ), so a GR child needs no
impedance-matching layer for its data path.

### Length-prefixed JSON, not newline-delimited

A `u32` length prefix makes framing robust to embedded newlines and binary-ish content and
makes the max-frame bound trivial to enforce before reading the body — the fail-closed
allocation guard. Newline-delimited JSON would require scanning and is fragile to partial
reads.

### The gate stays on the Rust side

A subprocess must never be a gate bypass. If a Tier-B capability can perform an active-IP or
RF-TX operation, the `SubprocessPlugin` obtains the `Grant`/`TxGrant` on the Rust side and
only then drives the child. Authorization is a compile-time property of the host, and Tier B
does not get to opt out of it.

### Untrusted child output

The child's frames are untrusted input (same stance as any telecom byte stream): validate
the length bound, then deserialize inside a `Result`, mapping any failure to
`PluginError::Backend`. A malformed frame, early close, or deadline miss is an error, never a
panic or a hang.

## Lifecycle

`SubprocessPlugin` spawns the child, tracks health, terminates and reaps it on drop. A crash
mid-`dispatch` surfaces as `PluginError::Backend`. `manifest()` is served from a cached
handshake taken at spawn so it stays cheap and callable repeatedly (matching the Tier-A
contract).

## Status

Specification only. Implementation is deferred until the first RF/polyglot capability
requires it (RF/air-interface layer). When built, it gets its own `tasks.md` filled in
and its own crate (likely `phonetool-subprocess` or a module in a plugin crate).
