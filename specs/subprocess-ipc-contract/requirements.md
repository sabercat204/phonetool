# Requirements Document — subprocess IPC contract (Tier-B)

> **DESIGN-ONLY. NOT BUILT IN SPRINT 1.** This spec fixes the wire contract for the
> future Tier-B plugin seam so that when a polyglot capability (GNU Radio, Osmocom, any
> Python/C++ tool) is added, the shell does not change. No code in this repo implements it
> yet.

## Introduction

phonetool's plugin model has two tiers behind one `Plugin` trait. Tier A is in-process
native Rust (numintel and all future native layers). **Tier B** is out-of-process and
polyglot: a future `SubprocessPlugin` implements the *same* `Plugin` trait by proxying
`dispatch` to a child process, so GNU Radio (C++/Python + its own scheduler) and Osmocom
snap in without ever linking their runtimes into the core. The subprocess seam — not the
shell's language — is the load-bearing polyglot decision.

This document specifies the wire contract at that seam: a control channel for
request/response and an out-of-band channel for bulk sample data (IQ), so that high-rate
DSP data never flows through the JSON control path.

## Glossary

- **Tier B**: An out-of-process plugin. Implements `Plugin` by proxying to a child process.
- **`SubprocessPlugin`**: The future Rust-side proxy that spawns/owns the child and
  implements `Plugin` over the wire contract. (Not built.)
- **Control channel**: The request/response path — length-prefixed JSON frames over a Unix
  domain socket (or the child's stdin/stdout).
- **Data channel**: The out-of-band bulk path for IQ/pcap samples — a named pipe (FIFO) or
  shared-memory (mmap) region, referenced from the control channel by handle, never inlined.
- **Frame**: One control message = a 4-byte big-endian `u32` length prefix followed by that
  many bytes of UTF-8 JSON.
- **`CaptureRef`**: The existing `phonetool-core` capture-record variant `{ kind, path }`
  that already models an out-of-band bulk capture by on-disk path — the Tier-B data channel
  surfaces through it.

## Requirements

### Requirement 1: Same trait, hidden tier

#### Acceptance Criteria

1. THE contract SHALL allow a `SubprocessPlugin` to implement the existing `Plugin` trait
   (`manifest()` + `dispatch(&Command) -> Result<Event, PluginError>`) unchanged.
2. THE registry and shell SHALL NOT be able to distinguish a Tier-B plugin from a Tier-A one
   through the trait surface.
3. THE `Command` and `Event` types SHALL cross the seam by their existing serde
   representations without new shell-side types.

### Requirement 2: Framed JSON control channel

#### Acceptance Criteria

1. THE control channel SHALL carry each message as a 4-byte big-endian `u32` length prefix
   followed by that many bytes of UTF-8 JSON.
2. THE Rust side SHALL send a `Command` frame and the child SHALL reply with exactly one
   response frame carrying either an `Event` or a `PluginError`-shaped error object.
3. THE contract SHALL bound the maximum frame length, so a malformed or hostile length
   prefix cannot force an unbounded allocation (fail-closed on oversize).
4. WHERE the child emits a malformed frame, closes early, or exceeds a response deadline,
   THE `SubprocessPlugin` SHALL surface a `PluginError::Backend`, never hang or panic.

### Requirement 3: Out-of-band bulk data

#### Acceptance Criteria

1. THE bulk IQ/pcap path SHALL NOT flow through the JSON control channel.
2. THE control channel SHALL reference bulk captures by handle (a FIFO path or an mmap
   region id), which the shell records as a `CaptureRef { kind, path }`.
3. WHERE GNU Radio is the child, the data path MAY reuse GR's native ZeroMQ blocks; the
   control contract is independent of the bulk transport chosen.

### Requirement 4: Process lifecycle and trust boundary

#### Acceptance Criteria

1. THE `SubprocessPlugin` SHALL own the child's lifecycle (spawn, health, terminate) and
   SHALL reap it on drop.
2. THE child's output SHALL be treated as untrusted input and validated at the frame
   boundary before deserialization.
3. WHERE the child is capable of an active or RF-TX operation, THAT operation SHALL still
   route through `phonetool-authgate` on the Rust side — a subprocess SHALL NOT be a way to
   bypass the gate.

## Non-goals (Sprint 1 and this document)

- No implementation. No `SubprocessPlugin`, no framing code, no child harness.
- No choice of concrete bulk transport (FIFO vs mmap vs ZeroMQ) is frozen — only the rule
  that it is out-of-band and referenced by handle.
