# Design Document — phonetool-legacy-hw

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** Fixes the copper-layer module seams, the
> WAV/trace-source-vs-device boundary, and — the load-bearing decision — surfaces the
> missing physical-plant gate axis that active injection needs, so the passive decode/
> sense/synth half can be built ahead of any loop hardware. No code implements this yet.

## Overview

`phonetool-legacy-hw` is the analog local-loop layer. It has two faces of one `Wireline`
capability, deliberately split across the gate:

- **Passive (built path):** decode DTMF/MF and Bell-202 Caller-ID from a supplied audio
  buffer, sense loop-current / line-voltage / ring / hook-state from a supplied trace, and
  synthesize DTMF/MF/2600-SF tones to a WAV. All observation or file rendering; implements
  the plain `Plugin` trait, declares `Wireline` / `Passive`, and **never sees a gate**. The
  entire DSP is exhaustively testable offline against a known sample vector — the
  ahead-of-hardware proof that the decoders are correct before any loop exists.

- **Active physical injection (the gap, NOT built):** driving tones/ring/seizure onto a
  live tip-and-ring pair. This is where the load-bearing architectural gap lives: it fits
  **neither** gate axis. The design's job here is not to build it but to **name the gap
  precisely and recommend a direction** for the operator to decide (see the dedicated
  section below and Open Question 1).

Two load-bearing decisions shape the built half, both borrowed from sdr-rx: a
device-agnostic **source seam** separates the DSP/sense pipeline from the sample producer
(so the pipeline runs today against a `WavFileSource` / recorded trace and a live front end
snaps in behind an off-by-default feature), and all memory-unsafe device FFI is
**quarantined** in one off-by-default crate so the default build stays pure-Rust,
unsafe-free, and egress-free.

Inbound bytes are untrusted at every boundary. A WAV header can lie about its length; a
Caller-ID burst is attacker-shaped structure and its decoded calling number is trivially
spoofed (caller-ID spoofing is itself a fraud vector this workbench exists to observe); a
sense trace is an attacker-supplied integer series. Every boundary validates fail-closed,
is bounded by a `SAMPLE_CAP`, and moves bulk audio out-of-band by `CaptureRef`.

### Threat note

The copper layer eats adversary input on both the byte side and — for the future active
half — the physical side:

1. **The WAV/trace container** — a declared sample count or rate is an attacker-controlled
   integer; trusting it as an allocation size is a memory-exhaustion primitive. Mitigation:
   never allocate to a declared length; read into a `SAMPLE_CAP`-bounded buffer and truncate
   (Req 2.3, 2.5). A malformed container → `PluginError::InvalidInput`, never a panic.
2. **The sample stream / FSK burst** — a total, panic-free Goertzel + FSK demod over any
   byte length (no `unwrap`/`expect`/unchecked index); malformed or non-audio input → an
   error value, never a crash (Req 2.4, 3.4).
3. **The decoded Caller-ID identity** — the recovered calling number/name is
   attacker-shaped and spoofable. The tool reports it as *observed on the wire*, never as a
   verified identity, and takes no action keyed on it (Req 3.2). This is the numintel model
   applied to copper: observing a spoofed CID is clean recon; trusting it would be the bug.
4. **The physical hazard (future active half)** — telco line voltage (nominally tens of
   volts DC idle, ~90 V AC ringing — figures illustrative, exact values deferred to an Open
   Question grounded in the SLIC datasheet) can injure the operator or destroy the front
   end, and a mis-fired relay/seizure is irreversible. Mitigation: **no** default-build code
   can energize a pair; the injection path lives entirely in the FFI-quarantine crate behind
   an off-by-default feature and fires only after an explicit hardware-safety interlock
   assertion that is orthogonal to authorization (Req 8).

The built layer is passive, so there is no transmit-side or line-driving threat in the
default binary — but "passive" does not mean "trusted input": it means the danger is a
crash/hang/RCE on decode, which the totality discipline closes.

## Architecture

```
   CLI: line decode|cid|sense|synth <args>         (Passive — NO gate, NO Grant/TxGrant)
        │
        ▼
   registry.dispatch("line", &cmd)                  Plugin trait (never ActivePlugin)
        │
        ▼
   LineHw::dispatch(cmd)
        │  verb guard: decode | cid | sense | synth
        │  audio  ← WavFileSource   (default, no hardware)   ── or device source (feature)
        │  trace  ← RecordedSenseSource (default)            ── or live ADC/GPIO (feature)
        ▼
   ┌──────────────── LineSource (RX/SENSE-only trait; NO drive/inject method) ───────────┐
   │  WavFileSource / RecordedSenseSource     LiveLineSource(feat)  RingDetectSource(feat) │
   │  supplied WAV / recorded trace     ── FFI-QUARANTINE CRATE: unsafe allowed, OFF ──    │
   └───────────────────────────────┬─────────────────────────────────────────────────────┘
        │  read_block(): PCM / sense samples, bounded by SAMPLE_CAP (truncate, never trust len)
        ▼
   dsp / sense pipeline (pure Rust, unsafe_code = forbid, TOTAL over bytes)
        │  decode → Goertzel bank → DTMF/MF symbols (confident-match-or-nothing)
        │  cid    → Bell-202 FSK demod → CidFrame (untrusted identity; validate checksum)
        │  sense  → classify loop-current / line-voltage / ring / hook-state
        │  synth  → DTMF/MF/2600-SF → PCM buffer → WAV file (renders to file, NEVER a line)
        ▼
   degenerate discipline: nothing usable → PluginError::Empty ; malformed → InvalidInput
        │  else → Event{ source:"line", summary, data:{ symbols|cid|line_state, truncated } }
        │         synthesized WAV / retained loop audio → CaptureRef{ CallAudio, path } (never inlined)
        ▼
   CaptureBus.record_event(event) + record CaptureRef for bulk audio

   ══════════════════ GAP: ACTIVE PHYSICAL INJECTION (NOT BUILT — no legal trait) ══════════
   inject tones/ring | seize loop | drive pair
        │  needs a token NEITHER axis provides:
        │    Axis A Grant  → cyber/IP target      ✗ (no IP target)
        │    Axis B TxGrant→ RF band/license      ✗ (no spectrum)
        │  ┌── OPEN QUESTION 1: third axis WireGrant  OR  Axis-A Grant{target=line-ID} ──┐
        │  └──────────────────────────────────────────────────────────────────────────┘
        │  AND (independent) hardware-safety interlock  ── line voltage ~48 V DC / ~90 V AC
        ▼
   [ no ActivePlugin-analogue trait takes the chosen token yet — prerequisite Task 0 ]
```

## Modules

- **`source`** — the `LineSource` trait (RX/SENSE-only: `read_block` returning bounded
  PCM/sense samples + `describe()` returning rate/kind; **no** `drive`/`inject`/`seize`
  method), and the two default pure-Rust sources `WavFileSource` (supplied audio) and
  `RecordedSenseSource` (a captured ADC/voltage series). `SampleBlock` (a bounded owned
  buffer + its rate/kind). `SAMPLE_CAP` lives here. Missing/unreadable input →
  `PluginError::InvalidInput` before any DSP.
- **`dsp`** — pure, source-free tone processing: `decode` (a Goertzel bank over the grounded
  tone table → ordered DTMF/MF symbols, confident-match-or-nothing), `cid` (Bell-202
  mark/space FSK demod → `CidFrame` with checksum/parity validation), and `synth` (symbol
  spec → DTMF/MF/2600-SF PCM buffer). Exhaustively testable against a known sample vector
  with no I/O. Tone frequencies and thresholds are grounded constants / configuration, never
  literals invented here (Req 10).
- **`sense`** — classification of a sense `SampleBlock` into `LineState { loop_current,
  line_voltage, ring, hook }`, returning a level/present classification. Returns an idle-line
  state (a real result) vs an empty/unreadable trace (an error) — the degenerate split.
- **`lib` (`LineHw`)** — the `Plugin` boundary: verb guard (`decode`/`cid`/`sense`/`synth`),
  source selection, `LineConfig` (tolerances, `SAMPLE_CAP`, WAV render params), the
  degenerate-case discipline, and `Event` assembly with `CaptureRef` emission for synthesized
  or retained audio. Implements only `Plugin`; **names no `Grant`/`TxGrant`**.
- **`phonetool-linehw-ffi`** (separate crate, OFF-BY-DEFAULT feature, **the only place
  `unsafe` is allowed**) — the live front end: `LiveLineSource` / `RingDetectSource` (ADC +
  ring-detect GPIO) as `LineSource` impls over `gpio-cdev` / `linux-embedded-hal`, and — when
  and only when the gate gap is resolved and built — the injection driver and its
  hardware-safety interlock. Board-agnostic; **not** `rppal`.

## Design decisions

### `LineSource` has no drive/inject method (by construction, not by convention)

The source trait yields sample blocks and describes its tuning; it exposes nothing that
could drive a line, close a relay, or seize a loop. This makes "sensing never energizes the
pair" and "a passive plugin cannot reach an injection path" compiler-checked facts rather
than review conventions — the same stance sdr-rx takes with its transmit-free `SdrSource`
and authgate takes with `Grant`. A live front end that *is physically capable* of driving
the pair (a SLIC) is modeled, on the sense path, as a `LineSource` whose drive capability is
simply **not reachable through this trait**. When injection is specified (after the gate gap
is resolved), it gets its own seam, its own token, and its own hardware-safety interlock —
never a method on `LineSource`.

### `WavFileSource` / `RecordedSenseSource` are the ahead-of-hardware path, not test doubles

The operator directive is explicit: software leads gear. The WAV and recorded-trace sources
are first-class, shipping, default sources — not mocks. The whole decode/cid/sense pipeline
is verifiable offline against a known recorded or synthetic sample, so decoder correctness is
provable before any loop tap exists. This is the exact stance sdr-rx takes with
`IqFileSource`.

### FFI quarantine: `unsafe` in exactly one off-by-default crate

All GPIO/ADC/relay/SLIC FFI is memory-unsafe by nature and must be isolated. It lives in
`phonetool-linehw-ffi`, the only crate permitted to relax `unsafe_code = forbid`, behind an
off-by-default Cargo feature. The default build — the four DSP/sense verbs against files and
traces — stays pure-Rust, unsafe-free, egress-free, and statically cross-compilable to
aarch64-musl. This mirrors numintel's off-by-default `online` feature and sdr-rx's
`phonetool-sdr-ffi`: the offline claim is "zero egress/unsafe dependencies in the default
graph," verified by `cargo tree -e no-dev`. Board-agnosticism (`gpio-cdev` /
`linux-embedded-hal`, not the archived `rppal`) keeps the front end portable across the SBC
fleet.

### Synthesis renders to a file, never to a line (the inert-payload discipline)

`synth` produces a PCM buffer / WAV file and has no path to a physical output — rendering is
not injection. This is the copper analogue of sip's "always-compiled, gate-only" honesty
caveat: the default binary *contains* the tone-generation code that a future injection path
would use as its payload, but that code is **line-inert** — it can only write samples. The
docs must state this honestly: the offline claim is "the default binary cannot drive a
pair," not "the default binary contains no tone-generation code." The synthesis becomes a
payload only when combined with the gated, interlocked, FFI-quarantined output driver.

### `SAMPLE_CAP` — the RECV_CAP analogue for bulk audio

A WAV/trace header's declared sample count is attacker-controlled. Every source reads into a
`SAMPLE_CAP`-bounded buffer and truncates, never allocating to a declared length — the exact
discipline sip applies to `RECV_CAP` on a UDP datagram and sdr-rx to `SAMPLE_CAP` on IQ. When
truncation happens it is recorded in the `Event`. Bulk audio (a synthesized WAV, retained
loop audio) is moved out-of-band and referenced by `CaptureRef { kind: CaptureKind::CallAudio,
path }`; only bounded metadata (the decoded symbol string, the CID fields, the classified
line state) ever enters an `Event`.

### Caller-ID identity is untrusted (observe, never trust)

A decoded `CidFrame` is reported as *observed on the wire*, with its checksum-validation
status attached — never as a verified identity, and the tool takes no action keyed on it.
Caller-ID spoofing is a first-class fraud vector this workbench exists to *observe*; trusting
the decoded number would be the exact bug the passive stance forbids. This is the same
discipline ss7 applies to a decoded MAP operation: flag presence, never fabricate attribution.

### Degenerate = failure; quiet line / no-tones = success

Two distinct outcomes, deliberately not conflated (the sip/sdr-rx discipline). An **empty,
unreadable, or nothing-recovered** run is degenerate — useless — and returns
`PluginError::Empty` (or `InvalidInput` for a malformed container). A buffer **analyzed and
confidently carrying zero tones**, or a trace **showing an idle line**, is a genuine
observation and returns `Ok(Event)`: "this recording carries no tones" / "this line is idle"
is a real, reportable result. No decoder ever fabricates a symbol, a CID field, or a line
state to avoid an empty result.

## The gate gap: active physical injection fits neither axis (design deliverable, not a decision)

This is the load-bearing gap this spec exists to surface. Active physical injection —
seizing a loop, injecting DTMF/MF/2600-SF onto a live pair, applying ringing voltage,
characterizing the pair by driving it — is a real capability the operator may want, and it
fits **neither** existing gate axis:

- **Axis A (`Grant`, `Gate::request_ip`)** answers to a **cyber** authority: target
  ownership of an IP/network endpoint. Loop seizure has no IP target.
- **Axis B (`TxGrant`, `Gate::request_tx`)** answers to a **regulatory/spectrum** authority:
  band + power + license. A copper pair radiates nothing licensable; there is no band.

Driving a pair the operator does not own is a **distinct wrong** — theft of service and
physical trespass on carrier plant — with a **distinct hazard** — line voltage. It deserves
its own accountable authorization record, not a mislabeled reuse of a cyber or spectrum
token. There are two coherent ways to close the gap, argued here and left to the operator:

- **Option 1 — a third gate axis (`WireGrant`), the recommended direction.** Add, in
  `phonetool-authgate`, a `WireAuthorization { line_id, plant_basis }`, a `Gate::request_wire`
  that mints an unforgeable `WireGrant` fail-closed (empty `line_id` → `NoTarget`, empty
  `plant_basis` → `NoBasis`), and — in `phonetool-core` — a new active-wire trait whose
  dispatch method takes `&WireGrant`, with the line-ID living in the grant (never the
  `Command`), exactly as `ActivePlugin` carries the target in `&Grant`. Every decision logs to
  the `ConsentLog` like the other axes. **Why recommended:** the crate's own thesis is that
  distinct wrongs get distinct tokens ("an SS7/IP authorization is not a transmit license" —
  gate.rs). Theft-of-service-on-plant is a third distinct wrong; a distinct `WireGrant` keeps
  the consent log honest about *which* authority was asserted, and makes "a cyber grant does
  not authorize seizing a physical loop" a compiler-checked fact. **Cost:** a new axis is new
  authgate surface, a new trait, and a new registry dispatch path.

- **Option 2 — fold under Axis A with `target = "<line/pair/line-ID>"`.** Reuse `Grant`; the
  operator's `IpAuthorization.target` carries the line/pair identifier and `basis` carries the
  plant-ownership assertion. **Why tempting:** zero new authgate surface; the existing
  `ActivePlugin` trait and `dispatch_active` already carry the target-in-grant invariant.
  **Cost:** it overloads "Axis A" past its stated meaning (cyber/IP target ownership),
  muddies the consent log (a plant seizure is recorded as an `ActiveIp { target }` — a
  category error mirroring the one registry.rs warns against for `Ip`-vs-physical
  transducers), and erases the compiler-checked distinction the crate was built to enforce.

**Recommendation: Option 1 (a third `WireGrant` axis).** This spec does **not** implement or
silently adopt either; the choice is Open Question 1 and a prerequisite task. Note the exact
parallel to ss7 Open Question 1 (is unlawful interconnect signalling a third regulatory
axis?) and to sdr-rx's flagged rf-tx gap (no trait takes a `&TxGrant`): the workbench has
**three** places where the two-axis gate model is proving too narrow. The operator may prefer
to resolve them together with one "generalize the gate to N named axes" decision rather than
three point additions — that meta-question is itself surfaced (Open Question 6).

Whichever token is chosen, it is **necessary but not sufficient**: the injector additionally
requires the hardware-safety interlock (Req 8), and neither the token nor the interlock
satisfies the other — the same double-precondition shape ss7 applies to its future injector
(`Grant` + a lawful link).

## Error handling

One error vocabulary at the boundary: `PluginError` (the trait's enum). A file/trace that
cannot be read, a malformed WAV/trace container, or an oversized-declared length maps to
`PluginError::InvalidInput`. An unsupported verb maps to `PluginError::Unsupported`. A run
that recovered nothing usable (empty buffer, no recoverable symbol/frame) maps to
`PluginError::Empty` (the degenerate case). A device-absent condition on a feature build maps
to `PluginError::Backend`. The Goertzel decode, the FSK demod, the sense classifier, and the
synth renderer are all total: no `unwrap`/`expect`/unchecked index, no panic on any input —
enforced by `unsafe_code = forbid` and the workspace deny-lints on the default (non-FFI)
crates.

## Testing strategy

- **Offline decode/synth round-trip (no hardware):** `synth` renders a known DTMF/MF/2600-SF
  sequence to a PCM buffer; `decode` recovers exactly that sequence — the ahead-of-hardware
  proof that the tone table and the Goertzel bank agree, with no device. A separate vector
  feeds a hand-built Bell-202 CID burst to `cid` and asserts the exact decoded fields and a
  passing checksum.
- **Hostile-input parser (table-driven):** empty buffer, non-audio bytes, truncated WAV, a
  header declaring a sample count far above `SAMPLE_CAP`, a non-multiple-of-sample-size byte
  length, a multi-gigabyte declared length, a CID burst with a corrupted checksum, and a
  noise-only buffer — each maps to the exact `PluginError` or truncates to `SAMPLE_CAP` /
  reports `decoded: false` **without panic or over-allocation**.
- **Degenerate discipline:** an empty/unreadable input → `PluginError::Empty` /
  `InvalidInput`; a clean buffer with confidently zero tones → `Ok(Event)` with zero symbols;
  an idle-line trace → `Ok(Event)` reporting idle — assert each pair is distinguished, and
  that no decoder fabricates a symbol/field/state.
- **Untrusted-identity check:** a CID frame carrying an obviously-spoofed number decodes and
  is reported as *observed*, with no code path treating it as a verified identity.
- **Passive invariant:** a compile-level check / test that `LineHw` implements `Plugin` and
  **not** `ActivePlugin`, and that no path references `Grant` / `TxGrant` / any wire token.
- **Grounded-constants guard:** a test asserting that any tone frequency / threshold / CID
  field layout not yet cited to a standard is left in the `unknown`/declines-to-decode state,
  never shipped as an invented value.
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]` since the
  no-panic discipline binds library code, not assertions.

## Open questions for operator

1. **Does active physical injection get a third gate axis (`WireGrant`), or fold under Axis
   A?** The load-bearing gap. Injection fits neither Axis A (no IP target) nor Axis B (no
   spectrum). **Recommended: Option 1 — a distinct `WireGrant` axis** (`Gate::request_wire`,
   a new active-wire trait taking `&WireGrant`, line-ID in the grant), because a distinct
   wrong (theft of service / plant trespass) deserves a distinct token and an honest consent
   record. Option 2 (reuse `Grant` with `target = "<line-ID>"`) is cheaper but overloads the
   cyber axis and erases the compiler-checked distinction. **Not decided here.**
2. **Line-voltage interlock thresholds.** The exact hardware-safety interlock trip voltages,
   clamp values, and the nominal idle/ringing figures are **datasheet constants**, not
   guessable — they depend on the specific SLIC / line-interface front end. The ~48 V DC /
   ~90 V AC figures in this spec are **illustrative**; the real trip points are deferred to
   the chosen hardware's datasheet, not invented.
3. **DTMF/MF/CID grounded constants + source of truth.** DTMF pairs (ITU-T Q.23/Q.24) are
   well-known and citable; the MF (R1) tone set and the 2600-SF supervision tone, the Bell-202
   mark/space frequencies, and the Caller-ID frame layout (Bellcore/Telcordia GR-30/GR-31
   lineage) need a citable reference the operator accepts before the tone table and CID parser
   are populated. No frequency is asserted in this spec pending that. Which reference?
4. **Detection tolerances.** The Goertzel twist/duration/detection thresholds and the FSK
   demod decision boundaries are safety/quality constants, not protocol constants. Their exact
   values (what separates a confident DTMF match from noise) need an operator decision or a
   grounded reference; deferred rather than invented.
5. **Switch-generation signalling specifics (grounding discipline, hard).** The classes are enumerated as
   labels (step-by-step, crossbar, ESS, DSS, COCOT), but per-class behavior — dial-pulse vs
   DTMF acceptance, trunk supervision (does MF/2600 apply to this generation at all?),
   coin/COCOT tone signalling, DSS vs ESS line-side differences — **must** be grounded in real
   documentation or a physical unit at build time. This spec confabulates **none** of it.
   Which classes does the operator actually intend to target, and what is the grounding source
   (real docs / a bench unit) for each?
6. **Should the gate generalize to N named axes?** Three specs now surface the two-axis model
   as too narrow: this layer (physical plant), ss7 (interconnect signalling), and rf-tx
   (missing `&TxGrant` trait). Does the operator want three point additions, or one
   refactor of `phonetool-authgate` to a set of named authorization axes with a uniform
   token-minting + consent-logging shape? A meta-decision that shapes all three.
7. **Front-end / SBC hardware priority.** Which line-interface front end comes first (a
   SLIC-based dev board vs a discrete opto-isolated sense front end vs a butt-set tap), so the
   `phonetool-linehw-ffi` crate targets the right `gpio-cdev`/`linux-embedded-hal` bindings and
   the right datasheet for the interlock (Open Question 2) first?
