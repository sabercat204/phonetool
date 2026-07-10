# Design Document — phonetool-cell-survey

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** Fixes the module seams, the RAT-decoder
> split, and the recorded-capture-vs-device boundary now, so the survey software is
> finished ahead of the SDR and the live path is a source swap. No code implements this
> yet.

## Overview

`phonetool-cell-survey` decodes the broadcast / system-information channels of GSM, LTE, and
5G NR from a capture, aggregates the decoded cells into a `CellMap` with a neighbour graph,
and scans that map for the tells of a cell-site simulator (IMSI catcher / rogue BTS). It is
passive by construction: it declares `CapabilityClass::Passive` and `Transducer::RfRx`,
implements the `Plugin` trait (never `ActivePlugin`), and is never handed a gate. Receiving
broadcast cell info is observation; the layer never transmits, so it touches neither gate
axis.

The design has four seams, each with one job:

- **`source`** — where samples come from. A `CaptureSource` trait with two implementations:
  `FileCaptureSource` (a recorded `gr-gsm` / IQ / GSMTAP-pcap dump — the hardware-free path
  that runs **today**) and `LiveCaptureSource` (a Tier-B subprocess holding the SDR — the
  **device seam**). The decode path does not know which it is fed.
- **`decode_gsm` / `decode_lte` / `decode_nr`** — three **distinct**, total decoders, one per
  RAT. Each converts untrusted broadcast blocks into typed cells; each is exhaustively
  testable against recorded input with no radio.
- **`cellmap`** — pure aggregation: decoded cells → `CellMap` + neighbour graph. Socket-free,
  radio-free.
- **`detect`** — pure analysis: `CellMap` + baseline + thresholds → `Vec<AnomalyFlag>`. Also
  socket-free; runs today over recorded captures.

The load-bearing decision: **the sample source is the only thing that changes when hardware
arrives.** Decode / map / detect are pure functions of bytes-in, so the recorded-file path
proves them end-to-end before an SDR exists, and the live Tier-B path reuses them verbatim.

## Architecture

```
   CLI: cell-survey survey <capture-file | --live>
        │
        ▼
   CellSurvey::dispatch(cmd)          verb guard: "survey"   (Plugin — no Grant, ever)
        │  arg → CaptureSource
        │
   ┌────┴───────────────────────────────┐
   │ TODAY (no hardware)                 │  DEVICE SEAM (hardware arrives)
   │ FileCaptureSource(path)             │  LiveCaptureSource ─► Tier-B SubprocessPlugin
   │  recorded gr-gsm / IQ / GSMTAP pcap │   (gr-gsm / Osmocom / srsRAN child)
   │  bounded, streamed read             │   CONTROL: length-prefixed JSON (Command/Event)
   └────┬───────────────────────────────┘   DATA: bulk IQ out-of-band, by handle
        │                                       │  RfRx claim held for the scan
        ▼                                       ▼
   segments (untrusted broadcast bytes) ◄───────┘
        │
        │  per segment → RAT dispatch (distinct decoders, total over hostile bytes)
        ├─► decode_gsm  → GsmCell { MCC,MNC,LAC,CID,ARFCN, neighbour ARFCNs }
        ├─► decode_lte  → LteCell { PCI,EARFCN,TAC,PLMN,band }
        ├─► decode_nr   → NrCell  { PCI,GSCN,PLMN,TAC }
        │   (malformed/truncated field → skip+flag, never panic)
        ▼
   cellmap::build(cells)  → CellMap + neighbour graph   (pure)
        │
        ▼
   detect::scan(&CellMap, &Baseline, &Thresholds) → Vec<AnomalyFlag>   (pure, advisory)
        │
        │  decoded-cell count == 0 → PluginError::Empty   (degenerate = failure)
        ▼
   Event { source:"cell-survey", summary, data: {cells, neighbours, anomalies} }
   CaptureBus.record_event(event)
   CaptureBus.record CaptureRef{ kind: Iq|Pcap, path }   ← bulk samples referenced, never inlined
```

## Modules

- **`source`** — `CaptureSource` trait (`fn segments(&self) -> Result<SegmentIter, SourceError>`
  or equivalent bounded reader), `FileCaptureSource { path }` (bounded/streamed read of a
  recorded dump — the default, hardware-free path), and `LiveCaptureSource` (the device seam;
  drives a Tier-B `SubprocessPlugin`, not built). `SourceError` (`NotFound` / `Unreadable` /
  `TooLarge` / `LiveUnavailable`).
- **`decode_gsm`** — `GsmCell` and a total BCCH/SI decoder. Distinct module: GSM's L3 RR
  System Information format shares nothing with LTE/NR.
- **`decode_lte`** — `LteCell` and a total MIB/SIB decoder.
- **`decode_nr`** — `NrCell` and a total SSB/MIB/SIB1 decoder.
- **`cellmap`** — `CellMap`, `CellId` (per-RAT identity key), the neighbour graph, and
  `build`. Pure; retains conflicting observations of one identity (Req 5.3).
- **`detect`** — `AnomalyKind`, `AnomalyFlag { kind, evidence, confidence }`, `Baseline`,
  `Thresholds`, and `scan`. Pure; advisory-only output.
- **`lib`** — `CellSurvey`, its `Plugin` impl (`manifest` + `dispatch`), verb guard, source
  selection, degenerate-case discipline, and `CaptureRef` emission.

## Design decisions

### Passive `Plugin`, never `ActivePlugin` — and never `TxGrant`

Broadcast RX is observation; it is on neither gate axis, so `CellSurvey` implements only
`Plugin::dispatch(&Command)` and is never handed a gate — the same stance as numintel, but
on `RfRx` rather than `Ip`. Detection is *advisory*: it emits `AnomalyFlag`s and stops. The
moment a response would go on the air (jamming a rogue BTS, forcing a UE off it, active
paging) the operation crosses onto Axis B (regulatory) and would need a `TxGrant` — a
**distinct wrong** from cyber, and out of scope for this layer. We do not build it here, and
we note (Open Questions) that no `ActivePlugin`-style trait takes a `&TxGrant` today anyway,
so an active-response capability has no legal plug-in point yet regardless.

### Source seam: recorded file today, Tier-B live later

`CaptureSource` is the single abstraction the decode path sees. `FileCaptureSource` reads a
recorded `gr-gsm` / IQ / GSMTAP-pcap dump — this is the default and runs with no SDR, so the
whole pipeline is provable today. `LiveCaptureSource` is the device seam: it drives a Tier-B
`SubprocessPlugin` that owns the SDR and a DSP toolchain (`gr-gsm`, Osmocom, srsRAN) which do
not exist in pure Rust. Because the source is the only thing that differs, hardware arrival is
a source swap, not a rewrite.

### Three distinct decoders, not one blob

GSM SI (L3 RR), LTE MIB/SIB (ASN.1 PER), and 5G NR SSB/SIB (ASN.1 PER, different schema) are
unrelated wire formats. Modelling them as one decoder would force a lowest-common-denominator
shape and hide RAT-specific validation. Three modules keep each decoder's boundary checks and
field set honest, and make "GSM decodes but NR is garbage" an isolatable test.

### Total decoders over adversary bytes

A rogue BTS crafts its broadcasts to mislead — including to break a naive parser. Every
decoder is total: a truncated block, an out-of-range field, or an air-supplied length is
skipped-and-flagged, never used to size an allocation or index a buffer unchecked. This is the
same stance as sip's `Response::parse`, enforced by the workspace no-panic deny-lints, but
stated explicitly because the input is hostile by design.

### Absent fields stay absent

When a field within a decodable block does not decode, it is recorded as unknown, never
defaulted or guessed. A fabricated default would poison the detector (a guessed neighbour list
could mask a `MissingNeighbours` anomaly). This mirrors numintel's "no country-code inference".

### Detection categories grounded; thresholds deferred, not invented

The `AnomalyKind` set (`UnexpectedPlmn`, `ForcedReregistration`, `RatDowngrade`,
`MissingNeighbours`, `SignalGeometryImplausible`, `DuplicateIdentity`) names the *categories*
of rogue-BTS tell documented in public IMSI-catcher research. The **numeric thresholds** and
scoring weights are **not** invented here: signal-geometry bounds, confidence cutoffs, and the
re-registration heuristic must be grounded in cited research at build time. They are `Thresholds`
config inputs, and each unresolved value is an Open Question, not a hardcoded constant. This
honors the no-fabrication rule: a plausible-looking dBm cutoff we cannot cite is
worse than a deferred one.

### Degenerate = failure; per-segment = resilient

Two disciplines at two layers, mirroring sip. Within a survey, one malformed segment is a
decode miss, never a run-aborting error — a hostile transmitter cannot kill the whole scan.
Across the survey, if *zero* cells decoded, `dispatch` returns `PluginError::Empty`: a survey
that learned nothing is a failure the operator sees, never an empty success misread as "the
area is clean".

### Bulk IQ by reference, decoded results inline

Raw IQ/pcap is recorded as a `CaptureRef { kind, path }` on the `CaptureBus`; only decoded
structured results (cells, neighbour graph, anomaly flags) go into the `Event` data, so event
size scales with cell count, not sample count. This is the control/data split of the
subprocess-IPC contract, applied at the capture bus.

## Threat model

Every byte decoded here is **adversary-controlled** — a cell-site simulator's entire purpose
is to transmit crafted broadcasts (spoofed PLMN, forged neighbour lists, a LAC/TAC set to
trigger re-registration, an SI block truncated to trip a parser). Threat note: a malformed
broadcast block, an air-supplied length/count field, or a hostile capture file must never
cause a panic, an unbounded allocation, an unchecked index, or a fabricated field. Mitigations:
(1) total decoders under the no-panic deny-lints; (2) air-supplied lengths/counts bound-checked
before any alloc/index; (3) capture-file reads bounded/streamed, never slurped whole (Req 7.4);
(4) undecodable fields recorded absent, never defaulted; (5) the detector is advisory — no
action is taken on the air, so a spoofed broadcast can at worst raise a false flag, never
trigger a transmit; (6) Tier-B child frames are themselves untrusted input, validated at the
subprocess-IPC boundary (length bound → deserialize in a `Result` → `PluginError::Backend`),
and the child is never a gate bypass.

## Known architectural gaps (design deliverables, not silently decided)

### Gap 1 — no `RfRx` live source exists yet (device seam is empty)

`LiveCaptureSource` depends on the Tier-B `SubprocessPlugin`, which is DESIGN-ONLY in
`specs/subprocess-ipc-contract/` and unbuilt. Until it exists, only `FileCaptureSource` is
real. This is intentional (software ahead of hardware) but must be a prominent prerequisite,
not a silent stub. **Recommended direction (operator decides):** build and prove the recorded
pipeline first; gate `LiveCaptureSource` behind an off-by-default `live` Cargo feature so the
default build carries no SDR/subprocess surface. Not decided here.

### Gap 2 — how does an `RfRx` claim govern a process that physically holds the SDR?

Registry arbitration marks `RfRx` exclusive (one holder) on the **Rust side**, but under
Tier-B the *child process* physically opens the SDR. A Rust-side claim does not by itself stop
a second child from grabbing the device. **Recommended direction (operator decides):** the
`SubprocessPlugin` host holds the `RfRx` claim for the child's lifetime and is the sole
spawner of SDR-bound children, so the claim and the device stay 1:1. Confirm when the live path
is built; recorded in Open Questions.

### Gap 3 — active rogue-BTS response has no legal plug-in point

If the operator ever wants an active defensive response to a detected IMSI catcher, that is an
Axis-B transmit and would need a `&TxGrant` — but no plugin trait takes a `&TxGrant` today
(`ActivePlugin::dispatch_active` takes `&Grant`, Axis A only). This layer does **not** need
that trait — it is passive by charter — but the gap is real and noted so the boundary is
explicit: cell-survey stops at *reporting*.

## Error handling

`SourceError` (`NotFound`/`Unreadable`/`TooLarge`/`LiveUnavailable`) is the source layer's
vocabulary; decoders surface per-block decode misses as flagged skips rather than errors; the
`lib` layer maps outcomes to `PluginError` (bad/absent source → `InvalidInput`; zero cells →
`Empty`; source I/O failure → `Backend`; a Tier-B child failure → `Backend`). No panics: the
crate compiles under `unsafe_code = forbid` and the workspace no-panic deny-lints. Any future
SDR/DSP FFI lives in a separate crate behind an off-by-default feature (Req 10.2).

## Testing strategy

- **Recorded-capture end-to-end** (hardware-free): fixture `gr-gsm` / GSMTAP-pcap dumps drive
  `dispatch` through decode → map → detect; assert decoded cell fields, neighbour edges, and
  expected `AnomalyFlag`s. This is the primary proof and needs no SDR.
- **Per-RAT decoder hostile-input** (table-driven, one table per RAT): empty, truncated,
  over-long air-supplied length, out-of-range field, non-matching RAT — each maps to a decode
  miss or a typed skip, never a panic. The rogue-BTS analogue of sip's parser table.
- **Detector unit tests**: baseline + synthetic `CellMap` → expected flags for each
  `AnomalyKind` category; a clean map → zero flags; thresholds injected (never hardcoded).
- **Degenerate case**: a capture that decodes zero cells → `PluginError::Empty` (nonzero exit),
  not an empty success.
- **CaptureRef discipline**: assert bulk IQ/pcap is recorded as `CaptureRef { kind, path }` and
  never inlined into `Event` data.
- **Passive/no-gate property**: structural — the plugin implements only `Plugin` and is never
  handed a gate; covered by the `plugins` listing showing `cell-survey [RfRx/Passive]`.
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]` since the
  no-panic discipline binds library code, not assertions.

## Open questions for operator

1. **IMSI-catcher detection thresholds — must be grounded, not invented.** What are the cited
   research values for: signal-geometry implausibility bounds, the LAC/TAC-change
   re-registration heuristic, the RAT-downgrade trigger, and per-flag confidence cutoffs? Until
   sourced (e.g. SnoopSnitch / SRLabs, AIMSICD, academic IMSI-catcher-detection literature),
   these stay `Thresholds` config inputs with no default — do not ship a guessed dBm or count.
2. **Baseline provenance.** Where does "what should be present" come from — a prior clean
   survey snapshot, a crowd-sourced tower DB (OpenCellID / Mozilla Location Service), the
   regulator's licensed-PLMN list, or operator hand-entry? This determines how strong
   `UnexpectedPlmn` / `MissingNeighbours` can be without false positives.
3. **Recorded capture format(s) for the today-path.** Fix the input format now: `gr-gsm`'s
   GSMTAP-over-pcap, raw IQ (which sample format / rate / metadata sidecar), or both? LTE/NR
   have no `gr-gsm` equivalent — what recorded source proves `decode_lte` / `decode_nr` before
   hardware (srsRAN file replay, a captured SIB corpus)?
4. **Gap 1 — live-path feature gating.** Off-by-default `live` Cargo feature for
   `LiveCaptureSource`, keeping SDR/subprocess surface out of the default build? (Recommended;
   confirm.)
5. **Gap 2 — RfRx claim vs. child-held device.** Is "the `SubprocessPlugin` host holds the
   `RfRx` claim and is the sole spawner of SDR-bound children" the accepted rule for keeping
   the Rust-side claim 1:1 with the physical device? Confirm at live-path build time.
6. **Gap 3 — active response boundary.** Confirm cell-survey stays report-only forever, and any
   active rogue-BTS countermeasure (which would need a `&TxGrant` trait that does not exist)
   lives in a separate, explicitly gated layer if ever pursued.
7. **LTE/NR neighbour relations.** GSM broadcasts a neighbour ARFCN list directly; LTE/NR
   neighbour info is more conditional. How complete a neighbour graph can we build passively per
   RAT, and does `MissingNeighbours` apply to LTE/NR or GSM-only in v1?
8. **5G NR scope.** NSA (LTE-anchored) vs SA broadcast decode differ. Which does v1 target, and
   is FR2 (mmWave) in scope or FR1-only?
