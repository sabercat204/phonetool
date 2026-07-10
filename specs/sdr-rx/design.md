# Design Document — phonetool-sdr-rx

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** Fixes the RX source seam, the DSP
> pipeline shape, and the Tier-A/Tier-B split now, so the shell and the capture bus
> are stable when the first radio (or the first GNU Radio child) lands. No code
> implements this yet.

## Overview

`phonetool-sdr-rx` is the receive path: sweep (power vs frequency), identify (energy
detect + classify), and demod (FM/AM/SSB → audio; simple digital → bits). It is
`Passive` — receiving is observation, so it implements the plain `Plugin` trait,
declares transducer `RfRx` / capability `Passive`, and **never sees a `Grant` or a
`TxGrant`.** This is the counterpart to sip: sip is the first thing that transmits
and is always gated; sdr-rx never transmits and is never gated.

The load-bearing decision is a device-agnostic `SdrSource` seam that separates the
DSP pipeline from the sample producer. Because of it, the entire pipeline runs
**today with no radio**, against an `IqFileSource` reading a recorded or synthetic IQ
capture — and a live radio snaps in later behind an off-by-default feature with the
pipeline unchanged. The fleet is deliberately not modeled as one capability: RTL-SDR
is RX-only, HackRF/Lime/Pluto are TX-capable, and the `SdrSource` contract has no
transmit method, so an RX operation can never be blocked for lack of a transmitter
nor accidentally reach a transmit path.

Bulk IQ is data but adversary-controlled data. A capture's header can lie about its
length, its samples can be pathological, and a demodulated payload (a digital frame,
a nav message) is attacker-shaped structure. Every boundary validates fail-closed,
is bounded by a `SAMPLE_CAP`, and moves bulk artifacts out-of-band by `CaptureRef`.

### Threat note

Inbound IQ is untrusted at three layers, each an attack surface:
1. **The file/device header** — a declared sample count or rate is an
   attacker-controlled integer; trusting it as an allocation size is a memory-
   exhaustion primitive. Mitigation: never allocate to a declared length; read into
   a `SAMPLE_CAP`-bounded buffer and truncate.
2. **The sample stream** — a total, panic-free parser (no `unwrap`/`expect`/unchecked
   index) over any byte length; malformed encoding → `PluginError::Backend`.
3. **The demodulated content** — recovered bits or a decoded frame/nav message is
   attacker-shaped; treat it as untrusted structure, never trust its self-declared
   fields, never panic decoding it. (Content *semantics* — e.g. GNSS nav-message or
   any RAT frame decode — are grounded/deferred, not confabulated; see Open
   Questions.) The default build is `unsafe`-free and egress-free; `unsafe` and any
   network transport live only behind off-by-default features.

## Architecture

```
   CLI: sdr sweep|identify|demod <args>          (Passive — NO gate, NO Grant)
        │
        ▼
   registry.dispatch("sdr", &cmd)                 Plugin trait (never ActivePlugin)
        │
        ▼
   SdrRx::dispatch(cmd)
        │  verb guard: sweep | identify | demod
        │  source ← IqFileSource (default, no hardware)  ── or device source (feature)
        ▼
   ┌──────────────────────── SdrSource (RX-only trait; no tx method) ───────────────┐
   │  IqFileSource        RtlSdrSource(feat)     HackRfSource(feat, RX-only)         │
   │  recorded/synth IQ   ── FFI-QUARANTINE CRATE: unsafe allowed, OFF BY DEFAULT ── │
   └───────────────────────────────┬────────────────────────────────────────────────┘
        │  read_block(): IQ samples, bounded by SAMPLE_CAP (truncate, never trust len)
        ▼
   dsp pipeline (pure Rust, unsafe_code = forbid, TOTAL over bytes)
        │  sweep   → Vec<(freq, power)>  (bin count bounded)
        │  identify→ energy-detect → Vec<DetectedSignal>{center,bw,power,mod:Unknown-safe}
        │  demod   → fm/am/ssb → audio  | digital → bits (bounded)
        ▼
   degenerate discipline: 0 samples → PluginError::Empty
        │  else → Event{ source:"sdr", summary, data:{ tuned, bins|signals, truncated } }
        │         bulk IQ  → CaptureRef{ kind: Iq,        path }   (never inlined)
        │         demod wav→ CaptureRef{ kind: CallAudio, path }   (never inlined)
        ▼
   CaptureBus.record_event(event) + record CaptureRef for bulk artifacts

   ── Tier-B alternative (subprocess-ipc-contract) ────────────────────────────────
   SdrRx (or a SubprocessPlugin) ──► GNU Radio flowgraph child
        CONTROL: length-prefixed JSON (Command → Event)   [gate stays Rust-side; N/A here — Passive]
        DATA:    bulk IQ out-of-band by handle ──► CaptureRef{ Iq, path }
```

## Modules

- **`source`** — the `SdrSource` trait (RX-only: `read_block` / `tuned()` returning
  sample rate + center frequency; **no** `transmit`), and `IqFileSource` (pure Rust,
  default, no hardware). `SampleBlock` (a bounded owned buffer of complex samples
  plus its rate/center). `SAMPLE_CAP` lives here.
- **`dsp`** — pure, source-free signal processing: `sweep` (PSD/periodogram →
  bounded `Vec<(f64, f64)>` bins), `identify` (energy detect over a sweep →
  `Vec<DetectedSignal>`), `demod` (`fm`/`am`/`ssb` → audio samples; `digital` →
  bits). Exhaustively testable against a known IQ vector with no I/O.
- **`classify`** — bandwidth/center-based modulation estimate returning
  `Modulation` (`Fm`/`Am`/`Ssb`/`Digital`/`Unknown`); returns `Unknown` rather than
  guessing. Thresholds are configuration, not literals (see Open Questions).
- **`lib` (`SdrRx`)** — the `Plugin` boundary: verb guard, source selection,
  `RxConfig` (bin count, energy threshold, `SAMPLE_CAP`, bind params), the
  degenerate-case discipline, and `Event` assembly with `CaptureRef` emission for
  bulk artifacts.
- **`phonetool-sdr-ffi`** (separate crate, OFF-BY-DEFAULT feature, **the only place
  `unsafe` is allowed**) — `RtlSdrSource` (RX-only device) and `HackRfSource`
  (TX-capable device driven RX-only), each `impl SdrSource` over soapysdr/librtlsdr.

## Design decisions

### `SdrSource` has no transmit method (by construction, not by convention)

The trait yields IQ blocks and reports its tuning; it exposes nothing that could
transmit. This makes "RX never requires a transmitter" and "an RX plugin cannot
energize a TX path" compiler-checked facts rather than review conventions — the
same stance authgate takes with `Grant`. A TX-capable radio (HackRF) is modeled as
an `SdrSource` implementation that happens to run RX-only here; its transmit
capability is simply not reachable through this trait. When TX is specified (the
rf-tx layer), it gets its own seam and its own `&TxGrant` gate — see the gap below.

### `IqFileSource` is the ahead-of-hardware path, not a test double

The operator directive is explicit: build software first, gear later. `IqFileSource`
is a first-class, shipping source — the default — not a mock. The whole
sweep/identify/demod pipeline is verifiable offline against a known recorded or
synthetic IQ capture, so DSP correctness is provable before any radio exists. Device
sources are the *later* addition, quarantined behind a feature; the pipeline they
feed is the same one already proven against files.

### FFI quarantine: `unsafe` in exactly one off-by-default crate

All C-driver FFI (soapysdr, librtlsdr, GPIO/ADC) is memory-unsafe by nature and must
be isolated. It lives in `phonetool-sdr-ffi`, the only crate permitted to relax
`unsafe_code = forbid`, behind an off-by-default Cargo feature. The default build —
`IqFileSource` + `dsp` — stays pure-Rust, `unsafe`-free, egress-free, and
statically cross-compilable to aarch64-musl. This mirrors numintel's off-by-default
`online` feature: the offline claim is "zero egress/unsafe dependencies in the
default graph," verified by `cargo tree -e no-dev`.

### `SAMPLE_CAP` — the RECV_CAP analogue for bulk IQ

A capture header's declared sample count is attacker-controlled. The source reads
into a `SAMPLE_CAP`-bounded buffer and truncates, never allocating to a declared
length — the exact discipline sip applies to `RECV_CAP` on a UDP datagram. When
truncation happens it is recorded in the `Event` so the operator knows the analysis
was partial. Bulk IQ and demodulated audio are moved out-of-band and referenced by
`CaptureRef { kind, path }`; only bounded metadata (capped bins, capped signal list)
ever enters an `Event` or a control frame.

### Degenerate = failure; quiet band = success

Two distinct outcomes, deliberately not conflated. **Zero samples read** is a
degenerate run — useless — and returns `PluginError::Empty`, the same discipline sip
applies when no probe was answered. **Samples analyzed but no signal above
threshold** is a genuine observation and returns `Ok(Event)` reporting zero
detections: "this band is quiet" is a real, reportable result an operator asked for.
A classifier that cannot justify a label emits `Unknown`, never a fabricated class —
a technically-correct-but-useless guess is not a result.

### Tier-B (GNU Radio) primary vs Tier-A (soapysdr FFI) — recommendation, not decision

Two viable paths to live-radio breadth, argued here and surfaced as an Open Question
rather than silently chosen:

- **Tier-A native (soapysdr FFI):** in-process, lowest latency, one language. Cost:
  reimplementing FM/AM/SSB/digital demodulators and all classification in Rust —
  wide, error-prone DSP surface — plus the `unsafe` FFI to every device.
- **Tier-B (GNU Radio flowgraph child), the recommended primary:** GNU Radio already
  provides mature, tested demodulators and sample sources for the whole fleet. Drive
  a flowgraph child over the `specs/subprocess-ipc-contract` seam — control frames as
  length-prefixed JSON `Command`/`Event`, **bulk IQ out-of-band by handle** recorded
  as `CaptureRef { Iq, path }` (GNU Radio's native ZeroMQ blocks fit this exactly).
  This layer being `Passive`, the "gate stays Rust-side" rule is trivially satisfied
  (there is no gate), but the framing/bounds/untrusted-child-output stance of that
  contract still applies to every frame the child sends back.

**Recommendation:** Tier-B primary for demod/DSP breadth (do not hand-port GNU
Radio); Tier-A native `IqFileSource` + `dsp` for the ahead-of-hardware offline path
and for lightweight sweep/identify. The two coexist behind the one `SdrSource` seam.
The operator decides whether native demod is ever worth building or whether Tier-B
is the sole live path (Open Question).

## Known gap: no numeric DSP/RF constants are fixed here (grounded-or-deferred)

Per the grounding discipline, this design deliberately does **not** invent numeric
thresholds or protocol behavior. Left as configuration + Open Questions rather than
confabulated:

- Energy-detection threshold, sweep bin count / FFT size, demod filter bandwidths.
- Per-modulation classification boundaries (what occupied-bandwidth ranges imply
  FM vs SSB vs a digital mode).
- Any decoded-content semantics (GNSS nav-message structure, a specific RAT's frame
  layout) — these MUST be grounded in real protocol docs at build time, never
  guessed. Until grounded, `identify` classifies to `Unknown` and demod stops at
  audio/raw-bits rather than claiming a decoded frame.

## Error handling

One error vocabulary at the boundary: `PluginError` (the trait's enum). A file that
cannot be read, an unsupported source rate/frequency, a malformed IQ header, or a
device-absent condition all map to `PluginError::Backend`. An unsupported verb or
demod mode maps to `PluginError::Unsupported`. A run that read zero samples maps to
`PluginError::Empty`. The IQ parser and the demodulated-content path are total: no
`unwrap`/`expect`/unchecked index, no panic on any input — enforced by
`unsafe_code = forbid` and the workspace deny-lints on the default (non-FFI) crates.

## Testing strategy

- **Offline pipeline (no hardware):** synthesize known IQ (a pure tone, an
  FM-modulated tone, a two-tone SSB) into an `IqFileSource`; assert `sweep` puts
  power in the expected bin, `identify` detects the expected count with correct
  center/bandwidth, and `demod` recovers the modulating signal. This is the
  ahead-of-hardware proof that the DSP is correct before any radio exists.
- **Hostile-input parser (table-driven):** empty file, truncated record, a header
  declaring a sample count far above `SAMPLE_CAP`, non-multiple-of-sample-size byte
  length, and a multi-gigabyte declared length — each maps to the exact
  `PluginError` or truncates to `SAMPLE_CAP` without panic or over-allocation.
- **Degenerate discipline:** a zero-sample source → `PluginError::Empty`; a
  silence-only capture analyzed → `Ok(Event)` with zero detections (assert the two
  are distinguished).
- **Classifier honesty:** an ambiguous capture → `Modulation::Unknown`, never a
  fabricated label.
- **Passive invariant:** a compile-level check / test that `SdrRx` implements
  `Plugin` and not `ActivePlugin`, and that no path references `Grant`/`TxGrant`.
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]`
  since the no-panic discipline binds library code, not assertions.

## Open questions for operator

1. **Tier-B primary vs Tier-A native demod.** Recommended: Tier-B (GNU Radio child
   over the subprocess-IPC contract) as the primary live-radio path, native
   `IqFileSource` + `dsp` for offline/sweep. Confirm, or decide native demod is worth
   building — this shapes whether `dsp` grows full FM/AM/SSB/digital demodulators or
   stays a sweep/identify + file-verification core.
2. **DSP numeric constants.** Energy-detection threshold, FFT size / sweep bin count,
   per-mode demod filter bandwidths, and the occupied-bandwidth→modulation
   classification boundaries are all deferred as configuration — none are invented
   here. Which need grounding in real references before build, and what are the
   defaults?
3. **IQ file format.** Which on-disk IQ format(s) does `IqFileSource` read — raw
   interleaved `cf32`/`cs16`, SigMF (`.sigmf-meta` + `.sigmf-data`), or GNU Radio's
   native file-sink format? SigMF carries trustworthy-looking metadata that is still
   untrusted input — confirm the format and the parse handling.
4. **`SAMPLE_CAP` value + budget semantics.** What is the sample ceiling on a handheld
   SBC, and when a capture exceeds it, is the right behavior head-truncate,
   decimate-to-fit, or window-and-page? (Truncate is specified as the safe default.)
5. **Device fleet priority.** Which radios matter first — RTL-SDR (RX-only, cheapest)
   vs a HackRF/Lime/Pluto — so the FFI-quarantine crate targets the right binding
   (librtlsdr vs soapysdr) first?
6. **Decoded-content scope.** How far past audio/raw-bits should demod go (e.g. any
   digital-mode framing, GNSS nav-message decode)? Any such decoder MUST be grounded
   in real protocol docs, not confabulated, and likely belongs in a downstream layer
   rather than sdr-rx.
