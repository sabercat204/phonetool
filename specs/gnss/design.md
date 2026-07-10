# Design Document — phonetool-gnss

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** Fixes the GNSS receive-and-integrity
> contract now — the acquisition/decode/PVT pipeline shape, the reuse of the
> `phonetool-sdr-rx` RX source seam, the spoof/jam detector families, and the Tier-A /
> Tier-B split — so the shell and the capture bus are stable when the first antenna (or
> the first `gnss-sdr` child) lands. No code implements this yet.

## Overview

`phonetool-gnss` is the satellite-navigation receive path: acquire and track GPS L1 C/A,
decode the broadcast navigation message, solve a position/velocity/time `Fix` — and
**qualify every fix with a spoof/jam integrity verdict**. It is `Passive` — receiving GNSS
is observation — so it implements the plain `Plugin` trait, declares transducer `RfRx` /
capability `Passive`, and **never sees a `Grant` or a `TxGrant`.** It is the direct
sibling of `phonetool-sdr-rx` and `phonetool-cell-survey`: all three are passive `RfRx`
decoders that read a file today and snap a device in behind the same seam. **These three now
co-register in one registry** — the spine sprint made `RfRx` a shareable logical medium
(`is_exclusive(RfRx)` is `false`), mirroring the `Ip`-shareable fix SIP task 1 applied so
numintel and SIP could both hold the `Ip` transducer. The "run every `RfRx` layer on files
today" premise holds. Physical single-SDR arbitration (when a live radio exists) is a separate
seam owned by the Tier-B subprocess host, not the logical index — still open (Open Question 5).

The defensive payload is the reason the layer exists. A bare fix is worthless under
attack: a spoofer transmits valid-looking, higher-power L1 signals to capture and drag a
receiver's solution; a jammer raises the noise floor to deny a fix. So the deliverable is
**fix + integrity verdict**, and the integrity assessment runs even when no fix is
obtained (a denied fix diagnosed as jamming is itself the result).

Three facts drive the design:

- **The RX source seam is reused, not re-invented.** `phonetool-sdr-rx` already defines the
  device-agnostic `SdrSource` trait, the hardware-free `IqFileSource`, the `SAMPLE_CAP`
  bound, and the FFI-quarantine crate for device drivers. GNSS consumes that seam so the
  whole acquire→fix→integrity pipeline runs **today** against a recorded/synthetic IQ file
  and a live radio snaps in later unchanged. Building a parallel source abstraction here
  would be a needless parallel type.
- **The nav message is adversary input.** It is exactly what a spoofer forges. The decoder
  is total (no `unwrap`/`expect`/unchecked index, checked lengths, parity-gated fields),
  and **decoded ephemeris/time is a *candidate*, never trusted truth until the integrity
  layer has ruled.** The spoof detector *is* the trust boundary.
- **No numeric thresholds are invented.** Per the grounding discipline, the detector *families* are
  grounded in the GNSS-security literature but every numeric bound (C/N0 floors, AGC
  deviation, position/velocity jump limits, SQM cutoffs, loss-of-lock fractions) is
  configuration deferred to build-time calibration against cited references — never a
  literal in this spec.

### Threat note

Inbound GNSS is untrusted at three layers, each an attack surface:

1. **The RF / IQ front end** — a jammer raises the in-band noise floor; a spoofer injects
   higher-power replica signals. Mitigation: the jamming assessment (noise-floor, AGC,
   simultaneous loss-of-lock) runs *before and independent of* any successful decode, so
   denial and deception are diagnosed rather than silently accepted.
2. **The navigation message bits** — a spoofer authors valid-looking frames carrying lying
   ephemeris and time. Mitigation: a total, panic-free decoder that never trusts an
   air-supplied length/count to size an allocation, discards parity-failing subframes, and
   marks undecoded fields absent rather than guessing them.
3. **The solved fix itself** — even a cleanly decoded, self-consistent solution can be a
   spoofer's fabrication. Mitigation: the fix is never emitted without an integrity verdict
   (`PowerAnomaly`, `ClockAnomaly`, `PositionJump`, `SqmDistortion`, cross-constellation
   disagreement), and a check that cannot be performed reports `unavailable`, never a false
   "clean". A run that acquires nothing returns an honest no-fix / `PluginError::Empty`,
   **never a fabricated position** — the degenerate-case discipline is a safety property
   here, not just tidiness.

The default build is `unsafe`-free and egress-free; `unsafe` (device FFI) and any network
transport live only behind off-by-default features. Passive does not mean trusted input:
"passive" means the danger is a crash/hang on decode or a silently-accepted forged fix —
both of which the totality + integrity disciplines close.

## Architecture

```
   CLI: gnss fix <capture>            (capture = path to IQ file; NO gate, NO grant)
        │
        ▼
   registry.dispatch("gnss", &cmd)                 Plugin trait (never ActivePlugin)
        │  verb guard: "fix"
        │  source ← IqFileSource(cmd.arg)  ── blank arg → InvalidInput · named file fails to open/read → Backend ──► Err
        ▼
   ┌──────────────────── SdrSource (RX-only trait; reused from phonetool-sdr-rx) ─────────┐
   │  IqFileSource            GnssSdrSource(feat, Tier-B gnss-sdr)   DeviceSource(feat,FFI) │
   │  recorded/synth IQ   ── device paths: OFF BY DEFAULT, snap in at the seam ──          │
   └───────────────────────────────┬──────────────────────────────────────────────────────┘
        │  read_block(): IQ samples, bounded by SAMPLE_CAP (truncate, never trust len)
        ▼
   acquire (PRN × Doppler × code-phase search)  ──► Vec<AcquiredSv>{ prn, code_phase, doppler, cn0 }
        │
        ▼
   track (code/carrier loops)  ──► per-SV observables{ E/P/L correlators, carrier phase, cn0(t) }
        │                                                            │
        ▼                                                            │ (observables feed integrity)
   navmsg::decode (TOTAL over untrusted bits; parity-gated)          │
        │  subframe parity fail → field discarded (never trusted)    │
        ▼                                                            │
   pvt::solve  ──► Fix{ pos, time, vel?, quality }  |  fix: null     │
        │            (no fabricated / stale position on solve fail)  │
        ▼                                                            ▼
   integrity::assess(observables, fix?, baseline?)  ── grounded detector families ──►
        │   SPOOF: PowerAnomaly · ClockAnomaly · PositionJump · SqmDistortion ·
        │          CrossConstellationDisagreement · [SingleSourceGeometry = UNAVAILABLE, single-antenna]
        │   JAM:   NoiseFloorElevation · AgcAnomaly(if source reports AGC) · SimultaneousLossOfLock
        │   (thresholds = CONFIG, grounded/deferred — no literals here)
        ▼
   degenerate discipline:
        │  nothing observed (0 SV, no fix, no flag)        → PluginError::Empty  (failure)
        │  fix solved (even if flagged spoofed)            → Ok(Event){ fix, flags }
        │  no fix BUT a jam/spoof flag raised              → Ok(Event){ fix:null, flags }
        │  no fix but SVs acquired                         → Ok(Event){ fix:null, svs }
        ▼
   CaptureBus.record_event(event) + CaptureRef{ kind: Iq, path }   ← bulk IQ never inlined

   ── Tier-B alternative (subprocess-ipc-contract) ──────────────────────────────────────
   GnssRx (or a SubprocessPlugin) ──► gnss-sdr flowgraph child
        CONTROL: length-prefixed JSON (Command → Event)   [gate stays Rust-side; N/A here — Passive]
        DATA:    bulk IQ out-of-band by handle ──► CaptureRef{ Iq, path }
```

## Modules

- **`source`** — *not defined here.* GNSS reuses the `SdrSource` trait, `IqFileSource`,
  `SampleBlock`, and `SAMPLE_CAP` from `phonetool-sdr-rx`, and the off-by-default
  FFI-quarantine crate for device sources. The only GNSS-specific source is the Tier-B
  `GnssSdrSource` (a `gnss-sdr` child), behind a feature. The seam is the sole thing that
  distinguishes TODAY (file) from the device future (radio).
- **`acquire`** — the coarse (PRN × Doppler × code-phase) search over an IQ block. Pure,
  source-free, testable against a synthetic IQ vector. Emits `AcquiredSv { prn, code_phase,
  doppler, cn0 }`. GPS L1 C/A Gold-code generation is a grounded constant set (IS-GPS-200).
- **`track`** — per-SV code/carrier tracking loops producing the time-series observables
  (Early/Prompt/Late correlators, carrier phase, C/N0 over time) that both PVT and the
  integrity detectors consume. Pure DSP; no I/O.
- **`navmsg`** — the total, parity-gated navigation-message decoder: subframe framing, GPS
  parity check, ephemeris/clock/TOW field extraction. Every field is `Option`-typed
  (absent on decode/parity failure); no field is admitted without passing parity. Adversary
  input; no panic, no unchecked index, no trusted length.
- **`pvt`** — the position/velocity/time solve from pseudoranges + valid ephemeris. Returns
  `Some(Fix)` on convergence with sufficient geometry, `None` otherwise — **never a
  fabricated or carried-forward position.** `Fix` carries a solve-quality indicator (SV
  count + a geometry metric).
- **`integrity`** — the defensive core: the spoof and jam detector families over the
  observables (+ optional `Fix`, + optional operator baseline). Emits
  `Vec<IntegrityFlag>` with `IntegrityKind` and evidence, plus an `unavailable` marker per
  check it could not perform. **All thresholds are `IntegrityConfig` inputs, grounded or
  deferred — no literals.**
- **`lib` (`GnssRx`)** — the `Plugin` boundary: verb guard, source selection, `GnssConfig`
  (constellation set, `SAMPLE_CAP`, acquisition threshold, `IntegrityConfig`, optional
  baseline), the degenerate-case discipline, and `Event` assembly with `CaptureRef`
  emission for bulk IQ.

## Design decisions

### Reuse the `phonetool-sdr-rx` source seam; do not re-invent it

`phonetool-sdr-rx` owns the device-agnostic RX abstraction (`SdrSource`, `IqFileSource`,
`SAMPLE_CAP`, the FFI-quarantine crate). GNSS is another consumer of the *same* seam, not a
new one. This keeps one hardware-arbitration story for every `RfRx` capability, one
`IqFileSource` file-format decision, and one FFI-quarantine crate — and it is the direct
a design rule: a GNSS-specific `IqSource` would be a parallel type the task forbids.
GNSS adds only what is GNSS-specific: acquisition, nav decode, PVT, and integrity.

### `Passive`, `Plugin` not `ActivePlugin` — and why it is load-bearing

Receiving and decoding GNSS is observation; it transmits nothing. So `GnssRx` implements
`Plugin`, is handed no gate, and never references a `Grant`/`TxGrant`. This is the same
stance as sdr-rx and cell-survey, and the counterpart to sip (the thing that transmits and
is always gated). The two-trait split means the crate that *decodes* a nav message has, by
construction, no code path to *transmit* one — GNSS spoofing (transmitting forged L1) would
be an Axis-B `RfTx` capability in a different layer entirely, which this crate cannot reach.

### The fix is never trusted without an integrity verdict

The load-bearing product decision: `GnssRx` never emits a position without the accompanying
spoof/jam assessment. A fix and its integrity flags travel together in one `Event`; a fix
flagged as spoofed is still returned (with the spoof verdict as its payload) so the operator
sees *both* the solution and the reason to distrust it. This is what makes the layer a
defensive instrument rather than a naive receiver.

### Spoof/jam detector families (grounded), thresholds deferred

The detector families below are drawn from the GNSS-security literature (the direction to
cite at build time is an Open Question). Each is named and its *evidence* is defined; **no
numeric threshold is stated here.**

- **`PowerAnomaly`** — abnormally high, or suspiciously uniform, C/N0 across SVs (a spoofer
  transmitting all replicas at one power tends to produce unnaturally even, elevated C/N0).
- **`ClockAnomaly`** — a receiver clock-bias/-drift discontinuity inconsistent with an
  oscillator's physical behavior.
- **`PositionJump`** — a position/velocity discontinuity implausible for the platform,
  measured against an operator baseline (a last-known good or surveyed static position).
- **`SqmDistortion`** — Signal-Quality-Monitoring correlator-shape metrics distorting as an
  authentic and a spoofed peak interact during a capture/lift-off attack.
- **`CrossConstellationDisagreement`** — PVT solutions from independent constellations
  disagreeing beyond tolerance (harder to spoof every constellation consistently).
- **`NoiseFloorElevation`** — a rise in in-band power / noise floor (jamming).
- **`AgcAnomaly`** — a front-end AGC deviation (jamming); **available only from a live
  device source that reports AGC** — `unavailable` on a plain IQ file.
- **`SimultaneousLossOfLock`** — all tracked SVs losing lock together, which a genuine
  outage rarely produces (jamming or a spoofing takeover).
- **`SingleSourceGeometry`** (AoA) — the strongest single-receiver spoof tell, but
  **`unavailable` on any single-stream source** — see the known gap below.

Every threshold, weight, and confidence cutoff is an `IntegrityConfig` input. Where a value
is not grounded in a cited reference at build time, the detector reports `unavailable`
rather than firing on an invented number — the same "grounded-or-deferred" discipline
ss7/cell-survey take with protocol constants.

### `unavailable` is a first-class result, distinct from "clean"

A detector that cannot run (no baseline supplied, no AGC from the source, no multi-antenna
for AoA) reports `unavailable`, **never** a negative result. Reporting "no spoofing" for a
check that could not be performed would be a false assurance — the exact degenerate failure
this project forbids, applied to the integrity layer. The operator sees precisely which
defenses were and were not exercised.

### Degenerate = failure; no-fix-with-a-detection = success

Three outcomes, deliberately not conflated (mirroring sip / sdr-rx / cell-survey):

- **Nothing observed** — zero SV acquired, no fix, and no integrity signal — is a
  degenerate run and returns `PluginError::Empty`. A useless run is a failure the operator
  sees, not an empty success mistaken for "no threat."
- **No fix but a jam/spoof detected** is a **success** (`Ok(Event)`, `fix: null`, flags):
  the detection is exactly the defensive result the operator wanted, and a denied fix
  diagnosed as jamming is more useful than a bare "no fix."
- **A fix solved** (even one flagged as spoofed) is a success carrying the fix and its
  verdict. And critically, an honest no-fix is **never** a fabricated position.

### Tier-B (`gnss-sdr`) primary vs Tier-A native acquisition — recommendation, not decision

Two viable paths to a live/complete GNSS receiver, argued here and surfaced as an Open
Question rather than silently chosen:

- **Tier-A native (Rust acquisition + track + decode + PVT):** in-process, one language,
  no subprocess. Cost: reimplementing a full software GNSS receiver — acquisition search,
  tracking loops, nav decode, and a PVT solver — is a wide, error-prone DSP/estimation
  surface. Feasible for the *ahead-of-hardware acquisition proof* over a file; a complete
  multi-constellation receiver is a large build.
- **Tier-B (`gnss-sdr` child), the recommended primary for the live/complete path:**
  `gnss-sdr` is a mature open software GNSS receiver with acquisition, tracking, decode,
  and PVT for multiple constellations. Drive it as a child over the
  `specs/subprocess-ipc-contract` seam — control frames as length-prefixed JSON
  `Command`/`Event`, **bulk IQ out-of-band by handle** recorded as `CaptureRef { Iq, path }`.
  This layer being `Passive`, the "gate stays Rust-side" rule is trivially satisfied (there
  is no gate), but the framing/bounds/untrusted-child-output stance of that contract still
  applies to every frame the child returns — a `gnss-sdr` result is adversary-adjacent
  input like any other.

**Recommendation:** Tier-B (`gnss-sdr`) primary for the complete/live receiver and
multi-constellation breadth; a Tier-A native `acquire` stage over `IqFileSource` as the
ahead-of-hardware proof that the software pipeline is correct before any antenna exists.
The **integrity layer is native Rust in both cases** — the spoof/jam assessment is the
value this project adds on top of whatever produces the observables, and it must not be
outsourced to the child. The operator decides whether native track/PVT is ever worth
building or whether Tier-B is the sole live path (Open Question).

## Known architectural gap: no multi-antenna / AoA source seam (the strongest spoof tell)

Angle-of-arrival discrimination — noticing that every "satellite" arrives from one
direction — is the strongest single-receiver anti-spoof method, and it is **unreachable
through the current seam.** The `SdrSource` trait yields one IQ stream and the `RfRx`
transducer names one receive port; AoA needs a **multi-antenna / multi-channel** front end
(coherent multi-stream capture). There is no type in the RX seam that expresses this today.

Consequence, stated plainly rather than hidden: on any single-stream source, the
`SingleSourceGeometry` / AoA detector reports **`unavailable`**, and the layer must not
present its remaining (power/clock/position/SQM/cross-constellation) detectors as a complete
anti-spoof suite. They are a defense-in-depth set with a known blind spot.

**Recommendation (not a silent decision):** introduce a multi-stream RX capability as an
*optional* extension of the `phonetool-sdr-rx` source seam — e.g. a distinct
`MultiChannelSource` trait or a channel-count parameter on `SdrSource` — rather than
bolting a second antenna concept into GNSS alone, since AoA benefits cell-survey and sdr-rx
too. Whether that lands as an sdr-rx seam extension, a distinct downstream layer, or a
deferral is **an Open Question for the operator.** Until it exists, AoA is `unavailable` and
honestly reported as such (Requirement 6.5 / 10.2).

A second, related seam is unresolved: how registry `RfRx` **exclusivity** (a Rust-side
claim on the one receive port) governs a `gnss-sdr` **child process** that physically holds
the SDR — the same open seam cell-survey records. It is a prerequisite for the live Tier-B
path and an Open Question, because the Tier-B `SubprocessPlugin` does not exist yet.

## Error handling

One error vocabulary at the boundary: `PluginError` (the trait's enum). A blank/absent
`arg` with no live source configured maps to `PluginError::InvalidInput` before any DSP.
A named file that fails to open/read, a source that cannot supply the GNSS band's
rate/frequency, or a device-absent condition map to `PluginError::Backend`. An
unsupported verb maps to `PluginError::Unsupported`. A run that observed nothing usable maps to `PluginError::Empty`
(degenerate). Internal decode errors (a parity-failing subframe, a malformed field) never
escape `navmsg::decode` — they become absent fields and, at worst, a no-fix, not a run
abort or a panic. The acquisition, decode, PVT, and integrity paths are total: no
`unwrap`/`expect`/unchecked index, no panic on any input of any length — enforced by
`unsafe_code = forbid` and the workspace deny-lints on the default (non-FFI) crates, and
mandatory here because the nav-message surface is adversary-authored.

## Testing strategy

- **Offline acquisition (no hardware):** synthesize a known GPS L1 C/A IQ vector (a chosen
  PRN at a known code phase and Doppler) into an `IqFileSource`; assert `acquire` detects
  the correct PRN with code phase/Doppler within tolerance and a plausible C/N0. This is the
  ahead-of-hardware proof the software pipeline is correct before any antenna exists.
- **Nav-message hostile-input (table-driven):** empty, truncated subframe, parity-failing
  subframe, out-of-range field, a length/count field far beyond the buffer, and a giant
  input — each maps to absent fields / a decode-miss / the exact `PluginError` **without
  panic or over-allocation**, and no parity-failing subframe's fields are ever admitted.
- **PVT honesty:** a geometry with too few SVs / insufficient ephemeris → `fix: null` and
  no position value; a solvable geometry → a `Fix` with a real quality indicator; assert no
  stale/fabricated position is ever emitted on solve failure.
- **Spoof-detection fixtures:** synthetic captures exhibiting each grounded family — an
  elevated/uniform-C/N0 set (`PowerAnomaly`), a clock discontinuity (`ClockAnomaly`), an
  implausible position jump vs a baseline (`PositionJump`), an SQM distortion — each firing
  the expected `IntegrityFlag` at a *configured* threshold (thresholds injected by the test,
  never hardcoded in the library).
- **Jam-detection fixtures:** an elevated-noise-floor capture (`NoiseFloorElevation`) and an
  all-SV simultaneous loss-of-lock (`SimultaneousLossOfLock`) each firing with **no fix
  obtained** → `Ok(Event)`, `fix: null`, the jam flag present (assert this is *not*
  `PluginError::Empty`).
- **`unavailable` honesty:** a single-antenna source → `SingleSourceGeometry`/AoA reported
  `unavailable`; a no-AGC file source → `AgcAnomaly` `unavailable`; a run with no baseline →
  `PositionJump` `unavailable` — assert none is reported as "no spoofing."
- **Degenerate discipline:** a zero-sample source, and a samples-but-nothing-usable source →
  `PluginError::Empty`; assert it is distinguished from the no-fix-with-a-detection success.
- **Passive invariant:** a compile-level check/test that `GnssRx` implements `Plugin` and
  not `ActivePlugin`, and that no path references `Grant`/`TxGrant`.
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]` since
  the no-panic discipline binds library code, not assertions.

## Open questions for operator

1. **Multi-antenna / AoA anti-spoof seam (the known gap).** The strongest single-receiver
   spoof discriminator (`SingleSourceGeometry` / AoA) needs a multi-channel front end the
   single-stream `SdrSource` seam cannot express. Recommended direction: add an *optional*
   multi-stream RX capability to the shared `phonetool-sdr-rx` seam (it benefits cell-survey
   and sdr-rx too), not a GNSS-only antenna concept. Confirm the direction, or decide to
   defer AoA entirely and ship the power/clock/position/SQM/cross-constellation set with the
   blind spot documented. Not decided here.
2. **Spoof/jam threshold grounding — source of truth.** Every numeric bound (C/N0 floors,
   AGC deviation, position/velocity-jump limits, clock-drift limits, SQM cutoffs,
   simultaneous-loss-of-lock fraction/timing, scoring weights) is deferred to configuration
   and build-time calibration. Which GNSS-security references should the `IntegrityConfig`
   defaults be grounded in, and against what recorded/synthetic captures should they be
   calibrated? No threshold is stated in this spec pending that decision.
3. **GPS L1 C/A signal-parameter grounding.** Carrier/code/nav-bit parameters and the
   Gold-code / subframe / parity definitions must be grounded in **IS-GPS-200**. Is that ICD
   (or a citable open derivation of it) the accepted grounding source, and is the first cut
   GPS-L1-C/A-only with GLONASS/Galileo/BeiDou (each needing its own grounded ICD) as later
   extensions?
4. **Tier-B (`gnss-sdr`) primary vs native Tier-A receiver.** Recommended: `gnss-sdr` child
   over the subprocess-IPC contract as the complete/live path; native Rust `acquire` over
   `IqFileSource` as the ahead-of-hardware proof; **integrity native in both cases.**
   Confirm, or decide whether a native track/PVT is worth building or Tier-B is the sole live
   path. This shapes how far `acquire`/`track`/`pvt` grow natively.
5. **`RfRx` exclusivity vs a device-holding child.** How does the registry's `RfRx`
   exclusive claim (Rust-side) govern a `gnss-sdr` child that physically holds the SDR? The
   Tier-B `SubprocessPlugin` does not exist yet; this seam is shared with cell-survey and is
   a prerequisite for any live path. Recommended: resolve it once, at the subprocess-IPC
   layer, for all `RfRx` Tier-B capabilities. Deferred.
6. **Baseline provenance.** Several spoof detectors (`PositionJump`, `ClockAnomaly`) need an
   operator-supplied reference — a last-known good position, a surveyed static location, an
   independent time source. Where does the baseline come from, how is it supplied to a
   `"fix"` run, and what does the layer do when none is available (recommended: mark the
   baseline-dependent checks `unavailable`, per Requirement 6.5)?
7. **IQ file format (inherited from sdr-rx).** GNSS reads whatever `IqFileSource` reads
   (raw interleaved `cf32`/`cs16`, SigMF, or a GNU Radio file-sink format). This is an
   sdr-rx Open Question; GNSS only adds that a GNSS capture must also carry (or be told) its
   center frequency and sample rate so acquisition can target the right band — where these
   are absent or implausible, the run is `PluginError::Backend`, not a guess.
8. **`SAMPLE_CAP` vs acquisition dwell.** GNSS acquisition needs enough coherent/non-coherent
   integration time to pull a weak SV out of the noise, which can conflict with a small
   `SAMPLE_CAP` on a handheld SBC. What is the right cap, and when a capture exceeds it, is
   the right behavior head-truncate, window-and-page, or a GNSS-specific integration budget?
   (Truncate is the inherited safe default; GNSS may need a larger or paged budget — deferred.)
9. **Multiple `RfRx` plugins co-register (RESOLVED, spine sprint).** `is_exclusive(RfRx)` is
   now `false` — `RfRx` is a shareable logical medium, so gnss, sdr-rx, and cell-survey all
   `register()` in one registry, including on the hardware-free `IqFileSource` path. Resolved
   by making `RfRx` shareable (the `Ip` fix, treating the transducer as a logical medium, not
   the one physical dongle) rather than modeling device identity in the index; physical-device
   identity is instead arbitrated at the Tier-B subprocess-host seam. This was distinct from
   Open Question 5 (a device-holding `gnss-sdr` child), which remains open: OQ5 is about the
   *live radio*, this was about *co-registration with no radio present*.
