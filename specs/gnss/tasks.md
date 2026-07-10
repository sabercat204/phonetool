# Tasks — phonetool-gnss

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

**DESIGN-ONLY this sprint. Nothing below is built** — every item is unchecked by
intent. This list is the build plan for when the layer is scheduled.

## Prerequisites (must resolve before the corresponding build item)

- [ ] P1. Ground GPS L1 C/A signal parameters, Gold-code generation, subframe framing,
  and parity against **IS-GPS-200** (or a citable open derivation). No signal parameter is
  written until grounded. _(Req 3.3, 4.3; Open Question 3)_
- [ ] P2. Decide the spoof/jam threshold grounding source and calibration captures; every
  `IntegrityConfig` numeric default stays deferred until this lands. No threshold is coded
  from a guess. _(Req 6.2, 7.5; Open Questions 2)_
- [ ] P3. Resolve the multi-antenna / AoA source-seam direction (optional multi-stream
  extension of the shared `phonetool-sdr-rx` seam vs a distinct layer vs deferral) WITHOUT
  silently deciding it. Until resolved, `SingleSourceGeometry`/AoA is `unavailable`.
  _(Req 10.1, 10.3; Open Question 1) — the known architectural gap._
- [ ] P4. Resolve how the Tier-B subprocess host arbitrates the one physical SDR for a
  device-holding `gnss-sdr` child (shared with cell-survey; belongs at the subprocess-IPC
  layer). The logical `RfRx` index is now shareable (spine sprint) and no longer the seam;
  this is device arbitration, not co-registration. Prerequisite for any live Tier-B path.
  _(Req 10.4; Open Question 5)_
- [ ] P5. Confirm the RX source seam is reused from `phonetool-sdr-rx` (`SdrSource`,
  `IqFileSource`, `SampleBlock`, `SAMPLE_CAP`, FFI-quarantine crate) — GNSS adds no parallel
  source abstraction. _(Req 2.2, 2.3, 8.3, 11.2)_

## Build plan

- [ ] 1. Crate `phonetool-gnss` skeleton: `GnssRx` type, `GnssConfig` (constellation set,
  acquisition threshold, `SAMPLE_CAP`, `IntegrityConfig`, optional baseline), manifest
  (`name:"gnss"`, `Transducer::RfRx`, `CapabilityClass::Passive`). Implements `Plugin`, NOT
  `ActivePlugin`; references no `Grant`/`TxGrant`. Verb guard: `"fix"` else `Unsupported`.
  _(Req 1)_
- [ ] 2. Wire the reused `SdrSource` seam: `IqFileSource` as the default hardware-free
  source; blank/absent arg → `InvalidInput`; named file that fails to open/read, or
  incompatible rate/frequency for the GNSS band → `Backend`. Bound reads by `SAMPLE_CAP`;
  record truncation. _(Req 2, 8.3, 8.4)_
- [ ] 3. `acquire` module: PRN × Doppler × code-phase search over an IQ block →
  `Vec<AcquiredSv>{ prn, code_phase, doppler, cn0 }`, using the P1-grounded GPS L1 C/A
  Gold codes. Zero SVs above the configured threshold → zero acquired (not fabricated).
  Pure, testable against a synthetic IQ vector. _(Req 3.1, 3.3, 3.5)_
- [ ] 4. `track` module: per-SV code/carrier loops → observables (E/P/L correlators,
  carrier phase, C/N0 time-series) for PVT and integrity. Pure DSP, no I/O. _(Req 3.2)_
- [ ] 5. `navmsg` module: TOTAL, parity-gated nav-message decoder — subframe framing, GPS
  parity, ephemeris/clock/TOW extraction. Every field `Option`; parity-failing subframes
  discarded; no `unwrap`/`expect`/unchecked index; no trusted air-supplied length. Decoded
  ephemeris/time is a *candidate*, not trusted truth. _(Req 4)_
- [ ] 6. `pvt` module: position/velocity/time solve from pseudoranges + valid ephemeris →
  `Some(Fix)` on convergence with a real quality indicator (SV count + geometry metric),
  `None` otherwise. No fabricated, interpolated, or carried-forward position on solve fail.
  _(Req 5)_
- [ ] 7. `integrity` module — SPOOFING families over observables (+ optional `Fix`, +
  optional baseline): `PowerAnomaly`, `ClockAnomaly`, `PositionJump`, `SqmDistortion`,
  `CrossConstellationDisagreement`. Emit `IntegrityFlag{ kind, evidence }`. All thresholds
  from `IntegrityConfig` (P2-grounded); an unperformable check → `unavailable`, never a
  "clean". _(Req 6)_
- [ ] 8. `integrity` module — JAMMING families, running even on a no-fix / zero-SV run:
  `NoiseFloorElevation`, `AgcAnomaly` (only where the source reports AGC; else
  `unavailable`), `SimultaneousLossOfLock`. Thresholds from config (P2-grounded). A fired
  jam detector on a no-fix run is a reportable `Ok(Event)`, not `Empty`. _(Req 7)_
- [ ] 9. `SingleSourceGeometry`/AoA detector stub reporting `unavailable` on every
  single-stream source, per the P3 gap resolution; never presents the remaining detectors as
  a complete anti-spoof suite. _(Req 6.5, 10.2)_
- [ ] 10. `lib` orchestration + degenerate discipline: fix-solved → `Ok(Event){ fix, flags }`;
  no-fix-with-a-flag → `Ok(Event){ fix:null, flags }`; no-fix-with-SVs → `Ok(Event){ fix:null,
  svs }`; nothing observed → `PluginError::Empty` (naming the source). Fix always paired with
  its integrity verdict. _(Req 1.6, 9)_
- [ ] 11. `CaptureRef` emission: record bulk IQ as `CaptureRef{ kind: CaptureKind::Iq, path }`
  on the `CaptureBus`; `Event` data carries only bounded results (SV list, fix-or-null, flag
  list), never inlined samples. _(Req 8.1, 8.2)_
- [ ] 12. CLI wired: `gnss fix <capture>` → `registry.dispatch("gnss", &cmd)` → record the
  `Event` (and the `CaptureRef`) on the one `CaptureBus`. Passive path — no gate, no `Grant`.
  _(Req 1, 2.1)_
- [ ] 13. Tier-B `GnssSdrSource`: `gnss-sdr` child over `specs/subprocess-ipc-contract`
  (control = length-prefixed JSON; bulk IQ out-of-band by handle → `CaptureRef{ Iq }`),
  behind an off-by-default feature. Child output treated as untrusted per that contract.
  Gated on P4. Integrity stays native Rust — not outsourced to the child. _(Req 2.4; Open
  Question 4)_
- [ ] 14. Optional FFI-quarantine device source (alternative to Tier-B): a live `RfRx`
  device `impl SdrSource` in the shared off-by-default FFI crate; the ONLY place `unsafe`
  is allowed; device-absent → `Backend`, never panic. _(Req 2.4, 11.2)_
- [ ] 15. Tests: offline acquisition against synthetic IQ; nav-message hostile-input table
  (no panic, no admitted parity-fail); PVT honesty (no fabricated position); per-family
  spoof + jam fixtures firing at *injected* thresholds; `unavailable` honesty (single
  antenna / no AGC / no baseline); degenerate discipline (`Empty` vs no-fix-with-detection);
  passive-invariant check (`Plugin` not `ActivePlugin`, no `Grant`). Test targets
  `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]`. _(Req 1, 4, 5, 6, 7, 9)_
- [ ] 16. Compile clean under `unsafe_code = forbid` + workspace deny-lints;
  `clippy --all-targets` clean; `fmt` clean; `cargo tree -e no-dev` shows zero egress deps
  in the default graph. `unsafe`/network only behind off-by-default features. _(Req 11)_
- [ ] 17. Docs + version: this `specs/gnss/` triple; VERSION + `[workspace.package]` bumped
  together when the layer lands; STATE.md updated (passive `RfRx` GNSS + integrity;
  offline = zero egress deps). _(Req 11.3)_

## Deferred

- **GLONASS / Galileo / BeiDou decode** — GPS L1 C/A is the first cut; each other
  constellation needs its own grounded ICD before it is added. _(Req 3.4)_
- **OSNMA (Galileo nav-message authentication)** — a cryptographic per-signal spoof
  defense; a distinct future capability once Galileo decode exists.
- **Multi-antenna / AoA anti-spoof** — blocked on the P3 seam decision; the strongest spoof
  discriminator, unreachable through the single-stream `SdrSource` seam today.
- **Native full receiver (Tier-A track/PVT for the complete/live path)** — deferred pending
  the Open-Question-4 decision; `gnss-sdr` (Tier-B) is the recommended live path, native
  `acquire` is the ahead-of-hardware proof, integrity is native regardless.
- **Anti-spoof beyond detection** (e.g. spoof-resistant re-acquisition, holdover timing) —
  out of scope; this layer detects and reports, it does not correct.
