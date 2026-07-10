# Tasks — phonetool-sdr-rx

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

**DESIGN-ONLY this sprint — nothing below is built.** The checklist is the build
plan for when this layer is scheduled; every item is unchecked.

- [ ] 0. **Prerequisite / gap resolution:** resolve Open Questions 1 (Tier-B vs
  Tier-A native demod) and 2 (which DSP numeric constants need grounding in real
  references before any DSP is written). No `dsp` code lands until the constants it
  needs are grounded or explicitly parameterized, never confabulated.
  _(gates Req 6, 7, 8)_
- [ ] 1. `source` module: `SdrSource` trait (RX-only — `read_block` + `tuned()`, no
  transmit method), `SampleBlock` (bounded owned complex-sample buffer + rate +
  center), and `SAMPLE_CAP`. Drive all operations against the trait, never a concrete
  device.
  _(Req 1)_
- [ ] 2. `IqFileSource`: pure-Rust `SdrSource` reading a recorded/synthetic IQ file;
  default source, no hardware, no feature flag. Unreadable/missing path →
  `PluginError::Backend` before DSP.
  _(Req 2)_
- [ ] 3. Untrusted-IQ bounding: read into a `SAMPLE_CAP`-bounded buffer, truncate
  rather than allocate to a declared count; total, panic-free header/sample parser
  (no `unwrap`/`expect`/unchecked index) mapping every malformed input to
  `PluginError::Backend`; record truncation in the `Event`.
  _(Req 5, 9.1)_
- [ ] 4. `dsp::sweep`: PSD/periodogram → bounded `Vec<(freq, power)>`; bins derived
  from source rate + center, bin count bounded by config; zero samples →
  `PluginError::Empty`.
  _(Req 6, 5.4)_
- [ ] 5. `dsp::identify` + `classify`: energy-detect over the sweep →
  `Vec<DetectedSignal>{center, bandwidth, power}`; config threshold (NOT a
  hard-coded literal); `Modulation::Unknown` when no confident label; analyzed-but-
  quiet → `Ok(Event)` with zero detections.
  _(Req 7, 9.4)_
- [ ] 6. `dsp::demod`: `fm`/`am`/`ssb` → audio; `digital` → bounded bits; unsupported
  mode → `PluginError::Unsupported`; no demodulable samples → `PluginError::Empty`;
  recovered bits/decoded content treated as untrusted, parsed panic-free.
  _(Req 8, 9.2)_
- [ ] 7. `lib` (`SdrRx`) implements the passive `Plugin` trait: manifest
  `{ transducer: RfRx, capability: Passive }`; verb guard (sweep/identify/demod);
  `RxConfig`; degenerate discipline; NEVER references `Grant`/`TxGrant`.
  _(Req 4, 6, 7, 8, 9.3)_
- [ ] 8. Bulk-artifact out-of-band: record retained IQ as
  `CaptureRef { kind: CaptureKind::Iq, path }` and demod audio as
  `CaptureRef { kind: CaptureKind::CallAudio, path }`; keep raw samples out of every
  `Event` payload and control frame.
  _(Req 5.3, 5.4)_
- [ ] 9. CLI wiring: `sdr sweep|identify|demod <args>` → `registry.dispatch("sdr",
  &cmd)` (passive path, no gate construction, no `Grant`) → record `Event` +
  `CaptureRef` to the `CaptureBus`.
  _(Req 4)_
- [ ] 10. `phonetool-sdr-ffi` crate (OFF-BY-DEFAULT feature, the ONLY crate relaxing
  `unsafe_code = forbid`): `RtlSdrSource` (RX-only) and `HackRfSource` (TX-capable,
  driven RX-only) as `SdrSource` impls over soapysdr/librtlsdr; device-absent →
  `PluginError::Backend`, never panic.
  _(Req 1.3, 3)_
- [ ] 11. Offline pipeline tests (no hardware): synthesized known IQ (tone,
  FM-tone, two-tone SSB) → assert sweep bin, identify count/center/bandwidth, demod
  recovery. The ahead-of-hardware DSP-correctness proof.
  _(Req 2, 6, 7, 8)_
- [ ] 12. Hostile-input + degenerate tests (table-driven): empty/truncated/oversize-
  declared/mis-sized IQ → exact `PluginError` or truncate-to-`SAMPLE_CAP` without
  panic; zero-sample → `Empty` vs silence-analyzed → `Ok(Event)` zero detections;
  ambiguous → `Unknown`.
  _(Req 5, 9)_
- [ ] 13. Passive-invariant check: `SdrRx: Plugin` and NOT `ActivePlugin`; no path
  names `Grant`/`TxGrant` (compile-level assertion or trait-bound test).
  _(Req 4.1, 4.3)_
- [ ] 14. Default-graph hardening: default (no-device, no-subprocess) build compiles
  under `unsafe_code = forbid` + workspace deny-lints; `clippy --all-targets` clean;
  `fmt` clean; `cargo tree -e no-dev` shows no radio-driver/network crate; static
  aarch64-musl cross-compile unchanged.
  _(Req 3.3, 10)_

## Deferred

- **Tier-B GNU Radio child** — the recommended primary live-radio path (Open
  Question 1). Built against `specs/subprocess-ipc-contract` when the operator
  confirms Tier-B; control via length-prefixed JSON, bulk IQ out-of-band as
  `CaptureRef { Iq, path }`. Deferred until that contract is implemented.
- **Native full demod suite** (production FM/AM/SSB/digital in Rust `dsp`) — only if
  the operator decides native demod is worth building over Tier-B (Open Question 1).
- **Decoded-content layers** — any digital-mode framing, GNSS nav-message decode, or
  per-RAT cell decode. Requires real protocol docs (grounding discipline, no
  confabulation) and likely belongs in a downstream layer, not sdr-rx (Open
  Question 6).
- **IQ file format selection + SAMPLE_CAP value** — SigMF vs raw `cf32`/`cs16`, and
  the on-SBC sample ceiling + over-budget policy (Open Questions 3, 4).
- **rf-tx layer's missing `&TxGrant` trait** — out of scope here (sdr-rx is
  RX-only/`Passive`), but flagged: there is currently no plugin trait taking a
  `&TxGrant`; any transmit capability has no legal plug-in point yet. That gap is the
  rf-tx layer's prerequisite, not this one's.
