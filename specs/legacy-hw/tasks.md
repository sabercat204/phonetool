# Tasks — phonetool-legacy-hw

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

**DESIGN-ONLY this sprint — nothing below is built.** The checklist is the build plan for
when this layer is scheduled; every item is unchecked by construction. Tasks 0a/0b are
prerequisites that gate the active half and the grounded constants — no injection code and no
tone table lands until they are resolved with the operator.

- [ ] 0a. **Prerequisite / GATE-GAP resolution (blocks the entire active half):** resolve
  Open Question 1 with the operator — does active physical injection get a third gate axis
  (`WireGrant` via `Gate::request_wire`, a new active-wire trait taking `&WireGrant`, line-ID
  in the grant) or fold under Axis A (`Grant { target = "<line-ID>" }`)? Recommended: the
  third axis. Also decide Open Question 6 (three-point-additions vs one N-axis gate refactor).
  The decision MUST be recorded before any injection trait, token, or dispatch path is
  designed; it MUST NOT be silently chosen in code.
  _(Req 7.3, 7.4)_
- [ ] 0b. **Prerequisite / GROUNDED-CONSTANTS resolution (blocks any tone table / decoder):**
  resolve Open Questions 3–5 — the DTMF (Q.23/Q.24), MF R1, 2600-SF, and Bell-202/CID
  frequencies + frame layout source of truth; the Goertzel/FSK detection tolerances; and which
  switch-generation classes are actually in scope and their grounding source. No frequency,
  threshold, or switch behavior is populated from memory.
  _(Req 10.1, 10.2, 10.3)_
- [ ] 1. `source` module: `LineSource` trait (RX/SENSE-only — `read_block` + `describe()`,
  **no** drive/inject/seize method), `SampleBlock` (bounded owned PCM/sense buffer + rate +
  kind), and `SAMPLE_CAP`. Drive all operations against the trait, never a concrete device.
  _(Req 1.1, 5.2)_
- [ ] 2. Default pure-Rust sources: `WavFileSource` (supplied audio) and `RecordedSenseSource`
  (captured ADC/voltage series); default, no hardware, no feature flag. Missing/unreadable/
  malformed-container input → `PluginError::InvalidInput` before any DSP.
  _(Req 1.3, 2.5, 5.1, 5.2)_
- [ ] 3. Untrusted-audio bounding: read into a `SAMPLE_CAP`-bounded buffer, truncate rather
  than allocate to a declared count; total, panic-free WAV/trace header + sample parser (no
  `unwrap`/`expect`/unchecked index) mapping every malformed input to `InvalidInput`; record
  truncation in the `Event`.
  _(Req 2.3, 2.4, 2.5)_
- [ ] 4. `dsp::decode`: Goertzel bank over the **grounded** DTMF (and configured MF R1) tone
  table → ordered symbol sequence; confident-match-or-nothing (no guessed symbol); analyzed-
  but-tone-free buffer → `Ok(Event)` with zero symbols. Constants from Task 0b, never literals.
  _(Req 2.1, 2.2, 6.2, 6.3)_
- [ ] 5. `dsp::cid`: Bell-202 mark/space FSK demod → `CidFrame` (calling number, optional
  name/timestamp) with checksum/parity validation; decoded fields treated as **untrusted,
  observed-on-the-wire** structure, never a verified identity; absent/corrupt burst →
  `decoded: false` or `PluginError::Empty`, never a fabricated number.
  _(Req 3.1, 3.2, 3.3, 3.4)_
- [ ] 6. `dsp::synth`: symbol/tone spec → DTMF/MF/2600-SF PCM buffer using the **grounded**
  tone table; writes to a buffer / WAV file only, **no** path to a physical line/relay/SLIC;
  empty/all-invalid spec → `InvalidInput`. Line-inert by construction.
  _(Req 4.1, 4.2, 4.4)_
- [ ] 7. `sense` module: classify a sense `SampleBlock` → `LineState { loop_current,
  line_voltage, ring, hook }`; idle/quiet line → `Ok(Event)` reporting idle (a real result);
  empty/unreadable trace → `InvalidInput`. Remains `Passive` — no gate, no token.
  _(Req 5.1, 5.4, 5.5)_
- [ ] 8. `lib` (`LineHw`) implements the passive `Plugin` trait: manifest
  `{ transducer: Wireline, capability: Passive }`; verb guard (decode/cid/sense/synth →
  else `Unsupported`); `LineConfig`; degenerate discipline (nothing usable → `Empty`;
  malformed → `InvalidInput`); event `data` carries symbol/CID/line-state counts + truncation
  flag; NEVER references `Grant`/`TxGrant`/any wire token.
  _(Req 1.1, 1.2, 1.4, 6.1, 6.4)_
- [ ] 9. Bulk-audio out-of-band: record synthesized WAVs and any retained loop audio as
  `CaptureRef { kind: CaptureKind::CallAudio, path }`; keep raw samples out of every `Event`
  payload and control frame.
  _(Req 4.3)_
- [ ] 10. CLI wiring: `line decode|cid|sense|synth <args>` → `registry.dispatch("line", &cmd)`
  (passive path, no gate construction, no `Grant`) → record `Event` + `CaptureRef` to the
  `CaptureBus`. `plugins` lists `line [Wireline/Passive]`.
  _(Req 1.1, 1.2)_
- [ ] 11. `phonetool-linehw-ffi` crate (OFF-BY-DEFAULT feature, the ONLY crate relaxing
  `unsafe_code = forbid`): `LiveLineSource` / `RingDetectSource` (ADC + ring-detect GPIO) as
  `LineSource` impls over `gpio-cdev` / `linux-embedded-hal` (board-agnostic, NOT `rppal`);
  device-absent → `PluginError::Backend`, never panic. **No injection driver here yet** —
  blocked on Task 0a.
  _(Req 5.3, 9.1, 9.2)_
- [ ] 12. Offline decode/synth + CID tests (no hardware): `synth`→`decode` round-trips a known
  DTMF/MF/2600-SF sequence; a hand-built Bell-202 burst decodes to exact fields with a passing
  checksum. The ahead-of-hardware decoder-correctness proof.
  _(Req 2, 3, 4)_
- [ ] 13. Hostile-input + degenerate tests (table-driven): empty/non-audio/truncated/
  oversize-declared/mis-sized WAV → exact `PluginError` or truncate-to-`SAMPLE_CAP` without
  panic; corrupted-checksum CID → `decoded: false`; noise-only buffer → zero symbols; empty
  trace → `InvalidInput` vs idle trace → `Ok(Event)` idle. Spoofed-CID → reported as observed,
  never trusted.
  _(Req 2.4, 3.3, 6)_
- [ ] 14. Passive-invariant + grounded-constants guards: `LineHw: Plugin` and NOT
  `ActivePlugin`; no path names `Grant`/`TxGrant`/any wire token (compile-level assertion);
  a test asserting any un-cited frequency/threshold/CID-layout stays in the `unknown`/
  declines-to-decode state, never an invented value.
  _(Req 1.1, 10.2)_
- [ ] 15. Default-graph hardening: default (no-device) build compiles under
  `unsafe_code = forbid` + workspace deny-lints; `clippy --all-targets` clean; `fmt` clean;
  `cargo tree -e no-dev` shows no device-driver/network crate for this layer; static
  aarch64-musl cross-compile unchanged; no RNG dependency. VERSION + `[workspace.package]`
  bump on build.
  _(Req 9.3, 9.4)_

## Deferred (post-passive, needs operator decision + hardware + the gate gap closed)

- **The gate axis itself** (`WireGrant` + `Gate::request_wire` + a new active-wire trait, OR
  the Axis-A folding) — a `phonetool-authgate` + `phonetool-core` change that is the
  prerequisite for the entire active half. Blocked on Open Question 1 / Task 0a; may be
  subsumed by the N-axis gate refactor (Open Question 6). Gets its own spec triple once the
  direction is chosen — this is not a `phonetool-legacy-hw`-local change.
- **Active physical injection** (loop seizure, DTMF/MF/2600-SF drive onto a live pair, ring
  injection, drive-the-pair line characterization) — a distinct future capability, **doubly
  gated** on the chosen authorization token (`WireGrant` or Axis-A `Grant`) **and** the
  independent hardware-safety interlock; neither alone suffices. The tone-synthesis code
  (Task 6) is its inert payload today. Explicitly out of scope here.
- **The hardware-safety interlock** — an explicit, affirmative, authorization-orthogonal
  hardware-safety assertion in the FFI-quarantine crate that must precede any line drive;
  fail-closed. Trip thresholds are datasheet constants (Open Question 2), not invented. Built
  only alongside the injection driver.
- **Switch-generation-specific signalling** (per-class dial-pulse/DTMF/MF/SF/COCOT behavior for
  step-by-step, crossbar, ESS, DSS, COCOT) — requires real docs or a bench unit (grounding discipline
  discipline, no confabulation, Open Question 5). Likely a configuration/profile layer over the
  grounded tone tables, not a decode-kernel change.
- **Live-line sense hardening** beyond a basic ADC/ring-detect front end (galvanic isolation,
  over-voltage clamp characterization) — front-end-dependent, tracks Open Questions 2 and 7.
