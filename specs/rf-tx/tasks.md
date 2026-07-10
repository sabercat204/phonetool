# Tasks — phonetool-rf-tx

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

**DESIGN-ONLY this sprint — nothing below is built.** The checklist is the build plan
for when this layer is scheduled; every item is unchecked. Task 0 is a **core-crate
prerequisite** the operator must approve before any rf-tx code lands (Open Question 1).

- [ ] 0. **Prerequisite / core gap — `TxPlugin` trait + `dispatch_tx` path.** In
  `phonetool-core::plugin`, add `TxPlugin { manifest; dispatch_tx(&self, cmd: &Command,
  grant: &TxGrant) -> Result<Event, PluginError> }` — takes `&TxGrant`, never `&Grant`. In
  `PluginRegistry`, add a `tx` map, `register_tx(Arc<dyn TxPlugin>)` routed through the
  existing private `claim` helper (shared name namespace + exclusive-transducer index, so the
  exclusive `RfTx` port admits one TX plugin), `dispatch_tx(plugin, cmd, grant)`, and extend
  `manifests()` to span the third map. This is a shared-crate change; do not start rf-tx code
  until the operator approves the shape (Open Question 1) and the single-token-enum alternative
  is rejected on the record.
  _(Req 1.1, 1.3, 2)_
- [ ] 0b. **Prerequisite / grounding — resolve the numeric Open Questions.** No `bandplan`
  numbers, AFSK/CW/SSB constants, or `SAMPLE_CAP`/duration bounds are written until grounded in
  real regulatory/protocol references (Open Questions 2, 3, 5, 7). Until grounded, the relevant
  band/scheme fails closed rather than shipping an invented literal.
  _(gates Req 5.4, 7.4)_
- [ ] 0c. **Prerequisite / core gap — resolve how a second per-op parameter (freq) reaches the
  plugin.** An rf-tx operation needs both a payload and a requested frequency, but the core
  `Command` exposes one positional field `arg: String` with no defined encoding for both. Pick a
  resolution with the operator — freq into `TxConfig`, a structured/delimited `arg` encoding, or
  a second field on the core `Command` type (a shared-crate change) — before Task 8/10 are built.
  Do not silently pick an encoding (Open Question 8).
  _(gates Req 5.1, 8; blocks Task 8, 10)_
- [ ] 0d. **Prerequisite / core gap — public `CaptureRef` writer on `CaptureBus`.** Recording a
  rendered waveform as a `CaptureRef` (Task 9) has no core support today: `CaptureRecord::CaptureRef`
  is a genuine type but `#[allow(dead_code)]`, and `CaptureBus` exposes only `record_event(Event)` —
  no public method records a `CaptureRef`. Add a small public capture-recording method on
  `CaptureBus` in `phonetool-core`. Shared-crate change; systemic — sdr-rx, cell-survey, gnss, ss7,
  and legacy-hw assume the same writer, so design it once for all bulk-artifact producers.
  _(blocks Task 9; Req 4.3)_
- [ ] 1. `modulate` module scaffold: pure, sink-free, grant-free `modulate(scheme, payload,
  cfg) -> Result<Waveform, ..>`; `Waveform` (bounded owned sample buffer + rate); `SAMPLE_CAP`
  render bound. Drive the whole pipeline against `Waveform`, never a device.
  _(Req 4.1, 7.5)_
- [ ] 2. `modulate::cw`: text → on-off-keyed CW at a configurable WPM; dit/dah timing from a
  grounded ITU ratio (Task 0b). Empty text → zero samples (feeds the degenerate discipline).
  _(Req 7.1)_
- [ ] 3. `modulate::afsk`: AX.25/APRS frame → Bell-202 1200-baud AFSK; framing (flag,
  bit-stuffing, FCS) and mark/space tones from grounded constants (Task 0b).
  _(Req 7.2)_
- [ ] 4. `modulate::fm` + `modulate::ssb`: input audio → FM / SSB waveform; SSB filter/sideband
  from grounded parameters (Task 0b).
  _(Req 7.3)_
- [ ] 5. `payload` module: per-scheme boundary validation — CW encodable-character set, AX.25/
  APRS frame validation, input-audio reader; all parsers total and panic-free; bad payload →
  exact `PluginError` before any render; unsupported verb → `Unsupported`.
  _(Req 6)_
- [ ] 6. `bandplan` module: `BandPlan` (band → freq range + regulatory power ceiling),
  `check(band, freq, power_dbm)` → `BandError` (`FreqOutOfBand`/`OverPower`/`UnknownBand`);
  fail-closed on unknown band; contents are grounded constants (Task 0b), the module ships only
  the mechanism.
  _(Req 5)_
- [ ] 7. `sink` module: `TxSink` transmit-only trait (`key(&Waveform)` + tuning, NO receive
  method) and `FileSink` (pure Rust, default, writes waveform to a path, NO emission).
  _(Req 3.2, 10.1)_
- [ ] 8. `lib` (`RfTx`) implements `TxPlugin`: manifest `{ transducer: RfTx, capability:
  RfTx }`; verb guard (cw/afsk/fm/ssb); read band/power/license from the `TxGrant` (NEVER cmd);
  run `bandplan::check` BEFORE sink selection; drive `modulate`; degenerate discipline (0
  samples → `Empty`, never key a sink with dead air); one transmit per call, never auto-repeat;
  select `FileSink` by default. `TxConfig` (WPM, rate, `SAMPLE_CAP`, output path).
  _(Req 1.2, 1.5, 5.5, 8, 9)_
- [ ] 9. Bulk-artifact out-of-band: record the rendered waveform as `CaptureRef { kind:
  CaptureKind::Iq, path }` (IQ) or `CaptureRef { kind: CaptureKind::CallAudio, path }` (audio),
  per Open Question 6; keep raw samples out of every `Event` payload and control frame; `Event`
  carries only bounded metadata (scheme, band, freq, power, samples, sink).
  _(Req 4.3, 4.4)_
- [ ] 10. CLI wiring: `rf-tx <scheme> <payload> --band <b> --power-dbm <p> --license <why>
  [--freq <hz>]` → one `CaptureBus` → `Gate::request_tx` (fail-closed on empty band/license/
  non-finite power, logs decision) → on `TxGrant`, `registry.dispatch_tx("rf-tx", &cmd,
  &grant)` → record `Event` + `CaptureRef`. Refusal ends the flow with a non-zero exit.
  _(Req 1.1, 2.3)_
- [ ] 11. `phonetool-rf-tx-ffi` crate (OFF-BY-DEFAULT feature, the ONLY crate relaxing
  `unsafe_code = forbid`): `HackRfTxSink`/`LimeTxSink`/`PlutoTxSink` as `TxSink` impls over
  soapysdr/device libs, key path additionally taking `&TxGrant` (double lock); NO RX-only
  (RTL-SDR) impl; device-absent → `PluginError::Backend`, never panic. Selecting a device sink
  in the default (no-feature) build is a compile error, not a runtime one.
  _(Req 3.1, 3.3, 3.4, 10.2, 10.3, 10.4)_
- [ ] 12. Offline modulation-correctness tests (no hardware, no gate): known payloads → assert
  `modulate` output matches a reference waveform (CW dit/dah timing, AFSK/AX.25 tones + FCS,
  FM/SSB of a known tone). The ahead-of-hardware proof; needs no `TxGrant`.
  _(Req 4.1, 7)_
- [ ] 13. Gate + enforcement tests: mint a `TxGrant` via the real `Gate::request_tx` on the
  production `CaptureBus`, drive `dispatch_tx` with `FileSink`, assert the file + `CaptureRef`;
  empty band/license → `Denied` recorded on the bus, no render; out-of-band freq / over-power /
  unknown band → `InvalidInput` BEFORE any sink work.
  _(Req 1, 5)_
- [ ] 14. Compile-fail doctest on `RfTx`: fabricating a `TxGrant` to reach `dispatch_tx` does
  not compile (Axis-B mirror of authgate/sip).
  _(Req 1.4)_
- [ ] 15. Payload hostile-input + degenerate tests (table-driven): unencodable CW char,
  malformed AX.25 frame, unreadable/oversize audio, oversize payload > `SAMPLE_CAP` → exact
  `PluginError` or refused without panic; empty text/frame/silence → `Empty` and no sink keyed;
  single-character payload → `Ok(Event)`.
  _(Req 6, 9)_
- [ ] 16. No-emission + default-graph hardening: assert the default build contains no device
  `TxSink` and the transmit path with no device feature resolves to `FileSink`; default build
  compiles under `unsafe_code = forbid` + workspace deny-lints; `clippy --all-targets` clean;
  `fmt` clean; `cargo tree -e no-dev` shows no radio-driver/network crate; static aarch64-musl
  cross-compile unchanged.
  _(Req 3, 11)_
- [ ] 17. Docs + version: `specs/rf-tx/` triple already present; on build, bump VERSION +
  `[workspace.package]` together (MINOR — new gated capability + the `TxPlugin` core addition);
  STATE.md notes that rf-tx is the first Axis-B consumer and that the default binary
  has no device sink (emission requires the feature AND a `TxGrant`).
  _(Req 3, 11.3)_

## Deferred

- **Tier-B GNU Radio TX flowgraph** — the candidate live-TX path (Open Question 4). Built against
  `specs/subprocess-ipc-contract` when the operator confirms Tier-B; control via length-prefixed
  JSON, bulk IQ handed out-of-band as `CaptureRef { Iq, path }`, **the gate obtained Rust-side
  before the child is driven** (a subprocess is never a gate bypass). Deferred until that contract
  is implemented and the tier is chosen.
- **Native device sinks (Tier-A soapysdr FFI)** — `HackRfTxSink`/`LimeTxSink`/`PlutoTxSink` in the
  FFI-quarantine crate — only if the operator chooses a native live path over (or alongside)
  Tier-B (Open Question 4). Task 11 scaffolds the shape; the actual FFI is deferred to a device
  arriving and the fleet priority being set (Open Question 5).
- **Grounded regulatory + protocol constant tables** — the `BandPlan` numbers and the AFSK/CW/SSB
  constants, sourced from real FCC/ISED and AX.25/Bell-202/ITU references (Open Questions 2, 3).
  Deferred to the grounded build; nothing numeric is confabulated.
- **ERP/EIRP power semantics + antenna note in the consent log** — whether the power ceiling is
  device-output or radiated, and what antenna metadata the consent record should carry
  (Open Question 5). Deferred.
- **Additional schemes** (PSK31, FT8/FT4, other digital modes, repeater tones/CTCSS) — beyond the
  initial CW/AFSK/FM/SSB set; each needs grounded constants and heavier gate justification.
  Revisit with the operator.
- **Single-token-enum alternative to `TxPlugin`** — recorded and rejected in `design.md` for the
  type-safety reason (it would push the Axis-A/Axis-B distinction to a runtime `match`); kept as
  an Open Question so the rejection is on the record, not silently decided.
