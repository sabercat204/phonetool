# Tasks — phonetool-cell-survey

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

> **BUILT IN SPRINT (cell-survey) (0.12.0): the GSM path, end-to-end.** Tasks 3, 4, 5,
> 8, 9, 10, 11, 12, 14, 15, 16 are `[x]`. Task 2 (recorded format) is DONE for GSM
> (GSMTAP-over-pcap chosen + grounded), undecided for LTE/NR. Tasks 6, 7
> (`decode_lte` / `decode_nr`) are `[~]` — **type + seam only**, decoder unbuilt (SIB1 is
> ASN.1 UPER + PHY-layer sync; hand-rolling UPER from memory is the confabulation the project
> forbids, and OQ3 has fixed no recorded LTE/NR source). Task 1 (thresholds) is `[~]` — the
> numeric-threshold *plumbing* is built (injected `Thresholds`, no `Default` cutoff), but the
> cited values remain unsourced (OQ1); the four categorical detectors that need no number run
> today. Task 13 (hostile-input) is DONE for GSM, N/A for LTE/NR (their decoders are `None`).

- [~] 1. **Prerequisite (Open Question 1): ground the detection thresholds.** Cite
  IMSI-catcher-detection research (SnoopSnitch / SRLabs, AIMSICD, academic literature) for
  signal-geometry bounds, the LAC/TAC re-registration heuristic, the RAT-downgrade trigger,
  and per-flag confidence cutoffs. No numeric threshold is written until sourced.
  **DONE:** the injection plumbing — `Thresholds` has NO `Default` cutoff; an absent
  threshold *skips* its check (`SignalGeometryImplausible`, `RatDowngrade`), never runs a
  guessed number; confidence is `None` without an injected weight. **NOT DONE:** the cited
  numeric values (still OQ1). The four purely-categorical detectors (`UnexpectedPlmn`,
  `ForcedReregistration`, `MissingNeighbours`, `DuplicateIdentity`) need no number and run now.
  _(Req 6.5)_
- [~] 2. **Prerequisite (Open Question 3): fix the recorded-capture format(s)** for the
  hardware-free today-path. **DONE (GSM):** GSMTAP-over-pcap (`LINKTYPE_GSMTAP_UM = 217`),
  grounded against libosmocore + tcpdump. **NOT DONE (LTE/NR):** no recorded source decided;
  blocks tasks 6/7.
  _(Req 2.1, 2.2)_
- [x] 3. `CellSurvey` skeleton + manifest: name `"cell-survey"`, `Transducer::RfRx`,
  `CapabilityClass::Passive`; implements `Plugin` (never `ActivePlugin`; compile-fail doctest);
  verb guard → `"survey"` else `Unsupported`. Registered on the shell; `plugins` lists
  `cell-survey [RfRx/Passive]`.
  _(Req 1.1, 1.2, 1.3, 1.5)_
- [x] 4. `source` module: `CaptureSource` trait + `SourceError`
  (`NotFound`/`Unreadable`/`TooLarge`/`LiveUnavailable`); `FileCaptureSource` with a bounded
  (`Read::take` to `DEFAULT_BYTE_CAP`) read of a GSMTAP-over-pcap capture (never slurps
  unbounded). Total pcap+GSMTAP walk. `LiveCaptureSource` present as an unwired seam.
  _(Req 2.1, 2.2, 2.5, 7.4)_
- [x] 5. `decode_gsm`: `GsmCell` + total SI3/SI2 decoder → MCC, MNC, LAC, CID, ARFCN,
  neighbour ARFCN list (bit-map-0 only; other formats flagged `neighbours_undecoded`, never
  fabricated). Malformed/truncated block → decode miss / absent field, never panic;
  air-supplied lengths bound-checked. Constants grounded (libosmocore, Wireshark, TS 24.008).
  _(Req 3.1, 3.2, 3.3, 4.1, 4.4)_
- [~] 6. `decode_lte`: `LteCell` + total MIB/SIB decoder → PCI, EARFCN, TAC, PLMN, band.
  **SEAM ONLY:** `LteCell` type + `decode()` boundary shipped; decoder returns `None`. SIB1
  is ASN.1 UPER + PHY-layer sync; blocked on OQ3 (no recorded source) and a grounded UPER
  path. Not fabricated.
  _(Req 3.1, 3.2, 3.3, 4.2, 4.4)_
- [~] 7. `decode_nr`: `NrCell` + total SSB/MIB/SIB1 decoder → PCI, GSCN, PLMN, TAC.
  **SEAM ONLY:** `NrCell` type + `decode()` boundary shipped; decoder returns `None`. Same
  UPER/PHY gap as LTE, plus OQ8 (SA/NSA, FR1/FR2 scope). Not fabricated.
  _(Req 3.1, 3.2, 3.3, 4.3, 4.4)_
- [x] 8. `cellmap` module: `CellMap`, per-RAT `CellId`, neighbour-graph build; retains
  conflicting observations of one identity rather than overwriting (identical ones deduped).
  Undecoded-format neighbour list is NOT recorded as a "no neighbours" edge. `CellEntry`
  serializable projection (enum keys can't be JSON object keys).
  _(Req 3.4, 5.1, 5.2, 5.3)_
- [x] 9. `detect` module: `AnomalyKind` (`UnexpectedPlmn`, `ForcedReregistration`,
  `RatDowngrade`, `MissingNeighbours`, `SignalGeometryImplausible`, `DuplicateIdentity`),
  `AnomalyFlag { kind, evidence, confidence }`, `Baseline`, `Thresholds` (injected, no
  hardcoded value), `scan`. Advisory only — emits flags, takes no on-air action.
  _(Req 1.4, 6.1, 6.2, 6.3, 6.4, 6.6, 6.7)_
- [x] 10. `lib` wiring: `dispatch` → source select → per-segment RAT dispatch → `cellmap::build`
  → `detect::scan`; degenerate discipline (0 cells → `PluginError::Empty` naming the source);
  `Event` data carries decoded results only, plus explicit `rats_decoded`/`rats_seam_only`.
  _(Req 2.5, 7.3, 8.1, 8.2, 8.3)_
- [x] 11. `CaptureRef` emission: the CLI records `CaptureRef { kind: Pcap, path }` on the
  `CaptureBus` after a successful survey; the survey `Event` carries only decoded cells (a
  test asserts the raw `payload` never appears in `Event` data).
  _(Req 7.1, 7.2)_
- [x] 12. Recorded-capture end-to-end test (hardware-free): synthetic GSMTAP-over-pcap drives
  `dispatch` through decode → map → detect; asserts cell fields, neighbour edges, and the
  zero-cell degenerate `Empty` (+ CLI smoke test exits 1 on an empty capture).
  _(Req 2.1, 4, 5, 6, 8)_
- [~] 13. Per-RAT decoder hostile-input tables. **DONE (GSM):** empty / header-only / truncated
  SI3+SI2 / over-long / out-of-range / non-RR / unknown-MT / 4 KiB garbage → decode miss or
  absent field, never panic; pcap-layer hostile tests (bad magic, wrong link-type, truncated
  record, non-Um frame). **N/A yet (LTE/NR):** their decoders are `None` — nothing to fuzz.
  _(Req 3.2, 3.3, 3.4)_
- [x] 14. Detector unit tests: baseline + synthetic `CellMap` → expected flag per category;
  clean map → zero flags; thresholds injected; skipped-without-threshold proven; empty baseline
  does not fabricate `UnexpectedPlmn`; undecoded neighbours do not trigger `MissingNeighbours`.
  _(Req 6.1–6.4, 6.7)_
- [x] 15. Compile clean under `unsafe_code = forbid` + workspace no-panic deny-lints;
  `clippy --all-targets` clean (crate carries no new warnings); `fmt` clean; default build
  adds zero egress deps (`cargo tree -e no-dev` shows no `reqwest`).
  _(Req 10.1, 10.3)_
- [x] 16. Docs + version: `specs/cell-survey/` triple; VERSION + `[workspace.package]` bumped
  to 0.12.0 together; STATE.md updated with the passive-RX survey + advisory-
  detector stance, the GSM-real / LTE-NR-seam split, and the recorded-vs-live boundary.
  _(Req 1, 2)_

## Deferred (behind the device seam / later sprints)

- **Gap 1 — `LiveCaptureSource` (Tier-B live scan).** Depends on the unbuilt
  `SubprocessPlugin` of `specs/subprocess-ipc-contract/`. Prerequisite: that contract is
  built. Recommended: gate behind an off-by-default `live` Cargo feature (Open Question 4).
  _(Req 2.3, 2.4, 9.2)_
- **Gap 2 — `RfRx` claim vs. child-held SDR.** Resolve how the Rust-side exclusive claim
  governs a child process that physically opens the device (Open Question 5) before the live
  path ships.
  _(Req 9.1, 9.4)_
- **Gap 3 — active rogue-BTS countermeasure.** Out of scope: would be an Axis-B transmit
  needing a `&TxGrant` trait that does not exist. If ever pursued, a separate explicitly gated
  layer (Open Question 6).
- **SDR/DSP FFI crate** (e.g. `soapysdr`) — the only `unsafe` surface, quarantined in its own
  crate behind an off-by-default feature; not in the default decode path.
  _(Req 10.2)_
- **Baseline sourcing** (OpenCellID / MLS / regulator PLMN list / prior-survey snapshot) —
  Open Question 2.
- **5G NR SA vs NSA and FR1 vs FR2 scope** — Open Question 8.
