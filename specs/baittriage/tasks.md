# Tasks — phonetool-baittriage

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** Every task below is unchecked; none is started.
> This file exists so the plugin has a task list ready when the fraud-triage layer is
> scheduled. No code implements this yet.

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

- [ ] 1. **Prerequisite — resolve the known gap direction before building correlation.**
  Take the Open-Question decision on fuzzy correlation + atomic reuse: direction (A) widen
  `IntelStore` (add a scan/similarity surface + atomic `put`-if-absent) vs. (B) keep
  `IntelStore` exact-match and defer fuzzy analytics to a Tier-B out-of-process analyzer plus a
  minimal atomic `put`-if-absent. Recommendation on record: (B) + the minimal atomic
  extension. This unblocks Task 6's reuse write and Task 7's fuzzy scope.
  _(Req 8.4)_
- [ ] 2. Crate scaffold: `phonetool-baittriage` as a Tier-A native plugin. `BaitTriage { store:
  Arc<dyn IntelStore> }` with `new`; manifest name `"baittriage"`, `Transducer::Ip`,
  `CapabilityClass::Passive`. Implements the passive `Plugin` trait only (never `ActivePlugin`,
  never handed a `Gate`).
  _(Req 1)_
- [ ] 3. `ingest` module: `RawBait` serde model + `parse(arg) -> Result<RawBait, IngestError>`.
  Bounds `MAX_BAIT_BYTES` / `MAX_FIELD_BYTES` / `MAX_IOCS`; empty/whitespace → `Empty`,
  malformed JSON → `Malformed`, oversize → `TooLarge`. Total over arbitrary/non-UTF-8 bytes; no
  fetch/resolve/execute of any artifact value.
  _(Req 2)_
- [ ] 4. `extract` module: `Ioc`/`IocKind`; `iocs(&RawBait) -> Vec<Ioc>` from typed fields and
  transcript. Phone normalized via shared `Number::parse`; URL/email host and wallet lowercased
  for comparison; one bad artifact skipped, run continues. Wallets kept opaque (no per-chain
  checksum).
  _(Req 3)_
- [ ] 5. `correlate` module — assessment: `assess(store, &iocs)` doing exact-match
  `get(KNOWN_BAD_NS, ioc)` / `get(REUSE_NS, ioc)`, Store-backed `ScamPattern` classification
  (`SIGNATURE_NS`, else `Unknown`), and counted `Confidence` (0 corroboration ⇒ `Low`; never
  above `Low` without a Store-backed hit; no padding). Store error → `Backend`.
  _(Req 4, 5)_
- [ ] 6. `correlate` module — reuse-index write-back: idempotent `put(REUSE_NS, ioc, bait_hash)`
  keyed by a content hash of the bait; a failed index write still returns the assessment
  `Event` with an index-failed marker. **Depends on Task 1** (atomic-put decision).
  _(Req 8.1, 8.2, 8.3)_
- [ ] 7. `lib` (`BaitTriage`) `Plugin::dispatch`: verb guard (`"triage"`), ingest → extract →
  assess, two-tier degenerate discipline (0 IOCs → `PluginError::Empty` with the
  "no indicator extracted" message; ≥1 IOC → `Ok(Event)` with "no prior correlation" marker at
  `Confidence::Low` when nothing matched), emit `Event { source: "baittriage" }`.
  _(Req 2.1, 6)_
- [ ] 8. Capture-timeline + provenance: shell records the `Event` as
  `CaptureRecord::PluginEvent`; carry a bundle-supplied `source_capture` path
  (`CaptureRef { kind: CallAudio, path }`) as provenance without opening the recording; no bulk
  audio inlined.
  _(Req 9)_
- [ ] 9. Online enrichment behind the off-by-default `online` Cargo feature: provider-agnostic
  `enrich(endpoint, ioc)` over `reqwest`(rustls), write-through to the store, `OnlineError`
  (`Transport`/`Status`/`Cache`). Transmits only operator-selected indicators to the configured
  endpoint — never an artifact URL. Default graph links no `reqwest` (`cargo tree -e no-dev`).
  _(Req 7, 10.2)_
- [ ] 10. CLI wiring: `baittriage triage '<json bundle>'` (no `--basis`: passive path, no gate)
  → `registry.dispatch("baittriage", &cmd)` → record `Event` to the `CaptureBus`. `plugins`
  lists `baittriage [Ip/Passive]`.
  _(Req 1, 9.1)_
- [ ] 11. Tests: `tests/ingest.rs` (hostile-input table incl. "artifact URL is never
  contacted"), `tests/extract.rs` (normalization + per-artifact skip + `MAX_IOCS`),
  `tests/assess.rs` (known-bad/prior-case correlation, zero-IOC `Empty`, ≥1-IOC-no-match
  `Ok`/`Low`, backend error, idempotent reuse), `tests/enrich.rs` under `--features online`.
  Test targets `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]`.
  _(Req 2, 3, 4, 5, 6, 7, 8)_
- [ ] 12. Hardening + docs + version: compile clean under `unsafe_code = forbid` + workspace
  deny-lints in default and `--features online`; `clippy --all-targets` and `fmt` clean;
  cross-compile unchanged (no new default deps); `specs/baittriage/` triple finalized; VERSION +
  `[workspace.package]` bumped together.
  _(Req 10)_

## Deferred

- **Fuzzy / near-duplicate correlation** (look-alike domain, off-by-a-char wallet, paraphrased
  script). The current `IntelStore` is exact-match only; this is the known gap. Direction
  deferred to Task 1's decision; heavy analytics recommended out-of-process (Tier-B, behind the
  `specs/subprocess-ipc-contract/` seam — a passive subprocess needs no gate).
- **Audio → transcript (speech-to-text).** A future device-seam capability (likely Tier-B)
  turns a `CaptureRef { kind: CallAudio, path }` recording into transcript text; this crate
  ingests the text, never the audio.
- **Per-chain wallet validation.** BTC/ETH/… checksum rules to reject typo'd wallets before
  they enter the reuse index — needs real per-chain rules grounded in docs, deferred rather than
  invented.
- **Confidence cutoff tuning & pattern-signature seed corpus.** The `Low`/`Medium`/`High`
  graduation and the `ScamPattern` signatures need operator-validated seed data; the monotone
  rule ships, the numeric policy is deferred (Open Question 1, 2).
- **Reuse-index retention/privacy policy** (purge window, at-rest encryption on a seized SBC) —
  the index accumulates PII about real callers; policy deferred to the operator.
