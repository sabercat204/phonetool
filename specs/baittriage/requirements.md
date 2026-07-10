# Requirements Document — phonetool-baittriage

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** This spec fixes the shape of the fraud-caller
> footprint-triage plugin so the work is ready when it is scheduled. No code implements this
> yet; every task in `tasks.md` is unchecked.

## Introduction

`phonetool-baittriage` is a **passive, defensive** capability: given a bundle of artifacts
about a scam/vishing caller — a phone number, a claimed identity or agency, callback URLs,
crypto wallet addresses, gift-card rails, a transcript, an email — it triages them into a
structured *footprint* and a confidence-scored *risk assessment*. It is defense of others and
observation-coded: extracting indicators from artifacts the operator was handed is knowledge
work, clean under the operator's model (ingestion ≠ theft). It therefore declares
`CapabilityClass::Passive`, is handed no `Gate`, and never mints a `Grant`/`TxGrant` — the
recon path carries zero authorization friction, exactly as numintel does.

The dual-use line does not run through this crate: triaging a caller's own footprint touches
no third-party infrastructure. The one place egress could occur — optional online enrichment
(reverse-number, breach/IOC corpora) — is behind an off-by-default `online` Cargo feature
(numintel's model), and even then it transmits only the operator's chosen indicators to the
operator's chosen provider, **never** to any host or URL found inside an artifact.

**Ahead-of-hardware split (operator directive).** Everything the default build does runs
**today, with no device and no network**: the operator supplies artifacts as data (an inline
JSON bundle, or a transcript they typed or pasted), and correlation runs against the local
offline intel store. Two things sit behind a **device/enrichment seam** that snaps in later:
(1) the `online` enrichment path (a network provider, off by default), and (2) live-capture
provenance — when the wireline/RF layers produce a `CaptureRef { kind: CallAudio, path }` on
the timeline, a future speech-to-text capability turns that recording into the transcript
text this crate ingests. Transcript **text** is a today-artifact; audio→text is the seam.

## Glossary

- **phonetool-baittriage**: The crate/plugin under specification; the fraud-caller
  footprint-triage plugin.
- **`BaitTriage`**: The plugin type. Manifest name `"baittriage"`, transducer `Ip`,
  capability `Passive`. Holds an `Arc<dyn IntelStore>` handle to the shared offline store.
- **Artifact**: One operator-supplied datum about a caller (a URL, a wallet, an email, a
  transcript, a claimed identity). Untrusted, adversary-supplied; treated as opaque data.
- **`RawBait`**: The untrusted, deserialized input bundle (the `Command`'s `arg` as JSON).
- **IOC (indicator)**: A normalized, comparable indicator extracted from the artifacts —
  `Ioc { kind, value }`. `IocKind`: `Phone`, `Url`, `Wallet`, `Email`, `GiftCardRail`,
  `Identity`.
- **Footprint**: The structured product — the extracted IOCs, their correlations, the
  classified scam pattern, the confidence, and any capture provenance.
- **`ScamPattern`**: The classified pattern — `IrsSsaImpersonation`, `TechSupport`, `Romance`,
  `PigButchering`, or `Unknown`.
- **`Confidence`**: The ordinal assessment strength — `Low` / `Medium` / `High`. Derived from
  countable corroborating evidence; the exact graduation cutoffs are operator-tunable and
  deferred (see Open Questions), not invented here.
- **Correlation / reuse hit**: An IOC that matches a Store-backed known-bad entry
  (`KNOWN_BAD_NS`) or an IOC recorded from a prior triaged bait (`REUSE_NS`).
- **`IntelStore`**: The shared offline key/value cache (`get`/`put` over `(namespace, key)`),
  the same store numintel serves from. baittriage reads it to correlate and writes to it to
  maintain the reuse index.
- **`online` feature**: Off-by-default Cargo feature enabling a live provider enrichment
  lookup; the default build links no `reqwest` and makes no network call.
- **`CaptureRef`**: The capture-bus record `CaptureRef { kind: CaptureKind, path }` that the
  future call-capture layers emit for bulk recordings; baittriage may cite its `path` as
  footprint provenance but never reads the recording.
- **Degenerate result**: A bundle from which no indicator could be extracted — useless, and
  therefore a failure (`PluginError::Empty`) the operator sees, not an empty success.
- **Operator**: The human invoking phonetool (here, the one who received or logged the scam
  call and is triaging it).

## Requirements

### Requirement 1: Passive, ungated

**User Story:** As the operator, I want footprint triage to run with zero authorization
friction, so defensive work against a scam caller is never gated ("do not narc-jump").

#### Acceptance Criteria

1. THE baittriage manifest SHALL declare `CapabilityClass::Passive` and `Transducer::Ip`.
2. THE baittriage plugin SHALL perform its operation without constructing a `Gate`, without
   requesting a `Grant`/`TxGrant`, and without emitting a consent record.
3. THE baittriage plugin SHALL be constructible and runnable given only an
   `Arc<dyn IntelStore>`, and SHALL implement the passive `Plugin` trait
   (`dispatch(&self, cmd) -> Result<Event, PluginError>`), never `ActivePlugin`.

### Requirement 2: Untrusted-artifact ingest boundary

**User Story:** As a security-conscious maintainer, I want every ingested artifact treated as
adversary-controlled data and validated at the boundary, so a malicious URL, wallet, or
transcript cannot make the plugin fetch, execute, or fall over.

#### Acceptance Criteria

1. WHEN `dispatch` receives a verb other than `"triage"`, THE baittriage SHALL return
   `Err(PluginError::Unsupported)`.
2. WHEN the command `arg` is empty or whitespace-only, THE baittriage SHALL return
   `Err(PluginError::InvalidInput)` before any parsing.
3. WHEN the `arg` does not deserialize into a well-formed `RawBait` bundle, THE baittriage
   SHALL return `Err(PluginError::InvalidInput)`.
4. THE baittriage SHALL treat every artifact value (URL, wallet, email, gift-card rail,
   transcript, claimed identity) as opaque data, and SHALL NOT fetch, resolve, dereference,
   open, or execute any of them on any path (default or `online`).
5. THE baittriage SHALL bound the accepted input: an `arg` longer than `MAX_BAIT_BYTES`, a
   field longer than `MAX_FIELD_BYTES`, or a bundle yielding more than `MAX_IOCS` indicators
   SHALL be rejected with `Err(PluginError::InvalidInput)` rather than processed unbounded.
   (These are engineering caps, not protocol constants; their values are recorded in the
   design as tunable, not asserted as facts about any scam.)
6. THE ingest and normalization SHALL be total over arbitrary and non-UTF-8 bytes: they SHALL
   NOT panic, `unwrap`, `expect`, or index unchecked on any input (workspace deny-lints).

### Requirement 3: Indicator extraction and normalization

**User Story:** As the operator, I want indicators pulled out of the artifacts and normalized
to a comparable form, so the same wallet or number written two ways still matches a prior case.

#### Acceptance Criteria

1. THE baittriage SHALL extract IOCs from the typed fields of the bundle AND from the free-text
   transcript, emitting each as an `Ioc { kind, value }`.
2. WHEN a phone-number artifact is present, THE baittriage SHALL normalize it to canonical
   E.164 using the shared `Number::parse` (the same validator numintel uses), so numbers
   compare canonically across cases.
3. WHEN a single artifact fails its own normalization (e.g. a phone field that is not a valid
   number), THE baittriage SHALL skip that one artifact and continue extracting the rest, never
   aborting the run — the same per-item resilience the SIP prober applies per probe.
4. THE baittriage SHALL normalize URLs and emails case-insensitively on the host part for
   comparison, and SHALL normalize wallet strings case-insensitively.
5. THE baittriage SHALL NOT assert chain-specific wallet checksum validity (e.g. BTC vs. ETH
   address rules): a wallet is normalized and compared as an opaque string. Per-chain
   validation is deferred (see Open Questions), not invented.

### Requirement 4: Offline correlation against the local store (default path)

**User Story:** As the operator on an air-gapped SBC, I want extracted indicators checked
against my local known-bad and prior-case data with no network call.

#### Acceptance Criteria

1. WHEN triage runs, THE baittriage SHALL look up each IOC by exact match against the store —
   `IntelStore::get(KNOWN_BAD_NS, ioc)` and `IntelStore::get(REUSE_NS, ioc)` — and SHALL make
   no network call on the default path.
2. WHEN an IOC matches a known-bad entry, THE baittriage SHALL record a `KnownBad` correlation
   for it; WHEN it matches a prior-case entry, THE baittriage SHALL record a `PriorCase`
   correlation carrying the prior case reference.
3. WHEN the store backend fails, THE baittriage SHALL return `Err(PluginError::Backend)`.
4. THE baittriage SHALL rely only on the store's `get`/`put` (`(namespace, key)`) surface for
   correlation, and SHALL document that exact-match is the only reuse test available today
   (fuzzy/substring reuse is the known gap — see Requirement 8 and the design).

### Requirement 5: Scam-pattern classification and honest confidence

**User Story:** As the operator, I want the footprint classified into a scam pattern with a
confidence I can trust, so a thin result is never dressed up as a conclusion.

#### Acceptance Criteria

1. THE baittriage SHALL classify the footprint into a `ScamPattern` by matching the extracted
   IOCs and identity claims against Store-backed pattern signatures, and SHALL return
   `ScamPattern::Unknown` when no signature matches.
2. THE baittriage SHALL derive `Confidence` from the count of independent corroborating
   indicators (known-bad hits, prior-case reuse hits, signature matches).
3. WHEN no IOC corroborates (no known-bad hit, no reuse hit, and no signature match), THE
   baittriage SHALL report `Confidence::Low` and SHALL NOT report any higher confidence.
4. THE baittriage SHALL NOT report a confidence above `Low` unless at least one IOC
   corroborated against a Store-backed entry or signature.
5. THE baittriage SHALL NOT fabricate, pad, or inflate the confidence to make a thin result
   appear conclusive. (The exact `Low`→`Medium`→`High` cutoffs and per-IOC weighting are
   operator-tunable and deferred — see Open Questions.)

### Requirement 6: Degenerate-case discipline (two tiers)

**User Story:** As the operator, I want a bundle that yields nothing to fail loudly, but a
bundle that yields indicators-without-correlation to succeed honestly, so neither an empty
input nor a thin match is mistaken for the other.

#### Acceptance Criteria

1. WHEN the bundle yields **zero** extractable indicators, THE baittriage SHALL return
   `Err(PluginError::Empty)` — nothing to triage is a failure the operator sees, not an
   empty-but-successful `Event`.
2. WHEN **at least one** indicator was extracted but nothing correlated, THE baittriage SHALL
   return `Ok(Event)` carrying the extracted footprint, `Confidence::Low`, and an explicit
   "no prior correlation" marker — a real, reportable result, not a failure.
3. THE `Empty` error message SHALL state that no indicator could be extracted from the supplied
   artifacts, so the operator can distinguish "nothing usable given" from "nothing matched".

### Requirement 7: Optional online enrichment — opt-in and opsec-aware

**User Story:** As the operator, I want any off-box enrichment to be off by default,
provider-agnostic, and to leak an indicator at most once, so triaging a caller does not
broadcast my investigation.

#### Acceptance Criteria

1. THE online enrichment SHALL exist only under the `online` Cargo feature; the default build
   SHALL NOT link `reqwest` or make any network call (`cargo tree -e no-dev` on the default
   graph SHALL show no `reqwest`).
2. THE online path SHALL NOT hardcode a provider — the enrichment `endpoint` (a URL template)
   is supplied at call time so a no-retain/no-resell source can be chosen (same stance and
   Open Question as numintel's online path).
3. THE online path SHALL transmit only the operator-selected indicators to the
   operator-configured endpoint, and SHALL NEVER send a request to any host or URL taken from
   an artifact.
4. WHEN an online enrichment succeeds, THE baittriage SHALL write the result through to the
   store so the indicator leaks off-box at most once.
5. WHEN the transport fails, THE baittriage SHALL surface `Transport`; on a non-success HTTP
   status, `Status(code)`; on a cache-write failure, `Cache`.

### Requirement 8: Reuse-index maintenance and its known limits

**User Story:** As the operator, I want each triaged bait's indicators remembered so the next
caller reusing a wallet or number is flagged, while I understand what the current store can and
cannot do.

#### Acceptance Criteria

1. WHERE reuse-index recording is enabled, THE baittriage SHALL write each extracted IOC to the
   store under `REUSE_NS` keyed by the IOC value, so a future bait's exact-match lookup finds it.
2. THE baittriage SHALL make the reuse write idempotent — keyed/deduplicated by a content hash
   of the bait — so re-triaging the same bait does not inflate reuse counts.
3. WHEN the reuse-index write fails, THE baittriage SHALL still return the assessment `Event`
   and SHALL mark index maintenance as failed in the event data, rather than discarding an
   otherwise-complete assessment.
4. THE design SHALL state explicitly that the current `IntelStore` `get`/`put` surface supports
   only exact-match reuse and has no atomic read-modify-write; fuzzy/near-duplicate reuse and a
   race-free append are the known architectural gap, deferred, not silently implemented.

### Requirement 9: Capture-timeline integration and capture provenance

**User Story:** As the operator, I want a triage result to land on the same timeline as
everything else, and to tie back to the recorded call it came from when one exists.

#### Acceptance Criteria

1. THE baittriage SHALL emit its result as an `Event` (`source = "baittriage"`) that the shell
   records to the `CaptureBus` as `CaptureRecord::PluginEvent`.
2. THE baittriage SHALL NOT inline any bulk capture (call audio) into its `Event`; a recording
   is referenced by path only.
3. WHERE the bundle cites a source-capture path (a `CaptureRef { kind: CallAudio, path }`
   already on the timeline), THE baittriage SHALL carry that path as footprint provenance and
   SHALL NOT open, read, or decode the recording — audio→text is a future device-seam
   capability, not part of this crate.

### Requirement 10: Hardened, offline-structural

**User Story:** As a maintainer, I want the crate hardened and dependency-lean, so it preserves
the pure-Rust static-musl offline build and cannot fall over on hostile input.

#### Acceptance Criteria

1. THE baittriage SHALL compile under `unsafe_code = forbid` and the workspace
   `unwrap_used`/`expect_used`/`indexing_slicing = deny` lints, in both the default and
   `--features online` configurations.
2. THE default build SHALL add zero egress dependencies; network egress SHALL exist only under
   the `online` feature, never in the core/default graph.
