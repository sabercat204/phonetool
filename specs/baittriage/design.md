# Design Document — phonetool-baittriage

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** This document fixes the shape of the fraud-caller
> footprint-triage plugin so it is ready to build when scheduled. No code implements this yet.

## Overview

`phonetool-baittriage` ingests a bundle of operator-supplied artifacts about a scam/vishing
caller and produces a structured footprint plus a confidence-scored risk assessment. It is a
**Tier-A native, passive** plugin: it implements the ordinary `Plugin` trait
(`dispatch(&self, cmd) -> Result<Event, PluginError>`), is handed no `Gate`, and never mints a
`Grant`/`TxGrant`. This is defense of others and is observation-coded — clean under the
operator's model — so it carries the same zero-friction recon path as numintel, and the
dual-use gate is simply absent here by construction.

The crate has four seams, each with a single job:

- **`ingest`** — pure, network-free deserialization and bounding of the untrusted `RawBait`
  bundle. Turns the `Command`'s `arg` (JSON) into a validated in-memory structure or a
  boundary error. Exhaustively testable with no store and no network.
- **`extract`** — pure indicator extraction/normalization. Pulls `Ioc`s from typed fields and
  from transcript text; normalizes phone (via shared `Number::parse`), URL/email host, and
  wallet strings. Per-artifact resilient: a bad artifact is skipped, never fatal.
- **`correlate`** — the Store layer. Exact-match lookups against `KNOWN_BAD_NS` and `REUSE_NS`,
  pattern classification against Store-backed signatures, confidence derivation, and (opt-in)
  reuse-index write-back. Owns no gate logic (there is none).
- **`lib` (`BaitTriage`)** — the `Plugin` boundary. Verb guard, drives ingest → extract →
  correlate, applies the two-tier degenerate discipline, and emits the `Event`.

## Architecture

```
   CLI: baittriage triage '<json bundle>'          (no --basis: passive, ungated)
        │  arg = untrusted artifact bundle (JSON)
        ▼
   BaitTriage::dispatch(cmd)          verb guard: "triage"
        │
        ▼
   ingest::parse(cmd.arg)   ── bounds: MAX_BAIT_BYTES / MAX_FIELD_BYTES ──► RawBait
        │  (empty | malformed | oversize → PluginError::InvalidInput; NEVER fetches a URL)
        ▼
   extract::iocs(RawBait)                             ┌─ Number::parse (shared, E.164)
        │  typed fields + transcript → Vec<Ioc>  ─────┤  URL/email host lower-case
        │  bad artifact → skip & continue (resilient) └─ wallet lower-case (opaque)
        │  0 IOCs → PluginError::Empty  (degenerate = failure)
        ▼
   correlate::assess(store, &iocs)
        │  per IOC:  IntelStore::get(KNOWN_BAD_NS, ioc)  → KnownBad
        │            IntelStore::get(REUSE_NS,   ioc)    → PriorCase{ ref }
        │  classify against Store-backed signatures      → ScamPattern | Unknown
        │  confidence ← count(corroborating evidence)     (0 corroboration ⇒ Low)
        │  [opt-in] reuse write-back: IntelStore::put(REUSE_NS, ioc, bait_hash)
        │  store backend error → PluginError::Backend
        ▼
   Footprint { iocs, correlations, pattern, confidence, provenance }
        │  ≥1 IOC → Ok(Event{ source:"baittriage", summary, data: Footprint })
        ▼
   CaptureBus.record_event(event)   ← same timeline as gate decisions & other plugins

   ── device / enrichment seams (snap in later; NOT this crate today) ──────────────
   [online feature] correlate::enrich(endpoint, ioc) ─► operator-chosen provider only
   [future STT]     CaptureRef{ kind: CallAudio, path } ─► transcript text ─► ingest
```

## Modules

- **`ingest`** — `RawBait` (serde `Deserialize`; optional typed fields: `phone`, `identity`,
  `agency_claim`, `urls: Vec<String>`, `wallets: Vec<String>`, `emails: Vec<String>`,
  `gift_card_rails: Vec<String>`, `transcript`, `email_body`, optional `source_capture: String`
  for a `CaptureRef` path). `parse(arg: &str) -> Result<RawBait, IngestError>`. `IngestError`
  (`Empty` / `Malformed` / `TooLarge`). Constants `MAX_BAIT_BYTES`, `MAX_FIELD_BYTES`,
  `MAX_IOCS` (engineering caps, documented as tunable — see Design decisions).
- **`extract`** — `Ioc { kind: IocKind, value: String }`; `IocKind`
  (`Phone`/`Url`/`Wallet`/`Email`/`GiftCardRail`/`Identity`, `Serialize`, snake_case);
  `iocs(bait: &RawBait) -> Vec<Ioc>`; private per-kind normalizers. Phone normalization calls
  the shared `Number::parse`; a normalization failure on one artifact drops that artifact and
  is not fatal. Pure; no store, no network.
- **`correlate`** — `Correlation` (`KnownBad { ioc }` / `PriorCase { ioc, case_ref }`);
  `ScamPattern` (`IrsSsaImpersonation`/`TechSupport`/`Romance`/`PigButchering`/`Unknown`,
  `Serialize`); `Confidence` (`Low`/`Medium`/`High`, `Serialize`, ordinal);
  `Footprint { iocs, correlations, pattern, confidence, provenance, reuse_index_ok }`;
  `assess(store: &dyn IntelStore, iocs: &[Ioc]) -> Result<Footprint, StoreError>`; constants
  `KNOWN_BAD_NS = "baittriage_known_bad"`, `REUSE_NS = "baittriage_reuse"`,
  `SIGNATURE_NS = "baittriage_signature"`. Under `online`: `enrich(endpoint, ioc)` +
  `OnlineError` (`Transport`/`Status(u16)`/`Cache`), compiled only under the feature.
- **`lib`** — `BaitTriage { store: Arc<dyn IntelStore> }` (`new`), its `Plugin` impl, and the
  private helpers `bait_hash` (content hash for idempotent reuse writes) and `map_store_error`.

## Design decisions

### Passive by construction — no gate, no ActivePlugin

baittriage implements `Plugin`, not `ActivePlugin`, and is constructed with only an
`Arc<dyn IntelStore>`. It is never handed a `Gate` and has no code path that mints or consumes
a `Grant`/`TxGrant`. Triaging a caller's own footprint touches no third-party infrastructure —
it is knowledge/defense work — so gating it would be safety theater the operator directive
explicitly forbids ("do not narc-jump"). The dual-use line runs through the *active* crates
(sip, and the future RF/legacy layers), not here.

### Artifacts are data, never destinations

Every artifact — most sharply a URL or wallet — is adversary-supplied. The single hardest rule
in the crate: **nothing in an artifact is ever fetched, resolved, opened, or executed on any
path.** A URL is a string to normalize and compare; it is never a request target. The `online`
enrichment path (Req 7) sends only operator-selected indicators to the operator-configured
endpoint — the artifact-supplied URL is never itself contacted. This keeps the crate from being
turned, via a crafted bundle, into an SSRF gadget or a beacon that tells the scammer their
victim is investigating.

### Bounded ingest of untrusted input

`ingest::parse` enforces `MAX_BAIT_BYTES` on the whole `arg`, `MAX_FIELD_BYTES` per field, and
`MAX_IOCS` on the extracted set, so a hostile or accidental megabyte-transcript cannot force an
unbounded allocation or an unbounded correlation loop. These are **engineering caps chosen for
safety, not claims about scam behavior** — their concrete values are recorded here as tunable
and are not asserted as facts about any real fraud campaign. Deserialization runs inside a
`Result`; malformed JSON is `PluginError::InvalidInput`, never a panic.

### Two-tier degenerate discipline

Deliberately two behaviors at two points. During extraction, one artifact that fails its own
normalization is **skipped**, never run-aborting — the SIP prober's per-probe resilience,
applied per artifact. Across the run, **zero** extractable indicators is
`PluginError::Empty`: nothing to triage is a failure the operator sees. But **≥1 indicator
with no correlation** is an honest `Ok(Event)` at `Confidence::Low` with an explicit
"no prior correlation" marker — a thin-but-real result, distinct from an empty input. The
failure mode this guards against is padding a thin result into false certainty; confidence is
floored at `Low` and cannot rise without a Store-backed corroboration (Req 5.3, 5.4).

### Confidence is counted, not asserted; cutoffs are deferred

`Confidence` is derived from the *count* of independent corroborating indicators (known-bad
hits + prior-case reuse hits + signature matches). The design fixes the monotone rule (more
corroboration never lowers confidence; zero corroboration is `Low`) but **does not invent the
`Low`→`Medium`→`High` numeric cutoffs or per-IOC weights** — those are operator-tunable policy
grounded in real triage experience, deferred to an Open Question rather than fabricated.
Likewise, `ScamPattern` classification matches against **Store-backed signatures** the operator
seeds, not against hardcoded keyword lists invented here; an unseeded bench returns
`ScamPattern::Unknown` honestly.

### Store as the correlation substrate, and its known limit

Correlation reuses the existing `IntelStore` `get`/`put` `(namespace, key)` surface — the same
store numintel serves from — under distinct namespaces (`KNOWN_BAD_NS`, `REUSE_NS`,
`SIGNATURE_NS`). This keeps the offline-first, air-gapped stance with no new backend. The
limit is explicit: `IntelStore` offers only **exact-match** lookup and has **no atomic
read-modify-write**. So (a) reuse detection is exact-match only today, and (b) the reuse-index
write is a plain `put` keyed by a content hash of the bait (`bait_hash`) for idempotency, not a
race-free append. Fuzzy/near-duplicate reuse and a concurrency-safe counter are the known gap
(next section), deferred rather than silently faked.

### Known architectural gap: fuzzy correlation & atomic reuse (prominent, undecided)

The value of footprint triage grows with **fuzzy** matching — a wallet off by a character, a
number in a different format, a look-alike domain, a transcript that paraphrases a known
script. The current `IntelStore` supports none of this: it is exact-key `get`/`put` with no
similarity index and no atomic increment. This crate therefore ships, in its first form,
**exact-match reuse only**, and this design flags the gap as a first-class deliverable rather
than papering over it. Two directions, neither silently chosen here:

- **(A) Extend `IntelStore`** with a query/scan or similarity surface (and an atomic
  read-modify-write) so correlation logic stays in Rust and offline. Larger blast radius: every
  store consumer inherits the wider trait.
- **(B) Keep `IntelStore` exact-match** and defer fuzzy correlation to a future capability —
  e.g. a Tier-B out-of-process analyzer behind the `specs/subprocess-ipc-contract/` seam, with
  the same passive stance and no gate (a subprocess is never a gate bypass, but a passive
  subprocess needs none). Keeps core minimal; adds process/IPC surface.

The recommendation recorded for the operator is **(B) for fuzzy analytics, plus a minimal
atomic-`put`-if-absent extension to `IntelStore` for race-free reuse counting** — smallest core
change that removes the correctness gap, with heavy analytics kept out-of-process. This is a
recommendation, not a decision; it is an Open Question and a prerequisite task.

### Online enrichment mirrors numintel

The optional `online` path is off-by-default (Cargo feature), provider-agnostic (endpoint
supplied at call time so a no-retain/no-resell source can be chosen), and write-throughs to the
store so an indicator leaks off-box at most once. It reuses numintel's exact stance and
inherits numintel's open provider question. Critically, it enriches only
**operator-selected indicators**, never an artifact-supplied URL.

## Ahead-of-hardware: what runs today vs. the device/enrichment seam

- **Today, no device, no network (default build):** the operator passes an artifact bundle as
  the command `arg` (inline JSON — a file the operator wrote, or a transcript they pasted).
  Ingest, extraction, offline correlation, classification, confidence, and reuse-index
  maintenance all run against the local `IntelStore`. This is the whole default capability and
  it needs no hardware.
- **Enrichment seam (`online` feature, off by default):** a network provider for
  reverse-number / breach / IOC-corpus enrichment. Snaps in behind the same feature flag
  numintel uses; the default binary links no `reqwest`.
- **Capture seam (future STT, not this crate):** when the wireline/RF layers record a call,
  they emit `CaptureRef { kind: CallAudio, path }` on the `CaptureBus`. A future
  speech-to-text capability (likely Tier-B, per the subprocess IPC contract) turns that
  recording into transcript **text**, which is then an ordinary today-artifact for this crate.
  baittriage never opens the audio itself; it only carries the `path` as provenance.

## Threat handling

**Threat note.** All input is adversary-controlled. The artifact bundle arrives from a caller
the operator does not trust; a crafted URL or wallet is a deliberate attempt to make the tool
act. Concrete failure modes guarded: (1) **SSRF / beacon** — a URL/host in the bundle is never
fetched, so a bundle cannot make the bench phone home to the scammer or an internal host;
(2) **resource exhaustion** — `MAX_BAIT_BYTES`/`MAX_FIELD_BYTES`/`MAX_IOCS` bound memory and
loop work against a giant transcript or an IOC-flood; (3) **parser panic** — deserialization
and normalization are total over arbitrary/non-UTF-8 bytes (`Result`, no `unwrap`/`expect`/
unchecked index), enforced by the workspace deny-lints; (4) **opsec leak** — the default path
makes no network call at all, and the `online` path transmits only operator-selected indicators
to an operator-chosen endpoint, so triaging a caller does not by itself reveal the operator to
any third party. Boundary validation happens in `ingest` before any value reaches the store or
(under `online`) an endpoint.

## Error handling

Errors map at two boundaries. `IngestError` (`Empty`/`Malformed`/`TooLarge`) and an
extraction-yielded-nothing condition map to the trait-level `PluginError`
(`InvalidInput` for ingest/bound failures; `Empty` for the zero-IOC degenerate case). Store
failures map through `map_store_error` to `PluginError::Backend`. Under `online`, `OnlineError`
(`Transport`/`Status`/`Cache`) is the enrichment vocabulary and never escapes as a panic. No
panics anywhere: the crate compiles under `unsafe_code = forbid` and the workspace
`unwrap_used`/`expect_used`/`indexing_slicing = deny` lints.

## Testing strategy

- **Ingest hostile-input** (`tests/ingest.rs`, table-driven): empty, whitespace, malformed
  JSON, oversize `arg`, oversize field, non-UTF-8 bytes, and a bundle whose only field is a
  URL — each maps to the exact `IngestError`/`PluginError` or parses without panic. An explicit
  test asserts **no artifact URL is ever contacted** (a bundle with a loopback URL that would
  be observable if fetched: nothing is sent).
- **Extraction** (`tests/extract.rs`): typed-field and transcript IOCs are pulled and
  normalized; a phone written three ways normalizes to one E.164; one malformed artifact is
  skipped while the rest extract; `MAX_IOCS` truncation/rejection.
- **Correlation & degenerate discipline** (`tests/assess.rs`): with a seeded in-memory
  `SqliteStore`, a known-bad IOC produces a `KnownBad` correlation; a prior-case IOC produces
  `PriorCase`; zero IOCs → `PluginError::Empty`; ≥1 IOC with no store hit → `Ok(Event)` at
  `Confidence::Low` with the "no prior correlation" marker (confidence never exceeds `Low`
  without corroboration); a store backend error → `PluginError::Backend`; reuse write-back is
  idempotent across a re-triage of the same bait.
- **Online path** (`tests/enrich.rs`, `--features online`): success write-throughs the store;
  transport/status/cache failures map to the right `OnlineError`; and the enrichment target is
  the configured endpoint, never an artifact URL.
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]` since the
  no-panic discipline binds library code, not assertions.

## Open questions for operator

1. **Confidence cutoffs & weighting.** What corroboration counts move `Low`→`Medium`→`High`,
   and are known-bad hits weighted above prior-case reuse above signature matches? Deferred —
   these are policy grounded in real triage experience, not numbers to invent. Blocks
   Requirement 5's graduation.
2. **`ScamPattern` signature seeding & taxonomy.** The five-way pattern set
   (`IrsSsaImpersonation`/`TechSupport`/`Romance`/`PigButchering`/`Unknown`) and the
   Store-backed signatures that drive classification need operator-validated seed data. Is this
   the right taxonomy, and where do the seeds come from (operator-authored vs. an imported
   public corpus)?
3. **Fuzzy correlation & atomic reuse (the known gap).** Direction (A) widen `IntelStore` vs.
   (B) out-of-process Tier-B analyzer + a minimal atomic `put`-if-absent. Recommendation on
   record: (B) plus the minimal atomic extension. Operator to confirm before either lands.
4. **Online enrichment provider.** Which reverse-number / breach / IOC-corpus source, under
   what retention/resale terms? Shared, unresolved, with numintel's identical online question —
   resolve once for both.
5. **Wallet / address validation depth.** Stay opaque-string (current design), or add
   per-chain checksum validation (BTC/ETH/…) to reject typo'd wallets before they pollute the
   reuse index? The latter needs real per-chain rules grounded in docs, not invented.
6. **Reuse-index retention & privacy.** The reuse index accumulates indicators about real
   people (a scammer's number is still PII). Retention window, and whether the index should be
   purgeable/encrypted at rest on a seized SBC? Not decided here.
