# Tasks — phonetool-wardial

> **BUILT IN SPRINT (wardial) (0.13.0): the SIP-only origination path, end-to-end.**
> The workbench's SECOND `ActivePlugin`. Tasks 4, 5, 6, 7, 8, 10, 11, 12, 13, 14 are
> `[x]`. Task 3 (trunk-policy bounds) is `[~]` — the bounds *plumbing* ships as a
> conservative SAFETY FLOOR (`max_range=32`, 1 call/sec), explicitly flagged as
> ungrounded; the grounded values remain OQ1/OQ2. Tasks 1, 9 (media path + RTP) are
> `[ ]` — NOT built: no RTP/media exists anywhere in the workbench and the direction
> (Tier-A G.711 vs Tier-B) is OQ6; `MediaDisposition` is always `NotAnalyzed`. Task 2
> (tone constants) is `[~]` — the Goertzel algorithm ships; the SIT/CNG/CED frequencies
> it would be configured with are NOT invented (OQ4). Task 12's tone-fixture assertions
> use synthetic tones only (no standards numbers asserted).

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

- [ ] 1. **Prerequisite / gap resolution — media path direction.** Resolve Open
  Question 6 with the operator: in-process Tier-A G.711 RTP receiver (recommended)
  vs. Tier-B subprocess media handler. **NOT built:** no RTP/media exists anywhere in
  the workbench; `MediaDisposition` is always `NotAnalyzed`. wardial ships at
  `SipDisposition`-only fidelity, which is fully useful on its own.
  _(Req 6, 10)_
- [~] 2. **Prerequisite — standards-grounded tone constants.** Fill Open Question 4:
  cite SIT (Telcordia/ITU-T), CNG (T.30), CED/answer tone (V.25/V.8) frequencies,
  tolerances, durations, cadences, and the Goertzel confidence threshold from the
  governing standards. **DONE:** the `tone` Goertzel algorithm ships (pure DSP).
  **NOT DONE:** the numeric config — deliberately not invented (OQ4).
  _(Req 6.3)_
- [~] 3. **Prerequisite — trunk-policy bounds.** Fill Open Questions 1 and 2 against a
  reference trunk provider's acceptable-use terms: `MAX_RANGE`, default
  calls-per-second, max-concurrent. **DONE:** the bounds plumbing ships as a
  conservative SAFETY FLOOR (`DEFAULT_MAX_RANGE=32`, 1 call/sec, sequential dispatch),
  loudly flagged as ungrounded. **NOT DONE:** the grounded values (OQ1/OQ2).
  _(Req 3.3, 4.2, 4.3)_
- [x] 4. `message` module: `InviteRequest::to_wire` with an SDP audio offer (PCMU/0 +
  telephone-event) + accurate `Content-Length`; `TeardownRequest` (ACK/BYE/CANCEL);
  total `Response::parse` over untrusted bytes (UTF-8-lossy, CRLF/bare-LF, every
  malformed input → `ParseError`, no panic/no unchecked index). Runs today, no network.
  Duplicates sip's parser handling (shared-crate is OQ7, out of scope).
  _(Req 5)_
- [x] 5. `classify` module: `SipDisposition` + `classify_sip` (known codes mapped,
  unrecognized → `Unknown`, never guessed; Q.850-cause table NOT hard-coded — OQ5);
  `MediaDisposition` (incl. `NotAnalyzed`/`Inconclusive`, undifferentiated `Voice`);
  `Outcome`. Pure functions, run today.
  _(Req 5.4, 6.1, 6.4)_
- [x] 6. `tone` module: dependency-free Goertzel single-bin detector over PCM buffers.
  Algorithm only; frequencies/thresholds supplied by the caller (from Task 2, ungrounded
  today). Degenerate configs (NaN/non-positive/≥Nyquist) refused; total over input.
  _(Req 6.2, 9.4, 11.1)_
- [x] 7. `originate` module: `sweep` places one bounded, rate-limited (paced),
  deadline-bounded SIP call per DID; per-call timeout/transport-err =
  `CallResult { reached: false }`, never aborts; recv cap on SIP; ACK/BYE/CANCEL
  teardown so no dialog dangles. `SweepConfig` with test-friendly `Default`.
  `TrunkConfig` device seam (secret redacted in Debug, not Serialize) — inert
  (refuses non-loopback) without it.
  _(Req 4, 7.1, 7.2, 9.1)_
- [x] 8. `lib` (`WarDial`) implements `ActivePlugin`: verb guard (`"sweep"`) → range
  from `grant.target()` (NEVER cmd) → `parse_range` + bounds (`max_range`, non-empty,
  inverted-span, per-DID digit validation) → RNG-free `short_session` (FNV-1a) →
  `originate::sweep` → fold `CallResult`s through `classify`. Degenerate discipline:
  0 reached → `Empty`; ≥1 → `Ok(Event)`. Manifest `Ip`/`ActiveIp`. `with_trunk` /
  `with_loopback` ctors.
  _(Req 1, 2, 3, 7.3, 7.4, 11.2)_
- [ ] 9. Media path (gated on Task 1): SDP offer/answer + RTP receive/depacketize +
  codec decode → PCM into `tone`. **NOT built** — no media substrate exists (OQ6).
  _(Req 6.5, 10.3, 10.4)_
- [x] 10. CLI wired: `wardial <range> --basis <why> --i-accept-billing-and-attribution
  [--trunk-host <h> --caller-id <c>]` → surface the cost/attribution notice + require
  the acknowledgement BEFORE `request_ip` (Req 8.2) → one `CaptureBus` →
  `Gate::request_ip` (fail-closed on empty basis, logs decision) → on `Grant`,
  `dispatch_active` → record `Event`. Trunk secret never enters `basis`/`arg`/logs
  (provisioned out of band; empty in the CLI path).
  _(Req 8, 9.1)_
- [x] 11. Compile-fail doctest on `WarDial`: fabricating a `Grant` to reach
  `dispatch_active` does not compile.
  _(Req 1.2)_
- [x] 12. Tests: loopback-responder end-to-end via a real minted grant
  (`SipDisposition` per DID, `reached`, degenerate `Empty`, gate refusal on empty basis
  recorded on the `CaptureBus`, malformed-range-before-any-socket, no-trunk refusal);
  table-driven SIP parser hostile-input; classifier code coverage; `tone` detector over
  SYNTHETIC tones (no standards numbers asserted — OQ4). RTP/PCM hostile-input gated on
  Task 9 (not built). Loopback only — no PSTN origination in tests.
  _(Req 1, 5, 6, 7)_
- [x] 13. Compile clean under `unsafe_code = forbid` + workspace deny-lints;
  `clippy --all-targets` clean (crate carries no warnings); `fmt` clean. Adds no egress
  deps; `cargo tree -e no-dev` shows zero reqwest.
  _(Req 9.2, 9.3, 11.1)_
- [x] 14. Docs + version: `specs/wardial/` triple updated; VERSION +
  `[workspace.package]` bumped to 0.13.0; STATE.md updated with the wardial
  cost/attribution stance and the honest offline caveat (default binary has an inert
  origination path; live requires both a `Grant` and a `TrunkConfig`).
  _(Req 9.3)_

## Deferred

- **Answering-machine detection (human-vs-voicemail split).** `MediaDisposition::Voice`
  is undifferentiated by design; AMD is unreliable and ethically loaded (implies intent
  to reach a person). Revisit with the operator (Open Question 8) — do not build
  reflexively.
- **Codecs beyond G.711.** Wideband / Opus early-media decoding — only if a provider or
  target requires it; escalates the media path toward Option B.
- **Grant scope narrowing** (per-time-window / per-cost-budget tokens). A grant today
  authorizes the operation it was minted for; a spend cap enforced by the gate is a
  natural extension once cost is a first-class concern.
- **TCP/TLS SIP transport and SIP `REGISTER` against the trunk.** UDP + provider-specific
  registration deferred to the trunk-integration build.
- **Shared SIP message crate.** Factoring `message` out of phonetool-sip (Open Question
  7) is a refactor to schedule alongside this build, not a wardial-only task.
