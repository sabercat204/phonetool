# Design Document — phonetool-wardial

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** This document fixes the contract for the
> SIP-origination wardial so the shell and the auth-gate are ready when the trunk
> seam and the media path land. No code implements this yet.

## Overview

`phonetool-wardial` enumerates a DID range by placing one outbound SIP call per
number through a configured trunk and classifying what answered. It is the
workbench's second `ActivePlugin` (after phonetool-sip) and inherits sip's
invariants verbatim: the target — here the DID range — comes from `Grant::target`,
the response bytes are untrusted, execution is bounded, and a run that learns
nothing is a failure.

It differs from sip in one load-bearing way: **sip's OPTIONS probe rings no one and
costs nothing; wardial originates real calls that are billable, attributable, and
can complete to a live human.** That property drives two design commitments beyond
sip's: (1) a cost/attribution acknowledgement layered on top of the gate `Grant`,
and (2) conservative bounds (small `MAX_RANGE`, mandatory rate limit) because each
unit of the sweep is a metered call, not a free packet.

The design has four seams, each with a single job, arranged so that the maximum
runnable-today surface is separated from the trunk and media hardware seams:

- **`message`** (today, no network) — pure SIP wire format for origination: an
  `InviteRequest::to_wire` builder (with an SDP offer) and a **total**
  `Response::parse` over untrusted bytes. Reuses phonetool-sip's parser handling; a
  shared SIP-message crate is an Open Question.
- **`classify`** (today, no network) — `SipDisposition` from response codes
  (Requirement 5) and `MediaDisposition` from tone analysis (Requirement 6), plus
  the Goertzel `tone` detector. Pure functions and pure DSP; exhaustively testable
  against synthetic and recorded audio with zero network.
- **`originate`** (behind the trunk seam) — the socket + trunk layer. One bounded,
  rate-limited, deadline-bounded call per DID; owns no gate logic on purpose. Inert
  without a `TrunkConfig`.
- **`lib` (`WarDial`)** — the `ActivePlugin` boundary. Reads the range from the
  grant, validates and bounds it, drives `originate::sweep`, folds per-call results
  through the classifier, and applies the degenerate-case discipline.

### Today vs. the device seam (operator directive)

| Capability | Runs TODAY (no gear, no trunk) | Behind a seam |
|---|---|---|
| `InviteRequest::to_wire` / SDP offer builder | ✅ pure function | — |
| `Response::parse` over hostile bytes | ✅ total parser | — |
| `SipDisposition` code classifier | ✅ pure function | — |
| Goertzel `tone` detector | ✅ pure DSP over PCM buffers | — |
| `MediaDisposition` over **recorded/synthetic** audio | ✅ fed from a file/fixture | — |
| Loopback SIP exchange (127.0.0.1 responder) | ✅ operator-owned, rings no one, costs nothing | — |
| Real SIP origination onto the PSTN | ❌ | **trunk seam** (`TrunkConfig`) |
| Live early-media / RTP capture from a call | ❌ | **media seam** (Req 10) |

The trunk account is this layer's "device". The media path (RTP receive + codec
decode) is a second seam that does not exist anywhere in the workbench yet — see
the prominent gap below.

## Architecture

```
   CLI: wardial sweep <range-in-grant> --basis <why + cost-ack> [--trunk <cfg>]
        │
        │  COST/ATTRIBUTION NOTICE  ──► operator must acknowledge (Req 8)
        ▼
   Gate::request_ip { target: DID-range, basis }  ──► ConsentLog (CaptureBus): Granted | Refused
        │  Ok(Grant)                                    (refusal ends the flow here)
        ▼
   registry.dispatch_active("wardial", &cmd, &grant)
        │
        ▼
   WarDial::dispatch_active(cmd, grant)
        │  range ← parse_range(grant.target())   (NEVER cmd)     verb guard: "sweep"
        │  bounds: MAX_RANGE, non-empty, per-DID digit validation
        │  session ← FNV-1a(target + basis)       RNG-free transaction ids
        ▼
   originate::sweep(range, trunk, session, cfg)          ◄── inert without TrunkConfig
        │  rate-limit + concurrency cap + per-call deadline
        │  per DID → place_one:
        │     InviteRequest::to_wire → trunk send → collect SIP responses
        │        │
        │        ├─ classify_sip(codes) ─────────────► SipDisposition   (always)
        │        │
        │        └─ IF early media / answer  ┌───────────────────────────────┐
        │              RTP recv (media seam) │  >>> NOT BUILT ANYWHERE YET    │
        │              → depacketize → PCM ──►│  Tier-A RTP/G.711  OR  Tier-B │──► tone::goertzel
        │              → tone::goertzel       │  subprocess media handler     │      → MediaDisposition
        │                                     └───────────────────────────────┘
        │        teardown (CANCEL/BYE); timeout/err → CallResult{reached:false}
        ▼
   Vec<CallResult>
        │  reached == 0 → PluginError::Empty   (degenerate = failure)
        │  else → Event { summary, data: {range, placed, reached, by_outcome, results} }
        ▼
   CaptureBus.record_event(event)
   (bulk call audio, if ever captured, is a CaptureRef{ kind: CallAudio, path } — never inlined)
```

## Modules

- **`message`** — `InviteRequest<'a>` (borrowed fields; `to_wire` builds the request
  line, headers, and an SDP offer body via infallible `write!`, routed through
  `let _ =` to honor the no-panic lint). `Response { status_code, reason, headers }`
  with case-insensitive `header` lookup and `ParseError`
  (`Empty`/`BadStatusLine`/`BadStatusCode`) — the phonetool-sip parser, ideally
  shared (Open Question). SDP is emitted as a fixed audio offer (one payload type);
  the offered codec is an Open Question (bind to a codec the media decoder supports).
- **`classify`** — `SipDisposition` (e.g. `Ringing`, `Busy`, `Unavailable`,
  `Answered`, `Rejected`, `Unknown`) + `classify_sip`; `MediaDisposition`
  (`NotAnalyzed`, `Inconclusive`, `Sit`, `Fax`, `Modem`, `Voice`) + `classify_media`;
  `Outcome { sip: SipDisposition, media: MediaDisposition }`. All `Serialize`. The
  `Unknown`/`NotAnalyzed`/`Inconclusive` variants are the "will not guess" discipline
  made explicit in the type.
- **`tone`** — a dependency-free Goertzel single-bin detector over `&[i16]` / `&[f32]`
  PCM: `Goertzel::new(target_hz, sample_rate, block_len)` and a magnitude/energy
  readout. Pure DSP; the frequencies, tolerances, cadences, and confidence thresholds
  it is *configured with* are the standards-grounded constants deferred to Open
  Questions — the algorithm ships, the numbers do not until grounded.
- **`originate`** — `SweepConfig { per_call_deadline, calls_per_sec, max_concurrent,
  recv_cap }` (test-friendly `Default`), `CallResult { did, reached, outcome,
  sip_code }` (`Serialize`), `SweepError`
  (`BadRange`/`Trunk`/`TooMany`/`EmptyRange`), `sweep`, and the private `place_one`.
  `TrunkConfig { host, credentials, caller_id }` is the device seam; absent, `sweep`
  is restricted to a loopback target and places no PSTN call.
- **`lib`** — `WarDial { cfg, trunk: Option<TrunkConfig> }` (`new` / `with_config`),
  its `ActivePlugin` impl, and private helpers `parse_range`, `short_session`
  (FNV-1a), `map_sweep_error`.

## Design decisions

### Reuse the phonetool-sip invariants wholesale

Target-in-the-grant, total parser over untrusted bytes, RNG-free FNV-1a session
tokens, degenerate-is-failure, per-call resilience: these are already proven in
phonetool-sip and are copied here, not reinvented. The one addition is that wardial's
"probe" is a real call, which changes the bounds' *values* (conservative) and adds
the cost/attribution layer — not the *structure*.

### Cost/attribution acknowledgement on top of the Grant

The gate already forces a target and a basis. Wardial layers one more affirmative:
before `Gate::request_ip` is even called, the CLI surfaces that origination is
billable, attributable, and can ring a real person, and requires the operator to
acknowledge it (Requirement 8). This is *not* a second token type — the wrong here is
still Axis A (target ownership / authorization), and inventing a parallel token would
fracture the model. It is a CLI-side precondition plus an expectation that the
`basis` names the cost acknowledgement, all recorded verbatim on the `CaptureBus`.
Whether the acknowledgement should instead be a structured field the gate validates
is an Open Question; this design keeps the gate unchanged and puts the friction in the
shell, matching sip's "gate stays minimal" stance.

### Conservative bounds because each unit is billable

`MAX_RANGE` is intentionally *not* set to sip's 4096. A number that large is 4096
metered calls. The ceiling, the default rate limit, and the concurrency cap are all
operator decisions grounded in the trunk provider's acceptable-use terms (Open
Questions) — the spec refuses to invent them, because a wrong-by-default rate is a
toll-fraud-shaped or TDoS-shaped footgun, not a mere performance knob.

### Two classification tiers, evidence-gated

`SipDisposition` needs only the response codes and is always available — it is the
runnable-today floor and works with zero media. `MediaDisposition` needs decoded
audio and is therefore behind the media seam; when there is no audio it is
`NotAnalyzed`, and when there is audio but the detector is not confident it is
`Inconclusive`. The type makes "I did not analyze" and "I analyzed and am unsure"
distinct from a positive label, so a useless result can never masquerade as a
confident one.

### Standards-grounded tone constants, never invented (grounding discipline)

The Goertzel algorithm is dependency-free math and ships today. The tones it looks
for — SIT segment frequencies/durations (Telcordia / ITU-T), fax CNG (T.30), CED /
answer tone (V.25 / V.8) — carry specific numeric frequencies, tolerances, and
cadences that this spec deliberately does *not* state, because stating them from
memory risks confabulation. They are Open Questions to be filled from the governing
standards at build time. This is the grounding discipline applied: the code path is designed
now; the physics constants are cited later, from documents.

### Degenerate = failure, per-call = resilient (inherited)

Within a sweep, one dead DID is a `CallResult { reached: false }`, never a
sweep-aborting error. Across the sweep, if *nothing* was reached, the op returns
`PluginError::Empty` — a sweep that learned nothing is a failure the operator sees,
not "the block is clean". Identical to sip's two-layer discipline.

## The known architectural gap: no media path exists yet

**This is a prominent design deliverable, not a footnote.** phonetool-sip is
signalling-only: UDP OPTIONS, no SDP negotiation, no RTP, no codec. Nothing in the
workbench today can receive, depacketize, or decode call audio. Therefore
`MediaDisposition` — the entire SIT/fax/modem/voice classification that distinguishes
a wardial from a plain SIP scanner — has **no substrate to run on** until a media path
is built.

Two directions, neither silently chosen:

- **Option A — minimal in-process Tier-A media receiver.** Add SDP offer/answer
  handling and a small RTP receiver + G.711 (µ-law/A-law) decoder in Rust, feeding
  PCM straight into `tone::goertzel`. Pros: pure Rust, no subprocess, honors the
  static-musl offline build, keeps the gate trivially on the Rust side. Cons: RTP
  jitter-buffer and codec handling is real surface to get total-over-hostile-input
  correct; G.711 only (no wideband/Opus without more work).
- **Option B — Tier-B subprocess media handler.** Route media through a
  `SubprocessPlugin` (per `specs/subprocess-ipc-contract/`) that owns the RTP/codec
  work in an existing library, returns a `CaptureRef { kind: CallAudio, path }` for
  bulk audio, and hands decoded features back over the control channel. Pros: reuses
  a mature media stack; bulk audio stays out-of-band by handle. Cons: a subprocess and
  its language runtime on the SBC; **the `Grant` must be obtained on the Rust side
  before the child is driven — a subprocess is never a gate bypass** (Requirement
  10.4).

**Recommendation (not a decision):** start with Option A restricted to G.711 early
media, because the SBC target and offline stance favor pure Rust and the wardial's
tone targets (SIT/CNG/CED) are narrowband and well within G.711's band. Escalate to
Option B only if a codec beyond G.711 becomes necessary. This choice is an Open
Question for the operator; until it is made, wardial ships at `SipDisposition`-only
fidelity (Requirement 10.2), which is fully useful on its own (live/disconnected/busy
mapping across a block).

## Error handling

Two error enums at two boundaries, mirroring sip. `SweepError` (`thiserror`) is the
origination layer's vocabulary; `map_sweep_error` maps it to the trait-level
`PluginError` (`BadRange`/`EmptyRange`/`TooMany` → `InvalidInput`; `Trunk` →
`Backend`). `ParseError` never escapes `place_one` — a parse failure becomes a
`reached: true`, `SipDisposition::Unknown` `CallResult`. A malformed SDP body or RTP
packet is dropped or mapped to `MediaDisposition::Inconclusive`, never propagated as a
panic. No panics anywhere: the crate compiles under `unsafe_code = forbid` and the
workspace `unwrap_used`/`expect_used`/`indexing_slicing = deny` lints.

## Threat note

Origination handles untrusted input, elevated real-world consequence, and
credentials — three of the threat-context triggers at once.

- **Billable + attributable + can-ring-a-human is the headline risk.** A `200 OK`
  means a real phone rang and a person may have answered; a large or fast sweep is
  toll-fraud-shaped and TDoS-shaped against the far end and can run up a real bill on
  the operator's own trunk. Mitigation: conservative `MAX_RANGE`, a mandatory rate
  limit and concurrency cap (Requirement 4), the cost/attribution acknowledgement
  (Requirement 8), and the whole thing gated behind an Axis-A `Grant` whose `basis`
  is recorded verbatim. The gate justification here is heavier than sip enum by
  design.
- **Inbound bytes are adversary-controlled even under an authorized gate.** SIP
  responses, SDP bodies, and RTP packets can come from a honeypot trunk, a hostile
  gateway, or a spoofed source. Every one is validated at its boundary; the parser is
  total; the RTP/PCM path is total; recv sizes are capped so a remote-supplied length
  cannot force an unbounded allocation.
- **Credential handling.** The trunk SIP auth secret lives only in `TrunkConfig` and
  must never enter the `basis`, the command `arg`, an `Event`, or a log line
  (Requirement 8.4). What can go wrong if it leaks: an attacker who reads a capture
  log obtains PSTN origination on the operator's dime.
- **Not narc-jumping:** against a range the operator owns or is authorized to test
  (their own DID block, a scoped pentest engagement), this is legitimate defensive /
  recon work and the design carries no friction beyond the gate + cost ack. The
  friction is reserved for exactly the consequential, billable, reaches-a-third-party
  case — named once, here, flat.

## Testing strategy

- **Compile-fail doctest** (in `lib.rs`, on `WarDial`): fabricating a `Grant` struct
  literal to reach `dispatch_active` does not compile — the plugin-layer mirror of
  authgate's doctest.
- **End-to-end, loopback only** (`tests/sweep_loopback.rs`): a loopback SIP responder
  on `127.0.0.1` (operator-owned, no trunk, rings no one, costs nothing) answers with
  scripted response codes across a small range; the `Grant` is minted the only legal
  way — through the real `Gate` — then drives `dispatch_active`; asserts
  `SipDisposition` per DID, `reached` flags, and the degenerate `Empty` when the
  responder is silent. A second test asserts an empty basis is a `Denied::NoBasis`
  refusal recorded on the production `CaptureBus`. (Building and firing at loopback ≠
  firing at a third party.)
- **SIP parser hostile-input** (`tests/message_parse.rs`, table-driven): empty,
  whitespace, non-SIP version, missing/non-numeric/wrong-length code, non-UTF-8,
  bare-LF, giant header block — each maps to the exact `ParseError` or parses without
  panic. Reuses sip's table if the message crate is shared.
- **Classifier coverage** (`tests/classify.rs`): every known SIP code → its
  `SipDisposition`; unrecognized code → `Unknown`.
- **Tone detector over fixtures** (`tests/tone.rs`): the Goertzel detector run against
  **synthetic** tones (generated in-test) and, where available, **recorded** SIT / CNG
  / CED captures as fixtures — asserting detection and, importantly, asserting
  `Inconclusive`/`NotAnalyzed` on silence and noise. This test is meaningful only once
  the standards-grounded constants are filled (Open Questions); until then it is
  written against placeholder tones with the numeric assertions marked pending.
- **RTP/PCM hostile-input** (`tests/media_parse.rs`): malformed packet, unknown
  payload type, truncated stream → dropped / `Inconclusive`, never a panic. Gated on
  the media seam being built.
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]`
  since the no-panic discipline binds library code, not assertions.

## Open questions for operator

1. **`MAX_RANGE` ceiling.** How many DIDs may a single authorized sweep cover?
   Deliberately unset — each is a billable call, so the value is a cost/policy call,
   not a performance one. Needs a conservative default grounded in the trunk's terms.
2. **Default rate limit and concurrency cap.** Calls-per-second and max-concurrent
   defaults MUST come from the trunk provider's acceptable-use policy, not a guess.
   Which provider is the reference?
3. **Cost/attribution acknowledgement form.** A CLI flag
   (`--i-accept-billing-and-attribution`) vs. an interactive typed confirmation vs. a
   structured field the gate validates? This design keeps the gate unchanged and puts
   the affirmative in the shell — confirm or override.
4. **SIT / CNG / CED tone constants.** The exact segment frequencies, tolerances,
   durations, and cadences for SIT (Telcordia / ITU-T), fax CNG (T.30), and CED /
   answer tone (V.25 / V.8), plus the Goertzel confidence threshold. NOT stated here to
   avoid confabulation; to be filled from the governing standards at build time.
5. **Q.850 cause → disposition mapping.** The SIP `Reason`-header (RFC 3398) cause-code
   to PSTN-disposition table is gateway-dependent. Ground it against the actual trunk
   provider's behavior, or keep classification at SIP-code granularity only?
6. **Media path: Option A (in-process Tier-A G.711 RTP) vs. Option B (Tier-B
   subprocess).** Recommendation is A for the offline/SBC stance, escalating to B only
   if a non-G.711 codec is needed — operator to confirm the direction and the initial
   codec set.
7. **Shared SIP message crate.** Should `message` (request builder + total
   `Response::parse`) be factored out of phonetool-sip into a shared crate both consume,
   or duplicated? Sharing reduces parser drift; a shared crate is new surface.
8. **Human-vs-voicemail.** Is undifferentiated `Voice` acceptable, or is an
   answering-machine-detection heuristic wanted later? AMD is notoriously unreliable and
   ethically loaded (it implies intent to reach a person); deferred and flagged, not
   assumed.
9. **Caller-ID policy.** What outbound caller-ID does the trunk present, and is
   presenting a specific number itself a legal/attribution consideration for the
   operator's jurisdiction?
