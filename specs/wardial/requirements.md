# Requirements Document — phonetool-wardial

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** This triple fixes the contract for the
> modern wardial; no code implements it yet. `tasks.md` is entirely unchecked.

## Introduction

`phonetool-wardial` is DID-range enumeration by **SIP origination** — the modern
wardial. Where a 1990s wardial drove a modem bank across a phone-number range,
this drives one SIP `INVITE` per number through a configured trunk and classifies
what answered: ringing / no-answer, busy, SIT / intercept (a disconnected or
invalid number), voice (a human or voicemail), fax (T.30), or modem (an answer
tone). The product is a map of which numbers in a block are live and what sits
behind each.

This is the workbench's most consequential active operation to date, and the
reason is not code — it is **cost and attribution**. SIP origination is *billable*
(it rides a real trunk account and is metered per call / per minute),
*attributable* (the trunk account and outbound caller-ID identify the operator; it
is not anonymous), and *capable of completing a call to a real person* (a `200 OK`
means a live phone rang and someone answered). phonetool-sip's OPTIONS probe
touches a remote but rings no one and costs nothing; wardial can do both. The gate
justification is therefore heavier than SIP enumeration's, and this crate adds an
explicit cost/attribution acknowledgement on top of the auth-gate `Grant`.

Like phonetool-sip, wardial is Axis A (`ActiveIp`): every run routes through a
`Grant` the auth-gate minted, acts only on the DID range that grant names, and
treats every inbound byte — SIP response, SDP, RTP media — as untrusted adversary
input. It reuses the phonetool-sip invariants wholesale: target-in-the-grant, a
total response parser, bounded execution, degenerate-is-failure.

Per the operator directive, this spec separates what runs **today with no
hardware and no trunk** (pure wire builders, a total parser, a SIP-code classifier,
a Goertzel tone detector fed by recorded/synthetic audio, and a loopback SIP
responder) from what sits behind a **trunk seam** that snaps in when a provider
account is configured (real origination onto the PSTN). The trunk account is this
layer's "device": absent it, the origination path is present but inert.

## Glossary

- **phonetool-wardial**: The crate under specification; the SIP-origination
  DID-range enumeration active plugin. Manifest name `"wardial"`, transducer `Ip`,
  capability `ActiveIp`.
- **DID**: Direct Inward Dialing number — one dialable E.164 telephone number.
- **DID range**: A contiguous block of DIDs to enumerate, encoded in the grant's
  target (e.g. a base number plus a last-digit span).
- **SIP origination**: Placing an outbound call by sending a SIP `INVITE` through a
  trunk toward a DID. The active, billable operation this crate performs.
- **`INVITE`**: The SIP request that initiates a call; carries an SDP offer.
- **Trunk / trunk account**: An account with a SIP provider (ITSP) that bridges SIP
  to the PSTN. Requires credentials; metered and attributable. Modeled by
  `TrunkConfig`. This layer's "device seam".
- **Early media**: Audio the far end sends *before* answer (ringback, SIT,
  announcements), signalled by a `183 Session Progress` carrying SDP + RTP. The
  primary evidence source for pre-answer classification.
- **RTP**: Real-time Transport Protocol — the packetized audio stream negotiated by
  SDP. Its payload must be depacketized and decoded to PCM before tone analysis.
- **SIP disposition**: The coarse outcome inferred from the SIP response
  code(s) alone (`SipDisposition`) — always available, no media path required.
- **Media disposition**: The outcome inferred from tone analysis of early or
  answered media (`MediaDisposition`) — available only behind the RTP seam.
- **`Outcome`**: The per-DID classification, combining `SipDisposition` and (where
  present) `MediaDisposition`.
- **SIT**: Special Information Tone — the tri-tone sequence a network plays for
  intercepted / vacant / reorder conditions (ITU-T / Telcordia). Its exact segment
  frequencies and durations are deferred to an Open Question (see design).
- **CNG**: Fax calling tone (ITU-T T.30). Commonly cited near 1100 Hz; detection
  tolerance/cadence deferred to an Open Question.
- **CED / answer tone**: The answering-terminal tone (ITU-T V.25 / V.8), commonly
  cited near 2100 Hz; fax-vs-modem disambiguation deferred to an Open Question.
- **Goertzel**: A single-bin DFT algorithm for detecting energy at a target
  frequency; the tone-detector primitive. Pure DSP, no dependencies.
- **`TrunkConfig`**: Operator-supplied trunk parameters — provider host, auth
  credentials, outbound caller-ID/DID. The seam that turns an inert origination path
  into a live one.
- **Cost/attribution acknowledgement**: An explicit affirmative the operator gives,
  in addition to the gate basis, that they accept this run is billable and
  attributable. Recorded to the capture timeline.
- **`ActivePlugin`**: The core trait for an Axis-A capability;
  `dispatch_active(&self, cmd, grant: &Grant)` requires a `Grant`.
- **`Grant`**: The unforgeable Axis-A token (from `phonetool-authgate`); no public
  constructor, obtainable only from `Gate::request_ip`. Carries the authorized
  `target` (here, the DID range) and the operator's `basis`.
- **Degenerate result**: A run in which no DID in the range was reachable / answered
  — useless, and therefore a failure the operator sees (`PluginError::Empty`), never
  an empty success.
- **RTP-media prerequisite**: The fact that no RTP/SDP/media handling exists anywhere
  in the workbench yet; media-based classification is gated on building it. See the
  design's prominent architectural gap.

## Requirements

### Requirement 1: The origination is unrepresentable without authorization

**User Story:** As the operator, I want a wardial run to be impossible to invoke
without the gate having authorized it, so that the dual-use line is a compile-time
property rather than a reviewer's vigilance.

#### Acceptance Criteria

1. THE wardial plugin SHALL implement `ActivePlugin`, whose `dispatch_active` takes
   a `&Grant`, and SHALL NOT expose any path that originates a call without a
   `Grant`.
2. WHERE a caller attempts to fabricate a `Grant` to reach `dispatch_active`, THE
   crate SHALL make the code fail to compile (proven by a compile-fail doctest).
3. THE wardial plugin's manifest SHALL declare capability `ActiveIp` and transducer
   `Ip`.
4. WHEN `dispatch_active` receives a command whose verb is not `"sweep"`, THE
   wardial plugin SHALL return `Err(PluginError::Unsupported)`.

### Requirement 2: The DID range lives in the Grant, never the command

**User Story:** As the operator, I want origination to act only on the DID range the
gate authorized, so that a command argument cannot smuggle in a second, uncharged,
unauthorized range.

#### Acceptance Criteria

1. THE wardial plugin SHALL read the DID range from `Grant::target`, never from the
   command.
2. THE command's `arg` SHALL carry only the operation's own parameters (per-call
   timeout override, rate override, classification depth) and SHALL NOT be
   interpreted as a target or a range.
3. WHERE the command `arg` and the grant target disagree about a range, THE wardial
   plugin SHALL use the grant target and SHALL NOT consult the command for a range.

### Requirement 3: The DID range is validated and its expansion is bounded

**User Story:** As the operator, I want the range validated and capped before any
call is placed, so that a malformed range or a fat-fingered span cannot become an
unbounded — and unbounded-cost — sweep.

#### Acceptance Criteria

1. WHEN the grant target does not parse as a well-formed DID range, THE wardial
   plugin SHALL return `Err(PluginError::InvalidInput)` before any socket or trunk
   work.
2. WHEN the range expands to zero DIDs, THE wardial plugin SHALL return
   `Err(PluginError::InvalidInput)` (an empty range is not a runnable op).
3. THE wardial plugin SHALL refuse a range whose expanded size exceeds `MAX_RANGE`
   with `Err(PluginError::InvalidInput)`. (The value of `MAX_RANGE` is an operator
   decision — see Open Questions — and SHALL be set conservatively because each DID
   is a billable call, not a free probe.)
4. WHEN a candidate DID contains any character outside the digits and a leading
   `+`, THE wardial plugin SHALL reject it before it becomes part of a wire message.

### Requirement 4: Origination is bounded, rate-limited, and timed

**User Story:** As the operator, I want one authorized sweep to stay one bounded,
paced operation, so that a hostile/slow far end, a large range, or a runaway loop
cannot turn it into a hang, a flood, or a runaway bill.

#### Acceptance Criteria

1. THE origination layer SHALL apply a per-call deadline, after which a call that
   has not reached an answered dialog is torn down (`CANCEL` before a final
   response, `BYE` after a `200 OK`) and recorded as a no-response `CallResult`,
   never a hang.
2. THE origination layer SHALL rate-limit call initiation to at most a configured
   number of new calls per unit time, so a sweep cannot burst into a
   toll-fraud / TDoS-shaped pattern. (The default rate is an operator decision — see
   Open Questions — and SHALL be grounded in the trunk provider's terms, not
   invented.)
3. THE origination layer SHALL bound concurrent in-flight calls to a configured
   ceiling.
4. THE origination layer SHALL cap the bytes read from any single SIP response and
   from any single RTP packet, truncating rather than trusting a remote-supplied
   size.
5. WHEN the trunk is unreachable or refuses the SIP registration/authentication,
   THE origination layer SHALL return `Err(PluginError::Backend)` for the run rather
   than silently placing zero calls and reporting success.

### Requirement 5: SIP-response-code classification is total over untrusted bytes

**User Story:** As a maintainer, I want the SIP-response parser and classifier to
never panic and to always yield a disposition, because the bytes on the wire are
adversary-controlled even under an authorized gate (a honeypot trunk, a hostile
gateway, a spoofed response).

#### Acceptance Criteria

1. WHEN the response parser receives empty, whitespace-only, or non-SIP bytes, THE
   parser SHALL return a `ParseError` variant, never a panic.
2. THE parser SHALL handle non-UTF-8 input lossily and SHALL tolerate both CRLF and
   bare-LF line endings.
3. THE parser SHALL NOT panic, `unwrap`, `expect`, or index unchecked on any input,
   for any length (enforced by the workspace deny-lints on library code).
4. THE classifier SHALL map every SIP final/provisional response code to a
   `SipDisposition` (e.g. ringing, busy, unavailable, answered, error), and SHALL
   map any code it does not specifically recognize to an explicit `Unknown`
   disposition rather than guessing.
5. THE fine mapping from a gateway's Q.850 cause (via the SIP `Reason` header, RFC
   3398) to a PSTN disposition SHALL be treated as gateway-dependent and its exact
   table deferred to an Open Question; THE classifier SHALL NOT hard-code a
   cause→disposition table asserted as universal.

### Requirement 6: Media-based classification is evidence-gated and fidelity-flagged

**User Story:** As the operator, I want tone-based classification (SIT / fax / modem
/ voice) to run only when there is real media to analyze and to refuse to guess, so
that a confident-sounding but unsupported label is never emitted.

#### Acceptance Criteria

1. WHERE no RTP media path is available for a call (no early media received, or the
   media seam is not built — see Requirement 10), THE wardial plugin SHALL classify
   that call by `SipDisposition` alone and SHALL leave `MediaDisposition` as
   `NotAnalyzed`, never inferring a tone outcome without audio.
2. WHEN media is available, THE tone detector SHALL run over decoded linear PCM and
   SHALL emit a `MediaDisposition` only when its detection confidence meets a
   configured threshold; otherwise it SHALL emit `Inconclusive`.
3. THE tone detector SHALL treat SIT, CNG, and CED/answer-tone detection thresholds,
   frequencies, tolerances, and cadences as constants that MUST be grounded in the
   governing standards (ITU-T T.30, V.25/V.8, Telcordia SIT) at build time, and
   SHALL NOT ship invented numeric thresholds (see Open Questions).
4. THE tone detector SHALL NOT claim to distinguish a live human from voicemail
   beyond what the evidence supports; where it cannot, the `MediaDisposition` SHALL
   be `Voice` (undifferentiated), not a fabricated human/VM split.
5. THE RTP depacketizer and PCM decoder SHALL be total over untrusted input: a
   malformed packet, an unknown payload type, or a truncated stream SHALL be dropped
   or mapped to `Inconclusive`, never a panic.

### Requirement 7: Per-call resilience and degenerate-case discipline

**User Story:** As the operator, I want one dead number to never abort the sweep, and
a sweep that reached nothing to be reported as a failure, so that a
technically-correct-but-useless run is not mistaken for "the block is empty".

#### Acceptance Criteria

1. WHEN a single call times out or hits a transport error, THE origination layer
   SHALL record a `CallResult { reached: false }` and continue with the next DID,
   never aborting the sweep.
2. WHEN a call receives bytes that do not parse as a SIP response, THE origination
   layer SHALL record `reached: true` with `SipDisposition::Unknown` (it will not
   guess).
3. WHEN no DID in the range was reached (every call errored or timed out), THE
   wardial plugin SHALL return `Err(PluginError::Empty)`.
4. WHEN at least one DID was reached, THE wardial plugin SHALL return `Ok(Event)` —
   "these numbers are disconnected / these are busy" is itself a real, reportable
   result.

### Requirement 8: Cost and attribution are acknowledged before the grant

**User Story:** As the operator, I want to be forced to confront that this run is
billable and attributable before it is authorized, so that the heaviest active op in
the workbench cannot be fired reflexively.

#### Acceptance Criteria

1. WHEN the operator initiates a wardial run, THE CLI SHALL surface, before
   requesting the `Grant`, an explicit notice that origination is billable
   (metered on the trunk), attributable (identified by the trunk account and
   caller-ID), and can complete a call to a real person.
2. THE CLI SHALL require an explicit affirmative cost/attribution acknowledgement
   before calling `Gate::request_ip`; absent it, no `Grant` is requested and no call
   is placed. (The exact form of the affirmative — a flag vs. an interactive
   confirm — is an Open Question.)
3. THE operator's gate `basis` for a wardial run SHALL be expected to state the
   authorization *and* the cost/attribution acknowledgement, and SHALL be recorded
   verbatim to the capture timeline by the auth-gate as for any Axis-A op.
4. THE CLI SHALL NOT place the trunk's SIP auth secret into the `basis`, the command
   `arg`, or any logged field; credentials live only in `TrunkConfig`.

### Requirement 9: The trunk is a config seam; the offline story is honest

**User Story:** As the operator, I want wardial to run everything it can without a
trunk (against loopback and recorded audio) and to make the origination path light
up only when a real trunk is configured, and I want the offline claim stated
honestly.

#### Acceptance Criteria

1. WHERE no `TrunkConfig` is configured, THE wardial plugin SHALL NOT place a call
   onto the PSTN; the origination path SHALL be present but inert, exercisable only
   against a loopback / recorded source.
2. THE wardial plugin SHALL use `std::net` for SIP and RTP and SHALL add zero egress
   dependencies: `cargo tree -e no-dev` on the default graph SHALL show no
   `reqwest`.
3. THE project documentation SHALL state the offline guarantee as "zero egress
   *dependencies*", NOT "no active code" — the default binary contains an inert
   origination path, present but unreachable without both a `Grant` and a
   `TrunkConfig`.
4. THE tone detector and PCM decoder SHALL be pure Rust with no added dependency,
   preserving the aarch64-musl static build.

### Requirement 10: The RTP/early-media prerequisite is explicit, not assumed

**User Story:** As a maintainer, I want the spec to state plainly that no media
handling exists in the workbench yet, so that media-based classification is planned
as a prerequisite build rather than silently assumed present.

#### Acceptance Criteria

1. THE design SHALL document that phonetool-sip is signalling-only (UDP OPTIONS, no
   SDP, no RTP) and that SDP negotiation, RTP receive/depacketize, and codec decode
   do not exist anywhere in the workbench.
2. THE wardial plugin SHALL be usable at `SipDisposition`-only fidelity before any
   media path is built, and SHALL degrade to `MediaDisposition::NotAnalyzed` in that
   mode (per Requirement 6.1) rather than being blocked entirely.
3. THE design SHALL name the media-path options (a minimal in-process Tier-A RTP /
   G.711 receiver versus a Tier-B subprocess media handler) and SHALL recommend a
   direction WITHOUT silently deciding it (see Open Questions).
4. WHERE media handling is later routed through a Tier-B subprocess, THE `Grant`
   SHALL be obtained on the Rust side and only then SHALL the child be driven — a
   subprocess is never a gate bypass.

### Requirement 11: No unsafe, no panics, no RNG dependency

**User Story:** As a maintainer, I want the crate hardened and dependency-lean, so it
preserves the pure-Rust static-musl offline build and cannot fall over on hostile
SIP / SDP / RTP input.

#### Acceptance Criteria

1. THE crate SHALL compile under `unsafe_code = forbid` and the workspace
   `unwrap_used`/`expect_used`/`indexing_slicing = deny` lints.
2. THE crate SHALL derive per-transaction SIP identifiers (branch/tag/call-id)
   without an RNG dependency (FNV-1a over grant fields, reusing the phonetool-sip
   pattern), so it adds no `rand`/`getrandom` dependency.
3. THE crate SHALL validate every inbound boundary — SIP response, SDP body, RTP
   packet — before use, treating all of them as adversary input.
