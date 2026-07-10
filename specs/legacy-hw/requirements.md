# Requirements Document — phonetool-legacy-hw

## Introduction

`phonetool-legacy-hw` is the workbench's **copper / lineman physical-I/O** layer: the
classic analog local-loop world of DTMF/MF signalling, Bell-202 Caller-ID, loop-current
and line-voltage sensing, and the historical phreak primitives (bluebox 2600/MF, loop
seizure). It has two halves that sit on opposite sides of the gate:

- **(A) RX / SENSE — `Passive`.** Loop-current and line-voltage sensing, ring detect,
  hook-state, DTMF/MF decode, and Bell-202 Caller-ID FSK decode. Observation of a line's
  state or of audio the operator already holds. On neither gate axis; never touches the
  gate — the same stance as numintel and sdr-rx.
- **(B) ACTIVE PHYSICAL INJECTION — the gap.** Tone generation *onto a live pair*
  (DTMF/MF dialing, historical bluebox 2600/MF), loop seizure, ring injection, and
  line characterization that *drives* the tip-and-ring pair.

The offensive half surfaces a **load-bearing architectural gap**: active physical
injection fits **neither** existing gate axis. It is not Axis A (there is no IP target)
and not Axis B (there is no RF spectrum / license). Seizing a loop or MF-signalling a
switch the operator does not own is a **distinct wrong** — theft of service and physical
trespass on carrier plant — carrying a **distinct physical hazard** (telco line voltage).
This spec's top deliverable for the operator is the question of whether phonetool needs a
**third gate axis** (a physical-plant authorization token — a `WireGrant` over line/pair
ownership) or whether physical injection folds under Axis A with `target = "<line-ID>"`.
This document **recommends a direction and does not silently decide it** (Open Question 1).

Per the operator directive, software leads hardware: the entire DSP half is verifiable
**today with no device** — Goertzel DTMF/MF decode over a supplied WAV/PCM buffer,
Bell-202 Caller-ID FSK decode over a sample, and DTMF/MF/2600-SF tone **synthesis rendered
to a WAV file**. Physical loop I/O (GPIO/ADC/relay/SLIC) sits behind an off-by-default
hardware feature in an FFI-quarantine crate that alone relaxes `unsafe_code = forbid`,
board-agnostic (gpio-cdev / linux-embedded-hal, **not** the archived `rppal`).

> This spec is authored ahead of any physical loop hardware. Everything in Requirements
> 1–6 and 10 runs **TODAY** against a supplied WAV / recorded trace with no device. Live
> sensing (Requirement 5) sits behind a device seam; **active injection (Requirements 7–9)
> is not built at all** — it is blocked on the gate-axis decision and the safety interlock.

## Glossary

- **phonetool-legacy-hw**: The crate(s) under specification; the copper/lineman
  physical-I/O layer. Two faces of one `Wireline` capability: passive decode/sense (built)
  and active injection (deferred behind the gate gap).
- **Wireline**: The `Transducer` this layer binds — the single physical loop tap
  (butt-set / alligator clips). **Exclusive**: only one plugin may hold it
  (`registry::is_exclusive`), because the bench has one pair of clips.
- **Passive**: Observation / RX / sensing. On neither gate axis; never constructs or
  consults a `Gate`. The passive half implements only the `Plugin` trait.
- **DTMF**: Dual-Tone Multi-Frequency — the touch-tone dialing scheme (one low-group +
  one high-group tone per digit; ITU-T Q.23 / Q.24).
- **MF (R1)**: Multi-Frequency inter-register/trunk signalling — tone *pairs* from a
  six-frequency set; the historical inter-office signalling blueboxing exploited.
- **SF / 2600**: Single-Frequency supervision — the 2600 Hz tone associated with trunk
  supervision in the MF era; the canonical bluebox seizure tone.
- **Goertzel**: A single-bin DFT algorithm used to detect a fixed tone frequency in a
  sample buffer cheaply — the decode kernel for DTMF/MF/SF.
- **Bell-202 / Caller-ID (CID) FSK**: The frequency-shift-keyed modem tones (mark/space)
  carrying the on-hook Caller-ID data burst between the first and second ring.
- **CID frame**: The decoded Caller-ID payload (calling number, optional name, timestamp).
  **Adversary-controlled**: caller-ID is trivially spoofed, so a decoded CID frame is an
  *observation*, never a trusted identity.
- **Loop current / line voltage**: The DC current drawn by an off-hook set and the
  tip-and-ring voltage — the electrical signals a passive sense path classifies.
- **On-hook / off-hook**: The idle vs seized state of the loop. Nominal idle tip-ring
  voltage and ringing voltage are hazardous (see Requirement 8).
- **Loop seizure**: Going off-hook — drawing loop current to seize the line. An **active**
  operation (drives the pair).
- **Ring injection**: Applying ringing voltage to the pair. An **active** operation.
- **SLIC**: Subscriber Line Interface Circuit — the codec/driver IC that terminates and
  drives a subscriber loop; the injection path's hardware front end.
- **Plant**: Carrier-owned outside/inside physical infrastructure (the pair, the switch).
- **Theft of service / plant trespass**: The distinct wrong committed by driving a line
  the operator does not own — neither cybercrime (Axis A) nor a spectrum offense (Axis B).
- **`WireGrant`** *(proposed, does not exist)*: A hypothetical third-axis authorization
  token over physical-plant ownership (line/pair-ID + plant basis), analogous to `Grant`
  (Axis A) and `TxGrant` (Axis B). Its existence is Open Question 1, not a decision.
- **Hardware-safety interlock**: An explicit, affirmative hardware-safety assertion that
  must precede any injection, independent of authorization — the line-voltage safeguard.
- **Source seam**: The RX-only trait separating the DSP/sense pipeline from the sample
  producer — `WavFileSource` (default, no hardware) vs a device source behind a feature.
- **FFI-quarantine crate** (`phonetool-linehw-ffi`): The off-by-default crate that alone
  relaxes `unsafe_code = forbid` to hold the GPIO/ADC/relay/SLIC FFI.
- **`Plugin` / `ActivePlugin`**: The passive and active core traits (`phonetool-core`).
  The passive half implements `Plugin`; the active half has **no legal trait yet** — see
  the gate gap (Requirement 7).
- **`Grant` / `TxGrant`**: The existing Axis-A and Axis-B tokens (`phonetool-authgate`).
  Neither models physical-plant authorization — that is the gap.
- **`CaptureRef` / `CaptureKind::CallAudio`**: The bulk-capture reference on the
  `CaptureBus`; synthesized WAVs and captured loop audio are referenced by path, never
  inlined.
- **Switch-generation class**: A named historical central-office / line-side switch type
  the operator supplies as context (step-by-step, crossbar, ESS, DSS, COCOT). Per-class
  signalling behavior is **grounded or deferred, never confabulated** (Requirement 10).
- **Degenerate result**: A decode/sense run that learned nothing (unreadable or empty
  input) — a failure the operator sees, not an empty success.

## Requirements

### Requirement 1: The wireline capability is passive by construction and hardware-free today

**User Story:** As the operator, I want the copper layer's decode and sense work to carry
no authorization friction and to run with no device attached, so recon on audio and traces
I already hold is immediate and the active half cannot leak into it.

#### Acceptance Criteria

1. THE built layer SHALL implement only the passive `Plugin` trait (`dispatch(&self, cmd)`)
   and SHALL NOT implement `ActivePlugin` or reference `Grant` / `TxGrant` on any code path.
2. THE plugin's manifest SHALL declare transducer `Wireline` and capability
   `CapabilityClass::Passive`.
3. THE plugin's default (no-feature) build SHALL operate entirely on supplied inputs
   (a WAV/PCM buffer, a recorded sense trace) and SHALL require no GPIO/ADC/relay hardware.
4. WHEN `dispatch` receives a command whose verb is not a supported passive verb
   (decode / cid / sense / synth), THE plugin SHALL return `Err(PluginError::Unsupported)`.

### Requirement 2: Total DTMF/MF decode over untrusted audio

**User Story:** As the operator, I want to recover the touch-tones or MF digits present in
a recording without the decoder ever panicking or inventing a digit, because the sample
buffer is adversary-authored input.

#### Acceptance Criteria

1. WHEN given a supplied PCM/WAV sample buffer, THE decode path SHALL detect DTMF (and,
   where configured, MF R1) symbols using a Goertzel per-target-frequency kernel and SHALL
   return the ordered sequence of decoded symbols.
2. WHEN a candidate tone pair does not confidently match a symbol in the grounded tone
   table (frequency and twist/duration within configured tolerances), THE decode path SHALL
   emit **no symbol** for that interval rather than a guessed one.
3. THE decode path SHALL bound the analyzed buffer at a configured `SAMPLE_CAP`, truncating
   rather than allocating to any declared/attacker-supplied length, and SHALL record in the
   event when truncation occurred.
4. THE decode path SHALL be total over any byte input — no `unwrap`, `expect`, unchecked
   index, or panic on empty, non-audio, mis-sized, or oversized-declared input (enforced by
   the workspace deny-lints on library code).
5. WHERE the WAV/PCM container header is malformed or its declared sample count exceeds the
   buffer, THE decode path SHALL return `Err(PluginError::InvalidInput)` before analysis,
   never trusting the declared length as an allocation size.

### Requirement 3: Total Bell-202 Caller-ID decode; the decoded identity is untrusted

**User Story:** As the operator, I want to recover a Caller-ID FSK burst from a sample and
have the tool treat the recovered calling number as an *observation*, not an identity,
because caller-ID is trivially spoofed and is itself a fraud vector.

#### Acceptance Criteria

1. WHEN given a sample buffer containing a Bell-202 FSK burst, THE cid path SHALL demodulate
   the mark/space tones and decode the Caller-ID frame (calling number, optional name and
   timestamp) into a serializable `CidFrame`.
2. THE cid path SHALL treat every decoded CID field as untrusted structure: it SHALL report
   the fields as *observed on the wire* and SHALL NOT assert them as a verified identity,
   nor take any action keyed on them.
3. WHEN the burst is absent, truncated, or fails checksum/parity validation, THE cid path
   SHALL report the frame as `decoded: false` (or return `Err(PluginError::Empty)` if no
   frame was recoverable) rather than emitting a fabricated or partially-guessed number.
4. THE cid path SHALL be total over any byte input — no panic, `unwrap`, `expect`, or
   unchecked index — for any buffer length or content.

### Requirement 4: Synthesis is a passive WAV renderer, inert until hardware

**User Story:** As the operator, I want to render DTMF/MF/2600-SF tones to a file so I can
build and inspect signalling offline, and I want it to be impossible for that rendering to
touch a live line, so synthesis carries no injection risk on its own.

#### Acceptance Criteria

1. WHEN given a symbol/tone specification, THE synth path SHALL render the corresponding
   DTMF / MF (R1) / 2600-SF waveform to an in-memory PCM buffer and, on request, to a WAV
   file, using the grounded tone table.
2. THE synth path SHALL write only to a sample buffer or a file and SHALL have **no code
   path** that drives a physical line, relay, or SLIC — rendering is not injection.
3. WHEN a synthesized WAV is retained, THE plugin SHALL record it on the `CaptureBus` as
   `CaptureRef { kind: CaptureKind::CallAudio, path }` (by path, never inlined in an event).
4. WHEN the synth specification yields no renderable symbol (empty or all-invalid), THE
   synth path SHALL return `Err(PluginError::InvalidInput)`.
5. THE documentation SHALL state that the synthesis code becomes an injection *payload* only
   when a hardware output drives the pair (the active/gated path, Requirement 7) — the
   default binary contains an **inert** tone-generation path, present but line-inert, the
   direct analogue of sip's inert active code path.

### Requirement 5: Passive electrical sensing — recorded trace today, live ADC/GPIO behind a device seam

**User Story:** As the operator, I want to classify loop current, line voltage, ring, and
hook-state from a recorded trace today and have a live line-sense path snap in behind the
same seam when I have the front-end hardware, without the default build depending on it.

#### Acceptance Criteria

1. WHEN given a supplied recorded sense trace (a captured series of ADC/voltage samples),
   THE sense path SHALL classify loop-current level, line-voltage level, ring presence, and
   on-hook/off-hook state, and SHALL return them in the event.
2. THE sense path SHALL drive all classification through a source seam and SHALL NOT depend
   on any concrete device in the default build; a recorded-trace source SHALL be the default.
3. WHERE a live-line sense source (ADC / ring-detect GPIO) is compiled, it SHALL be behind
   an **off-by-default** Cargo feature and SHALL implement the same source seam, so the
   classification logic is unchanged whether the samples are recorded or live.
4. THE sense path SHALL remain `Passive`: reading a line's electrical state is observation,
   requires no gate, and SHALL construct no `Gate` and consult no token.
5. WHEN a sense trace is empty or unreadable, THE sense path SHALL return
   `Err(PluginError::InvalidInput)`; WHEN it is analyzable but shows an idle, quiet line,
   THE sense path SHALL return `Ok(Event)` reporting an idle line — a quiet line is a real
   result, distinct from a useless run.

### Requirement 6: Degenerate-case discipline

**User Story:** As the operator, I want a decode/sense run that learned nothing reported as
a failure, and a run that analyzed cleanly but found nothing reported as a real result, so a
useless run is never mistaken for a clean observation.

#### Acceptance Criteria

1. WHEN a decode input buffer is empty, silence-only-unanalyzable, or unreadable, THE plugin
   SHALL return `Err(PluginError::Empty)` (or `InvalidInput` for a malformed container) —
   a run that recovered nothing usable is a failure, not an empty success.
2. WHEN a buffer is analyzed and confidently contains **zero** DTMF/MF symbols, THE plugin
   SHALL return `Ok(Event)` reporting zero symbols — "this recording carries no tones" is a
   real, reportable observation.
3. THE plugin SHALL never emit a fabricated symbol, a guessed CID field, or a fabricated
   line state to avoid an empty result — confident-match-or-nothing at every decoder.
4. THE event `data` SHALL carry enough counts (symbols decoded, whether the buffer was
   truncated, whether a CID frame validated) to distinguish a partial/degenerate run from a
   clean one.

### Requirement 7: Active physical injection is out of scope and doubly gated (known gap)

**User Story:** As the operator, I want active injection named as a distinct, doubly-gated
future capability — not smuggled into the passive plugin — and I want the missing gate axis
surfaced as a decision I make, so the passive/active line stays a compile-time property.

#### Acceptance Criteria

1. THE built layer SHALL provide **no code path** that seizes a loop, injects tones/ring
   onto a live pair, or otherwise drives the tip-and-ring — it decodes, senses, and renders
   to files only.
2. THE spec SHALL record that active physical injection fits **neither** existing gate axis:
   it is not Axis A (no IP target) and not Axis B (no RF spectrum/license); it is a distinct
   wrong (theft of service / plant trespass) with a distinct hazard (line voltage).
3. THE spec SHALL surface, as **Open Question 1**, whether phonetool adds a **third gate
   axis** — a `WireGrant` minted by a new `Gate::request_wire(WireAuthorization { line_id,
   plant_basis })` and consumed by a new active-wire trait taking `&WireGrant` — **or**
   folds injection under Axis A with `Grant { target = "<line/pair/line-ID>" }`, and SHALL
   **recommend a direction without silently deciding it**.
4. THE spec SHALL record that whichever token is chosen, the future injector requires that
   token **and** the hardware-safety interlock (Requirement 8), and **neither alone
   suffices** — the same double-precondition shape ss7 applies to its future injector
   (`Grant` + a lawful link).
5. THE spec SHALL record that the future injector's authorization token, like every gate
   token, is minted **Rust-side** and its target/line-ID lives in the token, never in the
   `Command` — the active-plugin target invariant, carried to the wireline case.

### Requirement 8: The hardware-safety interlock is a design requirement

**User Story:** As the operator, I want it to be impossible for any future injection to fire
without an explicit hardware-safety assertion, because telco line voltage can injure me or
destroy the front end, and a mis-fired relay is irreversible.

#### Acceptance Criteria

1. THE spec SHALL require that the future injection path fire **only** after an explicit,
   affirmative hardware-safety interlock assertion, and that the absence of that assertion is
   a fail-closed refusal — never a default-fire.
2. THE interlock SHALL be **independent of authorization**: an authorization token
   (`WireGrant` or Axis-A `Grant`) SHALL NOT satisfy the interlock, and the interlock SHALL
   NOT satisfy authorization — the two are orthogonal preconditions.
3. THE interlock and all line-driving code SHALL live in the FFI-quarantine crate
   (Requirement 9), so no default-build code can energize a pair.
4. THE spec SHALL treat the line-voltage hazard figures as **nominal and illustrative** —
   idle tip-ring voltage on the order of tens of volts DC and ringing voltage on the order
   of ~90 V AC — and SHALL defer the **exact** interlock trip thresholds and clamp values to
   an Open Question grounded in the specific SLIC/front-end datasheet, never inventing them.

### Requirement 9: FFI quarantine, off-by-default hardware, and a structural offline claim

**User Story:** As a maintainer, I want every line of memory-unsafe device FFI isolated in
one off-by-default crate and the default build to stay pure-Rust, unsafe-free, and
egress-free, so the offline static-musl build is preserved and hardware code cannot
compromise the DSP core.

#### Acceptance Criteria

1. ALL GPIO/ADC/relay/SLIC FFI SHALL live in a single crate (`phonetool-linehw-ffi`) that is
   the **only** crate permitted to relax `unsafe_code = forbid`, and it SHALL be reachable
   only behind an **off-by-default** Cargo feature.
2. THE device FFI SHALL be **board-agnostic** via `gpio-cdev` / `linux-embedded-hal`
   abstractions and SHALL NOT depend on the archived `rppal` or any single-board crate.
3. THE default (no-feature) build SHALL add **zero egress dependencies** and **zero unsafe**:
   `cargo tree -e no-dev` on the default graph SHALL show no network-client crate and no
   device-driver crate for this layer, and the default build SHALL cross-compile to
   `aarch64-unknown-linux-musl` unchanged.
4. THE DSP and sense library code SHALL compile under `unsafe_code = forbid` and the
   workspace `unwrap_used` / `expect_used` / `indexing_slicing = deny` lints, and SHALL add
   no RNG dependency (decode/sense/synth are deterministic).

### Requirement 10: Grounded constants, no confabulated switch-generation behavior

**User Story:** As a maintainer, I want every tone frequency, detection threshold, and any
switch-signalling behavior traceable to a cited standard or hardware datasheet, so the
decoders are correct rather than plausible and the tool never fabricates protocol behavior.

#### Acceptance Criteria

1. THE crate SHALL source every DTMF frequency pair from ITU-T Q.23/Q.24, the Bell-202
   mark/space tones and CID frame format from their governing standard (Bellcore/Telcordia
   GR-30 / GR-31 lineage), and the MF (R1) / 2600-SF tone set from a cited reference, with
   the citation recorded at the definition site.
2. WHERE a required constant — a tone frequency, a twist/duration/detection threshold, an
   interlock trip value, or a CID frame field layout — is not yet verified against its
   standard or datasheet, THE crate SHALL leave it explicitly unresolved (an Open Question or
   a guarded `TODO` that reports `unknown` / declines to decode) and SHALL NOT ship an
   invented value.
3. THE spec SHALL enumerate the switch-generation classes the operator named (step-by-step,
   crossbar, ESS, DSS, COCOT) as **labels only** and SHALL defer every per-class signalling
   specific (dial pulse vs tone, supervision, MF vs SF applicability, coin/COCOT tones) to an
   Open Question grounded in real documentation or a physical unit — it SHALL **not**
   confabulate any switch's signalling behavior or timing.
