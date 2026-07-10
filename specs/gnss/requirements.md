# Requirements Document — phonetool-gnss

## Introduction

`phonetool-gnss` is the workbench's satellite-navigation **receive** path: acquire and
track GPS L1 C/A (extensible to GLONASS, Galileo, BeiDou), decode the broadcast
navigation message, solve a position/velocity/time fix — and, the reason the layer
exists, **detect spoofing and jamming** of that fix. Receiving GNSS is observation:
photons already arriving at an antenna, near-universally legal on the receive path. The
layer therefore declares `CapabilityClass::Passive`, is handed no gate, and implements
the passive `Plugin` trait — never `ActivePlugin`. It holds `Transducer::RfRx`. It
transmits nothing and requires no `Grant` or `TxGrant`.

The point of the layer is **defense**: an unattended GNSS fix is trivially forged. A
spoofer transmits valid-looking, higher-power L1 signals to walk a receiver's solution
off the truth; a jammer raises the in-band noise floor to deny a fix entirely. Both are
field-realistic threats to a device that navigates or timestamps without a data network.
So the deliverable is not just "a fix" — it is **a fix qualified by an integrity
verdict**, plus a jamming/spoofing assessment that runs even when no fix is obtained.

phonetool builds software ahead of hardware. This layer has two faces. **Today, with no
antenna**, it runs end-to-end against a *recorded or synthetic* IQ capture read from a
file (the same `SdrSource` / `IqFileSource` seam that `phonetool-sdr-rx` defines):
acquire → track → decode → PVT → integrity, all offline, no radio present. **When
hardware arrives**, a live receive path snaps in behind that seam — primary as a
**Tier-B** `gnss-sdr` child driven over the subprocess-IPC control channel with bulk IQ
moved out-of-band by handle; alternatively via the off-by-default FFI-quarantine crate.
The acquisition, decode, PVT, and integrity modules do not change; only the sample source
does.

The bytes decoded here are **adversary-controlled**. The navigation message is exactly
what a spoofer forges: a valid-looking frame carrying lying ephemeris and time. **The
spoof detector is the trust boundary** — no decoded nav field is trusted as truth until
the integrity layer has had its say. Every decoder is total over untrusted input: it
never panics, never trusts an air-supplied length or count to size an allocation, and
records a field it could not decode as absent rather than fabricating one. Crucially, a
run that acquires no fix returns an honest "no fix" and **never a fabricated position**; a
run that observed nothing usable is a failure the operator sees (`PluginError::Empty`),
not an empty success.

**Grounding discipline:** the spoof/jam detector *families* below are drawn from
the GNSS-security literature, but this document states **no numeric detection
thresholds** — carrier-to-noise floors, AGC-deviation bounds, position/velocity-jump
limits, and scoring weights are all deferred to configuration and to build-time
calibration against cited references (see `## Open questions for operator`). Inventing a
plausible threshold is the failure mode this project forbids.

This document specifies the layer. **No code is written this sprint** (see `design.md`).

## Glossary

- **phonetool-gnss**: The crate/plugin under specification; the passive GNSS receive,
  fix, and spoof/jam-detection capability.
- **`GnssRx`**: The plugin type. Manifest name `"gnss"`, transducer `RfRx`, capability
  class `Passive`. Implements `Plugin`, not `ActivePlugin`.
- **GNSS**: Global Navigation Satellite System — the umbrella for GPS, GLONASS, Galileo,
  and BeiDou. This layer builds **GPS L1 C/A** first; the others are extension targets
  behind grounded per-constellation configuration.
- **GPS L1 C/A**: The GPS civil signal on the L1 carrier (1575.42 MHz), a per-satellite
  Gold code (PRN) carrying a 50 bit/s navigation message. The authoritative signal
  definition is **IS-GPS-200** (the grounding document; see Open Questions).
- **PRN / SV**: Pseudo-Random Noise code index / Space Vehicle — one satellite's
  distinguishing code and the satellite itself.
- **`SdrSource` / `IqFileSource`**: The device-agnostic RX sample seam and its
  hardware-free file implementation, defined by `phonetool-sdr-rx` and **reused** here
  (not re-invented). `IqFileSource` reads a recorded/synthetic IQ capture; a live source
  implements the same trait behind a feature.
- **`GnssSdrSource`**: The Tier-B live source — a `gnss-sdr` child process driven over
  the subprocess-IPC contract, behind an off-by-default feature. The device seam.
- **Acquisition**: The coarse search over (PRN × Doppler × code-phase) that detects which
  satellites are present in an IQ block and estimates each one's code phase, Doppler, and
  carrier-to-noise density.
- **Tracking**: The per-SV loops (code/carrier) that refine acquisition and produce
  correlator outputs (Early/Prompt/Late), carrier phase, and a C/N0 estimate over time —
  the raw material the integrity detectors consume.
- **C/N0**: Carrier-to-noise-density ratio (dB-Hz), the standard per-SV signal-strength
  observable. Abnormally high or suspiciously uniform C/N0 across SVs is a spoofing tell.
- **AGC**: Automatic Gain Control level reported by a front-end. A sudden AGC change is a
  classic in-band-power / jamming indicator. Available only from a live device source.
- **Navigation message / ephemeris / TOW**: The broadcast data bits carrying satellite
  orbit parameters (ephemeris), clock corrections, and Time-Of-Week. **Untrusted input** —
  a spoofer authors these.
- **Pseudorange**: The apparent satellite-to-receiver range derived from code phase and
  time-of-transmission, the input to the position solve.
- **PVT / `Fix`**: Position-Velocity-Time solution and the value carrying it. `Fix` is
  emitted only when a solve succeeds; absence of a solve is `fix: null`, never a guess.
- **`IntegrityFlag` / `IntegrityKind`**: An advisory spoof/jam indicator and its category
  (e.g. `ClockAnomaly`, `PositionJump`, `PowerAnomaly`, `SqmDistortion`,
  `CrossConstellationDisagreement`, `SingleSourceGeometry`, `NoiseFloorElevation`,
  `AgcAnomaly`, `SimultaneousLossOfLock`).
- **SQM**: Signal-Quality Monitoring — correlator-shape metrics (e.g. early/late-phase,
  ratio, delta) that distort when an authentic and a spoofed correlation peak interact.
- **AoA**: Angle-of-Arrival — the direction a signal arrives from. A single-antenna
  spoofer emits every "satellite" from one direction; AoA discrimination is the strongest
  single-receiver spoof tell but **requires multi-antenna hardware the RX seam cannot
  express yet** (see Requirement 10, the known gap).
- **OSNMA**: Galileo Open Service Navigation Message Authentication — a cryptographic
  nav-message authentication scheme; a future per-signal spoof defense, out of scope for
  the GPS-L1-C/A first cut.
- **Baseline**: An operator-supplied reference (a last-known good position, a surveyed
  static location, an independent time source) the detectors compare against. Its
  provenance is an Open Question.
- **`CaptureRef { kind, path }`**: The `phonetool-core` capture record for a bulk
  artifact. Bulk IQ is referenced by on-disk path (`CaptureKind::Iq`), **never** inlined
  into an `Event`.
- **Tier-A / Tier-B**: Tier-A is a native in-process Rust plugin. Tier-B is an
  out-of-process capability (a `gnss-sdr` flowgraph) driven over
  `specs/subprocess-ipc-contract/`. This layer argues Tier-B primary for live decode
  breadth, with a native `IqFileSource` acquisition path as the Tier-A ahead-of-hardware
  proof.
- **`Passive`**: The capability class (no gate). RX is observation; `RfRx` is the
  transducer; neither the `Plugin` trait nor this layer ever sees a `Grant`/`TxGrant`.
- **Degenerate result**: A run that observed nothing usable — no SV energy, no fix, and no
  integrity signal — which is a failure the operator sees (`PluginError::Empty`), distinct
  from an honest no-fix that still reported a jamming/spoofing detection.
- **Operator**: The human invoking phonetool.

## Requirements

### Requirement 1: Passive, RX-only — no gate; the fix is never trusted blindly

**User Story:** As the operator, I want GNSS work to carry zero authorization friction
because receiving is observation, while never being handed a fix I am asked to trust
without an integrity verdict.

#### Acceptance Criteria

1. THE gnss manifest SHALL declare `Transducer::RfRx` and `CapabilityClass::Passive`.
2. THE gnss plugin SHALL implement the `Plugin` trait and SHALL NOT implement
   `ActivePlugin`.
3. THE gnss plugin SHALL perform its operation without constructing a `Gate`, without
   requesting a `Grant` or `TxGrant`, and without emitting a consent record.
4. THE gnss plugin SHALL NOT transmit and SHALL expose no operation that energizes a
   transmit path.
5. WHEN `dispatch` receives a verb other than `"fix"`, THE gnss plugin SHALL return
   `Err(PluginError::Unsupported)`.
6. THE gnss plugin SHALL emit every `Fix` accompanied by an integrity verdict, and SHALL
   NOT report a position without the accompanying spoof/jam assessment (see Requirement 9).

### Requirement 2: Runs today on a recorded/synthetic capture; live RX behind the device seam

**User Story:** As the operator with no antenna yet, I want the full acquire → fix →
integrity pipeline to run over a recorded or synthetic IQ file today, so the software is
proven before any radio exists and the live path is just a source swap.

#### Acceptance Criteria

1. WHEN `dispatch` receives verb `"fix"` with an `arg` naming a readable local IQ capture,
   THE gnss plugin SHALL run acquire → track → decode → PVT → integrity without opening
   any radio device.
2. THE gnss plugin SHALL use `IqFileSource` (the `phonetool-sdr-rx` RX seam) as the
   default, hardware-free source, requiring no device and no off-by-default feature.
3. THE gnss plugin SHALL drive its acquisition, decode, PVT, and integrity modules against
   the `SdrSource` trait only, never against a concrete device type, so the pipeline is
   identical for a file source and a live radio.
4. THE gnss plugin SHALL place the live receive path behind the `SdrSource` seam
   (`GnssSdrSource`, a Tier-B `gnss-sdr` child, or an off-by-default FFI-quarantine device
   source) so it snaps in when an `RfRx` device arrives without changing the acquire,
   decode, PVT, or integrity modules.
5. WHEN `arg` is blank/absent and no live source is configured, THE gnss plugin SHALL
   return `Err(PluginError::InvalidInput)` before any DSP work; WHEN `arg` names a file
   that fails to open or read, THE gnss plugin SHALL return `Err(PluginError::Backend)`.
6. WHERE a source cannot supply a sample rate or center frequency compatible with the
   requested GNSS band, THE gnss plugin SHALL return `Err(PluginError::Backend)` rather
   than silently substituting a different rate or frequency.

### Requirement 3: GPS L1 C/A acquisition and tracking; other constellations are grounded extensions

**User Story:** As the operator, I want the receiver to detect and track the GPS
satellites present in a capture, with the door open to GLONASS/Galileo/BeiDou, so I get a
fix from the primary constellation and can extend later without a rewrite.

#### Acceptance Criteria

1. THE gnss plugin SHALL acquire GPS L1 C/A satellites by searching PRN × Doppler ×
   code-phase over an IQ block and SHALL report, per acquired SV, its PRN, estimated code
   phase, estimated Doppler, and estimated C/N0.
2. THE gnss plugin SHALL track each acquired SV to produce the per-SV observables
   (correlator outputs, carrier phase, C/N0 over time) the integrity detectors consume.
3. THE gnss plugin SHALL derive GPS L1 C/A signal parameters (carrier frequency, code
   rate, code length, nav bit rate) from a grounded constant set cited to IS-GPS-200, and
   SHALL NOT hardcode a signal parameter that has not been grounded in a cited reference.
4. WHERE support for GLONASS, Galileo, or BeiDou is enabled, THE gnss plugin SHALL take
   that constellation's signal parameters from its own grounded ICD (deferred — see Open
   Questions) and SHALL NOT reuse GPS parameters for a different constellation.
5. WHEN acquisition finds no SV above the configured acquisition threshold, THE gnss plugin
   SHALL report zero acquired SVs (a real observation, subject to the integrity assessment
   and the degenerate discipline of Requirement 9), never a fabricated SV.

### Requirement 4: The navigation-message decode is total over untrusted bits

**User Story:** As a maintainer, I want every nav-message decode proven never to panic and
never to trust a decoded field as truth, because the bits are exactly what a spoofer
forges.

#### Acceptance Criteria

1. WHEN a nav-message decoder encounters a malformed, truncated, failed-parity, or
   out-of-range field in a subframe, THE decoder SHALL skip or flag that field and
   continue, and SHALL NOT panic, `unwrap`, `expect`, or index unchecked on any input.
2. THE nav-message decoder SHALL treat every decoded length, count, or offset as untrusted
   and SHALL NOT use one to size an allocation or index a buffer without a bound check.
3. WHEN a subframe fails its parity/CRC check, THE decoder SHALL discard that subframe's
   fields rather than admitting unauthenticated content as ephemeris or time.
4. WHEN a field within an otherwise-decodable subframe does not decode, THE decoder SHALL
   record that field as absent/unknown and SHALL NOT substitute a default or guessed value.
5. THE gnss plugin SHALL treat decoded ephemeris and time as *candidate* inputs to the
   PVT solve and the integrity layer, never as trusted truth prior to the integrity verdict.

### Requirement 5: Position/time solve — or an honest no-fix, never a fabricated position

**User Story:** As the operator, I want a real position/time solution when the geometry
supports one and an explicit "no fix" when it does not, so I am never handed a guessed
coordinate.

#### Acceptance Criteria

1. WHEN pseudoranges and valid ephemeris are available for enough satellites to solve, THE
   gnss plugin SHALL compute a `Fix` (position, and time; velocity where derivable) and
   SHALL carry it in the `Event` payload.
2. WHEN too few satellites, insufficient ephemeris, or a non-converging solve prevents a
   solution, THE gnss plugin SHALL report `fix: null` and SHALL NOT emit any position value.
3. THE gnss plugin SHALL NOT fabricate, interpolate, or carry forward a stale position when
   the current solve fails.
4. THE `Fix` SHALL carry a solve-quality indicator (e.g. satellite count and a geometry
   metric) derived from the observed satellites, not a fixed placeholder.

### Requirement 6: Spoofing detection (the defensive payload) — grounded families, calibrated thresholds

**User Story:** As the operator, I want the receiver to flag the tells of a GNSS spoofer,
so an attempt to walk my position or time off the truth is detected rather than silently
accepted — a defense-of-self capability.

#### Acceptance Criteria

1. THE gnss plugin SHALL run a spoofing assessment over the observables of every `"fix"`
   run and SHALL emit `IntegrityFlag`s drawn from a fixed set of grounded categories
   including at least `PowerAnomaly` (abnormally high or uniform C/N0 across SVs),
   `ClockAnomaly` (receiver clock-bias/-drift discontinuity), `PositionJump` (implausible
   position/velocity discontinuity vs the baseline), `SqmDistortion` (correlator-shape
   distortion), and `CrossConstellationDisagreement` (disagreeing PVT across
   constellations).
2. THE gnss plugin's spoofing-detection numeric thresholds and scoring weights (C/N0
   bounds, clock-drift limits, position/velocity-jump limits, SQM-metric cutoffs) SHALL be
   supplied as configuration inputs, and THE gnss plugin SHALL NOT hardcode any detection
   threshold that has not been grounded in cited GNSS-security research — each such value
   remains an Open Question until calibrated.
3. WHEN a spoofing detector's evidence exceeds its configured threshold, THE gnss plugin
   SHALL emit the corresponding `IntegrityFlag` carrying the supporting evidence
   (the metric value and the SVs involved).
4. THE `IntegrityFlag`s SHALL be advisory: THE gnss plugin SHALL report each flag with its
   evidence and SHALL NOT take any active or transmit action in response.
5. WHERE a spoofing detector requires an input the current source cannot supply (e.g. AoA
   from a single-antenna capture, or a baseline the operator did not provide), THE gnss
   plugin SHALL mark that detector's result as `unavailable` and SHALL NOT report a
   negative result as "no spoofing" for a check it could not perform.

### Requirement 7: Jamming detection — runs even when no fix is obtained

**User Story:** As the operator, I want denial of a fix to be diagnosed as jamming when the
evidence supports it, so "no position" is not silently mistaken for "no satellites in view."

#### Acceptance Criteria

1. THE gnss plugin SHALL run a jamming assessment on every `"fix"` run, including runs in
   which no SV was acquired and no fix was solved.
2. THE jamming assessment SHALL emit `IntegrityFlag`s from a grounded set including at
   least `NoiseFloorElevation` (in-band power/noise-floor rise), `AgcAnomaly` (a front-end
   AGC deviation, where the source reports AGC), and `SimultaneousLossOfLock` (all tracked
   SVs losing lock together, which a genuine outage rarely produces).
3. WHERE the source does not report AGC (e.g. a plain IQ file with no front-end metadata),
   THE gnss plugin SHALL mark the AGC-based check `unavailable` and SHALL NOT infer an AGC
   anomaly from absent data.
4. WHEN a jamming detector fires, THE gnss plugin SHALL report the detection as a real,
   reportable result (`Ok(Event)`) even if no fix was obtained — a diagnosed jam is the
   defensive payload, not a degenerate failure.
5. THE jamming-detection numeric thresholds (noise-floor rise, AGC deviation,
   loss-of-lock fraction/timing) SHALL be configuration inputs grounded in cited research,
   not hardcoded literals (see Requirement 6.2 and Open Questions).

### Requirement 8: Bulk IQ is referenced by path, never inlined

**User Story:** As a maintainer, I want raw samples kept out of the event stream, because
MS/s of IQ would swamp the capture timeline and the control channel.

#### Acceptance Criteria

1. WHEN a fix run is backed by an IQ capture, THE gnss plugin SHALL record a
   `CaptureRef { kind: CaptureKind::Iq, path }` on the `CaptureBus` and SHALL NOT inline
   raw samples into the `Event` data.
2. THE `Event` data SHALL carry only bounded structured results — the acquired-SV list,
   the `Fix` (or `fix: null`), and the `IntegrityFlag` list — whose size is bounded by the
   satellite count and the detector-family count, never by the sample count.
3. THE gnss plugin SHALL bound its read of any single source at a configurable sample cap
   (the `SAMPLE_CAP` discipline of `phonetool-sdr-rx`), truncating rather than allocating
   to a source- or file-declared sample count, and SHALL record when truncation occurred.
4. THE gnss plugin SHALL NOT load an unbounded capture file wholly into memory.

### Requirement 9: The integrity verdict qualifies every fix; degenerate = failure

**User Story:** As the operator, I want a fix always paired with its trust verdict, an
honest no-fix that still reports a detected jam/spoof, and a genuinely empty run reported
as a failure — so a technically-correct-but-useless run never reads as a clean fix.

#### Acceptance Criteria

1. WHEN a fix is solved, THE gnss plugin SHALL return `Ok(Event)` carrying the `Fix` and
   its `IntegrityFlag` list — a fix flagged as spoofed is still a reportable result, with
   the spoof verdict as its payload.
2. WHEN no fix is solved but at least one `IntegrityFlag` (jamming or spoofing) was raised,
   THE gnss plugin SHALL return `Ok(Event)` with `fix: null` and the flags — the detection
   is the result.
3. WHEN no fix is solved and at least one SV was acquired, THE gnss plugin SHALL return
   `Ok(Event)` with `fix: null` and the acquired-SV observables — observed satellites
   without a solve is a real partial observation.
4. WHEN a run reads zero samples, or processes samples but observes nothing usable (no SV
   acquired, no fix, and no integrity signal), THE gnss plugin SHALL return
   `Err(PluginError::Empty)`, and the message SHALL name the source and state that nothing
   usable was observed.
5. THE gnss plugin SHALL distinguish "nothing observed" (degenerate failure,
   `PluginError::Empty`) from "no fix but a jam/spoof detected" (a reportable `Ok(Event)`).

### Requirement 10: Multi-antenna / AoA anti-spoof has no source seam (known architectural gap)

**User Story:** As a maintainer, I want the absence of a hardware seam for the strongest
spoof discriminator surfaced explicitly, so the layer does not silently ship a weaker
detector set as if it were complete, and the operator decides the direction.

#### Acceptance Criteria

1. THE design SHALL document that angle-of-arrival / single-source-geometry spoof
   discrimination requires a multi-antenna (multi-channel) front-end, which the single-
   stream `SdrSource` seam and the `RfRx` transducer cannot express.
2. THE gnss plugin SHALL treat `SingleSourceGeometry` / AoA-based checks as `unavailable`
   on any single-stream source and SHALL NOT report their absence as evidence of no
   spoofing (per Requirement 6.5).
3. THE design SHALL record, as a prerequisite and an Open Question, how a multi-channel RX
   seam would be introduced (an optional multi-stream `SdrSource` variant, a distinct
   downstream layer, or deferral) WITHOUT silently deciding it.
4. THE gnss plugin SHALL resolve, before a live Tier-B path is built, how the Tier-B
   subprocess host arbitrates the one physical SDR when a `gnss-sdr` child holds the device
   (the logical `RfRx` index is now shareable and does not arbitrate hardware — spine sprint)
   — an unresolved seam recorded as an Open Question and a prerequisite task (the
   Tier-B `SubprocessPlugin` of `specs/subprocess-ipc-contract/` does not exist yet).

### Requirement 11: Hardened, offline-structural, no unsafe in the default path

**User Story:** As a maintainer, I want the decode path hardened and dependency-lean, so it
preserves the pure-Rust static-musl offline build and cannot fall over on hostile input.

#### Acceptance Criteria

1. THE default (no-device, no-subprocess) build SHALL compile under `unsafe_code = forbid`
   and the workspace `unwrap_used` / `expect_used` / `indexing_slicing = deny` lints.
2. THE acquisition, tracking, decode, PVT, and integrity modules SHALL contain no
   `unsafe`; any C-driver / DSP FFI SHALL live in a separate FFI-quarantine crate behind an
   off-by-default Cargo feature, never in the default path.
3. THE default build SHALL add zero network-egress dependencies; the default path SHALL
   read local capture files only, and any Tier-B subprocess transport SHALL be behind an
   off-by-default feature. The offline claim is "zero egress dependencies on the analysis
   path," verified by `cargo tree -e no-dev`.
4. THE gnss plugin SHALL avoid an RNG dependency where a value is derivable, consistent
   with the workspace pure-Rust static-musl target.
