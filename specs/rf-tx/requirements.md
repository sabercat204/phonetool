# Requirements Document — phonetool-rf-tx

## Introduction

`phonetool-rf-tx` is the workbench's **transmit** path: it modulates an operator-supplied
payload (Morse/CW, AFSK packet/APRS, FM voice, SSB) into a waveform and — when a real TX
radio is present and authorized — keys it. It is the workbench's **first Axis-B consumer**
and the sharpest legal surface in the project. Transmitting on regulated spectrum without
authority is a **regulatory** offense (FCC / ISED), a *distinct wrong* from cybercrime, so it
answers to a distinct authority and carries a distinct token: the `TxGrant` minted only by
`Gate::request_tx`. This layer is the mirror of `phonetool-sdr-rx`: sdr-rx receives and is
`Passive` (never gated); rf-tx transmits and is **always** gated, per transmission.

Two facts drive the whole design.

- **The danger is emission, not a crash.** Every other layer's threat is a panic/hang/RCE on
  hostile input. Here the input is largely the operator's own, and the danger is *causing a
  real-world transmission* — on the wrong band, over power, or by accident. The
  ahead-of-hardware build must make keying a real radio **structurally impossible**: rendering
  a waveform to a **file** is the compiled-in default, and a device transmit path does not
  exist in the default build at all.
- **This layer needs a core primitive that does not yet exist.** `ActivePlugin::dispatch_active`
  takes `&Grant` (Axis A / cyber) only; there is **no plugin trait today that takes a
  `&TxGrant`**. The `Transducer::RfTx` port and `CapabilityClass::RfTx` label already exist,
  but there is no legal plug-in point for an RF-TX capability. Defining that primitive — a new
  `TxPlugin` trait and a third registry dispatch path — is this layer's load-bearing
  architectural deliverable and its prerequisite.

The operator's standing directive binds this layer: **lack of hardware is not a limiter.** The
entire modulation pipeline is specified to run **today, with no radio**, rendering the IQ or
audio waveform to a file with zero emission — modulation correctness is fully verifiable
offline. A live radio (HackRF / LimeSDR / PlutoSDR — **not** RTL-SDR, which is RX-only) snaps
in later behind an off-by-default FFI-quarantine feature and the `TxGrant`.

**No code is written this sprint** (see `design.md`).

## Glossary

- **phonetool-rf-tx**: The crate under specification; the RF transmit-path plugin.
- **Axis B / regulatory axis**: Band / power / license authority for RF transmission. Distinct
  from Axis A (cyber / target ownership). Illegal transmission is an FCC/ISED offense, not
  cybercrime — a different wrong, a different token.
- **`TxGrant`**: The unforgeable Axis-B token (from `phonetool-authgate`). Private fields, no
  public constructor; obtainable only from a successful `Gate::request_tx`. Carries `band()`,
  `power_dbm()`, and `license_basis()`. Not `Clone`/`Copy` — minted per transmission.
- **`TxAuthorization`**: Operator-supplied Axis-B evidence — `band` + `power_dbm` +
  `license_basis` — validated fail-closed by the gate (empty band → `NoTarget`, empty license
  → `NoBasis`, non-finite power → `Invalid`).
- **`Gate::request_tx`**: The only mint site for a `TxGrant`. Logs every decision (grant and
  refusal) to the injected `ConsentLog`.
- **`TxPlugin`** *(NEW — the core prerequisite)*: The proposed `phonetool-core` trait for a
  transmit capability. `dispatch_tx(&self, cmd: &Command, grant: &TxGrant) -> Result<Event,
  PluginError>`. Takes `&TxGrant`, mirroring how `ActivePlugin::dispatch_active` takes
  `&Grant` — but a distinct trait because `Grant` and `TxGrant` are deliberately
  non-interchangeable types.
- **`dispatch_tx`**: The proposed third registry path, alongside `dispatch` (passive) and
  `dispatch_active` (Axis A).
- **`RfTx` (`RfTx { .. }` transducer)**: `Transducer::RfTx` — the SDR transmit port. An
  **exclusive** physical resource (only `Wireline`/`RfRx`/`RfTx` are exclusive). Already
  defined in `phonetool-core`.
- **`CapabilityClass::RfTx`**: The payload-free manifest label for an Axis-B plugin. Already
  defined in `phonetool-core`.
- **Modulate / `Waveform`**: The pure, sink-free, grant-free step that turns a validated
  payload into a bounded buffer of samples (baseband IQ, or real audio for an AF stage).
  Testable offline with zero emission.
- **CW / Morse**: On-off-keyed continuous-wave; a text payload encoded to dits/dahs.
- **AFSK / Bell-202 / APRS**: Audio-frequency-shift-keyed packet at 1200 baud (Bell 202),
  carrying an AX.25 / APRS frame.
- **FM / SSB**: Frequency-modulated voice; single-sideband voice.
- **`TxSink`**: The device-agnostic **transmit-only** sink trait (the counterpart to sdr-rx's
  `SdrSource`, which has no transmit method). Implemented by `FileSink` (no hardware) and, behind
  features, by TX-capable device sinks. RTL-SDR does **not** implement it.
- **`FileSink`**: The ahead-of-hardware sink. Writes the rendered waveform to a file path.
  Pure Rust, no feature flag, no device, **no emission** — the default.
- **Device sink**: A `TxSink` that keys a real radio (`HackRfTxSink` / `LimeTxSink` /
  `PlutoTxSink`). Behind the FFI-quarantine crate and an off-by-default Cargo feature; its key
  path takes a `&TxGrant`.
- **FFI-quarantine crate**: A separate crate holding all C-driver TX FFI (soapysdr / device
  libs). The *only* place `unsafe_code` is permitted; off by default. The default crate stays
  `unsafe_code = forbid`.
- **`BandPlan`**: The table mapping an authorized band name → its allowed frequency range and
  regulatory power ceiling. The *mechanism* is specified here; the *numeric contents* are
  grounded regulatory constants, deferred to Open Questions (never confabulated).
- **Band-vs-license consistency**: The fail-closed check that the operation's requested
  transmit frequency lies within the band the `TxGrant` authorizes (a 70cm grant cannot key a
  2m frequency).
- **Power ceiling**: The fail-closed cap = min(grant `power_dbm`, the band's regulatory
  maximum). A transmission may not exceed it.
- **`CaptureRef { kind, path }`**: The `phonetool-core` bulk-artifact record. A rendered
  waveform is recorded as `CaptureRef { kind: CaptureKind::Iq, path }` (or `CallAudio` for an
  audio-domain render), never inlined into an `Event`.
- **Tier-A / Tier-B**: Tier-A is a native in-process Rust plugin. Tier-B is an out-of-process
  capability (a GNU Radio TX flowgraph) driven over the subprocess-IPC contract, with the gate
  held Rust-side.
- **Degenerate result**: A transmit request whose validated payload produces zero samples
  (nothing to send) — useless, and therefore a failure the operator sees
  (`PluginError::Empty`), never a silent success that would key a radio with dead air.
- **Emission**: Radiating RF energy from a real antenna. The regulated act; the thing the
  ahead-of-hardware build makes structurally impossible.

## Requirements

### Requirement 1: A transmit is unrepresentable without an Axis-B authorization

**User Story:** As the operator, I want an RF transmission to be impossible to invoke without
the gate having minted a `TxGrant`, so that the regulatory line is a type-level property, not
a reviewer's vigilance — the same guarantee the cyber axis already has.

#### Acceptance Criteria

1. THE rf-tx plugin SHALL be reachable only through a method that takes a `&TxGrant`, and SHALL
   NOT expose any transmit or render path that does not take a `&TxGrant`.
2. THE rf-tx plugin SHALL read the authorized band from `TxGrant::band`, the authorized power
   from `TxGrant::power_dbm`, and the license justification from `TxGrant::license_basis` —
   never from the command.
3. THE rf-tx plugin's manifest SHALL declare transducer `Transducer::RfTx` and capability
   `CapabilityClass::RfTx`.
4. WHERE a caller attempts to fabricate a `TxGrant` to reach the transmit path, THE crate SHALL
   make the code fail to compile (a compile-fail doctest proves it, mirroring authgate and sip).
5. THE `TxGrant` SHALL authorize exactly one transmission; THE rf-tx plugin SHALL NOT re-key or
   auto-repeat a transmission from a single grant.

### Requirement 2: The core needs a new `TxPlugin` trait and dispatch path (the prerequisite gap)

**User Story:** As a maintainer, I want a legal, type-checked plug-in point for an Axis-B
capability, because none exists today — `ActivePlugin::dispatch_active` takes `&Grant` (Axis A)
only — so an RF-TX plugin cannot be wired into the registry without a core change.

#### Acceptance Criteria

1. THE `phonetool-core` `plugin` module SHALL define a `TxPlugin` trait whose method is
   `dispatch_tx(&self, cmd: &Command, grant: &TxGrant) -> Result<Event, PluginError>`, plus a
   `manifest(&self) -> Manifest`.
2. THE `TxPlugin` trait SHALL take `&TxGrant`, and SHALL NOT accept a `&Grant`, so that an
   Axis-A (cyber) authorization can never key a radio and an Axis-B token can never satisfy an
   Axis-A operation.
3. THE `PluginRegistry` SHALL provide a third registration path `register_tx(Arc<dyn
   TxPlugin>)` and a third dispatch path `dispatch_tx(plugin, cmd, grant: &TxGrant)`, alongside
   the existing passive `dispatch` and Axis-A `dispatch_active`.
4. THE `register_tx` path SHALL share the one name namespace and the one exclusive-transducer
   index used by `register` and `register_active` (the existing private `claim` helper), so a
   TX plugin cannot collide on a name and cannot co-hold the exclusive `RfTx` port with a
   second TX plugin.
5. THE `manifests()` listing SHALL span the passive, active, and TX maps so a TX plugin appears
   in `phonetool plugins`.
6. THE `dispatch_tx` registry path SHALL reach only TX plugins, and the passive `dispatch` and
   Axis-A `dispatch_active` paths SHALL NOT reach a TX plugin — the map a name is registered in
   decides which dispatch path is legal.

### Requirement 3: Emission is structurally impossible in the ahead-of-hardware build

**User Story:** As the operator, I want it to be impossible to accidentally key a real radio
before I have deliberately compiled in device support, so that building and testing the
transmit software carries zero risk of an unlawful or unintended emission.

#### Acceptance Criteria

1. THE default build (no device feature) SHALL contain no device `TxSink` implementation, so no
   code path — even holding a valid `TxGrant` — can key a real radio.
2. THE default sink SHALL be `FileSink`, which writes the rendered waveform to a file and
   performs no emission.
3. WHERE the operator has not enabled the FFI-quarantine device feature, THE rf-tx plugin SHALL
   route every transmit request to `FileSink`, and selecting a device sink SHALL fail to
   compile (the type is not present) rather than fail at runtime.
4. WHERE the device feature IS enabled, THE device sink's key path SHALL additionally require a
   `&TxGrant`, so a real emission requires **both** the compiled-in feature **and** a
   gate-minted token (a double lock).

### Requirement 4: The full modulation pipeline runs today with no radio

**User Story:** As the operator, I want to render and verify CW, AFSK, FM, and SSB waveforms to
a file before any transmitter exists, so software progress is never gated on gear arriving.

#### Acceptance Criteria

1. THE rf-tx layer SHALL provide a pure, sink-free `modulate` step that turns a validated
   payload into a bounded `Waveform` (baseband IQ, or audio for an AF stage), requiring no
   device, no feature flag, and no `TxGrant` to invoke as a library function (so modulation is
   unit-testable offline with zero gate friction).
2. THE rf-tx plugin SHALL drive `FileSink` by default, so every supported scheme renders to a
   file and is verifiable against a known-good reference waveform with no hardware attached.
3. THE rf-tx plugin SHALL record a rendered waveform as `CaptureRef { kind: CaptureKind::Iq,
   path }` (IQ domain) or `CaptureRef { kind: CaptureKind::CallAudio, path }` (audio domain),
   and SHALL NOT inline raw samples into an `Event` payload or a subprocess control frame.
4. THE `Event` payload for a render SHALL carry only bounded metadata (scheme, sample count,
   duration, sink kind, truncation flag), never the underlying sample buffer.

### Requirement 5: Band-vs-license consistency and a power ceiling are enforced at the boundary

**User Story:** As the operator, I want a transmission refused when its frequency is not within
the band my `TxGrant` authorized, or when its power exceeds what I am licensed for, so that a
grant for one band cannot key another and an over-power emission cannot slip through.

#### Acceptance Criteria

1. WHEN the operation's requested transmit frequency is not within the frequency range of the
   band named by `TxGrant::band`, THE rf-tx plugin SHALL return `Err(PluginError::InvalidInput)`
   before any modulation or sink work (a 70cm grant cannot key a 2m frequency).
2. WHEN the effective transmit power would exceed the power ceiling — defined as the minimum of
   `TxGrant::power_dbm` and the band's regulatory maximum — THE rf-tx plugin SHALL return
   `Err(PluginError::InvalidInput)` before any sink work.
3. WHERE the band named by `TxGrant::band` is not present in the grounded `BandPlan` table, THE
   rf-tx plugin SHALL fail closed with `Err(PluginError::InvalidInput)`, and SHALL NOT assume a
   frequency range or power limit for an unknown band.
4. THE rf-tx layer SHALL NOT hard-code band-plan frequency ranges or power limits as invented
   literals; those values SHALL be grounded regulatory constants sourced from real FCC/ISED
   tables (the numeric contents are deferred — see `design.md` Open Questions).
5. THE band-vs-license and power checks SHALL run before the sink is selected, so a refused
   transmission never reaches a device sink even when the device feature is enabled.

### Requirement 6: Payload boundary validation per scheme

**User Story:** As the operator, I want each scheme's payload validated before it becomes a
waveform, so that an unencodable character or a malformed frame is rejected rather than
rendered and keyed.

#### Acceptance Criteria

1. WHEN a CW/Morse payload contains a character outside the encodable set (letters, digits, and
   the supported prosigns/punctuation), THE rf-tx plugin SHALL return
   `Err(PluginError::InvalidInput)` before rendering.
2. WHEN an AFSK/APRS payload's callsign or frame fields do not satisfy the AX.25 / APRS framing
   rules, THE rf-tx plugin SHALL return `Err(PluginError::InvalidInput)` before rendering.
3. WHEN an FM or SSB source (an input audio waveform, from a file) cannot be read or is not a
   supported format, THE rf-tx plugin SHALL return `Err(PluginError::Backend)` before rendering.
4. WHEN the command's verb is not a supported scheme (`cw` / `afsk` / `fm` / `ssb`), THE rf-tx
   plugin SHALL return `Err(PluginError::Unsupported)`.
5. THE payload SHALL be treated as untrusted input even though it is largely operator-supplied:
   parsing it (including an AX.25 frame or an input audio file) SHALL be total and SHALL NOT
   `unwrap`, `expect`, index unchecked, or panic on any input of any length.

### Requirement 7: Supported modulation schemes

**User Story:** As the operator, I want CW, AFSK packet/APRS, FM voice, and SSB rendered
correctly, so the workbench can produce every waveform the target services need.

#### Acceptance Criteria

1. WHEN dispatched the verb `"cw"` with a valid text payload, THE rf-tx plugin SHALL produce an
   on-off-keyed CW waveform whose dit/dah timing is derived from a configurable words-per-minute
   rate.
2. WHEN dispatched the verb `"afsk"` with a valid AX.25 / APRS frame, THE rf-tx plugin SHALL
   produce a Bell-202 1200-baud AFSK waveform whose framing (flag, bit-stuffing, FCS) and
   mark/space tones match the grounded AX.25 / Bell-202 specification.
3. WHEN dispatched the verb `"fm"` or `"ssb"` with a valid input audio source, THE rf-tx plugin
   SHALL produce the corresponding modulated waveform.
4. THE rf-tx layer SHALL NOT invent AFSK tone frequencies, baud, framing constants, CW timing
   ratios, or SSB filter parameters as unverified literals; each SHALL be a grounded constant
   cited against its specification (exact values deferred — see `design.md` Open Questions).
5. THE modulated `Waveform` SHALL be bounded by a configurable sample cap; WHEN a payload would
   produce more samples than the cap, THE layer SHALL refuse it with
   `Err(PluginError::InvalidInput)` rather than allocate an unbounded buffer.

### Requirement 8: The transmission is bounded and per-transmission-gated

**User Story:** As the operator, I want one authorized transmission to stay one bounded
transmission, so that a pathological payload or a mis-set duration cannot turn into an unbounded
or repeating key-down.

#### Acceptance Criteria

1. THE rf-tx layer SHALL bound the rendered waveform's duration/sample count by configuration,
   and SHALL refuse a payload that would exceed it.
2. THE rf-tx plugin SHALL perform exactly one transmit per `dispatch_tx` call and SHALL NOT loop
   or schedule a repeat from a single `TxGrant`.
3. WHERE a device sink is keyed, THE device sink SHALL cease transmitting when the bounded
   waveform is exhausted, and SHALL NOT hold the carrier open past the rendered samples.

### Requirement 9: Degenerate result is a failure

**User Story:** As the operator, I want a transmit request that carries nothing to send
reported as a failure, so that a technically-correct-but-useless transmission (dead carrier) is
never mistaken for a successful send.

#### Acceptance Criteria

1. WHEN a validated payload produces zero samples (an empty CW text, an empty AFSK frame, a
   silent/empty audio source), THE rf-tx plugin SHALL return `Err(PluginError::Empty)`.
2. THE rf-tx plugin SHALL NOT key a sink — file or device — with a zero-sample waveform.
3. WHEN a payload produces a valid non-empty waveform, THE rf-tx plugin SHALL return
   `Ok(Event)` — a single Morse character or a one-line APRS beacon is a real, reportable
   result, not a degenerate one.

### Requirement 10: Device sinks are quarantined and off by default; the sink trait is transmit-only

**User Story:** As a maintainer, I want every line of transmit C-driver FFI isolated in one
off-by-default crate, so the default build stays pure-Rust, `unsafe`-free, egress-free, and
statically cross-compilable to aarch64-musl.

#### Acceptance Criteria

1. THE rf-tx layer SHALL define a `TxSink` trait that is transmit-only (a key/send path plus its
   tuning), the mirror of sdr-rx's RX-only `SdrSource`.
2. THE rf-tx layer SHALL place all device TX FFI (`HackRfTxSink` / `LimeTxSink` / `PlutoTxSink`,
   any soapysdr/device binding) in a separate FFI-quarantine crate, which SHALL be the only
   crate permitted to relax `unsafe_code = forbid`, gated behind an off-by-default Cargo feature.
3. THE rf-tx layer SHALL NOT provide a `TxSink` implementation for an RX-only device (RTL-SDR):
   an RX-only radio SHALL have no transmit path, by construction.
4. WHERE the device feature is enabled but the device is absent at runtime, THE device sink
   SHALL return `Err(PluginError::Backend)`, never panic.

### Requirement 11: Hardening and structural offline

**User Story:** As a maintainer, I want the default build hardened, panic-free, egress-free, and
RNG-free, so the layer preserves the pure-Rust static-musl offline guarantee.

#### Acceptance Criteria

1. THE default (no-device, no-subprocess) build SHALL compile under `unsafe_code = forbid` and
   the workspace `unwrap_used`/`expect_used`/`indexing_slicing = deny` lints.
2. THE `modulate` step, the `BandPlan` check, `FileSink`, the `TxSink` trait, and the plugin
   boundary SHALL contain no `unsafe`; `unsafe` SHALL exist only in the off-by-default
   FFI-quarantine crate.
3. THE default graph SHALL contain no network egress dependency; any Tier-B subprocess transport
   SHALL be behind an off-by-default feature, verified by `cargo tree -e no-dev`.
4. THE rf-tx layer SHALL avoid an RNG dependency where a value is derivable, consistent with the
   pure-Rust static-musl target.
