# Requirements Document — phonetool-sdr-rx

## Introduction

`phonetool-sdr-rx` is the workbench's software-defined-radio **receive** path:
sweep the spectrum, identify signals, and demodulate them (FM/AM/SSB → audio;
simple digital → bits). Receiving is observation — photons already arriving at an
antenna — and is near-universally legal, so this layer is `Passive`: it never
touches the auth gate, mirroring numintel's friction-free recon path. The
regulated act is *transmission* (Axis B / `TxGrant`), which this layer does not
perform and must not require.

The operator's standing directive binds the sweep: **lack of hardware is not a
limiter.** The entire DSP + classify + demod pipeline is specified to run **today,
with no radio attached**, against a recorded or synthetic IQ capture read from a
file. A device-agnostic `SdrSource` seam separates the pipeline from the sample
producer, so a live radio (RTL-SDR, HackRF, LimeSDR, PlutoSDR) snaps in later
behind an off-by-default feature without the pipeline changing. The fleet is not
one capability — RTL-SDR is RX-only (~$30); HackRF/Lime/Pluto are TX-capable — so
an RX operation MUST never require a TX-capable device.

IQ is *data*, but it is adversary-controlled data: a hostile or malformed capture
(a lying metadata header, a pathological sample count, a crafted waveform whose
demodulated payload is a nav message or a digital frame) is attack surface. Every
boundary — file parse, sample budget, demodulated-content decode — validates
fail-closed and never panics.

This document specifies the layer. **No code is written this sprint** (see
`design.md`).

## Glossary

- **phonetool-sdr-rx**: The crate under specification; the SDR receive-path plugin.
- **`SdrSource`**: The device-agnostic trait that yields IQ sample blocks. Its
  contract is RX-only and says nothing about transmission. Implemented by
  `IqFileSource` (no hardware) and, behind features, by device sources.
- **IQ sample**: One complex baseband sample (in-phase + quadrature). A capture is
  a stream of IQ samples at a stated sample rate and center frequency.
- **`IqFileSource`**: The ahead-of-hardware source. Reads a recorded/synthetic IQ
  capture from a file. Pure Rust, no feature flag, no device — the offline default.
- **`RtlSdrSource`**: A device source for RTL-SDR dongles (RX-only). Behind the
  FFI-quarantine crate and an off-by-default Cargo feature.
- **`HackRfSource`**: A device source for a TX-capable radio, used here **RX-only**.
  Behind the same FFI-quarantine crate and feature.
- **FFI-quarantine crate**: A separate crate holding all C-driver FFI (soapysdr /
  librtlsdr / GPIO). It is the *only* place `unsafe_code` is permitted, and it is
  off by default; the core pipeline crate stays `unsafe_code = forbid`.
- **Sweep**: Power-versus-frequency measurement across a band (a periodogram / power
  spectral density estimate). Yields a bounded vector of (frequency, power) bins.
- **Identify**: Energy-detection over a sweep plus a bandwidth/center/modulation
  classification of each detected signal.
- **Demod**: Demodulation of a selected signal — FM/AM/SSB to audio, simple digital
  to bits.
- **`DetectedSignal`**: One identified emission — center frequency, occupied
  bandwidth, estimated modulation label, and measured power.
- **Estimated modulation**: A label from a bounded set (`Fm`, `Am`, `Ssb`, `Digital`,
  `Unknown`). `Unknown` is emitted when the classifier cannot justify a confident
  label — it never fabricates a class.
- **Sample budget / `SAMPLE_CAP`**: A configurable ceiling on samples read from any
  single source, the IQ analogue of sip's `RECV_CAP`. A remote- or file-supplied
  size is never trusted; the source truncates to the budget rather than allocating
  to an attacker-declared length.
- **`CaptureRef { kind, path }`**: The `phonetool-core` capture record for a bulk
  artifact. Bulk IQ is recorded as `CaptureRef { kind: CaptureKind::Iq, path }` and
  demodulated audio as `CaptureRef { kind: CaptureKind::CallAudio, path }` — the
  samples themselves are never inlined into an `Event` or a control frame.
- **Tier-A / Tier-B**: Tier-A is a native in-process Rust plugin. Tier-B is an
  out-of-process capability (a GNU Radio flowgraph) driven over the subprocess-IPC
  contract. This layer argues Tier-B primary for demod breadth, with the native
  `IqFileSource` pipeline as the Tier-A ahead-of-hardware path.
- **`Passive`**: The capability class (no gate). RX is observation; `RfRx` is the
  transducer; neither the `Plugin` trait nor this layer ever sees a `Grant`.
- **Degenerate result**: A run that read zero samples — useless, and therefore a
  failure the operator sees (`PluginError::Empty`), distinct from a run that
  analyzed samples and found a quiet band (a real, reportable observation).

## Requirements

### Requirement 1: A device-agnostic RX source that never assumes transmit

**User Story:** As the operator, I want the DSP pipeline decoupled from any specific
radio through one source trait, so the cheap RX-only dongle and the expensive
TX-capable SDR are interchangeable and no RX operation is blocked for lack of a
transmitter.

#### Acceptance Criteria

1. THE sdr-rx layer SHALL define an `SdrSource` trait whose contract yields IQ
   sample blocks with a stated sample rate and center frequency, and SHALL NOT
   expose any transmit method on that trait.
2. THE sdr-rx layer SHALL drive its `sweep`, `identify`, and `demod` operations
   against the `SdrSource` trait only, never against a concrete device type, so the
   pipeline is identical for a file source and a live radio.
3. THE sdr-rx layer SHALL NOT require a TX-capable device for any operation: an
   RX-only source (`IqFileSource`, `RtlSdrSource`) SHALL satisfy every operation.
4. WHERE a source cannot supply the requested sample rate or center frequency, THE
   sdr-rx layer SHALL return `Err(PluginError::Backend)` rather than silently
   substituting a different rate/frequency.

### Requirement 2: The whole pipeline runs today with no hardware

**User Story:** As the operator, I want to verify sweep, identify, and demod against
a recorded or synthetic IQ file before any radio exists, so software progress is
never gated on gear arriving.

#### Acceptance Criteria

1. THE sdr-rx layer SHALL provide `IqFileSource`, a pure-Rust `SdrSource` that reads
   a recorded/synthetic IQ capture from a file path, requiring no device and no
   off-by-default feature.
2. THE sdr-rx layer SHALL make `IqFileSource` the default source, so `sweep`,
   `identify`, and `demod` all run and are testable against a known IQ file with no
   hardware attached.
3. WHEN `IqFileSource` is given a path that does not exist or cannot be read, THE
   layer SHALL return `Err(PluginError::Backend)` before any DSP work.
4. THE sdr-rx layer SHALL treat the on-file IQ format's declared parameters (sample
   rate, sample count, sample encoding) as untrusted (see Requirement 5), never as
   a directive to allocate or to trust a length.

### Requirement 3: Device sources are quarantined and off by default

**User Story:** As a maintainer, I want every line of C-driver FFI isolated in one
off-by-default crate, so the default build stays pure-Rust, `unsafe`-free, and
statically cross-compilable to aarch64-musl.

#### Acceptance Criteria

1. THE sdr-rx layer SHALL place all device FFI (`RtlSdrSource`, `HackRfSource`, any
   soapysdr/librtlsdr/GPIO binding) in a separate FFI-quarantine crate.
2. THE FFI-quarantine crate SHALL be the only crate in this layer permitted to relax
   `unsafe_code = forbid`, and it SHALL be gated behind an off-by-default Cargo
   feature.
3. THE default build (no device feature) SHALL contain no device FFI, no `unsafe`,
   and zero egress dependencies: `cargo tree -e no-dev` on the default graph SHALL
   show no radio-driver or network crate.
4. WHERE a device feature is enabled but the corresponding device is absent at
   runtime, THE device source SHALL return `Err(PluginError::Backend)`, never panic.

### Requirement 4: Receive is passive and never touches the gate

**User Story:** As the operator, I want RX work to carry zero authorization friction,
because receiving is observation, not an act against a third party.

#### Acceptance Criteria

1. THE sdr-rx plugin SHALL implement the passive `Plugin` trait (not `ActivePlugin`)
   and SHALL declare capability `CapabilityClass::Passive` in its manifest.
2. THE sdr-rx plugin's manifest SHALL declare transducer `Transducer::RfRx`.
3. THE sdr-rx plugin SHALL never receive, require, or reference a `Grant` or a
   `TxGrant` on any code path.
4. THE sdr-rx plugin SHALL perform no transmission and SHALL expose no operation that
   energizes a transmit path.

### Requirement 5: Untrusted IQ is bounded and never inlined

**User Story:** As a maintainer, I want a hostile capture — a lying header, a
pathological sample count, a multi-gigabyte file — to be truncated to a budget and
referenced by path, so it can neither exhaust memory nor swamp the control channel.

#### Acceptance Criteria

1. THE sdr-rx layer SHALL cap samples read from any single source at a configurable
   `SAMPLE_CAP`, truncating rather than allocating to a source- or file-declared
   sample count.
2. WHEN a capture's declared sample count exceeds `SAMPLE_CAP`, THE layer SHALL read
   and analyze only up to `SAMPLE_CAP` samples and SHALL record that truncation
   occurred in the emitted `Event`.
3. THE sdr-rx layer SHALL record any retained bulk IQ as
   `CaptureRef { kind: CaptureKind::Iq, path }` and any demodulated audio as
   `CaptureRef { kind: CaptureKind::CallAudio, path }`, and SHALL NOT inline raw
   samples into an `Event` payload or a subprocess control frame.
4. THE `Event` payload for a sweep or identify SHALL carry only bounded metadata (a
   capped vector of frequency/power bins, a capped list of `DetectedSignal`), never
   the underlying sample stream.

### Requirement 6: Spectrum sweep

**User Story:** As the operator, I want power-versus-frequency across a band, so I can
see what is on the air (or in a recorded capture) at a glance.

#### Acceptance Criteria

1. WHEN dispatched the verb `"sweep"`, THE sdr-rx plugin SHALL produce a bounded
   vector of (frequency, power) bins spanning the source's tuned range and SHALL
   return it in the `Event` payload.
2. THE sweep SHALL derive its bin frequencies from the source's stated sample rate
   and center frequency, not from an operator-supplied frequency in the command.
3. WHEN the source yields zero samples, THE sweep SHALL return
   `Err(PluginError::Empty)` (a degenerate run, per Requirement 9), not an
   empty-but-successful spectrum.
4. THE number of sweep bins SHALL be bounded by configuration, so a long capture
   cannot produce an unbounded `Event` payload.

### Requirement 7: Signal identify (energy-detect + classify)

**User Story:** As the operator, I want detected emissions listed with center,
bandwidth, and a best-effort modulation label, so I can triage a band — while never
being handed a fabricated classification.

#### Acceptance Criteria

1. WHEN dispatched the verb `"identify"`, THE sdr-rx plugin SHALL run energy
   detection over the sweep and SHALL emit one `DetectedSignal` per occupied region,
   each carrying center frequency, occupied bandwidth, and measured power.
2. WHERE an energy-detection threshold is supplied by configuration, THE layer SHALL
   mark a region occupied only when its measured power exceeds that threshold; THE
   layer SHALL NOT hard-code a detection threshold (the numeric value is deferred —
   see `design.md` Open Questions).
3. WHEN the classifier cannot justify a confident modulation label for a detected
   signal, THE layer SHALL report `Unknown`, never a guessed class.
4. WHEN energy detection finds no region above the configured threshold, THE identify
   operation SHALL return `Ok(Event)` reporting zero detections — an analyzed-but-
   quiet band is a real observation, not a failure.

### Requirement 8: Demodulation

**User Story:** As the operator, I want a selected signal demodulated to audio
(FM/AM/SSB) or to bits (simple digital), so a capture becomes an intelligible
artifact.

#### Acceptance Criteria

1. WHEN dispatched the verb `"demod"` with a demodulation mode from the supported set
   (`fm`, `am`, `ssb`, `digital`), THE sdr-rx plugin SHALL demodulate the selected
   signal in that mode.
2. WHEN the mode produces audio (`fm`/`am`/`ssb`), THE layer SHALL write the audio
   out-of-band and record a `CaptureRef { kind: CaptureKind::CallAudio, path }`.
3. WHEN the mode is `digital`, THE layer SHALL emit the recovered bit stream (bounded
   by `SAMPLE_CAP`) and SHALL treat those recovered bits as untrusted content (per
   Requirement 9) rather than as a structure to be trusted.
4. WHEN the demod mode is not in the supported set, THE layer SHALL return
   `Err(PluginError::Unsupported)`.
5. WHEN the selected signal yields no demodulable samples, THE layer SHALL return
   `Err(PluginError::Empty)`.

### Requirement 9: Total over untrusted input; degenerate = failure

**User Story:** As a maintainer, I want every parse of adversary-controlled input —
the IQ file header, the samples, the demodulated payload — to be total, and a run
that learned nothing to be reported as a failure, so a crafted capture cannot crash
the tool and a useless run is not mistaken for a clean result.

#### Acceptance Criteria

1. THE IQ file parser SHALL be total over its bytes: any malformed header, truncated
   record, or invalid sample encoding SHALL map to `Err(PluginError::Backend)` and
   SHALL NOT `unwrap`, `expect`, index unchecked, or panic on any input of any
   length.
2. THE demodulated-content path (digital bit recovery, any decoded frame or nav
   message) SHALL treat its output as untrusted and SHALL NOT panic while parsing it.
3. WHEN a source yields zero samples for any operation, THE plugin SHALL return
   `Err(PluginError::Empty)`.
4. THE layer SHALL distinguish "zero samples read" (a degenerate failure,
   `PluginError::Empty`) from "samples analyzed, no signal detected" (a successful
   `Event` reporting zero detections).

### Requirement 10: Hardening and structural offline

**User Story:** As a maintainer, I want the default build hardened, panic-free, and
egress-free, so the layer preserves the pure-Rust static-musl offline guarantee.

#### Acceptance Criteria

1. THE default (no-device, no-subprocess) build SHALL compile under
   `unsafe_code = forbid` and the workspace `unwrap_used`/`expect_used`/
   `indexing_slicing = deny` lints.
2. THE `SdrSource` trait, the DSP pipeline, `IqFileSource`, and the plugin boundary
   SHALL contain no `unsafe`; `unsafe` SHALL exist only in the off-by-default
   FFI-quarantine crate.
3. THE layer SHALL avoid an RNG dependency where a value is derivable, consistent
   with the workspace pure-Rust static-musl target.
4. THE layer SHALL not add a network egress dependency to the default graph; any
   Tier-B subprocess transport SHALL be behind an off-by-default feature.
