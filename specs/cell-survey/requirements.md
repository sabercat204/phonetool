# Requirements Document — phonetool-cell-survey

## Introduction

`phonetool-cell-survey` is a **passive** cellular survey capability: it decodes the
broadcast / system-information channels that every base station transmits in the clear —
GSM, LTE, and 5G NR — and builds a map of the cells (and their advertised neighbours)
visible from where the operator is standing. Receiving broadcast cell information is
observation-coded: it is clean under the operator's model (ingestion ≠ theft) and legal on
the receive path near-universally. It therefore declares `CapabilityClass::Passive`, is
handed no gate, and implements the passive `Plugin` trait — never `ActivePlugin`. It holds
`Transducer::RfRx`.

The point of the layer is **defense of self**: a cell map plus a baseline is the raw
material for IMSI-catcher / rogue-BTS detection. A cell-site simulator gives itself away in
its broadcasts — a PLMN that should not be present, a LAC/TAC crafted to force
re-registration, an advertised downgrade to 2G, an implausibly strong signal, a missing
neighbour list. The detector flags those anomalies. It is advisory only: it *reports*, it
never *transmits* — any active response would cross onto the regulatory (Axis B) axis and is
explicitly out of scope.

phonetool builds software ahead of hardware. This layer therefore has two faces. **Today,
with no radio**, it decodes a *recorded* capture file (a `gr-gsm` / IQ / GSMTAP pcap dump)
end-to-end: decode → cell map → anomaly scan, all offline, no SDR present. **When hardware
arrives**, a live scan snaps in behind a `CaptureSource` seam as a **Tier-B** capability — a
`gr-gsm` / Osmocom / srsRAN child driven over the subprocess-IPC control channel, with bulk
IQ moved out-of-band by handle. The decode / map / detect modules do not change; only the
sample source does.

The bytes decoded here are **adversary-controlled**: a rogue BTS transmits whatever it
likes, precisely to mislead. Every decoder is total over untrusted input — it never panics,
never trusts an air-supplied length or count to size an allocation, and records a field it
could not decode as absent rather than fabricating one. A capture that yields zero cells is
a **failure** the operator sees (`PluginError::Empty`), never an empty success mistaken for
"the area is clean".

## Glossary

- **phonetool-cell-survey**: The crate/plugin under specification; the passive cellular
  cell-survey and rogue-BTS detector.
- **`CellSurvey`**: The plugin type. Manifest name `"cell-survey"`, transducer `RfRx`,
  capability class `Passive`. Implements `Plugin`, not `ActivePlugin`.
- **RAT**: Radio Access Technology — GSM (2G), LTE (4G), or 5G NR. The three are decoded by
  **distinct** modules; their broadcast formats have nothing in common.
- **Broadcast / system information**: The unencrypted cell-identity data every base station
  transmits so idle handsets can find and camp on it. The only channels this layer reads.
- **BCCH / SI (GSM)**: Broadcast Control Channel and its System Information messages —
  carry MCC, MNC, LAC, CID, ARFCN, and the neighbour ARFCN list.
- **MIB / SIB (LTE)**: Master / System Information Blocks — carry PCI, EARFCN, TAC, PLMN,
  operating band.
- **SSB / MIB / SIB1 (5G NR)**: Synchronization Signal Block and its broadcast blocks —
  carry PCI, GSCN, PLMN, TAC.
- **PLMN**: Public Land Mobile Network identity = MCC (country) + MNC (operator). The
  primary "is this operator supposed to be here?" key.
- **ARFCN / EARFCN / GSCN**: The per-RAT channel/frequency index (GSM / LTE / NR).
- **LAC / TAC**: Location / Tracking Area Code. A change forces a handset to re-register — a
  classic IMSI-catcher tell.
- **`CellMap`**: The aggregate of decoded cells across RATs, plus a neighbour graph built
  from advertised neighbour relations.
- **`AnomalyFlag` / `AnomalyKind`**: An advisory rogue-BTS indicator and its category
  (e.g. `UnexpectedPlmn`, `ForcedReregistration`, `RatDowngrade`, `MissingNeighbours`,
  `SignalGeometryImplausible`, `DuplicateIdentity`).
- **Baseline**: The operator-supplied "what should be present" — the reference the detector
  compares a live/recorded survey against. Its provenance is an open question.
- **`CaptureSource`**: The seam abstracting where samples come from. `FileCaptureSource`
  (recorded file, hardware-free, runs today) vs `LiveCaptureSource` (Tier-B subprocess,
  device seam).
- **Tier-B / `SubprocessPlugin`**: An out-of-process, any-language capability that proxies
  the same `Plugin` trait over the length-prefixed JSON control channel of
  `specs/subprocess-ipc-contract/`. Not built yet.
- **`CaptureRef { kind, path }`**: The capture-bus record for a bulk artifact. Bulk IQ/pcap
  is referenced by on-disk path (`CaptureKind::Iq` / `::Pcap`), **never** inlined.
- **Degenerate result**: A survey that decoded no cells — useless, and therefore a failure
  the operator sees, not an empty success.
- **Operator**: The human invoking phonetool.

## Requirements

### Requirement 1: Passive, RX-only survey — no gate, active/TX out of scope

**User Story:** As the operator, I want cell-survey to run with zero authorization friction,
so that observing broadcast cell information — a defensive act — is never gated, while the
layer stays strictly on the receive path.

#### Acceptance Criteria

1. THE cell-survey manifest SHALL declare `Transducer::RfRx` and `CapabilityClass::Passive`.
2. THE cell-survey SHALL implement the `Plugin` trait and SHALL NOT implement `ActivePlugin`.
3. THE cell-survey SHALL perform its operation without constructing a `Gate`, without
   requesting a `Grant` or `TxGrant`, and without emitting a consent record.
4. THE cell-survey SHALL NOT transmit, and SHALL NOT perform any active cellular measurement
   of its own; a detected rogue BTS SHALL be reported, never answered on the air (an active
   response is Axis B / regulatory and is out of scope for this layer).
5. WHEN `dispatch` receives a verb other than `"survey"`, THE cell-survey SHALL return
   `Err(PluginError::Unsupported)`.

### Requirement 2: Runs today on a recorded capture; live scan behind the device seam

**User Story:** As the operator with no SDR yet, I want a full survey over a recorded capture
file today, so that the software is finished and proven before hardware arrives and the live
path is just a source swap.

#### Acceptance Criteria

1. WHEN `dispatch` receives verb `"survey"` with an `arg` naming a readable local capture
   file, THE cell-survey SHALL decode it (decode → cell map → anomaly scan) without opening
   any radio device.
2. THE cell-survey SHALL implement the recorded-file decode path (`FileCaptureSource`) as the
   default, hardware-free path that runs with no SDR present.
3. THE cell-survey SHALL place the live-scan path behind a `CaptureSource` seam
   (`LiveCaptureSource`) so it snaps in when an `RfRx` device arrives, without changing the
   `decode_*`, `cellmap`, or `detect` modules.
4. WHERE the live source is used, THE cell-survey SHALL obtain samples only through a Tier-B
   `SubprocessPlugin` (`gr-gsm` / Osmocom / srsRAN over subprocess-IPC), per Requirement 9.
5. WHEN `arg` names no readable file and no live source is configured, THE cell-survey SHALL
   return `Err(PluginError::InvalidInput)` before any decode work.

### Requirement 3: Per-RAT decoders are distinct and total over untrusted broadcast bytes

**User Story:** As a maintainer, I want each RAT decoded by its own module and every decoder
proven never to panic, because a rogue BTS controls the bytes on the air and will craft them
to break a naive parser.

#### Acceptance Criteria

1. THE cell-survey SHALL implement GSM, LTE, and 5G NR broadcast decode as three distinct
   modules (`decode_gsm`, `decode_lte`, `decode_nr`), not one combined decoder.
2. WHEN a decoder encounters a malformed, truncated, or out-of-range field in a broadcast /
   system-information block, THE decoder SHALL skip or flag that block and continue, and SHALL
   NOT panic, `unwrap`, `expect`, or index unchecked on any input.
3. THE decoders SHALL treat all decoded broadcast content as untrusted: a length, count, or
   offset field read from the air SHALL NOT be used to size an allocation or index a buffer
   without a bound check.
4. WHEN a capture segment's RAT cannot be determined or matches no decoder, THE cell-survey
   SHALL record that segment as a decode miss and continue, never abort or panic.

### Requirement 4: Minimum decoded field set per RAT

**User Story:** As the operator, I want each decoded cell to carry the fields that identify
it and expose an anomaly, so that the cell map and the detector have something to work with.

#### Acceptance Criteria

1. WHERE a GSM BCCH/SI block decodes, THE `decode_gsm` SHALL populate a `GsmCell` carrying at
   least MCC, MNC, LAC, CID, ARFCN, and the advertised neighbour ARFCN list.
2. WHERE an LTE MIB/SIB block decodes, THE `decode_lte` SHALL populate an `LteCell` carrying
   at least PCI, EARFCN, TAC, PLMN (MCC+MNC), and operating band.
3. WHERE a 5G NR SSB/MIB/SIB1 block decodes, THE `decode_nr` SHALL populate an `NrCell`
   carrying at least PCI, GSCN, PLMN, and TAC.
4. WHEN a field within an otherwise-decodable block does not decode, THE decoder SHALL record
   that field as absent/unknown and SHALL NOT substitute a default or guessed value.

### Requirement 5: Cell map and neighbour graph

**User Story:** As the operator, I want the decoded cells aggregated into one map with a
neighbour graph, so that a missing or inconsistent neighbour relation becomes visible.

#### Acceptance Criteria

1. THE cell-survey SHALL aggregate decoded cells across all three RATs into one `CellMap`,
   keyed by a per-RAT cell identity.
2. THE cell-survey SHALL build a neighbour graph from advertised neighbour relations (GSM
   neighbour ARFCNs; LTE/NR neighbour relations where the capture provides them).
3. WHEN the same cell identity is decoded more than once with inconsistent parameters, THE
   cell-survey SHALL retain both observations for the detector rather than silently
   overwriting one (a parameter flip is itself a signal).

### Requirement 6: Rogue-BTS / IMSI-catcher anomaly flags (grounded categories, calibrated thresholds)

**User Story:** As the operator, I want the survey to flag the tells of a cell-site simulator,
so that I can detect a device trying to intercept or downgrade my connection — a
defense-of-self capability.

#### Acceptance Criteria

1. THE detector SHALL emit `AnomalyFlag`s drawn from a fixed set of grounded categories
   including at least `UnexpectedPlmn`, `ForcedReregistration`, `RatDowngrade`,
   `MissingNeighbours`, `SignalGeometryImplausible`, and `DuplicateIdentity`.
2. WHEN a decoded cell advertises a PLMN not present in the operator-supplied baseline, THE
   detector SHALL emit `UnexpectedPlmn`.
3. WHEN a cell advertises a LAC/TAC that differs from the baseline for that PLMN in a way that
   forces UE re-registration, THE detector SHALL emit `ForcedReregistration`.
4. WHEN a cell advertises an empty or absent neighbour list where the baseline for that PLMN
   expects neighbours, THE detector SHALL emit `MissingNeighbours`.
5. THE detector's numeric thresholds and scoring weights (signal-geometry bounds, confidence
   cutoffs) SHALL be supplied as configuration inputs, and THE cell-survey SHALL NOT hardcode
   any detection threshold that has not been grounded in cited research — each such value
   remains an Open Question until calibrated (see `## Open questions for operator`).
6. THE detector SHALL operate on the decoded `CellMap`, so it runs today over recorded
   captures with no live radio.
7. THE `AnomalyFlag`s SHALL be advisory: THE cell-survey SHALL report each flag with its
   supporting evidence and SHALL NOT take any active or transmit action in response.

### Requirement 7: Bulk IQ is referenced by path, never inlined

**User Story:** As a maintainer, I want raw samples kept out of the event stream, because MS/s
of IQ would swamp the capture timeline and the JSON control path.

#### Acceptance Criteria

1. WHEN a survey is backed by an IQ or pcap capture, THE cell-survey SHALL record a
   `CaptureRef { kind, path }` on the `CaptureBus` and SHALL NOT inline raw samples into the
   `Event` data.
2. THE cell-survey SHALL set `CaptureKind::Iq` for SDR IQ captures and `CaptureKind::Pcap`
   for packet captures.
3. THE `Event` data SHALL carry only decoded structured results (cells, neighbour graph,
   anomaly flags), whose size is bounded by the cell count, never by the sample count.
4. THE cell-survey SHALL bound its read of a capture file (streamed or capped) and SHALL NOT
   load an unbounded file wholly into memory.

### Requirement 8: A survey that decodes nothing is a failure

**User Story:** As the operator, I want "no cells found" to be a nonzero-exit failure, so that
a technically-correct-but-useless survey never reads as a clean all-clear (degenerate-case
discipline).

#### Acceptance Criteria

1. WHEN a survey decodes zero cells across all RATs, THE cell-survey SHALL return
   `Err(PluginError::Empty)`, not an empty-but-successful `Event`.
2. THE `Empty` error message SHALL name the capture source and state that no cells were
   decoded.
3. WHEN at least one cell decodes, THE cell-survey SHALL return `Ok(Event)` — "these cells are
   present and none is anomalous" is itself a real, reportable result.

### Requirement 9: Device arbitration and the Tier-B prerequisite (no bypass)

**User Story:** As a maintainer, I want the live path to honor hardware arbitration and never
become an arbitration or gate bypass, even though the survey is passive, so that the single
scarce SDR is not grabbed by two capabilities at once and authorization stays on the Rust
side.

#### Acceptance Criteria

1. THE registry SHALL treat `RfRx` as a shareable logical medium (resolved in the spine sprint;
   many passive RX layers co-register); WHERE a live survey is running, arbitration of the one
   physical SDR SHALL be held by the Tier-B subprocess host for the scan's duration, not by the
   logical `RfRx` index.
2. THE cell-survey SHALL obtain live samples only through a Tier-B `SubprocessPlugin`, and the
   `decode_*` / `cellmap` / `detect` modules SHALL NOT open the SDR device directly.
3. THE cell-survey SHALL NOT require, consult, or hold a `Grant` or `TxGrant`: passive RX is
   on neither gate axis.
4. THE design SHALL resolve, before the live path is built, how the Tier-B subprocess host
   arbitrates the one physical SDR when a child process holds the device (the logical `RfRx`
   index is now shareable and does not arbitrate hardware — spine sprint) — an unresolved seam
   recorded as an Open Question and a prerequisite task (see Requirement 2.4;
   the Tier-B `SubprocessPlugin` of `specs/subprocess-ipc-contract/` does not exist yet).

### Requirement 10: Hardened, offline-structural, no unsafe in the default path

**User Story:** As a maintainer, I want the decode path hardened and dependency-lean, so it
preserves the pure-Rust static-musl offline build and cannot fall over on hostile input.

#### Acceptance Criteria

1. THE cell-survey SHALL compile under `unsafe_code = forbid` and the workspace
   `unwrap_used` / `expect_used` / `indexing_slicing = deny` lints.
2. WHERE a future FFI binding to an SDR/DSP C library (e.g. `soapysdr`) is added, THE `unsafe`
   surface SHALL live in a separate crate behind an off-by-default Cargo feature, never in the
   default decode path.
3. THE default build SHALL add zero network-egress dependencies; the default decode path SHALL
   read local capture files only.
