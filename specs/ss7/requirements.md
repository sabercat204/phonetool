# Requirements Document — phonetool-ss7

## Introduction

`phonetool-ss7` is the workbench's signalling-analysis capability: an **offline, passive
decoder** for SS7 and Diameter control-plane traffic supplied as a capture. Modern SS7 no
longer rides TDM trunks in the deployments an operator can observe — it rides **SIGTRAN**
(MTP3-User Adaptation / M3UA over SCTP over IP), and Diameter S6a is IP-native. Hence the
`Ip` transducer even though the payload is telecom signalling, not VoIP.

This crate is **`Passive`**: it observes bytes the operator already holds (a `.pcap` file, a
hex PDU dump) and never transmits, so it never touches the auth-gate — the same stance as
numintel. Its defensive payload is to decode the SCCP/TCAP/MAP stack and its Diameter S6a
analogues and to **flag the privacy-sensitive operations that make SS7 infamous**: MAP
`AnyTimeInterrogation` (ATI), `SendRoutingInfoForSM` (SRI-SM), `SendRoutingInfo` (SRI),
`UpdateLocation`, `ProvideSubscriberInfo` (PSI), and the Diameter S6a commands
`Update-Location-Request` (ULR), `Authentication-Information-Request` (AIR), and
`Insert-Subscriber-Data-Request` (IDR). These span two privacy-sensitive classes the flag
distinguishes — **location-disclosure** (a response revealing a subscriber's location or
serving node, the ATI/SRI-SM tracking vectors) and **intercept-enabling** (AIR fetching auth
vectors, UpdateLocation enabling a registration/redirect hijack) — so no such operation is
silently dropped; exact per-opcode membership is grounded against GSMA guidance (Open
Question), not fixed here. Surfacing this activity from a capture **is** the deliverable.

Knowledge and observation are clean under the operator model: decoding a capture the operator
holds is recon, not intrusion. **Originating** live SS7/Diameter signalling — SRI-SM
injection against a carrier's HLR, ATI location queries against a subscriber you do not own —
is a different thing entirely: an **Axis-A active operation** requiring a `Grant` *and* a real
SS7/Diameter link (carrier- and hardware-gated). That injector is **explicitly out of scope**
for this spec and is surfaced as a gated future capability (Requirement 9), not built here.

> This spec is authored ahead of any live signalling link. Everything in Requirements 1–7
> runs **TODAY** against a supplied file with no device. The live-link capture path and the
> active injector sit behind a device/carrier seam (Requirements 8–9) that snaps in when a
> lawful SS7/Diameter link exists.

## Glossary

- **phonetool-ss7**: The crate under specification; the passive SS7/Diameter capture analyzer.
- **SIGTRAN**: IETF adaptation of SS7 over IP — here, **M3UA** (RFC 4666) carrying MTP3-User
  payload over **SCTP** (RFC 4960). The reason the analysis path binds `Transducer::Ip`.
- **SCCP**: Signalling Connection Control Part (ITU-T Q.713). Carries Global Titles (GT) and
  Subsystem Numbers (SSN) — the addressing that a decoder reads to attribute a message.
- **TCAP**: Transaction Capabilities Application Part (ITU-T Q.771–Q.775). BER-encoded;
  message types Begin / Continue / End / Abort; its component portion carries Invoke /
  ReturnResult / ReturnError / Reject components, each Invoke naming an **operation code**.
- **MAP**: Mobile Application Part (3GPP TS 29.002). A TCAP user; the ASN.1 application whose
  operations (ATI, SRI-SM, SRI, UpdateLocation, PSI) are the privacy-sensitive surface.
- **Diameter S6a**: The LTE MME↔HSS interface (3GPP TS 29.272) over Diameter base (RFC 6733).
  AVP-based (Attribute-Value Pairs). Commands ULR / AIR / IDR are the S6a analogues of the
  MAP location/authentication operations.
- **Disclosure class**: The privacy-sensitivity classification attached to a decoded operation:
  `LocationDisclosure` (its response reveals or enables discovery of a subscriber's location or
  serving node — e.g. ATI, SRI-SM, SRI, PSI, ULR, IDR), `InterceptEnabling` (it fetches auth
  material or redirects registration — e.g. AIR, UpdateLocation), `Benign`, or `Unknown`
  (category not yet grounded). Assigning it is the crate's defensive payload; exact per-opcode
  membership is deferred to the grounded build (Open Question).
- **Capture**: The supplied input — a `.pcap`/`.pcapng` file or a hex PDU dump. Adversary-
  authored bytes; never trusted.
- **PDU**: One protocol data unit (one SCCP-carried TCAP message, or one Diameter message).
- **`Plugin`**: The passive core trait (`phonetool-core`). `Ss7Analyzer` implements it;
  `dispatch(&self, cmd: &Command)` never sees a `Grant`.
- **`ActivePlugin`**: The active-path trait, whose `dispatch_active(&self, cmd, grant: &Grant)`
  requires a `Grant`. The **future** injector would implement this, not `Ss7Analyzer`.
- **`Finding`**: The decoded outcome for one PDU — protocol, operation, addressing, a
  `disclosure_class` (the multi-class disclosure classification), and a `decoded` completeness
  flag.
- **Degenerate result**: A capture that yielded **no decodable PDU** — useless, and therefore
  a failure the operator sees (`PluginError::Empty`), never an empty success. A capture that
  decoded cleanly but contained no location-disclosure operation is a *real, reportable*
  result, not a degenerate one.
- **Grounded constant**: A numeric opcode / command code / ASN.1 tag / GSMA category read
  from a cited standard at build time, never invented from memory.

## Requirements

### Requirement 1: Passive-only scope; the analysis path never touches the gate

**User Story:** As the operator, I want capture analysis to be pure observation, so that
decoding traffic I already hold carries zero authorization friction, exactly like numintel.

#### Acceptance Criteria

1. THE ss7 analyzer SHALL implement the passive `Plugin` trait and SHALL NOT implement
   `ActivePlugin` in this spec.
2. THE ss7 analyzer's manifest SHALL declare transducer `Ip` and capability class
   `CapabilityClass::Passive`.
3. THE ss7 analyzer SHALL require no `Gate`, no `Grant`, and no `ConsentRecord` to decode a
   capture; `dispatch` SHALL never receive a gate token.
4. WHEN `dispatch` receives a command whose verb is not a decode verb this crate handles, THE
   ss7 analyzer SHALL return `Err(PluginError::Unsupported)`.

### Requirement 2: Total decode over untrusted PDU bytes

**User Story:** As a maintainer, I want every decode layer to be total over hostile bytes,
because a capture is adversary-authored — a honeypot, a malformed-by-design PDU, or a
truncated frame must produce an error, never a panic, a hang, or an unbounded allocation.

#### Acceptance Criteria

1. THE ss7 analyzer SHALL NOT panic, `unwrap`, `expect`, or index unchecked on any input, for
   any length or content (enforced by the workspace `unwrap_used`/`expect_used`/
   `indexing_slicing = deny` lints on library code).
2. WHEN a BER/TLV length field declares a length exceeding the remaining bytes of the PDU, THE
   decoder SHALL return a decode error for that PDU and SHALL NOT read past the buffer.
3. THE TCAP/MAP BER decoder SHALL enforce a maximum nesting depth and SHALL return a decode
   error rather than recursing unboundedly on nested or indefinite-length constructed
   elements, so a crafted PDU cannot exhaust the stack.
4. WHEN a single PDU fails to decode, THE analyzer SHALL record a `Finding { decoded: false }`
   for it and SHALL continue with the next PDU, never aborting the whole capture.
5. THE decoder SHALL treat every multi-byte length and offset as fallible arithmetic
   (checked/saturating), so an integer overflow in a length field cannot wrap into an
   in-bounds read.

### Requirement 3: Capture ingestion from a supplied source (TODAY, no device)

**User Story:** As the operator, I want to analyze a capture I supply from a file, so that the
full decode/flag capability is exercisable now, ahead of any live signalling link.

#### Acceptance Criteria

1. THE ss7 analyzer SHALL accept a **hex PDU dump** source — one or more whitespace/newline-
   separated hex-encoded PDUs — and decode each as one PDU, with **zero network egress
   dependency**.
2. THE ss7 analyzer SHALL accept a **`.pcap`/`.pcapng` file** source and extract SS7/Diameter
   PDUs by reassembling SCTP DATA chunks / reading Diameter over SCTP or TCP, treating file
   contents as untrusted.
3. WHEN the command arg names a source path that does not exist (or is blank/absent), THE ss7
   analyzer SHALL return `Err(PluginError::InvalidInput)`; WHEN a valid, existing source fails
   mid-read (a genuine I/O failure), THE ss7 analyzer SHALL return `Err(PluginError::Backend)`
   — a missing/blank path is a boundary-validation failure, an I/O failure on a real source is
   a backend failure, and both are distinct from a decode failure of well-read bytes.
4. WHEN the hex PDU dump contains a token that is not valid hex, THE ss7 analyzer SHALL return
   `Err(PluginError::InvalidInput)` before attempting any protocol decode.
5. THE capture-source interface SHALL be a seam (a trait) so the live-link source
   (Requirement 8) substitutes for the file source without changing the decode/flag layers.

### Requirement 4: SS7 stack decode (SCCP → TCAP → MAP)

**User Story:** As the operator, I want each SS7 PDU decoded down to its MAP operation and
addressing, so that a flagged finding names *what* operation touched *which* subscriber-
addressing.

#### Acceptance Criteria

1. WHEN a PDU decodes as SCCP, THE analyzer SHALL extract the Called-Party and Calling-Party
   addresses (Global Title digits and/or SSN) per ITU-T Q.713, and SHALL surface unparseable
   address fields as absent rather than guessed.
2. WHEN the SCCP payload decodes as TCAP, THE analyzer SHALL identify the TCAP message type
   (Begin / Continue / End / Abort) and, for messages carrying a component portion, the
   component type (Invoke / ReturnResult / ReturnError / Reject) per ITU-T Q.771–Q.775.
3. WHEN a TCAP Invoke component carries a MAP operation code, THE analyzer SHALL resolve it to
   a named MAP operation using an operation-code table **grounded in 3GPP TS 29.002** (see
   Requirement 10), and SHALL report an unrecognized code as `operation: unknown(<code>)`
   rather than omitting the finding.
4. THE analyzer SHALL decode a PDU only as far as it can and SHALL emit a partial
   `Finding { decoded: false }` (with whatever layers did decode) when an inner layer fails,
   never discarding the outer decode.

### Requirement 5: Diameter S6a decode (ULR / AIR / IDR)

**User Story:** As the operator, I want the Diameter S6a analogues decoded from the same
capture, so that an LTE/IMS location-tracking or authentication-vector query is flagged the
same way its SS7 predecessor is.

#### Acceptance Criteria

1. WHEN a PDU decodes as a Diameter message (RFC 6733 header), THE analyzer SHALL extract the
   Command Code, the Request/Answer (R) bit, and the Application-Id, and SHALL iterate its
   AVPs without trusting any AVP length field (Requirement 2 applies to AVP lengths).
2. WHEN the Command Code resolves to an S6a command, THE analyzer SHALL name it (ULR / ULA /
   AIR / AIA / IDR / IDA / …) using a command-code table **grounded in 3GPP TS 29.272 and
   RFC 6733** (see Requirement 10).
3. THE analyzer SHALL extract the subscriber-identifying AVP (e.g. User-Name / IMSI) when
   present and SHALL report it as absent rather than fabricated when the AVP is missing or
   unparseable.
4. WHEN a Diameter AVP declares a length that would read past the message, THE analyzer SHALL
   stop iterating AVPs for that message and record `decoded: false`, never reading past the
   buffer.

### Requirement 6: Location-disclosure / intercept-enabling flagging (the defensive payload)

**User Story:** As the operator, I want the privacy-sensitive operations flagged distinctly
from ordinary signalling, so that a capture's subscriber-tracking / intercept-enabling
activity is the headline result, not buried in a decode dump.

#### Acceptance Criteria

1. THE analyzer SHALL classify each decoded operation into a `disclosure_class` —
   `LocationDisclosure` (a location / serving-node reveal, e.g. MAP ATI, SRI-SM, SRI, PSI and
   Diameter S6a ULR, IDR), `InterceptEnabling` (auth-vector fetch or registration/redirect
   hijack, e.g. Diameter AIR and MAP UpdateLocation), or `Benign` otherwise — using a
   classification table **grounded in GSMA FS.11 (SS7) and GSMA FS.19 (Diameter)** category
   guidance (see Requirement 10). The exact per-opcode membership of each class is deferred to
   the grounded build (Open Question), not fixed here.
2. THE analyzer SHALL NOT infer intent from a flagged operation: it SHALL report that a
   flagged operation is *present in the capture*, and SHALL NOT assert that it was
   malicious, unauthorized, or attributable to a named actor.
3. THE event summary SHALL state the count of flagged findings (location-disclosure and
   intercept-enabling) and the operation names observed, so the headline is legible without
   reading `data`.
4. WHERE an operation's GSMA category assignment is not yet grounded against the standard, THE
   analyzer SHALL report the operation with `disclosure_class: Unknown` rather than guessing a
   class.

### Requirement 7: Degenerate-case discipline

**User Story:** As the operator, I want a capture that taught me nothing reported as a failure,
and a capture that decoded cleanly but was benign reported as a real result, so that a useless
run is never mistaken for a clean one.

#### Acceptance Criteria

1. WHEN a capture yields **no decodable PDU** (every PDU failed to decode, or the source held
   no PDUs), THE ss7 analyzer SHALL return `Err(PluginError::Empty)`.
2. WHEN a capture source is empty or whitespace-only, THE ss7 analyzer SHALL return
   `Err(PluginError::InvalidInput)` (nothing to analyze is a bad input, distinct from a
   populated-but-undecodable capture).
3. WHEN at least one PDU decoded — **even if none were location-disclosure operations** — THE
   ss7 analyzer SHALL return `Ok(Event)`; "this capture contained no location-disclosure
   traffic" is a real, reportable result.
4. THE analyzer SHALL include the total PDU count, the decoded count, and the flagged count in
   the event `data`, so a partial-decode run is distinguishable from a clean one.

### Requirement 8: Live-link capture is a device/carrier seam (off-by-default)

**User Story:** As the operator, I want the live signalling-link capture path to snap in
behind the same source seam when a lawful link exists, without the offline analyzer depending
on it, so the offline claim holds.

#### Acceptance Criteria

1. THE offline analysis path (hex + pcap) SHALL add **zero egress dependencies**;
   `cargo tree -e no-dev` on the default graph SHALL show no network-client crate for this
   crate.
2. WHERE a live SIGTRAN/Diameter link source is compiled, it SHALL be behind an
   **off-by-default Cargo feature** (numintel's `online` model), and it SHALL implement the
   same capture-source seam (Requirement 3.5) so the decode/flag layers are unchanged.
3. THE live-link source SHALL be documented as **carrier- and hardware-gated**: it requires a
   provisioned SS7 point code / Diameter peering that the operator does not possess by
   building this crate, so enabling the feature does not by itself create a link.
4. THE documentation SHALL state the offline guarantee as "zero egress *dependencies* on the
   analysis path", NOT "no network code", once the live-link feature exists.

### Requirement 9: Active signalling injection is out of scope and gated (known gap)

**User Story:** As the operator, I want the active injector (originating SRI-SM/ATI/etc.)
named as a distinct, gated future capability rather than smuggled into the analyzer, so the
passive/active line stays a compile-time property.

#### Acceptance Criteria

1. THE ss7 analyzer SHALL provide **no code path** that originates or transmits an
   SS7/Diameter message; it decodes supplied bytes only.
2. THE spec SHALL record that a future active injector is an **Axis-A active operation**
   implementing `ActivePlugin` (its `dispatch_active` taking a `&Grant`), reading its target
   from `grant.target()` and never from the command, per the active-plugin invariant.
3. THE spec SHALL record that the active injector additionally requires a live SS7/Diameter
   **link** (Requirement 8's carrier/HW gate) — so it is gated on **both** a `Grant` (cyber
   authorization) **and** a lawful link, and neither alone suffices.
4. THE spec SHALL surface as an **Open Question** whether SS7/Diameter injection is adequately
   modeled by Axis A alone, or whether it also implicates a regulatory/interconnect authority
   (analogous to Axis B for spectrum), and SHALL NOT silently decide it.

### Requirement 10: Grounded constants, no confabulated protocol behavior

**User Story:** As a maintainer, I want every numeric opcode, command code, ASN.1 tag, and
category assignment traceable to a cited standard, so the analyzer's flags are correct rather
than plausible.

#### Acceptance Criteria

1. THE crate SHALL source every MAP operation code from 3GPP TS 29.002, every Diameter command
   code from 3GPP TS 29.272 / RFC 6733, and every location-disclosure category from GSMA
   FS.11 / FS.19, with the citation recorded at the definition site.
2. WHERE a required constant or category assignment is not yet verified against its standard,
   THE crate SHALL leave it explicitly unresolved (an Open Question / a `TODO` guarded so the
   operation reports `unknown`), and SHALL NOT ship an invented value.
3. THE crate SHALL compile under `unsafe_code = forbid` and the workspace deny-lints, and
   SHALL add no RNG dependency (analysis is deterministic over the capture).
