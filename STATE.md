# phonetool — STATE

**Lifecycle:** ACTIVE
**Version:** 0.17.0
**Scope:** personal
**Established:** 2026-07-06

## Current state

**Doc added (2026-07-09): `docs/DEVICES.md` — device interface reference.** Maps
every hardware/signal-source seam across the 15 crates to the real gear that
attaches to it, grounded on both sides: code facts verified against the tree at
`0.17.0` (trait + feature-flag + file/socket contract, file:line cited), device
facts from vendor/standards sources (RTL-SDR Blog V4, HackRF One, USRP B200,
SoapySDR, GSMTAP, ATA/DAHDI, IS-GPS-200, FCC Part 97). Per module: an **(A) what
interfaces today** table and a **(B) live-device seam** table marked built vs.
declared-only. Load-bearing conclusion restated for future sessions: **only three
live paths are built — `sip enum`, `wardial`, and the `online` enrichment fetches
(all network sockets, no hardware).** Every physical seam (`SdrSource`, `TxSink`,
`WirePlugin`, cell-survey `live`) is a named trait + off-by-default feature with
**no implementor** — the doc says so and cites the `Cargo.toml`/source comment for
each. No code changed; documentation only. README gained a `## Devices` pointer.

**Sprint 17 shipped (2026-07-09): copper/lineman physical-I/O (passive half) —
`phonetool-legacy-hw` (0.17.0), AND the third gate axis it needed.** The 15th
crate — the **last un-built spec triple** — plus the `WireGrant` Axis-C plumbing in
the shared gate. The passive half decodes/senses/synthesizes over supplied audio and
traces with no hardware; the active injection half is deliberately **not built** (it
needs the new token AND a hardware-safety interlock that does not exist).

**Axis-C gate plumbing (shared authgate + core):**
- **`WireGrant`** (authgate) — the third unforgeable token, minted only by
  `Gate::request_wire(WireAuthorization { line_id, plant_basis })`, fail-closed on
  empty line-ID / plant basis, logged as `Capability::Wireline`. Distinct from
  `Grant`/`TxGrant`: "a cyber authorization does not authorize seizing a physical
  loop" is now a compiler-checked fact — the third instance of the crate's
  distinct-wrongs-get-distinct-tokens thesis. **Resolves legacy-hw OQ1 (Option 1,
  the recommended direction) and pre-empts the OQ6 N-axis meta-question by landing
  the third axis concretely.**
- **`WirePlugin`** (core) — `dispatch_wire(&self, cmd, grant: &WireGrant)`, the third
  registry dispatch path (`register_wire`/`dispatch_wire`/`wire` map through the same
  `claim`), `CapabilityClass::ActiveWire`. Non-interchangeable with the other two
  token types at the dispatch boundary. **No injector implements it yet** — the trait
  is the legal plug-in point, reserved.

**`phonetool-legacy-hw` (passive, `Wireline`/`Passive`, never gated):**
- **`dsp`** — Goertzel DTMF decode (ITU-T Q.23/Q.24 pairs) + 2600-Hz SF, **confident-
  match-or-nothing** (an ambiguous window yields no symbol, never a guess); DTMF/2600
  synthesis to a PCM/WAV buffer (**inert** — writes samples only, no line path); and
  Bell-202 Caller-ID FSK demod → `CidFrame`, whose fields are reported **observed on
  the wire, never a verified identity** (Caller-ID is trivially spoofed). The
  synth→decode round-trip is the ahead-of-hardware correctness proof.
- **`source`** — the `LineSource` RX/sense-only seam (no drive/inject method exists,
  by construction) + `WavFileSource` (total RIFF/WAVE parse, `SAMPLE_CAP`-bounded,
  never trusts a declared length) + `RecordedSenseSource`. A live front end is a
  declared `device`-feature seam.
- **`sense`** — classifies loop/line voltage → `LineState` (on/off-hook, ring, idle).
  An idle line is a real `Ok` result; an empty trace is a failure. Thresholds are
  flagged nominal/illustrative (exact datasheet values are OQ2).
- **`lib`** — four passive verbs (`decode`/`cid`/`sense`/`synth`); implements only
  `Plugin`, names no token; compile-fail doctest proves NOT `ActivePlugin`. Degenerate
  discipline: unreadable/empty → `Empty`/`InvalidInput`; clean-but-toneless → `Ok`.
- **CLI wired:** `phonetool line <decode|cid|sense|synth>`; synth records its WAV as
  `CaptureRef { CallAudio }`.

**What is NOT built (declared seams / Open Questions, not fabricated):**
- **Active physical injection (Req 7, the known gap)** — loop seizure, tone/ring
  injection onto a live pair. The `WireGrant`/`WirePlugin` legal point now exists, but
  the injector needs BOTH the token AND the orthogonal hardware-safety interlock (line
  voltage is a physical hazard), plus the FFI-quarantine crate — none built. This crate
  has **no code path** that drives a pair.
- **FFI-quarantine crate + live sources (Req 9, OQ7)** — `phonetool-linehw-ffi`
  (`gpio-cdev`/`linux-embedded-hal`, the only `unsafe`); the live line-sense source
  and the interlock live here, behind the off-by-default `device` feature. Unbuilt.
- **Interlock thresholds (OQ2)** — datasheet constants (idle/ring voltages, trip
  points) deferred to the chosen SLIC front end; the sense bands are illustrative.
- **MF R1 full tone set + switch-generation behavior (OQ3/OQ5)** — DTMF + 2600 ship
  grounded; the six-frequency MF R1 table and per-class switch signalling
  (step-by-step/crossbar/ESS/DSS/COCOT) are deferred, never confabulated.

**434 tests pass** (was 390: +38 legacy-hw — 29 unit incl. synth↔decode round-trip +
Goertzel peak + CID round-trip/checksum + WAV hostile-input + sense classify, 8
integration incl. round-trip-via-files + degenerate + no-inject-verb, 1 compile-fail
doctest; +6 gate: 3 authgate `request_wire` fail-closed/logging + 3 registry
`register_wire`/`dispatch_wire`/exclusive-port); clippy `--all-targets` clean (crate
adds zero warnings); fmt clean; `unsafe_code=forbid` holds; zero egress deps.

**All spec triples are now built.** baittriage, ss7, rf-tx, legacy-hw — the four
design-only layers from Sprint 3 have all shipped. The workbench spans all three gate
axes with consumers on A (sip/wardial) and B (rf-tx); C has its token + trait, awaiting
a hardware-gated consumer.

---

**Sprint 16 shipped (2026-07-09): RF transmit path — `phonetool-rf-tx` (0.16.0),
the workbench's FIRST Axis-B consumer.** The 14th crate, and the mirror of sdr-rx:
sdr-rx receives and is `Passive` (never gated); rf-tx transmits and is **always**
gated — every transmission routes through `Gate::request_tx`, holds a `TxGrant`, and
never auto-repeats. It modulates an operator payload (CW, AFSK/AX.25) into a waveform
and renders it to a **file**. The sharpest legal surface in the project, handled by
two structural properties, not vigilance.

- **New crate: `phonetool-rf-tx`** — implements the `TxPlugin` trait (manifest
  `RfTx`/`RfTx`), reachable only through `dispatch_tx(&self, cmd, grant: &TxGrant)`.
  Registered via `register_tx` (the third dispatch path, which already existed in
  core since Sprint 4 — the spec's stated prerequisite was already met). One
  compile-fail doctest proves a fabricated `TxGrant` cannot reach transmit.
- **Two structural safety properties:** (1) *the type prevents the wrong axis* —
  `Grant` (Axis A) and `TxGrant` (Axis B) are non-interchangeable, so a cyber
  authorization physically cannot key a radio; (2) *the default build cannot emit* —
  NO device `TxSink` is compiled in, so `FileSink` is the only sink and selecting a
  device sink is a **compile** error. Emission requires BOTH the off-by-default
  `device` feature AND a gate-minted token (a double lock). The `device` FFI crate is
  a declared seam, unbuilt.
- **`modulate` (pure, sink-free, grant-free)** — the ahead-of-hardware core.
  **CW** (OOK, ITU-R M.1677-1 1:3:7 dit/dah/gap timing, PARIS WPM) and **AFSK**
  (Bell-202 1200-baud continuous-phase mark 1200 Hz / space 2200 Hz) ship fully
  grounded and reference-verifiable offline. Bounded by `SAMPLE_CAP`; a zero-sample
  render is refused. FM/SSB are declared seams (need an input-audio reader + grounded
  filter params) returning `Unsupported`.
- **`payload`** — total, panic-free boundary validation: CW Morse table
  (M.1677-1); AX.25 v2.2 UI-frame construction (callsign shift-encoding + SSID octet,
  control 0x03, PID 0xF0, **CRC-16/X.25 FCS** — known-vector 0x906E verified, HDLC
  bit-stuffing + flag framing). Unencodable char / bad callsign → `InvalidInput`.
- **`bandplan`** — the fail-closed regulatory check run BEFORE any sink work:
  frequency-in-band + power ceiling = min(grant, regulatory max). Grounded to **US
  FCC Part 97** (40m/20m/2m/70cm §97.301 edges; §97.313 1500 W = 61.76 dBm umbrella).
  An unlisted band **fails closed** — never assumes a range. A 70cm grant cannot key
  a 2m frequency.
- **Authority from the grant, parameters from the command:** band/power/license read
  from `TxGrant`; the command `arg` is a fail-closed JSON envelope
  `{"freq_hz":<u64>,"payload":"..."}` (design Open Question 8 resolved without a core
  `Command` change — payload is CW text or `"SRC>DEST:info"` for AFSK).
- **Degenerate discipline:** a zero-sample render → `PluginError::Empty`, and no sink
  is ever keyed with a dead carrier. A single dit / one-line beacon is a real result.
- **CLI wired:** `phonetool rf-tx <cw|afsk> --freq-hz --payload --band --power-dbm
  --license [--out]`; routes through `Gate::request_tx`, renders to a file, records
  the waveform as `CaptureRef { Iq }` on the timeline. `Event` carries only bounded
  metadata + `emission:false`, never the sample buffer.

**What is NOT built (declared seams / Open Questions, not fabricated):**
- **Device sinks + FFI-quarantine crate (Req 10, OQ4/OQ5)** — `HackRfTxSink`/
  `LimeTxSink`/`PlutoTxSink` behind the off-by-default `device` feature; the only
  place `unsafe` would be permitted. Unbuilt: no radio, no emission path exists.
- **FM / SSB (OQ3/OQ6)** — need an input-audio (WAV) reader + grounded filter/
  deviation params; declared seams returning `Unsupported`.
- **Band plan is US FCC Part 97 only (OQ2)** — ISED, CB/GMRS/MURS are later table
  additions behind the same mechanism; unlisted bands fail closed today.
- **Live TX tier (OQ4)** — Tier-B GNU Radio TX flowgraph vs native soapysdr FFI;
  either way the gate + bandplan check stay Rust-side, before the child.

**390 tests pass** (was 342: +48 rf-tx — 41 unit incl. CW timing/WPM scaling + AFSK
framing + CRC-16/X.25 known-vector + bit-stuffing + bandplan per-case + payload
hostile-input, 6 gate-only integration incl. real `Gate::request_tx` mint + grant/
refusal logged + wrong-band/empty-payload refused-before-sink, 1 compile-fail
doctest); clippy `--all-targets` clean (crate adds zero warnings); fmt clean;
`unsafe_code = forbid` holds (no device FFI in the default graph); zero egress deps.

---

**Sprint 15 shipped (2026-07-09): passive SS7/Diameter signalling analyzer —
`phonetool-ss7` (0.15.0).** The 13th crate. An offline decoder for SIGTRAN
(M3UA/SCTP) SCCP/TCAP/MAP and Diameter S6a supplied as a capture, that flags the
privacy-sensitive operations SS7 is infamous for: **location-disclosure** (MAP ATI,
SRI-SM, SRI, PSI; Diameter ULR, IDR) and **intercept-enabling** (MAP
sendAuthenticationInfo/updateLocation; Diameter AIR). `Passive`, ungated —
observation of a capture the operator holds is recon, not intrusion. Runs today
against a file with no signalling link.

- **New crate: `phonetool-ss7`** — `Passive`, `Ip` transducer (modern SS7 is
  IP-carried SIGTRAN), never gated (implements `Plugin` only; compile-fail doctest
  proves NOT `ActivePlugin`). One verb: `analyze`. Registered passive alongside
  numintel/attest/cell-survey/baittriage.
- **`ber`** — a bounded, depth-capped BER/TLV reader (the foundation TCAP rides on).
  Every declared length checked against the remaining buffer; indefinite-length form
  refused (a fuzzer lever); nesting depth-capped (`MAX_DEPTH`); multi-byte tags +
  oversized long-form lengths refused. Total over arbitrary bytes (grounded X.690).
- **`ss7`** — SCCP UDT/XUDT best-effort address extraction (GT digits via TBCD when
  GTI=4, else absent — never guessed; SSN; Q.713) → TCAP message/component decode
  (Q.773 tags) → MAP operation resolution via the grounded `MAP_OPS` table (TS 29.002
  local values, cross-checked vs Wireshark `packet-gsm_map`). Unknown opcode →
  `unknown(<code>)`, never omitted. A malformed inner layer keeps the outer decode.
- **`diameter`** — RFC 6733 header (command code, R-bit, application-id) + bounded
  AVP iteration (an AVP length overrunning the message → `avps_truncated`, no
  overread) + S6a command resolution via the grounded `DIAMETER_S6A_CMDS` table
  (TS 29.272 / RFC 6733). User-Name/IMSI extracted when present, absent not faked.
- **`classify`** — `DisclosureClass` (`LocationDisclosure`/`InterceptEnabling`/
  `Benign`/`Unknown`) from published SS7/Diameter security-research categories
  (GSMA FS.11/FS.19). **Flags presence, not intent** (Req 6.2): reports that a
  flagged op is *in the capture*, never that it was malicious/unauthorized/
  attributable. An un-grounded op → `Unknown`, never guessed.
- **`source`** — the `CaptureSource` seam. `HexDumpSource` (one PDU per line, `#`
  comments) + `PcapSource` (bounded read mirroring cell-survey; LINKTYPE_SCTP pcap →
  SCTP DATA-chunk reassembly → M3UA/Diameter PDUs). Both total over hostile bytes.
- **Degenerate discipline:** zero decodable PDUs → `PluginError::Empty`; a
  clean-but-benign capture (decoded, zero flagged) → `Ok(Event)` ("no
  location-disclosure traffic" is a real result); empty source → `InvalidInput`.
  Per-PDU resilience: one undecodable PDU → `Finding { decoded: false }`, run continues.
- **CLI wired:** `phonetool ss7 <source>` (path to `.pcap`/hex dump, or `hex:<...>`);
  a `.pcap` is recorded by-path on the timeline (bulk artifact, never inlined).

**What is NOT built (declared seams / Open Questions, not fabricated):**
- **Live signalling link (Req 8)** — `LiveLinkSource` behind the off-by-default
  `live` feature; carrier/hardware-gated (needs a provisioned point code / Diameter
  peering) and unbuilt. Offline guarantee is "zero egress *deps* on the analysis
  path" — verified `cargo tree -e no-dev` (std + serde only, no network crate).
- **Active injection (Req 9, the known gap)** — originating SRI-SM/ATI/ULR is out of
  scope: an `ActivePlugin` gated on BOTH a `Grant` AND a lawful link. Whether SS7/
  Diameter interconnect is a third regulatory gate axis is an operator Open Question
  (design OQ1), not silently decided.
- **Grounded tables are deliberately partial (OQ2/OQ3)** — `MAP_OPS`/
  `DIAMETER_S6A_CMDS`/disclosure categories seed the widely-published ops; unlisted
  codes/categories resolve to `unknown`/`Unknown`, never invented. Extend as values
  are verified against the (paywalled 3GPP) standards.
- **Depth/size bounds (OQ6)** — `MAX_DEPTH=32`, 64 MiB byte cap, `MAX_PDUS` are
  safety constants, not protocol values.

**342 tests pass** (was 278: +64 ss7 — 55 unit incl. BER hostile-input table +
SCCP/TCAP/MAP decode + Diameter AVP/S6a + classifier-per-category, 8 integration
incl. fixture corpus per flagged op + benign control + degenerate `Empty` + pcap
tempfile round-trip + pathological-BER termination, 1 compile-fail doctest); clippy
`--all-targets` clean (crate adds zero warnings); fmt clean; zero egress deps on the
default graph.

---

**Sprint 14 shipped (2026-07-09): passive fraud-caller footprint triage —
`phonetool-baittriage` (0.14.0).** The 12th crate, and the first new *defensive*
roadmap layer since attest/cell-survey. Given a bundle of operator-supplied
artifacts about a scam/vishing caller — a number, a claimed identity, callback
URLs, wallets, gift-card rails, a transcript — it extracts + normalizes indicators
(`Ioc`s), correlates them against the offline store, classifies a scam pattern, and
reports a confidence-scored footprint. **Defense of others, observation-coded** —
`Passive`, no gate, zero authorization friction ("do not narc-jump"). Runs 100%
today with no device and no network.

- **New crate: `phonetool-baittriage`** — `Passive`, `Ip` transducer, never gated
  (implements `Plugin` only; compile-fail doctest proves it is NOT `ActivePlugin`).
  One verb: `triage`. Registered passive alongside numintel/attest/cell-survey;
  holds `Arc<dyn IntelStore>`, the same store numintel serves from.
- **`ingest`** — total, bounded parse of the untrusted `RawBait` bundle
  (`MAX_BAIT_BYTES`/`MAX_FIELD_BYTES`/`MAX_IOCS`, documented tunable engineering
  caps — not scam-facts). `serde(deny_unknown_fields)`: a typo'd/injected field is
  rejected, not ignored. Empty/malformed/oversize → typed `IngestError`, never a
  panic. **Nothing in an artifact is ever fetched** (an integration test binds a
  real socket and asserts a bundle-supplied URL is never contacted — SSRF/beacon).
- **`extract`** — `Ioc { kind, value }`; phone → shared `Number::parse` (E.164, the
  numintel validator, reused not duplicated); URL/email host + wallet case-folded;
  wallet stays **opaque** (no per-chain checksum — OQ5). Per-artifact resilient (a
  bad artifact is skipped, never fatal); transcript free-text lifts obvious
  URL/email tokens but does **not** guess phone numbers out of prose (no fabricated
  IOCs). Dedup + `MAX_IOCS` bound.
- **`correlate`** — exact-match `get` against `KNOWN_BAD_NS`/`REUSE_NS`;
  `classify` against operator-seeded `SIGNATURE_NS`. **Confidence is counted, never
  asserted** (cell-survey's threshold discipline): the `Low`→`Medium`→`High` cutoffs
  are **injected** via `ConfidenceCutoffs` (no `Default`) — absent them the grade
  stays at the honest `Low` floor and the raw `corroboration_count` is surfaced
  (OQ1). Zero corroboration is always `Low`. Reuse write-back is idempotent (`put`
  keyed by `bait_hash`); a self-hash reuse hit is not counted as a prior case.
- **Two-tier degenerate discipline:** 0 extractable IOCs → `PluginError::Empty`
  (the operator sees a loud failure); ≥1 IOC with no correlation → `Ok(Event)` at
  `Confidence::Low` with an explicit "no prior correlation" marker (a thin-but-real
  result, never padded into false certainty). Store backend failure →
  `PluginError::Backend`; a reuse-write failure is non-fatal (`reuse_index_ok=false`).
- **CLI wired:** `phonetool triage '<json bundle>'` (no `--basis`: passive, ungated).
  Cited `source_capture` path is carried as footprint provenance **by path only** —
  the recording is never opened (audio→text is a future device seam).

**What is NOT built (declared seams / Open Questions, not fabricated):**
- **`online` enrichment (Req 7)** — a DECLARED feature seam only (numintel's model).
  The default build links no `reqwest` (verified `cargo tree -e no-dev`); the
  provider Open Question (OQ4, shared with numintel) is unresolved, so the path is
  reserved, not built.
- **`ScamPattern` signatures ship empty (OQ2)** — `classify` reads `SIGNATURE_NS`;
  with no operator-seeded signatures it returns `Unknown` honestly. No hardcoded
  keyword lists. The taxonomy + seed provenance are the operator's to fix.
- **Confidence cutoffs (OQ1)** — the graduation machinery ships; the numeric cutoffs
  are injected policy, deferred, not invented.
- **Fuzzy correlation + atomic reuse (the known gap)** — `IntelStore` is exact-match
  `get`/`put` with no similarity index and no atomic read-modify-write. Direction B
  (out-of-process Tier-B analyzer + a minimal atomic `put`-if-absent) is the
  recorded recommendation; deferred, flagged as a first-class gap, not faked.

**278 tests pass** (was 225: +53 baittriage — 35 unit incl. ingest hostile-input +
extract normalization/dedup/bounds + correlate confidence-floor/idempotency tables,
8 assess integration incl. seeded known-bad/prior-case + degenerate `Empty` +
backend-failure + reuse idempotency, 5 extract + 4 ingest incl. "artifact URL never
contacted", 1 compile-fail doctest); clippy `--all-targets` clean (crate adds zero
warnings; pre-existing warnings in core/gnss/attest/subprocess predate this sprint);
fmt clean; zero egress deps on the default graph (`std` + rusqlite only).

---

**Sprint 13 shipped (2026-07-08): SIP-origination wardial —
`phonetool-wardial` (0.13.0).** The workbench's **second `ActivePlugin`** (after
phonetool-sip), and its most consequential active op: DID-range enumeration by
placing one outbound SIP `INVITE` per number and classifying what answered. Unlike
sip's OPTIONS probe (rings no one, costs nothing), origination is **billable**
(metered on a trunk), **attributable** (trunk account + caller-ID identify the
operator), and **can complete a call to a real person**. That drove two additions
beyond sip: a cost/attribution acknowledgement layered on the gate, and
conservative bounds because each unit is a metered call.

- **New crate: `phonetool-wardial`** — `ActiveIp`, `Ip` transducer, gate-bound.
  Implements `ActivePlugin`; `dispatch_active` requires a `Grant` (no public
  constructor). Compile-fail doctest proves fabricating a `Grant` to reach it does
  not compile — the dual-use line is a compile-time property, not reviewer
  vigilance. One verb: `sweep`.
- **The DID range lives in `Grant::target`, never the command** (Req 2). The cmd
  `arg` is unused for targeting. `parse_range` accepts a bare DID (`+15125550100`)
  or a zero-padded span (`+1512555:0100-0109`), validated + bounded BEFORE any
  socket: malformed/inverted/over-`max_range`/illegal-DID-char → `InvalidInput`.
- **`message`** — `InviteRequest::to_wire` (with an SDP PCMU offer + accurate
  Content-Length), `TeardownRequest` (ACK/BYE/CANCEL so no dialog dangles), total
  `Response::parse` over untrusted bytes (sip's parser handling, duplicated — shared
  crate is OQ7).
- **`classify`** — `SipDisposition` from response codes (unknown code → `Unknown`,
  never guessed; the Q.850-cause table is NOT hard-coded as universal — OQ5);
  `MediaDisposition` with `NotAnalyzed`/`Inconclusive`/undifferentiated `Voice`.
- **`tone`** — dependency-free Goertzel single-bin detector (pure DSP, textbook
  recurrence). Degenerate configs (NaN / non-positive / ≥Nyquist) refused; total
  over input. **The SIT/CNG/CED target frequencies it would be configured with are
  NOT invented (OQ4)** — the algorithm ships, the standards numbers don't.
- **`originate`** — bounded/paced/deadline-bounded sweep; per-call timeout or
  transport error → `CallResult { reached:false }`, never aborts the sweep; recv
  cap; ACK/BYE/CANCEL teardown. `SweepConfig` (test-friendly `Default`).
  `TrunkConfig` is the device seam — **secret redacted in `Debug`, not
  `Serialize`** (Req 8.4); without a trunk, `sweep` REFUSES any non-loopback target
  (the inert-by-default guarantee, enforced in code, not just documented).
- **Cost/attribution gate (Req 8):** the CLI surfaces the billable/attributable/
  can-ring-a-human notice and requires `--i-accept-billing-and-attribution`
  BEFORE `Gate::request_ip` is called; absent it, no grant is requested and no
  call placed. Three fail-closed guards proven: no-ack → refusal; empty basis →
  gate refusal (logged to bus); no trunk + non-loopback → inert `Backend` refusal.
- **Degenerate discipline:** 0 DIDs reached → `PluginError::Empty` (the sweep
  learned nothing — a failure the operator sees, not "the block is empty").
- **CLI wired:** `wardial <range> --basis <why> --i-accept-billing-and-attribution
  [--trunk-host --caller-id]`; registered active alongside sip.

**What is NOT built (declared seams / Open Questions, not fabricated):**
- **Media / RTP path (OQ6, Req 10)** — no RTP receive or codec decode exists
  anywhere in the workbench, so `MediaDisposition` is always `NotAnalyzed`. The
  whole SIT/fax/modem/voice tier has no substrate yet; wardial ships at
  **`SipDisposition`-only fidelity** (live/disconnected/busy across a block), which
  is fully useful on its own.
- **Grounded tone constants (OQ4)** — Goertzel ships; the frequencies/thresholds
  await citation from ITU-T/Telcordia.
- **Grounded trunk-policy bounds (OQ1/OQ2)** — `max_range=32`, 1 call/sec ship as a
  conservative SAFETY FLOOR, loudly flagged as ungrounded, never authoritative.
- **Real PSTN origination** — requires a `TrunkConfig` with a real secret
  (provisioned out of band, never via CLI/basis/arg). All tests are loopback-only.

**225 tests pass** (was 190: +35 wardial — 28 unit incl. range-parse bounds +
SIP-parser hostile table + classifier coverage + Goertzel + trunk-secret redaction,
6 integration incl. loopback sweep via a real minted grant + degenerate `Empty` +
gate refusal recorded on the bus + inert-no-trunk refusal, 1 compile-fail doctest);
clippy `--all-targets` clean (crate adds no warnings); fmt clean; zero egress deps.
`std::net` only — the default binary carries an INERT origination path (present,
unreachable without BOTH a `Grant` and a `TrunkConfig`); NOT "no active code".

---

**Sprint 12 shipped (2026-07-08): passive cellular survey + rogue-BTS detection —
`phonetool-cell-survey` (0.12.0).** Roadmap layer #? — the 9th crate, and the
second `RfRx`/`Passive` layer after sdr-rx/gnss. Decodes the broadcast /
system-information channels a base station transmits in the clear, builds a cell
map + neighbour graph, and flags the tells of a cell-site simulator (IMSI
catcher). Defense of self: observation-coded, never gated; advisory only —
it *reports* anomalies, never answers on the air (an active response would be an
Axis-B transmit needing a `&TxGrant`, which no trait grants).

- **New crate: `phonetool-cell-survey`** — `Passive`, `RfRx` transducer, never
  gated (no `dispatch_active`; compile-fail doctest proves NOT `ActivePlugin`).
  One verb: `survey`. Registered passive alongside sdr/gnss (shareable `RfRx`).
- **`source` module** — `CaptureSource` seam + `FileCaptureSource` reading
  GSMTAP-over-pcap (`LINKTYPE_GSMTAP_UM = 217`) with a **bounded** read
  (`Read::take` to a 64 MiB `DEFAULT_BYTE_CAP` — never slurps unbounded). Total
  pcap+GSMTAP walk: bad magic / wrong link-type / truncated record / non-Um frame
  → skip or typed error, never panic. `LiveCaptureSource` is a declared unwired
  device seam (Tier-B subprocess, off-by-default `live` feature — unbuilt).
- **`decode_gsm` — REAL, grounded.** Total SI Type 3 decode → LAI (MCC/MNC/LAC,
  BCD per TS 24.008) + Cell Identity; SI Type 2 → neighbour ARFCNs (bit-map-0
  format only). Every constant/offset cited: libosmocore `gsmtap.h` +
  `gsm_04_08.h` (`PDISC_RR=0x06`, `MT_SYSINFO_3=0x1b`), Wireshark
  `packet-gsm_a_rr.c` (bit-map-0 loop transcribed verbatim), tcpdump link-types.
  Non-bit-map-0 neighbour formats (range/variable) → flagged `neighbours_undecoded`,
  **never fabricated into ARFCNs**. Absent field stays absent (no guessed default).
- **`decode_lte` / `decode_nr` — DECLARED SEAMS ONLY.** `LteCell`/`NrCell` types
  and `decode()` boundaries exist; both return `None`. Their identity lives in
  ASN.1-**UPER** SIB1 + PHY-layer sync — hand-rolling UPER from memory is the
  confabulation the project forbids, and Open Question 3 has fixed no recorded
  LTE/NR source to prove a decoder against (OQ8 also leaves NR SA/NSA + FR scope
  open). Named as unbuilt, not faked; `cellmap`/`detect` consume them unchanged
  when grounded.
- **`cellmap`** — aggregates observations by per-RAT `CellId`; **retains
  conflicting observations** of one identity (a parameter flip is itself a
  signal; identical sightings deduped). GSM neighbour lists → graph edges; an
  *undecoded-format* list is NOT recorded as a "no neighbours" edge.
- **`detect`** — advisory `AnomalyKind` set (`UnexpectedPlmn`,
  `ForcedReregistration`, `RatDowngrade`, `MissingNeighbours`,
  `SignalGeometryImplausible`, `DuplicateIdentity`). **Thresholds injected, not
  hardcoded (OQ1):** `Thresholds` has NO `Default` cutoff — a check whose cited
  value is absent is *skipped* (`SignalGeometryImplausible`, `RatDowngrade`),
  never run on a guessed dBm; confidence is `None` without an injected weight.
  The four purely-categorical detectors need no number and run today.
- **Degenerate discipline:** a survey that decodes zero cells → `PluginError::Empty`
  naming the source (CLI exits 1), never an empty success misread as "area clean".
- **CLI wired:** `phonetool cell-survey <pcap>`; on success the pcap is recorded
  as `CaptureRef { Pcap }` on the bus while the `Event` carries only decoded cells
  (test asserts raw `payload` never enters `Event` data). NOTE: the workspace now
  has two bins — invoke `cargo run --bin phonetool`.

**190 tests pass** (was 139: +51 cell-survey — 44 unit incl. GSM/pcap hostile-
input tables + detector-per-category + threshold-injection discipline, 6
integration incl. end-to-end recorded pcap + degenerate `Empty`, 1 compile-fail
doctest); clippy `--all-targets` clean (crate adds no new warnings; 2 pre-existing
in core + 5 in gnss predate this sprint); fmt clean; zero egress deps on the
default graph.

**Honest scope line:** GSM is decoded end-to-end from a recorded capture with no
radio. LTE/NR decode, the live scan, and the cited detection thresholds are named
seams/Open Questions — built where groundable, deferred (not fabricated) where not.

---

**Sprint 11 shipped (2026-07-08): STIR/SHAKEN attestation inspection —
`phonetool-attest` (0.11.0).** First new roadmap *layer* since the RF/GNSS
thread (roadmap #8). A passive, defensive-core capability: reads what an inbound
call claims about its own origin (the PASSporT in the SIP `Identity` header) and
reports the attestation level + a verification verdict. Anti-spoof/anti-vishing
intelligence, observation-only — the numintel model, never the gate.

- **New crate: `phonetool-attest`** — `Passive`, `Ip` transducer, never gated
  (no `dispatch_active`; a compile-fail doctest proves it is NOT `ActivePlugin`).
  One verb: `inspect`.
- **`passport` module** — total parse of an untrusted `Identity` header/PASSporT:
  three-segment JWS split, a hand-rolled total unpadded-base64url decoder
  (RFC 4648 §5), JSON parse of JOSE + claims, attestation classify (A/B/C →
  Full/Partial/Gateway; anything else → `Unknown { raw }`, never coerced; absent
  → `None`). `MAX_IDENTITY`/`MAX_SEGMENT` caps reject a remote-supplied size
  before allocating. `alg`≠ES256 → `UnexpectedAlg` finding (no verify attempted —
  defends alg-confusion incl. `none`/RS256); `ppt`≠"shaken" → `UnexpectedPpt`.
  Every malformed input → typed `ParseError`, no panic (grounded RFC 8224/8225,
  ATIS-1000074).
- **`sipmsg` module** — minimal total `Identity`-header extractor: ASCII-case-
  insensitive match, CRLF/bare-LF, RFC 3261 line-folding; locates zero/one/many
  headers without parsing the full SIP grammar.
- **Degenerate discipline (inverted for a passive reader — absence IS signal):**
  SIP message with no `Identity` → `Ok(Event, NoIdentityHeader)` (unsigned call
  is a real result); PASSporT with no `attest` → `Ok(Event, None, NoAttestClaim)`;
  empty input → `PluginError::Empty`; non-SIP non-token garbage → `InvalidInput`.
- **Input sourcing** — inline arg and `@file` run TODAY, no hardware; a `LiveTap`
  `Source` variant is a declared-but-unwired device seam (parser is ready).
- **Offline/online split (numintel model):** default build performs STRUCTURAL
  inspection only, verdict always `StructuralOnly`, **zero egress deps**
  (verified `cargo tree -e no-dev`). `online` is a declared feature seam that
  wires `reqwest` but does **not** yet build `verify` — the `x5u` fetch + ES256
  path is BLOCKED on three operator Open Questions (trust-anchor provisioning,
  x5u host allowlist, pure-Rust crypto crate) the spec flags as prerequisites.
  Shipping a half-decided trust model would be worse than none; `StructuralOnly`
  is an honest status, never a disguised pass.
- **CLI wired:** `phonetool attest <header|@file>`; registered passive alongside
  numintel/sdr/gnss (shares the shareable `Ip` transducer with active `sip`).

**139 tests pass** (was 104: +35 attest — 24 unit incl. hostile-input table +
alg-confusion + base64url edge cases, 10 integration incl. degenerate discipline
+ inline/@file equivalence, 1 compile-fail doctest); clippy `--all-targets` clean
(default AND `--features online`); fmt clean; zero egress deps on the default graph.

---

**Sprint 10 shipped (2026-07-08): GNSS bit-sync + nav-bit demod —
`navsync` closes the IQ→ephemeris chain (`phonetool-gnss` 0.10.0).** The last
honesty gap in the GNSS decode path: the stage that turns tracking-loop prompts
into synchronized 50 bps nav bits, frames them on the TLM preamble, and feeds
parity-gated subframes to the (Sprint 9) decoder. Every stage of
IQ → prompts → bits → subframes → ephemeris → ECEF is now built and tested.

- **New module: `navsync`** — `correlate_prompts` (per-1 ms-period prompt
  correlation with carrier + code wipeoff at the acquisition estimates),
  `estimate_bit_phase` (max-coherent-energy bit-edge search over 20 periods),
  `demod_navbits` (BPSK sign per 20-period window), `find_preambles`
  (TLM preamble in both polarities, **two-preamble/300-bit confirmation** to
  reject chance 8-bit matches; resolves the PLL 180° ambiguity), `subframe_bits`
  (polarity-corrected 300-bit extraction).
- **Grounded, no invented timing** — 20 periods/bit (§20.3.3.2), TLM preamble
  0b10001011 (§20.3.3.1); reuses the existing cited constants.
- **Wired into `do_fix`** — `decode_nav` runs the full chain per acquired SV,
  merges parity-OK subframes into a per-SV ephemeris, picks the most complete,
  and exposes `nav.{svs_bit_synced, preambles_found, subframes_parity_ok,
  ephemeris_fields, ephemeris_complete}` in the Event.
- **Honest by construction** — on the file-proof path a short (1 ms) fixture
  yields too few prompts to bit-sync, so every counter stays zero and the
  ephemeris is `None`: no fabricated bit, edge, preamble, or field. A capture
  spanning multiple subframes is what produces a decoded ephemeris. The IQ→bits
  seam is proven at small scale (matched-PRN energy dominates a mismatched PRN
  by >10×; recovered prompt signs match the modulated nav bits).
- **The one remaining gap (named):** a *full-scale* end-to-end IQ→coordinate run
  needs a ≥6 s multi-subframe capture (~12M samples at 2 MHz) — too slow for a
  unit test and gated on real/large synthetic data, and a full position fix
  additionally needs pseudorange extraction from the tracking loops (still the
  observable-only `solve` → honest `None`). The stages are individually proven;
  the megasample integration run and pseudorange wiring are the residual depth.

**104 tests pass** (was 93: +11 navsync — prompt correlation from IQ, bit-phase
recovery, demod, frame sync both polarities, PRN orthogonality, total-input
guards); clippy `--all-targets` clean; fmt clean; zero egress deps.

---

**Sprint 9 shipped (2026-07-08): GNSS ephemeris bridge — real Table 20-III
decode → PVT propagator (`phonetool-gnss` 0.9.0).** Closes the decode half of
the loop Sprint 8 opened: the nav-message decoder now extracts the full
Keplerian parameter set and hands it to the position propagator, so decoded
ephemeris → real ECEF satellite position is a proven, tested path.

- **Complete IS-GPS-200 Table 20-III extraction (`navmsg`).** The old partial
  decoder (a handful of MSB fragments, `sqrt_a` truncated to 8 bits) is
  replaced by full-precision extraction of all ~20 clock+ephemeris fields
  across subframes 1/2/3: `sqrt_a`, `e`, `m0`, `delta_n`, `i0`, `idot`,
  `omega0`, `omega`, `omega_dot`, the six harmonic corrections
  (`cuc/cus/crc/crs/cic/cis`), `toe`, `af0/af1/af2`, `toc`, `week`.
- **Grounding (two independent sources agree).** Bit offsets + scale factors are
  IS-GPS-200 Table 20-III, cross-checked *verbatim* against RTKLIB `rcvraw.c`
  `decode_subfrm1/2/3` (the reference open-source decoder). No constant is
  invented — the no-unverified-constants rule is cleared by
  two-source agreement, recorded in the fetch trail.
- **Word-splice bug avoided by construction.** The decoder reconstructs
  RTKLIB's parity-stripped 240-bit buffer (24 data bits × 10 words), so the
  word-boundary-spanning 32-bit fields (`m0`, `e`, `sqrt_a`, `omega0`, `i0`,
  `omega`) fall out of single `getbitu`/`getbits` reads — no hand-rolled
  cross-word splicing to get wrong.
- **Bridge: `Ephemeris::to_orbital_elements() -> Option<OrbitalElements>`.**
  Returns `None` if ANY required orbital field is absent — the propagator never
  runs on a half-decoded ephemeris, so no ECEF position is fabricated from
  partial data. A decode→bridge→propagate round-trip test recovers every field
  within its LSB and propagates to a valid GPS orbital radius.
- **The remaining gap (named, not faked):** `lib.rs::do_fix` still does NOT call
  `navmsg` — feeding it requires bit-synchronization + 50 bps nav-bit
  demodulation from the tracking loops (data bits across 20 ms code periods),
  which the file-proof `track()` does not yet produce. So a real capture cannot
  yet reach a coordinate end-to-end; the decode and propagate stages are proven
  in isolation, and the tracking→nav-bit stage is the next depth step.

**93 tests pass** (was 91: +2 net — navmsg gains the full decode round-trip +
partial-ephemeris-None guard); clippy `--all-targets` clean; fmt clean; zero
egress deps.

---

**Sprint 8 shipped (2026-07-08): GNSS depth — real parity + real PVT
(`phonetool-gnss` 0.8.0).** Deepens the shipped GNSS layer by removing two
honesty-holes the file-proof Sprint 6 left as placeholders. No new crate; the
defensive payload gains a real forgery-detection primitive and the PVT path
stops fabricating coordinates.

- **Real GPS parity (`navmsg::check_parity`).** The always-`true` stub is
  replaced by the IS-GPS-200 §20.3.5.2 (32,26) Hamming algorithm: the six
  parity equations D25..D30 recomputed from Table 20-XIV tap sets and the
  previous word's D29*/D30*, threaded across all 10 words of a subframe. Source
  data bits are de-complemented (`d_n = D_n ⊕ D30*`) so field extraction reads
  true bits. **This is the defensive point:** a forged/corrupted nav word — the
  spoofer's payload — now *fails* parity and its fields are discarded, instead
  of being silently admitted. A parity failure poisons the running state so the
  rest of the subframe fails too, rather than fabricating a recovery.
- **Real PVT (`pvt`).** The fabricated `(0,0,0)` fix + placeholder GDOP lookup
  are gone. New machinery: `sv_position_ecef` (Keplerian → ECEF propagation,
  IS-GPS-200 §20.3.3.4.3.1, bounded Kepler iteration total on hostile
  eccentricity), `solve_from_observations` (Gauss-Newton weighted
  least-squares position + clock-bias solve over ≥4 real satellite
  observations, real GDOP from `√trace((GᵀG)⁻¹)`, singular-geometry → `None`),
  `ecef_to_geodetic` (Bowring WGS-84). A known-receiver round-trip test recovers
  position + clock bias to sub-µs.
- **Honest `None` on the file path.** `solve(&observables)` returns `None` — the
  file-proof tracking loop produces neither decoded ephemeris nor calibrated
  pseudoranges, so a position is *not derivable* from it, and the solver says so
  rather than emitting `(0,0,0)`. New WGS-84 + relativity constants added to
  `constants.rs`, all IS-GPS-200 / WGS-84 cited.
- **The remaining bridge (named, not faked):** `OrbitalElements` (ICD-complete
  Kepler set) is the propagator's input; the partially-decoded `navmsg::
  Ephemeris` does not yet extract the harmonic-correction / rate fields
  (`delta_n`, `cuc/cus/crc/crs/cic/cis`, `idot`, split multi-word fields). Wiring
  navmsg → `OrbitalElements` with grounded Table 20-III bit offsets is the next
  depth step; no ECEF position is fabricated from partial data until it lands.

**91 tests pass** (was 78: +13 — 6 navmsg parity/hostile-input + 7 pvt
solve/propagation/matrix); clippy `--all-targets` clean (4×4 matrix math carries
a scoped, justified `indexing_slicing` allow — literal-bounded indices over
fixed stack arrays, the sanctioned exception); fmt clean; zero egress deps.

---

**Sprint 7 shipped (2026-07-08): Tier-B subprocess plugin host —
`phonetool-subprocess` (0.7.0).** The polyglot seam: any-language capabilities
(GNU Radio, gnss-sdr, Osmocom, Python) now plug in behind the exact same
`Plugin` trait via a length-prefixed JSON control channel over stdio.

- **New crate: `phonetool-subprocess`** — `SubprocessPlugin` implements `Plugin`
  by proxying `dispatch` to a child process. Spawns/owns/reaps the child;
  lazy-start on first dispatch or eager via `spawn()`.
- **Wire contract:** `[u32 BE length][UTF-8 JSON body]`. Request = `Command`;
  response = `Event` or `{"error":{"kind":"...","message":"..."}}` mapping to
  `PluginError`. Max frame bound (1 MB) enforced before allocation — a hostile
  prefix cannot force an unbounded alloc.
- **Untrusted child output:** every frame is bounded, deserialized in `Result`,
  mapped to `PluginError::Backend` on any malformation/timeout/early-close.
- **Reference echo-child binary** (`echo_child`) proves conformance: reads
  command frames, echoes back Events (or error frames on verb "error").
- **Gate stays Rust-side:** the `SubprocessPlugin` implements `Plugin` (passive);
  for active Tier-B ops, the host obtains a `Grant`/`TxGrant` before driving
  the child — a subprocess never bypasses authorization.

**78 tests pass** (was 70: +3 frame unit + 5 integration); clippy + fmt clean;
zero egress deps.

---

**Sprint 6 shipped (2026-07-08): GNSS receive + spoof/jam integrity —
`phonetool-gnss` on `IqFileSource` (0.6.0).** The full acquire → track → PVT →
integrity pipeline runs against recorded/synthetic GPS L1 C/A IQ files. The
defensive payload: every fix is qualified by a 9-family integrity verdict (spoof
+ jam detection), and the assessment runs even when no fix is obtained.

- **New crate: `phonetool-gnss`** — `Passive`, `RfRx`, never gated. One verb:
  `fix`. Pipeline: acquire GPS L1 C/A satellites (PRN × Doppler × code-phase FFT
  correlation), track (produce per-SV C/N0 + correlator observables), PVT solve
  (≥4 SVs → Fix with GDOP), integrity assessment (9 detector families).
- **Gold-code generation grounded in IS-GPS-200** — G1/G2 LFSR feedback
  polynomials + Table 3-Ia G2 tap-select pairs for PRN 1–32. Code length 1023
  chips; chipping rate 1.023 Mchip/s. All signal constants cited.
- **Integrity: 9 detector families** — `PowerAnomaly`, `ClockAnomaly`,
  `PositionJump`, `SqmDistortion`, `CrossConstellationDisagreement`,
  `NoiseFloorElevation`, `AgcAnomaly`, `SimultaneousLossOfLock`,
  `SingleSourceGeometry`. Each reports `Fired`/`Clean`/`Unavailable`. All
  thresholds parameterized via `IntegrityConfig` (no hardcoded literals).
- **`unavailable` is first-class** — checks that cannot run (no AGC from file
  source, no multi-antenna for AoA, no baseline for position-jump) honestly
  report `unavailable`, never a false "clean".
- **Degenerate discipline** — nothing observed = `PluginError::Empty`; no fix
  but a jam/spoof detected = `Ok(Event)` (the detection IS the result).
- **Reuses `SdrSource`/`IqFileSource` from sdr-rx** — no parallel source seam.
- **CLI wired:** `phonetool gnss <capture.iq>`. Registered in the passive
  registry alongside sdr and numintel.
- **Compile-fail doctest:** proves `GnssRx` NOT `ActivePlugin`.

**69 tests pass** (was 53: +4 gold-code unit + 11 gnss-pipeline integration + 1
compile-fail doctest); clippy `--all-targets` clean; fmt clean; zero egress deps.

---

**Sprint 5 shipped (2026-07-07): first passive RF layer — `phonetool-sdr-rx` on
`IqFileSource` (0.5.0).** The SDR receive pipeline runs today against recorded /
synthetic IQ files with no radio, no FFI, no hardware — the ahead-of-hardware
file-proof path the standing directive demands. Defines the `SdrSource` trait seam
that GNSS and cell-survey will consume downstream.

- **New crate: `phonetool-sdr-rx`** — `Passive`, `RfRx` transducer, never gated.
  Three verbs: `sweep` (PSD/periodogram), `identify` (energy detect + classify),
  `demod` (FM/AM/SSB → audio, digital → bits). All thresholds parameterized via
  `RxConfig` (no confabulated constants); `IqFileSource` reads raw `cf32` files.
- **`SdrSource` trait (RX-only, no transmit method)** — the device-agnostic seam.
  Has `read_block()` and `tuned()`; deliberately has NO transmit method, so an RX
  op cannot reach a TX path (same design as the authgate). `IqFileSource` is the
  default implementation, not a test double.
- **`SAMPLE_CAP` bounding** — file reads are capped at a configurable ceiling
  (default 16M samples ≈ 64 MB cf32); truncation recorded in the Event. Untrusted
  file length never trusted as an allocation size.
- **CLI wired:** `phonetool sdr sweep|identify|demod <file> [mode]`. Plugin
  registered in the passive registry alongside numintel.
- **Compile-fail doctest:** proves `SdrRx` does NOT implement `ActivePlugin` —
  the passive invariant is a compiler-checked fact.
- **Dependencies:** `rustfft` + `num-complex` (pure Rust, MIT, no unsafe, no
  network). Zero reqwest in default `cargo tree -e no-dev`.

**53 tests pass** (was 38: +15 offline-pipeline + 1 compile-fail doctest); clippy
`--all-targets` clean; fmt clean; zero egress deps.

---

**Sprint 4 shipped (2026-07-07): the spine sprint — core changes the spec sweep
proved every new layer needs before it can build.** First code since Sprint 2;
MINOR bump 0.3.0 → 0.4.0 (three backward-compatible core additions + one semantic
loosening). Resolves the three *mechanical* decisions the Sprint 3 sweep surfaced;
the two genuine *forks* (#2 meta-gate, #3 WireGrant) are explicitly DEFERRED with
rationale, not silently decided.

- **#6 `CaptureRef` writer (RESOLVED).** `CaptureBus::record_capture(kind, path)`
  is now the one public writer every bulk-artifact layer (RF RX/TX, cell-survey,
  gnss, ss7, legacy-hw) uses; `CaptureRecord::CaptureRef` lost its `#[allow(dead_code)]`.
  Bulk samples stay out of the timeline by reference. +2 unit tests.
- **#4 `RfRx` shareable (RESOLVED).** `is_exclusive` now `true` only for `Wireline`
  and `RfTx`; `RfRx` is a shareable *logical medium*, so `sdr-rx`/`gnss`/`cell-survey`
  co-register and run together on the hardware-free `IqFileSource` path (the same
  category fix the `Ip` change applied in Sprint 2). Physical single-SDR arbitration
  (live radio) is a *separate* seam owned by the Tier-B subprocess host — still open
  (gnss OQ5 / cell-survey Gap 2), which is about the device, not co-registration.
  +2 registry tests; stale spec claims in `workbench-shell`/`gnss`/`cell-survey`
  corrected to match code.
- **#1 `TxPlugin` dispatch path (RESOLVED — Axis B is now fully wired).** New
  `TxPlugin { dispatch_tx(cmd, grant: &TxGrant) }` trait + `PluginRegistry` third
  map with `register_tx`/`dispatch_tx`, routed through the same `claim` helper;
  `manifests()` spans all three maps. Mirrors the passive/active pattern exactly;
  the single-token-enum alternative stays rejected (preserves compile-time
  Grant≠TxGrant non-interchangeability). Closes the symmetric doctest gap: a
  `compile_fail` proof that a `TxGrant` cannot be fabricated to reach `dispatch_tx`
  (authgate now carries both the `Grant` and `TxGrant` forgery proofs). rf-tx can
  now plug in. +4 registry/dispatch tests.

**33 tests pass** (was 24: +2 capture, +6 registry, +1 doctest); clippy `--all-targets`
clean (default AND `--features online`); fmt clean.

**#5 RF Tier policy (RATIFIED, no code):** Tier-B (GNU Radio / gr-gsm / gnss-sdr /
Osmocom children over the subprocess-IPC contract) is the primary LIVE path for RF
DSP breadth; native Rust is the ahead-of-hardware file-proof path (`IqFileSource` +
`dsp`), and safety/integrity logic (GNSS spoof verdict, TX bandplan check, the gate
itself) stays Rust-side in BOTH regimes — never outsourced to a child. Confirms the
direction all four RF specs already recommend; the concrete Tier-B build waits on
`specs/subprocess-ipc-contract/`.

**Deferred forks (surfaced, NOT decided — await a concrete consumer):**
- **#2 META-GATE (generalize authgate to N named axes): DEFERRED.** Minimalism call: the two
  axes are hand-duplicated *on purpose* — distinct nominal token types are a
  spec-mandated compile-time guarantee (an IP `Grant` must be unable to satisfy a TX
  parameter). Macro/generic-abstracting 2 axes to serve consumers that don't exist yet
  (`WireGrant` has no plugin; ss7 link-auth is unbuilt) is speculative generality.
  Revisit when the *4th* concrete axis lands, or when #3 is built (whichever first).
- **#3 `WireGrant` (legacy-hw physical-injection axis): DEFERRED.** legacy-hw is the
  furthest-off layer (hazardous, hardware-gated, no device). Adding a third gate axis
  with zero consumer now is premature; fold it in (as its own axis — a plant seizure
  is not an `ActiveIp{target}`) when legacy-hw's active half is actually built. The
  orthogonal hardware-safety interlock (line voltage) remains a separate necessary
  precondition, not an auth axis.

---

**Sprint 3 shipped (2026-07-07): full-stack spec sweep — design-only triples for
all 9 remaining roadmap layers.** DESIGN-ONLY, no code (version held at 0.3.0 — the
Cargo manifest mirrors the buildable artifact, which did not change; specs are the
destination map, not a shipped feature). Authored + independently verified +
cross-layer-synthesized. New `specs/<layer>/{requirements,
design,tasks}.md` for: `attest`, `baittriage`, `ss7`, `wardial` (IP); `sdr-rx`,
`cell-survey`, `gnss`, `rf-tx` (RF); `legacy-hw` (copper). 6 passed verify clean;
3 (`ss7`/`gnss`/`rf-tx`) had real defects fixed (error-mapping contradictions,
false-resolution of a Command-arg problem, boolean→multi-class flag). Every triple:
EARS/Kiro house format, real-type-grounded, degenerate-case discipline,
ahead-of-hardware TODAY-vs-device-seam split, no confabulated constants (all
deferred to Open Questions).

**Operator decision framing banked:** lack of physical hardware is NOT a scoping
limiter — spec everything, build software functionality first, hardware follows.
(Recorded in project memory.)

### Architectural decisions the sweep surfaced. Items 1/4/5/6 RESOLVED and 2/3
### DEFERRED by Sprint 4 (the spine sprint) — see the Current state block above.
### Items 7–11 remain OPEN (do NOT silently decide these):

1. ✅ **RESOLVED (Sprint 4) — Axis-B dispatch.** `TxPlugin { dispatch_tx(cmd, grant:
   &TxGrant) }` + `register_tx`/`dispatch_tx` through the existing `claim()` helper,
   as recommended; single-token-enum alternative rejected. rf-tx can now plug in.
2. ⏸️ **DEFERRED (Sprint 4) — META-GATE (N named axes).** The two axes are distinct
   nominal types *by design* (compile-time Grant≠TxGrant). Generalizing to serve
   consumers that don't yet exist is speculative generality; revisit at the 4th
   concrete axis, or when #3 is built. (Original framing preserved below.) The
   two-axis model strains in 3 places (`rf-tx` Axis-B dispatch — now built; `legacy-hw`
   physical-plant injection = neither axis; `ss7` interconnect injection).
3. ⏸️ **DEFERRED (Sprint 4) — `legacy-hw` `WireGrant`.** furthest-off layer, zero
   consumer; add as its OWN axis (a plant seizure logged as `ActiveIp{target}` is a
   category error) when legacy-hw's active half is built — not before. The ORTHOGONAL
   hardware-safety interlock (line voltage) stays a separate necessary precondition.
4. ✅ **RESOLVED (Sprint 4) — RfRx registry collision.** `is_exclusive(RfRx)` now
   `false`; `RfRx` is a shareable logical medium, so `gnss`/`sdr-rx`/`cell-survey`
   co-register on the `IqFileSource` path (the `Ip` fix's shape). Physical-device
   arbitration moved to the Tier-B host seam (gnss OQ5 — still open, but distinct).
5. ✅ **RATIFIED (Sprint 4, no code) — RF Tier policy.** Tier-B (GNU Radio / gr-gsm /
   gnss-sdr children over the subprocess-IPC contract) is the primary LIVE path; native
   Rust is the ahead-of-hardware file-proof; safety/integrity logic + the gate stay
   Rust-side in both regimes. Shapes `sdr-rx`/`cell-survey`/`gnss`/`rf-tx`.
6. ✅ **RESOLVED (Sprint 4) — `CaptureRef` writer.** `CaptureBus::record_capture(kind,
   path)` is the one public bulk-artifact writer; `CaptureRef` no longer dead-code.
7. **Shared-crate factoring** (dedup): a SIP-message crate (`sip`/`wardial`/`attest`);
   a Goertzel/DSP crate (`wardial`/`legacy-hw`, broadenable); one bounded-source
   pattern (deconflict the `CaptureSource` name collision + shared `SAMPLE_CAP`); a
   shared soapysdr FFI binding; one pure-Rust pcap/SCTP crate (`ss7`/`cell-survey`).
8. **Core principle to ratify:** "egress is gated by an off-by-default Cargo feature,
   not the runtime gate; egress ≠ active op" (`attest` x5u, `baittriage`/`numintel`
   enrich) + state SSRF-hardening (https-only/timeout/byte-cap/allowlist) once.
9. **Media path gap:** `wardial`'s SIT/fax/modem/voice disposition has no substrate
   (no RTP-receive + codec decode anywhere). Recommended: in-process Tier-A G.711 RTP
   receiver. Also implied: a Tier-B STT consumer of `CaptureRef{CallAudio}` that
   `baittriage` depends on.
10. **`IntelStore` gap:** exact-match get/put only, no atomic RMW → `baittriage` fuzzy
    correlation impossible + non-race-free reuse counting. Recommended: Tier-B fuzzy
    analyzer + a minimal atomic put-if-absent on the (numintel-shared) store.
11. **Grounded-constants sourcing** (no unverified constants): each layer's deferred
    numeric constants need a designated citable source at build time (SS7 opcode
    tables, IMSI-catcher thresholds, GNSS spoof/jam metrics, wardial SIT/CNG tones,
    rf-tx band plans, legacy-hw DTMF/MF/2600 + interlock voltages). None invented.

**Coverage note (roadmap gaps still un-specced):** SIM-swap intel, DECT/Bluetooth/
satphone RF decode, the media/RTP+codec layer, STT, and the `discovery` module — named
in the project roadmap, no spec yet. Next sweep or fold into existing layers (TBD).

---

**Sprint 2 shipped (2026-07-07): first active capability — `phonetool-sip` (SIP
extension enumeration).** This is the first operation that transmits to a remote,
so it is the first end-to-end exercise of the auth-gate spine (numintel is Passive
and never touched it). The gate reaches the plugin layer via a new `ActivePlugin`
trait whose `dispatch_active` requires a `Grant`; a compile-fail doctest proves an
enum op is unrepresentable without one. Verified against the real binary: `plugins`
lists `sip [Ip/ActiveIp]`; empty `--basis` → gate refusal (exit 1); valid basis with
no listener → `Empty` degenerate failure (exit 1). **24 tests pass** (5 gate + 3
registry + 8 numintel + 6 sip + 2 doctest); clippy `--all-targets` clean; fmt clean.

**Two binding operator decisions this sprint:**
1. **Always-compiled, gate-only.** `phonetool-sip` is a normal (non-optional) CLI
   dependency and ships in the default binary; the only lock is the runtime `Grant`
   (rejected an off-by-default `sip` Cargo feature as a redundant second lock).
   **Honesty consequence:** the offline claim narrows to "zero egress *dependencies*"
   (SIP uses `std::net`; `cargo tree -e no-dev` still shows zero reqwest), NOT "no
   active code" — the default binary contains an inert active path, present but
   unreachable without a `Grant`. Fixed in the project docs + this file.
2. **First op = extension enumeration** (not gentler OPTIONS-liveness) — straight to
   genuinely toll-fraud-adjacent recon. No narc-jump: the gate is the real control
   and stays fully in force. All tests drive a loopback responder on `127.0.0.1`
   (operator-owned); building ≠ firing at a third party.

**Invariant banked for all future active plugins:** target authority lives in the
`Grant`, never the `Command` — read `grant.target()`; the command arg carries only
the operation's own params. Closes second-target-injection by construction.

Specs added: `specs/sip-recon/` triple.

---

**Sprint 1 shipped (2026-07-07): Rust workbench shell + auth-gate + numintel.** The
vertical slice is built, tested, and cross-compile-proven — this ends the
"permanent-0.1.0 purgatory" by landing the shell + one plugin end-to-end.

Cargo workspace (resolver 3, edition 2024, rust-version 1.89, `unsafe_code=forbid` +
`unwrap/expect/indexing_slicing=deny`, `lto=thin`), four crates:

- `phonetool-authgate` — **the spine.** Two-axis type-state gate. `Grant` (Axis A / IP,
  target-ownership) and `TxGrant` (Axis B / RF-TX, band+power+license) are unforgeable,
  crate-private-ctor tokens; an active op is *unrepresentable* without one (compile-fail
  doctest proves it). Fail-closed; every grant AND refusal logged via `ConsentLog`.
- `phonetool-core` — the shell: `Plugin` trait + `PluginRegistry` (indexed by
  `Transducer`, arbitrates exclusive hardware ports), `CaptureBus` (unified event+consent
  timeline; implements the gate's `ConsentLog`), offline-first `SqliteStore` (bundled
  sqlite), `Config`. **No network egress in core** (compile-time).
- `phonetool-numintel` — first plugin. `Passive` (never gated). E.164 boundary validation.
  Offline cache by default; `online` Cargo feature (OFF by default) adds `reqwest`(rustls)
  write-through. Cache miss = `Empty` (failure, not empty success).
- `phonetool-cli` — `phonetool` binary (clap): `plugins`, `lookup`, `seed`.

**Verified:** 16 tests pass (5 gate + 2 registry + 8 numintel + 1 compile-fail doctest);
clippy clean (default AND `--features online`); fmt clean; end-to-end run proven via the
real binary; **zero reqwest in default `cargo tree -e no-dev`** (offline is structural);
**aarch64-unknown-linux-musl static cross-compile CONFIRMED** for both default and
`--features online` (clears the plan's flagged rusqlite-bundled + rustls-under-musl risk).

Specs written as `specs/{authgate,workbench-shell,numintel}/` triples
(requirements/design/tasks) + `specs/subprocess-ipc-contract/` **DESIGN-ONLY** (Tier-B
wire seam, not built).

**Scope:** phonetool is a full-spectrum telecom *workbench* — one console interfacing every
layer of the network: copper/pre-digital (wardialing via SIP origination; lineman physical
eval for legacy pre-DSS switching if hardware is acquired) through current-state IP telecom
(SIP/VoIP, SS7/Diameter, caller-ID/STIR-SHAKEN, vishing/SIM-swap intel) through
RF/air-interface (cellular, cordless/DECT, CB, ham, Bluetooth, satphone, GNSS/GPS, general
SDR signal work). Full-spectrum is intent, not over-build: implement one layer deep at a
time, modern IP first; copper/lineman and RF land when hardware or a concrete target
exists. RF and lineman are distinct module classes — separate toolchains, not folded into
IP socket code. RF TX carries a band/license gate axis beyond target-ownership.

## Architecture decision (2026-07-06 → confirmed & executed 2026-07-07)

**Runtime = Rust** (overturns the old "Python assumed" default). Chosen via a
structured evaluation (recon → 3-way design panel → synthesis → adversarial verification); all
6 ecosystem claims came back CONFIRMED, zero refutations. Grounded in a prior in-house
exemplar — same defensive/untrusted-byte domain, already a Rust
Cargo workspace on a trait+Registry plugin model. Rust answers both halves of the
native-vs-Python question (control plane + the future soft-real-time DSP/tone-gen crux) in
one binary, gives memory safety on hostile telecom input, a compiler-enforced auth-gate
spine, and a static-musl offline-first single binary.

Defensive recon core with offensive capability held in reserve as a **continuity
mechanism** — operator's explicit framing. Offensive/intrusive modules gate
behind an authorization + target-ownership assertion; this is now a **compile-time
property** (the authgate spine), the code-level expression of the standing directive: no
illegal cybercrime except self-defense / defense of others.

## Next steps

**Shell → spine → SDR RX → GNSS → durable sink → Tier-B seam** all done. The workbench
now has the complete plugin-host infrastructure: native Tier-A plugins + subprocess Tier-B
proxy + durable capture timeline. Eight crates.

1. ~~**SDR RX file-proof.**~~ **DONE (Sprint 5).**
2. ~~**GNSS + integrity.**~~ **DONE (Sprint 6).**
3. ~~**Durable capture sink.**~~ **DONE (Sprint 6 patch).** JSONL file behind `CaptureBus`.
4. ~~**Tier-B subprocess seam.**~~ **DONE (Sprint 7).** `SubprocessPlugin` + echo-child
   conformance harness.
5. **First Tier-B consumer** — wire a real GNU Radio flowgraph (or `gnss-sdr`) through
   `SubprocessPlugin` for live-radio receive. Deferred until hardware/device arrives.
6. **numintel `online` provider** — ship cache-only; prefer no-retain/no-resell when
   enabling `online`; never hardcode a provider.
7. **GNSS depth — MOSTLY DONE (Sprints 8–10).** Real parity (§20.3.5.2), real PVT machinery
   (ephemeris→ECEF Kepler propagation, Gauss-Newton LSQ, real GDOP, WGS-84), full Table 20-III
   ephemeris extraction, the `Ephemeris → OrbitalElements` bridge, AND bit-sync + 50 bps
   nav-bit demod + frame sync (`navsync`) all ship; every stage of IQ→prompts→bits→subframes→
   ephemeris→ECEF is built and tested. The `(0,0,0)` fabrication is gone. **Remaining:**
   (a) a full-scale end-to-end IQ→coordinate run on a ≥6 s multi-subframe capture (megasample,
   gated on real/large synthetic data) + pseudorange extraction from the tracking loops to
   feed `solve_from_observations` (observable-only `solve` still returns honest `None`);
   (b) integrity threshold grounding (P2 — no threshold coded until a citable source lands);
   (c) multi-constellation extension.
8. **New spec-to-code layers.** ~~attest~~ **DONE (Sprint 11).** ~~cell-survey~~ **DONE
   (Sprint 12)** — GSM decode end-to-end from GSMTAP-over-pcap; LTE/NR decoders are declared
   seams (ASN.1 UPER, blocked on OQ3 recorded-source + a grounded UPER path); detection
   thresholds injected not hardcoded (cited values still OQ1); the live scan is the
   off-by-default `live` Tier-B seam. The `online` `verify` half of **attest** (x5u fetch +
   ES256) remains BLOCKED on operator OQs (trust-anchor provisioning, x5u allowlist, pure-Rust
   crypto crate). ~~wardial~~ **DONE (Sprint 13)** — SIP-only origination path shipped
   (2nd `ActivePlugin`; gate + cost/attribution acknowledgement; range-in-grant; inert
   without a trunk). wardial follow-ons: the media/RTP path (OQ6 — nothing in the
   workbench receives RTP yet; `MediaDisposition` is always `NotAnalyzed`, so no
   SIT/fax/modem/voice tier); grounded tone constants (OQ4); grounded trunk-policy
   bounds (OQ1/OQ2); real trunk integration (SIP REGISTER/auth, TCP/TLS). cell-survey
   follow-ons: LTE/NR decode + live scan when hardware/UPER land; cited detection
   thresholds (OQ1); baseline provenance (OQ2).
   ~~baittriage~~ **DONE (Sprint 14)** — passive fraud-caller footprint triage: IOC
   extraction + normalization (shared `Number::parse`) + offline exact-match correlation +
   store-backed scam-pattern classification + idempotent reuse index. Default-path only;
   `online` enrichment is a declared feature seam (provider OQ unresolved), signatures ship
   empty (`Unknown` until seeded — OQ2), confidence cutoffs injected not invented (OQ1).
   baittriage follow-ons: fuzzy correlation + atomic reuse (the known gap — Tier-B analyzer +
   a minimal atomic `put`-if-absent, direction B on record); `online` provider when the
   numintel OQ resolves; signature seed corpus + confidence-cutoff policy.
   ~~ss7~~ **DONE (Sprint 15)** — passive SS7/Diameter analyzer: bounded BER reader,
   SCCP/TCAP/MAP + Diameter S6a decode from hex/pcap, location-disclosure / intercept-enabling
   flagging (grounded, `Unknown` where not). ss7 follow-ons: the live signalling-link source
   (`live` feature, carrier/HW-gated); the active injector (Axis-A `Grant` + lawful link — is
   interconnect a third gate axis? OQ1); grounded-table completion from the 3GPP specs (OQ2/OQ3).
   ~~rf-tx~~ **DONE (Sprint 16)** — first Axis-B `TxPlugin` consumer: CW/AFSK modulation →
   FileSink render, `TxGrant`-gated, FCC Part 97 band plan, no device sink (emission structurally
   impossible). rf-tx follow-ons: the device FFI-quarantine crate (`device` feature — HackRF/
   Lime/Pluto, the only `unsafe`); FM/SSB (input-audio reader + filter params); band-plan
   jurisdiction expansion (ISED/CB/GMRS, OQ2); live TX tier (Tier-B GNU Radio vs native FFI, OQ4).
   ~~legacy-hw~~ **DONE (Sprint 17)** — copper passive half (DTMF/MF/2600 decode + synth, Bell-202
   CID, line sense) + the third gate axis (`WireGrant`/`WirePlugin`, Axis-C, resolving OQ1 Option 1
   and pre-empting the OQ6 N-axis question). legacy-hw follow-ons: the active injector
   (needs the `WireGrant` — now exists — AND a hardware-safety interlock, neither built);
   the FFI-quarantine crate + live sense source; MF R1 full table + switch-generation grounding.
9. **All spec triples are built.** No design-only layer remains. Remaining work is
   follow-ons and hardware-gated seams, not new layers: the Tier-B media handler that would
   unblock wardial's `MediaDisposition`; each layer's FFI/live-hardware seam; and the several
   named per-crate Open Questions (grounded-constant completion, provider choices, injectors).
   The next *new-code* candidate is a follow-on chosen with the operator, not a spec triple.

## Open questions for operator

- numintel `online` data source — which no-retain/no-resell provider, when opted in?
- Standalone or eventual embedded component? (STATE said standalone; revisit.)
- Target board (Pi 5 vs RK3588): deferred — hardware layer stays board-agnostic until one
  is chosen.
