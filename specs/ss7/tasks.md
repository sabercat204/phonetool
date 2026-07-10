# Tasks — phonetool-ss7

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

**DESIGN-ONLY spec — nothing below is built. All items unchecked by construction.**

- [ ] 0. **Prerequisite / gap resolution (do before any decode code):** resolve the grounded-
  constants source of truth (Open Questions 2–3) and the active-injection axis question (Open
  Question 1) with the operator. Decode tables and the disclosure set MUST NOT be populated
  from memory; the injector's gate model MUST NOT be silently chosen. Records the decision
  before Task 4/5/6 can ground their tables.
  _(Req 9.4, 10.1, 10.2)_
- [ ] 1. Crate skeleton `phonetool-ss7`: `Ss7Analyzer` implements the passive `Plugin` trait
  only (no `ActivePlugin`); manifest declares transducer `Ip`, capability
  `CapabilityClass::Passive`. Verb guard → non-decode verb returns `PluginError::Unsupported`.
  Compiles under `unsafe_code = forbid` + workspace deny-lints; no RNG dep.
  _(Req 1, 10.3)_
- [ ] 2. `source` seam: `CaptureSource` trait + `SourceError`
  (`NotFound`/`Unreadable`/`Empty`/`BadHex`/`BadContainer`). `HexDumpSource` (hex tokens →
  PDU bytes, non-hex → `BadHex`, empty/whitespace → `Empty`). Zero egress dependency. Runs
  today with no device.
  _(Req 3.1, 3.3, 3.4, 3.5, 7.2, 8.1)_
- [ ] 3. Bounded BER/TLV reader: every length checked against remaining buffer (Req 2.2),
  fallible/saturating offset arithmetic (Req 2.5), maximum nesting-depth cap with a decode
  error past it (Req 2.3). No `unwrap`/`expect`/unchecked index. Hostile-input unit tests
  (truncated, over-declared length, deep nesting, indefinite-length) — none panic.
  _(Req 2)_
- [ ] 4. `ss7` decoder: SCCP address extraction (Called/Calling GT + SSN, Q.713) →
  TCAP message/component type (Q.771–Q.775) → MAP operation resolution via the **grounded**
  `MAP_OPS` table (TS 29.002; unknown code → `unknown(<code>)`). Inner-layer failure emits a
  partial `Finding { decoded: false }`, never discards the outer decode.
  _(Req 4)_
- [ ] 5. `diameter` decoder: RFC 6733 header (Command Code, R-bit, Application-Id), bounded
  AVP iteration (over-declared AVP length → stop + `decoded: false`), S6a command resolution
  via the **grounded** `DIAMETER_S6A_CMDS` table (TS 29.272 / RFC 6733), subscriber AVP
  (IMSI/User-Name) extracted or reported absent.
  _(Req 2.4, 5)_
- [ ] 6. `classify` module: unified `Operation`, `DisclosureClass`
  (`LocationDisclosure`/`InterceptEnabling`/`Benign`/`Unknown`), and the **grounded**
  `DISCLOSURE_TABLE` (GSMA FS.11 / FS.19). Classifies MAP ATI/SRI-SM/SRI/PSI and Diameter
  ULR/IDR as `LocationDisclosure`, MAP UpdateLocation and Diameter AIR as `InterceptEnabling`;
  ungrounded category → `Unknown`, never a guessed class; exact per-opcode membership deferred
  to Open Question. Reports presence, not intent or attribution.
  _(Req 6)_
- [ ] 7. `lib` glue: `open_source` (path missing/blank/empty → `InvalidInput`, mid-read I/O
  failure on a valid source → `Backend`),
  `dispatch_pdu` (total, per-PDU-resilient), degenerate discipline (0 decoded →
  `PluginError::Empty`; ≥1 decoded → `Ok(Event)` even with 0 flagged), event `data` carries
  `total`/`decoded`/`flagged`/`findings`, summary states flagged count + operation names.
  _(Req 3.3, 6.3, 7)_
- [ ] 8. `PcapSource` (behind the container-parsing decision, Open Question 4): read
  `.pcap`/`.pcapng`, reassemble SCTP DATA chunks / read Diameter-over-SCTP|TCP, untrusted
  container framing → `BadContainer` on corruption. Same `CaptureSource` seam as Task 2.
  _(Req 3.2, 3.3)_
- [ ] 9. CLI wired: `ss7 analyze <source>` → `Ss7Analyzer::dispatch` (no gate, no grant, same
  passive path numintel uses) → record `Event` on the `CaptureBus`. `plugins` lists
  `ss7 [Ip/Passive]`.
  _(Req 1)_
- [ ] 10. Fixture corpus + hostile-input + degenerate tests (`tests/`): one standard-cited PDU
  per flagged op (location-disclosure ATI/SRI-SM/SRI/PSI/ULR/IDR; intercept-enabling
  AIR/UpdateLocation) + benign control asserting op name and `disclosure_class`;
  hostile-input table maps to exact error / `decoded:false` without panic; all-undecodable →
  `Empty`; clean-but-benign → `Ok(Event)` with `flagged:0`; empty source → `InvalidInput`.
  Test targets `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]`.
  _(Req 2, 4, 5, 6, 7)_
- [ ] 11. Offline proof + docs: `cargo tree -e no-dev` shows zero egress crate for this crate;
  cross-compile aarch64-musl unchanged; docs state the offline guarantee as "zero egress
  *dependencies* on the analysis path" once `live` exists, not "no network code". VERSION +
  `[workspace.package]` bump on build.
  _(Req 8.1, 8.4, 10.3)_

## Deferred (post-analyzer, needs operator + hardware/carrier)

> **Tier seam.** The `LiveLinkSource` (SIGTRAN/M3UA/SCTP stack) and the future active injector
> are natural **Tier-B / subprocess** capabilities (per `specs/subprocess-ipc-contract/`) — an
> Osmocom/SIGTRAN stack proxied over the subprocess seam — not only native Tier-A. Whichever
> tier, they implement the same `CaptureSource` / `ActivePlugin` contract, so the decode/flag
> layers are unchanged either way.

- **Live-link capture source** (`LiveLinkSource`, `feature = "live"`, OFF by default): a real
  SIGTRAN/Diameter peer feeding the same `CaptureSource` seam. Carrier- and hardware-gated —
  requires a provisioned SS7 point code / Diameter peering the operator does not possess by
  building this crate. Decode/flag layers unchanged when it lands.
  _(Req 8.2, 8.3)_
- **Active signalling injector** (originating SRI-SM/ATI/PSI/ULR/IDR): a distinct future
  `ActivePlugin` — doubly gated on a `Grant` (Axis A, target from `grant.target()`, never the
  command) **and** a lawful link. Explicitly out of scope here; gets its own spec triple.
  Blocked on Open Question 1 (is interconnect a third regulatory axis?).
  _(Req 9)_
- **Bulk `.pcap` referencing** on the `CaptureBus` as `CaptureRef { kind: CaptureKind::Pcap,
  path }` (by-path, never inlined) for large captures — Open Question 5.
- **Legacy TDM/E1-tap capture** feeding the same decoders via a `Wireline`-transducer source
  (a `source`-module concern, not a decode-layer change) — only if a physical tap ever exists.
- **Correlation across PDUs** (matching TCAP Begin/Continue/End into transactions; linking a
  flagged query to its response) — the first cut classifies per-PDU; transaction stitching is
  a later enrichment.
