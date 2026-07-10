# Design Document — phonetool-ss7

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** This spec fixes the passive SS7/Diameter
> capture-analysis contract now, so the decode/flag layers and the capture-source seam are
> stable when the first real capture (and, later, a live signalling link) lands. No code
> implements this yet.

## Overview

`phonetool-ss7` decodes a **supplied** SS7/Diameter capture offline and flags the privacy-
sensitive operations that make SS7 infamous. It is `Passive` (an observation of bytes the
operator already holds) and therefore, like numintel, implements only the `Plugin` trait and
never touches the auth-gate.

Two facts drive the whole design:

- **Modern SS7 is IP.** In an operator-observable deployment, SS7 rides **SIGTRAN**
  (M3UA/SCTP/IP) and Diameter S6a is IP-native. So the transducer is `Ip`, even though the
  payload is telecom signalling rather than VoIP. This is a *decode* of IP-carried bytes; it
  transmits nothing.
- **The bytes are adversary input.** A capture is a file — a honeypot dump, a fuzzed PDU set,
  a truncated recording. Every decode layer is total: malformed/truncated/deeply-nested input
  yields a decode error and a partial `Finding`, never a panic, a hang, or an unbounded
  allocation.

The capability splits into four seams, each with one job:

- **`source`** — where PDUs come from. A `CaptureSource` trait yields `Vec<u8>` PDUs. TODAY:
  `HexDumpSource` (a hex PDU dump) and `PcapSource` (a `.pcap`/`.pcapng` file). A future
  `LiveLinkSource` behind an off-by-default feature substitutes here without touching decode.
- **`ss7`** — the SS7 stack decoder: SCCP → TCAP (BER) → MAP operation resolution. Pure,
  socket-free, exhaustively testable against fixture PDUs with no network.
- **`diameter`** — the Diameter base + S6a decoder: header, command-code resolution, AVP
  iteration. Also pure and socket-free.
- **`lib` (`Ss7Analyzer`)** — the `Plugin` boundary. Reads the source from the command, drives
  the decoders, applies the location-disclosure classification and the degenerate-case
  discipline, and emits one `Event`.

## Architecture

```
   CLI: ss7 analyze <source>          (source = path to .pcap | .hexdump; NO gate, NO grant)
        │
        ▼
   Ss7Analyzer::dispatch(cmd)                    ← Plugin (passive); never sees a Grant
        │  verb guard: "analyze"
        │  source ← open(cmd.arg)  ── InvalidInput on missing/blank/empty; Backend on I/O failure ──► Err
        ▼
   CaptureSource::pdus()  ──────────────────────────────────────────────┐
     HexDumpSource   (hex tokens → bytes;  TODAY, zero egress deps)      │  SEAM
     PcapSource      (SCTP-reassemble / Diameter-over-SCTP|TCP; TODAY)   │
     LiveLinkSource  (SIGTRAN/Diameter peer; feature="live", OFF)  ◄─────┘  device/carrier gate
        │  Vec<Pdu>   (each Pdu = untrusted bytes)
        ▼
   for each pdu → dispatch_pdu (total; bounded; depth-capped BER):
        │
        ├─ ss7::decode ──► Sccp{ called_gt, calling_gt, ssn }
        │                    └► Tcap{ msg_type, component }
        │                         └► Map{ opcode → name (TS 29.002 table) }
        │
        └─ diameter::decode ──► Header{ cmd_code, r_bit, app_id }
                                  └► AVPs (bounded) → S6a name (TS 29.272 / RFC 6733 table)
        │
        ▼
   classify_disclosure(op)   ── GSMA FS.11 / FS.19 table ──► disclosure_class: LocationDisclosure|InterceptEnabling|Benign|Unknown
        │
        ▼
   Vec<Finding>   (decode failure of one PDU → Finding{ decoded:false }; never aborts run)
        │  decoded == 0 → PluginError::Empty      (degenerate = failure)
        │  else → Event{ summary, data:{ total, decoded, flagged, findings } }
        ▼
   CaptureBus.record_event(event)                ← same passive path numintel uses
```

## Modules

- **`source`** — the `CaptureSource` trait (`fn pdus(&self) -> Result<Vec<Vec<u8>>, SourceError>`),
  `HexDumpSource`, `PcapSource`, and `SourceError` (`NotFound`/`Unreadable`/`Empty`/`BadHex`/
  `BadContainer`). The `feature = "live"` `LiveLinkSource` implements the same trait. This is
  the one seam that distinguishes TODAY (file) from the device/carrier future (link).
- **`ss7`** — `Sccp`, `Tcap` (`TcapMessageType`, `Component`), `Map` (`operation: MapOp`),
  the grounded `MAP_OPS` table (TS 29.002), a bounded BER/TLV reader, and `Ss7DecodeError`.
- **`diameter`** — `DiameterHeader`, an AVP iterator, `S6aCommand`, the grounded
  `DIAMETER_S6A_CMDS` table (TS 29.272 / RFC 6733), and `DiameterDecodeError`.
- **`classify`** — `Operation` (unified across SS7/Diameter), `DisclosureClass`
  (`LocationDisclosure`/`InterceptEnabling`/`Benign`/`Unknown` — a location/serving-node reveal,
  an auth-vector fetch or registration/redirect hijack, neither, or not-yet-grounded), and the
  grounded `DISCLOSURE_TABLE` (GSMA FS.11 / FS.19) mapping each operation to its class.
- **`lib`** — `Ss7Analyzer { }`, its `Plugin` impl, `Finding` (`Serialize`, carrying a
  `disclosure_class` and a `decoded` flag), and the private helpers `open_source`,
  `dispatch_pdu`, `map_source_error`.

## Design decisions

### `Ip` transducer for a signalling analyzer

The transducer names the *port the plugin binds to*, and modern SS7/Diameter that an operator
can observe is IP-carried (SIGTRAN M3UA/SCTP, Diameter over SCTP/TCP). `Ip` is shareable in
the registry (only `Wireline`/`RfRx`/`RfTx` are exclusive physical ports), so the analyzer
coexists with numintel and phonetool-sip on the same `Ip` medium without an arbitration
collision. A legacy TDM/E1-tap capture path, if it ever exists, would be a `Wireline` source
feeding the *same* decode layers — a `source`-module concern, not a decode-layer one.

### Passive `Plugin`, not `ActivePlugin` — and why the distinction is load-bearing here

Decoding a capture the operator holds is observation; it never transmits. So `Ss7Analyzer`
implements `Plugin` and is handed no `Grant`. This is the whole point of the two-trait split:
the same crate that can *read* an SRI-SM PDU has, by construction, no code path to *originate*
one — origination lives in a different trait (`ActivePlugin`) that cannot be dispatched without
a gate-minted `Grant`. The infamous-ness of SS7 is in the active use; the analyzer is the
defensive mirror of it and carries none of that capability.

### Total, bounded, depth-capped decode over untrusted bytes

TCAP is BER-encoded and MAP is ASN.1 — both admit nested, constructed, and indefinite-length
elements. A naive recursive-descent BER reader is a stack-exhaustion vector on a crafted PDU.
The reader therefore (a) treats every TLV length as fallible arithmetic against the remaining
buffer (checked, never trusting the declared length), and (b) enforces a **maximum nesting
depth**, returning a decode error past it rather than recursing. Diameter AVP iteration is the
same discipline: an AVP length that would overrun the message stops iteration with
`decoded: false`. No `unwrap`, no `buf[i]` — the workspace deny-lints enforce it, but the
intent is explicit because the input is adversary-authored even though the op is passive.

### Per-PDU resilience vs. whole-capture degenerate discipline

Two disciplines at two layers, mirroring phonetool-sip's split. *Within* a capture, one PDU
that fails to decode is a `Finding { decoded: false }`, never a run-aborting error — a single
malformed frame cannot kill analysis of the rest. *Across* the capture, if **nothing**
decoded, the op returns `PluginError::Empty`: a capture that taught us nothing is a failure
the operator sees. Crucially, a capture that decoded cleanly but contained **no** location-
disclosure operation is **not** degenerate — "no tracking traffic here" is a real, reportable
`Ok(Event)`.

### The capture-source seam is the TODAY-vs-device split

`CaptureSource` is the single abstraction that separates what runs now from what needs
hardware. `HexDumpSource` and `PcapSource` are pure file readers — they run **today**, with no
device and zero egress dependencies. `LiveLinkSource` (a live SIGTRAN/Diameter peer) is a
future implementer of the *same* trait, behind an **off-by-default `live` Cargo feature**
(numintel's `online` model). Because the decode/flag layers consume `CaptureSource` and never
a socket, adding the live source changes no decode code and the offline analyzer never links
egress. Honesty caveat, stated as in sip-recon: once `live` exists the offline guarantee is
"**zero egress dependencies on the analysis path**", not "no network code".

### Flag presence, not intent

The classifier reports that a flagged operation (location-disclosure or intercept-enabling) is
*present in the capture* — it does **not** assert the operation was malicious, unauthorized, or
attributable. A ULR from a
subscriber's own home MME is routine; a cross-boundary ATI is the abuse case; the analyzer
does not have the context to tell them apart and does not pretend to. This keeps the tool
defensive/observational and avoids fabricating an accusation the bytes do not support.

### Grounded constants only

Every MAP operation code (TS 29.002), Diameter command code (TS 29.272 / RFC 6733), ASN.1 tag
(ITU-T Q.773), and GSMA disclosure category (FS.11 / FS.19) is a **grounded constant** cited
at its definition site. Where a value is not yet verified against the standard at build time,
the code leaves it unresolved and the operation reports `unknown` (opcode) /
`disclosure_class: Unknown` rather than shipping an invented number. This spec deliberately
states **no** numeric opcodes, command codes, or category thresholds — they are deferred to
the grounded build (Open Questions), because confabulating them is exactly the fabrication failure
mode this project forbids.

## Known architectural gap: active injection has no home here (and shouldn't yet)

The active injector — originating SRI-SM, ATI, PSI, or Diameter ULR/IDR onto a real link — is
**deliberately absent**. It is a distinct, doubly-gated future capability:

1. **Cyber authorization (Axis A).** It would implement `ActivePlugin`, and its
   `dispatch_active(&self, cmd, grant: &Grant)` would read the authorized target from
   `grant.target()`, never from the command — the active-plugin invariant phonetool-sip
   established. No `Grant` ⇒ no injection, as a compile-time property.
2. **A lawful link (carrier/HW gate).** Even *with* a `Grant`, origination requires a
   provisioned SS7 point code or Diameter peering the operator does not possess by building
   this crate. This is the `LiveLinkSource` device/carrier seam, in its transmit direction.

So the injector is gated on **both** a `Grant` **and** a lawful link, and neither alone
suffices. **Recommendation (not a silent decision):** model injection as Axis A *plus* a new
explicit link-authorization assertion recorded in the consent log, and treat the "is SS7/
Diameter interconnect a third regulatory axis, like spectrum's Axis B?" question as an Open
Question for the operator — see below. Building the analyzer first is correct per the standing
directive: software functionality ahead of the gear, defensive decode ahead of any injector.

## Error handling

Two error vocabularies at two boundaries. `SourceError` (`thiserror`) is the ingestion layer's
(`NotFound`/`Unreadable`/`Empty`/`BadHex`/`BadContainer`); `map_source_error` maps it to the
trait-level `PluginError`. A boundary-validation failure — `NotFound` (missing/blank path),
`BadHex`, `BadContainer`, or `Empty-source` — maps to `InvalidInput`; a genuine I/O failure
mid-read on a valid, existing source (`Unreadable`) maps to `Backend`, mirroring sip-recon's
`Socket → Backend` (this crate's `Backend` variant is otherwise unused). `Ss7DecodeError` and `DiameterDecodeError` never escape `dispatch_pdu` — a
decode failure becomes a `Finding { decoded: false }`, not a run abort. A capture that decoded
zero PDUs becomes `PluginError::Empty` (degenerate). No panics: the crate compiles under
`unsafe_code = forbid` and the workspace `unwrap_used`/`expect_used`/`indexing_slicing = deny`
lints — mandatory here because the whole input surface is hostile bytes.

## Threat note

The entire input surface is adversary-controlled: SCCP/TCAP/MAP PDUs, Diameter AVPs, and the
`.pcap` container framing are all attacker-authored bytes. Attack classes and mitigations:
(1) **truncated / lying length fields** → checked arithmetic against remaining buffer, never
trust a declared length (Req 2.2, 2.5); (2) **deeply-nested / indefinite-length BER** →
depth cap, no unbounded recursion (Req 2.3); (3) **oversized capture / oversized PDU** → a
bounded per-PDU size and a bounded PDU count, so a giant file cannot force an unbounded alloc;
(4) **malformed pcap container** → `BadContainer` error, not a panic; (5) **misleading
content** (a benign-looking op that is actually cross-boundary tracking) → the tool flags
*presence*, not intent, and does not fabricate attribution (Req 6.2). The op is passive, so
there is no transmit-side threat — but "passive" does not mean "trusted input": it means the
danger is a crash/hang/RCE on decode, which the totality discipline closes.

## Testing strategy

- **Fixture PDU corpus** (`tests/`): hand-built, standard-cited SCCP/TCAP/MAP and Diameter S6a
  PDUs — one per flagged operation (location-disclosure ATI, SRI-SM, SRI, PSI, ULR, IDR;
  intercept-enabling AIR, UpdateLocation) and a benign control — each asserting the resolved
  operation name and the `disclosure_class`. Fixtures are **operator-authored bytes**, not a
  live capture; no network, runs today.
- **Hostile-input table** (`tests/`): empty, whitespace, non-hex token, truncated TLV, length
  field larger than the buffer, BER nested past the depth cap, indefinite-length construct,
  AVP length overrunning the Diameter message, and a giant PDU — each maps to the exact error
  or a `decoded: false` `Finding` **without panic**.
- **Degenerate discipline**: an all-undecodable capture → `PluginError::Empty`; a clean-but-
  benign capture (decoded PDUs, zero flagged) → `Ok(Event)` with `flagged: 0`; an empty source
  → `InvalidInput`.
- **`.pcap` ingestion**: a small canned SIGTRAN-over-SCTP capture and a Diameter-over-SCTP
  capture decode to the expected PDU set; a corrupt container → `BadContainer`.
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]` since the
  no-panic discipline binds library code, not assertions.

## Open questions for operator

1. **Is SS7/Diameter interconnect a third gate axis?** Injection (out of scope here) is Axis A
   (cyber) + a lawful link. Is unlawful *interconnect signalling* a distinct regulatory wrong
   deserving its own token — analogous to Axis B for spectrum — or is "Axis A `Grant` + a
   link-authorization assertion" sufficient? Not decided here; recommended direction is the
   latter, but flagged for the operator.
2. **Grounded constants source of truth.** TS 29.002 / TS 29.272 are paywalled 3GPP specs;
   RFC 6733 is open. Which reference does the operator want the `MAP_OPS` / `DIAMETER_S6A_CMDS`
   tables built from, and is a citable open mirror (e.g. a Wireshark dissector's opcode table
   with its own citations) acceptable as the grounding source? No opcodes are stated in this
   spec pending that decision.
3. **GSMA disclosure categories.** FS.11 (SS7) and FS.19 (Diameter) define the "category 1/2/3
   should-not-cross-boundary" guidance that underpins the flag. These are GSMA-membership
   documents. Which operations land in each `disclosure_class` (`LocationDisclosure` vs.
   `InterceptEnabling`), and how to source the category assignment without confabulating it, is
   deferred — operations default to `disclosure_class: Unknown` until grounded.
4. **`.pcap` parsing dependency.** Reading `.pcap`/`.pcapng` and reassembling SCTP is
   non-trivial. Does the operator accept a pure-Rust pcap/SCTP crate (vetted for the static-
   musl offline build and the deny-lints), or should the first cut be **hex-dump-only** with
   pcap deferred until a crate is chosen? The hex path alone satisfies the "runs today"
   directive.
5. **Bulk-capture referencing.** A large `.pcap` is a bulk artifact. Should the analyzer, when
   fed a large file, record a `CaptureRecord::CaptureRef { kind: CaptureKind::Pcap, path }` on
   the `CaptureBus` (by-path, never inlined) rather than holding the whole file, mirroring the
   IQ/pcap out-of-band discipline? Recommended yes; deferred to a task pending confirmation.
6. **Depth/size bounds.** The BER nesting-depth cap, the per-PDU byte cap, and the max-PDU-
   count are safety constants, not protocol constants — but their exact values need an operator
   decision (what's a realistic legitimate TCAP nesting depth vs. an attack). Deferred rather
   than invented.
