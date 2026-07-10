# Design Document — phonetool-attest

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** Fixes the shape of STIR/SHAKEN attestation
> inspection now — the passive parser, the offline/online split, and the untrusted-token
> threat model — so it is ready to build ahead of any telecom-capture hardware. No code
> implements this yet.

## Overview

`phonetool-attest` answers one question about a call: *what does it claim about its own
origin, and (online) does that claim cryptographically hold?* It parses the SIP `Identity`
header (RFC 8224) and the PASSporT JWT inside it (RFC 8225), reports the attestation level
(A/B/C per ATIS-1000074), the claims (`orig`/`dest`/`iat`/`origid`), and a `verstat`-style
verdict.

It is **passive** — reading what a call asserts is observation/knowledge, on neither
authorization axis — so it implements the plain `Plugin` trait and never receives a `Grant`,
exactly like numintel. The dual-use gate does not apply. What binds hard instead is the
threat stance: the `Identity` header and PASSporT are wholly adversary-controlled, so the
parser is **total** (never panics) and **fail-closed** (a malformed or unattested token is a
reported result or a typed error, never a guessed attestation).

The design has three seams, each with one job:

- **`passport`** — pure, network-free. Total decode/parse of an `Identity` header and its
  PASSporT: base64url segments → JOSE header + claims → attestation level. Exhaustively
  testable with no network and no hardware.
- **`verify`** (feature = `online`) — the only egress seam. Fetches the `x5u` certificate,
  verifies the ES256 signature, validates the chain to a trust anchor. Absent the feature,
  this module does not compile in and `VerificationStatus` is `StructuralOnly`.
- **`lib` (`AttestInspect`)** — the passive `Plugin` boundary. Selects the input source,
  drives the parser, applies the degenerate-case discipline, assembles the `AttestReport`.

## Architecture

```
   CLI: attest inspect <identity-header | @file | @pcap-ref>
        │  (no gate: Passive — dispatch(), never dispatch_active)
        ▼
   AttestInspect::dispatch(cmd)                 verb guard: "inspect"
        │  source ← inline arg | file | CaptureRef{ Pcap, path }   ── TODAY, no device ──┐
        │  (future) live Ip/wireline tap ──────────────────────────── DEVICE SEAM ───────┤
        ▼                                                                                 │
   extract Identity header(s) from SIP  ── none? → Ok(Event: NoIdentityHeader finding) ◄──┘
        │
        ▼
   passport::Identity::parse(bytes)     ── TOTAL over untrusted bytes ──
        │   split "jose.claims.sig"  → base64url-decode each  → JSON parse
        │   caps: MAX_IDENTITY, MAX_SEGMENT   errors: Empty|Malformed|BadBase64|BadJson|TooLarge
        ▼
   JOSE { alg, ppt, x5u }   Claims { attest, orig, dest, iat, origid }   Signature(bytes)
        │   attest → Full|Partial|Gateway|Unknown{raw}|None
        │   alg≠ES256 → finding UnexpectedAlg (no verify)   ppt≠"shaken" → finding UnexpectedPpt
        │
        ├── default build ───────────────────► VerificationStatus::StructuralOnly
        │
        └── feature "online" ──► verify::check_signature
                │   x5u: https-only, timeout, MAX_CERT_BYTES cap  (attacker-influenced URL)
                │   fetch cert → parse DER/PEM (untrusted) → ES256 verify over jose"."claims
                │   chain → STI-PA trust anchor?     no anchor → Failed{"no trust anchor"}
                ▼
             VerificationStatus::Verified | Failed{ reason }
        │
        ▼
   AttestReport → Event { source:"attest", summary, data }
        │   degenerate: parsed-but-no-attestation → Ok(Event, level None, finding)
        │              empty input → PluginError::Empty (nothing to inspect)
        ▼
   CaptureBus.record_event(event)          (no ConsentRecord — passive path)
```

## Modules

- **`passport`** — network-free, always compiled. `Identity` (the parsed header +
  parameters); `Identity::parse(&[u8]) -> Result<Passport, ParseError>`; `Passport { jose,
  claims, signature }`; `Jose { alg, ppt, x5u, typ }`; `Claims { attest, orig, dest, iat,
  origid }`; `Attestation` (`Full`/`Partial`/`Gateway`/`Unknown { raw }`/`None`); a total
  unpadded-base64url decoder; `ParseError` (`Empty`/`MalformedToken`/`BadBase64`/`BadJson`/
  `TooLarge`); `Finding` (`NoIdentityHeader`/`NoAttestClaim`/`UnexpectedAlg`/`UnexpectedPpt`).
  Constants `MAX_IDENTITY`, `MAX_SEGMENT` (values are an Open Question).
- **`sipmsg`** — network-free. A minimal, total extractor that pulls `Identity` header value(s)
  out of a SIP message or fragment (header-name match is ASCII-case-insensitive per RFC 3261),
  tolerant of CRLF and bare-LF line folding. Reused shape from `phonetool-sip`'s parser
  discipline: no `unwrap`, no unchecked index. It does *not* parse the whole SIP grammar —
  only enough to locate `Identity`.
- **`verify`** *(feature = `online`)* — the only egress module. `check_signature(passport,
  &TrustAnchor, &FetchCfg) -> VerificationStatus`; the `x5u` fetch (https-only, timeout,
  byte-cap); ES256 verification; chain validation to the STI-PA anchor. `TrustAnchor` and its
  provisioning are an Open Question. Absent the feature, this module is `#[cfg(feature =
  "online")]`-gated out entirely.
- **`lib`** — `AttestInspect { cfg }` and its `Plugin` impl; `AttestReport` and
  `VerificationStatus` (`StructuralOnly`/`Verified`/`Failed { reason }`); the private helpers
  `select_source`, `to_report`, and the verb guard.

## Design decisions

### Passive, not gated — attest never sees a Grant

Inspecting a token a call already sent is receptive: no packet leaves the box on the default
path, nothing is done *to* a third party. So attest implements `Plugin` (like numintel), not
`ActivePlugin`, and the compiler guarantees it: with no `dispatch_active`, there is no code
path that can be handed a `Grant`. This keeps the recon path frictionless per the standing
directive — no gate theater on knowledge work.

### The online `x5u` fetch is egress, but is *not* an active op

Fetching a public certificate the caller named is still observation-coded — it leaks nothing
about the operator's intent or targets (it is the same GET any verifying SBC makes). So it does
**not** cross the gate; it is not an Axis-A active operation against a chosen target. It is,
however, network egress and an *attacker-influenced* request, so it is fenced behind the
off-by-default `online` feature exactly like numintel's live lookup, and hardened as an SSRF
surface (https-only, timeout, byte-cap, optional host allowlist). The offline claim narrows to
"zero egress *dependencies*", never "no network code".

### Total parser over untrusted bytes, fail-closed on attestation

`Identity::parse` mirrors `phonetool-sip`'s `Response::parse` stance: UTF-8-lossy where it
must be, CRLF/bare-LF tolerant, every structural defect mapped to a typed `ParseError`, no
`unwrap`/`expect`/unchecked index. Crucially, uncertainty about attestation is never resolved
in the caller's favor: an `attest` value that is not exactly `A`/`B`/`C` becomes
`Unknown { raw }`, not a coerced level; an `alg` that is not `ES256` disables verification and
raises a finding rather than trying an alternate algorithm.

### Degenerate = reportable finding, not empty success

Two shapes of "nothing useful" are distinct, deliberately. A call with **no `Identity`
header** and a PASSporT with **no `attest` claim** are *real results* — "this call is
unsigned/gateway" is exactly the intelligence a spoof-hunt wants — so they return
`Ok(Event)` carrying a `Finding`, never a silent empty. Only genuinely empty input (nothing to
inspect) is `PluginError::Empty`. This is the same discipline as sip's "0 responded → Empty",
inverted for a passive reader: here the *absence of a signature is the signal*.

### StructuralOnly is a status, never a disguised pass

In the default (offline) build, and online when a trust anchor is missing or a fetch fails, the
verdict is explicit: `StructuralOnly` (offline) or `Failed { reason }` (online, unverifiable).
The design forbids collapsing an *unverifiable* online result down to `StructuralOnly` — that
would let a call that failed verification read as merely un-checked. A verified-vs-unverified
call must never be ambiguous.

### Offline/online split mirrors numintel exactly

`online` is an off-by-default feature that adds `dep:<crypto>` and `dep:<http>`; the default
`[features]` list is empty. `verify` is `#[cfg(feature = "online")]`. This is a house pattern,
not a new one — a reviewer verifies the offline guarantee with the same `cargo tree -e no-dev`
check the build docs already document.

## Known architectural gap — the trust-anchor provisioning seam

STIR/SHAKEN's online verification is only as meaningful as the **trust anchor** it validates
against: the set of STI-CA roots the STI-PA blesses. This crate has **no offline source of that
anchor** today, and the workbench's whole reason for being is an offline/SHTF handheld. Three
tensions the operator must resolve, stated without silently deciding:

- **Where does the anchor come from on an air-gapped box?** The STI-PA list is a live
  service. Options: (a) a bundled snapshot shipped in the crate/data dir (goes stale, but
  offline); (b) an operator-provisioned anchor file loaded at runtime; (c) online-only anchor
  retrieval (defeats the offline story for verification). This is R6.3's `no trust anchor →
  Failed` behavior made concrete.
- **CRL/OCSP revocation** is inherently online and time-sensitive; an offline verifier cannot
  know a cert was revoked. The spec must state that offline `Verified` means "signature valid
  under a possibly-stale anchor", not "currently trusted".
- The gap is a **prerequisite task**, not a build detail: nail the anchor model before writing
  `verify`, because it determines the module's whole shape. Recommended direction (operator to
  confirm): implement (b) operator-provisioned anchor file *first* (deterministic, offline,
  testable), with (a) bundled-snapshot as an optional convenience — never (c) as the only path.

## Error handling

Two error surfaces at two layers. `ParseError` (`thiserror`) is the `passport`/`sipmsg` layer's
vocabulary (`Empty`/`MalformedToken`/`BadBase64`/`BadJson`/`TooLarge`); a private
`map_parse_error` maps it to `PluginError` (`Empty`/`InvalidInput`). Online verification never
returns a parse-style error to the caller — an `x5u` failure, a bad cert, a missing anchor, or a
signature mismatch all resolve to a `VerificationStatus::Failed { reason }` carried *inside* a
successful `Ok(Event)` (the inspection succeeded; the verification verdict is part of the
result). No panics: the crate compiles under `unsafe_code = forbid` and the workspace
`unwrap_used`/`expect_used`/`indexing_slicing = deny` lints.

**Threat note.** Every input is adversary-controlled. (1) The `Identity` header / PASSporT is
crafted by the caller — oversized headers, deep/huge base64 segments (decompression/alloc
bombs), non-UTF-8, missing/duplicate claims, `alg`-confusion (e.g. `none`, or an RS256 token
hoping a naïve verifier picks the wrong scheme): caps + fail-closed alg handling + total parse
defend each. (2) *(online)* The `x5u` URL is attacker-chosen — an SSRF primitive: https-only,
timeout, byte-cap, and (open question) a host allowlist contain it; the URL is never followed to
a non-https or internal target. (3) *(online)* The fetched certificate bytes are untrusted DER/
PEM — parsed totally, chain-validated, never trusted merely because it was reachable. (4) A
`verstat`/attestation value must never be *upgraded* by the tool: the safe default under any
uncertainty is the lower-trust verdict (`Unknown`/`None`/`Failed`/`StructuralOnly`).

## Testing strategy

- **Parser hostile-input** (`tests/passport_parse.rs`, table-driven, offline): empty,
  whitespace, two-segment token, non-base64url segment, base64url that decodes to non-JSON,
  `alg` = `none`/`RS256`, missing `attest`, `attest` = `"D"`/`""`, oversized header, non-UTF-8
  bytes, CRLF vs bare-LF — each maps to the exact `ParseError` or the exact `Finding`, none
  panic.
- **Attestation classification** (`tests/classify.rs`, offline): A/B/C → Full/Partial/Gateway;
  absent `attest` → `None` + `NoAttestClaim`; unknown value → `Unknown { raw }`.
- **Degenerate discipline** (offline): a SIP message with no `Identity` header → `Ok(Event)`
  with `NoIdentityHeader`; a PASSporT with no `attest` → `Ok(Event)` level `None`; empty input →
  `PluginError::Empty`.
- **Input sourcing** (offline): inline arg, `@file`, and a `CaptureRef { Pcap, path }` all feed
  the same parser and yield the same report for the same header. The live-tap seam is asserted
  only at the type level (a source enum with a not-yet-wired variant) — no hardware required.
- **Online verification** (`tests/verify.rs`, `--features online`, no live network): a locally
  generated P-256 key signs a synthetic PASSporT; the test provisions a matching operator
  trust anchor and asserts `Verified`; a tampered signature asserts `Failed`; a missing anchor
  asserts `Failed { "no trust anchor" }`; a non-https `x5u` asserts refusal before any fetch.
  The fetch itself is stubbed/loopback — the online test never reaches the public internet.
- **Offline guarantee**: a CI check that `cargo tree -e no-dev` on the default graph shows no
  `reqwest` and no crypto/http client (the numintel check, extended to attest).
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]` since the
  no-panic discipline binds library code, not assertions.

## Open questions for operator

1. **Trust-anchor provisioning (the known gap).** Bundled STI-PA snapshot, operator-provisioned
   anchor file, or online-only? Recommended: operator-provisioned file first; do not ship
   online-only as the sole path. **Must be decided before `verify` is built.**
2. **`MAX_IDENTITY` / `MAX_SEGMENT` / `MAX_CERT_BYTES` numeric caps.** RFC 8224/8225 and
   ATIS-1000074 constrain field *shapes* but I cannot state normative byte ceilings with
   confidence — deferred rather than invented. Need a real-world figure for typical SHAKEN
   `Identity` header size and STI cert size before fixing constants.
3. **`x5u` host allowlist vs. https-only + caps.** Is an operator-configured allowlist of STI
   certificate repositories required (R7.3), or do https-only + timeout + byte-cap suffice? SSRF
   exposure argues for an allowlist; offline/SHTF flexibility argues against a hard-coded one.
4. **Pure-Rust ES256 + X.509 crate choice** for the `online` feature that preserves
   `unsafe_code = forbid` and the static-musl build (candidates exist in the RustCrypto family,
   but the exact selection and their transitive `unsafe`/`getrandom` stance must be verified at
   build time, not assumed here).
5. **`dest` claim shape.** RFC 8225 `dest` can be a set of TNs and/or URIs; confirm whether the
   report should normalize multiple destinations or surface them verbatim.
6. **`iat` freshness policy.** Should the offline report flag a stale/future `iat` (replay
   indicator), and against what clock on an air-gapped box with no reliable time? Deferred —
   depends on the handheld's time source.
7. **Diversion / `div` PASSporTs and multiple `Identity` headers.** A forwarded call can carry
   more than one `Identity` header (RFC 8946 `div`). Report all, or only the terminating one?
   Out of scope for v1 unless the operator wants call-diversion attestation now.
