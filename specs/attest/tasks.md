# Tasks — phonetool-attest

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

> **BUILT IN SPRINT 11 (0.11.0): the offline structural path.** Tasks 1–6, 8, and
> the offline halves of 9–11 are `[x]`. Tasks 0 and 7 (the online `verify` module)
> remain `[ ]` — BLOCKED on operator Open Questions 1/3/4 (trust-anchor model,
> x5u allowlist, pure-Rust crypto crate). Do not build `verify` until those land.

- [ ] 0. **Prerequisite (blocks task 7): resolve the trust-anchor provisioning model.**
  Decide bundled-snapshot vs. operator-provisioned file vs. online-only (design "Known
  architectural gap" + Open Question 1). Define the `TrustAnchor` type and its load path, and
  state in docs that offline `Verified` is "valid under a possibly-stale anchor, no revocation
  check". Do NOT build `verify` until this is fixed.
  _(Req 6.2, 6.3)_
- [x] 1. Crate scaffold `phonetool-numintel`-shaped: `phonetool-attest` depending on
  `phonetool-core`, `serde`, `serde_json`, `thiserror`; `[features] default = []`,
  `online = ["dep:reqwest", "dep:<crypto>", "dep:<x509>"]`; workspace lints; manifest
  transducer `Ip`, capability `Passive`.
  _(Req 1.2, 5.1, 5.2, 9.1)_
- [x] 2. `passport` module: total `Identity::parse` over untrusted bytes — three-segment split,
  unpadded-base64url decode, JSON parse of JOSE + claims; `MAX_IDENTITY`/`MAX_SEGMENT` caps;
  every malformed input → typed `ParseError`, no panic/no unchecked index; CRLF/bare-LF and
  non-UTF-8 tolerant.
  _(Req 2)_
- [x] 3. `passport` classification: `attest` A/B/C → `Full`/`Partial`/`Gateway`; other value →
  `Unknown { raw }`; absent → `None`; `alg`≠`ES256` → `UnexpectedAlg` finding (no verify);
  `ppt`≠`"shaken"` → `UnexpectedPpt` finding; surface `orig`/`dest`/`iat`/`origid`/`x5u`
  absent-as-absent.
  _(Req 3)_
- [x] 4. `sipmsg` module: total, minimal `Identity`-header extractor from a SIP message/fragment
  (ASCII-case-insensitive header match, CRLF/bare-LF, line folding); locates zero, one, or many
  `Identity` headers without parsing the full SIP grammar; no panic/no unchecked index.
  _(Req 4.1, 8.1)_
- [x] 5. `lib` (`AttestInspect`) implements the passive `Plugin` trait: verb guard (`"inspect"`
  → run, else `Unsupported`); assemble `AttestReport`; degenerate discipline — no `Identity` →
  `Ok(Event, NoIdentityHeader)`, no `attest` → `Ok(Event, None, NoAttestClaim)`, empty input →
  `PluginError::Empty`, unrecognizable non-empty → `InvalidInput`. NO `ActivePlugin`, no gate.
  _(Req 1.1, 1.3, 1.4, 4)_
- [~] 6. Input sourcing: inline arg (TODAY, no device) and `@file` DONE; the live-tap `Source`
  enum variant is defined as an unwired seam (no hardware required). **NOT done:** the
  `CaptureRef { Pcap, path }` bus source — needs a pcap parser (not yet built anywhere in the
  workbench); deferred with the capture/RF hardware layer alongside the live tap.
  _(Req 8)_
- [ ] 7. `verify` module *(feature = "online")*: `x5u` fetch (https-only, timeout,
  `MAX_CERT_BYTES` cap, optional host allowlist); total DER/PEM parse of untrusted cert bytes;
  ES256 signature verify over `jose"."claims`; chain validation to the trust anchor from task 0;
  `VerificationStatus::Verified`/`Failed { reason }`; missing-anchor and fetch-fail → `Failed`,
  never a silent downgrade to `StructuralOnly`. **Blocked on task 0.**
  _(Req 6, 7)_
- [x] 8. Register `attest` in the CLI/registry alongside numintel (passive path; shares the `Ip`
  transducer, which is shareable); `attest inspect <...>` records the `Event` to the
  `CaptureBus`; NO gate call on this path.
  _(Req 1.1, 1.3)_
- [~] 9. Tests: table-driven parser hostile-input (`tests/passport_parse.rs`); attestation
  classification (`tests/classify.rs`); degenerate discipline; input-sourcing equivalence; online
  verification with a locally-signed synthetic PASSporT + operator anchor, tamper→`Failed`,
  missing-anchor→`Failed`, non-https `x5u`→refusal (`tests/verify.rs`, `--features online`,
  loopback/stubbed — never hits the public internet).
  _(Req 2, 3, 4, 6, 7)_
- [~] 10. Offline-guarantee CI check: `cargo tree -e no-dev` on the default graph shows no
  `reqwest` and no crypto/http client; compile clean under `unsafe_code = forbid` +
  workspace deny-lints; `clippy --all-targets` and `--features online --all-targets` clean;
  `fmt` clean; cross-compile to `aarch64-unknown-linux-musl` unchanged for the default build.
  _(Req 5.1, 9.1, 9.3)_
- [~] 11. Docs + version: `specs/attest/` triple; bump `VERSION` + `[workspace.package]`
  together; STATE.md notes the honest egress caveat (default binary has zero egress
  deps; the `online` `x5u` fetch leaks nothing about the operator but is still network + an
  attacker-influenced request behind the feature).
  _(Req 5.3, 5.4)_

## Deferred

- **Diversion attestation** (`div` PASSporTs, RFC 8946) and multiple-`Identity`-header calls —
  report only the terminating attestation for v1 unless the operator wants call-forwarding
  attestation now (Open Question 7).
- **`iat` freshness / replay flagging** — needs a reliable clock the air-gapped handheld may not
  have; deferred pending the time-source decision (Open Question 6).
- **CRL/OCSP revocation checking** — inherently online and time-sensitive; offline `Verified`
  means "signature valid under a possibly-stale anchor", never "currently un-revoked".
- **Live-capture input** (SIP `Identity` headers off a live `Ip`/wireline tap) — the parser and
  `Source` seam are built now; the tap itself lands with the capture/RF hardware layers.
- **Tier-B verification offload** — if a future polyglot crypto/telecom stack is easier
  out-of-process, it proxies the same passive `Plugin` trait per
  `specs/subprocess-ipc-contract/`; the offline/structural path stays native Tier-A.
- **Emitting a `verstat` back into a SIP flow** — attest only *reads*; producing/signing an
  `Identity` header (an active, likely gated origination behavior) is explicitly out of scope.
