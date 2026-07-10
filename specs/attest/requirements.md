# Requirements Document — phonetool-attest

## Introduction

`phonetool-attest` inspects caller-ID attestation carried by STIR/SHAKEN. Given the
SIP `Identity` header of a call — and the PASSporT (a JWT-shaped token) inside it — it
reports what the call *claims* about its own origin: the attestation level (A / B / C),
the PASSporT claims (`orig`, `dest`, `iat`, `origid`), and a verification verdict in the
`verstat` vocabulary. It is a **Passive**, observation-coded capability: reading what a
call asserts about itself is knowledge/OSINT, not an action against a third party, so it
answers to neither authorization axis and **never touches the gate** (numintel is the
precedent). It implements the passive `Plugin` trait, not `ActivePlugin`.

The dual-use line does not apply here — inspection of a supplied token is purely
receptive. What *does* apply is the threat stance: the `Identity` header and its PASSporT
are **100% adversary-controlled** — a hostile caller crafts them to spoof caller-ID or to
break a naïve parser. Every byte is untrusted; parsing is total (no panic) and fail-closed
(a malformed token is a reported error, never a guessed attestation).

Two modes, split exactly like numintel's `online` feature:

- **Offline (default):** total *structural* inspection of a supplied `Identity` header /
  PASSporT — decode base64url, parse the JOSE header and claims, extract the signature,
  classify the attestation level. No network, no cryptography-of-trust. The default binary
  links **zero egress dependencies**.
- **Online (off-by-default `online` Cargo feature):** additionally fetch the `x5u`
  certificate chain and *cryptographically* verify the ES256 signature, then validate the
  certificate to the STI-PA trust anchor. The `x5u` fetch is egress. It leaks nothing about
  the operator (it retrieves a public certificate the caller named), but it is still a
  network call and an SSRF surface (the URL is attacker-supplied) — so it lives behind the
  feature, never in the core graph.

## Glossary

- **phonetool-attest**: The crate under specification; the passive STIR/SHAKEN
  attestation-inspection plugin.
- **STIR/SHAKEN**: The IETF/ATIS framework for signed caller-ID. STIR = the token/signature
  mechanism (RFC 8224/8225/8226/8588); SHAKEN = the ATIS-1000074 deployment profile over SIP.
- **`Identity` header**: The SIP header (RFC 8224) that carries a PASSporT plus parameters
  (`info` = cert URL, `alg`, `ppt`). The plugin's primary input.
- **PASSporT**: The signed token (RFC 8225), shaped `base64url(JOSE) "." base64url(claims)
  "." base64url(signature)` — JWS compact serialization.
- **JOSE header**: The PASSporT's protected header. For SHAKEN it carries `alg` (`ES256`),
  `typ` (`passport`), `ppt` (`shaken`), and `x5u` (the signing certificate's URL).
- **Claims**: The PASSporT payload. SHAKEN claims: `orig` (originating TN), `dest`
  (destination TN(s)), `iat` (issued-at, seconds), `origid` (origination identifier, a UUID),
  and `attest` (the attestation level).
- **`attest` claim**: The single-character attestation level — `"A"`, `"B"`, or `"C"`.
- **Attestation level**: A = Full (originator authenticated *and* authorized for the TN);
  B = Partial (originator authenticated, TN not verified); C = Gateway (call entered from a
  gateway, originator not authenticated). Definitions per ATIS-1000074.
- **`verstat`**: The verification-status verdict (ATIS-1000074) — one of
  `TN-Validation-Passed`, `TN-Validation-Failed`, `No-TN-Validation`. The plugin's output
  verdict uses this vocabulary.
- **`x5u`**: The HTTPS URL of the signing STI certificate (chain), named in the JOSE header.
- **STI certificate**: The X.509 certificate (RFC 8226) whose private key signed the PASSporT.
- **STI-PA**: Secure Telephone Identity Policy Administrator — the authority that maintains
  the list of trusted STI Certification Authorities (the online trust anchor).
- **Trust anchor**: The set of trusted STI-CA roots the fetched certificate chain must
  validate against. Provisioning it offline is an open architectural question (see below).
- **base64url**: URL-safe base64 without padding (RFC 4648 §5), the PASSporT segment encoding.
- **ES256**: ECDSA over NIST P-256 with SHA-256 — the SHAKEN signature algorithm (the only
  `alg` SHAKEN permits).
- **`AttestReport`**: The structured result — attestation level, claims, verdict,
  verification status, and structural findings. Serialized into the `Event` `data`.
- **`VerificationStatus`**: Whether the signature was cryptographically checked —
  `StructuralOnly` (offline), `Verified`, or `Failed { reason }` (online).
- **`Plugin`**: The passive core trait (`dispatch(&self, cmd) -> Result<Event, PluginError>`);
  attest implements this and never sees a `Grant`.
- **Degenerate finding**: A token that parses but carries no attestation, or a call with no
  `Identity` header at all — a *reportable* result (unsigned / gateway), NOT a silent empty
  success. Truly empty input is `PluginError::Empty`.

## Requirements

### Requirement 1: Passive by construction — no gate, ever

**User Story:** As the operator, I want attestation inspection to carry zero authorization
friction, so that reading what a call asserts about itself stays pure recon ("do not
narc-jump").

#### Acceptance Criteria

1. THE attest plugin SHALL implement the passive `Plugin` trait and SHALL NOT implement
   `ActivePlugin`, so its `dispatch` never receives a `Grant` and never consults the gate.
2. THE attest plugin's manifest SHALL declare transducer `Ip` and capability class `Passive`.
3. THE attest plugin SHALL construct no `Gate`, mint no token, and write no `ConsentRecord`
   for any inspection, in either the offline or the online build.
4. WHEN `dispatch` receives a command whose verb is not `"inspect"`, THE attest plugin SHALL
   return `Err(PluginError::Unsupported)`.

### Requirement 2: Total structural parse of an untrusted Identity header / PASSporT

**User Story:** As a maintainer, I want the parser to survive any input a hostile caller can
craft, because the `Identity` header is adversary-controlled even on a call I merely observe.

#### Acceptance Criteria

1. WHEN `Identity::parse` receives empty or whitespace-only input, THE parser SHALL return
   `Err(ParseError::Empty)`.
2. WHEN the input does not contain a PASSporT of exactly three `.`-separated base64url
   segments, THE parser SHALL return `Err(ParseError::MalformedToken)`.
3. WHEN any PASSporT segment is not valid unpadded base64url, THE parser SHALL return
   `Err(ParseError::BadBase64)` and SHALL NOT panic on invalid bytes or length.
4. WHEN a decoded JOSE-header or claims segment is not valid JSON, THE parser SHALL return
   `Err(ParseError::BadJson)`.
5. WHEN the JOSE header's `alg` is present and is not `"ES256"`, THE parser SHALL record a
   structural finding `UnexpectedAlg` and SHALL NOT attempt any signature verification for
   that token (SHAKEN permits only `ES256`).
6. THE parser SHALL NOT `unwrap`, `expect`, index unchecked, or panic on any input of any
   length (enforced by the workspace deny-lints on library code).
7. THE parser SHALL cap the accepted `Identity` header length at `MAX_IDENTITY` and each
   decoded segment at `MAX_SEGMENT`, returning `Err(ParseError::TooLarge)` rather than
   allocating on a remote-supplied size. _(Numeric caps are an Open Question — see design.)_

### Requirement 3: Report the attestation level and the JOSE/claims contents

**User Story:** As the operator, I want the level, claims, and signing metadata surfaced,
so that I can tell a Full-attested call from a Gateway-attested one and see who signed it.

#### Acceptance Criteria

1. WHEN the `attest` claim is `"A"`, `"B"`, or `"C"`, THE attest plugin SHALL report the
   corresponding attestation level `Full` / `Partial` / `Gateway`.
2. WHEN the `attest` claim is present but is not one of `"A"` / `"B"` / `"C"`, THE attest
   plugin SHALL report attestation level `Unknown { raw }` carrying the verbatim value, and
   SHALL NOT map it to a valid level.
3. THE attest plugin SHALL surface the parsed `orig`, `dest`, `iat`, and `origid` claims and
   the JOSE `x5u`, `alg`, and `ppt` fields in the `AttestReport`, reporting each absent field
   as absent rather than fabricating a default.
4. WHERE the `ppt` field is present and is not `"shaken"`, THE attest plugin SHALL record a
   structural finding `UnexpectedPpt` and still report the remaining parsed contents.

### Requirement 4: Degenerate-case discipline — unsigned / no-attestation is a finding

**User Story:** As the operator, I want "this call is unsigned" and "this token carries no
attestation" reported as real results, so a spoof-prone call is not mistaken for a clean or
empty one.

#### Acceptance Criteria

1. WHEN the supplied input is a well-formed SIP message (or message fragment) that contains
   **no** `Identity` header, THE attest plugin SHALL return `Ok(Event)` reporting the
   `NoIdentityHeader` finding — an unsigned/unattested call is a reportable result, not a
   failure.
2. WHEN the PASSporT parses but carries no `attest` claim, THE attest plugin SHALL return
   `Ok(Event)` with attestation level `None` and the `NoAttestClaim` finding — never a
   silent empty success.
3. WHEN the supplied input is empty or whitespace-only, THE attest plugin SHALL return
   `Err(PluginError::Empty)` (there is nothing to inspect).
4. WHEN the input is non-empty but the parser cannot locate a PASSporT and the input is not a
   recognizable SIP message, THE attest plugin SHALL return `Err(PluginError::InvalidInput)`.

### Requirement 5: Offline-default / online-feature split, with honest egress

**User Story:** As the operator, I want the default build air-gapped and the one network path
opt-in and clearly labelled, so the offline claim is honest and the SSRF surface is contained.

#### Acceptance Criteria

1. THE attest plugin's default build SHALL perform total structural inspection with **zero
   egress dependencies**: `cargo tree -e no-dev` on the default graph SHALL show no `reqwest`
   and no HTTP/TLS client.
2. THE `x5u` certificate fetch and all cryptographic signature/chain verification SHALL be
   compiled only under an off-by-default `online` Cargo feature (mirroring numintel's model).
3. WHERE the crate is built without the `online` feature, THE `AttestReport`'s
   `VerificationStatus` SHALL be exactly `StructuralOnly`, and THE plugin SHALL NOT claim a
   cryptographic pass or fail.
4. THE project documentation SHALL state that the `x5u` fetch leaks nothing about the operator
   (it retrieves a public certificate the caller named) but is nonetheless egress and an
   attacker-influenced request, and is therefore gated behind the feature — NOT described as
   "no network code".

### Requirement 6: Online cryptographic verification (feature = "online")

**User Story:** As the operator, when I opt in, I want the signature actually checked against
a trusted certificate, so an attestation is proof rather than a self-asserted label.

#### Acceptance Criteria

1. WHERE the `online` feature is enabled AND `alg` is `ES256`, THE attest plugin SHALL fetch
   the certificate named by `x5u`, verify the ES256 signature over
   `base64url(JOSE) "." base64url(claims)`, and set `VerificationStatus::Verified` only if the
   signature validates against that certificate's public key.
2. WHEN the fetched certificate chain does not validate to a configured STI-PA trust anchor,
   THE attest plugin SHALL set `VerificationStatus::Failed { reason }` and SHALL NOT report
   `Verified`.
3. WHEN no trust anchor is configured, THE attest plugin SHALL fail closed to
   `VerificationStatus::Failed { reason: "no trust anchor" }` — it SHALL NOT downgrade
   silently to `StructuralOnly` (which would let an unverifiable call read as merely
   un-checked).
4. WHEN the `x5u` fetch fails, times out, or returns more than `MAX_CERT_BYTES`, THE attest
   plugin SHALL set `VerificationStatus::Failed { reason }` — a network failure is never a
   pass, and a remote-supplied size never dictates the allocation.
5. THE online path SHALL treat the fetched certificate bytes as untrusted input: it SHALL
   parse them totally, never panicking on malformed DER/PEM.

### Requirement 7: The x5u fetch is a bounded, validated, attacker-influenced request

**User Story:** As a maintainer, I want the `x5u` fetch hardened, because the URL comes out of
the adversary's token and a naïve fetch is a server-side request forgery primitive.

#### Acceptance Criteria

1. WHEN the `x5u` URL scheme is not `https`, THE online path SHALL refuse the fetch with
   `VerificationStatus::Failed { reason }` before opening any connection.
2. THE online path SHALL apply a fetch timeout and the `MAX_CERT_BYTES` response cap to the
   `x5u` request, so a hostile or slow certificate host cannot hang or exhaust the workbench.
3. WHERE an operator-configured host allowlist for STI certificate repositories is present,
   THE online path SHALL fetch only from an allowed host and refuse otherwise. _(Whether an
   allowlist is required vs. https-only-plus-caps is an Open Question — see design.)_

### Requirement 8: TODAY-vs-device-seam input sourcing

**User Story:** As the operator, I want to inspect attestation with no telecom hardware today,
and to have a live-capture path that snaps in later, so the software leads the gear.

#### Acceptance Criteria

1. THE attest plugin SHALL accept, TODAY with no device, an `Identity` header or full SIP
   message supplied inline in the command `arg`.
2. THE attest plugin SHALL accept a path to a file or a recorded packet capture (pcap)
   referenced as a `CaptureRef { kind: Pcap, path }` on the capture bus, extracting `Identity`
   headers from the SIP messages therein.
3. THE attest plugin SHALL define a live-capture *seam* — a source of `Identity` headers from
   a live `Ip` (or wireline) tap — as a future input that plugs into the same parser without
   changing it, and SHALL NOT require that hardware to exist for the offline path to run.

### Requirement 9: No unsafe, no panics, no RNG, pure-Rust musl-friendly

**User Story:** As a maintainer, I want the crate hardened and dependency-lean, so it preserves
the pure-Rust static-musl offline build and cannot fall over on hostile input.

#### Acceptance Criteria

1. THE crate SHALL compile under `unsafe_code = forbid` and the workspace
   `unwrap_used`/`expect_used`/`indexing_slicing = deny` lints.
2. THE crate SHALL require no `rand`/`getrandom` dependency (attestation *verification* needs
   no randomness; ECDSA verification is deterministic).
3. WHERE the `online` feature pulls a cryptography library, THE crate SHALL prefer a pure-Rust
   implementation so the static-musl build and the `unsafe_code = forbid` stance are
   preserved. _(Exact crate choice is an Open Question — see design.)_
