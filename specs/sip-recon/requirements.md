# Requirements Document — phonetool-sip

## Introduction

`phonetool-sip` is the workbench's first **active** capability: SIP extension
enumeration over UDP. It is the first operation that transmits to a remote, so it
is the first end-to-end exercise of the auth-gate spine — numintel (Sprint 1) is
`Passive` and never touches the gate; SIP always does.

The dual-use line in telecom tooling is defined by **authorization and target
scope, not by code**: the same OPTIONS-probe logic is a pentest tool against a PBX
the operator owns and a toll-fraud recon tool against one they do not. This crate
therefore routes every enumeration through a `Grant` the auth-gate minted, acts
only on the target that grant names, and treats the bytes coming back as untrusted
adversary input. What ships in the default binary is an *inert* active code path —
present, but unreachable without a gate-minted token.

## Glossary

- **phonetool-sip**: The crate under specification; the SIP extension-enumeration
  active plugin.
- **Active operation / Axis A**: An operation that transmits to a remote the
  operator does not own by default; gated on target ownership / authorization.
- **`ActivePlugin`**: The core trait for an active capability. Its
  `dispatch_active(&self, cmd, grant: &Grant)` requires a `Grant`; distinct from
  the passive `Plugin` trait so the passive path carries no gate friction.
- **`Grant`**: The unforgeable Axis-A authorization token (from `phonetool-authgate`).
  Private fields, no public constructor; obtainable only from `Gate::request_ip`.
  Carries the authorized `target` and the operator's `basis`.
- **`SipRecon`**: The `ActivePlugin` implementation. Manifest name `"sip"`,
  transducer `Ip`, capability `ActiveIp`.
- **Extension**: A SIP user part being probed (e.g. `100`, `admin`), forming the
  request URI `sip:<ext>@<host>`.
- **OPTIONS probe**: One SIP `OPTIONS` request/response exchange used to infer
  whether an extension exists.
- **`Verdict`**: The per-extension inference — `Exists` (200/401/407), `Absent`
  (404), or `Ambiguous` (anything else).
- **`Finding`**: The outcome for one probed extension — extension, verdict,
  `responded` flag, status code, server fingerprint.
- **`Response::parse`**: The total parser over an untrusted response datagram.
- **Degenerate result**: A run in which no probe was answered — useless, and
  therefore a failure the operator sees, not an empty success.
- **Always-compiled, gate-only**: The operator's binding build decision — SIP is a
  normal (non-optional) dependency of the CLI and ships in the default binary; the
  only lock is the runtime `Grant`, not an off-by-default Cargo feature.

## Requirements

### Requirement 1: The enumeration is unrepresentable without authorization

**User Story:** As the operator, I want a SIP enumeration to be impossible to
invoke without the gate having authorized it, so that the dual-use line is a
compile-time property, not a reviewer's vigilance.

#### Acceptance Criteria

1. THE sip plugin SHALL implement `ActivePlugin`, whose `dispatch_active` takes a
   `&Grant`, and SHALL NOT expose any path to enumerate that does not take a `Grant`.
2. WHERE a caller attempts to fabricate a `Grant` to reach `dispatch_active`, THE
   crate SHALL make the code fail to compile (a compile-fail doctest proves it).
3. THE sip plugin's manifest SHALL declare capability `ActiveIp` and transducer `Ip`.
4. WHEN `dispatch_active` receives a command whose verb is not `"enum"`, THE sip
   plugin SHALL return `Err(PluginError::Unsupported)`.

### Requirement 2: Target authority lives in the Grant, never the command

**User Story:** As the operator, I want the enumeration to act only on the target
the gate authorized, so that a command argument cannot smuggle in a second,
unchecked target.

#### Acceptance Criteria

1. THE sip plugin SHALL read the target host:port from `Grant::target`, never from
   the command.
2. THE sip plugin SHALL derive the request-URI host from the grant's target (the
   part before the final `:`).
3. THE command's `arg` SHALL carry only the operation's own parameter — the
   comma-separated extension list — and SHALL NOT be interpreted as a target.

### Requirement 3: Boundary validation of the extension list

**User Story:** As the operator, I want the extension list validated before it
becomes part of a wire message, so that operator typos or injection attempts are
rejected rather than sent.

#### Acceptance Criteria

1. WHEN the command arg contains an extension with any character outside
   ASCII-alphanumeric and `.`, `-`, `_`, THE sip plugin SHALL return
   `Err(PluginError::InvalidInput)` before any socket work.
2. THE sip plugin SHALL trim surrounding whitespace on each extension and SHALL
   skip empty entries between commas.
3. WHEN the command arg yields no non-empty extensions, THE sip plugin SHALL return
   `Err(PluginError::InvalidInput)`.

### Requirement 4: The enumeration is bounded

**User Story:** As the operator, I want one authorized op to stay one bounded op,
so that a pathological input or a hostile/slow remote cannot turn it into an
unbounded scan or a hang.

#### Acceptance Criteria

1. THE enumerate layer SHALL refuse an extension list longer than `MAX_EXTENSIONS`
   (4096) with `Err(EnumError::TooMany)`.
2. THE enumerate layer SHALL apply a per-probe socket read timeout, after which an
   unanswered probe is a no-response `Finding`, not a hang.
3. THE enumerate layer SHALL cap the bytes read from any single response at
   `RECV_CAP` (8192), truncating rather than trusting a remote-supplied size.
4. WHEN the target string has no `host:port` shape (no `:`), THE enumerate layer
   SHALL return `Err(EnumError::BadTarget)` before binding a socket.
5. WHEN the extension list is empty at the enumerate layer, THE enumerate layer
   SHALL return `Err(EnumError::NoExtensions)`.

### Requirement 5: The response parser is total over untrusted bytes

**User Story:** As a maintainer, I want the response parser to never panic on any
input, because the bytes on the wire are adversary-controlled even under an
authorized gate (a honeypot, a hostile PBX, a spoofed source).

#### Acceptance Criteria

1. WHEN `Response::parse` receives empty or whitespace-only bytes, THE parser SHALL
   return `Err(ParseError::Empty)`.
2. WHEN the first line is not a `SIP/<version> <code> [reason]` status line, THE
   parser SHALL return `Err(ParseError::BadStatusLine)`.
3. WHEN the status token is not exactly three ASCII digits, THE parser SHALL return
   `Err(ParseError::BadStatusCode)`.
4. THE parser SHALL handle non-UTF-8 input lossily and SHALL tolerate both CRLF and
   bare-LF line endings.
5. THE parser SHALL NOT panic, `unwrap`, `expect`, or index unchecked on any input,
   for any length (enforced by the workspace deny-lints on library code).
6. THE `classify` function SHALL map 200/401/407 → `Exists`, 404 → `Absent`, and
   every other status → `Ambiguous`.

### Requirement 6: Per-probe resilience and degenerate-case discipline

**User Story:** As the operator, I want one dead extension to never abort the run,
and a run that learned nothing to be reported as a failure, so that a
technically-correct-but-useless probe is not mistaken for a clean result.

#### Acceptance Criteria

1. WHEN a single probe times out or hits a transport error, THE enumerate layer
   SHALL record a `Finding { responded: false }` and continue with the next
   extension, never aborting the run.
2. WHEN a probe receives bytes that do not parse as a SIP response, THE enumerate
   layer SHALL record `responded: true` with no verdict (it will not guess).
3. WHEN no probe in a run was answered, THE sip plugin SHALL return
   `Err(PluginError::Empty)`.
4. WHEN at least one probe was answered, THE sip plugin SHALL return `Ok(Event)` —
   "these extensions are absent" is itself a real, reportable result.

### Requirement 7: Always-compiled, gate-only, with an honest offline story

**User Story:** As the operator, I want SIP to ship in the default binary with the
gate as its only lock, and I want the offline claim stated honestly, so the
capability is present as a continuity mechanism without over-claiming air-gap.

#### Acceptance Criteria

1. THE sip plugin SHALL be a normal (non-optional) dependency of the CLI and SHALL
   ship in the default binary; the only runtime lock SHALL be the `Grant`.
2. THE sip plugin SHALL use `std::net` only and SHALL add zero egress dependencies:
   `cargo tree -e no-dev` on the default graph SHALL show no `reqwest`.
3. THE project documentation SHALL state the offline guarantee as "zero egress
   *dependencies*", NOT as "no active code" — the default binary contains an inert
   active code path, present but unreachable without a `Grant`.

### Requirement 8: No unsafe, no panics, no RNG dependency

**User Story:** As a maintainer, I want the crate hardened and dependency-lean, so
it preserves the pure-Rust static-musl offline build and cannot fall over on
hostile input.

#### Acceptance Criteria

1. THE crate SHALL compile under `unsafe_code = forbid` and the workspace
   `unwrap_used`/`expect_used`/`indexing_slicing = deny` lints.
2. THE crate SHALL derive per-transaction SIP identifiers (branch/tag/call-id)
   without an RNG dependency (FNV-1a over grant fields), so it adds no
   `rand`/`getrandom` dependency and keeps the static-musl build pure-Rust.
