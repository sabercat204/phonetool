# Requirements Document — phonetool-authgate

## Introduction

`phonetool-authgate` is the compile-time spine of the phonetool workbench. phonetool
is dual-use: in voice-telecom tooling the legal/illegal line is defined by
**authorization and target scope, not by code** — the same SIP-enumeration logic is a
pentest tool against infrastructure the operator owns and a toll-fraud tool against one
they do not. This crate makes that line a property of the type system rather than a
runtime convention or a reviewer's vigilance: an active operation is *unrepresentable*
without an unforgeable token that only the gate can mint, and the gate is **fail-closed**
(absence of authorization is a refusal, never a default-allow).

The crate models two orthogonal authorization axes because active operations answer to
two different authorities — a cyber authority (target ownership) and a regulatory
authority (spectrum license). Passive operations (observation, RX, knowledge lookup)
answer to neither and route around the gate entirely, by construction, so the recon path
carries zero authorization friction. Every gate decision — grant and refusal alike — is
recorded through an injected consent log.

## Glossary

- **phonetool-authgate**: The crate under specification; the type-state authorization gate.
- **Axis A / cyber axis**: Target-ownership / authorization for active IP operations (SIP
  enumeration, wardial origination, signalling injection against a remote).
- **Axis B / regulatory axis**: Band / power / license authority for RF transmission.
  Illegal transmission is an FCC/ISED regulatory offense, a *distinct wrong* from
  cybercrime, so it carries a distinct token.
- **Passive**: Observation / RX / knowledge. On neither axis; never touches the gate.
- **`Capability`**: The payload-carrying label of an operation's authorization class —
  `Passive`, `ActiveIp { target }`, or `RfTx { band, power_dbm, license_basis }`. Used for
  logging and display; it is *not* the enforcement mechanism.
- **`Grant`**: The unforgeable Axis-A token. Private fields, no public constructor;
  obtainable only from `Gate::request_ip`. Holding `&Grant` proves an IP active op is
  authorized.
- **`TxGrant`**: The unforgeable Axis-B token, obtainable only from `Gate::request_tx`. A
  distinct type from `Grant` so a cyber authorization can never stand in for a transmit
  license and vice versa.
- **`IpAuthorization`**: Operator-supplied evidence for an Axis-A op — `target` +
  `basis` (free-text assertion of why this is authorized).
- **`TxAuthorization`**: Operator-supplied evidence for an Axis-B op — `band` +
  `power_dbm` + `license_basis`.
- **`Gate`**: The gate instance. Borrows a `ConsentLog`; every `request_*` records its
  decision before returning.
- **`Denied`**: The refusal reason — `NoTarget`, `NoBasis`, or `Invalid(String)`.
- **`ConsentLog`**: The sink trait the gate depends on. Infallible by contract. Implemented
  by the shell's capture bus; `NullConsentLog` discards for tests and the passive path.
- **`ConsentRecord`**: One immutable decision record — capability, decision, verbatim basis.
- **`Decision`**: `Granted` or `Refused { reason }`.
- **Fail-closed**: Absent or malformed authorization yields a refusal, never a token.
- **Operator**: The human invoking phonetool.

## Requirements

### Requirement 1: Unforgeable authorization tokens

**User Story:** As the operator, I want active-operation tokens that cannot be fabricated
in code, so that an unauthorized active op is a compile error rather than a bug caught
(or missed) in review.

#### Acceptance Criteria

1. WHERE a `Grant` or `TxGrant` is constructed outside this crate, THE authgate SHALL make
   the code fail to compile (private fields, no public constructor).
2. THE authgate SHALL provide no way to obtain a `Grant` other than a successful
   `Gate::request_ip`, and no way to obtain a `TxGrant` other than a successful
   `Gate::request_tx`.
3. THE authgate SHALL make `Grant` and `TxGrant` distinct, non-interchangeable types, so
   that an Axis-A token cannot satisfy an Axis-B parameter or vice versa.
4. THE authgate SHALL NOT implement `Clone` or `Copy` for `Grant` or `TxGrant`, so a token
   is minted per authorized operation rather than stamped and reused.

### Requirement 2: Fail-closed Axis-A (IP) authorization

**User Story:** As the operator, I want an IP active op refused unless I supply a target
and a stated basis, so that authorization is affirmative evidence, never a default.

#### Acceptance Criteria

1. WHEN `request_ip` receives an `IpAuthorization` whose `target` is empty or whitespace-only,
   THE authgate SHALL return `Err(Denied::NoTarget)`.
2. WHEN `request_ip` receives an `IpAuthorization` whose `basis` is empty or whitespace-only,
   THE authgate SHALL return `Err(Denied::NoBasis)`.
3. WHEN `request_ip` receives a well-formed `IpAuthorization` (non-empty target and basis),
   THE authgate SHALL return `Ok(Grant)` carrying that target and basis.
4. THE authgate SHALL evaluate the target before the basis, so the reported refusal reason
   is deterministic.

### Requirement 3: Fail-closed Axis-B (RF TX) authorization

**User Story:** As the operator, I want an RF transmission refused unless I supply a band,
a finite power, and a license basis, so that regulatory authority is affirmative and a
malformed power value cannot slip through.

#### Acceptance Criteria

1. WHEN `request_tx` receives a `TxAuthorization` whose `band` is empty or whitespace-only,
   THE authgate SHALL return `Err(Denied::NoTarget)`.
2. WHEN `request_tx` receives a `TxAuthorization` whose `license_basis` is empty or
   whitespace-only, THE authgate SHALL return `Err(Denied::NoBasis)`.
3. WHEN `request_tx` receives a `TxAuthorization` whose `power_dbm` is not finite (NaN or
   ±∞), THE authgate SHALL return `Err(Denied::Invalid)`.
4. WHEN `request_tx` receives a well-formed `TxAuthorization`, THE authgate SHALL return
   `Ok(TxGrant)` carrying the band, power, and license basis.

### Requirement 4: Every decision is logged

**User Story:** As the operator, I want every grant and every refusal appended to the
consent log, so that an attempt to run an active op without authorization leaves a trace
rather than vanishing.

#### Acceptance Criteria

1. WHEN `request_ip` or `request_tx` returns — whether `Ok` or `Err` — THE authgate SHALL
   have recorded exactly one `ConsentRecord` to the injected `ConsentLog` before returning.
2. WHEN the decision is a grant, THE authgate SHALL record `Decision::Granted`.
3. WHEN the decision is a refusal, THE authgate SHALL record `Decision::Refused { reason }`
   with the human-facing cause.
4. THE authgate SHALL record the operator's stated basis (`basis` / `license_basis`)
   verbatim in the record.
5. THE `ConsentLog` contract SHALL be infallible: a logging failure SHALL NOT become a
   reason to let an unlogged active op proceed, nor to abort one already authorized.

### Requirement 5: The passive path carries no friction

**User Story:** As the operator, I want observation/knowledge work to never touch the gate,
so that defensive and recon work carries no authorization theater ("do not narc-jump").

#### Acceptance Criteria

1. THE authgate SHALL define `Capability::Passive` as a class that neither `request_*`
   method mints a token for.
2. THE authgate SHALL require no gate construction, no token, and no consent record for a
   passive operation.
3. THE authgate SHALL provide `NullConsentLog` so a passive-only or test context can
   satisfy the sink type without a durable log.

### Requirement 6: No upward dependencies, no unsafe, no panics

**User Story:** As a maintainer, I want the spine to stay minimal and hardened, so it
cannot be compromised by shell churn or by hostile input.

#### Acceptance Criteria

1. THE authgate SHALL depend only on a small `ConsentLog` interface it defines, not on
   `phonetool-core` or the shell (no upward dependency).
2. THE authgate SHALL compile under `unsafe_code = forbid`.
3. THE authgate SHALL contain no `unwrap`/`expect`/indexing that can panic on any input
   (workspace deny-lints).
