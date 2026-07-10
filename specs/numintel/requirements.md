# Requirements Document — phonetool-numintel

## Introduction

`phonetool-numintel` is phonetool's first plugin and the proof that the plugin socket works
end-to-end. Given a phone number, it returns what is known about it (carrier, line type,
region). It exists in Sprint 1 to demonstrate that a capability snaps into the shell, not to
be complete.

numintel is **passive by construction**. Number intelligence is observation/knowledge-coded
— clean under the operator's model (ingestion ≠ theft) — so it declares
`CapabilityClass::Passive` and is handed no gate. It *cannot* perform an active operation
because it is never given a `Grant`: the recon path carries zero authorization friction by
design.

Offline is the default. The plugin reads the shared intel store and makes no network call.
The one non-air-gapped path — a live provider lookup — is behind the off-by-default `online`
Cargo feature; the default build cannot make that call at all.

## Glossary

- **phonetool-numintel**: The crate/plugin under specification.
- **`NumIntel`**: The plugin type; holds an `Arc<dyn IntelStore>` handle to the shared cache.
- **`Number`**: A validated E.164 number. The only constructor is `Number::parse`; downstream
  code (cache key, URL construction) can trust its shape.
- **E.164**: The number canonical form — leading `+`, 1–15 digits, nothing else.
- **`NumberError`**: Boundary-validation refusal — `Empty` / `IllegalChar` / `BadLength`.
- **`NAMESPACE`**: The intel-store namespace for numintel entries (`"numintel"`).
- **Cache hit / miss**: A `(NAMESPACE, e164)` key present / absent in the `IntelStore`.
- **`online` feature**: Off-by-default Cargo feature enabling a live `reqwest`(rustls)
  provider lookup that write-throughs the cache.
- **`OnlineError`**: Online-path failure — `Transport` / `Status(u16)` / `Cache`. Compiled
  only under `online`.
- **Off-box leak**: An online lookup transmits the target number to a third-party provider,
  who learns who the operator is investigating and may retain/resell the query.
- **Operator**: The human invoking phonetool.

## Requirements

### Requirement 1: Passive, ungated

**User Story:** As the operator, I want number intelligence to run with zero authorization
friction, so defensive/recon work is never gated.

#### Acceptance Criteria

1. THE numintel manifest SHALL declare `CapabilityClass::Passive` and `Transducer::Ip`.
2. THE numintel plugin SHALL perform its operation without constructing a `Gate`, without
   requesting a `Grant`/`TxGrant`, and without emitting a consent record.
3. THE numintel plugin SHALL be constructible and runnable given only an `Arc<dyn IntelStore>`.

### Requirement 2: Input boundary validation (E.164)

**User Story:** As a security-conscious maintainer, I want the untrusted number constrained
to canonical E.164 before it can reach a cache key or (under `online`) a URL, so malformed
or injection-shaped input is rejected at the boundary.

#### Acceptance Criteria

1. WHEN `Number::parse` receives empty or whitespace-only input, THE numintel SHALL return
   `Err(NumberError::Empty)`.
2. WHEN the input contains any character other than digits, a leading `+`, or the accepted
   human separators (space, `-`, `.`, `(`, `)`), THE numintel SHALL return
   `Err(NumberError::IllegalChar)`.
3. WHEN a `+` appears anywhere other than position 0, THE numintel SHALL return
   `Err(NumberError::IllegalChar)`.
4. WHEN the digit count (after stripping separators and an optional leading `+`) is 0 or
   greater than 15, THE numintel SHALL return `Err(NumberError::BadLength)`.
5. WHEN the input is well-formed, THE numintel SHALL strip human separators and return a
   canonical `+`-prefixed E.164 string.
6. THE `Number::parse` SHALL NOT guess a country code: a bare national number normalizes
   with only a leading `+` (e.g. `(512) 555-0100` → `+5125550100`). Callers must supply
   international form. (This behavior is intentional and documented.)

### Requirement 3: Offline cache lookup (default path)

**User Story:** As the operator on an air-gapped SBC, I want a lookup served from the local
store with no network call.

#### Acceptance Criteria

1. WHEN `dispatch` receives a verb other than `"lookup"`, THE numintel SHALL return
   `Err(PluginError::Unsupported)`.
2. WHEN `dispatch` receives `"lookup"` with a valid number, THE numintel SHALL read the
   `(NAMESPACE, e164)` key from the `IntelStore` and make no network call.
3. WHEN the number fails boundary validation, THE numintel SHALL return
   `Err(PluginError::InvalidInput)`.
4. WHEN the store backend fails, THE numintel SHALL return `Err(PluginError::Backend)`.
5. WHEN a cached record exists, THE numintel SHALL return an `Event` whose `data` is the
   record parsed as JSON, or the raw string wrapped as a JSON string if it does not parse.

### Requirement 4: A cache miss is a failure, not an empty success

**User Story:** As the operator, I want "found nothing" to be a nonzero-exit failure, so a
technically-correct-but-useless result never reads as OK (degenerate-case discipline).

#### Acceptance Criteria

1. WHEN the offline cache has no record for a valid number, THE numintel SHALL return
   `Err(PluginError::Empty)`, not an empty-but-successful `Event`.
2. THE `Empty` error message SHALL name the E.164 number and note that `online` can query a
   provider.

### Requirement 5: Online path is opt-in and opsec-aware

**User Story:** As the operator, I want any off-box lookup to be off by default, provider-
agnostic, and to leak the number at most once, so my investigative footprint is minimized.

#### Acceptance Criteria

1. THE online lookup SHALL exist only under the `online` Cargo feature; the default build
   SHALL NOT link `reqwest` or make any network call.
2. THE online path SHALL NOT hardcode a provider — the `endpoint` (a URL template containing
   `{number}`) is supplied at call time so a no-retain/no-resell source can be chosen.
3. WHEN an online lookup succeeds, THE numintel SHALL write the result through to the cache
   under `(NAMESPACE, e164)`, so the number leaks off-box at most once.
4. WHEN the transport fails, THE numintel SHALL return `Err(OnlineError::Transport)`; on a
   non-success HTTP status, `Err(OnlineError::Status(code))`; on a cache-write failure,
   `Err(OnlineError::Cache)`.
5. THE `{number}` substituted into the URL SHALL be the already-validated E.164 string, so
   it cannot carry characters that reshape the URL.

### Requirement 6: Hardened

#### Acceptance Criteria

1. THE numintel SHALL compile under `unsafe_code = forbid` and the workspace no-panic
   deny-lints, in both default and `--features online` configurations.
