# Tasks — phonetool-sip

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

- [x] 1. Registry prerequisite: fix `is_exclusive` so `Ip` is a shareable kernel
  net stack (only `Wireline`/`RfRx`/`RfTx` are exclusive physical ports); a second
  `Ip` plugin (SIP) no longer collides with numintel at registration.
  Test `ip_transducer_is_shareable`.
  _(enables Req 1.3)_
- [x] 2. `ActivePlugin` trait in `phonetool-core` (`plugin.rs`):
  `dispatch_active(&self, cmd, grant: &Grant) -> Result<Event, PluginError>`.
  Registry gains `register_active` + `dispatch_active`, sharing one name namespace
  and transducer index with the passive path via a private `claim()` helper;
  `registry.plugins()` → `manifests()` spans both maps.
  _(Req 1.1, 2.1)_
- [x] 3. `message` module: pure `OptionsRequest::to_wire`; total `Response::parse`
  over untrusted bytes (UTF-8-lossy, CRLF/bare-LF, every malformed input →
  `ParseError`, no panic/no unchecked index); `Verdict` + `classify`.
  _(Req 5)_
- [x] 4. `enumerate` module: `run` does one UDP OPTIONS per extension via
  `std::net::UdpSocket` with per-probe read timeout; timeout/transport-err =
  `Finding { responded: false }`, never aborts. Bounds: `RECV_CAP = 8192`,
  `MAX_EXTENSIONS = 4096`, empty/oversize/bad-target refused. `EnumConfig` with a
  test-friendly `Default`.
  _(Req 4, 6.1, 6.2)_
- [x] 5. `lib` (`SipRecon`) implements `ActivePlugin`: verb guard → target from
  grant → `parse_extensions` (boundary char-validation) → RNG-free `short_session`
  (FNV-1a) → `enumerate::run`. Degenerate discipline: 0 responded → `Empty`; ≥1 →
  `Ok(Event)`. `with_config` ctor for tests.
  _(Req 1.4, 2, 3, 6.3, 6.4, 8.2)_
- [x] 6. CLI wired: `sip enum <target> <extensions> --basis <why>` → one
  `CaptureBus` → `Gate::request_ip` (fail-closed on empty basis, logs decision) →
  on `Grant`, `registry.dispatch_active("sip", &cmd, &grant)` → record `Event`.
  numintel events also recorded to the bus.
  _(Req 1.1, 2.3, 7.1)_
- [x] 7. Manual end-to-end verify against the real binary: `plugins` lists
  `sip [Ip/ActiveIp]`; empty `--basis ""` → gate refusal, exit 1; valid basis, no
  listener → `Empty` degenerate failure, exit 1. **All three confirmed.**
  _(Req 6.3, 7.1)_
- [x] 8. Compile-fail doctest on `SipRecon`: fabricating a `Grant` to reach
  `dispatch_active` does not compile.
  _(Req 1.2)_
- [x] 9. Tests (`tests/active_enum.rs`, `tests/message_parse.rs`): loopback-responder
  end-to-end via a real minted grant (verdicts, status, fingerprint); gate refusal
  recorded on the production `CaptureBus`; table-driven parser hostile-input; verdict
  classification. Plus the active-path degenerate-case discipline: no-listener →
  `Empty` (with the grant still logged), illegal-extension boundary rejection,
  unsupported verb, empty extension list. **11 tests pass** (6 e2e + 4 parser + 1 doctest).
  _(Req 1, 5, 6)_
- [x] 10. Compile clean under `unsafe_code = forbid` + workspace deny-lints;
  `clippy --all-targets` clean; `fmt` clean. Cross-compile unchanged (SIP adds no
  deps; `cargo tree -e no-dev` shows zero reqwest).
  _(Req 7.2, 8.1)_
- [x] 11. Docs + version: `specs/sip-recon/` triple; VERSION + `[workspace.package]`
  bumped `0.2.0` → `0.3.0`; STATE.md updated with the honest offline
  caveat (default binary has an inert active path; "air-gapped" = zero egress deps).
  _(Req 7.3)_

## Deferred (post-Sprint 2)

- SIP extension **wordlists** / REGISTER-brute — a deliberate NON-goal for now:
  more intrusive, needs heavier gate justification. Revisit with the operator.
- Grant scope narrowing (per-time-window / rate-limited tokens) — the token today
  authorizes the operation it was minted for.
- TCP/TLS SIP transport — UDP only for now.
