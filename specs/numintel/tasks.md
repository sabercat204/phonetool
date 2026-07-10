# Tasks — phonetool-numintel

Status legend: `[x]` done · `[ ]` not started · `[~]` in progress.

- [x] 1. `number` module: `Number` newtype (private field), `Number::parse` (trim, single
  char-walk, leading-`+`-only, separator strip, 1–15 digit bound, `+{digits}` output),
  `as_e164`, `NumberError` (`Empty`/`IllegalChar`/`BadLength`). No country-code inference.
  _(Req 2)_
- [x] 2. `lookup` module: `NAMESPACE`, `cached()` (offline, no network).
  _(Req 3)_
- [x] 3. `lookup` module: `online()` + `OnlineError`, both `#[cfg(feature = "online")]`;
  `{number}`→E.164 URL template, status check, write-through cache. `online` feature
  off by default in `Cargo.toml`.
  _(Req 5)_
- [x] 4. `NumIntel` + `Plugin` impl: manifest (`Passive`, `Ip`), `dispatch` (verb guard →
  parse → cached → miss=`Empty` → JSON-or-string `Event`).
  _(Req 1, 3, 4)_
- [x] 5. Degenerate-case tests (`tests/degenerate_cases.rs`): empty/illegal/bad-length,
  valid+human normalization, miss=`Empty`, unsupported verb, hit=`Event`. **8 tests pass.**
  _(Req 2, 3, 4)_
- [x] 6. Compile clean default AND `--features online`; clippy clean both; verify no
  `reqwest` in default `cargo tree -e no-dev`.
  _(Req 5, 6)_

## Deferred (operator-decided, not Sprint 1)

- Provider selection: ship cache-only; when enabling `online`, prefer a no-retain/no-resell
  provider. Never hardcode one into the crate.
- Richer intelligence fields (line type, ported-number history, STIR/SHAKEN attestation)
  once a concrete provider and schema are chosen.
- An `async` online path if batch lookups warrant it (blocking `reqwest` suffices at
  Sprint-1 single-lookup volume).
