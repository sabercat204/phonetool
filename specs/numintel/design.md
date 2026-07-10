# Design Document — phonetool-numintel

## Overview

`phonetool-numintel` is the first `Plugin` and the end-to-end proof of the socket. It holds
a shared `Arc<dyn IntelStore>` and answers a `"lookup"` command by validating the number to
canonical E.164, reading the offline cache, and returning an `Event` — or failing with a
typed `PluginError`. It is passive by construction: it declares `CapabilityClass::Passive`,
is never handed a gate, and therefore cannot perform an active operation. The single
non-air-gapped path (a live provider lookup) is quarantined behind the off-by-default
`online` feature.

## Architecture

```
   Command{verb,arg}
        │
        ▼
   verb == "lookup"? ── no ──► Err(Unsupported)
        │ yes
        ▼
   Number::parse(arg)  ── invalid ──► Err(InvalidInput)      [boundary: untrusted → E.164]
        │ ok (+digits)
        ▼
   lookup::cached(store, &number)  ── backend err ──► Err(Backend)
        │
   ┌────┴─────┐
 miss        hit
   │           │
   ▼           ▼
Err(Empty)   Event{ source:"numintel", summary, data: json(record) }

   [online feature only]
   lookup::online(store, &number, endpoint)
        replace {number} → validated E.164
        GET → status? → body → write-through cache → Ok(body)
```

## Modules

- **`number`** — `Number` (newtype over `String`, private field), `Number::parse`,
  `as_e164`, `NumberError`. The input boundary.
- **`lookup`** — `NAMESPACE`, `cached()` (always compiled, never touches the network),
  `online()` + `OnlineError` (both `#[cfg(feature = "online")]`).
- **`lib`** — `NumIntel`, its `Plugin` impl (`manifest` + `dispatch`).

## Design decisions

### E.164 newtype as the trust boundary

`Number` can only be built via `parse`, so any code holding a `Number` can trust its shape.
`parse` trims, walks characters once (digits kept; leading `+` allowed only at index 0;
space/`-`/`.`/`(`/`)` stripped; anything else → `IllegalChar`), enforces 1–15 digits, and
emits `+{digits}`. This is the tightest useful constraint and matters most under `online`,
where the number becomes part of an outbound URL — validating first means it cannot carry
URL-reshaping characters.

**No country-code inference.** A bare national number normalizes with only a leading `+`
(`(512) 555-0100` → `+5125550100`), *not* a guessed region. The parser refuses to invent a
country code; callers must supply international form. This is intentional and documented; a
test that assumed otherwise was a test bug (caught and fixed in Sprint 1).

### Miss is `Empty`, not `Ok(None)`

`dispatch` treats a cache miss as `PluginError::Empty`, naming the number and pointing at
`online`. A "found nothing" result is a failure surfaced to the operator (nonzero CLI exit),
never a silent success — the degenerate-case discipline.

### Record parsed leniently

A cached record is parsed as JSON; if it does not parse, it is wrapped as a JSON string
rather than failing. Seed data may be plain text; the plugin still returns a usable `Event`.

### Online is a feature, provider supplied at call time

`online()` compiles only under the `online` feature — the default build cannot link
`reqwest` or reach the network (verified via `cargo tree -e no-dev`). The provider is never
hardcoded: `endpoint` is a `{number}`-templated URL passed in, so a no-retain/no-resell
source is chosen per deployment. A success write-throughs to the cache so the number leaks
off-box at most once. rustls (not native-tls) is used, and it cross-compiles clean for
`aarch64-unknown-linux-musl` (verified in Sprint 1).

## Threat model

The number reaching the plugin is untrusted input. Under `online` it becomes an outbound URL
and is transmitted to a third party who learns the operator's target and may retain/resell
it. Mitigations: (1) boundary-validate to E.164 before the number can touch a URL or key;
(2) online is off by default — the shipped/default build is incapable of the call;
(3) no hardcoded provider; (4) write-through caps the off-box leak at one query.

## Error handling

`NumberError` (boundary), `PluginError` (via the trait), `OnlineError` (online only) — all
`thiserror`, no panics. The JSON re-parse of a cached record uses `unwrap_or_else` to a
string fallback, never an unwrap-panic. Compiles clean under both feature configs and the
no-panic deny-lints.

## Testing strategy

`tests/degenerate_cases.rs` (8 tests): empty/illegal-char/bad-length rejected; valid number
normalizes; human-formatted number normalizes to the same E.164 key as its canonical form;
cache miss → `Empty`; unsupported verb → `Unsupported`; cache hit → `Event`. The passive/
no-gate property is covered by the plugin never being handed a gate (structural) plus the
`plugins` end-to-end listing.
