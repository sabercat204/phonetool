# Design Document — phonetool-rf-tx

> **DESIGN-ONLY. NOT BUILT IN SPRINT 3.** Fixes the transmit-path contract, the
> `TxGrant` gate wiring, the modulation pipeline shape, and the missing-`TxPlugin`-trait
> core change now, so the shell, the auth-gate, and the capture bus are stable when the
> first TX-capable radio (or the first GNU Radio TX child) lands. No code implements this
> yet.

## Overview

`phonetool-rf-tx` modulates a payload into a waveform and, when authorized and equipped,
transmits it. It is the workbench's first **Axis-B** capability — the regulatory axis — and its
whole point is the gate: **every transmission routes through `Gate::request_tx`, holds a
`TxGrant`, and NEVER auto-transmits.** The token is per-transmission.

The design separates three concerns, each of which fails closed:

- **`modulate`** — pure, sink-free, grant-free DSP. Turns a validated payload into a bounded
  `Waveform`. This is the ahead-of-hardware core: CW/AFSK/FM/SSB correctness is a property of a
  pure function that touches neither a socket, a radio, nor a gate, and is exhaustively
  verifiable offline with **zero emission**.
- **`bandplan`** — the fail-closed regulatory check. Given the `TxGrant`'s band and the
  operation's requested frequency and power, it enforces band-vs-license consistency and the
  power ceiling *before* any sink is touched. Its numeric contents are grounded regulatory
  constants (deferred, never confabulated).
- **`sink`** — the `TxSink` seam. `FileSink` (the default, no hardware, **no emission**) and,
  behind an off-by-default FFI-quarantine feature, device sinks that key a real radio and take
  a `&TxGrant` on their key path.

Two structural properties carry the safety:

1. **The type prevents the wrong axis.** Transmit is reachable only through a method taking
   `&TxGrant`. `Grant` (Axis A) and `TxGrant` (Axis B) are distinct types with no public
   constructor, so a cyber authorization physically cannot key a radio and a transmit license
   physically cannot drive a SIP enum. This extends authgate's compile-time guarantee into the
   TX plugin layer — but it needs a trait that does not exist yet (see the gap below).
2. **The default build cannot emit.** No device `TxSink` is compiled into the default graph, so
   even a valid `TxGrant` has nowhere to key. Emission requires **both** the compiled-in device
   feature **and** the token — a double lock. `FileSink` is the default; rendering a waveform to
   disk is the shipping behavior.

### Threat note

Unlike every other layer, the primary threat here is **not** a crash on hostile input — it is
**causing a real-world RF emission**. Attack/failure classes and mitigations:

1. **Accidental emission (the top risk).** A bug, a copy-paste, or a test that keys a live radio
   is an FCC/ISED violation with physical consequences. Mitigation: the device sink does not
   exist in the default build (Req 3.1); emission requires the off-by-default feature **and** a
   `TxGrant` (Req 3.4); `FileSink` is the default (Req 3.2).
2. **Wrong-band / over-power emission.** A grant for one band keying another, or exceeding the
   licensed power, is unlawful even when a real license exists. Mitigation: fail-closed
   band-vs-license consistency and a power ceiling = min(grant power, regulatory max), checked
   before the sink (Req 5), against a grounded band plan — an unknown band fails closed
   (Req 5.3), never assumes a range.
3. **Axis confusion.** Using a cyber `Grant` to authorize a transmission (or vice versa).
   Mitigation: `TxPlugin::dispatch_tx` takes `&TxGrant` only; the two token types are
   non-interchangeable (Req 1, 2.2). This is the reason a *new* trait is required rather than
   overloading `ActivePlugin`.
4. **Untrusted payload / input audio.** Even operator-supplied, an AX.25 frame or an input WAV
   is parsed bytes; a malformed one must not panic. Mitigation: total, panic-free parsing under
   the deny-lints (Req 6.5); an oversize payload is refused, not allocated (Req 7.5).
5. **Dead-carrier / degenerate send.** Keying a radio with a zero-sample waveform wastes
   spectrum and misleads the operator. Mitigation: zero samples → `PluginError::Empty`; never
   key a sink with an empty waveform (Req 9).

## Architecture

```
   CLI: rf-tx <scheme> <payload> --band <b> --power-dbm <p> --license <why> [--freq <hz>]
        │
        ▼
   Gate::request_tx { band, power_dbm, license_basis }  ──► ConsentLog (CaptureBus): Granted | Refused
        │  Ok(TxGrant)                                        (refusal ends the flow here — fail-closed)
        ▼
   registry.dispatch_tx("rf-tx", &cmd, &tx_grant)        ← NEW third path (Req 2); NOT dispatch/dispatch_active
        │
        ▼
   RfTx::dispatch_tx(cmd, grant: &TxGrant)               ← NEW TxPlugin trait (Req 2); mirrors ActivePlugin
        │  band     ← grant.band()        (NEVER cmd)     verb guard: cw | afsk | fm | ssb
        │  power    ← grant.power_dbm()    (NEVER cmd)
        │  license  ← grant.license_basis()
        │  payload  ← cmd.arg  (operation parameter)
        │  freq     ← UNRESOLVED: one `arg` slot can't also carry freq (Open Question 8)
        ▼
   bandplan::check(band, freq, power)   ── grounded FCC/ISED table ──► InvalidInput on:
        │   • freq ∉ band range     (70cm grant cannot key 2m)          (checked BEFORE sink)
        │   • power > min(grant power, regulatory max)
        │   • band ∉ BandPlan       (unknown band fails closed)
        ▼
   modulate(scheme, payload, cfg) → Waveform            ← PURE, sink-free, grant-free, TOTAL
        │   cw   → OOK dit/dah (wpm)                       payload validated at boundary (Req 6)
        │   afsk → Bell-202 1200bd AX.25/APRS              bounded by SAMPLE_CAP (Req 7.5)
        │   fm   → FM(audio)   ssb → SSB(audio)            0 samples → PluginError::Empty (Req 9)
        ▼
   ┌──────────────────────── TxSink (TRANSMIT-ONLY trait; RTL-SDR has NO impl) ─────────────────┐
   │  FileSink (DEFAULT, no hardware, NO EMISSION)                                                │
   │  HackRfTxSink / LimeTxSink / PlutoTxSink  ── FFI-QUARANTINE crate: unsafe allowed, OFF ──    │
   │     device key path additionally takes &TxGrant  ── double lock: feature AND token (Req 3.4) │
   └───────────────────────────────┬─────────────────────────────────────────────────────────────┘
        ▼
   Event{ source:"rf-tx", summary, data:{ scheme, band, freq, power_dbm, samples, sink } }
        │  rendered waveform → CaptureRef{ kind: Iq | CallAudio, path }   (never inlined)
        ▼
   CaptureBus.record_event(event) + record CaptureRef for the bulk waveform

   ── Tier-B alternative (subprocess-ipc-contract) ─────────────────────────────────────────────
   RfTx (or a SubprocessPlugin) ──► GNU Radio TX flowgraph child
        THE GATE STAYS RUST-SIDE: host obtains the TxGrant, THEN drives the child (never a bypass)
        CONTROL: length-prefixed JSON (Command → Event)
        DATA:    bulk IQ handed to the child out-of-band by handle ──► CaptureRef{ Iq, path }
```

## Modules

- **`modulate`** — pure, sink-free, grant-free DSP producing a bounded `Waveform` (an owned
  buffer of complex baseband samples, or real audio samples for an AF stage, plus its sample
  rate). Submodules: `cw` (text → OOK at a configurable WPM), `afsk` (AX.25/APRS frame →
  Bell-202 1200-baud AFSK), `fm`, `ssb` (input audio → modulated). Each is a pure function of
  its validated input, exhaustively testable against a reference waveform with no I/O and no
  token. `SAMPLE_CAP` lives here (the render bound, Req 7.5).
- **`payload`** — boundary validation per scheme: the CW encodable-character set, AX.25/APRS
  frame construction and validation (flag, bit-stuffing, FCS), and the input-audio reader. All
  parsers total and panic-free. Emits the exact `PluginError` on a bad payload before any
  render (Req 6).
- **`bandplan`** — `BandPlan` (band name → allowed frequency range + regulatory power ceiling),
  `check(band, freq, power_dbm) -> Result<(), BandError>`, and `BandError`
  (`FreqOutOfBand`/`OverPower`/`UnknownBand`). The table's *contents* are grounded regulatory
  constants sourced from real FCC/ISED references; this module ships the *mechanism* and leaves
  the numbers to the grounded build (Open Questions). Fail-closed on an unknown band.
- **`sink`** — the `TxSink` trait (transmit-only: a `key(&Waveform)` path plus its tuning; **no
  receive method**, the mirror of sdr-rx's `SdrSource` having no transmit method) and `FileSink`
  (pure Rust, default, writes the waveform to a path, no emission).
- **`lib` (`RfTx`)** — the `TxPlugin` boundary: manifest `{ transducer: RfTx, capability:
  RfTx }`, verb guard, reads band/power/license from the `TxGrant` (never the command), runs the
  `bandplan` check, drives `modulate`, applies the degenerate discipline, selects the sink
  (`FileSink` by default), and assembles the `Event` + `CaptureRef`. `TxConfig` (WPM, sample
  rate, `SAMPLE_CAP`, output path). **Second core prerequisite:** recording the `CaptureRef`
  needs a core addition. `CaptureRecord::CaptureRef` is a genuine existing type but is
  `#[allow(dead_code)]`, and `CaptureBus` today exposes only `record_event(Event)` — there is no
  public method to record a `CaptureRef`. rf-tx needs a public capture-recording writer on
  `CaptureBus`. This is systemic/cross-cutting, not rf-tx-local: sdr-rx, cell-survey, gnss, ss7,
  and legacy-hw all assume the same missing writer for their bulk artifacts.
- **`phonetool-rf-tx-ffi`** (separate crate, OFF-BY-DEFAULT feature, **the only place `unsafe`
  is allowed**) — `HackRfTxSink` / `LimeTxSink` / `PlutoTxSink`, each `impl TxSink` over
  soapysdr/device libs, with a key path that additionally takes a `&TxGrant`. No RX-only device
  (RTL-SDR) appears here.

## The load-bearing gap: there is no plugin trait that takes a `&TxGrant`

This is the layer's central architectural deliverable, stated plainly because the operator must
approve the core change before rf-tx can be built.

**Today:**
- `Plugin::dispatch(&self, cmd)` — passive, no token. (numintel, sdr-rx, ss7.)
- `ActivePlugin::dispatch_active(&self, cmd, grant: &Grant)` — Axis A / cyber. (phonetool-sip.)
- `Transducer::RfTx` **exists**. `CapabilityClass::RfTx` **exists**. `TxGrant` **exists** and is
  minted by `Gate::request_tx`.
- **But there is no trait whose method takes a `&TxGrant`, and no registry path to dispatch
  one.** An RF-TX capability has the port, the label, and the token — and no legal plug-in
  point. It cannot be registered or dispatched without a core change.

### The prerequisite core change (proposed, argued — the operator approves the shape)

Add to `phonetool-core::plugin`:

```
pub trait TxPlugin: Send + Sync {
    fn manifest(&self) -> Manifest;
    fn dispatch_tx(&self, cmd: &Command, grant: &TxGrant) -> Result<Event, PluginError>;
}
```

Add to `phonetool-core::registry::PluginRegistry`:
- a `tx: HashMap<String, Arc<dyn TxPlugin>>` map,
- `register_tx(Arc<dyn TxPlugin>)` routed through the **existing private `claim` helper** so it
  shares the one name namespace and the one exclusive-transducer index (the `RfTx` port is
  exclusive — only one TX plugin can hold it),
- `dispatch_tx(plugin, cmd, grant: &TxGrant)`,
- `manifests()` extended to span the third map.

### Why a distinct trait, not a flag or an overload (the argument)

- **`Grant` and `TxGrant` are deliberately non-interchangeable types** (authgate's whole
  Axis-A/Axis-B separation). A single `dispatch_active(cmd, grant: &Grant)` cannot carry a
  `TxGrant`; widening it to an enum-of-tokens would push the axis distinction back to a runtime
  `match` — exactly the convention the gate exists to eliminate. Three traits keep "a cyber
  authorization is not a transmit license" a compile-checked fact at the dispatch boundary, the
  same property it has at the mint boundary.
- **The three dispatch paths mirror the three capability classes** already in the manifest
  (`Passive` → `dispatch`, `ActiveIp` → `dispatch_active`, `RfTx` → `dispatch_tx`). The registry
  already keeps passive and active in separate maps sharing one `claim`; adding a third map is
  the established pattern, not a new one.
- **The passive path stays frictionless** (the "do not narc-jump" invariant): a passive plugin
  still implements only `Plugin` and never sees any token. Only a genuine transmit capability
  implements `TxPlugin`.

### The recommendation, not a silent decision

Recommended direction: **add `TxPlugin` + `register_tx` + `dispatch_tx` as the minimal,
pattern-consistent core change**, exactly mirroring the passive/active split that already
exists. This is marked as the prerequisite Task 0 in `tasks.md` and touches `phonetool-core`,
which is a shared crate — so it is called out as a cross-crate change for the operator to
approve before rf-tx work begins, rather than decided here. An alternative (a single
`Capability`-tagged token enum on one trait) is explicitly **not** recommended, for the
type-safety reason above, and is left as an Open Question so the rejection is on the record.

## Design decisions

### The `TxGrant` is per-transmission; the plugin never auto-keys

`dispatch_tx` performs exactly one transmit and returns. A `TxGrant` is not `Clone`/`Copy` and
is minted per operation by `Gate::request_tx`; the plugin holds `&TxGrant` for the duration of
one send and cannot loop, schedule, or re-key from it (Req 1.5, 8.2). "NEVER auto-TX" is the
operator's binding instruction and is enforced structurally: there is no code path from one
grant to two emissions.

### Band/power authority from the `TxGrant`, requested frequency from the command

The authorized band, power, and license basis are read from `grant.band()`,
`grant.power_dbm()`, `grant.license_basis()` — never the command. The command carries the
*operation's* parameters, not the regulatory authority. This is the Axis-B analogue of sip's
"target lives in the Grant" invariant: the regulatory authority a transmission answers to is
fixed by the gate, and the command cannot smuggle in a different band or a higher power. The
requested frequency, once it reaches the plugin, is checked *against* the grant's band by
`bandplan` — it is a parameter to be validated, not an authority to be trusted.

An operation needs **two** distinct parameters at the plugin boundary — the payload *and* the
requested frequency within the band — but the real `Command` exposes a single positional field
`arg: String`, and this spec does not define an encoding that carries both. How the second
per-op parameter (freq) reaches the plugin is therefore left unresolved rather than silently
picked — see Open Question 8.

### Fail-closed band plan; unknown band is a refusal

`bandplan::check` enforces two things before any sink is touched: (1) the requested frequency
lies within the frequency range of the grant's band (a 70cm grant cannot key a 2m frequency);
(2) the effective power does not exceed min(grant power, the band's regulatory maximum). A band
absent from the table fails closed with `InvalidInput` — the plan never assumes a range or a
limit for a band it does not know. Checks run *before* sink selection so a refused transmission
never reaches a device sink even when the device feature is on (Req 5.5).

### `modulate` is pure, sink-free, grant-free — the ahead-of-hardware core

Modulation correctness is separated entirely from transmission. `modulate(scheme, payload, cfg)
-> Result<Waveform, ..>` is a pure function: no socket, no radio, no token. This is the operator
directive made concrete — the entire CW/AFSK/FM/SSB pipeline is written and *proven* before any
transmitter exists, by rendering to a file and comparing against a reference waveform. A live
radio changes nothing about `modulate`; it only swaps `FileSink` for a device `TxSink`
downstream. Keeping `modulate` grant-free is deliberate: the gate belongs at the transmit
boundary (the sink key), not smeared through the DSP — a rendered file is not an emission and
must not require a token.

### `FileSink` is the default and the ahead-of-hardware sink, not a test double

Like sdr-rx's `IqFileSource`, `FileSink` is a first-class shipping sink — the default — not a
mock. Rendering to a file is the primary behavior of the tool until a radio arrives, and the
file is a real, inspectable artifact (recorded as a `CaptureRef`). Device sinks are the *later*
addition, quarantined behind a feature; the waveform they key is the same one already rendered
to files.

### Emission requires a double lock: the feature AND the token

The device sink is compiled in only under an off-by-default FFI-quarantine feature, and its key
path additionally requires a `&TxGrant`. So a real emission is impossible without **both** a
deliberate build decision (the feature) **and** a gate-minted token. In the default build the
device type does not exist, so selecting it is a *compile* error, not a runtime one — the
ahead-of-hardware build cannot accidentally key a radio at all (Req 3).

### `TxSink` is transmit-only; RTL-SDR has no implementation

Symmetric to sdr-rx: `SdrSource` (RX) has no transmit method, so an RX plugin cannot energize a
TX path; `TxSink` (TX) is transmit-only and no RX-only device implements it. RTL-SDR is RX-only
and therefore simply has no `TxSink` — a transmit operation can never be attempted on a
receive-only radio, by construction rather than by a runtime guard.

### Degenerate = failure; a single dit is success

A validated payload that produces zero samples (empty CW text, empty AFSK frame, silent audio)
returns `PluginError::Empty` and never keys a sink — a dead carrier is useless and misleading,
the same discipline sip applies to a probe that learned nothing. A non-empty waveform, however
small (one Morse character, a one-line APRS beacon), is a real result and returns `Ok(Event)`.

### Tier-B (GNU Radio TX flowgraph) with the gate held Rust-side

Per the brief, the live TX path is a Tier-B GNU Radio TX flowgraph, driven over
`specs/subprocess-ipc-contract`. The critical invariant from that contract binds here: **the
gate stays on the Rust side.** The host (`RfTx` or a `SubprocessPlugin`) obtains the `TxGrant`
via `Gate::request_tx` *first*, runs the `bandplan` check *first*, and only then drives the
child flowgraph — a subprocess is never a gate bypass. Bulk IQ handed to the child moves
out-of-band by handle and is recorded as `CaptureRef { Iq, path }`; control frames carry only
`Command`/`Event`. Whether the live path is Tier-B GNU Radio or a Tier-A native soapysdr FFI
sink is an Open Question (mirroring sdr-rx), but either way the token and the regulatory check
precede the child.

### Grounded constants only

Every band-plan frequency range, regulatory power limit, AFSK tone pair, baud rate, AX.25
framing constant, CW timing ratio, and SSB filter parameter is a **grounded constant** cited
against its source (FCC Part 97 / Part 95, ISED RBR-2 / RSS-210, the AX.25 v2.2 spec, Bell 202).
Where a value is not verified against a real reference at build time, the code leaves it
unresolved and the operation fails closed rather than shipping an invented number. This spec
deliberately states **no** numeric frequencies, power limits, tone frequencies, or timing
ratios — they are deferred to the grounded build (Open Questions), because confabulating them is
exactly the fabrication failure mode this project forbids, and here a confabulated band edge could
authorize an unlawful emission.

## Error handling

One error vocabulary at the boundary: `PluginError` (the trait's enum). A payload that fails
per-scheme boundary validation → `PluginError::InvalidInput` (Req 6.1, 6.2); a band-plan
violation (out-of-band frequency, over-power, unknown band) → `PluginError::InvalidInput`
(Req 5); an unsupported scheme verb → `PluginError::Unsupported` (Req 6.4); an unreadable input
audio file or a device-absent condition → `PluginError::Backend` (Req 6.3, 10.4); a zero-sample
render → `PluginError::Empty` (Req 9). The internal `BandError` maps into `InvalidInput`; the
`payload`/`modulate` parsers are total (no `unwrap`/`expect`/unchecked index) — enforced by
`unsafe_code = forbid` and the workspace deny-lints on the default (non-FFI) crate. No panics on
any input.

## Testing strategy

- **Offline modulation proof (no hardware, no gate):** feed a known payload to `modulate` and
  assert the rendered `Waveform` matches a reference — CW dit/dah timing at a given WPM, an
  AFSK/AX.25 frame's tone transitions and FCS, an FM/SSB render of a known input tone. This is
  the ahead-of-hardware correctness proof, and it needs no `TxGrant` because `modulate` is
  grant-free.
- **Gate-only end-to-end (loopback, no emission):** mint a `TxGrant` the only legal way —
  through the real `Gate::request_tx` on the production `CaptureBus` — then drive `dispatch_tx`
  with `FileSink`; assert the file is written and the `CaptureRef { kind, path }` is recorded.
  A second test asserts an empty band or empty license is a `Denied::NoTarget` / `Denied::NoBasis`
  refusal recorded on the bus (fail-closed, no waveform rendered). Rendering to a file is not an
  emission.
- **Band-vs-license enforcement:** a `TxGrant` for band A with a requested frequency in band B →
  `InvalidInput`; a power above min(grant, regulatory) → `InvalidInput`; an unknown band →
  `InvalidInput` (fail-closed) — each asserted to occur *before* any sink work.
- **Compile-fail doctest:** fabricating a `TxGrant` struct literal to reach `dispatch_tx` does
  not compile — the Axis-B mirror of authgate's and sip's doctests.
- **Payload hostile-input (table-driven):** unencodable CW character, malformed AX.25 frame,
  unreadable/oversize input audio, oversize payload exceeding `SAMPLE_CAP` — each maps to the
  exact `PluginError` or is refused without panic.
- **Degenerate discipline:** empty CW text / empty frame / silent audio → `PluginError::Empty`;
  assert no sink is keyed with a zero-sample waveform; a single-character payload → `Ok(Event)`.
- **No-emission invariant:** a test (or a compile-level check) that the default build contains no
  device `TxSink` and that the transmit path with no device feature resolves to `FileSink`; that
  `cargo tree -e no-dev` shows no radio-driver/network crate in the default graph.
- Test targets carry `#![allow(clippy::{expect_used,unwrap_used,indexing_slicing})]` since the
  no-panic discipline binds library code, not assertions.

## Open questions for operator

1. **Approve the `TxPlugin` core change (the prerequisite).** rf-tx cannot be wired without
   adding `TxPlugin` + `register_tx` + `dispatch_tx` to the shared `phonetool-core`. Recommended
   shape is above (a distinct trait mirroring `ActivePlugin`, a third registry map through the
   existing `claim`). Confirm the shape — and confirm the rejection of the single-token-enum
   alternative — before the change lands, since it touches a shared crate.
2. **Band-plan numeric contents + jurisdiction.** The frequency ranges and power limits for each
   band (ham HF/VHF/UHF, CB, GMRS, MURS, APRS frequencies) are grounded regulatory constants that
   MUST come from real FCC/ISED tables — none are invented here. Which jurisdiction(s) does the
   operator build for first (US FCC Part 97/95, ISED, both), and what is the citable source of
   truth for the `BandPlan` table? Until grounded, an unmatched band fails closed.
3. **AFSK / CW / SSB numeric constants.** Bell-202 mark/space tone frequencies, 1200-baud
   timing, AX.25 framing (flag, bit-stuffing, FCS polynomial), CW dit/dah timing ratios and the
   Farnsworth question, and SSB filter bandwidth/sideband selection are all grounded constants
   deferred to the build (AX.25 v2.2, Bell 202, ITU CW timing). Which references does the
   operator want each sourced from?
4. **Live-path tier: Tier-B GNU Radio TX vs Tier-A native soapysdr FFI sink.** The brief names a
   Tier-B GNU Radio TX flowgraph; sdr-rx recommends Tier-B for DSP breadth. Should rf-tx's live
   path be a GNU Radio TX child (over the subprocess-IPC contract, gate held Rust-side), a native
   `HackRfTxSink` over soapysdr FFI, or both behind the one `TxSink` seam? This shapes whether the
   FFI-quarantine crate is built at all or whether the live path is purely Tier-B.
5. **Device fleet priority + power-vs-antenna semantics.** Which TX-capable radio matters first
   (HackRF / LimeSDR / PlutoSDR) for the FFI-quarantine binding? And is the `power_dbm` ceiling
   interpreted at the device output only, or does the operator want an antenna/ERP note recorded
   in the consent log (since regulatory limits are often ERP/EIRP, not device output)? Not
   decided — flagged because it affects what the power ceiling actually means.
6. **`Waveform` domain + IQ file format.** Does `modulate` render baseband IQ (for a device that
   up-converts) recorded as `CaptureRef { Iq, path }`, or an audio-domain waveform (for an AF
   input to a transmitter) recorded as `CaptureRef { CallAudio, path }`, or both per scheme? And
   which on-disk IQ/audio format(s) does `FileSink` write (raw `cf32`/`cs16`, WAV, SigMF)?
   Recommended: IQ for CW/AFSK, audio for FM/SSB source stages — confirm.
7. **`SAMPLE_CAP` / duration bound values.** The maximum rendered duration/sample count is a
   safety constant, not a protocol one, but its value needs an operator decision (what is a
   realistic legitimate transmission length vs. a runaway key-down on a handheld SBC). Deferred
   rather than invented.
8. **How a second per-op parameter (freq) reaches the plugin.** An rf-tx operation needs both a
   payload and a requested frequency, but the core `Command` exposes one positional field
   `arg: String` and no encoding is defined here to carry both. Three candidate resolutions, none
   picked: (a) move `freq` into `TxConfig` (out of the command entirely, alongside WPM/rate/cap);
   (b) define a structured or delimited `arg` encoding that packs payload + freq and is parsed,
   total and fail-closed, at the boundary; (c) extend the core `Command` type with a second field
   (a shared-crate change, like the `TxPlugin` addition). Confirm which before Task 8 is built —
   the enforcement and payload-validation logic depend on it.
