# phonetool

`0.17.0` · voice-telecom recon & intelligence toolkit

Defensive recon with offensive capability held in reserve as a continuity
mechanism — capability exists, deployment is metered and gated.

## What it is

A **portable, all-in-one comms workbench for off-the-grid / SHTF operation** —
max capability with no internet, no carrier, no infrastructure assumed. Offline
is the default; online is a *mode* (enumeration / debugging / evaluation) used
only when a link exists.

Envisioned embodiment: a **handheld SBC / mobile-class device with a universal
physical interface** — USB-to-alligator-clips and tone/frequency generation
(bluebox/DTMF/MF) for wireline and physical tap, SDR for RF, ethernet/wifi/
cellular for IP. Classic phreak/lineman primitives (tone signalling, loop
manipulation, physical tap) treated as still-valid and married to modern SDR/IP.

Architecture is **platform + plugins**: a common shell (console, config, unified
logging/capture, authorization gate, offline-first local data layer, shared
hardware arbitration) that each capability snaps into. Spans the full comms
stack — RF/air-interface, IP/VoIP, copper/legacy-switching — as pluggable layers,
built one deep at a time.

## Operating model (load-bearing)

- **Defensive core.** Number intelligence, spoof/attestation checking, SIP
  endpoint discovery against owned/authorized infrastructure, fraud-seller
  triage (scambait recon).
- **Offensive modules gate.** Anything active/intrusive requires an explicit
  authorization + target-ownership assertion before it will run. This mirrors
  the operator's standing line: capability exists; illegal offense does not,
  save self-defense or defense of others.

## Planned capability surface (roadmap, not sprint)

**Build the shell first** (console + config + logging/capture + auth gate +
offline data layer), then plugins snap in one at a time. `numintel` is plugin
one. Everything below is destination, not a single milestone.

All roadmap plugins are now built (Sprints 5–17); the offline/RF/copper paths
ship their ahead-of-hardware file/socket default, live-device seams declared-only.
See `docs/DEVICES.md` for the built-vs-declared split per module.

| Plugin        | Layer   | On/Offline | Notes                                             |
|---------------|---------|-----------|---------------------------------------------------|
| `numintel`    | IP      | online     | line-type/carrier/VoIP-vs-mobile/spoof *(built)*  |
| `sip`         | IP      | online     | SIP extension enum over UDP — active, gated *(built)* |
| `attest`      | IP      | online     | STIR/SHAKEN attestation inspection *(built; `online` verify seam)* |
| `ss7`         | IP/sig  | offline    | SS7/Diameter signalling analysis *(built; `live` peer seam)* |
| `baittriage`  | IP      | offline    | fraud-caller footprint OSINT (defense of others) *(built)* |
| `sdr-rx`      | RF      | offline    | SDR sweep / identify / demod *(built; `IqFileSource`)* |
| `cell-survey` | RF      | offline    | GSM cell enum + rogue-BTS scan (passive/RX) *(built; LTE/NR + `live` seams)* |
| `rf-tx`       | RF      | offline    | ham/APRS/Morse TX, gated on license+band *(built; renders to file, `device` seam)* |
| `gnss`        | RF      | offline    | position w/o data; spoof/jam detection *(built)*  |
| `wardial`     | copper  | online     | DID-range enum/fingerprint via SIP origination *(built)* |
| `legacy-hw`   | copper  | offline    | copper line DSP/sense/synth (passive) *(built; injection + `device` seam declared)* |

## Devices

`docs/DEVICES.md` maps every hardware/signal-source seam to the real gear that
attaches to it (SDRs, ATA/FXO cards, VoIP trunks) and states plainly which live
paths are built vs. declared-only. Read it before sourcing hardware.

## Quick start

```
# passive, ungated — offline number intelligence:
cargo run -q -- --store /tmp/pt.db seed "+15125550100" '{"carrier":"TestCo"}'
cargo run -q -- --store /tmp/pt.db lookup "+1 (512) 555-0100"

# active, gated — SIP extension enum routes through the auth gate (--basis mandatory):
cargo run -q -- plugins                                                   # sip [Ip/ActiveIp]
cargo run -q -- sip enum "127.0.0.1:5099" "100,101" --basis "owned lab"
```

An active op is unrepresentable without a `Grant` the gate minted (an empty
`--basis` is a fail-closed refusal). The default binary has **zero egress
dependencies** (`std::net` only); it is not, however, free of active code — the
default binary still contains the gated active-op code paths (inert without a `Grant`).

## Status

See `STATE.md`. Lifecycle: **ACTIVE**, `0.17.0`. All 15 crates built — the full
roadmap surface across IP, RF, and copper, each shipping its ahead-of-hardware
default with live-device paths held behind off-by-default seams. Three gate axes
plumbed: **A** cyber (`Grant`), **B** spectrum (`TxGrant`), **C** wireline
(`WireGrant`) — non-interchangeable, compile-checked. Sprint 17 landed the copper
passive half + Axis-C token. `docs/DEVICES.md` maps every hardware seam.
