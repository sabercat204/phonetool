# phonetool — Device Interface Reference

**Version:** matches workspace `0.17.0` · **Status:** reference · **Scope:** hardware and signal-source devices that interface with phonetool as it exists today.

## Reading this document

phonetool is **ahead of hardware by design**. Every physical-layer capability is built as a *seam*: a Rust trait plus a pure, file/socket-backed default that needs no gear. A live device attaches to a named seam through either an off-by-default Cargo feature (`device`, `online`, `live`) or an already-implemented network/file path.

Two tables per module: **(A) what interfaces today** (file/socket contract you can drive right now) and **(B) live-device seam** (the hardware that *would* attach, the trait it implements, and whether that path is built or declared-only).

The honest caveat that governs the whole document: **a "declared seam" is a named trait and feature flag with no implementation behind it.** Where a live path is unbuilt, this doc says so and cites the code comment that says so. Do not read a device recommendation as "phonetool drives this today" unless the row is in an (A) table or explicitly marked built.

Grounding for every hardware fact below is a vendor spec page or standards document, cited inline. Grounding for every code fact is a `crate/src/file.rs` path verified against the tree at `0.17.0`.

---

## Seam map at a glance

| Module (crate) | Axis / class | Interfaces today (A) | Live-device seam (B) | Seam built? |
|---|---|---|---|---|
| `phonetool-sdr-rx` | Passive RF RX | interleaved `cf32` IQ file | `SdrSource` trait ← real SDR | **Declared** (`IqFileSource` only) |
| `phonetool-gnss` | Passive RF RX | `cf32` IQ file (GPS L1) | `SdrSource` (shared) ← GPS antenna+SDR | **Declared** |
| `phonetool-rf-tx` | Active RF TX (Axis B) | renders waveform → `cf32`/`f32` file | `TxSink` trait + `device` feature ← TX SDR | **Declared** (`FileSink` only) |
| `phonetool-legacy-hw` | Passive wireline / Active (Axis C) | WAV/PCM file DSP + sense trace | `device` feature ← SLIC/FXO/GPIO | **Declared** |
| `phonetool-ss7` | Passive IP | SIGTRAN-over-SCTP `.pcap` + hex | `live` feature ← SS7/Diameter peer | **Declared** |
| `phonetool-cell-survey` | Passive RF (indirect) | GSMTAP-over-pcap file | `live` ← SDR via gr-gsm subprocess | **Declared** (subprocess design-only) |
| `phonetool-sip` | Active IP (Axis A) | **UDP socket** to gated `host:port` | — network path is the device | **Built** |
| `phonetool-wardial` | Active IP + billable | **SIP/UDP** to gated trunk `host:port` | VoIP trunk / ITSP | **Built** (needs `--trunk-host`) |
| `phonetool-numintel` | Passive IP | local cache | `online` feature ← HTTP provider | **Declared** |
| `phonetool-attest` | Passive IP | structural, offline | `online` feature ← x5u cert fetch | **Declared** |

Axis legend: **A** = cyber (`Grant`), **B** = spectrum (`TxGrant`), **C** = physical wireline (`WireGrant`). The three grant types are non-interchangeable and compile-checked (`crates/phonetool-core/src/plugin.rs:197`).

---

## 1. Software-Defined Radio — receive (`phonetool-sdr-rx`, `phonetool-gnss`)

### (A) Interfaces today
- **Input:** raw **interleaved `cf32`** — pairs of little-endian `f32` (I, Q), no header, no framing. `IqFileSource`, `crates/phonetool-sdr-rx/src/source.rs:51`.
- **Default sample rate assumption:** `2_048_000.0` Hz (`crates/phonetool-sdr-rx/src/lib.rs:61`) — an RTL-SDR-class rate. Center frequency is caller-supplied metadata; the file carries no tuning.
- **GNSS:** same `IqFileSource`, expecting GPS **L1 C/A at 1575.42 MHz** carrier, 1.023 Mchip/s C/A code (`crates/phonetool-gnss/src/constants.rs:7`, grounded in IS-GPS-200). "Runs today on `IqFileSource` (no antenna)" — `crates/phonetool-gnss/src/lib.rs:8`.
- Verbs: `sdr sweep|identify|demod`; GNSS acquire→track→PVT→integrity.

### (B) Live-device seam
The trait a real radio implements (`crates/phonetool-sdr-rx/src/source.rs:37`):
```rust
pub trait SdrSource: Send + Sync {
    fn read_block(&mut self, max_samples: usize) -> Result<SampleBlock, PluginError>;
    fn tuned(&self) -> (f64, f64);   // (sample_rate_hz, center_freq_hz)
}
```
`IqFileSource` is the **only** implementor today, and it is explicitly *not* a test double — it is "the ahead-of-hardware default" (`source.rs:51`). A live SDR attaches by adding a second implementor. There is **no** `device` feature on `sdr-rx` yet; the seam is the trait alone.

**Recommended devices** (all expose `cf32`/`cs16` IQ; all covered by the SoapySDR vendor-neutral driver layer that a Rust binding — `kevinmehall/rust-soapysdr` — would target [SoapySDR wiki]):

| Device | Freq range | Max sample rate | ADC | Fit for phonetool |
|---|---|---|---|---|
| **RTL-SDR Blog V4** | 500 kHz–1.766 GHz (HF via upconverter; R828D tuner 24–1766 MHz) | ~2.56 MSPS stable (3.2 max, unstable) | 8-bit | **Best match to the 2.048 MSPS default.** Cheapest RX-only path. GSM900/DCS1800 downlink, FM, ADS-B, POCSAG. [rtl-sdr.com V4 release; rtl-sdr.com/about] |
| **Airspy / Airspy HF+** | HF+ up to ~260 MHz / Mini 24 MHz–1.7 GHz | up to 10 MSPS | 12-bit | Higher dynamic range than RTL; good for HF signalling & weak-signal work. [SoapySDR wiki] |
| **HackRF One** | **1 MHz – 6 GHz** | up to 20 MSPS | 8-bit, half-duplex | Wide tuning incl. GSM1800/UMTS/ISM; RX+TX in one box (see §3). [greatscottgadgets.com/hackrf/one] |
| **USRP B200** | **70 MHz – 6 GHz** | 61.44 MSPS quadrature, 56 MHz BW | AD9364, **full-duplex** | Lab-grade; full-duplex enables simultaneous RX/TX. USB 3.0. [ettus.com ub200-kit] |
| **LimeSDR / PlutoSDR / BladeRF** | device-dependent, ~70 MHz–3.8/6 GHz | 30–61 MSPS | 12-bit | All SoapySDR-supported; PlutoSDR is the low-cost full-duplex option. [SoapySDR wiki] |

> **GNSS note:** L1 reception needs an **active GPS antenna** (3.3 V bias) and an SDR that tunes 1575.42 MHz with ≥2 MHz usable bandwidth — HackRF, USRP, or an RTL-SDR V4 with bias-tee. The integrity/spoof-detection payload runs on any recorded L1 IQ file today with no antenna.

**Producing an IQ file today** (no code change): capture with `rtl_sdr`, `hackrf_transfer`, or SoapySDR's `SoapyRateTest`/GNU Radio file sink, output as `cf32`. Match the sample rate you pass to phonetool.

---

## 2. RF transmit (`phonetool-rf-tx`) — Axis B

### (A) Interfaces today
- **Output:** renders the modulated waveform to a **file** as a bare little-endian `f32` stream (`cf32` for IQ). `FileSink`, "no device, **no emission** — the default" (`crates/phonetool-rf-tx/src/sink.rs:103`).
- **Sample rate:** `SAMPLE_RATE = 48_000` Hz baseband (`crates/phonetool-rf-tx/src/modulate.rs:36`).
- **Modes built:** CW (ITU M.1677-1 timing, 600 Hz tone), AFSK (Bell-202 mark 1200 / space 2200 Hz, AX.25 v2.2). FM/SSB are declared seams.
- **Band-plan gate:** US **FCC Part 97** amateur allocations, table at `crates/phonetool-rf-tx/src/bandplan.rs:36`. Built entries: **40m** (7.0–7.3 MHz), **20m** (14.0–14.35 MHz), **2m** (144–148 MHz), **70cm** (420–450 MHz). Power ceiling 1500 W PEP = 61.76 dBm. **Unlisted band fails closed.**

### (B) Live-device seam — double lock
Keying a real radio is a **compile error, not a runtime one** (`sink.rs` header, `Cargo.toml:14`). Two independent locks:
1. **Cargo feature `device`** (off by default, `crates/phonetool-rf-tx/Cargo.toml:19`) — a declared seam for an FFI-quarantine crate targeting **soapysdr / HackRF / Lime / Pluto** (`Cargo.toml:16`). Unbuilt.
2. **`&TxGrant` token** — the device sink's `accept` path "additionally takes a `&TxGrant`" (`Cargo.toml:17`). Band/power/license live in the grant, never the command (`crates/phonetool-core/src/plugin.rs:155`).

The trait a device sink implements (`crates/phonetool-rf-tx/src/sink.rs:90`):
```rust
pub trait TxSink {
    fn kind(&self) -> &'static str;
    fn accept(&self, waveform: &Waveform) -> Result<(), SinkError>;  // FileSink writes; a device sink keys the radio
}
```

**Recommended transmit-capable devices** (require a valid amateur license for the band; phonetool's band plan enforces Part 97 edges):

| Device | TX range | TX sample rate | Duplex | Note |
|---|---|---|---|---|
| **HackRF One** | 1 MHz–6 GHz | up to 20 MSPS, 8-bit | **Half-duplex** | Single-box TX for all four built bands (40m/20m/70cm need external filtering/PA; it's a 0 dBm-class source). [greatscottgadgets] |
| **USRP B200** | 70 MHz–6 GHz | 61.44 MSPS, 56 MHz BW | **Full-duplex** | Covers 2m/70cm cleanly (below 70 MHz, i.e. 40m/20m, needs a transverter/upconverter). [ettus.com] |
| **LimeSDR / PlutoSDR** | ~70 MHz–3.8/6 GHz | up to 61.44 MSPS | Full-duplex | SoapySDR-native; below 70 MHz same upconverter caveat as B200. [SoapySDR wiki] |

> **Reality check:** `rf-tx` renders a 48 kHz baseband waveform to a file. A live device path would resample to the SDR's rate and up-mix to the on-air frequency (set by the transmitter, not the file — `modulate.rs:46`). None of that is built; the `device` feature is a name reserving the seam. **Do not represent phonetool as able to transmit today.**

---

## 3. Copper / legacy wireline (`phonetool-legacy-hw`) — Axis C

### (A) Interfaces today (passive, no gate)
- **Input:** **WAV** (`RIFF`/`WAVE`, PCM `fmt=1` or IEEE-float `fmt=3`) or raw PCM buffers — `crates/phonetool-legacy-hw/src/source.rs:88`. `SAMPLE_CAP = 4_000_000` samples (~91 s @ 44.1 kHz).
- **DSP built:** DTMF decode (ITU-T Q.23/Q.24, low group 697/770/852/941 Hz, high group 1209/1336/1477/1633 Hz — `crates/phonetool-legacy-hw/src/dsp.rs:22`), 2600 Hz SF supervision, **Bell-202 CID** (mark 1200/space 2200, SDMF frame + checksum — `dsp.rs:16`).
- **Line-sense trace:** decodes recorded voltage traces to line state. Nominal idle **48 V**, off-hook ceiling 15 V, ring swing 120 V (`crates/phonetool-legacy-hw/src/sense.rs:22`) — flagged as datasheet placeholders (design OQ2), *not* grounded SLIC values.
- Verbs: `line synth|decode|cid|sense`. `synth` is **inert** — writes samples, never drives a line.

### (B) Live-device seam
- **Cargo feature `device`** (off by default, `crates/phonetool-legacy-hw/Cargo.toml`) — reserved for a future FFI-quarantine crate `phonetool-linehw-ffi` (gpio-cdev / linux-embedded-hal) that alone relaxes `unsafe_code=forbid`. Holds the live line-sense source and, "only once the gate gap is resolved AND the hardware-safety interlock exists," the injection driver. **Unbuilt.**
- **Active injection (Axis C)** additionally requires the `WireGrant` token (`Gate::request_wire`) *and* a hardware-safety interlock. The trait exists (`crates/phonetool-core/src/plugin.rs:197`, `dispatch_wire(&self, cmd, grant: &WireGrant)`); there is no `WirePlugin` consumer. **Token present, no injector.**

**Devices that would attach at this seam:**

| Device class | Example hardware | Role | phonetool fit |
|---|---|---|---|
| **ATA / FXS gateway** | Grandstream HT801/HT802, Cisco/Linksys SPA, Obihai | Presents dial tone, ring, CID to an analog phone; bridges to SIP | Source of realistic DTMF/CID **audio** (via the SIP/RTP side → WAV) for the passive decoders today [Wikipedia: analog telephone adapter] |
| **FXO interface** | ATA/gateway FXO port, or DAHDI card FXO module | Connects *toward* the PSTN/CO line — line seizure, loop current sense | The live line-sense + (future, interlocked) injection path [voip-info.org/dahdi] |
| **DAHDI analog card** | Digium/Sangoma Wildcard **TDM410P / TDM800P**, A200 | PCIe card giving a Linux host direct FXO/FXS ports | The canonical Axis-C device: raw copper access under `dahdi_cfg` [voip-info.org/dahdi] |
| **SLIC front-end** | Silicon Labs Si3217x / Si3050 codec + SBC GPIO | Subscriber Line Interface Circuit — the actual BORSCHT functions (battery, ring, hybrid) | What `sense.rs`'s placeholder voltage constants (48 V / 120 V) would be replaced by from the chosen SLIC datasheet |

FXS = *toward the phone* (delivers −48 V battery, 90 V RMS ring, dial tone, CID). FXO = *toward the CO/PSTN* (draws loop current, detects ring). [Wikipedia: ATA; voip-info.org DAHDI] phonetool's passive decoders consume the **audio** either produces; the active seam would drive the FXO side.

> **Line-voltage hazard.** Ring is ~90 V RMS / 120 V peak. Any live-wireline device requires the hardware-safety interlock that is explicitly unbuilt (`Cargo.toml:19`). This is why Axis C carries its own distinct grant.

---

## 4. SS7 / SIGTRAN signalling (`phonetool-ss7`) — Passive IP

### (A) Interfaces today
- **Input:** `.pcap` recorded at the **SCTP** layer — `LINKTYPE_SCTP = 248` (tcpdump.org linktypes), bare SCTP packet, no Ethernet/IP framing (`crates/phonetool-ss7/src/source.rs:170`). Also accepts an inline **hex PDU** dump (`hex:...`).
- Decodes SCCP/TCAP/MAP + Diameter S6a; flags location-disclosure (ATI/SRI-SM/SRI/PSI/ULR/IDR) and intercept-enabling ops (AIR/updateLocation/sendAuthInfo). Grounding: RFC 4960 (SCTP), IETF pcap draft.

### (B) Live-device seam
- **Cargo feature `live`** (`crates/phonetool-ss7/Cargo.toml:19`) — a live SIGTRAN/Diameter **peer source** implementing the same `CaptureSource` trait. "Carrier- and hardware-gated (a provisioned point code / Diameter peering)" — `Cargo.toml:16`. **Unbuilt.**

**Devices/infrastructure at this seam** (all require a carrier relationship, not consumer gear):
- **SIGTRAN stack** on a provisioned **point code** — an SS7-over-IP (M3UA/SUA) association to an STP. This is carrier infrastructure, not a purchasable dongle.
- **Diameter agent/peer** — an S6a/S6d peering to an HSS/MME in an LTE core.
- **Capture in practice today:** an SCTP capture from a lab core (osmo-* / Kamailio-IMS / free5GC) written with `tcpdump -y LINKTYPE_SCTP` or converted to it. No special hardware — the "device" is a peering relationship.

---

## 5. Cellular survey (`phonetool-cell-survey`) — Passive RF, indirect

### (A) Interfaces today
- **Input:** `.pcap` of **GSMTAP-over-Um** — `LINKTYPE_GSMTAP_UM = 217` (tcpdump.org), bare 16-byte GSMTAP header (version 0x02, type 0x01) + Um payload, no Ethernet/IP/UDP framing (`crates/phonetool-cell-survey/src/source.rs:112`). ARFCN read from the GSMTAP header.
- Decodes GSM SI3/SI2 → cell map + rogue-BTS anomaly scan. GSM decode is real (grounded: libosmocore / TS 24.008). LTE/NR SIB1 (ASN.1 UPER) are declared seams, unbuilt.

### (B) Live-device seam
- **Cargo feature `live`** (`crates/phonetool-cell-survey/Cargo.toml`) — would wire a `LiveCaptureSource` to a **Tier-B `SubprocessPlugin`** (gr-gsm / Osmocom / srsRAN) **that owns the SDR**. The subprocess IPC contract is **design-only** (`specs/subprocess-ipc-contract/`, DESIGN-ONLY) and unbuilt. Enabling `live` changes nothing yet.

**The device chain** (phonetool never touches the radio directly — a subprocess does):
```
[antenna] → [SDR: RTL-SDR / HackRF / USRP] → [gr-gsm grgsm_livemon or Osmocom]
          → GSMTAP UDP:4729 → [capture to LINKTYPE_GSMTAP_UM pcap] → phonetool cell-survey
```
- **GSMTAP** is a pseudo-header wrapping the GSM Um interface into UDP, statically bound to **UDP port 4729** and dissected by Wireshark. [wiki.wireshark.org/GSMTAP]
- **SDR for GSM downlink:** an **RTL-SDR** (GSM900 ~935–960 MHz, DCS1800 ~1805–1880 MHz are within the R828D 24–1766 MHz / upconverted range — note DCS1800 exceeds RTL's 1766 MHz top; use HackRF/USRP for the 1800 band). [rtl-sdr.com; greatscottgadgets]
- **Capture recipe today:** `grgsm_livemon` emits GSMTAP to UDP 4729; capture with `tcpdump -i lo -w cell.pcap` then convert/record to LINKTYPE_GSMTAP_UM. Passive reception only.

---

## 6. SIP enumeration + wardial (`phonetool-sip`, `phonetool-wardial`) — Active IP

> These are the **only modules whose live path is built.** The "device" is the network socket; no hardware is required. Both are gated — see the authgate.

### (A) `phonetool-sip` — extension enumeration
- **Transport:** one **UDP** `OPTIONS` per candidate via `std::net::UdpSocket` (`crates/phonetool-sip/src/enumerate.rs:18,116`). Target `host:port` comes from the **`Grant`**, not the command (`crates/phonetool-sip/src/lib.rs:12`). Default SIP port 5060; example uses 5099.
- Requires a non-empty `--basis`; gate refuses otherwise. This is a real active op against the gated target.

### (B) `phonetool-wardial` — SIP-origination wardial (billable)
- **Transport:** SIP/UDP to the gate-authorized **trunk `host:port`** (`crates/phonetool-wardial/src/message.rs:23`). Range lives in the `Grant`, never the command. Three fail-closed guards: gate (`--basis`), cost-ack (`--i-accept-billing-and-attribution`), and a `--trunk-host` backend.
- **SIP-only fidelity:** `MediaDisposition=NotAnalyzed` — no RTP/media path exists (OQ6). `MAX_RANGE=32` is a conservative safety floor, not a provider value.

**Devices/services at this seam** (network endpoints, not hardware):

| "Device" | Examples | Role |
|---|---|---|
| **SIP server / PBX** (enum target) | Asterisk, FreePBX, Kamailio, a lab UAS on `:5099` | The infrastructure `sip enum` probes — must be owned/authorized |
| **VoIP trunk / ITSP** (wardial `--trunk-host`) | A SIP trunk from an ITSP, or a self-hosted Asterisk/Kamailio trunk | Originates the calls; the billing/attribution surface the cost-ack guards |
| **ATA** (optional, at the far end) | Grandstream HT-series, etc. | Terminates a call onto an analog phone for end-to-end lab tests [Wikipedia: ATA] |

---

## 7. Online enrichment seams (`phonetool-numintel`, `phonetool-attest`) — Passive IP

No hardware. Listed for completeness because they are the workspace's only **egress** seams.

- **`numintel` `online` feature** (`Cargo.toml:18`, `online = ["dep:reqwest"]`, off by default) — the one non-air-gapped path: an HTTP lookup to a number-intelligence provider. Default build serves from local cache only, links no HTTP client. **Feature built; provider wiring per the threat note in `lookup.rs`.**
- **`attest` `online` feature** — adds the STIR/SHAKEN x5u certificate fetch + ES256 signature verification. **Declared seam** as of Sprint 11 (blocked on operator Open Questions); default build is structural-only, air-gapped.

The "device" here is an HTTPS endpoint. Verify the default graph stays egress-free with `cargo tree -e no-dev` (zero `reqwest` without `--features online`).

---

## Attaching a real device — the general procedure

1. **Identify the seam** from the at-a-glance table. It is a trait (`SdrSource`, `TxSink`, `WirePlugin`, `CaptureSource`) and possibly a feature (`device`/`live`/`online`).
2. **Passive/RX seams** (`SdrSource`, ss7/cell pcap): the simplest attach is to *produce the file/capture the tool already reads* — `cf32` IQ, LINKTYPE_SCTP/GSMTAP_UM pcap. No code change, no feature.
3. **Live in-process seams** need a new trait implementor behind the off-by-default feature. For `device` on `rf-tx`/`legacy-hw` this also means an **FFI-quarantine crate** (the only place `unsafe_code=forbid` relaxes) and, for active axes, the matching **grant token** — and for wireline, the unbuilt **hardware-safety interlock**.
4. **Active seams never take the target from the command** — it comes from the grant (`Grant`/`TxGrant`/`WireGrant`). This is compile-checked.

## What phonetool cannot do today (stated plainly)

- **Transmit RF** — `rf-tx` writes files; `device` feature unbuilt.
- **Drive a copper pair** — `legacy-hw` decodes audio/traces; injection driver + safety interlock unbuilt.
- **Own an SDR in-process** — `sdr-rx`/`gnss`/`cell-survey` read files; no live `SdrSource` implementor; the cell-survey subprocess contract is design-only.
- **Peer live SS7/Diameter** — `live` feature is a name; needs a provisioned point code.

Everything above is a **seam ready for a device**, not a working driver. The working live paths are exactly the network ones: `sip enum`, `wardial`, and the `online` enrichment fetches.

---

### Sources

Hardware: rtl-sdr.com (Blog V4 release; About RTL-SDR), greatscottgadgets.com/hackrf/one, ettus.com (USRP B200 / ub200-kit), SoapySDR project wiki (github.com/pothosware/SoapySDR/wiki), wiki.wireshark.org/GSMTAP, en.wikipedia.org/wiki/Analog_telephone_adapter, voip-info.org/dahdi.
Standards: IS-GPS-200 (GPS L1 C/A), ITU-T Q.23/Q.24 (DTMF), ITU-R M.1677-1 (CW), Bell-202 / AX.25 v2.2, FCC Part 97.301/.313, RFC 4960 (SCTP), tcpdump.org/linktypes.html, IETF pcap savefile draft.
Code: verified against the phonetool workspace tree at version `0.17.0` (paths cited inline).
