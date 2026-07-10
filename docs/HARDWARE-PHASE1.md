# phonetool — Phase 1 Hardware Spec (field-test procurement)

**Status:** procurement draft · **Target:** ESP32-class modules + companion radios, per-item < $50 · **Intent:** buy parts to field-test the built software layers against real signals.

## Scope and honesty caveats (read first)

This spec pairs phonetool's **built** software layers (see `STATE.md`) with the cheapest credible hardware that exercises each. Two hard constraints govern it:

1. **Prices are UNVERIFIED market ranges.** Live Alibaba / Shenzhen retailer pages could not be fetched when this was written. Every price below is a typical-street-price estimate from general market knowledge, tagged **[VERIFY]**. Do **not** treat any figure as a quote — confirm on the retailer at purchase time. Prices on Alibaba/AliExpress swing with MOQ, shipping, and season.
2. **ESP32 is a 2.4 GHz + BLE + sub-GHz-companion host, not an SDR.** An ESP32 cannot receive the wideband IQ that `sdr-rx`, `gnss`, and `cell-survey` decode — those need a real SDR (out of ESP32 scope; see the deferred layer note). ESP32 covers the WiFi/BLE/802.15.4 RF layer, drives SPI sub-GHz transceivers, and hosts the copper/audio DSP front end. Where a layer needs more than an ESP32 can do, this says so plainly rather than overselling the chip.

**Legal note (inherits the project gate):** every transmit-capable item below is RX-capable too and legal to *receive* with. Transmit (CC1101, Si5351, SX1276, the cellular modem) is lawful only on bands you're licensed/authorized for and against infrastructure you own — the same authorization line the software gate enforces. Buy for RX + owned-lab TX; do not key third-party spectrum.

---

## Layer → hardware map

| phonetool layer (crate) | Signal | ESP32-native? | Hardware needed |
|---|---|---|---|
| WiFi/BLE recon (future `discovery`) | 2.4 GHz | **Yes** | ESP32-S3 or C6 dev board |
| 802.15.4 / Thread / Zigbee | 2.4 GHz | **C6 only** | ESP32-C6 |
| sub-GHz ISM (ties to `rf-tx` AFSK/OOK, POCSAG, ADS-B-adjacent) | 300–928 MHz | No — SPI companion | CC1101 or SX1276 module |
| HF/VHF tone + CW TX signal source (`rf-tx` CW) | 8 kHz–200 MHz clock | No — I2C companion | Si5351 breakout + low-pass filter |
| Copper / DTMF / CID (`legacy-hw`) | audio (POTS) | No — analog front end | MT8870 decoder + audio codec + line coupler |
| GNSS receive + integrity (`gnss`) | 1575.42 MHz L1 | No | u-blox NEO-M8N (position truth) — NOT IQ |
| Cellular presence / SS7-adjacent context (`ss7`, `cell-survey` context) | LTE/GSM | No — UART/USB modem | SIM7600 modem (context only, not air capture) |
| SDR-fed layers (`sdr-rx`, `cell-survey` GSMTAP, `gnss` spoof-IQ) | wideband IQ | **No — needs real SDR** | RTL-SDR V4 / HackRF (see deferred note) |

---

## Part list — Phase 1 buy

Quantities assume **one field kit + one spare** of the cheap consumables. All prices **[VERIFY]**.

### A. Host controllers (the ESP32 core)

| # | Part | Radios | Why | Est. unit [VERIFY] | Source |
|---|---|---|---|---|---|
| A1 | **ESP32-C6-DevKitC-1** (WROOM-1) | WiFi 6 2.4 GHz, BLE 5, **802.15.4** (Thread/Zigbee) | The only ESP32 covering 802.15.4 — the widest RF-layer host. Primary controller. | $8–15 | Espressif official / AliExpress / LCSC |
| A2 | **ESP32-S3-DevKitC-1** (WROOM-1, N16R8) | WiFi 2.4 GHz, BLE 5 | More RAM/PSRAM + USB-OTG for the DSP/audio front end and packet capture buffering. | $8–18 | Espressif / AliExpress / LCSC |
| A3 | **ESP32-WROOM-32 DevKit** (classic) | WiFi 2.4 GHz, BT Classic + BLE | Cheap workhorse / spare; BT Classic (absent on C-series) if any classic-BT recon is wanted. | $4–8 | AliExpress / Shenzhen generic |

Radio facts grounded: C6 = WiFi 6 + BT5 + Zigbee 3.0 + Thread; S3 = WiFi + BLE5 (no 802.15.4); C3 = WiFi + BLE5 (cheapest, no 802.15.4) — Espressif module page.

### B. Sub-GHz transceivers (SPI companions)

| # | Part | Range / modes | Why | Est. unit [VERIFY] | Source |
|---|---|---|---|---|---|
| B1 | **CC1101 module** (E07-M1101D / generic 433 or 868/915) | 300–348 / 387–464 / 779–928 MHz; OOK/ASK, 2-/4-(G)FSK, MSK; +12 dBm; SPI | Cheapest programmable sub-GHz RX/TX. OOK/ASK covers common ISM remotes; FSK for data. Pairs to `rf-tx` AFSK/OOK bench work. | $3–9 | AliExpress (Ebyte) / LCSC |
| B2 | **SX1276 LoRa module** (RA-01/02, HopeRF RFM95) | 137–1020 MHz; LoRa + FSK/GFSK/MSK/OOK; −148 dBm; +20 dBm; SPI | Far better sensitivity + link budget than CC1101; LoRa spread-spectrum and long-range FSK. Get the band variant you'll test (433 vs 868/915). | $4–10 | AliExpress (Aithinker/HopeRF) / LCSC |

Grounded: CC1101 bands/modes/SPI — TI CC1101. SX1276 137–1020 MHz, LoRa+FSK+OOK, −148 dBm, +20 dBm PA — Semtech SX1276. **Get the antenna-band-matched variant; a 915 MHz module on 433 MHz is deaf.**

### C. HF/VHF signal source (`rf-tx` CW / tone)

| # | Part | Range | Why | Est. unit [VERIFY] | Source |
|---|---|---|---|---|---|
| C1 | **Si5351A breakout** (Adafruit clone / generic) | ~8 kHz–160/200 MHz, 3 clock outputs, I2C | Clean programmable clock → QRP CW/tone source for `rf-tx` timing validation on HF/VHF. I2C from any ESP32. | $4–8 | AliExpress / LCSC |
| C2 | **Low-pass filter kit** (band-specific, e.g. 7/14 MHz QRP LPF) | per-band | Si5351 is a square-wave source — rich in harmonics. An LPF is **mandatory** before any antenna to stay legal/clean. | $3–7 | QRP-Labs / AliExpress |

> C1+C2 are a **bench/owned-antenna TX-validation** pair, milliwatt-class. Not a station. The LPF is non-optional for any radiated test.

### D. Copper / POTS front end (`legacy-hw`)

| # | Part | Function | Why | Est. unit [VERIFY] | Source |
|---|---|---|---|---|---|
| D1 | **MT8870 DTMF decoder module** | DTMF tone-pair → 4-bit (Q1–Q4) + StD strobe | Hardware ground-truth for `legacy-hw` DTMF decode; cross-check the Goertzel software decoder against silicon. | $2–5 | AliExpress / LCSC |
| D2 | **Audio codec board** (PCM5102 DAC + INMP441/ES8388 ADC, I2S) | analog ↔ I2S for ESP32 | Feeds recorded/live line audio into the ESP32 for the software DSP path (DTMF/CID/2600). | $3–8 | AliExpress / LCSC |
| D3 | **DAA / line-coupling transformer** (600:600Ω isolation xfmr + caps) OR **Silvertel Ag1171/SLIC** | POTS line ↔ audio, galvanic isolation | Safe tap onto a real pair. **−48 V / 90 V ring is a hazard** — isolation is mandatory. SLIC if you need off-hook/ring generation on an owned line. | $5–20 | AliExpress / Mouser (Silvertel) |

> Passive-only Phase 1: D1+D2+D3-transformer decode audio you supply or observe. Active injection (SLIC drive) is out of the software's built scope (`legacy-hw` injection is unbuilt) — buy the SLIC only if you're pre-staging the Axis-C interlock work, and it stays inert without it.

### E. GNSS (`gnss` position truth)

| # | Part | Constellations | Why | Est. unit [VERIFY] | Source |
|---|---|---|---|---|---|
| E1 | **u-blox NEO-M8N module** (+ active patch antenna) | GPS/GLONASS/Galileo/BeiDou, UART NMEA | Position/timing ground-truth to validate `gnss` PVT output. **NMEA fixes, NOT raw IQ** — it can't feed the spoof/jam IQ integrity path. | $12–25 | AliExpress (u-blox clones common — verify genuine) / CSGShop (genuine) |

> Honest limit: NEO-M8N gives you a *fix* to check PVT against. The `gnss` **spoof/jam integrity** payload consumes L1 **IQ**, which needs an SDR (F1), not this module.

### F. SDR — the real air-capture front end (gates `sdr-rx`, `cell-survey`, `gnss`-IQ)

| # | Part | Range | Why | Est. unit [VERIFY] | Source |
|---|---|---|---|---|---|
| F1 | **RTL-SDR Blog V4** | 500 kHz–1.766 GHz, ~2.4 MSPS, 8-bit RX-only | Matches `sdr-rx`'s 2.048 MSPS default; produces the `cf32` IQ + GSMTAP/L1 captures the RF-decode layers actually eat. **This is the single highest-value RF buy.** | $30–40 | RTL-SDR Blog official (Aliexpress store) — avoid clones |

> The ESP32 modules test the WiFi/BLE/sub-GHz/copper layers; **F1 is what makes `sdr-rx`, `cell-survey`, and GNSS-spoof testable at all.** If budget forces a cut, F1 stays.

### G. Cellular context (optional, `ss7`/`cell-survey` context only)

| # | Part | Bands | Why | Est. unit [VERIFY] | Source |
|---|---|---|---|---|---|
| G1 | **SIM7600G-H module/HAT** | Global LTE Cat-1 + GSM fallback, GNSS, UART/USB | Live cellular attach for context/registration testing. **Not** an air-interface capture device (that's the SDR + gr-gsm chain). | $30–48 | Waveshare / AliExpress |

> Borderline on the <$50 rule and only context, not signal capture. Defer unless cellular attach testing is Phase 1.

### H. Support / consumables

| # | Part | Est. [VERIFY] | Note |
|---|---|---|---|
| H1 | Antenna set (2.4 GHz, 433/868/915 SMA whips, GPS patch) | $10–20 | **Band-matched** — most common field failure is wrong-band antenna. |
| H2 | Dupont jumpers + SMA pigtails + breadboards | $8–15 | SPI/I2C wiring. |
| H3 | USB-C cables + powered hub | $8–12 | Multiple boards off one host. |
| H4 | Logic analyzer (8-ch, generic Saleae clone) | $8–12 | Debug SPI/I2C/I2S bring-up — pays for itself day one. |
| H5 | Bench power (adjustable, current-limited) | $20–35 | Current-limit protects boards during bring-up. |

---

## Kit totals (all [VERIFY], shipping excluded)

| Tier | Contents | Rough total |
|---|---|---|
| **Minimum viable RF kit** | A1, A2, B1, B2, F1, H1–H2 | **~$75–110** |
| **Full Phase 1 (recommended)** | A1–A3, B1–B2, C1–C2, D1–D3, E1, F1, H1–H5 | **~$180–290** |
| **+ cellular** | add G1 | **+$30–48** |

No single line item exceeds $50 (G1 is the only one that approaches it). Totals are kit-level.

---

## Buying guidance (grounded, opinionated)

- **Genuine where it matters:** RTL-SDR Blog V4 (F1) and u-blox (E1) have rampant clones — buy F1 from the official RTL-SDR Blog store, E1 from CSGShop or verify the u-blox chip mark. Clones cost you sensitivity and hours.
- **Generic where it doesn't:** ESP32 dev boards, CC1101, MT8870, Si5351 breakouts are commodity — cheapest credible AliExpress/LCSC seller with real reviews is fine.
- **LCSC** (Shenzhen) is the sweet spot for the ICs/modules (B, C, D) — real part numbers, low prices, one consolidated order. **AliExpress** for dev boards + antennas + consumables. **Alibaba** only if buying at MOQ quantity (not Phase 1).
- **Band-match everything sub-GHz:** decide 433 vs 868/915 for your region *before* ordering B1/B2/H1 — mismatched band = dead RX.
- **Order the LPF (C2) with the Si5351 (C1)** — never radiate the raw square wave.

## What Phase 1 deliberately does NOT cover

- **Live SS7/Diameter** (`ss7` `live` seam) — needs a provisioned point code / carrier peering, not hardware you buy. Test `ss7` on recorded SCTP pcaps.
- **Active copper injection** (`legacy-hw` unbuilt) — no injector + no hardware-safety interlock exists; D3-SLIC stays inert.
- **RF transmit past bench/QRP** — `rf-tx` `device` sink is unbuilt; C1/B-series TX is owned-antenna validation only.
- **Wideband/LTE air capture** — RTL-SDR (F1) tops out ~1.766 GHz / 2.4 MSPS; HackRF ($150+, over budget) is the next tier for 1–6 GHz TX/RX.

---

### Sources
Espressif module page (ESP32-C3/C6/S3 radios); TI CC1101 (bands/modes/SPI); Semtech SX1276 (137–1020 MHz, LoRa/FSK/OOK, −148 dBm/+20 dBm); u-blox (GPS/GLONASS/Galileo/BeiDou); MT8870 (DTMF→4-bit, general datasheet knowledge — confirm at purchase); RTL-SDR Blog V4 (per `docs/DEVICES.md`, grounded). **All prices are unverified market estimates — confirm on the retailer before purchase.**
