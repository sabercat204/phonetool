//! `phonetool` — the workbench console.
//!
//! Sprint 1 wired the passive vertical slice (offline numintel, ungated). Sprint 2
//! adds the first **active** capability — `sip enum` — and with it the first
//! end-to-end exercise of the auth-gate spine: the command routes through
//! [`Gate::request_ip`], which mints an unforgeable `Grant` (or refuses, fail-
//! closed), and every decision plus the resulting plugin event lands on one
//! [`CaptureBus`] timeline. numintel still never touches the gate; SIP always does.

use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use phonetool_attest::AttestInspect;
use phonetool_baittriage::BaitTriage;
use phonetool_cell_survey::CellSurvey;
use phonetool_core::{
    ActivePlugin, CaptureBus, Command as PluginCommand, DispatchError, Gate, IntelStore,
    IpAuthorization, Plugin, PluginRegistry, SqliteStore, TxAuthorization, TxPlugin,
};
use phonetool_gnss::GnssRx;
use phonetool_legacy_hw::{LineConfig, LineHw};
use phonetool_numintel::NumIntel;
use phonetool_rf_tx::RfTx;
use phonetool_sdr_rx::SdrRx;
use phonetool_sip::SipRecon;
use phonetool_ss7::Ss7Analyzer;
use phonetool_wardial::WarDial;
use phonetool_wardial::originate::{SweepConfig, TrunkConfig};

/// phonetool — full-spectrum telecom workbench.
#[derive(Parser)]
#[command(name = "phonetool", version, about)]
struct Cli {
    /// Path to the offline intel store. Omit for an ephemeral in-memory store.
    #[arg(long, global = true)]
    store: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List registered plugins.
    Plugins,
    /// Look up number intelligence (offline cache; passive, ungated).
    Lookup {
        /// The number to look up (E.164 or a national number with country code).
        number: String,
    },
    /// Seed a cache record (dev/test aid — populate the offline store by hand).
    Seed {
        /// The number key.
        number: String,
        /// The JSON (or plain-text) intelligence record to cache.
        record: String,
    },
    /// SIP recon (ACTIVE — requires an authorization basis; routes through the gate).
    Sip {
        #[command(subcommand)]
        op: SipOp,
    },
    /// SIP-origination DID wardial (ACTIVE + BILLABLE — routes through the gate;
    /// each DID is a real, metered, attributable call. Requires an authorization
    /// basis AND an explicit cost/attribution acknowledgement).
    Wardial {
        /// The DID range to sweep, as the gate authorizes it: a single DID
        /// (`+15125550100`) or a span (`+1512555:0100-0109`). This is the target
        /// the gate authorizes; origination acts on it and nothing else.
        range: String,
        /// Your assertion of why this is authorized (owned DIDs, named engagement)
        /// AND your cost/attribution acknowledgement. Logged verbatim to the
        /// consent timeline. REQUIRED — an empty basis is a fail-closed refusal.
        #[arg(long)]
        basis: String,
        /// REQUIRED affirmative: you accept this run is billable (metered on the
        /// trunk), attributable (identified by the trunk account + caller-ID), and
        /// can complete a call to a real person. Without it, no grant is requested
        /// and no call is placed.
        #[arg(long = "i-accept-billing-and-attribution")]
        accept_billing: bool,
        /// Trunk host:port to originate through (the "device"). Absent, the
        /// origination path is inert — no PSTN call is placed.
        #[arg(long)]
        trunk_host: Option<String>,
        /// Outbound caller-ID to present (attribution). Required with --trunk-host.
        #[arg(long)]
        caller_id: Option<String>,
    },
    /// SDR receive (PASSIVE — no gate, no hardware required; operates on IQ files).
    Sdr {
        #[command(subcommand)]
        op: SdrOp,
    },
    /// GNSS receive + integrity (PASSIVE — no gate; spoof/jam detection from IQ files).
    Gnss {
        /// Path to a raw cf32 IQ capture at GPS L1 (1575.42 MHz).
        file: String,
    },
    /// STIR/SHAKEN attestation inspection (PASSIVE — no gate; structural, offline).
    Attest {
        /// An Identity header / PASSporT inline, or `@path` to a file / SIP message.
        input: String,
    },
    /// Cellular survey + rogue-BTS detection (PASSIVE — no gate; decodes a
    /// recorded GSMTAP-over-pcap capture, no radio required).
    CellSurvey {
        /// Path to a recorded GSMTAP-over-pcap capture file.
        file: String,
    },
    /// RF transmit (ACTIVE, Axis-B — routes through the regulatory gate; renders a
    /// CW/AFSK waveform to a FILE. No device sink exists in this build, so NO real
    /// emission is possible — rendering to disk is not transmitting).
    RfTx {
        /// The modulation scheme: `cw` or `afsk` (fm/ssb are declared seams).
        scheme: String,
        /// The requested transmit frequency in Hz (validated against the band the
        /// grant authorizes — a grant for one band cannot key another).
        #[arg(long)]
        freq_hz: u64,
        /// The payload: CW text, or `SRC>DEST:info` for an AFSK/AX.25 UI frame.
        #[arg(long)]
        payload: String,
        /// The band this transmission is authorized on (e.g. "2m", "70cm"). The
        /// regulatory authority — read into the TxGrant, never trusted from freq.
        #[arg(long)]
        band: String,
        /// Authorized transmit power in dBm. Capped at the band's regulatory maximum.
        #[arg(long)]
        power_dbm: f64,
        /// The regulatory/license basis for transmitting (e.g. a call sign + license
        /// class). Logged verbatim to the consent timeline. REQUIRED — empty is a
        /// fail-closed refusal.
        #[arg(long)]
        license: String,
        /// Output file for the rendered waveform (raw little-endian f32 / cf32).
        #[arg(long, default_value = "rf-tx-render.cf32")]
        out: std::path::PathBuf,
    },
    /// SS7/Diameter signalling analysis (PASSIVE — no gate; decodes a supplied
    /// SIGTRAN/Diameter capture and flags location-disclosure / intercept-enabling
    /// operations, no signalling link required).
    Ss7 {
        /// The capture source: a path to a `.pcap`/`.pcapng` (SCTP-carried
        /// SIGTRAN/Diameter), a path to a hex PDU dump, or `hex:<tokens>` inline.
        source: String,
    },
    /// Copper line I/O (PASSIVE — no gate; DTMF/MF/CID decode, line sense, tone
    /// synth to a WAV. No hardware required; active injection is NOT built).
    Line {
        #[command(subcommand)]
        op: LineOp,
    },
    /// Fraud-caller footprint triage (PASSIVE — no gate; extracts indicators from
    /// operator-supplied artifacts and correlates them against the offline store).
    Triage {
        /// The artifact bundle as inline JSON (an object with optional fields:
        /// phone, identity, agency_claim, urls, wallets, emails, gift_card_rails,
        /// transcript, email_body, source_capture). All values are opaque data —
        /// nothing in the bundle is ever fetched or opened.
        bundle: String,
    },
}

#[derive(Subcommand)]
enum SdrOp {
    /// Compute power spectral density of an IQ file.
    Sweep {
        /// Path to a raw cf32 IQ file.
        file: String,
    },
    /// Detect and classify signals in an IQ file.
    Identify {
        /// Path to a raw cf32 IQ file.
        file: String,
    },
    /// Demodulate an IQ file (FM, AM, SSB, or digital).
    Demod {
        /// Path to a raw cf32 IQ file.
        file: String,
        /// Demod mode: fm, am, ssb, or digital.
        mode: String,
    },
}

#[derive(Subcommand)]
enum LineOp {
    /// Decode DTMF/MF/2600 tones from a WAV file.
    Decode {
        /// Path to a WAV file (16-bit PCM or 32-bit float, mono or multi-channel).
        file: String,
    },
    /// Decode a Bell-202 Caller-ID FSK burst from a WAV file. The recovered number
    /// is an OBSERVATION on the wire, never a verified identity (CID is spoofable).
    Cid {
        /// Path to a WAV file containing the CID burst.
        file: String,
    },
    /// Classify line electrical state from a recorded sense trace (voltage samples).
    Sense {
        /// The trace: whitespace/comma-separated tip-ring voltage samples.
        trace: String,
    },
    /// Synthesize DTMF digits (or `2600`) to a WAV file. INERT — renders to a file,
    /// no physical line is ever driven.
    Synth {
        /// The DTMF digit string (e.g. "18005551234") or the literal `2600`.
        spec: String,
        /// Output WAV path.
        #[arg(long, default_value = "line-synth.wav")]
        out: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum SipOp {
    /// Enumerate SIP extensions on a target (active op against the gate-authorized target).
    Enum {
        /// The target SIP endpoint as host:port (e.g. 192.0.2.10:5060). This is the
        /// address the gate authorizes; the plugin acts on it and nothing else.
        target: String,
        /// Comma-separated extensions to probe (e.g. "100,101,1000,admin").
        extensions: String,
        /// Your assertion of why this is authorized (owned infra, named engagement,
        /// defense). Logged verbatim to the consent timeline. REQUIRED — an empty
        /// basis is a fail-closed refusal.
        #[arg(long)]
        basis: String,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Offline-first: the store is the default source of truth.
    let store: Arc<dyn IntelStore> = match &cli.store {
        Some(path) => Arc::new(SqliteStore::open(path)?),
        None => Arc::new(SqliteStore::open_in_memory()?),
    };

    // Build the shell: one capture bus (also the gate's consent sink), a registry
    // with the passive and active plugins snapped in. Durable JSONL sink alongside
    // the store when --store is provided.
    let bus = match &cli.store {
        Some(store_path) => {
            let capture_path = store_path.with_extension("capture.jsonl");
            CaptureBus::with_file(&capture_path)
        }
        None => CaptureBus::new(),
    };
    let mut registry = PluginRegistry::new();
    registry.register(Arc::new(NumIntel::new(Arc::clone(&store))))?;
    registry.register(Arc::new(SdrRx::new()))?;
    registry.register(Arc::new(GnssRx::new()))?;
    registry.register(Arc::new(AttestInspect::new()))?;
    registry.register(Arc::new(CellSurvey::new()))?;
    registry.register(Arc::new(BaitTriage::new(Arc::clone(&store))))?;
    registry.register(Arc::new(Ss7Analyzer::new()))?;
    // Register a display-only default LineHw so `plugins` lists it (holds the
    // exclusive Wireline port). The synth handler below builds a LineHw carrying the
    // per-invocation output path and dispatches on it directly; decode/cid/sense go
    // through the registry. All four verbs are passive — no gate, ever.
    registry.register(Arc::new(LineHw::new()))?;
    // Register a display-only default RfTx so `plugins` lists it (holds the RfTx
    // transducer). The actual dispatch (below) builds an RfTx carrying the
    // per-invocation output path and calls dispatch_tx on it directly — the
    // security property is identical (dispatch_tx requires the gate-minted TxGrant
    // either way; a TxGrant has no public constructor).
    registry.register_tx(Arc::new(RfTx::new()))?;
    registry.register_active(Arc::new(SipRecon::new()))?;
    // Register a display-only default WarDial so `plugins` lists it. The actual
    // dispatch (below) builds a WarDial carrying the per-invocation TrunkConfig and
    // calls dispatch_active on it directly — the security property is identical
    // (dispatch_active requires the gate-minted Grant either way; a Grant has no
    // public constructor), and this keeps the trunk config out of the registry.
    registry.register_active(Arc::new(WarDial::new()))?;

    match &cli.command {
        Commands::Plugins => {
            for m in registry.manifests() {
                println!(
                    "{:<12} v{:<8} [{:?}/{:?}]  {}",
                    m.name, m.version, m.transducer, m.capability, m.summary
                );
            }
            Ok(())
        }
        Commands::Seed { number, record } => {
            // Validate the key through the same boundary the plugin uses.
            let n = phonetool_numintel::number::Number::parse(number)?;
            store.put(phonetool_numintel::lookup::NAMESPACE, n.as_e164(), record)?;
            println!("seeded {}", n.as_e164());
            Ok(())
        }
        Commands::Lookup { number } => {
            let cmd = PluginCommand {
                verb: "lookup".to_owned(),
                arg: number.clone(),
            };
            match registry.dispatch("numintel", &cmd) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                // An empty/useless result is a failure surfaced to the operator,
                // not a silent success — the degenerate-case discipline.
                Err(DispatchError::Plugin(e)) => Err(Box::new(e)),
                Err(e) => Err(Box::new(e)),
            }
        }
        Commands::Sdr { op } => {
            let cmd = match op {
                SdrOp::Sweep { file } => PluginCommand {
                    verb: "sweep".to_owned(),
                    arg: file.clone(),
                },
                SdrOp::Identify { file } => PluginCommand {
                    verb: "identify".to_owned(),
                    arg: file.clone(),
                },
                SdrOp::Demod { file, mode } => PluginCommand {
                    verb: "demod".to_owned(),
                    arg: format!("{file} {mode}"),
                },
            };
            match registry.dispatch("sdr", &cmd) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                Err(DispatchError::Plugin(e)) => Err(Box::new(e)),
                Err(e) => Err(Box::new(e)),
            }
        }
        Commands::Gnss { file } => {
            let cmd = PluginCommand {
                verb: "fix".to_owned(),
                arg: file.clone(),
            };
            match registry.dispatch("gnss", &cmd) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                Err(DispatchError::Plugin(e)) => Err(Box::new(e)),
                Err(e) => Err(Box::new(e)),
            }
        }
        Commands::Attest { input } => {
            // PASSIVE: no gate. Reading what a call claims about itself is
            // observation-coded (numintel precedent) — dispatch(), never
            // dispatch_active.
            let cmd = PluginCommand {
                verb: "inspect".to_owned(),
                arg: input.clone(),
            };
            match registry.dispatch("attest", &cmd) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                Err(DispatchError::Plugin(e)) => Err(Box::new(e)),
                Err(e) => Err(Box::new(e)),
            }
        }
        Commands::CellSurvey { file } => {
            // PASSIVE: no gate. Decoding broadcast cell info is observation-coded
            // (numintel/attest precedent) — dispatch(), never dispatch_active.
            let cmd = PluginCommand {
                verb: "survey".to_owned(),
                arg: file.clone(),
            };
            match registry.dispatch("cell-survey", &cmd) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    // The bulk capture stays out of the timeline by reference: the
                    // survey Event carries only decoded cells, and the pcap itself
                    // is recorded as a CaptureRef (Req 7.1/7.2).
                    bus.record_capture(phonetool_core::CaptureKind::Pcap, file.clone());
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                Err(DispatchError::Plugin(e)) => Err(Box::new(e)),
                Err(e) => Err(Box::new(e)),
            }
        }
        Commands::RfTx {
            scheme,
            freq_hz,
            payload,
            band,
            power_dbm,
            license,
            out,
        } => {
            // THE REGULATORY GATE (Axis B). request_tx is fail-closed on an empty
            // band/license or non-finite power, and logs the decision (grant or
            // refusal) to the bus before returning. There is no other way to obtain
            // the TxGrant that dispatch_tx requires — and no device sink exists in
            // this build, so even with the grant the render goes to a FILE.
            let gate = Gate::new(&bus);
            let grant = gate.request_tx(TxAuthorization {
                band: band.clone(),
                power_dbm: *power_dbm,
                license_basis: license.clone(),
            })?;

            // Build the plugin for this invocation, carrying the output path. The
            // band/power/license live in the grant; freq + payload go in the arg.
            let plugin = RfTx::with_config(phonetool_rf_tx::TxConfig {
                out_path: out.clone(),
                ..Default::default()
            });
            let cmd = PluginCommand {
                verb: scheme.clone(),
                arg: serde_json::json!({ "freq_hz": freq_hz, "payload": payload }).to_string(),
            };
            // dispatch_tx takes the TxGrant; the grant carries the regulatory
            // authority, the command carries only the operation parameters.
            match plugin.dispatch_tx(&cmd, &grant) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    // The rendered waveform is a bulk artifact: record it by-path
                    // (Iq domain) on the timeline, never inlined.
                    bus.record_capture(phonetool_core::CaptureKind::Iq, out.display().to_string());
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                Err(e) => Err(Box::new(e)),
            }
        }
        Commands::Ss7 { source } => {
            // PASSIVE: no gate. Decoding a capture the operator holds is
            // observation-coded (numintel/attest/cell-survey precedent) —
            // dispatch(), never dispatch_active. The analyzer transmits nothing.
            let cmd = PluginCommand {
                verb: "analyze".to_owned(),
                arg: source.clone(),
            };
            match registry.dispatch("ss7", &cmd) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    // A .pcap is a bulk artifact: record it by-path on the timeline
                    // (never inlined), mirroring cell-survey's discipline. A hex
                    // dump / hex: arg is not a file, so only record real pcap paths.
                    if source.ends_with(".pcap") || source.ends_with(".pcapng") {
                        bus.record_capture(phonetool_core::CaptureKind::Pcap, source.clone());
                    }
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                Err(DispatchError::Plugin(e)) => Err(Box::new(e)),
                Err(e) => Err(Box::new(e)),
            }
        }
        Commands::Triage { bundle } => {
            // PASSIVE: no gate. Extracting indicators from artifacts the operator
            // was handed is observation-coded (numintel/attest precedent) —
            // dispatch(), never dispatch_active. Nothing in the bundle is fetched.
            let cmd = PluginCommand {
                verb: "triage".to_owned(),
                arg: bundle.clone(),
            };
            match registry.dispatch("baittriage", &cmd) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                Err(DispatchError::Plugin(e)) => Err(Box::new(e)),
                Err(e) => Err(Box::new(e)),
            }
        }
        Commands::Line { op } => {
            // PASSIVE: no gate. Decode/sense/synth over supplied audio and traces is
            // observation/file-rendering — dispatch(), never any gated path. Active
            // physical injection is NOT built (needs the Axis-C WireGrant AND a
            // hardware-safety interlock, neither reachable here).
            match op {
                LineOp::Synth { spec, out } => {
                    // synth carries a per-invocation output path, so build the plugin
                    // for this call (the wardial/rf-tx pattern) and dispatch directly.
                    let plugin = LineHw::with_config(LineConfig {
                        out_path: out.clone(),
                        ..Default::default()
                    });
                    let cmd = PluginCommand {
                        verb: "synth".to_owned(),
                        arg: spec.clone(),
                    };
                    match plugin.dispatch(&cmd) {
                        Ok(event) => {
                            bus.record_event(event.clone());
                            // The rendered WAV is a bulk artifact: record it by-path.
                            bus.record_capture(
                                phonetool_core::CaptureKind::CallAudio,
                                out.display().to_string(),
                            );
                            println!("{}", event.summary);
                            println!("{}", serde_json::to_string_pretty(&event.data)?);
                            Ok(())
                        }
                        Err(e) => Err(Box::new(e)),
                    }
                }
                _ => {
                    let cmd = match op {
                        LineOp::Decode { file } => PluginCommand {
                            verb: "decode".to_owned(),
                            arg: file.clone(),
                        },
                        LineOp::Cid { file } => PluginCommand {
                            verb: "cid".to_owned(),
                            arg: file.clone(),
                        },
                        LineOp::Sense { trace } => PluginCommand {
                            verb: "sense".to_owned(),
                            arg: trace.clone(),
                        },
                        LineOp::Synth { .. } => unreachable!("handled above"),
                    };
                    match registry.dispatch("line", &cmd) {
                        Ok(event) => {
                            bus.record_event(event.clone());
                            println!("{}", event.summary);
                            println!("{}", serde_json::to_string_pretty(&event.data)?);
                            Ok(())
                        }
                        Err(DispatchError::Plugin(e)) => Err(Box::new(e)),
                        Err(e) => Err(Box::new(e)),
                    }
                }
            }
        }
        Commands::Wardial {
            range,
            basis,
            accept_billing,
            trunk_host,
            caller_id,
        } => {
            // Requirement 8: surface the cost/attribution notice and require an
            // explicit affirmative BEFORE the grant is even requested. Absent the
            // acknowledgement, no Grant is requested and no call is placed.
            eprintln!(
                "wardial: SIP origination is BILLABLE (metered on the trunk), \
                 ATTRIBUTABLE (identified by the trunk account + caller-ID), and \
                 can COMPLETE A CALL TO A REAL PERSON (a 200 OK means a phone rang)."
            );
            if !accept_billing {
                return Err(Box::<dyn std::error::Error>::from(
                    "refused: pass --i-accept-billing-and-attribution to acknowledge that this \
                     run is billable and attributable; no grant requested, no call placed",
                ));
            }

            // Build the WarDial for this invocation. A trunk host lights up the
            // real origination path; absent it, the path is inert (loopback-only,
            // enforced in originate::sweep). The SIP auth secret is provisioned out
            // of band, NEVER via the CLI/basis/arg (Requirement 8.4) — here it is
            // left empty; a real deployment injects it into TrunkConfig elsewhere.
            let plugin = match (trunk_host, caller_id) {
                (Some(host), Some(cid)) => WarDial::with_trunk(
                    SweepConfig::default(),
                    TrunkConfig {
                        host: host.clone(),
                        caller_id: cid.clone(),
                        secret: String::new(),
                    },
                ),
                (Some(_), None) => {
                    return Err(Box::<dyn std::error::Error>::from(
                        "--trunk-host requires --caller-id (the attribution the trunk presents)",
                    ));
                }
                _ => WarDial::new(), // inert: no trunk → origination refuses non-loopback
            };

            // THE GATE. Fail-closed on empty target/basis; logs the decision
            // (grant or refusal) to the bus before returning. The DID range is the
            // gate's target — the plugin reads it from Grant::target, never the cmd.
            let gate = Gate::new(&bus);
            let grant = gate.request_ip(IpAuthorization {
                target: range.clone(),
                basis: basis.clone(),
            })?;

            let cmd = PluginCommand {
                verb: "sweep".to_owned(),
                arg: String::new(), // no range in the command — it lives in the grant
            };
            match plugin.dispatch_active(&cmd, &grant) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                Err(e) => Err(Box::new(e)),
            }
        }
        Commands::Sip {
            op:
                SipOp::Enum {
                    target,
                    extensions,
                    basis,
                },
        } => {
            // THE GATE. request_ip is fail-closed on an empty target/basis and logs
            // the decision (grant or refusal) to the bus before returning. There is
            // no other way to obtain the Grant that dispatch_active requires.
            let gate = Gate::new(&bus);
            let grant = gate.request_ip(IpAuthorization {
                target: target.clone(),
                basis: basis.clone(),
            })?;

            let cmd = PluginCommand {
                verb: "enum".to_owned(),
                arg: extensions.clone(),
            };
            // The Grant carries the authorized target; the plugin acts on it.
            match registry.dispatch_active("sip", &cmd, &grant) {
                Ok(event) => {
                    bus.record_event(event.clone());
                    println!("{}", event.summary);
                    println!("{}", serde_json::to_string_pretty(&event.data)?);
                    Ok(())
                }
                Err(DispatchError::Plugin(e)) => Err(Box::new(e)),
                Err(e) => Err(Box::new(e)),
            }
        }
    }
}
