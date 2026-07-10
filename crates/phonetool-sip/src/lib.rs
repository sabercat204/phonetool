//! `phonetool-sip` — the first **active** capability, and the first exercise of
//! the auth-gate spine end-to-end.
//!
//! numintel (Sprint 1) is `Passive` and never touches the gate. SIP recon is the
//! opposite: it transmits to a remote, so it is Axis-A active and implements
//! [`ActivePlugin`], whose `dispatch_active` **requires a `Grant`**. A `Grant` has
//! no public constructor — the only source is a successful
//! [`Gate::request_ip`](phonetool_core::Gate::request_ip) — so an enumeration is
//! *unrepresentable* without the gate having authorized it and logged the attempt.
//!
//! **The target is the gate's, not the caller's.** `dispatch_active` reads the
//! host:port from [`Grant::target`](phonetool_core::Grant::target); the command's
//! `arg` carries only the *operation's* parameters (which extensions to probe).
//! There is no code path by which this plugin touches a remote the gate did not
//! name — the second-target injection hole is closed by construction.
//!
//! Uses `std::net` only: no HTTP client, no async runtime, no SIP crate. The
//! socket fires solely inside an authorized, gated op, and the crate adds **zero
//! egress dependencies** — `cargo tree` shows nothing new, so the static-musl
//! offline story is unchanged. What ships in the default binary is an *inert*
//! active path: present, but unreachable without a `Grant`.

pub mod enumerate;
pub mod message;

use phonetool_core::{
    ActivePlugin, CapabilityClass, Command, Event, Grant, Manifest, PluginError, Transducer,
};

use crate::enumerate::{EnumConfig, EnumError, Finding};

/// The SIP extension-enumeration plugin. Stateless: each dispatch runs one gated,
/// bounded enumeration and returns.
///
/// You cannot enumerate without the gate having authorized it. `dispatch_active`
/// takes `&Grant`, and a `Grant` has no public constructor — the only source is a
/// successful [`Gate::request_ip`](phonetool_core::Gate::request_ip). Fabricating
/// one to skip the gate does not compile:
///
/// ```compile_fail
/// use phonetool_sip::SipRecon;
/// use phonetool_core::{ActivePlugin, Command, Grant};
///
/// let plugin = SipRecon::new();
/// let cmd = Command { verb: "enum".into(), arg: "100".into() };
/// // `Grant` has private fields and no public constructor — this line is the
/// // compile error. There is no legal way here to reach `dispatch_active`.
/// let forged = Grant { target: "victim:5060".into(), basis: String::new() };
/// let _ = plugin.dispatch_active(&cmd, &forged);
/// ```
#[derive(Debug, Default)]
pub struct SipRecon {
    cfg: EnumConfig,
}

impl SipRecon {
    /// Build with default enumeration knobs (conservative timeout, ephemeral bind).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with an explicit [`EnumConfig`] (used by tests to point the bind at
    /// loopback and shorten the timeout).
    #[must_use]
    pub fn with_config(cfg: EnumConfig) -> Self {
        Self { cfg }
    }
}

impl ActivePlugin for SipRecon {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "sip".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::Ip,
            capability: CapabilityClass::ActiveIp,
            summary: "SIP extension enumeration over UDP (active; requires an IP grant)".to_owned(),
        }
    }

    fn dispatch_active(&self, cmd: &Command, grant: &Grant) -> Result<Event, PluginError> {
        if cmd.verb != "enum" {
            return Err(PluginError::Unsupported(cmd.verb.clone()));
        }

        // The target is what the gate authorized — never taken from the command.
        let target = grant.target();
        let host = target
            .rsplit_once(':')
            .map(|(h, _port)| h)
            .unwrap_or(target);

        // The command arg is the operation's own parameter: a comma-separated
        // extension list. Validate/clean it at this boundary.
        let extensions = parse_extensions(&cmd.arg)?;

        // A session token derived from grant fields (no RNG dependency): unique per
        // (target, basis) so overlapping runs don't reuse SIP transaction ids.
        let session = short_session(grant);

        let findings = enumerate::run(target, host, &extensions, &session, &self.cfg)
            .map_err(map_enum_error)?;

        // Degenerate-case discipline: if NOTHING answered, the probe was useless —
        // likely the target is not a reachable SIP endpoint. That is a failure the
        // operator sees, not an empty success. If at least one probe responded,
        // "these extensions are absent" is itself a real, reportable result.
        let responded = findings.iter().filter(|f| f.responded).count();
        if responded == 0 {
            return Err(PluginError::Empty(format!(
                "no SIP response from {target} across {} probe(s); target may not be a reachable SIP endpoint",
                findings.len()
            )));
        }

        let existing: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.verdict == Some(message::Verdict::Exists))
            .collect();

        let data = serde_json::json!({
            "target": target,
            "probed": findings.len(),
            "responded": responded,
            "exists": existing.len(),
            "findings": findings,
        });

        Ok(Event {
            source: "sip".to_owned(),
            summary: format!(
                "sip enum {target}: {}/{} responded, {} extension(s) exist",
                responded,
                findings.len(),
                existing.len()
            ),
            data,
        })
    }
}

/// Parse and clean the comma-separated extension list from the command arg.
///
/// Boundary validation for untrusted operator input before it becomes part of a
/// SIP request URI: each extension may contain only characters legal in a SIP
/// user part that we choose to allow (alphanumerics, `.`, `-`, `_`). Anything
/// else is rejected rather than injected into the wire message.
fn parse_extensions(arg: &str) -> Result<Vec<String>, PluginError> {
    let mut out = Vec::new();
    for raw in arg.split(',') {
        let ext = raw.trim();
        if ext.is_empty() {
            continue;
        }
        if !ext
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            return Err(PluginError::InvalidInput(format!(
                "illegal character in extension {ext:?}"
            )));
        }
        out.push(ext.to_owned());
    }
    if out.is_empty() {
        return Err(PluginError::InvalidInput(
            "no extensions supplied (comma-separated list expected)".to_owned(),
        ));
    }
    Ok(out)
}

/// A short, RNG-free session token derived from the grant, used to seed unique SIP
/// transaction identifiers. Deterministic per grant, which is fine — a grant is
/// minted per authorized operation and is not reused.
fn short_session(grant: &Grant) -> String {
    // FNV-1a over target+basis → 16 hex chars. Cheap, dependency-free, and only
    // needs to be collision-resistant across concurrent runs, not cryptographic.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in grant.target().bytes().chain(grant.basis().bytes()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Map the enumerate layer's error into a plugin error at the trait boundary.
fn map_enum_error(e: EnumError) -> PluginError {
    match e {
        EnumError::NoExtensions => PluginError::InvalidInput(e.to_string()),
        EnumError::TooMany(_) | EnumError::BadTarget(_) => PluginError::InvalidInput(e.to_string()),
        EnumError::Socket(_) => PluginError::Backend(e.to_string()),
    }
}
