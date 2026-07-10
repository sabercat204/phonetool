//! `phonetool-wardial` — DID-range enumeration by SIP origination (the modern
//! wardial), and the workbench's **second** active capability after phonetool-sip.
//!
//! Like sip, wardial is Axis-A active: it implements [`ActivePlugin`], whose
//! `dispatch_active` **requires a `Grant`**. A `Grant` has no public constructor —
//! the only source is a successful
//! [`Gate::request_ip`](phonetool_core::Gate::request_ip) — so an origination is
//! *unrepresentable* without the gate having authorized it and logged the attempt.
//! It inherits sip's invariants wholesale: the target (here the DID range) comes
//! from [`Grant::target`](phonetool_core::Grant::target), the response bytes are
//! untrusted, execution is bounded, and a run that reaches nothing is a failure.
//!
//! **What makes wardial heavier than sip.** sip's OPTIONS probe rings no one and
//! costs nothing; wardial originates *real calls* that are **billable** (metered
//! on a trunk), **attributable** (the trunk account + caller-ID identify the
//! operator), and **can complete to a live human** (a `200 OK` means a phone
//! rang). Two consequences beyond sip: (1) conservative bounds — a small
//! `max_range`, a mandatory rate limit — because each unit is a metered call, not
//! a free packet; and (2) a cost/attribution acknowledgement the CLI forces
//! *before* the grant is even requested (Requirement 8).
//!
//! **Honest offline story (Requirement 9.3).** Uses `std::net` only; adds **zero
//! egress dependencies**. The default binary contains an *inert* origination path:
//! present, but unreachable without BOTH a `Grant` and a [`TrunkConfig`]. Without
//! a trunk, [`originate::sweep`] refuses any non-loopback target — a real
//! fail-closed property, not a doc promise. Do NOT claim "no active code".
//!
//! **What is NOT built (declared seams, blocked on operator Open Questions).**
//!   * **Media / RTP path (OQ6, Requirement 10).** No RTP receive, no codec decode
//!     exists anywhere in the workbench. So [`MediaDisposition`] is always
//!     [`NotAnalyzed`](classify::MediaDisposition::NotAnalyzed): the whole
//!     SIT/fax/modem/voice tier has no substrate yet. wardial ships at
//!     `SipDisposition`-only fidelity (live/disconnected/busy across a block),
//!     which is fully useful on its own.
//!   * **Grounded tone constants (OQ4).** The [`tone`] Goertzel algorithm ships;
//!     the SIT/CNG/CED frequencies/thresholds it would be *configured with* are
//!     NOT invented — they must be cited from ITU-T/Telcordia at build time.
//!   * **Grounded trunk-policy bounds (OQ1/OQ2).** `max_range`, rate, and
//!     concurrency ship as a conservative *safety floor*, explicitly flagged as
//!     ungrounded, never as an authoritative provider value.
//!
//! ## Example (compile-fail proof: reaching `dispatch_active` needs a real Grant)
//!
//! ```compile_fail
//! use phonetool_wardial::WarDial;
//! use phonetool_core::{ActivePlugin, Command, Grant};
//!
//! let plugin = WarDial::new();
//! let cmd = Command { verb: "sweep".into(), arg: String::new() };
//! // `Grant` has private fields and no public constructor — this line is the
//! // compile error. There is no legal way here to reach `dispatch_active`.
//! let forged = Grant { target: "+1512555:0100-0109".into(), basis: String::new() };
//! let _ = plugin.dispatch_active(&cmd, &forged);
//! ```

pub mod classify;
pub mod message;
pub mod originate;
pub mod tone;

use phonetool_core::{
    ActivePlugin, CapabilityClass, Command, Event, Grant, Manifest, PluginError, Transducer,
};

use crate::classify::SipDisposition;
use crate::originate::{SweepConfig, SweepError, TrunkConfig};

/// The SIP-origination DID-range enumeration plugin.
///
/// Holds a [`SweepConfig`] (bounds/pacing), an optional [`TrunkConfig`] (the
/// device seam — absent, origination is inert / loopback-only), and an optional
/// loopback target used only by tests to point the socket at a loopback responder
/// when no trunk is configured.
#[derive(Debug, Default)]
pub struct WarDial {
    cfg: SweepConfig,
    trunk: Option<TrunkConfig>,
    /// Test-only: when no trunk is configured, the loopback `host:port` to
    /// originate against (an operator-owned responder that rings no one). In the
    /// field a real run always carries a `TrunkConfig`; this stays `None`.
    loopback_target: Option<String>,
}

impl WarDial {
    /// Build with default bounds and no trunk (inert origination path).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with an explicit trunk configured (the live origination path).
    #[must_use]
    pub fn with_trunk(cfg: SweepConfig, trunk: TrunkConfig) -> Self {
        Self {
            cfg,
            trunk: Some(trunk),
            loopback_target: None,
        }
    }

    /// Build for a loopback test: no trunk, origination pointed at an
    /// operator-owned loopback responder. Building and firing here rings no one
    /// and costs nothing (the responder is on `127.0.0.1`).
    #[must_use]
    pub fn with_loopback(cfg: SweepConfig, loopback_target: String) -> Self {
        Self {
            cfg,
            trunk: None,
            loopback_target: Some(loopback_target),
        }
    }
}

impl ActivePlugin for WarDial {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "wardial".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            transducer: Transducer::Ip,
            capability: CapabilityClass::ActiveIp,
            summary:
                "DID-range enumeration by SIP origination (active; billable; requires an IP grant)"
                    .to_owned(),
        }
    }

    fn dispatch_active(&self, cmd: &Command, grant: &Grant) -> Result<Event, PluginError> {
        if cmd.verb != "sweep" {
            return Err(PluginError::Unsupported(cmd.verb.clone()));
        }

        // The DID range is what the gate authorized — read from Grant::target,
        // NEVER from the command. The command arg carries only operation
        // parameters (reserved; unused today) and is explicitly not consulted for
        // a range (Requirement 2).
        let dids = parse_range(grant.target(), self.cfg.max_range)?;

        // Resolve the socket destination + URI host + caller-ID:
        //   * trunk present  → send to the trunk, present its caller-ID (attribution)
        //   * loopback (test) → send to the operator-owned responder
        //   * neither         → inert: no trunk configured, refuse (Backend)
        let (target, uri_host, caller_id) = match (&self.trunk, &self.loopback_target) {
            (Some(t), _) => (
                t.host.clone(),
                t.host
                    .rsplit_once(':')
                    .map_or(t.host.clone(), |(h, _)| h.to_owned()),
                t.caller_id.clone(),
            ),
            (None, Some(lb)) => (
                lb.clone(),
                lb.rsplit_once(':')
                    .map_or(lb.clone(), |(h, _)| h.to_owned()),
                "anonymous".to_owned(),
            ),
            (None, None) => {
                return Err(PluginError::Backend(
                    "no trunk configured; origination path is inert (supply a TrunkConfig to \
                     place real calls, per Requirement 9.1)"
                        .to_owned(),
                ));
            }
        };

        // RNG-free per-run session token (FNV-1a over grant fields) seeding unique
        // SIP transaction identifiers — reuses the phonetool-sip pattern, adds no
        // rand/getrandom dependency (Requirement 11.2).
        let session = short_session(grant);

        let results = originate::sweep(
            &dids,
            &target,
            &uri_host,
            &caller_id,
            &session,
            self.trunk.as_ref(),
            &self.cfg,
        )
        .map_err(map_sweep_error)?;

        // Degenerate-case discipline: if NOTHING was reached, the sweep learned
        // nothing — a failure the operator sees, not an empty success misread as
        // "the block is empty". If at least one DID was reached, "these are
        // busy / disconnected" is itself a real, reportable result.
        let reached = results.iter().filter(|r| r.reached).count();
        if reached == 0 {
            return Err(PluginError::Empty(format!(
                "no DID in the range reached across {} call(s); trunk/target may be unreachable",
                results.len()
            )));
        }

        // Aggregate by SIP disposition for the summary.
        let answered = results
            .iter()
            .filter(|r| r.outcome.sip == SipDisposition::Answered)
            .count();

        let data = serde_json::json!({
            "range": grant.target(),
            "placed": results.len(),
            "reached": reached,
            "answered": answered,
            "results": results,
            // Named so the operator sees the honest fidelity in the event itself.
            "media_fidelity": "not_analyzed (no RTP/media path — Requirement 10)",
        });

        Ok(Event {
            source: "wardial".to_owned(),
            summary: format!(
                "wardial sweep {}: {}/{} reached, {} answered (SIP-only fidelity)",
                grant.target(),
                reached,
                results.len(),
                answered
            ),
            data,
        })
    }
}

/// Parse and bound the DID range carried in the grant target.
///
/// Two accepted forms:
///   * a bare single DID — `+15125550100` (digits, optional leading `+`);
///   * a span — `<prefix>:<lo>-<hi>`, expanding `prefix` + each integer in
///     `[lo, hi]` zero-padded to the width of `hi` (e.g. `+1512555:0100-0109` →
///     `+15125550100 ..= +15125550109`).
///
/// Bounds enforced BEFORE any socket work (Requirement 3): a malformed range →
/// `InvalidInput`; an empty expansion → `InvalidInput`; an expansion exceeding
/// `max_range` → `InvalidInput`; a candidate DID with any char outside digits and
/// a leading `+` → `InvalidInput`.
fn parse_range(target: &str, max_range: usize) -> Result<Vec<String>, PluginError> {
    let target = target.trim();
    if target.is_empty() {
        return Err(PluginError::InvalidInput(
            "empty DID range in grant target".to_owned(),
        ));
    }

    let dids = match target.split_once(':') {
        None => {
            // Bare single DID.
            validate_did(target)?;
            vec![target.to_owned()]
        }
        Some((prefix, span)) => {
            let (lo_str, hi_str) = span.split_once('-').ok_or_else(|| {
                PluginError::InvalidInput(format!(
                    "malformed DID range span {span:?} (expected <lo>-<hi>)"
                ))
            })?;
            let width = hi_str.len();
            let lo: u64 = lo_str.parse().map_err(|_| {
                PluginError::InvalidInput(format!("non-numeric range start {lo_str:?}"))
            })?;
            let hi: u64 = hi_str.parse().map_err(|_| {
                PluginError::InvalidInput(format!("non-numeric range end {hi_str:?}"))
            })?;
            if lo > hi {
                return Err(PluginError::InvalidInput(format!(
                    "inverted DID range {lo}-{hi}"
                )));
            }
            // Bound the expansion BEFORE materializing it — a fat-fingered span
            // must not allocate an unbounded vec (and each DID is a billable call).
            let count = hi - lo + 1;
            if count > max_range as u64 {
                return Err(PluginError::InvalidInput(format!(
                    "DID range expands to {count} numbers, exceeds max_range {max_range} \
                     (each is a billable call — bound is conservative, OQ1/OQ2)"
                )));
            }
            let mut out = Vec::with_capacity(count as usize);
            for n in lo..=hi {
                let did = format!("{prefix}{n:0width$}");
                validate_did(&did)?;
                out.push(did);
            }
            out
        }
    };

    if dids.is_empty() {
        return Err(PluginError::InvalidInput(
            "DID range expands to zero numbers".to_owned(),
        ));
    }
    Ok(dids)
}

/// Reject a candidate DID that contains anything but digits and a single leading
/// `+`, before it can become part of a wire message (Requirement 3.4).
fn validate_did(did: &str) -> Result<(), PluginError> {
    let digits = did.strip_prefix('+').unwrap_or(did);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PluginError::InvalidInput(format!(
            "illegal DID {did:?} (only digits and a leading + are allowed)"
        )));
    }
    Ok(())
}

/// A short, RNG-free session token derived from the grant (FNV-1a over
/// target+basis → 16 hex chars). Deterministic per grant, which is fine — a grant
/// is minted per authorized operation and not reused. Reuses the phonetool-sip
/// pattern so no `rand`/`getrandom` dependency enters the build (Requirement 11.2).
fn short_session(grant: &Grant) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in grant.target().bytes().chain(grant.basis().bytes()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Map the origination layer's error to the plugin error at the trait boundary.
fn map_sweep_error(e: SweepError) -> PluginError {
    match e {
        SweepError::Socket(_) | SweepError::Trunk(_) => PluginError::Backend(e.to_string()),
        SweepError::NoTrunkNonLoopback(_) => PluginError::Backend(e.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bare_single_did() {
        let dids = parse_range("+15125550100", 32).expect("valid single DID");
        assert_eq!(dids, vec!["+15125550100".to_owned()]);
    }

    #[test]
    fn expands_a_span_zero_padded() {
        let dids = parse_range("+1512555:0100-0103", 32).expect("valid span");
        assert_eq!(
            dids,
            vec![
                "+15125550100".to_owned(),
                "+15125550101".to_owned(),
                "+15125550102".to_owned(),
                "+15125550103".to_owned(),
            ]
        );
    }

    #[test]
    fn refuses_a_span_exceeding_max_range() {
        let err = parse_range("+1512555:0000-9999", 32).expect_err("too large");
        assert!(matches!(err, PluginError::InvalidInput(_)), "got {err:?}");
    }

    #[test]
    fn refuses_an_inverted_span() {
        let err = parse_range("+1512555:0100-0000", 32).expect_err("inverted");
        assert!(matches!(err, PluginError::InvalidInput(_)));
    }

    #[test]
    fn refuses_a_non_numeric_span() {
        assert!(matches!(
            parse_range("+1512555:01ab-0110", 32),
            Err(PluginError::InvalidInput(_))
        ));
    }

    #[test]
    fn refuses_an_illegal_did_character() {
        assert!(matches!(
            parse_range("+1512;rm-rf", 32),
            Err(PluginError::InvalidInput(_))
        ));
    }

    #[test]
    fn refuses_empty_target() {
        assert!(matches!(
            parse_range("   ", 32),
            Err(PluginError::InvalidInput(_))
        ));
    }

    #[test]
    fn refuses_a_span_missing_the_dash() {
        assert!(matches!(
            parse_range("+1512555:0100", 32),
            Err(PluginError::InvalidInput(_))
        ));
    }

    #[test]
    fn manifest_is_active_ip() {
        let m = WarDial::new().manifest();
        assert_eq!(m.name, "wardial");
        assert_eq!(m.transducer, Transducer::Ip);
        assert_eq!(m.capability, CapabilityClass::ActiveIp);
    }

    #[test]
    fn session_token_is_deterministic_per_grant_and_rng_free() {
        // Two grants with the same fields yield the same token (no RNG). We can't
        // build a Grant here (no public ctor — that's the point), so assert the
        // FNV-1a helper's shape via a stand-in string identical to the impl.
        fn fnv(s: &str) -> String {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in s.bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            format!("{h:016x}")
        }
        assert_eq!(fnv("a").len(), 16);
        assert_eq!(fnv("a"), fnv("a"));
        assert_ne!(fnv("a"), fnv("b"));
    }
}
