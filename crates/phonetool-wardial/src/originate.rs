//! The origination layer: one bounded, rate-limited, deadline-bounded SIP call
//! per DID, over UDP, using `std::net` only.
//!
//! ## Authorization / cost note
//!
//! This is the workbench's most consequential active operation: each call is
//! **billable** (metered on a real trunk), **attributable** (the trunk account +
//! caller-ID identify the operator), and **can complete to a real person** (a
//! `200 OK` means a phone rang and someone may have answered). This module holds
//! no gate logic on purpose — the [`Grant`](phonetool_core::Grant) is the single
//! choke point one layer up (`crate::WarDial`), and the DID range it sweeps was
//! derived from `Grant::target`. What this module owns is the *bounds* that keep
//! one authorized sweep from becoming a toll-fraud / TDoS-shaped flood or a
//! runaway bill, and the defensive posture toward the untrusted response bytes.
//!
//! ## The trunk seam and the inert-by-default guarantee
//!
//! Without a [`TrunkConfig`], `sweep` refuses any non-loopback target: the
//! origination path is *present but inert*, exercisable only against an operator-
//! owned loopback responder (which rings no one and costs nothing). A real PSTN
//! call requires an explicitly configured trunk — the "device" of this layer.

use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use crate::classify::{Outcome, SipDisposition, classify_sip};
use crate::message::{InviteRequest, ParseError, Response, TeardownRequest};

/// Largest datagram read from the far end per response. A SIP response is small;
/// anything past this is truncated rather than trusted to size the buffer.
pub const DEFAULT_RECV_CAP: usize = 16 * 1024;

/// A conservative default ceiling on DIDs per sweep. **This is a SAFETY FLOOR,
/// not a grounded value.** Open Questions 1/2 require the real ceiling, rate, and
/// concurrency to be grounded in the trunk provider's acceptable-use terms; until
/// that lands, this small default errs toward refusing an over-large sweep,
/// because each unit is a billable call, not a free probe. Deliberately far below
/// phonetool-sip's 4096 free OPTIONS probes.
pub const DEFAULT_MAX_RANGE: usize = 32;

/// Knobs for one sweep. `Default` is conservative and test-friendly.
#[derive(Debug, Clone)]
pub struct SweepConfig {
    /// Local address to bind the sending socket to. `127.0.0.1:0` for tests;
    /// `0.0.0.0:0` for an ephemeral port in the field.
    pub bind: String,
    /// Per-call deadline: how long to wait for a final SIP response before the
    /// call is torn down (`CANCEL`) and recorded as no-answer, never a hang.
    pub per_call_deadline: Duration,
    /// Minimum time between call *starts* — the rate limit, expressed as an
    /// interval so a sweep cannot burst. `calls_per_sec` in the ctor.
    pub min_call_interval: Duration,
    /// Ceiling on DIDs per sweep (see [`DEFAULT_MAX_RANGE`]; ungrounded floor).
    pub max_range: usize,
    /// Byte cap per response datagram.
    pub recv_cap: usize,
    /// User-Agent presented on the wire.
    pub user_agent: String,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:0".to_owned(),
            per_call_deadline: Duration::from_millis(1500),
            // 1 call/sec default: conservative pacing, NOT a grounded provider
            // rate (OQ2). Sequential dispatch means at most one call in flight.
            min_call_interval: Duration::from_millis(1000),
            max_range: DEFAULT_MAX_RANGE,
            recv_cap: DEFAULT_RECV_CAP,
            user_agent: concat!("phonetool-wardial/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }
}

impl SweepConfig {
    /// Set the rate limit as calls-per-second (stored internally as an interval).
    /// A non-positive rate is clamped to "as fast as sequential dispatch allows"
    /// (zero interval) — but note the default is deliberately paced.
    #[must_use]
    pub fn with_calls_per_sec(mut self, cps: f64) -> Self {
        self.min_call_interval = if cps > 0.0 {
            Duration::from_secs_f64(1.0 / cps)
        } else {
            Duration::ZERO
        };
        self
    }
}

/// The operator-supplied trunk parameters — this layer's "device seam". Absent,
/// `sweep` places no PSTN call (loopback-only).
///
/// The SIP auth secret lives ONLY here and must never enter the gate `basis`, the
/// command `arg`, an `Event`, or a log line (Requirement 8.4). It is not
/// `Serialize` and its `Debug` redacts the secret.
#[derive(Clone)]
pub struct TrunkConfig {
    /// The provider's SIP host:port to send origination to.
    pub host: String,
    /// The outbound caller-ID / DID presented in the From header (attribution).
    pub caller_id: String,
    /// The SIP auth secret. Held here only; never logged or serialized.
    pub secret: String,
}

impl std::fmt::Debug for TrunkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret — a capture/log reader must not obtain the
        // operator's PSTN origination credentials.
        f.debug_struct("TrunkConfig")
            .field("host", &self.host)
            .field("caller_id", &self.caller_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The outcome for one originated DID.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CallResult {
    /// The DID called.
    pub did: String,
    /// Whether any response was received (a final SIP response, or unparseable
    /// bytes). `false` on timeout / transport error (Requirement 7.1).
    pub reached: bool,
    /// The classification (SIP disposition + media disposition). Media is always
    /// `NotAnalyzed` — no media path exists (Requirement 10).
    pub outcome: Outcome,
    /// The final SIP status code, when one was parsed.
    pub sip_code: Option<u16>,
}

/// Why a sweep could not run at all (as opposed to a per-call no-answer, which is
/// a [`CallResult`], not an error).
#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    /// The local socket could not be bound / configured.
    #[error("socket setup failed: {0}")]
    Socket(String),
    /// A trunk operation failed (unreachable, auth refused). Requirement 4.5.
    #[error("trunk error: {0}")]
    Trunk(String),
    /// No `TrunkConfig` was supplied and the target is not loopback: the
    /// origination path is inert without a trunk (Requirement 9.1), so this is a
    /// fail-closed refusal, not a silent zero-call success.
    #[error("no trunk configured; refusing to originate to non-loopback target {0}")]
    NoTrunkNonLoopback(String),
}

/// Place one bounded call per DID against `target` and return one [`CallResult`]
/// each. `target` is the socket destination (the trunk host, or a loopback
/// responder in tests); `uri_host` is the host written into the request URIs;
/// `caller_id` is the attribution-bearing From identity; `session` seeds unique
/// per-call SIP transaction identifiers without an RNG.
///
/// # Errors
/// [`SweepError`] if the socket cannot be set up, the trunk fails, or origination
/// to a non-loopback target is attempted with no trunk configured. A per-call
/// timeout is a `CallResult { reached: false }`, never an error.
pub fn sweep(
    dids: &[String],
    target: &str,
    uri_host: &str,
    caller_id: &str,
    session: &str,
    trunk: Option<&TrunkConfig>,
    cfg: &SweepConfig,
) -> Result<Vec<CallResult>, SweepError> {
    // Inert-without-a-trunk guarantee: refuse a non-loopback target when no trunk
    // is configured. This is what makes the default binary's origination path
    // *present but unreachable against the PSTN* — a real safety property, in code.
    if trunk.is_none() && !target_is_loopback(target) {
        return Err(SweepError::NoTrunkNonLoopback(target.to_owned()));
    }

    let socket = UdpSocket::bind(&cfg.bind).map_err(|e| SweepError::Socket(e.to_string()))?;
    socket
        .set_read_timeout(Some(cfg.per_call_deadline))
        .map_err(|e| SweepError::Socket(e.to_string()))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| SweepError::Socket(e.to_string()))?
        .to_string();

    let mut results = Vec::with_capacity(dids.len());
    for (i, did) in dids.iter().enumerate() {
        // Rate limit: pace call starts so a sweep cannot burst into a
        // toll-fraud / TDoS-shaped pattern. Sequential dispatch already bounds
        // concurrency to one in-flight call.
        if i > 0 && !cfg.min_call_interval.is_zero() {
            thread::sleep(cfg.min_call_interval);
        }
        results.push(place_one(
            &socket,
            target,
            uri_host,
            did,
            &local_addr,
            caller_id,
            session,
            i,
            cfg,
        ));
    }
    Ok(results)
}

/// One call: build INVITE, send, collect responses until a final response or the
/// deadline, classify, tear down. Any transport error or timeout becomes a
/// no-answer result, so one dead DID never aborts the sweep (Requirement 7.1).
#[allow(clippy::too_many_arguments)]
fn place_one(
    socket: &UdpSocket,
    target: &str,
    uri_host: &str,
    did: &str,
    local_addr: &str,
    caller_id: &str,
    session: &str,
    seq: usize,
    cfg: &SweepConfig,
) -> CallResult {
    let branch = format!("z9hG4bK{session}{seq}");
    let tag = format!("{session}t{seq}");
    let call_id = format!("{session}-{seq}@phonetool");

    let invite = InviteRequest {
        target,
        did,
        host: uri_host,
        local_addr,
        caller_id,
        branch: &branch,
        tag: &tag,
        call_id: &call_id,
        cseq: 1,
        user_agent: &cfg.user_agent,
    };

    let no_answer = CallResult {
        did: did.to_owned(),
        reached: false,
        outcome: Outcome::sip_only(SipDisposition::Unknown),
        sip_code: None,
    };

    if socket.send_to(invite.to_wire().as_bytes(), target).is_err() {
        return no_answer;
    }

    // Collect responses until a final (>=200) response or the per-call deadline.
    // Provisional (1xx) responses are noted but we keep waiting for the final one.
    let deadline = Instant::now() + cfg.per_call_deadline;
    let mut buf = vec![0u8; cfg.recv_cap];
    let mut got_any_bytes = false;

    loop {
        if Instant::now() >= deadline {
            // Timed out before a final response. Tear the transaction down with a
            // CANCEL (best effort) so we never leave a call hanging (Req 4.1).
            send_teardown(
                socket, target, "CANCEL", did, uri_host, local_addr, caller_id, &branch, &tag,
                &call_id, 1,
            );
            // Reached iff we saw *some* bytes (e.g. a 1xx) — else a true no-answer.
            return CallResult {
                did: did.to_owned(),
                reached: got_any_bytes,
                outcome: Outcome::sip_only(SipDisposition::Unknown),
                sip_code: None,
            };
        }

        let n = match socket.recv_from(&mut buf) {
            Ok((n, _from)) => n,
            Err(_) => continue, // WouldBlock/timeout tick — re-check the deadline
        };
        got_any_bytes = true;
        let datagram = buf.get(..n).unwrap_or(&[]);

        match Response::parse(datagram) {
            Ok(resp) if resp.status_code >= 200 => {
                // Final response. ACK it (required for both 2xx and failure
                // finals); for a 2xx also BYE to end the answered dialog so a live
                // call is not left up. Best effort — teardown errors are ignored.
                send_teardown(
                    socket, target, "ACK", did, uri_host, local_addr, caller_id, &branch, &tag,
                    &call_id, 1,
                );
                if resp.status_code < 300 {
                    send_teardown(
                        socket, target, "BYE", did, uri_host, local_addr, caller_id, &branch, &tag,
                        &call_id, 2,
                    );
                }
                return CallResult {
                    did: did.to_owned(),
                    reached: true,
                    outcome: Outcome::sip_only(classify_sip(resp.status_code)),
                    sip_code: Some(resp.status_code),
                };
            }
            // Provisional (1xx): progress; keep waiting for the final response.
            Ok(_) => continue,
            // Got bytes but not a parseable SIP response: reached, but we will not
            // guess a disposition (Requirement 7.2).
            Err(
                _e @ (ParseError::Empty | ParseError::BadStatusLine | ParseError::BadStatusCode),
            ) => {
                return CallResult {
                    did: did.to_owned(),
                    reached: true,
                    outcome: Outcome::sip_only(SipDisposition::Unknown),
                    sip_code: None,
                };
            }
        }
    }
}

/// Send a best-effort teardown request (`ACK` / `BYE` / `CANCEL`). Errors are
/// intentionally ignored — teardown is cleanup, not the operation's result.
#[allow(clippy::too_many_arguments)]
fn send_teardown(
    socket: &UdpSocket,
    target: &str,
    method: &str,
    did: &str,
    host: &str,
    local_addr: &str,
    caller_id: &str,
    branch: &str,
    tag: &str,
    call_id: &str,
    cseq: u32,
) {
    let td = TeardownRequest {
        method,
        did,
        host,
        local_addr,
        caller_id,
        branch,
        tag,
        call_id,
        cseq,
    };
    let _ = socket.send_to(td.to_wire().as_bytes(), target);
}

/// Whether a `host:port` (or bare host) target resolves to a loopback address.
/// Used to enforce the inert-without-a-trunk guarantee. A hostname we cannot
/// classify as loopback is treated as non-loopback (fail-closed).
fn target_is_loopback(target: &str) -> bool {
    let host = host_part(target);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

/// Extract the host from a `host:port`, handling bracketed IPv6 (`[::1]:5060`).
fn host_part(target: &str) -> &str {
    if let Some(rest) = target.strip_prefix('[') {
        // [ipv6]:port → take up to the closing bracket.
        if let Some((h, _)) = rest.split_once(']') {
            return h;
        }
    }
    // host:port → strip the last :port; a bare host is returned as-is. IPv6
    // without brackets has multiple colons and is not split (returned whole,
    // which parse::<Ipv6Addr> then handles).
    match target.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => h,
        _ => target,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn loopback_targets_are_recognized() {
        assert!(target_is_loopback("127.0.0.1:5060"));
        assert!(target_is_loopback("127.0.0.1"));
        assert!(target_is_loopback("localhost:5060"));
        assert!(target_is_loopback("[::1]:5060"));
        assert!(target_is_loopback("::1"));
    }

    #[test]
    fn non_loopback_targets_are_rejected_by_the_guard() {
        assert!(!target_is_loopback("192.0.2.10:5060"));
        assert!(!target_is_loopback("trunk.example.com:5060"));
        assert!(!target_is_loopback("8.8.8.8"));
    }

    #[test]
    fn sweep_refuses_non_loopback_without_a_trunk() {
        let cfg = SweepConfig::default();
        let err = sweep(
            &["+15125550100".to_owned()],
            "192.0.2.10:5060",
            "trunk.example",
            "+15125550001",
            "sess",
            None, // no trunk
            &cfg,
        )
        .expect_err("must refuse PSTN origination without a trunk");
        assert!(
            matches!(err, SweepError::NoTrunkNonLoopback(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn trunk_config_debug_redacts_the_secret() {
        let tc = TrunkConfig {
            host: "sip.example:5060".to_owned(),
            caller_id: "+15125550001".to_owned(),
            secret: "hunter2".to_owned(),
        };
        let dbg = format!("{tc:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("hunter2"), "secret must never appear");
    }
}
