//! The extension-enumeration probe: one UDP OPTIONS per candidate, classified.
//!
//! ## Threat / authorization note
//!
//! This is the workbench's first **active** operation — it transmits to a remote.
//! It is reachable only through [`crate::SipRecon`]'s `dispatch_active`, which
//! requires a `Grant`, and the `target` it probes is the one the gate authorized
//! (passed down from `Grant::target`). This module holds no gate logic on purpose:
//! the gate is the single choke point one layer up, and duplicating the check here
//! would be a second, drift-prone copy. What this module *does* own is the
//! defensive posture toward the response — the bytes coming back are untrusted
//! (see [`crate::message`]).
//!
//! Bounds that keep a hostile or slow remote from hanging the operation: a
//! per-probe socket read timeout, a capped receive buffer, and a caller-supplied
//! ceiling on how many extensions may be probed in one call.

use std::net::UdpSocket;
use std::time::Duration;

use crate::message::{OptionsRequest, ParseError, Response, Verdict, classify};

/// Largest datagram we will read from the remote. A SIP OPTIONS response is small;
/// anything past this is truncated rather than trusted to size our buffer.
const RECV_CAP: usize = 8192;

/// Hard ceiling on extensions probed per enumerate call, so a pathological input
/// list cannot turn one authorized op into an unbounded scan.
pub const MAX_EXTENSIONS: usize = 4096;

/// Knobs for one enumeration run. Defaults are conservative (short timeout, modest
/// retries) — this is recon, not a stress test.
#[derive(Debug, Clone)]
pub struct EnumConfig {
    /// Local address to bind the sending socket to. `0.0.0.0:0` for an ephemeral port.
    pub bind: String,
    /// How long to wait for each probe's response before treating it as no-answer.
    pub timeout: Duration,
    /// User-Agent presented on the wire.
    pub user_agent: String,
}

impl Default for EnumConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:0".to_owned(),
            timeout: Duration::from_millis(750),
            user_agent: "phonetool-sip/0.3".to_owned(),
        }
    }
}

/// The outcome for one probed extension.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Finding {
    /// The extension probed.
    pub extension: String,
    /// Enumeration verdict (`exists` / `absent` / `ambiguous`), or omitted when
    /// the probe got no answer (see `responded`).
    pub verdict: Option<Verdict>,
    /// Whether any response was received at all within the timeout.
    pub responded: bool,
    /// The response status code, when one was parsed.
    pub status_code: Option<u16>,
    /// A short server fingerprint from `Server`/`User-Agent`, when present.
    pub fingerprint: Option<String>,
}

/// Why an enumeration run could not proceed at all (as opposed to a per-extension
/// no-answer, which is a [`Finding`], not an error).
#[derive(Debug, thiserror::Error)]
pub enum EnumError {
    /// The target string was not a usable `host:port`.
    #[error("invalid target address: {0}")]
    BadTarget(String),
    /// The local socket could not be bound / configured.
    #[error("socket setup failed: {0}")]
    Socket(String),
    /// The caller supplied more extensions than [`MAX_EXTENSIONS`].
    #[error("too many extensions: {0} (max {MAX_EXTENSIONS})")]
    TooMany(usize),
    /// No extensions were supplied — a degenerate no-op, refused as a failure.
    #[error("no extensions to probe")]
    NoExtensions,
}

/// Probe each extension against `target` and return one [`Finding`] per extension.
///
/// `target` is the gate-authorized `host:port`; `host` is its host part for the
/// request URI. `session` is a caller-unique token used to derive per-transaction
/// SIP branch/tag/call-id values without an RNG dependency (keeps the build a
/// pure-Rust static binary).
///
/// # Errors
/// [`EnumError`] if the target is unparseable, the socket cannot be set up, the
/// extension list is empty, or it exceeds [`MAX_EXTENSIONS`]. A per-extension
/// timeout is a `Finding { responded: false }`, never an error.
pub fn run(
    target: &str,
    host: &str,
    extensions: &[String],
    session: &str,
    cfg: &EnumConfig,
) -> Result<Vec<Finding>, EnumError> {
    if extensions.is_empty() {
        return Err(EnumError::NoExtensions);
    }
    if extensions.len() > MAX_EXTENSIONS {
        return Err(EnumError::TooMany(extensions.len()));
    }
    // Validate the target shape before any socket work.
    if target.rsplit_once(':').is_none() {
        return Err(EnumError::BadTarget(target.to_owned()));
    }

    let socket = UdpSocket::bind(&cfg.bind).map_err(|e| EnumError::Socket(e.to_string()))?;
    socket
        .set_read_timeout(Some(cfg.timeout))
        .map_err(|e| EnumError::Socket(e.to_string()))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| EnumError::Socket(e.to_string()))?
        .to_string();

    let mut findings = Vec::with_capacity(extensions.len());
    for (i, ext) in extensions.iter().enumerate() {
        findings.push(probe_one(
            &socket,
            target,
            host,
            ext,
            &local_addr,
            session,
            i,
            cfg,
        ));
    }
    Ok(findings)
}

/// One probe: build, send, receive-with-timeout, classify. Any transport error or
/// timeout becomes a no-answer `Finding`, so a single dead extension never aborts
/// the run.
#[allow(clippy::too_many_arguments)]
fn probe_one(
    socket: &UdpSocket,
    target: &str,
    host: &str,
    ext: &str,
    local_addr: &str,
    session: &str,
    seq: usize,
    cfg: &EnumConfig,
) -> Finding {
    let req = OptionsRequest {
        target,
        extension: ext,
        host,
        local_addr,
        branch: &format!("z9hG4bK{session}{seq}"),
        tag: &format!("{session}t{seq}"),
        call_id: &format!("{session}-{seq}@phonetool"),
        cseq: 1,
        user_agent: &cfg.user_agent,
    };
    let wire = req.to_wire();

    let no_answer = Finding {
        extension: ext.to_owned(),
        verdict: None,
        responded: false,
        status_code: None,
        fingerprint: None,
    };

    if socket.send_to(wire.as_bytes(), target).is_err() {
        return no_answer;
    }

    let mut buf = vec![0u8; RECV_CAP];
    let n = match socket.recv_from(&mut buf) {
        Ok((n, _from)) => n,
        Err(_) => return no_answer, // timeout / WouldBlock / transport error
    };
    let datagram = buf.get(..n).unwrap_or(&[]);

    match Response::parse(datagram) {
        Ok(resp) => {
            let verdict = classify(resp.status_code);
            let fingerprint = resp
                .header("server")
                .or_else(|| resp.header("user-agent"))
                .map(str::to_owned);
            Finding {
                extension: ext.to_owned(),
                verdict: Some(verdict),
                responded: true,
                status_code: Some(resp.status_code),
                fingerprint,
            }
        }
        // Got bytes but they were not a parseable SIP response: responded, but no
        // usable verdict. Untrusted-input discipline — we do not guess.
        Err(_e @ (ParseError::Empty | ParseError::BadStatusLine | ParseError::BadStatusCode)) => {
            Finding {
                extension: ext.to_owned(),
                verdict: None,
                responded: true,
                status_code: None,
                fingerprint: None,
            }
        }
    }
}
