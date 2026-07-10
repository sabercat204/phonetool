//! Two-tier call classification.
//!
//! [`SipDisposition`] is inferred from the SIP response code alone — always
//! available, no media path required, the runnable-today floor. [`MediaDisposition`]
//! is inferred from tone analysis of decoded audio — available only behind the
//! media seam (which does not exist; see the crate docs and Requirement 10), so it
//! is [`MediaDisposition::NotAnalyzed`] until that seam is built.
//!
//! The `Unknown` / `NotAnalyzed` / `Inconclusive` variants are the "will not
//! guess" discipline made explicit in the type: a code we do not recognize is
//! `Unknown`, not a fabricated label; audio we did not analyze is `NotAnalyzed`,
//! distinct from audio we analyzed but were unsure about (`Inconclusive`).

/// The coarse outcome inferred from the SIP response code(s). Always available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SipDisposition {
    /// Provisional ringing / progress (18x).
    Ringing,
    /// The line answered — a real phone rang and the dialog reached `200 OK`.
    Answered,
    /// Busy (486, 600).
    Busy,
    /// Unavailable / no answer / temporarily unreachable (408, 480).
    Unavailable,
    /// The far end actively rejected the call (401/403/407 auth/forbidden, other
    /// 4xx not otherwise mapped, 5xx server error).
    Rejected,
    /// A code we do not specifically recognize. Never guessed into another bucket.
    Unknown,
}

/// Map a SIP status code to a [`SipDisposition`]. Any code not specifically
/// recognized maps to [`SipDisposition::Unknown`] — the classifier never guesses.
///
/// Note (Requirement 5.5): the fine PSTN mapping from a gateway's Q.850 cause
/// (via the SIP `Reason` header, RFC 3398) is gateway-dependent and is
/// deliberately NOT hard-coded here as universal. This is coarse SIP-code
/// granularity only; a cause→disposition table is an Open Question (OQ5).
#[must_use]
pub fn classify_sip(status_code: u16) -> SipDisposition {
    match status_code {
        180 | 183 => SipDisposition::Ringing,
        200 => SipDisposition::Answered,
        486 | 600 => SipDisposition::Busy,
        408 | 480 => SipDisposition::Unavailable,
        // Auth challenges, forbidden, and other client/server errors are the far
        // end declining to complete — grouped as Rejected. 404 (number not
        // assigned) also lands here: at SIP granularity it is a rejection, and the
        // finer "disconnected/vacant" reading needs the Q.850 cause (OQ5) or a SIT
        // tone (media seam), neither of which we fabricate.
        401 | 403 | 404 | 407 | 410 | 484 | 488 => SipDisposition::Rejected,
        code if (500..=599).contains(&code) => SipDisposition::Rejected,
        _ => SipDisposition::Unknown,
    }
}

/// The outcome inferred from tone analysis of early or answered media. Available
/// only behind the media seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaDisposition {
    /// No media was analyzed — either no early media arrived or the media path is
    /// not built. The default and honest floor: NOT a claim about the audio.
    NotAnalyzed,
    /// Media was analyzed but no tone met the detection-confidence threshold.
    Inconclusive,
    /// Special Information Tone — an intercepted / vacant / reorder condition.
    Sit,
    /// Fax calling tone (CNG, T.30).
    Fax,
    /// Modem / answer tone (CED, V.25 / V.8).
    Modem,
    /// Voice — a human or voicemail. Undifferentiated by design (Requirement 6.4):
    /// answering-machine detection is unreliable and ethically loaded, so we do
    /// not fabricate a human/VM split.
    Voice,
}

/// The per-DID classification: the always-present SIP disposition plus the
/// media disposition (which is `NotAnalyzed` until the media seam exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Outcome {
    /// From the SIP response code(s).
    pub sip: SipDisposition,
    /// From tone analysis, or `NotAnalyzed`.
    pub media: MediaDisposition,
}

impl Outcome {
    /// Build an outcome at SIP-only fidelity (the runnable-today mode): the media
    /// disposition is `NotAnalyzed` because no audio was decoded.
    #[must_use]
    pub fn sip_only(sip: SipDisposition) -> Self {
        Self {
            sip,
            media: MediaDisposition::NotAnalyzed,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_map_to_their_dispositions() {
        assert_eq!(classify_sip(180), SipDisposition::Ringing);
        assert_eq!(classify_sip(183), SipDisposition::Ringing);
        assert_eq!(classify_sip(200), SipDisposition::Answered);
        assert_eq!(classify_sip(486), SipDisposition::Busy);
        assert_eq!(classify_sip(600), SipDisposition::Busy);
        assert_eq!(classify_sip(408), SipDisposition::Unavailable);
        assert_eq!(classify_sip(480), SipDisposition::Unavailable);
        assert_eq!(classify_sip(404), SipDisposition::Rejected);
        assert_eq!(classify_sip(403), SipDisposition::Rejected);
        assert_eq!(classify_sip(503), SipDisposition::Rejected);
    }

    #[test]
    fn unrecognized_codes_are_unknown_not_guessed() {
        assert_eq!(classify_sip(299), SipDisposition::Unknown);
        assert_eq!(classify_sip(100), SipDisposition::Unknown);
        assert_eq!(classify_sip(999), SipDisposition::Unknown);
        assert_eq!(classify_sip(0), SipDisposition::Unknown);
    }

    #[test]
    fn sip_only_outcome_leaves_media_not_analyzed() {
        let o = Outcome::sip_only(SipDisposition::Busy);
        assert_eq!(o.media, MediaDisposition::NotAnalyzed);
    }
}
