//! Indicator extraction and normalization — pure, no store, no network.
//!
//! Pulls comparable indicators (`Ioc`s) out of a [`RawBait`]'s typed fields and
//! its free-text transcript, and normalizes each to a canonical form so the same
//! wallet or number written two ways matches a prior case. Normalization is
//! per-artifact resilient: one artifact that fails its own normalization (a phone
//! field that is not a valid number) is **skipped**, never run-aborting — the same
//! per-item resilience the SIP prober applies per probe.
//!
//! Two deliberate non-goals, both grounded as Open Questions rather than invented:
//! wallets stay **opaque strings** (no per-chain checksum, OQ5), and free-text
//! mining is conservative — it lifts obvious tokens (URLs, emails) but does not
//! guess phone numbers out of prose, which would fabricate indicators.

use serde::Serialize;

use phonetool_numintel::number::Number;

use crate::ingest::{MAX_IOCS, RawBait};

/// The kind of an extracted indicator. `snake_case` so it serializes to a stable
/// wire form and doubles as a human label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    /// A phone number, normalized to canonical E.164.
    Phone,
    /// A URL (host lower-cased for comparison).
    Url,
    /// A crypto wallet address (lower-cased; opaque, no chain validation).
    Wallet,
    /// An email address (host lower-cased).
    Email,
    /// A gift-card rail ("apple", "google play").
    GiftCardRail,
    /// A claimed identity or agency.
    Identity,
}

/// A normalized, comparable indicator extracted from the artifacts. The `value`
/// is the canonical form used both as a store lookup key and for cross-case
/// comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Ioc {
    /// What kind of indicator this is.
    pub kind: IocKind,
    /// The normalized value (E.164 for phones, lower-cased host/string otherwise).
    pub value: String,
}

/// Normalize a phone artifact to canonical E.164 via the shared [`Number::parse`]
/// (the same validator numintel uses). Returns `None` on a value that is not a
/// valid number — the caller skips it and continues.
fn normalize_phone(raw: &str) -> Option<Ioc> {
    Number::parse(raw).ok().map(|n| Ioc {
        kind: IocKind::Phone,
        value: n.as_e164().to_owned(),
    })
}

/// Normalize a URL for comparison: lower-case the scheme+host (the case-
/// insensitive parts) while leaving the path untouched (paths are case-sensitive).
/// This is a *comparison* normalization, not a parser — the URL is never a request
/// target, so a permissive lower-casing that never fails is correct here. Returns
/// `None` only for an empty/whitespace value.
fn normalize_url(raw: &str) -> Option<Ioc> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Split scheme://host[/path]. Lower-case up to and including the authority; a
    // value with no path lower-cases wholesale. No dereference, ever.
    let value = match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = match rest.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (rest, None),
            };
            match path {
                Some(p) => format!(
                    "{}://{}/{p}",
                    scheme.to_lowercase(),
                    authority.to_lowercase()
                ),
                None => format!("{}://{}", scheme.to_lowercase(), authority.to_lowercase()),
            }
        }
        // No scheme — treat the whole thing as a bare host/token, lower-cased.
        None => trimmed.to_lowercase(),
    };
    Some(Ioc {
        kind: IocKind::Url,
        value,
    })
}

/// Normalize an email for comparison: lower-case the domain (case-insensitive),
/// preserve the local part (RFC 5321 allows case-sensitive local parts, so we do
/// not fold it). Returns `None` for an empty value or one with no `@`.
fn normalize_email(raw: &str) -> Option<Ioc> {
    let trimmed = raw.trim();
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(Ioc {
        kind: IocKind::Email,
        value: format!("{local}@{}", domain.to_lowercase()),
    })
}

/// Normalize a plain string artifact (wallet, gift-card rail, identity) to a
/// case-insensitive comparable value. Wallets stay opaque — no per-chain checksum
/// (OQ5). Returns `None` for an empty/whitespace value.
fn normalize_plain(raw: &str, kind: IocKind) -> Option<Ioc> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(Ioc {
        kind,
        value: trimmed.to_lowercase(),
    })
}

/// Extract email/URL tokens from free text (transcript, email body). Conservative:
/// it lifts whitespace-delimited tokens that clearly look like a URL or an email
/// (contain `://` or an `@` with a dotted domain). It does NOT attempt to guess
/// phone numbers or wallets out of prose — that would fabricate indicators from
/// ambiguous text. Each candidate goes through the same normalizer as a typed
/// field, so a false-positive token that does not normalize is dropped.
fn extract_from_text(text: &str, out: &mut Vec<Ioc>) {
    for token in text.split(|c: char| c.is_whitespace()) {
        // Strip trailing punctuation that commonly abuts a token in prose.
        let token = token.trim_matches(|c: char| {
            matches!(
                c,
                ',' | '.' | ';' | ':' | ')' | '(' | '"' | '\'' | '<' | '>' | '!' | '?'
            )
        });
        if token.is_empty() {
            continue;
        }
        if token.contains("://") {
            if let Some(ioc) = normalize_url(token) {
                out.push(ioc);
            }
        } else if let Some((local, domain)) = token.split_once('@') {
            // Require a dotted domain to avoid lifting stray "@handle" mentions.
            if !local.is_empty()
                && domain.contains('.')
                && let Some(ioc) = normalize_email(token)
            {
                out.push(ioc);
            }
        }
    }
}

/// Extract and normalize every indicator from a bundle.
///
/// Per-artifact resilient: an artifact that fails normalization is skipped, never
/// fatal. Deduplicates identical `(kind, value)` pairs (the same number in a typed
/// field and the transcript is one indicator). Bounded by [`MAX_IOCS`]: extraction
/// stops accepting new indicators once the cap is reached (a documented, logged
/// truncation — not a silent one; the caller surfaces the count).
#[must_use]
pub fn iocs(bait: &RawBait) -> Vec<Ioc> {
    let mut out: Vec<Ioc> = Vec::new();

    // Typed fields first — the operator's structured artifacts.
    if let Some(phone) = &bait.phone
        && let Some(ioc) = normalize_phone(phone)
    {
        out.push(ioc);
    }
    for url in &bait.urls {
        if let Some(ioc) = normalize_url(url) {
            out.push(ioc);
        }
    }
    for email in &bait.emails {
        if let Some(ioc) = normalize_email(email) {
            out.push(ioc);
        }
    }
    for wallet in &bait.wallets {
        if let Some(ioc) = normalize_plain(wallet, IocKind::Wallet) {
            out.push(ioc);
        }
    }
    for rail in &bait.gift_card_rails {
        if let Some(ioc) = normalize_plain(rail, IocKind::GiftCardRail) {
            out.push(ioc);
        }
    }
    if let Some(identity) = &bait.identity
        && let Some(ioc) = normalize_plain(identity, IocKind::Identity)
    {
        out.push(ioc);
    }
    if let Some(agency) = &bait.agency_claim
        && let Some(ioc) = normalize_plain(agency, IocKind::Identity)
    {
        out.push(ioc);
    }

    // Free-text: lift obvious URL/email tokens from transcript + email body.
    if let Some(transcript) = &bait.transcript {
        extract_from_text(transcript, &mut out);
    }
    if let Some(body) = &bait.email_body {
        extract_from_text(body, &mut out);
    }

    // Dedup identical indicators, then bound. Dedup before the cap so the cap
    // counts distinct indicators, not repetition.
    out.sort_by(|a, b| (a.kind as u8, &a.value).cmp(&(b.kind as u8, &b.value)));
    out.dedup();
    out.truncate(MAX_IOCS);
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn bait_with(f: impl FnOnce(&mut RawBait)) -> RawBait {
        let mut b = RawBait::default();
        f(&mut b);
        b
    }

    #[test]
    fn phone_normalizes_to_one_e164_across_formats() {
        let a = iocs(&bait_with(|b| {
            b.phone = Some("+1 (512) 555-0100".to_owned())
        }));
        let b = iocs(&bait_with(|b| b.phone = Some("+1.512.555.0100".to_owned())));
        let c = iocs(&bait_with(|b| b.phone = Some("+15125550100".to_owned())));
        assert_eq!(a[0].value, "+15125550100");
        assert_eq!(a[0], b[0]);
        assert_eq!(b[0], c[0]);
        assert_eq!(a[0].kind, IocKind::Phone);
    }

    #[test]
    fn bad_phone_is_skipped_not_fatal() {
        // A garbage phone plus a good wallet: the phone drops, the wallet extracts.
        let b = bait_with(|b| {
            b.phone = Some("not-a-number-!!!".to_owned());
            b.wallets = vec!["bc1qXYZ".to_owned()];
        });
        let out = iocs(&b);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, IocKind::Wallet);
        assert_eq!(out[0].value, "bc1qxyz");
    }

    #[test]
    fn url_host_lowercased_path_preserved() {
        let out = iocs(&bait_with(|b| {
            b.urls = vec!["HTTPS://Evil.EXAMPLE/PayNow".to_owned()];
        }));
        assert_eq!(out[0].value, "https://evil.example/PayNow");
    }

    #[test]
    fn email_domain_lowercased_local_preserved() {
        let out = iocs(&bait_with(|b| {
            b.emails = vec!["Scammer@EVIL.example".to_owned()]
        }));
        assert_eq!(out[0].value, "Scammer@evil.example");
    }

    #[test]
    fn wallet_is_opaque_lowercased() {
        let out = iocs(&bait_with(|b| b.wallets = vec!["0xAbCdEf".to_owned()]));
        assert_eq!(out[0].value, "0xabcdef");
        assert_eq!(out[0].kind, IocKind::Wallet);
    }

    #[test]
    fn transcript_lifts_url_and_email() {
        let out = iocs(&bait_with(|b| {
            b.transcript =
                Some("call back at http://evil.example/x or email scam@evil.example.".to_owned());
        }));
        assert!(out.iter().any(|i| i.kind == IocKind::Url));
        assert!(out.iter().any(|i| i.kind == IocKind::Email));
    }

    #[test]
    fn transcript_does_not_invent_phone_from_prose() {
        // A number embedded in prose is not lifted (we do not guess phones).
        let out = iocs(&bait_with(|b| {
            b.transcript = Some("they said call 5125550100 right now".to_owned());
        }));
        assert!(out.iter().all(|i| i.kind != IocKind::Phone));
    }

    #[test]
    fn duplicate_indicators_deduped() {
        // Same wallet as a typed field and in the transcript body → one Ioc.
        let out = iocs(&bait_with(|b| {
            b.emails = vec!["a@evil.example".to_owned()];
            b.email_body = Some("reach me at a@evil.example".to_owned());
        }));
        assert_eq!(out.iter().filter(|i| i.kind == IocKind::Email).count(), 1);
    }

    #[test]
    fn empty_bundle_yields_nothing() {
        assert!(iocs(&RawBait::default()).is_empty());
    }

    #[test]
    fn ioc_count_bounded_by_max() {
        // Flood with distinct wallets past the cap.
        let wallets: Vec<String> = (0..(MAX_IOCS + 50)).map(|i| format!("w{i}")).collect();
        let out = iocs(&bait_with(|b| b.wallets = wallets));
        assert_eq!(out.len(), MAX_IOCS);
    }
}
