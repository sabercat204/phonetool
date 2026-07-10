//! E.164 number normalization and validation — the input boundary.
//!
//! Threat note: the number reaching this plugin is untrusted input, and under
//! the `online` feature it becomes part of an outbound URL. Validate it into a
//! constrained canonical form *before* it can touch a cache key or a request, so
//! a malformed or injection-shaped argument is rejected at the boundary rather
//! than propagated. E.164 is the tightest useful constraint: leading `+`,
//! 1–15 digits, nothing else.

/// A validated E.164 number. The only way to obtain one is [`Number::parse`], so
/// downstream code (cache key, URL construction) can trust its shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number(String);

/// Why a candidate number was rejected at the boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NumberError {
    /// Empty or whitespace-only input.
    #[error("empty number")]
    Empty,
    /// Contained a character outside `+` and digits.
    #[error("illegal character in number")]
    IllegalChar,
    /// Not a valid E.164 length (1–15 digits after an optional leading `+`).
    #[error("not a valid E.164 length (need 1-15 digits)")]
    BadLength,
}

impl Number {
    /// Parse and normalize a candidate into canonical E.164 (`+` then digits).
    ///
    /// Accepts common human separators (spaces, dashes, dots, parens) and strips
    /// them; rejects anything else. A bare national number (no `+`) is accepted
    /// and normalized with a leading `+` only if it already carries a country
    /// code — this parser does not guess a region, so it requires the caller to
    /// supply international form. Digits-only input is treated as already-E.164
    /// without the `+`.
    ///
    /// # Errors
    /// Returns [`NumberError`] for empty, illegal-character, or bad-length input.
    pub fn parse(raw: &str) -> Result<Self, NumberError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(NumberError::Empty);
        }

        let mut digits = String::with_capacity(trimmed.len());
        for (i, c) in trimmed.chars().enumerate() {
            match c {
                '0'..='9' => digits.push(c),
                // A leading '+' is the E.164 marker; elsewhere it's illegal.
                '+' if i == 0 => {}
                // Common human separators are stripped, not rejected.
                ' ' | '-' | '.' | '(' | ')' => {}
                _ => return Err(NumberError::IllegalChar),
            }
        }

        // E.164: 1-15 digits.
        if digits.is_empty() || digits.len() > 15 {
            return Err(NumberError::BadLength);
        }

        Ok(Self(format!("+{digits}")))
    }

    /// The canonical E.164 string (with leading `+`).
    #[must_use]
    pub fn as_e164(&self) -> &str {
        &self.0
    }
}
