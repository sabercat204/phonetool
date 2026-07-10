//! A bounded, depth-capped BER/TLV reader — the foundation TCAP (Q.773) and MAP
//! ride on.
//!
//! Threat note: TCAP is BER-encoded and admits nested, constructed, and
//! indefinite-length elements. A naive recursive-descent reader is a
//! stack-exhaustion and buffer-overread vector on a crafted PDU. This reader is
//! total over arbitrary bytes:
//!   - every declared length is checked against the remaining buffer (never
//!     trusted to be in-bounds); offsets use checked/saturating arithmetic;
//!   - nesting is depth-capped ([`MAX_DEPTH`]) — a construct nested past the cap
//!     is a decode error, not unbounded recursion;
//!   - indefinite-length form (BER length byte `0x80`) is **refused** (a decode
//!     error), not chased. Definite-length is all a legitimate TCAP/MAP PDU needs
//!     here, and indefinite form is a classic fuzzer lever.
//!
//! Grounding: BER TLV encoding — ITU-T X.690 (identifier octet, length octets:
//! short form `<0x80`, long form `0x81..=0x84` giving the byte-count, `0x80`
//! reserved for indefinite). Tag classes/constructed bit — X.690 §8.1.2.

/// Maximum BER nesting depth. A safety constant (not a protocol constant): a
/// legitimate TCAP/MAP PDU nests only a handful of levels (message → component
/// portion → component → parameter sequence → parameter). 32 is generous headroom
/// while bounding a crafted deeply-nested construct. Its exact value is an
/// operator-tunable safety bound (design Open Question 6), not a standard figure.
pub const MAX_DEPTH: usize = 32;

/// Why a TLV read failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BerError {
    /// The buffer ended before a complete identifier + length + value could be read.
    #[error("truncated TLV")]
    Truncated,
    /// A declared length exceeds the bytes remaining in the buffer.
    #[error("TLV length {declared} exceeds {remaining} remaining")]
    LengthOverrun {
        /// The length the encoding declared.
        declared: usize,
        /// The bytes actually left in the buffer.
        remaining: usize,
    },
    /// Indefinite-length form (`0x80`) — refused rather than chased.
    #[error("indefinite-length BER form is not supported")]
    IndefiniteLength,
    /// A long-form length whose byte-count is larger than a `usize` can hold, or
    /// larger than this reader accepts (>4 bytes / >2^32).
    #[error("unsupported BER length encoding")]
    BadLength,
    /// Nesting exceeded [`MAX_DEPTH`].
    #[error("BER nesting deeper than {MAX_DEPTH}")]
    TooDeep,
    /// A multi-byte tag (identifier octet low bits all 1) — not needed for the
    /// tags this analyzer reads, and refused rather than partially parsed.
    #[error("multi-byte BER tag is not supported")]
    MultiByteTag,
}

/// One decoded TLV: its identifier octet, the constructed bit, and its value
/// bytes (the raw content, exclusive of identifier and length octets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The raw identifier octet (tag class in bits 7-6, constructed bit 5, number
    /// in bits 4-0 for the single-byte-tag case this reader handles).
    pub identifier: u8,
    /// Whether the constructed bit (0x20) is set — i.e. the value is itself a
    /// sequence of TLVs.
    pub constructed: bool,
    /// The value content bytes.
    pub value: &'a [u8],
}

impl Tlv<'_> {
    /// The tag number — the low 5 bits of the identifier (single-byte tags only).
    #[must_use]
    pub fn tag_number(&self) -> u8 {
        self.identifier & 0x1f
    }

    /// The tag class — the top two bits (0=universal, 1=application, 2=context,
    /// 3=private) per X.690 §8.1.2.2.
    #[must_use]
    pub fn tag_class(&self) -> u8 {
        (self.identifier >> 6) & 0x03
    }
}

/// Read exactly one TLV from the front of `buf`, returning the decoded TLV and the
/// remaining bytes after its value. Total over arbitrary input.
///
/// # Errors
/// [`BerError`] on truncation, a length overrun, indefinite/oversized length, a
/// multi-byte tag, or (never here directly — depth is enforced by
/// [`read_children`]) — see the variants.
pub fn read_tlv(buf: &[u8]) -> Result<(Tlv<'_>, &[u8]), BerError> {
    let (&identifier, rest) = buf.split_first().ok_or(BerError::Truncated)?;

    // Single-byte tags only: low 5 bits all set means a multi-byte tag follows.
    if identifier & 0x1f == 0x1f {
        return Err(BerError::MultiByteTag);
    }
    let constructed = identifier & 0x20 != 0;

    let (&len_first, after_len_first) = rest.split_first().ok_or(BerError::Truncated)?;
    let (value_len, after_len) = if len_first < 0x80 {
        // Short form: the length byte is the length.
        (usize::from(len_first), after_len_first)
    } else if len_first == 0x80 {
        return Err(BerError::IndefiniteLength);
    } else {
        // Long form: low 7 bits give the number of subsequent length bytes.
        let n = usize::from(len_first & 0x7f);
        if n == 0 || n > 4 {
            return Err(BerError::BadLength);
        }
        let len_bytes = after_len_first.get(..n).ok_or(BerError::Truncated)?;
        let mut len: usize = 0;
        for &b in len_bytes {
            // Shift-accumulate; n<=4 so this cannot overflow a usize on any
            // supported platform (>=32-bit).
            len = (len << 8) | usize::from(b);
        }
        let after = after_len_first.get(n..).ok_or(BerError::Truncated)?;
        (len, after)
    };

    let remaining = after_len.len();
    let value = after_len.get(..value_len).ok_or(BerError::LengthOverrun {
        declared: value_len,
        remaining,
    })?;
    // `get(..value_len)` guarantees `value_len <= remaining`, so this slice is safe.
    let tail = after_len.get(value_len..).unwrap_or(&[]);
    Ok((
        Tlv {
            identifier,
            constructed,
            value,
        },
        tail,
    ))
}

/// Decode every TLV in `buf` as a flat sequence (no descent into constructed
/// values). Stops at the first error, returning the TLVs read so far alongside it,
/// so a caller can use a partial decode. `depth` guards recursion when a caller
/// descends into a constructed TLV's value.
///
/// # Errors
/// [`BerError::TooDeep`] if `depth` exceeds [`MAX_DEPTH`]; otherwise the first
/// per-TLV [`BerError`] encountered (with prior TLVs returned).
pub fn read_children(buf: &[u8], depth: usize) -> Result<Vec<Tlv<'_>>, (Vec<Tlv<'_>>, BerError)> {
    if depth > MAX_DEPTH {
        return Err((Vec::new(), BerError::TooDeep));
    }
    let mut out = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        match read_tlv(rest) {
            Ok((tlv, tail)) => {
                out.push(tlv);
                rest = tail;
            }
            Err(e) => return Err((out, e)),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn short_form_primitive() {
        // tag 0x02 (INTEGER), len 2, value 0x00 0x64.
        let (tlv, rest) = read_tlv(&[0x02, 0x02, 0x00, 0x64]).expect("valid");
        assert_eq!(tlv.identifier, 0x02);
        assert!(!tlv.constructed);
        assert_eq!(tlv.value, &[0x00, 0x64]);
        assert!(rest.is_empty());
    }

    #[test]
    fn constructed_bit_detected() {
        // 0x30 = SEQUENCE (universal, constructed).
        let (tlv, _) = read_tlv(&[0x30, 0x00]).expect("valid");
        assert!(tlv.constructed);
        assert_eq!(tlv.tag_class(), 0); // universal
    }

    #[test]
    fn long_form_length_two_bytes() {
        // len encoded as 0x82 0x01 0x00 → 256 bytes of value.
        let mut pdu = vec![0x04, 0x82, 0x01, 0x00];
        pdu.extend(std::iter::repeat_n(0xAA, 256));
        let (tlv, rest) = read_tlv(&pdu).expect("valid");
        assert_eq!(tlv.value.len(), 256);
        assert!(rest.is_empty());
    }

    #[test]
    fn indefinite_length_refused() {
        assert_eq!(read_tlv(&[0x30, 0x80]), Err(BerError::IndefiniteLength));
    }

    #[test]
    fn length_overrun_is_error_not_panic() {
        // Declares 10 value bytes but only 2 present.
        let err = read_tlv(&[0x04, 0x0a, 0x01, 0x02]).unwrap_err();
        assert!(matches!(err, BerError::LengthOverrun { declared: 10, .. }));
    }

    #[test]
    fn truncated_before_length() {
        assert_eq!(read_tlv(&[0x04]), Err(BerError::Truncated));
    }

    #[test]
    fn empty_buffer_truncated() {
        assert_eq!(read_tlv(&[]), Err(BerError::Truncated));
    }

    #[test]
    fn multi_byte_tag_refused() {
        // 0x1f low bits → multi-byte tag.
        assert_eq!(read_tlv(&[0x1f, 0x00]), Err(BerError::MultiByteTag));
    }

    #[test]
    fn long_form_over_four_bytes_refused() {
        assert_eq!(
            read_tlv(&[0x04, 0x85, 1, 2, 3, 4, 5]),
            Err(BerError::BadLength)
        );
    }

    #[test]
    fn read_children_flat_sequence() {
        // Two primitives back to back.
        let kids = read_children(&[0x02, 0x01, 0x05, 0x04, 0x02, 0xaa, 0xbb], 0).expect("valid");
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].value, &[0x05]);
        assert_eq!(kids[1].value, &[0xaa, 0xbb]);
    }

    #[test]
    fn read_children_partial_on_error() {
        // First TLV ok, second truncated → partial result + error.
        let (kids, err) = read_children(&[0x02, 0x01, 0x05, 0x04, 0x0a, 0x01], 0).unwrap_err();
        assert_eq!(kids.len(), 1);
        assert!(matches!(err, BerError::LengthOverrun { .. }));
    }

    #[test]
    fn depth_cap_enforced() {
        let (_, err) = read_children(&[0x30, 0x00], MAX_DEPTH + 1).unwrap_err();
        assert_eq!(err, BerError::TooDeep);
    }

    #[test]
    fn descending_constructed_value_is_bounded() {
        // SEQUENCE { INTEGER 5 } — descend one level, staying under the cap.
        let (outer, _) = read_tlv(&[0x30, 0x03, 0x02, 0x01, 0x05]).expect("outer");
        assert!(outer.constructed);
        let kids = read_children(outer.value, 1).expect("inner");
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].value, &[0x05]);
    }
}
