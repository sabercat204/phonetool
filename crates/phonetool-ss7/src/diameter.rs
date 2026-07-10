//! Diameter base + S6a decode: RFC 6733 message header, bounded AVP iteration, and
//! S6a command-code resolution (the LTE MME↔HSS analogue of the MAP location/auth
//! operations).
//!
//! Grounding: message + AVP framing — RFC 6733 §3 (header: version 1B, message
//! length 3B, command flags 1B, command code 3B, application-id 4B, hop-by-hop 4B,
//! end-to-end 4B; AVP: code 4B, flags 1B, length 3B, optional vendor-id 4B when the
//! V-bit is set, then value, padded to 4 bytes). S6a command codes — 3GPP TS 29.272,
//! cross-checked against Wireshark `packet-diameter` / the IANA command-code
//! registry. S6a Application-Id = 16777251. User-Name AVP code = 1 (RFC 6733).

use serde::Serialize;

/// RFC 6733 header length in bytes.
const DIAMETER_HDR_LEN: usize = 20;
/// Diameter version 1 (RFC 6733 §3).
const DIAMETER_VERSION: u8 = 1;
/// Command-flags R-bit (Request) — top bit of the flags octet.
const CMD_FLAG_REQUEST: u8 = 0x80;
/// AVP flags V-bit (Vendor-Specific) — presence of a 4-byte Vendor-Id.
const AVP_FLAG_VENDOR: u8 = 0x80;
/// AVP minimum length (code 4 + flags 1 + length 3).
const AVP_HDR_LEN: usize = 8;
/// User-Name AVP code (RFC 6733 §8.14) — carries the IMSI on S6a.
const AVP_USER_NAME: u32 = 1;

/// The decoded Diameter header salient fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiameterHeader {
    /// Command code (RFC 6733 §3).
    pub command_code: u32,
    /// Whether the Request (R) bit is set (else it is an Answer).
    pub request: bool,
    /// Application-Id (S6a = 16777251).
    pub application_id: u32,
}

/// A resolved S6a command, or an unrecognized command code reported verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum S6aCommand {
    /// A named S6a command from the grounded table.
    Named(&'static str),
    /// A command code not in the grounded table — reported, never omitted.
    Unknown(u32),
}

/// The decoded Diameter finding for one PDU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiameterDecoded {
    /// The message header.
    pub header: DiameterHeader,
    /// The resolved S6a command (or unknown code).
    pub command: S6aCommand,
    /// The subscriber identity (User-Name / IMSI) if the AVP was present + UTF-8.
    pub user_name: Option<String>,
    /// `true` if AVP iteration stopped early on a length overrun (partial decode).
    pub avps_truncated: bool,
}

/// Why a Diameter decode failed at the header layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiameterDecodeError {
    /// The PDU is not a Diameter message (bad version / too short).
    #[error("not a Diameter message")]
    NotDiameter,
}

/// The grounded S6a command-code table (3GPP TS 29.272; names cross-checked against
/// Wireshark `packet-diameter`). Request and Answer share a command code, discerned
/// by the R-bit — the name here is the command; the finding carries `request`.
/// Deliberately partial and grounded; an unlisted code → [`S6aCommand::Unknown`].
const DIAMETER_S6A_CMDS: &[(u32, &str)] = &[
    (316, "Update-Location"),            // ULR/ULA — TS 29.272 §7.2.3/4
    (318, "Authentication-Information"), // AIR/AIA — auth-vector fetch
    (319, "Insert-Subscriber-Data"),     // IDR/IDA — subscriber-data push
    (317, "Cancel-Location"),            // CLR/CLA
    (321, "Purge-UE"),                   // PUR/PUA
    (322, "Reset"),                      // RSR/RSA
    (323, "Notify"),                     // NOR/NOA
];

/// S6a Application-Id (3GPP TS 29.272). Used only to annotate; decode does not
/// require it to match (a capture may carry other Diameter apps we still decode
/// structurally, reporting the command as unknown).
pub const S6A_APPLICATION_ID: u32 = 16_777_251;

fn resolve_s6a(code: u32) -> S6aCommand {
    for &(c, name) in DIAMETER_S6A_CMDS {
        if c == code {
            return S6aCommand::Named(name);
        }
    }
    S6aCommand::Unknown(code)
}

/// Read a big-endian 24-bit value from a 3-byte slice.
fn u24_be(b: &[u8]) -> Option<u32> {
    let x = b.get(0..3)?;
    Some((u32::from(*x.first()?) << 16) | (u32::from(*x.get(1)?) << 8) | u32::from(*x.get(2)?))
}

/// Read a big-endian 32-bit value from a 4-byte slice.
fn u32_be(b: &[u8]) -> Option<u32> {
    let x: [u8; 4] = b.get(0..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(x))
}

/// Decode one PDU as a Diameter message. Total over arbitrary bytes: the header is
/// validated (version + length sanity), then AVPs are iterated without trusting any
/// length field. A User-Name AVP is extracted when present and valid UTF-8.
///
/// # Errors
/// [`DiameterDecodeError::NotDiameter`] if the PDU is not a version-1 Diameter
/// message of plausible length.
pub fn decode(pdu: &[u8]) -> Result<DiameterDecoded, DiameterDecodeError> {
    let hdr = pdu
        .get(0..DIAMETER_HDR_LEN)
        .ok_or(DiameterDecodeError::NotDiameter)?;
    if hdr.first().copied() != Some(DIAMETER_VERSION) {
        return Err(DiameterDecodeError::NotDiameter);
    }
    // Message length (bytes 1..4) must at least cover the header and not be absurd.
    let msg_len =
        u24_be(hdr.get(1..4).unwrap_or(&[])).ok_or(DiameterDecodeError::NotDiameter)? as usize;
    if msg_len < DIAMETER_HDR_LEN {
        return Err(DiameterDecodeError::NotDiameter);
    }
    let flags = hdr
        .get(4)
        .copied()
        .ok_or(DiameterDecodeError::NotDiameter)?;
    let request = flags & CMD_FLAG_REQUEST != 0;
    let command_code =
        u24_be(hdr.get(5..8).unwrap_or(&[])).ok_or(DiameterDecodeError::NotDiameter)?;
    let application_id =
        u32_be(hdr.get(8..12).unwrap_or(&[])).ok_or(DiameterDecodeError::NotDiameter)?;

    // AVPs occupy the message body, bounded by the declared length but never read
    // past the actual buffer.
    let body_end = msg_len.min(pdu.len());
    let body = pdu.get(DIAMETER_HDR_LEN..body_end).unwrap_or(&[]);
    let (user_name, avps_truncated) = iterate_avps(body);

    Ok(DiameterDecoded {
        header: DiameterHeader {
            command_code,
            request,
            application_id,
        },
        command: resolve_s6a(command_code),
        user_name,
        avps_truncated,
    })
}

/// Iterate AVPs, extracting User-Name if present. Returns `(user_name, truncated)`
/// where `truncated` is `true` if an AVP length overran the body (iteration stopped
/// early). Never reads past `body`.
fn iterate_avps(body: &[u8]) -> (Option<String>, bool) {
    let mut user_name = None;
    let mut rest = body;
    loop {
        if rest.is_empty() {
            return (user_name, false);
        }
        let Some(hdr) = rest.get(0..AVP_HDR_LEN) else {
            // A partial AVP header at the tail → treat as truncated.
            return (user_name, true);
        };
        let code = u32_be(hdr.get(0..4).unwrap_or(&[])).unwrap_or(0);
        let flags = hdr.get(4).copied().unwrap_or(0);
        let avp_len = u24_be(hdr.get(5..8).unwrap_or(&[])).unwrap_or(0) as usize;
        if avp_len < AVP_HDR_LEN {
            return (user_name, true); // invalid AVP length
        }
        let Some(avp) = rest.get(0..avp_len) else {
            return (user_name, true); // declared length overruns the body
        };

        // Value offset depends on the V-bit (optional 4-byte Vendor-Id).
        let value_off = if flags & AVP_FLAG_VENDOR != 0 {
            AVP_HDR_LEN + 4
        } else {
            AVP_HDR_LEN
        };
        if code == AVP_USER_NAME
            && user_name.is_none()
            && let Some(v) = avp.get(value_off..)
            && let Ok(s) = std::str::from_utf8(v)
        {
            user_name = Some(s.to_owned());
        }

        // Advance past this AVP, padded to a 4-byte boundary.
        let padded = avp_len.saturating_add(3) & !3usize;
        let Some(next) = rest.get(padded..) else {
            return (user_name, false);
        };
        if next.len() >= rest.len() {
            return (user_name, false); // no forward progress
        }
        rest = next;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Build a Diameter message: header + AVP bytes, with a correct length field.
    fn diameter_msg(cmd: u32, request: bool, app_id: u32, avps: &[u8]) -> Vec<u8> {
        let total = DIAMETER_HDR_LEN + avps.len();
        let mut m = Vec::with_capacity(total);
        m.push(DIAMETER_VERSION);
        m.extend_from_slice(&(total as u32).to_be_bytes()[1..4]); // 24-bit length
        m.push(if request { CMD_FLAG_REQUEST } else { 0 });
        m.extend_from_slice(&cmd.to_be_bytes()[1..4]); // 24-bit command code
        m.extend_from_slice(&app_id.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes()); // hop-by-hop
        m.extend_from_slice(&0u32.to_be_bytes()); // end-to-end
        m.extend_from_slice(avps);
        m
    }

    /// Build a User-Name AVP (code 1, no vendor) carrying an IMSI string.
    fn user_name_avp(imsi: &str) -> Vec<u8> {
        let len = AVP_HDR_LEN + imsi.len();
        let mut a = Vec::new();
        a.extend_from_slice(&AVP_USER_NAME.to_be_bytes());
        a.push(0); // flags
        a.extend_from_slice(&(len as u32).to_be_bytes()[1..4]);
        a.extend_from_slice(imsi.as_bytes());
        while !a.len().is_multiple_of(4) {
            a.push(0);
        }
        a
    }

    #[test]
    fn decodes_air_request() {
        let m = diameter_msg(318, true, S6A_APPLICATION_ID, &[]);
        let d = decode(&m).expect("valid");
        assert_eq!(d.command, S6aCommand::Named("Authentication-Information"));
        assert!(d.header.request);
        assert_eq!(d.header.application_id, S6A_APPLICATION_ID);
    }

    #[test]
    fn decodes_ulr_with_imsi() {
        let avp = user_name_avp("001010123456789");
        let m = diameter_msg(316, true, S6A_APPLICATION_ID, &avp);
        let d = decode(&m).expect("valid");
        assert_eq!(d.command, S6aCommand::Named("Update-Location"));
        assert_eq!(d.user_name.as_deref(), Some("001010123456789"));
    }

    #[test]
    fn answer_bit_distinguished() {
        let m = diameter_msg(316, false, S6A_APPLICATION_ID, &[]);
        let d = decode(&m).expect("valid");
        assert!(!d.header.request); // ULA, not ULR
    }

    #[test]
    fn unknown_command_reported() {
        let m = diameter_msg(999, true, S6A_APPLICATION_ID, &[]);
        let d = decode(&m).expect("valid");
        assert_eq!(d.command, S6aCommand::Unknown(999));
    }

    #[test]
    fn not_diameter_rejected() {
        assert_eq!(decode(&[0x62, 0x00]), Err(DiameterDecodeError::NotDiameter));
        assert_eq!(decode(&[]), Err(DiameterDecodeError::NotDiameter));
        // Version byte != 1.
        let mut m = diameter_msg(316, true, S6A_APPLICATION_ID, &[]);
        m[0] = 2;
        assert_eq!(decode(&m), Err(DiameterDecodeError::NotDiameter));
    }

    #[test]
    fn avp_length_overrun_marks_truncated_no_panic() {
        // A User-Name AVP whose declared length overruns the message body.
        let mut avp = user_name_avp("001010123456789");
        // Corrupt the AVP length to a huge value.
        avp[5..8].copy_from_slice(&0xffffffu32.to_be_bytes()[1..4]);
        let m = diameter_msg(316, true, S6A_APPLICATION_ID, &avp);
        let d = decode(&m).expect("header valid");
        assert!(d.avps_truncated);
    }

    #[test]
    fn short_message_length_field_rejected() {
        let mut m = diameter_msg(316, true, S6A_APPLICATION_ID, &[]);
        // Set declared length below the header size.
        m[1..4].copy_from_slice(&5u32.to_be_bytes()[1..4]);
        assert_eq!(decode(&m), Err(DiameterDecodeError::NotDiameter));
    }
}
