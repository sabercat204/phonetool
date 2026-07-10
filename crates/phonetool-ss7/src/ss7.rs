//! SS7 stack decode: SCCP → TCAP → MAP operation resolution.
//!
//! The defensive headline this produces is "which MAP operation touched which
//! subscriber-addressing". The layering, honestly scoped:
//!
//! - **TCAP + MAP are decoded fully and confidently** — TCAP is BER (built on the
//!   [`crate::ber`] reader) with well-known application-class message tags
//!   (ITU-T Q.773), and the MAP operation is the `operationCode` INTEGER inside the
//!   Invoke component, resolved against the grounded [`MAP_OPS`] table.
//! - **SCCP addressing is best-effort** — SCCP UDT/XUDT (ITU-T Q.713) is decoded to
//!   extract SSN and, where the Global Title format is the common international one
//!   (GTI=4), the GT digits. Per Req 4.1 an address field that does not parse
//!   cleanly is reported **absent, never guessed**. The SCCP data pointer locates
//!   the TCAP payload.
//!
//! A PDU handed in may begin at the SCCP layer (UDT/XUDT) or already at the TCAP
//! layer (a bare TCAP hex fixture). [`decode`] recognizes both.
//!
//! Grounding: SCCP message types + address format — ITU-T Q.713 §3–4. TCAP tags —
//! ITU-T Q.773 (Begin=0x62, End=0x64, Continue=0x65, Abort=0x67; component portion
//! [APPLICATION 12]=0x6C; Invoke=[CONTEXT 1]=0xA1, ReturnResultLast=0xA2,
//! ReturnError=0xA3, Reject=0xA4; transaction IDs [APPLICATION 8/9]=0x48/0x49;
//! dialogue portion [APPLICATION 11]=0x6B). MAP operation local values — 3GPP
//! TS 29.002, cross-checked against Wireshark `packet-gsm_map` operation names.

use serde::Serialize;

use crate::ber::{self, BerError};

/// SCCP Unitdata message type (Q.713 §4.6).
const SCCP_UDT: u8 = 0x09;
/// SCCP Extended Unitdata message type (Q.713 §4.18).
const SCCP_XUDT: u8 = 0x11;
/// SCCP Long Unitdata message type (Q.713).
const SCCP_LUDT: u8 = 0x13;

/// TCAP message tags (Q.773, application class, constructed).
const TCAP_BEGIN: u8 = 0x62;
const TCAP_END: u8 = 0x64;
const TCAP_CONTINUE: u8 = 0x65;
const TCAP_ABORT: u8 = 0x67;
const TCAP_UNIDIRECTIONAL: u8 = 0x61;

/// TCAP component portion tag [APPLICATION 12] constructed (Q.773).
const TCAP_COMPONENT_PORTION: u8 = 0x6c;

/// TCAP component tags [CONTEXT n] constructed (Q.773).
const TCAP_INVOKE: u8 = 0xa1;
const TCAP_RETURN_RESULT_LAST: u8 = 0xa2;
const TCAP_RETURN_ERROR: u8 = 0xa3;
const TCAP_REJECT: u8 = 0xa4;
const TCAP_RETURN_RESULT_NOT_LAST: u8 = 0xa7;

/// BER universal INTEGER tag (opcode / invoke-id encoding).
const BER_INTEGER: u8 = 0x02;

/// The decoded SCCP layer: the addressing a message carries. Every field is
/// optional and reported absent rather than fabricated when it does not parse.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Sccp {
    /// Called-party Global Title digits, if a GT was present and parseable.
    pub called_gt: Option<String>,
    /// Called-party Subsystem Number, if present.
    pub called_ssn: Option<u8>,
    /// Calling-party Global Title digits, if present and parseable.
    pub calling_gt: Option<String>,
    /// Calling-party Subsystem Number, if present.
    pub calling_ssn: Option<u8>,
}

/// The TCAP message type (Q.773).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcapMessageType {
    Begin,
    End,
    Continue,
    Abort,
    Unidirectional,
}

/// The TCAP component type carried in the component portion (Q.773).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    Invoke,
    ReturnResultLast,
    ReturnResultNotLast,
    ReturnError,
    Reject,
}

/// A resolved MAP operation, or an unrecognized local opcode reported verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum MapOp {
    /// A named MAP operation from the grounded table.
    Named(&'static str),
    /// A local operation code not in the grounded table — reported, never omitted.
    Unknown(i64),
}

/// The decoded SS7 finding for one PDU: the layers that decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ss7Decoded {
    /// SCCP addressing, when an SCCP layer was present and (best-effort) decoded.
    pub sccp: Option<Sccp>,
    /// TCAP message type, when the TCAP layer decoded.
    pub tcap_type: Option<TcapMessageType>,
    /// The component type of the first component, when present.
    pub component: Option<ComponentType>,
    /// The MAP operation named by the first Invoke, when present.
    pub operation: Option<MapOp>,
}

/// Why an SS7 decode failed at the outermost layer (a per-PDU error; the caller
/// turns it into `Finding { decoded: false }`, never a run abort).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Ss7DecodeError {
    /// The PDU is neither a recognized SCCP message nor a TCAP message.
    #[error("not an SS7 (SCCP/TCAP) PDU")]
    NotSs7,
    /// The TCAP BER structure was malformed.
    #[error("TCAP decode: {0}")]
    Tcap(#[from] BerError),
}

/// The grounded MAP operation-code table (3GPP TS 29.002 local operation values;
/// names cross-checked against Wireshark `packet-gsm_map`). **Deliberately
/// partial**: it seeds the widely-published privacy-sensitive operations plus a few
/// common benign ones, each grounded. A code not present here resolves to
/// [`MapOp::Unknown`] — never invented. Extend as further values are verified
/// against the standard.
const MAP_OPS: &[(i64, &str)] = &[
    // --- privacy-sensitive: location-disclosure / intercept-enabling ---
    (2, "updateLocation"),       // TS 29.002 — registration; intercept-enabling
    (3, "cancelLocation"),       // TS 29.002
    (7, "insertSubscriberData"), // TS 29.002 — subscriber-data push
    (22, "sendRoutingInfo"),     // SRI — routing/location reveal
    (45, "sendRoutingInfoForSM"), // SRI-SM — the SMS-routing location vector
    (46, "mo-forwardSM"),        // TS 29.002
    (44, "mt-forwardSM"),        // TS 29.002
    (56, "sendAuthenticationInfo"), // auth-vector fetch — intercept-enabling
    (67, "purgeMS"),             // TS 29.002
    (70, "provideSubscriberInfo"), // PSI — serving-node/location reveal
    (71, "anyTimeInterrogation"), // ATI — the canonical location-tracking op
    (58, "sendIMSI"),            // IMSI disclosure
    // --- common benign control-plane ops (grounded, classified Benign) ---
    (23, "updateGprsLocation"), // TS 29.002
    (43, "checkIMEI"),          // TS 29.002
    (57, "restoreData"),        // TS 29.002
];

/// Resolve a MAP local operation code to a name, or [`MapOp::Unknown`].
fn resolve_map_op(code: i64) -> MapOp {
    for &(c, name) in MAP_OPS {
        if c == code {
            return MapOp::Named(name);
        }
    }
    MapOp::Unknown(code)
}

/// Decode one PDU as SS7. Recognizes an SCCP UDT/XUDT/LUDT front layer (extracting
/// addressing and locating the TCAP payload) or a bare TCAP message. Total over
/// arbitrary bytes.
///
/// # Errors
/// [`Ss7DecodeError::NotSs7`] if the PDU is neither SCCP nor TCAP-shaped;
/// [`Ss7DecodeError::Tcap`] if a recognized TCAP layer is structurally malformed.
pub fn decode(pdu: &[u8]) -> Result<Ss7Decoded, Ss7DecodeError> {
    let first = *pdu.first().ok_or(Ss7DecodeError::NotSs7)?;

    // SCCP front layer? Extract addressing (best-effort) and the TCAP slice.
    if matches!(first, SCCP_UDT | SCCP_XUDT | SCCP_LUDT) {
        let (sccp, tcap_bytes) = decode_sccp_udt(pdu);
        let mut decoded = Ss7Decoded {
            sccp: Some(sccp),
            tcap_type: None,
            component: None,
            operation: None,
        };
        if let Some(tcap) = tcap_bytes {
            // A malformed inner TCAP is a partial decode, not a hard error: keep
            // the SCCP layer we already have.
            if let Ok(t) = decode_tcap(tcap) {
                decoded.tcap_type = Some(t.tcap_type);
                decoded.component = t.component;
                decoded.operation = t.operation;
            }
        }
        return Ok(decoded);
    }

    // Bare TCAP message?
    if is_tcap_tag(first) {
        let t = decode_tcap(pdu)?;
        return Ok(Ss7Decoded {
            sccp: None,
            tcap_type: Some(t.tcap_type),
            component: t.component,
            operation: t.operation,
        });
    }

    Err(Ss7DecodeError::NotSs7)
}

fn is_tcap_tag(tag: u8) -> bool {
    matches!(
        tag,
        TCAP_BEGIN | TCAP_END | TCAP_CONTINUE | TCAP_ABORT | TCAP_UNIDIRECTIONAL
    )
}

/// Best-effort SCCP UDT/XUDT decode (Q.713 §4.6): extract SSN and GT digits for
/// each address, and return the TCAP payload located via the data pointer. Any
/// field that does not parse cleanly is reported absent (Req 4.1). Returns the
/// addressing and an optional TCAP slice.
fn decode_sccp_udt(pdu: &[u8]) -> (Sccp, Option<&[u8]>) {
    let mut sccp = Sccp::default();

    // UDT layout: type(0) class(1) ptr_called(2) ptr_calling(3) ptr_data(4), each
    // pointer relative to its own octet. XUDT inserts a hop-counter at offset 1,
    // shifting the pointers to 2/3/4/5 — handle the common UDT case; for XUDT the
    // pointers are one further along.
    let msg_type = pdu.first().copied().unwrap_or(0);
    let ptr_base = if msg_type == SCCP_UDT { 2 } else { 3 };

    let called = sccp_address_at(pdu, ptr_base);
    let calling = sccp_address_at(pdu, ptr_base + 1);
    if let Some((gt, ssn)) = called {
        sccp.called_gt = gt;
        sccp.called_ssn = ssn;
    }
    if let Some((gt, ssn)) = calling {
        sccp.calling_gt = gt;
        sccp.calling_ssn = ssn;
    }

    // Data pointer → TCAP. The pointer at ptr_base+2 is relative to its own octet.
    let data_ptr_pos = ptr_base + 2;
    let tcap = sccp_pointer_target(pdu, data_ptr_pos).and_then(|start| {
        // The data parameter is length-prefixed (1 byte) in UDT.
        let len = pdu.get(start).copied().map(usize::from)?;
        let data_start = start.checked_add(1)?;
        let data_end = data_start.checked_add(len)?;
        pdu.get(data_start..data_end)
    });

    (sccp, tcap)
}

/// Resolve an SCCP pointer at `pos` (a byte whose value is the offset from `pos`
/// to the target). Returns the absolute target index, or `None` if out of range or
/// a null (zero) pointer.
fn sccp_pointer_target(pdu: &[u8], pos: usize) -> Option<usize> {
    let ptr = pdu.get(pos).copied()?;
    if ptr == 0 {
        return None; // null pointer — parameter absent
    }
    pos.checked_add(usize::from(ptr))
}

/// Decode one SCCP address (called or calling) whose pointer is at `ptr_pos`.
/// Returns `(gt_digits, ssn)`, each optional. Best-effort: an address whose GT
/// format is not the recognized international form yields `None` GT digits.
fn sccp_address_at(pdu: &[u8], ptr_pos: usize) -> Option<(Option<String>, Option<u8>)> {
    let addr_start = sccp_pointer_target(pdu, ptr_pos)?;
    // Address parameter: length(1) then that many bytes.
    let addr_len = pdu.get(addr_start).copied().map(usize::from)?;
    let body_start = addr_start.checked_add(1)?;
    let body_end = body_start.checked_add(addr_len)?;
    let body = pdu.get(body_start..body_end)?;

    // Address indicator is the first body byte (Q.713 §3.4.1).
    let ai = *body.first()?;
    let pc_present = ai & 0x01 != 0;
    let ssn_present = ai & 0x02 != 0;
    let gti = (ai >> 2) & 0x0f;

    let mut idx = 1usize;
    if pc_present {
        idx = idx.checked_add(2)?; // 14-bit ITU point code, 2 octets
    }
    let ssn = if ssn_present {
        let s = body.get(idx).copied();
        idx = idx.checked_add(1)?;
        s
    } else {
        None
    };

    // GT digits, only for the common international format GTI=4
    // (TT + numbering-plan/encoding + NAI + TBCD digits). Other formats → absent.
    let gt = if gti == 0x04 {
        // Skip TT(1) + np/es(1) + nai(1) = 3 octets, then TBCD digits.
        let digits_start = idx.checked_add(3)?;
        body.get(digits_start..).map(decode_tbcd)
    } else {
        None
    };

    Some((gt, ssn))
}

/// Decode TBCD (Telephony Binary-Coded Decimal) digits: each octet holds two
/// digits, low nibble first; nibble 0xF is a filler that ends the number
/// (Q.713 / TS 29.002). Non-decimal nibbles other than filler are rendered as-is
/// in hex so nothing is silently dropped.
fn decode_tbcd(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let lo = b & 0x0f;
        let hi = b >> 4;
        for nib in [lo, hi] {
            match nib {
                0..=9 => s.push((b'0' + nib) as char),
                0x0f => return s, // filler terminates
                other => s.push(char::from_digit(u32::from(other), 16).unwrap_or('?')),
            }
        }
    }
    s
}

/// A decoded TCAP message's salient fields.
struct TcapDecoded {
    tcap_type: TcapMessageType,
    component: Option<ComponentType>,
    operation: Option<MapOp>,
}

/// Decode a TCAP message (Q.773). Reads the message-type tag, walks its children
/// to find the component portion, then decodes the first component (and, if an
/// Invoke, its MAP operation code). Total/bounded via the [`crate::ber`] reader.
fn decode_tcap(pdu: &[u8]) -> Result<TcapDecoded, Ss7DecodeError> {
    let (msg, _) = ber::read_tlv(pdu)?;
    let tcap_type = match msg.identifier {
        TCAP_BEGIN => TcapMessageType::Begin,
        TCAP_END => TcapMessageType::End,
        TCAP_CONTINUE => TcapMessageType::Continue,
        TCAP_ABORT => TcapMessageType::Abort,
        TCAP_UNIDIRECTIONAL => TcapMessageType::Unidirectional,
        _ => return Err(Ss7DecodeError::NotSs7),
    };

    // Children of the message: transaction IDs, optional dialogue portion, and the
    // component portion [APPLICATION 12] = 0x6C. A malformed inner structure yields
    // whatever we decoded so far (partial).
    let children = match ber::read_children(msg.value, 1) {
        Ok(c) => c,
        Err((partial, _)) => partial,
    };

    let mut component = None;
    let mut operation = None;
    if let Some(portion) = children
        .iter()
        .find(|t| t.identifier == TCAP_COMPONENT_PORTION)
    {
        let comps = match ber::read_children(portion.value, 2) {
            Ok(c) => c,
            Err((partial, _)) => partial,
        };
        if let Some(first) = comps.first() {
            component = component_type(first.identifier);
            if first.identifier == TCAP_INVOKE {
                operation = decode_invoke_operation(first.value);
            }
        }
    }

    Ok(TcapDecoded {
        tcap_type,
        component,
        operation,
    })
}

fn component_type(tag: u8) -> Option<ComponentType> {
    match tag {
        TCAP_INVOKE => Some(ComponentType::Invoke),
        TCAP_RETURN_RESULT_LAST => Some(ComponentType::ReturnResultLast),
        TCAP_RETURN_RESULT_NOT_LAST => Some(ComponentType::ReturnResultNotLast),
        TCAP_RETURN_ERROR => Some(ComponentType::ReturnError),
        TCAP_REJECT => Some(ComponentType::Reject),
        _ => None,
    }
}

/// Decode an Invoke component's MAP operation code (Q.773 Invoke: invokeID INTEGER,
/// optional linkedID, operationCode). The operationCode for MAP is a local
/// INTEGER; a global (OID) operation is not resolved to a name here (reported as no
/// operation rather than guessed).
fn decode_invoke_operation(invoke: &[u8]) -> Option<MapOp> {
    let children = match ber::read_children(invoke, 3) {
        Ok(c) => c,
        Err((partial, _)) => partial,
    };
    // The operation code is the last INTEGER before any parameter — in practice the
    // second INTEGER (after invokeID). Take the second universal-INTEGER child.
    let integers: Vec<&crate::ber::Tlv<'_>> = children
        .iter()
        .filter(|t| t.identifier == BER_INTEGER)
        .collect();
    // integers[0] = invokeID, integers[1] = local operationCode (when present).
    let op_tlv = integers.get(1)?;
    let code = decode_ber_integer(op_tlv.value)?;
    Some(resolve_map_op(code))
}

/// Decode a BER INTEGER value (two's-complement, big-endian, up to 8 bytes) into an
/// `i64`. Returns `None` for an empty or oversized encoding.
fn decode_ber_integer(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    // Sign-extend from the top bit of the first byte.
    let negative = bytes.first().copied().unwrap_or(0) & 0x80 != 0;
    let mut val: i64 = if negative { -1 } else { 0 };
    for &b in bytes {
        val = (val << 8) | i64::from(b);
    }
    Some(val)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Build a minimal TCAP Begin carrying one Invoke of the given local opcode:
    ///   62 len { 48 01 01 (otid)  6C len { A1 len { 02 01 01 (invokeID)  02 01 op } } }
    fn tcap_begin_invoke(opcode: u8) -> Vec<u8> {
        let invoke_body = vec![0x02, 0x01, 0x01, 0x02, 0x01, opcode];
        let mut invoke = vec![TCAP_INVOKE, invoke_body.len() as u8];
        invoke.extend_from_slice(&invoke_body);
        let mut portion = vec![TCAP_COMPONENT_PORTION, invoke.len() as u8];
        portion.extend_from_slice(&invoke);
        let otid = vec![0x48, 0x01, 0x01];
        let mut body = otid;
        body.extend_from_slice(&portion);
        let mut msg = vec![TCAP_BEGIN, body.len() as u8];
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn decodes_ati_invoke() {
        let pdu = tcap_begin_invoke(71);
        let d = decode(&pdu).expect("valid TCAP");
        assert_eq!(d.tcap_type, Some(TcapMessageType::Begin));
        assert_eq!(d.component, Some(ComponentType::Invoke));
        assert_eq!(d.operation, Some(MapOp::Named("anyTimeInterrogation")));
    }

    #[test]
    fn decodes_sri_sm_invoke() {
        let d = decode(&tcap_begin_invoke(45)).expect("valid");
        assert_eq!(d.operation, Some(MapOp::Named("sendRoutingInfoForSM")));
    }

    #[test]
    fn unknown_opcode_reported_not_dropped() {
        // 99 (0x63) is a positive single-byte BER INTEGER not in MAP_OPS.
        let d = decode(&tcap_begin_invoke(99)).expect("valid");
        assert_eq!(d.operation, Some(MapOp::Unknown(99)));
    }

    #[test]
    fn tcap_end_message_type() {
        let mut msg = tcap_begin_invoke(71);
        msg[0] = TCAP_END;
        let d = decode(&msg).expect("valid");
        assert_eq!(d.tcap_type, Some(TcapMessageType::End));
    }

    #[test]
    fn not_ss7_rejected() {
        assert_eq!(decode(&[0x00, 0x01, 0x02]), Err(Ss7DecodeError::NotSs7));
        assert_eq!(decode(&[]), Err(Ss7DecodeError::NotSs7));
    }

    #[test]
    fn truncated_tcap_is_error_not_panic() {
        // Begin tag with a length that overruns.
        let r = decode(&[TCAP_BEGIN, 0x40, 0x48, 0x01]);
        assert!(matches!(r, Err(Ss7DecodeError::Tcap(_))));
    }

    #[test]
    fn tbcd_decode_with_filler() {
        // 0x21 0x43 0x65 → "123456"; 0x21 0xF3 → "123" (filler ends).
        assert_eq!(decode_tbcd(&[0x21, 0x43, 0x65]), "123456");
        assert_eq!(decode_tbcd(&[0x21, 0xf3]), "123");
    }

    #[test]
    fn ber_integer_decodes_signed() {
        assert_eq!(decode_ber_integer(&[0x71]), Some(0x71));
        assert_eq!(decode_ber_integer(&[0x01, 0x00]), Some(256));
        assert_eq!(decode_ber_integer(&[]), None);
    }

    #[test]
    fn sccp_udt_wraps_tcap() {
        // Build UDT: type=09, class=00, ptr_called, ptr_calling, ptr_data, then
        // two minimal addresses and the TCAP data param.
        let tcap = tcap_begin_invoke(71);
        // addresses: length-prefixed; use SSN-only (AI=0x02) minimal addresses.
        let called = vec![0x02, 0x02, 0x06]; // len=2: AI=0x02 (SSN present), SSN=6 (HLR)
        let calling = vec![0x02, 0x02, 0x08]; // SSN=8 (MSC)
        // Layout after the 3 pointers (at offsets 2,3,4):
        //   called @ off = 5, calling @ off = 5+len(called)=8, data @ off = 11
        let mut pdu = vec![SCCP_UDT, 0x00];
        // pointers are relative to their own octet:
        //   ptr_called @2 → target 5  → 5-2 = 3
        //   ptr_calling@3 → target 8  → 8-3 = 5
        //   ptr_data  @4 → target 11 → 11-4 = 7
        pdu.push(3);
        pdu.push(5);
        pdu.push(7);
        pdu.extend_from_slice(&called);
        pdu.extend_from_slice(&calling);
        pdu.push(tcap.len() as u8); // data length prefix
        pdu.extend_from_slice(&tcap);

        let d = decode(&pdu).expect("valid UDT");
        let sccp = d.sccp.expect("sccp present");
        assert_eq!(sccp.called_ssn, Some(6));
        assert_eq!(sccp.calling_ssn, Some(8));
        assert_eq!(d.operation, Some(MapOp::Named("anyTimeInterrogation")));
    }

    #[test]
    fn sccp_with_unparseable_inner_keeps_addressing() {
        // UDT whose data param is garbage TCAP: SCCP addressing still returned.
        let called = vec![0x02, 0x02, 0x06];
        let calling = vec![0x02, 0x02, 0x08];
        let garbage = vec![0x00, 0x00, 0x00];
        let mut pdu = vec![SCCP_UDT, 0x00, 3, 5, 7];
        pdu.extend_from_slice(&called);
        pdu.extend_from_slice(&calling);
        pdu.push(garbage.len() as u8);
        pdu.extend_from_slice(&garbage);
        let d = decode(&pdu).expect("sccp ok even if tcap not");
        assert_eq!(d.sccp.expect("sccp").called_ssn, Some(6));
        assert_eq!(d.operation, None);
    }
}
