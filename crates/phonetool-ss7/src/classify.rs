//! Privacy-sensitivity classification — the defensive payload.
//!
//! Maps a decoded operation (MAP or Diameter S6a) to a [`DisclosureClass`]. The
//! classifier reports that a flagged operation is **present in the capture**; it
//! does NOT assert the operation was malicious, unauthorized, or attributable
//! (Req 6.2). A ULR from a subscriber's own home MME is routine; a cross-boundary
//! ATI is the abuse case — the bytes alone cannot distinguish them, and the tool
//! does not pretend to.
//!
//! Grounding: the class membership follows the well-documented SS7/Diameter
//! attack-surface literature (GSMA FS.11 for SS7, FS.19 for Diameter — the
//! "category 1/2/3 should-not-cross-boundary" guidance) as reflected in published
//! security research (e.g. the P1 Security / SRLabs SS7 surveys). An operation
//! whose class is not grounded resolves to [`DisclosureClass::Unknown`] — never
//! guessed (Req 6.4). The named operations here are the widely-published ones; the
//! exact per-opcode GSMA category is an operator Open Question (design OQ3).

use serde::Serialize;

use crate::diameter::S6aCommand;
use crate::ss7::MapOp;

/// The privacy-sensitivity classification of a decoded operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureClass {
    /// The operation's response reveals or enables discovery of a subscriber's
    /// location or serving node (e.g. MAP ATI, SRI-SM, SRI, PSI; Diameter ULR, IDR).
    LocationDisclosure,
    /// The operation fetches authentication material or redirects/hijacks
    /// registration (e.g. MAP sendAuthenticationInfo, updateLocation; Diameter AIR).
    InterceptEnabling,
    /// A decoded operation with no privacy-sensitivity concern.
    Benign,
    /// The operation decoded, but its class is not yet grounded — reported honestly
    /// rather than guessed.
    Unknown,
}

impl DisclosureClass {
    /// Whether this class is a flagged (privacy-sensitive) one.
    #[must_use]
    pub fn is_flagged(self) -> bool {
        matches!(self, Self::LocationDisclosure | Self::InterceptEnabling)
    }
}

/// Classify a resolved MAP operation. An `Unknown` opcode (not in the grounded
/// table) is `DisclosureClass::Unknown` — its class cannot be known if its identity
/// isn't. A named op not listed here is `Benign` (it decoded and is not on the
/// privacy-sensitive surface).
#[must_use]
pub fn classify_map(op: &MapOp) -> DisclosureClass {
    let name = match op {
        MapOp::Named(n) => *n,
        MapOp::Unknown(_) => return DisclosureClass::Unknown,
    };
    match name {
        // Location-disclosure surface.
        "anyTimeInterrogation"
        | "provideSubscriberInfo"
        | "sendRoutingInfo"
        | "sendRoutingInfoForSM"
        | "sendIMSI" => DisclosureClass::LocationDisclosure,
        // Intercept-enabling surface.
        "sendAuthenticationInfo" | "updateLocation" | "insertSubscriberData" => {
            DisclosureClass::InterceptEnabling
        }
        // Decoded and known, but not privacy-sensitive.
        _ => DisclosureClass::Benign,
    }
}

/// Classify a resolved Diameter S6a command. `request` distinguishes the operation
/// direction but not its class (both ULR and ULA touch the same surface); an
/// `Unknown` command → `DisclosureClass::Unknown`.
#[must_use]
pub fn classify_diameter(cmd: &S6aCommand) -> DisclosureClass {
    let name = match cmd {
        S6aCommand::Named(n) => *n,
        S6aCommand::Unknown(_) => return DisclosureClass::Unknown,
    };
    match name {
        "Update-Location" | "Insert-Subscriber-Data" => DisclosureClass::LocationDisclosure,
        "Authentication-Information" => DisclosureClass::InterceptEnabling,
        _ => DisclosureClass::Benign,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn ati_is_location_disclosure() {
        assert_eq!(
            classify_map(&MapOp::Named("anyTimeInterrogation")),
            DisclosureClass::LocationDisclosure
        );
    }

    #[test]
    fn send_auth_info_is_intercept_enabling() {
        assert_eq!(
            classify_map(&MapOp::Named("sendAuthenticationInfo")),
            DisclosureClass::InterceptEnabling
        );
    }

    #[test]
    fn known_benign_map_op() {
        assert_eq!(
            classify_map(&MapOp::Named("checkIMEI")),
            DisclosureClass::Benign
        );
    }

    #[test]
    fn unknown_map_opcode_is_unknown_class() {
        assert_eq!(classify_map(&MapOp::Unknown(200)), DisclosureClass::Unknown);
    }

    #[test]
    fn air_is_intercept_enabling() {
        assert_eq!(
            classify_diameter(&S6aCommand::Named("Authentication-Information")),
            DisclosureClass::InterceptEnabling
        );
    }

    #[test]
    fn ulr_is_location_disclosure() {
        assert_eq!(
            classify_diameter(&S6aCommand::Named("Update-Location")),
            DisclosureClass::LocationDisclosure
        );
    }

    #[test]
    fn unknown_diameter_cmd_is_unknown_class() {
        assert_eq!(
            classify_diameter(&S6aCommand::Unknown(999)),
            DisclosureClass::Unknown
        );
    }

    #[test]
    fn is_flagged_only_for_sensitive() {
        assert!(DisclosureClass::LocationDisclosure.is_flagged());
        assert!(DisclosureClass::InterceptEnabling.is_flagged());
        assert!(!DisclosureClass::Benign.is_flagged());
        assert!(!DisclosureClass::Unknown.is_flagged());
    }
}
