//! The fail-closed regulatory check: band-vs-license consistency and a power
//! ceiling, run **before** any sink is touched.
//!
//! Given the `TxGrant`'s band and the operation's requested frequency and power,
//! [`check`] enforces (1) the frequency lies within the band the grant authorizes
//! (a 70cm grant cannot key a 2m frequency), and (2) the effective power does not
//! exceed min(grant power, the band's regulatory maximum). A band absent from the
//! table **fails closed** — the plan never assumes a range or a limit for a band it
//! does not know.
//!
//! Grounding: the table is US **FCC Part 97** amateur allocations. Frequency edges
//! are the Part 97.301 band segments; the power figure is the general Part 97.313
//! ceiling of **1500 W PEP = ~61.76 dBm** (the statutory maximum; many bands/modes
//! are lower, but 1500 W is the umbrella cap this table applies uniformly — a
//! conservative, citable umbrella, not a per-segment fabrication). Other
//! jurisdictions (ISED) and services (CB/GMRS/MURS) are later additions behind the
//! same mechanism; an unlisted band fails closed today.

/// FCC Part 97.313 general power ceiling: 1500 W PEP. In dBm: 10*log10(1500*1000) =
/// 61.76 dBm. Applied as the umbrella regulatory maximum across the amateur bands
/// in this table (a conservative citable cap, not a per-segment invented value).
const FCC_PART97_MAX_DBM: f64 = 61.76;

/// One band-plan entry: the authorized band name, its inclusive frequency range in
/// Hz, and the regulatory power ceiling in dBm.
struct Band {
    name: &'static str,
    lo_hz: u64,
    hi_hz: u64,
    max_dbm: f64,
}

/// The grounded band plan (US FCC Part 97 amateur allocations, §97.301 segment
/// edges). Frequency edges are exact band boundaries; the power figure is the
/// §97.313 1500 W umbrella. Deliberately partial — an unlisted band fails closed.
const BAND_PLAN: &[Band] = &[
    // HF
    Band {
        name: "40m",
        lo_hz: 7_000_000,
        hi_hz: 7_300_000,
        max_dbm: FCC_PART97_MAX_DBM,
    },
    Band {
        name: "20m",
        lo_hz: 14_000_000,
        hi_hz: 14_350_000,
        max_dbm: FCC_PART97_MAX_DBM,
    },
    // VHF/UHF
    Band {
        name: "2m",
        lo_hz: 144_000_000,
        hi_hz: 148_000_000,
        max_dbm: FCC_PART97_MAX_DBM,
    },
    Band {
        name: "70cm",
        lo_hz: 420_000_000,
        hi_hz: 450_000_000,
        max_dbm: FCC_PART97_MAX_DBM,
    },
];

/// Why a transmission was refused by the band-plan check.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BandError {
    /// The requested frequency is outside the grant's band.
    #[error("frequency {freq_hz} Hz is outside band '{band}' ({lo_hz}-{hi_hz} Hz)")]
    FreqOutOfBand {
        /// The band the grant authorizes.
        band: String,
        /// The requested frequency.
        freq_hz: u64,
        /// The band's low edge.
        lo_hz: u64,
        /// The band's high edge.
        hi_hz: u64,
    },
    /// The requested power exceeds the ceiling (min of grant and regulatory max).
    #[error("power {requested_dbm} dBm exceeds ceiling {ceiling_dbm} dBm")]
    OverPower {
        /// The requested/authorized power.
        requested_dbm: f64,
        /// The enforced ceiling = min(grant power, regulatory max).
        ceiling_dbm: f64,
    },
    /// The band named by the grant is not in the grounded plan — fail closed.
    #[error("band '{0}' is not in the grounded band plan (fail-closed)")]
    UnknownBand(String),
}

/// The frequency/power envelope a transmission is confined to, once the band-plan
/// check has passed. Returned so the caller can surface the enforced ceiling.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Envelope {
    /// The requested frequency (Hz), validated in-band.
    pub freq_hz: u64,
    /// The enforced power ceiling (dBm) = min(grant power, regulatory max).
    pub ceiling_dbm: f64,
}

/// Look up a band by its (leading, case-insensitive) name. The grant's band string
/// may be verbose ("70cm amateur"); match on a leading token so it still resolves.
fn find_band(band: &str) -> Option<&'static Band> {
    let key = band.trim().to_ascii_lowercase();
    BAND_PLAN
        .iter()
        .find(|b| key == b.name || key.starts_with(&format!("{} ", b.name)))
}

/// Enforce band-vs-license consistency and the power ceiling.
///
/// `band` is `TxGrant::band()`, `power_dbm` is `TxGrant::power_dbm()`, `freq_hz` is
/// the operation's requested transmit frequency. Runs before any sink work (Req 5.5).
///
/// # Errors
/// - [`BandError::UnknownBand`] if the band is not in the grounded plan (fail-closed).
/// - [`BandError::FreqOutOfBand`] if `freq_hz` is outside the band's range.
/// - [`BandError::OverPower`] if `power_dbm` exceeds min(grant, regulatory max).
pub fn check(band: &str, freq_hz: u64, power_dbm: f64) -> Result<Envelope, BandError> {
    let Some(b) = find_band(band) else {
        return Err(BandError::UnknownBand(band.to_owned()));
    };
    if freq_hz < b.lo_hz || freq_hz > b.hi_hz {
        return Err(BandError::FreqOutOfBand {
            band: b.name.to_owned(),
            freq_hz,
            lo_hz: b.lo_hz,
            hi_hz: b.hi_hz,
        });
    }
    // Power ceiling = min(grant power, band regulatory max). A non-finite grant
    // power is treated as failing closed (the gate already rejects non-finite, but
    // stay defensive here).
    let ceiling = if power_dbm.is_finite() {
        power_dbm.min(b.max_dbm)
    } else {
        b.max_dbm
    };
    // The requested power IS the grant power here (the op transmits at the
    // authorized level); refuse if it exceeds the band's regulatory maximum.
    if !power_dbm.is_finite() || power_dbm > b.max_dbm {
        return Err(BandError::OverPower {
            requested_dbm: power_dbm,
            ceiling_dbm: b.max_dbm,
        });
    }
    Ok(Envelope {
        freq_hz,
        ceiling_dbm: ceiling,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn in_band_passes() {
        let env = check("2m", 146_520_000, 40.0).expect("in band");
        assert_eq!(env.freq_hz, 146_520_000);
        assert!((env.ceiling_dbm - 40.0).abs() < 1e-9);
    }

    #[test]
    fn verbose_band_name_resolves() {
        assert!(check("70cm amateur", 435_000_000, 30.0).is_ok());
    }

    #[test]
    fn freq_in_wrong_band_refused() {
        // A 70cm grant cannot key a 2m frequency.
        let err = check("70cm", 146_000_000, 30.0).unwrap_err();
        assert!(matches!(err, BandError::FreqOutOfBand { .. }));
    }

    #[test]
    fn unknown_band_fails_closed() {
        assert!(matches!(
            check("11m CB", 27_185_000, 4.0),
            Err(BandError::UnknownBand(_))
        ));
    }

    #[test]
    fn over_power_refused() {
        // 1500 W = 61.76 dBm ceiling; 70 dBm exceeds it.
        let err = check("20m", 14_200_000, 70.0).unwrap_err();
        assert!(matches!(err, BandError::OverPower { .. }));
    }

    #[test]
    fn non_finite_power_fails_closed() {
        assert!(matches!(
            check("2m", 146_000_000, f64::NAN),
            Err(BandError::OverPower { .. })
        ));
    }

    #[test]
    fn band_edges_inclusive() {
        assert!(check("40m", 7_000_000, 30.0).is_ok());
        assert!(check("40m", 7_300_000, 30.0).is_ok());
        assert!(check("40m", 6_999_999, 30.0).is_err());
        assert!(check("40m", 7_300_001, 30.0).is_err());
    }
}
