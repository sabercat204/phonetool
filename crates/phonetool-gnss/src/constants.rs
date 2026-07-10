//! GPS L1 C/A signal constants grounded in IS-GPS-200.
//!
//! Every constant here is cited to a specific section of IS-GPS-200 Rev N.
//! No signal parameter is invented or approximated.

/// GPS L1 carrier frequency: 1575.42 MHz (IS-GPS-200 §3.3.1.1).
pub const L1_CARRIER_HZ: f64 = 1_575_420_000.0;

/// C/A code chipping rate: 1.023 Mchip/s (IS-GPS-200 §3.3.2.3).
pub const CA_CHIP_RATE: f64 = 1_023_000.0;

/// C/A code length: 1023 chips per period (IS-GPS-200 §3.3.2.3).
pub const CA_CODE_LEN: usize = 1023;

/// C/A code period: 1 ms (1023 chips / 1.023 Mchip/s).
pub const CA_CODE_PERIOD_S: f64 = 0.001;

/// Navigation message bit rate: 50 bit/s (IS-GPS-200 §20.3.2).
pub const NAV_BIT_RATE: f64 = 50.0;

/// Navigation message bit period: 20 ms (20 C/A code periods per bit).
pub const NAV_BIT_PERIOD_S: f64 = 0.020;

/// Subframe length: 300 bits = 10 words × 30 bits (IS-GPS-200 §20.3.2).
pub const SUBFRAME_BITS: usize = 300;

/// Word length: 30 bits (IS-GPS-200 §20.3.2).
pub const WORD_BITS: usize = 30;

/// Words per subframe: 10 (IS-GPS-200 §20.3.2).
pub const WORDS_PER_SUBFRAME: usize = 10;

/// Subframe duration: 6 seconds (300 bits / 50 bps).
pub const SUBFRAME_DURATION_S: f64 = 6.0;

/// Preamble of a TLM word: 0b10001011 (IS-GPS-200 §20.3.3.1).
pub const TLM_PREAMBLE: u8 = 0b1000_1011;

/// Speed of light in vacuum (m/s), used in pseudorange calculation.
pub const C_LIGHT: f64 = 299_792_458.0;

/// WGS-84 Earth rotation rate (rad/s) (IS-GPS-200 §20.3.3.4.3).
pub const OMEGA_E: f64 = 7.2921151467e-5;

/// WGS-84 gravitational parameter (m³/s²) (IS-GPS-200 §20.3.3.4.3).
pub const MU_EARTH: f64 = 3.986005e14;

/// WGS-84 semi-major axis (equatorial radius), meters.
pub const WGS84_A: f64 = 6_378_137.0;

/// WGS-84 flattening (1 / 298.257223563).
pub const WGS84_F: f64 = 1.0 / 298.257_223_563;

/// WGS-84 first eccentricity squared: e² = f·(2 − f).
pub const WGS84_E2: f64 = WGS84_F * (2.0 - WGS84_F);
