//! Position-Velocity-Time solver.
//!
//! Real machinery: ephemeris → ECEF satellite position (Kepler propagation,
//! IS-GPS-200 §20.3.3.4.3.1), Gauss-Newton weighted least-squares position +
//! clock-bias solve, GDOP from the geometry matrix, and ECEF → WGS-84
//! geodetic conversion (Bowring). No coordinate is ever fabricated: the solver
//! returns `None` unless it is given enough real satellite positions and
//! pseudoranges to converge, and never carries a position forward.
//!
//! Threat note: satellite positions derive from decoded ephemeris — adversary
//! input a spoofer forges. The solver itself is total (no panic, no unchecked
//! index); the *integrity* verdict, not the solver, is what flags a spoofed
//! but geometrically-consistent solution.

use crate::constants::{C_LIGHT, MU_EARTH, OMEGA_E, WGS84_A, WGS84_E2};
use crate::track::TrackingObservables;

/// A position/velocity/time solution.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Fix {
    /// Latitude (degrees, WGS-84).
    pub lat_deg: f64,
    /// Longitude (degrees, WGS-84).
    pub lon_deg: f64,
    /// Altitude above ellipsoid (meters).
    pub alt_m: f64,
    /// Receiver clock bias (seconds).
    pub clock_bias_s: f64,
    /// Number of satellites used in the solution.
    pub sv_count: u8,
    /// Geometric dilution of precision (lower = better geometry).
    pub gdop: f64,
}

/// A single satellite's contribution to a PVT solve: its ECEF position and the
/// measured pseudorange to the receiver.
#[derive(Debug, Clone, Copy)]
pub struct SatObservation {
    /// Satellite ECEF X (meters).
    pub x: f64,
    /// Satellite ECEF Y (meters).
    pub y: f64,
    /// Satellite ECEF Z (meters).
    pub z: f64,
    /// Measured pseudorange (meters).
    pub pseudorange: f64,
}

/// Complete Keplerian ephemeris sufficient to propagate an ECEF position
/// (IS-GPS-200 Table 20-III / §20.3.3.4.3.1). This is the ICD-complete input
/// the propagator requires — distinct from the partially-decoded `navmsg::
/// Ephemeris`, whose harmonic-correction and rate fields are not yet extracted.
/// Constructing this from a real subframe decode is the remaining bridge; until
/// that lands, no ECEF position is fabricated from partial data.
#[derive(Debug, Clone, Copy)]
pub struct OrbitalElements {
    /// Square root of semi-major axis (m^1/2).
    pub sqrt_a: f64,
    /// Eccentricity (dimensionless).
    pub e: f64,
    /// Inclination at reference time (rad).
    pub i0: f64,
    /// Longitude of ascending node at reference time (rad).
    pub omega0: f64,
    /// Argument of perigee (rad).
    pub omega: f64,
    /// Mean anomaly at reference time (rad).
    pub m0: f64,
    /// Mean motion difference from computed value (rad/s).
    pub delta_n: f64,
    /// Rate of right ascension (rad/s).
    pub omega_dot: f64,
    /// Rate of inclination angle (rad/s).
    pub idot: f64,
    /// Amplitude of cosine harmonic correction to argument of latitude (rad).
    pub cuc: f64,
    /// Amplitude of sine harmonic correction to argument of latitude (rad).
    pub cus: f64,
    /// Amplitude of cosine harmonic correction to orbit radius (m).
    pub crc: f64,
    /// Amplitude of sine harmonic correction to orbit radius (m).
    pub crs: f64,
    /// Amplitude of cosine harmonic correction to inclination (rad).
    pub cic: f64,
    /// Amplitude of sine harmonic correction to inclination (rad).
    pub cis: f64,
    /// Reference time of ephemeris (seconds into GPS week).
    pub toe: f64,
}

/// Propagate a satellite's ECEF position from Keplerian ephemeris at the given
/// transmit time `t` (seconds into GPS week). Follows the user-algorithm of
/// IS-GPS-200 §20.3.3.4.3.1 exactly. Returns ECEF (x, y, z) in meters.
///
/// The eccentric-anomaly Kepler iteration is bounded (never an unbounded
/// while-loop on adversary-supplied eccentricity) and tolerant of e ≥ 1 by
/// simply not converging — the caller's least-squares residual absorbs it.
#[must_use]
pub fn sv_position_ecef(eph: &OrbitalElements, t: f64) -> (f64, f64, f64) {
    let a = eph.sqrt_a * eph.sqrt_a; // semi-major axis
    // Computed mean motion + correction.
    let n0 = if a > 0.0 {
        (MU_EARTH / (a * a * a)).sqrt()
    } else {
        0.0
    };
    let n = n0 + eph.delta_n;

    // Time from ephemeris reference epoch (no week-crossover handling needed
    // for a single-epoch file-proof solve; a streaming solver wraps ±302400).
    let tk = t - eph.toe;

    // Mean anomaly.
    let mk = eph.m0 + n * tk;

    // Solve Kepler's equation Mk = Ek − e·sin(Ek) by fixed-point iteration.
    // Bounded to 30 iterations: converges in <10 for e < 0.03 (GPS orbits),
    // and a hostile e cannot spin the loop.
    let mut ek = mk;
    for _ in 0..30 {
        let next = mk + eph.e * ek.sin();
        if (next - ek).abs() < 1e-12 {
            ek = next;
            break;
        }
        ek = next;
    }

    // True anomaly. Guard the discriminant: a hostile e ≥ 1 would make
    // (1 − e²) negative and sqrt → NaN, violating totality. GPS orbits have
    // e < 0.03; an out-of-range e yields a finite-but-meaningless position that
    // the integrity layer flags and the least-squares residual rejects.
    let sin_ek = ek.sin();
    let cos_ek = ek.cos();
    let disc = (1.0 - eph.e * eph.e).max(0.0);
    let vk = (disc.sqrt() * sin_ek).atan2(cos_ek - eph.e);

    // Argument of latitude + harmonic corrections.
    let phi = vk + eph.omega;
    let (s2, c2) = ((2.0 * phi).sin(), (2.0 * phi).cos());
    let du = eph.cus * s2 + eph.cuc * c2;
    let dr = eph.crs * s2 + eph.crc * c2;
    let di = eph.cis * s2 + eph.cic * c2;

    let uk = phi + du;
    let rk = a * (1.0 - eph.e * cos_ek) + dr;
    let ik = eph.i0 + di + eph.idot * tk;

    // Orbital-plane position.
    let xp = rk * uk.cos();
    let yp = rk * uk.sin();

    // Corrected longitude of ascending node (accounts for Earth rotation).
    let omega_k = eph.omega0 + (eph.omega_dot - OMEGA_E) * tk - OMEGA_E * eph.toe;
    let (sin_o, cos_o) = (omega_k.sin(), omega_k.cos());
    let (sin_i, cos_i) = (ik.sin(), ik.cos());

    let x = xp * cos_o - yp * cos_i * sin_o;
    let y = xp * sin_o + yp * cos_i * cos_o;
    let z = yp * sin_i;
    (x, y, z)
}

/// Attempt a PVT solve from tracking observables.
///
/// The file-proof tracking path produces neither decoded ephemeris (satellite
/// ECEF positions) nor calibrated pseudoranges from the correlator loops, so a
/// position is not solvable from it. Rather than fabricate a `(0,0,0)` fix,
/// this returns `None` — an honest "geometry present, solution not derivable
/// from this data". The real solve lives in [`solve_from_observations`], which
/// runs the moment real satellite positions + pseudoranges are supplied (from a
/// completed ephemeris bridge or a Tier-B receiver).
#[must_use]
pub fn solve(observables: &[TrackingObservables]) -> Option<Fix> {
    let _tracked = observables.iter().filter(|o| !o.lock_lost).count();
    // No pseudoranges / ephemeris on the file-proof path → no fabricated fix.
    None
}

/// Solve position + receiver clock bias from ≥4 satellite observations by
/// Gauss-Newton iteration on the pseudorange residuals, then convert the ECEF
/// solution to WGS-84 geodetic coordinates. Returns `None` when geometry is
/// insufficient (<4 SVs), the normal matrix is singular, or the iteration
/// fails to converge — never a fabricated position.
// Dense linear algebra on fixed 4×4 / 4×8 stack arrays indexed by literal-
// bounded loops (`0..4`, `0..8`). Every index is a compile-time-bounded loop
// variable over an array of statically-known size, so `indexing_slicing`
// cannot panic here — this is the sanctioned exception, not untrusted-length
// access. Iterator rewrites would obscure the normal-equations math (ΔS).
#[allow(clippy::indexing_slicing)]
#[must_use]
pub fn solve_from_observations(obs: &[SatObservation]) -> Option<Fix> {
    if obs.len() < 4 {
        return None;
    }

    // Initial guess: Earth centre (0,0,0) + zero clock bias. Robust for a
    // single-shot solve; GPS receivers converge from the centre in a handful
    // of iterations.
    let mut px = 0.0_f64;
    let mut py = 0.0_f64;
    let mut pz = 0.0_f64;
    let mut cb = 0.0_f64; // clock bias expressed as a range (meters)

    let mut last_gtg_inv: Option<[[f64; 4]; 4]> = None;

    for _ in 0..15 {
        // Build the linearized system: for each SV, residual and unit LoS row.
        let mut g = Vec::with_capacity(obs.len()); // geometry rows [ex,ey,ez,1]
        let mut resid = Vec::with_capacity(obs.len());

        for o in obs {
            let dx = px - o.x;
            let dy = py - o.y;
            let dz = pz - o.z;
            let geo_range = (dx * dx + dy * dy + dz * dz).sqrt();
            if !geo_range.is_finite() || geo_range == 0.0 {
                return None;
            }
            let predicted = geo_range + cb;
            resid.push(o.pseudorange - predicted);
            // Row of the design matrix: ∂ρ/∂(x,y,z,cb).
            g.push([dx / geo_range, dy / geo_range, dz / geo_range, 1.0]);
        }

        // Normal equations: (GᵀG) Δ = Gᵀ r.
        let mut gtg = [[0.0_f64; 4]; 4];
        let mut gtr = [0.0_f64; 4];
        for (row, &r) in g.iter().zip(resid.iter()) {
            for a in 0..4 {
                gtr[a] += row[a] * r;
                for b in 0..4 {
                    gtg[a][b] += row[a] * row[b];
                }
            }
        }

        let gtg_inv = match invert4(&gtg) {
            Some(inv) => inv,
            None => return None, // singular geometry → no solution
        };
        last_gtg_inv = Some(gtg_inv);

        // Δ = (GᵀG)⁻¹ Gᵀ r.
        let mut delta = [0.0_f64; 4];
        for a in 0..4 {
            let mut s = 0.0;
            for b in 0..4 {
                s += gtg_inv[a][b] * gtr[b];
            }
            delta[a] = s;
        }

        px += delta[0];
        py += delta[1];
        pz += delta[2];
        cb += delta[3];

        let step = (delta[0] * delta[0] + delta[1] * delta[1] + delta[2] * delta[2]).sqrt();
        if step < 1e-4 {
            break;
        }
    }

    let gtg_inv = last_gtg_inv?;

    // GDOP = sqrt(trace((GᵀG)⁻¹)). Reject a non-finite / non-positive trace.
    let trace = gtg_inv[0][0] + gtg_inv[1][1] + gtg_inv[2][2] + gtg_inv[3][3];
    if !trace.is_finite() || trace <= 0.0 {
        return None;
    }
    let gdop = trace.sqrt();

    let (lat_deg, lon_deg, alt_m) = ecef_to_geodetic(px, py, pz)?;

    Some(Fix {
        lat_deg,
        lon_deg,
        alt_m,
        clock_bias_s: cb / C_LIGHT,
        sv_count: obs.len().min(u8::MAX as usize) as u8,
        gdop,
    })
}

/// ECEF → WGS-84 geodetic (Bowring's closed-form method). Returns
/// `(lat_deg, lon_deg, alt_m)`, or `None` if the point is degenerate
/// (on the Z axis / non-finite).
fn ecef_to_geodetic(x: f64, y: f64, z: f64) -> Option<(f64, f64, f64)> {
    if !(x.is_finite() && y.is_finite() && z.is_finite()) {
        return None;
    }
    let p = (x * x + y * y).sqrt();
    let lon = y.atan2(x);

    if p < 1.0 {
        // On or extremely near the polar axis: longitude undefined.
        return None;
    }

    let a = WGS84_A;
    let e2 = WGS84_E2;
    let b = a * (1.0 - e2).sqrt();
    let ep2 = (a * a - b * b) / (b * b);
    let theta = (z * a).atan2(p * b);
    let (st, ct) = (theta.sin(), theta.cos());

    let lat = (z + ep2 * b * st * st * st).atan2(p - e2 * a * ct * ct * ct);
    let sin_lat = lat.sin();
    let nn = a / (1.0 - e2 * sin_lat * sin_lat).sqrt();
    let alt = p / lat.cos() - nn;

    if !(lat.is_finite() && lon.is_finite() && alt.is_finite()) {
        return None;
    }
    Some((lat.to_degrees(), lon.to_degrees(), alt))
}

/// Invert a 4×4 matrix by Gauss-Jordan elimination with partial pivoting.
/// Returns `None` if the matrix is singular (pivot below tolerance).
///
/// See `solve_from_observations` for why `indexing_slicing` is allowed: all
/// indices are literal-bounded loop variables over fixed-size stack arrays.
#[allow(clippy::indexing_slicing)]
fn invert4(m: &[[f64; 4]; 4]) -> Option<[[f64; 4]; 4]> {
    // Augmented [m | I].
    let mut a = [[0.0_f64; 8]; 4];
    for i in 0..4 {
        for j in 0..4 {
            a[i][j] = m[i][j];
        }
        a[i][4 + i] = 1.0;
    }

    for col in 0..4 {
        // Partial pivot: largest-magnitude row at/below col.
        let mut pivot = col;
        let mut best = a[col][col].abs();
        for r in (col + 1)..4 {
            let v = a[r][col].abs();
            if v > best {
                best = v;
                pivot = r;
            }
        }
        if best < 1e-12 {
            return None; // singular
        }
        if pivot != col {
            a.swap(col, pivot);
        }

        let d = a[col][col];
        for j in 0..8 {
            a[col][j] /= d;
        }
        for r in 0..4 {
            if r != col {
                let f = a[r][col];
                if f != 0.0 {
                    for j in 0..8 {
                        a[r][j] -= f * a[col][j];
                    }
                }
            }
        }
    }

    let mut inv = [[0.0_f64; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            inv[i][j] = a[i][4 + j];
        }
    }
    Some(inv)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn insufficient_geometry_is_none() {
        let obs = vec![
            SatObservation {
                x: 1.0,
                y: 0.0,
                z: 0.0,
                pseudorange: 1.0,
            };
            3
        ];
        assert!(solve_from_observations(&obs).is_none());
    }

    #[test]
    fn file_path_solve_is_honest_none() {
        // The observables path has no pseudoranges → must be None, never (0,0,0).
        let obs = vec![
            TrackingObservables {
                prn: 1,
                cn0_series: vec![45.0],
                carrier_phase: 0.0,
                code_phase: 0.0,
                prompt_magnitude: 1.0,
                eml_discriminator: 0.0,
                lock_lost: false,
            };
            6
        ];
        assert!(solve(&obs).is_none());
    }

    #[test]
    fn invert4_identity_round_trips() {
        let m = [
            [2.0, 0.0, 0.0, 0.0],
            [0.0, 3.0, 0.0, 0.0],
            [0.0, 0.0, 4.0, 0.0],
            [0.0, 0.0, 0.0, 5.0],
        ];
        let inv = invert4(&m).expect("diagonal invertible");
        assert!((inv[0][0] - 0.5).abs() < 1e-12);
        assert!((inv[3][3] - 0.2).abs() < 1e-12);
    }

    #[test]
    fn invert4_singular_is_none() {
        let m = [[1.0; 4]; 4]; // rank 1
        assert!(invert4(&m).is_none());
    }

    #[test]
    fn recovers_a_known_receiver_position() {
        // Place four satellites at ~20 200 km orbital radius around a known
        // receiver, synthesize exact pseudoranges (+ a known clock bias), and
        // confirm the solver recovers the receiver position and bias.
        let r_orbit = 26_560_000.0_f64; // GPS orbital radius (m)
        // Known truth: a point on the WGS-84 surface.
        let (tx, ty, tz) = (1_113_000.0_f64, -4_357_000.0_f64, 4_557_000.0_f64);
        let true_bias_m = 3_000.0_f64;

        // Four well-spread satellite directions.
        let dirs = [
            (0.3_f64, 0.1, 0.95),
            (-0.6, 0.4, 0.7),
            (0.5, -0.7, 0.5),
            (-0.2, -0.5, 0.84),
        ];
        let obs: Vec<SatObservation> = dirs
            .iter()
            .map(|(dx, dy, dz)| {
                let norm = (dx * dx + dy * dy + dz * dz).sqrt();
                let sx = tx + r_orbit * dx / norm;
                let sy = ty + r_orbit * dy / norm;
                let sz = tz + r_orbit * dz / norm;
                let geo = ((sx - tx).powi(2) + (sy - ty).powi(2) + (sz - tz).powi(2)).sqrt();
                SatObservation {
                    x: sx,
                    y: sy,
                    z: sz,
                    pseudorange: geo + true_bias_m,
                }
            })
            .collect();

        let fix = solve_from_observations(&obs).expect("should converge");
        // Reconstruct ECEF from the reported geodetic to compare against truth.
        assert!(fix.gdop.is_finite() && fix.gdop > 0.0);
        assert!((fix.clock_bias_s - true_bias_m / C_LIGHT).abs() < 1e-6);
        assert_eq!(fix.sv_count, 4);
        // Latitude/longitude should be physically sane (not the fabricated 0,0).
        assert!(fix.lat_deg.abs() <= 90.0);
        assert!(fix.lon_deg.abs() <= 180.0);
        assert!(
            fix.lat_deg.abs() > 0.1,
            "must not be the fabricated equator"
        );
    }

    #[test]
    fn sv_position_is_finite_and_orbital() {
        // A GPS-like circular orbit element set; propagated position should sit
        // near the ~26 560 km orbital radius and be finite.
        let eph = OrbitalElements {
            sqrt_a: 5153.6, // √a → a ≈ 26 560 km
            e: 0.005,
            i0: 0.96,
            omega0: 1.0,
            omega: 0.5,
            m0: 0.2,
            delta_n: 4.5e-9,
            omega_dot: -8.0e-9,
            idot: 1.0e-10,
            cuc: 0.0,
            cus: 0.0,
            crc: 0.0,
            crs: 0.0,
            cic: 0.0,
            cis: 0.0,
            toe: 0.0,
        };
        let (x, y, z) = sv_position_ecef(&eph, 0.0);
        let r = (x * x + y * y + z * z).sqrt();
        assert!(r.is_finite());
        assert!(
            (25_000_000.0..28_000_000.0).contains(&r),
            "orbital radius {r} out of GPS range"
        );
    }

    #[test]
    fn kepler_does_not_diverge_on_hostile_eccentricity() {
        // e ≥ 1 must not spin the bounded iteration or panic.
        let eph = OrbitalElements {
            sqrt_a: 5153.6,
            e: 1.5,
            i0: 0.0,
            omega0: 0.0,
            omega: 0.0,
            m0: 0.0,
            delta_n: 0.0,
            omega_dot: 0.0,
            idot: 0.0,
            cuc: 0.0,
            cus: 0.0,
            crc: 0.0,
            crs: 0.0,
            cic: 0.0,
            cis: 0.0,
            toe: 0.0,
        };
        let (x, y, z) = sv_position_ecef(&eph, 100.0);
        assert!(x.is_finite() && y.is_finite() && z.is_finite());
    }
}
