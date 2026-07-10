//! Pure aggregation: decoded per-RAT cells → one [`CellMap`] with a neighbour
//! graph. Socket-free, radio-free — runs today over recorded captures.
//!
//! Load-bearing invariant (Req 5.3): when the same cell identity is observed more
//! than once with *inconsistent* parameters, both observations are retained. A
//! parameter flip (a LAC that changes between two sightings of the same CID) is
//! itself a rogue-BTS signal, so silently overwriting one would erase evidence.

use std::collections::BTreeMap;

use crate::decode_gsm::GsmCell;
use crate::decode_lte::LteCell;
use crate::decode_nr::NrCell;

/// A per-RAT cell identity key. Used to group observations that claim to be the
/// same cell so the detector can compare their parameters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum CellId {
    /// GSM identity: ARFCN plus (when decoded) LAC and CID. ARFCN is always
    /// known (radio layer); LAC/CID may be absent for an SI2-only observation.
    Gsm {
        /// The ARFCN the cell was seen on.
        arfcn: u16,
        /// Location Area Code, if decoded.
        lac: Option<u16>,
        /// Cell Identity, if decoded.
        cid: Option<u16>,
    },
    /// LTE identity (PCI + EARFCN). Populated when `decode_lte` is built.
    Lte {
        /// Physical Cell Identity.
        pci: Option<u16>,
        /// EARFCN.
        earfcn: Option<u32>,
    },
    /// 5G NR identity (PCI + GSCN). Populated when `decode_nr` is built.
    Nr {
        /// Physical Cell Identity.
        pci: Option<u16>,
        /// GSCN.
        gscn: Option<u32>,
    },
}

/// One observation in the map, tagged by RAT. Keeps the full decoded cell so the
/// detector sees every field (signal, neighbours, PLMN).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase", tag = "rat")]
pub enum CellObservation {
    /// A GSM observation.
    Gsm(GsmCell),
    /// An LTE observation.
    Lte(LteCell),
    /// A 5G NR observation.
    Nr(NrCell),
}

/// One identity's grouped observations — the serializable form of a `CellMap`
/// entry (JSON object keys must be strings, so the enum-keyed map is rendered as
/// a list of these instead).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CellEntry {
    /// The per-RAT identity these observations share.
    pub id: CellId,
    /// The retained observations (more than one ⇒ a preserved parameter flip).
    pub observations: Vec<CellObservation>,
}

/// The aggregate map: observations grouped by identity, plus a neighbour graph.
#[derive(Debug, Clone, Default)]
pub struct CellMap {
    /// Observations grouped by `CellId`. A key with more than one observation is
    /// a re-sighting; if the observations differ, that difference is preserved
    /// for the detector (Req 5.3).
    pub cells: BTreeMap<CellId, Vec<CellObservation>>,
    /// Advertised neighbour edges: source ARFCN → the ARFCNs it lists. GSM only
    /// in v1 (LTE/NR neighbour relations are Open Question 7).
    pub neighbours: BTreeMap<u16, Vec<u16>>,
}

impl CellMap {
    /// Total number of distinct cell identities in the map.
    #[must_use]
    pub fn distinct_cells(&self) -> usize {
        self.cells.len()
    }

    /// Total number of observations across all identities.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.cells.values().map(Vec::len).sum()
    }

    /// The cells as a serializable list of `{id, observations}` entries. Used for
    /// `Event` data, since JSON object keys must be strings and `CellId` is an
    /// enum. Order is deterministic (the backing map is a `BTreeMap`).
    #[must_use]
    pub fn entries(&self) -> Vec<CellEntry> {
        self.cells
            .iter()
            .map(|(id, observations)| CellEntry {
                id: id.clone(),
                observations: observations.clone(),
            })
            .collect()
    }
}

/// Build a [`CellMap`] from decoded GSM/LTE/NR observations. Pure. GSM neighbour
/// ARFCN lists become graph edges; a re-sighting with different parameters is
/// retained, not merged.
#[must_use]
pub fn build(gsm: &[GsmCell], lte: &[LteCell], nr: &[NrCell]) -> CellMap {
    let mut map = CellMap::default();

    for cell in gsm {
        let id = CellId::Gsm {
            arfcn: cell.arfcn,
            lac: cell.lac,
            cid: cell.cid,
        };
        // Neighbour edges: only record when this observation actually decoded a
        // list. An empty decoded list is a real "advertises no neighbours" edge
        // (kept, for MissingNeighbours); an undecoded-format list is NOT recorded
        // as "no neighbours" (that would fabricate a tell).
        if !cell.neighbours_undecoded {
            let entry = map.neighbours.entry(cell.arfcn).or_default();
            for &n in &cell.neighbours {
                if !entry.contains(&n) {
                    entry.push(n);
                }
            }
        }
        push_observation(&mut map, id, CellObservation::Gsm(cell.clone()));
    }

    for cell in lte {
        let id = CellId::Lte {
            pci: cell.pci,
            earfcn: cell.earfcn,
        };
        push_observation(&mut map, id, CellObservation::Lte(cell.clone()));
    }

    for cell in nr {
        let id = CellId::Nr {
            pci: cell.pci,
            gscn: cell.gscn,
        };
        push_observation(&mut map, id, CellObservation::Nr(cell.clone()));
    }

    map
}

/// Append an observation under its identity. A duplicate identical observation
/// is dropped (no value in storing the same sighting twice); a differing one is
/// retained (the parameter flip is the signal).
fn push_observation(map: &mut CellMap, id: CellId, obs: CellObservation) {
    let entry = map.cells.entry(id).or_default();
    if !entry.contains(&obs) {
        entry.push(obs);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn gsm(arfcn: u16, lac: Option<u16>, cid: Option<u16>) -> GsmCell {
        GsmCell {
            mcc: Some(262),
            mnc: Some(2),
            mnc_digits: Some(2),
            lac,
            cid,
            arfcn,
            signal_dbm: Some(-70),
            neighbours: Vec::new(),
            neighbours_undecoded: false,
        }
    }

    #[test]
    fn aggregates_distinct_cells() {
        let map = build(
            &[gsm(1, Some(10), Some(100)), gsm(2, Some(10), Some(101))],
            &[],
            &[],
        );
        assert_eq!(map.distinct_cells(), 2);
        assert_eq!(map.observation_count(), 2);
    }

    #[test]
    fn retains_conflicting_observations_of_one_identity() {
        // Same ARFCN+LAC+CID key, but different signal level: kept as two.
        let mut a = gsm(1, Some(10), Some(100));
        let mut b = gsm(1, Some(10), Some(100));
        a.signal_dbm = Some(-70);
        b.signal_dbm = Some(-40);
        let map = build(&[a, b], &[], &[]);
        assert_eq!(map.distinct_cells(), 1);
        assert_eq!(map.observation_count(), 2, "the parameter flip is retained");
    }

    #[test]
    fn deduplicates_identical_observations() {
        let a = gsm(1, Some(10), Some(100));
        let map = build(&[a.clone(), a], &[], &[]);
        assert_eq!(map.observation_count(), 1);
    }

    #[test]
    fn builds_neighbour_edges_from_gsm() {
        let mut c = gsm(1, Some(10), Some(100));
        c.neighbours = vec![5, 9, 13];
        let map = build(&[c], &[], &[]);
        assert_eq!(map.neighbours.get(&1), Some(&vec![5, 9, 13]));
    }

    #[test]
    fn undecoded_neighbour_list_is_not_recorded_as_no_neighbours() {
        let mut c = gsm(1, Some(10), Some(100));
        c.neighbours_undecoded = true;
        let map = build(&[c], &[], &[]);
        assert!(
            !map.neighbours.contains_key(&1),
            "an undecoded list must not become a 'no neighbours' edge"
        );
    }
}
