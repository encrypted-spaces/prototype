//! Interval algebra + point map underlying [`crate::KvCache`].
//!
//! Two pieces of state:
//! - `points: BTreeMap<key, DataEntry>` — a `Value { bytes, .. }` presence or a
//!   `Deleted` tombstone.
//! - `intervals: BTreeMap<start, end>` — half-open `[start, end)` byte ranges
//!   that are fully known. Invariant: intervals are non-overlapping and
//!   non-adjacent (adjacent ranges merge on insert).
//!
//! Inside an interval, the absence of a point is authoritative; outside, it
//! means "we don't know".

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// A cache data entry.
///
/// `Value::decrypted` is a lazy per-entry decrypted-bytes memoization slot.
/// It is not soundness-bearing: equality and debug output ignore it.
pub(crate) enum DataEntry {
    Value {
        /// Raw bytes authenticated by the proof at the cache anchor.
        bytes: Vec<u8>,
        /// Lazily populated decrypted bytes for encrypted columns.
        decrypted: OnceLock<Vec<u8>>,
    },
    Deleted,
}

impl DataEntry {
    pub(crate) fn value(bytes: Vec<u8>) -> Self {
        Self::Value {
            bytes,
            decrypted: OnceLock::new(),
        }
    }
}

impl std::fmt::Debug for DataEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataEntry::Value { bytes, .. } => {
                f.debug_struct("Value").field("bytes", bytes).finish()
            }
            DataEntry::Deleted => f.write_str("Deleted"),
        }
    }
}

impl PartialEq for DataEntry {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (DataEntry::Value { bytes: a, .. }, DataEntry::Value { bytes: b, .. }) => a == b,
            (DataEntry::Deleted, DataEntry::Deleted) => true,
            _ => false,
        }
    }
}

impl Eq for DataEntry {}

#[derive(Debug, Default)]
pub struct CoverageStore {
    points: BTreeMap<Vec<u8>, DataEntry>,
    intervals: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl CoverageStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.points.clear();
        self.intervals.clear();
    }

    /// Record `key → Some(value)` (presence) or `key → None` (tombstone).
    pub fn put_point(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) {
        let entry = match value {
            Some(bytes) => DataEntry::value(bytes),
            None => DataEntry::Deleted,
        };
        self.points.insert(key, entry);
    }

    /// `None` means no point stored; `Some(DataEntry::Deleted)` is a tombstone;
    /// `Some(DataEntry::Value { .. })` is a stored value.
    #[cfg(test)]
    pub fn get_point(&self, key: &[u8]) -> Option<&DataEntry> {
        self.points.get(key)
    }

    /// True iff the half-open range `[start, end)` is fully contained in a
    /// single coverage interval.
    pub fn covers_range(&self, start: &[u8], end: &[u8]) -> bool {
        if start >= end {
            return true;
        }
        if let Some((s, e)) = self.intervals.range(..=start.to_vec()).next_back() {
            s.as_slice() <= start && end <= e.as_slice()
        } else {
            false
        }
    }

    /// Extend coverage by `[start, end)`, merging with any overlapping or
    /// adjacent existing intervals.
    pub fn extend_coverage(&mut self, start: Vec<u8>, end: Vec<u8>) {
        if start >= end {
            return;
        }
        let mut new_start = start;
        let mut new_end = end;

        // Candidates are intervals with start <= new_end AND end >= new_start
        // (overlap or touch at endpoint).
        let to_merge: Vec<(Vec<u8>, Vec<u8>)> = self
            .intervals
            .range(..=new_end.clone())
            .filter(|(_, e)| **e >= new_start)
            .map(|(s, e)| (s.clone(), e.clone()))
            .collect();

        for (k, v) in to_merge {
            self.intervals.remove(&k);
            if k < new_start {
                new_start = k;
            }
            if v > new_end {
                new_end = v;
            }
        }

        self.intervals.insert(new_start, new_end);
    }

    /// Iterate present (non-tombstone) point entries whose key starts with
    /// `prefix`, in sorted key order.
    pub fn iter_prefix_present(&self, prefix: &[u8]) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
        let p = prefix.to_vec();
        self.points
            .range(p.clone()..)
            .take_while(move |(k, _)| k.starts_with(&p))
            .filter_map(|(k, v)| match v {
                DataEntry::Value { bytes, .. } => Some((k, bytes)),
                DataEntry::Deleted => None,
            })
    }

    /// Iterate present entries whose key starts with `prefix`, preserving
    /// access to the entry identity for per-entry decryption memoization.
    pub fn iter_prefix_entries(
        &self,
        prefix: &[u8],
    ) -> impl Iterator<Item = (&Vec<u8>, &DataEntry)> {
        let p = prefix.to_vec();
        self.points
            .range(p.clone()..)
            .take_while(move |(k, _)| k.starts_with(&p))
            .filter(|(_, v)| matches!(v, DataEntry::Value { .. }))
    }

    /// Iterate present (non-tombstone) point entries in the half-open range
    /// `[start, end)`, in sorted key order.
    pub fn iter_range_present(
        &self,
        start: &[u8],
        end: &[u8],
    ) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
        self.points
            .range(start.to_vec()..end.to_vec())
            .filter_map(|(k, v)| match v {
                DataEntry::Value { bytes, .. } => Some((k, bytes)),
                DataEntry::Deleted => None,
            })
    }

    /// Iterate present entries in the half-open range `[start, end)`,
    /// preserving access to the entry identity for per-entry decryption
    /// memoization.
    pub fn iter_range_entries(
        &self,
        start: &[u8],
        end: &[u8],
    ) -> impl Iterator<Item = (&Vec<u8>, &DataEntry)> {
        self.points
            .range(start.to_vec()..end.to_vec())
            .filter(|(_, v)| matches!(v, DataEntry::Value { .. }))
    }

    /// Largest covered prefix of `[start, end)` walking forward from
    /// `start`. Returns the byte position where coverage first stops
    /// (clamped to `end`). If `start` itself isn't covered, returns
    /// `start` (no prefix is covered).
    pub fn covered_prefix_end(&self, start: &[u8], end: &[u8]) -> Vec<u8> {
        if start >= end {
            return end.to_vec();
        }
        // The interval containing or immediately preceding `start`.
        let Some((s, e)) = self.intervals.range(..=start.to_vec()).next_back() else {
            return start.to_vec();
        };
        if s.as_slice() > start || e.as_slice() <= start {
            return start.to_vec();
        }
        // Walk forward as long as adjacent intervals continue the run.
        let mut covered_end = e.clone();
        while covered_end.as_slice() < end {
            match self.intervals.get(&covered_end) {
                Some(next_end) => covered_end = next_end.clone(),
                None => break,
            }
        }
        if covered_end.as_slice() > end {
            end.to_vec()
        } else {
            covered_end
        }
    }

    /// Largest covered suffix of `[start, end)` walking backward from `end`.
    /// Returns the byte position where coverage begins (clamped to `start`).
    /// If the byte just before `end` isn't covered, returns `end` (no suffix
    /// is covered).
    pub fn covered_suffix_start(&self, start: &[u8], end: &[u8]) -> Vec<u8> {
        if start >= end {
            return start.to_vec();
        }
        // The interval immediately before `end` (covers byte end-1 if any
        // interval starting at or before end-1 ends at or after end).
        let last_byte_bound = end.to_vec();
        let Some((s, e)) = self.intervals.range(..last_byte_bound).next_back() else {
            return end.to_vec();
        };
        if e.as_slice() < end {
            return end.to_vec();
        }
        // Walk backward as long as adjacent intervals continue the run.
        let mut covered_start = s.clone();
        while let Some((prev_start, prev_end)) =
            self.intervals.range(..covered_start.clone()).next_back()
        {
            if prev_end.as_slice() < covered_start.as_slice() {
                break;
            }
            covered_start = prev_start.clone();
            if covered_start.as_slice() <= start {
                break;
            }
        }
        if covered_start.as_slice() < start {
            start.to_vec()
        } else {
            covered_start
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(b: &[u8]) -> Vec<u8> {
        b.to_vec()
    }

    #[test]
    fn covers_range_empty_store() {
        let cs = CoverageStore::new();
        assert!(!cs.covers_range(b"a", b"b"));
    }

    #[test]
    fn covers_range_fully_within() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"a"), s(b"z"));
        assert!(cs.covers_range(b"b", b"y"));
        assert!(cs.covers_range(b"a", b"z"));
    }

    #[test]
    fn covers_range_not_within() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"b"), s(b"y"));
        assert!(!cs.covers_range(b"a", b"c"));
        assert!(!cs.covers_range(b"x", b"z"));
    }

    #[test]
    fn extend_merges_overlap() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"a"), s(b"m"));
        cs.extend_coverage(s(b"k"), s(b"z"));
        assert!(cs.covers_range(b"a", b"z"));
        assert_eq!(cs.intervals.len(), 1);
    }

    #[test]
    fn extend_merges_adjacent() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"a"), s(b"m"));
        cs.extend_coverage(s(b"m"), s(b"z"));
        assert!(cs.covers_range(b"a", b"z"));
        assert_eq!(cs.intervals.len(), 1);
    }

    #[test]
    fn extend_keeps_disjoint_separate() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"a"), s(b"b"));
        cs.extend_coverage(s(b"y"), s(b"z"));
        assert_eq!(cs.intervals.len(), 2);
        assert!(!cs.covers_range(b"a", b"z"));
        assert!(cs.covers_range(b"a", b"b"));
        assert!(cs.covers_range(b"y", b"z"));
    }

    #[test]
    fn extend_swallows_contained_intervals() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"c"), s(b"d"));
        cs.extend_coverage(s(b"e"), s(b"f"));
        cs.extend_coverage(s(b"a"), s(b"z"));
        assert_eq!(cs.intervals.len(), 1);
        assert!(cs.covers_range(b"a", b"z"));
    }

    #[test]
    fn extend_ignores_zero_length() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"a"), s(b"a"));
        assert_eq!(cs.intervals.len(), 0);
    }

    #[test]
    fn points_put_and_get() {
        let mut cs = CoverageStore::new();
        cs.put_point(s(b"a"), Some(s(b"1")));
        cs.put_point(s(b"b"), None);
        assert_eq!(cs.get_point(b"a"), Some(&DataEntry::value(s(b"1"))));
        assert_eq!(cs.get_point(b"b"), Some(&DataEntry::Deleted));
        assert_eq!(cs.get_point(b"c"), None);
    }

    #[test]
    fn iter_prefix_present_excludes_tombstones_and_outsiders() {
        let mut cs = CoverageStore::new();
        cs.put_point(s(b"row/1/col"), Some(s(b"v1")));
        cs.put_point(s(b"row/2/col"), None);
        cs.put_point(s(b"row/3/col"), Some(s(b"v3")));
        cs.put_point(s(b"other/4"), Some(s(b"v4")));
        let got: Vec<_> = cs
            .iter_prefix_present(b"row/")
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(got, vec![s(b"row/1/col"), s(b"row/3/col")]);
    }

    #[test]
    fn iter_range_present_respects_half_open_end() {
        let mut cs = CoverageStore::new();
        cs.put_point(s(b"a"), Some(s(b"1")));
        cs.put_point(s(b"b"), Some(s(b"2")));
        cs.put_point(s(b"c"), Some(s(b"3")));
        let got: Vec<_> = cs
            .iter_range_present(b"a", b"c")
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(got, vec![s(b"a"), s(b"b")]);
    }

    #[test]
    fn covered_prefix_end_full_coverage() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"a"), s(b"z"));
        assert_eq!(cs.covered_prefix_end(b"a", b"z"), s(b"z"));
        assert_eq!(cs.covered_prefix_end(b"b", b"y"), s(b"y"));
    }

    #[test]
    fn covered_prefix_end_partial() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"a"), s(b"m"));
        // Walk [a, z) — covered through m, then gap.
        assert_eq!(cs.covered_prefix_end(b"a", b"z"), s(b"m"));
    }

    #[test]
    fn covered_prefix_end_runs_through_adjacent_intervals() {
        let mut cs = CoverageStore::new();
        // Two adjacent intervals merge on extend, so to test the walk-through
        // pattern we construct a disjoint case and a contained case.
        cs.extend_coverage(s(b"a"), s(b"f"));
        cs.extend_coverage(s(b"m"), s(b"z"));
        // [a, p) — covered through f, then gap before m.
        assert_eq!(cs.covered_prefix_end(b"a", b"p"), s(b"f"));
    }

    #[test]
    fn covered_prefix_end_start_not_covered() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"m"), s(b"z"));
        // start `a` is uncovered → returns start.
        assert_eq!(cs.covered_prefix_end(b"a", b"z"), s(b"a"));
    }

    #[test]
    fn covered_suffix_start_full_coverage() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"a"), s(b"z"));
        assert_eq!(cs.covered_suffix_start(b"a", b"z"), s(b"a"));
        assert_eq!(cs.covered_suffix_start(b"b", b"y"), s(b"b"));
    }

    #[test]
    fn covered_suffix_start_partial() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"m"), s(b"z"));
        // Walk back from `z` — covered down to `m`, then gap.
        assert_eq!(cs.covered_suffix_start(b"a", b"z"), s(b"m"));
    }

    #[test]
    fn covered_suffix_start_end_not_covered() {
        let mut cs = CoverageStore::new();
        cs.extend_coverage(s(b"a"), s(b"f"));
        // The byte just before `z` is uncovered → returns end.
        assert_eq!(cs.covered_suffix_start(b"a", b"z"), s(b"z"));
    }
}
