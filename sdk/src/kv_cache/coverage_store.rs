//! Interval algebra + point map underlying [`crate::KvCache`].
//!
//! Two pieces of state:
//! - `points: BTreeMap<key, Option<value>>` — explicit `(key, value)` (Some) or
//!   tombstone (None).
//! - `intervals: BTreeMap<start, end>` — half-open `[start, end)` byte ranges
//!   that are fully known. Invariant: intervals are non-overlapping and
//!   non-adjacent (adjacent ranges merge on insert).
//!
//! Inside an interval, the absence of a point is authoritative; outside, it
//! means "we don't know".

use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct CoverageStore {
    points: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
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
        self.points.insert(key, value);
    }

    /// Outer `None` means no point stored. Outer `Some(None)` is a tombstone.
    pub fn get_point(&self, key: &[u8]) -> Option<&Option<Vec<u8>>> {
        self.points.get(key)
    }

    /// True iff the half-open range `[start, end)` is fully contained in a
    /// single coverage interval.
    pub fn covers_range(&self, start: &[u8], end: &[u8]) -> bool {
        if start >= end {
            return true;
        }
        if let Some((s, e)) = self
            .intervals
            .range(..=start.to_vec())
            .next_back()
        {
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
    pub fn iter_prefix_present(
        &self,
        prefix: &[u8],
    ) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
        let p = prefix.to_vec();
        self.points
            .range(p.clone()..)
            .take_while(move |(k, _)| k.starts_with(&p))
            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))
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
            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))
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
        assert_eq!(cs.get_point(b"a"), Some(&Some(s(b"1"))));
        assert_eq!(cs.get_point(b"b"), Some(&None));
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
        let got: Vec<_> = cs.iter_range_present(b"a", b"c").map(|(k, _)| k.clone()).collect();
        assert_eq!(got, vec![s(b"a"), s(b"b")]);
    }
}
