//! Property tests for [`super::CoverageStore`] interval algebra.
//!
//! Cache correctness depends on "covered means authoritative" — if
//! `extend_coverage` or `covers_range` ever disagrees with what was
//! claimed, the cache can hand back stale or fabricated rows. The unit
//! tests in `coverage_store.rs` cover hand-picked edge cases; these
//! proptests check the invariants on randomly-generated workloads.
//!
//! Generators stay deliberately small (4-byte keys, ≤16-op sequences)
//! so each property runs in milliseconds.

use proptest::prelude::*;

use super::coverage_store::CoverageStore;

/// Small alphabet so the search hits boundary cases (adjacent intervals,
/// gaps of one byte, etc.) without generating noise we'd never see in
/// practice.
fn arb_key() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0u8..=4u8, 0..=4)
}

/// `(start, end)` with `start <= end`. Equal endpoints are valid empty
/// ranges (`extend_coverage` is a no-op there).
fn arb_interval() -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
    (arb_key(), arb_key()).prop_map(|(a, b)| if a <= b { (a, b) } else { (b, a) })
}

/// Reference oracle for `extend_coverage`: a sorted list of non-overlapping
/// non-adjacent half-open ranges. Implemented naively so any divergence
/// from `CoverageStore`'s production logic shows up.
#[derive(Default, Debug, Clone)]
struct IntervalOracle {
    intervals: Vec<(Vec<u8>, Vec<u8>)>,
}

impl IntervalOracle {
    fn extend(&mut self, start: Vec<u8>, end: Vec<u8>) {
        if start >= end {
            return;
        }
        let mut new_start = start;
        let mut new_end = end;
        let mut remaining = Vec::new();
        for (s, e) in self.intervals.drain(..) {
            // Touch or overlap: merge.
            if s <= new_end && e >= new_start {
                if s < new_start {
                    new_start = s;
                }
                if e > new_end {
                    new_end = e;
                }
            } else {
                remaining.push((s, e));
            }
        }
        remaining.push((new_start, new_end));
        remaining.sort();
        self.intervals = remaining;
    }

    fn covers(&self, start: &[u8], end: &[u8]) -> bool {
        if start >= end {
            return true;
        }
        self.intervals
            .iter()
            .any(|(s, e)| s.as_slice() <= start && end <= e.as_slice())
    }
}

proptest! {
    /// `extend_coverage(s, e)` followed by `covers_range(s, e)` is always true.
    #[test]
    fn extend_then_covers(ops in prop::collection::vec(arb_interval(), 0..=16)) {
        let mut store = CoverageStore::new();
        for (s, e) in &ops {
            store.extend_coverage(s.clone(), e.clone());
            prop_assert!(store.covers_range(s, e), "extend({s:?}..{e:?}) did not satisfy covers_range");
        }
    }

    /// `extend_coverage` is idempotent: extending the same range twice
    /// yields the same coverage as extending it once.
    #[test]
    fn extend_is_idempotent(ranges in prop::collection::vec(arb_interval(), 0..=8)) {
        let mut once = CoverageStore::new();
        let mut twice = CoverageStore::new();
        for (s, e) in &ranges {
            once.extend_coverage(s.clone(), e.clone());
            twice.extend_coverage(s.clone(), e.clone());
            twice.extend_coverage(s.clone(), e.clone());
        }
        // Equivalence via the only public query: every interval covered by
        // one must be covered by the other and vice versa.
        for (s, e) in &ranges {
            prop_assert_eq!(once.covers_range(s, e), twice.covers_range(s, e));
        }
    }

    /// `CoverageStore` agrees with a naive reference oracle on `covers_range`
    /// after an arbitrary sequence of `extend_coverage` ops, including
    /// queries over ranges we never extended.
    #[test]
    fn store_matches_oracle(
        extensions in prop::collection::vec(arb_interval(), 0..=12),
        queries in prop::collection::vec(arb_interval(), 0..=12),
    ) {
        let mut store = CoverageStore::new();
        let mut oracle = IntervalOracle::default();
        for (s, e) in extensions {
            store.extend_coverage(s.clone(), e.clone());
            oracle.extend(s, e);
            let intervals = store.intervals();
            prop_assert_eq!(&intervals, &oracle.intervals);
            for (start, end) in &intervals {
                prop_assert!(start < end, "empty or reversed interval");
            }
            for interval in intervals.windows(2) {
                let (_, left_end) = &interval[0];
                let (right_start, _) = &interval[1];
                prop_assert!(left_end < right_start, "overlapping or adjacent intervals");
            }
        }
        for (s, e) in queries {
            prop_assert_eq!(store.covers_range(&s, &e), oracle.covers(&s, &e));
        }
    }

    /// `covered_prefix_end(start, end)` always returns a byte in `[start, end]`.
    /// The returned byte is either `end` (fully covered prefix) or a gap
    /// somewhere strictly inside the range.
    #[test]
    fn covered_prefix_end_in_bounds(
        extensions in prop::collection::vec(arb_interval(), 0..=8),
        query in arb_interval(),
    ) {
        let mut store = CoverageStore::new();
        for (s, e) in extensions {
            store.extend_coverage(s, e);
        }
        let (start, end) = query;
        let result = store.covered_prefix_end(&start, &end);
        prop_assert!(result.as_slice() >= start.as_slice(), "prefix end before start");
        prop_assert!(result.as_slice() <= end.as_slice(), "prefix end past end");
    }

    /// `covered_suffix_start(start, end)` symmetric: result is in
    /// `[start, end]`.
    #[test]
    fn covered_suffix_start_in_bounds(
        extensions in prop::collection::vec(arb_interval(), 0..=8),
        query in arb_interval(),
    ) {
        let mut store = CoverageStore::new();
        for (s, e) in extensions {
            store.extend_coverage(s, e);
        }
        let (start, end) = query;
        let result = store.covered_suffix_start(&start, &end);
        prop_assert!(result.as_slice() >= start.as_slice(), "suffix start before start");
        prop_assert!(result.as_slice() <= end.as_slice(), "suffix start past end");
    }
}
