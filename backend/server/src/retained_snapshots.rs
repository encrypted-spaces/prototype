//! Bounded map of retained FastForward-boundary snapshots.
//!
//! The server takes a cheap, copy-on-write snapshot of its Merk tree at the
//! start of each unproven FastForward batch, to build that batch's proof
//! against a stable starting state ([`crate::db::SpaceState::tree_snapshot`]).
//! This map retains a small history of those snapshots, keyed by the
//! commitment (root hash) each FastForward boundary produced, so a read can
//! be proven against a commitment that isn't the live head, as long as it's
//! still retained.
//!
//! The map starts empty and only gains an entry once the first FastForward
//! boundary is actually produced. A commitment that predates that (or has
//! since fallen out of the window) is simply not retained; the client
//! recovers via an ordinary FastForward, the same fallback that already
//! covers every other unretained commitment.
//!
//! Retention is bounded, not unbounded: the most recent `window` boundaries
//! are kept, oldest evicted first. `window` counts boundaries, not changes,
//! and is independent of the FF batch size (which only decides how often a
//! new boundary is produced, not how many past ones are worth keeping
//! around).

use encrypted_spaces_backend::merk_storage::Tree;
use std::collections::{HashMap, VecDeque};

/// Default number of FastForward boundaries to retain.
///
/// This needs tuning alongside the FF batch size: the goal is a window wide
/// enough that a client doesn't fall out of it (and need an extra
/// FastForward just to keep reading) between the FastForwards it would run
/// anyway. Picking that value needs real data on FF batch size and how long
/// clients actually go between FastForwards; 16 is a placeholder, not a
/// measured answer.
pub const DEFAULT_RETENTION_WINDOW: usize = 16;

/// A bounded map from commitment to retained snapshot. See module docs.
pub struct RetainedSnapshots {
    by_commitment: HashMap<[u8; 32], (u32, Tree)>,
    /// Commitments in insertion order, oldest first, for windowed eviction.
    order: VecDeque<[u8; 32]>,
    window: usize,
}

impl RetainedSnapshots {
    pub fn new(window: usize) -> Self {
        Self {
            by_commitment: HashMap::new(),
            order: VecDeque::new(),
            window,
        }
    }

    /// Retain the snapshot produced by the FastForward boundary at
    /// `change_id`, reached at `commitment`. Evicts the oldest entry if the
    /// window is now over capacity.
    pub fn insert(&mut self, change_id: u32, commitment: [u8; 32], tree: Tree) {
        if self
            .by_commitment
            .insert(commitment, (change_id, tree))
            .is_none()
        {
            self.order.push_back(commitment);
        }
        while self.order.len() > self.window {
            if let Some(oldest) = self.order.pop_front() {
                self.by_commitment.remove(&oldest);
            }
        }
    }

    /// Look up the retained snapshot for `commitment`, if any.
    pub fn get(&self, commitment: &[u8; 32]) -> Option<&Tree> {
        self.by_commitment.get(commitment).map(|(_, tree)| tree)
    }

    /// Number of retained boundaries (test-only assertion helper).
    #[cfg(test)]
    pub fn retained_count(&self) -> usize {
        self.order.len()
    }

    /// The configured retention window (test-only assertion helper).
    #[cfg(test)]
    pub fn window(&self) -> usize {
        self.window
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::merk_storage::WriteOp;
    use merk::Backend as _;

    fn tree_for(seed: u8) -> Tree {
        let mut tree = Tree::default();
        tree.apply_write_ops(&[WriteOp::Put {
            key: vec![seed],
            value: vec![seed],
        }])
        .unwrap();
        tree
    }

    #[test]
    fn empty_map_retains_nothing() {
        let snapshots = RetainedSnapshots::new(2);
        assert_eq!(snapshots.retained_count(), 0);
        assert!(snapshots.get(&[0u8; 32]).is_none());
    }

    #[test]
    fn retains_and_looks_up_by_commitment() {
        let mut snapshots = RetainedSnapshots::new(2);
        let c1 = [1u8; 32];
        snapshots.insert(1, c1, tree_for(1));
        assert!(snapshots.get(&c1).is_some());
        assert!(snapshots.get(&[9u8; 32]).is_none());
    }

    #[test]
    fn evicts_oldest_beyond_window() {
        let mut snapshots = RetainedSnapshots::new(2);
        let (c1, c2, c3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        snapshots.insert(1, c1, tree_for(1));
        snapshots.insert(2, c2, tree_for(2));
        snapshots.insert(3, c3, tree_for(3));

        assert_eq!(snapshots.retained_count(), 2);
        assert!(snapshots.get(&c1).is_none(), "oldest should be evicted");
        assert!(snapshots.get(&c2).is_some());
        assert!(snapshots.get(&c3).is_some());
    }

    #[test]
    fn reinserting_same_commitment_does_not_grow_order() {
        let mut snapshots = RetainedSnapshots::new(2);
        let c1 = [1u8; 32];
        snapshots.insert(1, c1, tree_for(1));
        snapshots.insert(1, c1, tree_for(1));
        assert_eq!(snapshots.retained_count(), 1);
    }
}
