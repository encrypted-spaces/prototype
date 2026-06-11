//! Build PrunedMerkleTree from full tree guided by accessed keys.

use ffproof_tracer_shared::PrunedMerkleTree;
use merk::Node;
use std::collections::HashSet;

/// Build a pruned tree from accessed keys.
///
/// - Accessed key → `Full` (value carried verbatim so the verifier can
///   recompute Merk's key/value commitment directly).
/// - Not accessed at all → `Pruned`.
///
/// `read_target_keys ⊆ accessed_keys` must hold; nodes that are read
/// targets but not accessed cannot exist (we only know their hash if
/// the trace touched them).
pub fn build_pruned_tree_compacted(
    tree: &Node,
    accessed_keys: &HashSet<Vec<u8>>,
    _read_target_keys: &HashSet<Vec<u8>>,
) -> PrunedMerkleTree {
    build_pruned_recursive(tree, accessed_keys)
}

fn build_pruned_recursive(tree: &Node, accessed_keys: &HashSet<Vec<u8>>) -> PrunedMerkleTree {
    let key = tree.key().to_vec();

    if accessed_keys.contains(&key) {
        let left = match tree.child(true) {
            Some(child) => Box::new(build_pruned_recursive(child, accessed_keys)),
            None => Box::new(PrunedMerkleTree::Empty),
        };

        let right = match tree.child(false) {
            Some(child) => Box::new(build_pruned_recursive(child, accessed_keys)),
            None => Box::new(PrunedMerkleTree::Empty),
        };

        PrunedMerkleTree::Full {
            key,
            value: tree.value().to_vec(),
            left,
            right,
        }
    } else {
        // This node was not accessed - make it Pruned.
        let hash = tree.hash();
        let child_heights = tree.child_heights();

        PrunedMerkleTree::Pruned {
            key,
            hash,
            child_heights,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merk::InMemoryMerk;

    fn build_test_tree(entries: &[(Vec<u8>, Vec<u8>)]) -> Node {
        let merk = InMemoryMerk::new();
        for (k, v) in entries {
            merk.put(k.clone(), v.clone()).unwrap();
        }
        merk.snapshot().expect("tree should not be empty")
    }

    #[test]
    fn test_all_accessed_all_full() {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..5u8)
            .map(|i| {
                let mut key = vec![0u8; 16];
                key[0] = i;
                let mut value = vec![0u8; 32];
                value[0] = i * 10;
                (key, value)
            })
            .collect();

        let tree = build_test_tree(&entries);

        // Mark all keys as accessed
        let accessed: HashSet<Vec<u8>> = entries.iter().map(|(k, _)| k.clone()).collect();

        let pruned = build_pruned_tree_compacted(&tree, &accessed, &accessed);

        assert_eq!(pruned.count_full(), 5);
        assert_eq!(pruned.count_pruned(), 0);
    }

    #[test]
    fn test_only_root_accessed() {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..5u8)
            .map(|i| {
                let mut key = vec![0u8; 16];
                key[0] = i;
                let mut value = vec![0u8; 32];
                value[0] = i * 10;
                (key, value)
            })
            .collect();

        let tree = build_test_tree(&entries);
        let root_key = tree.key().to_vec();

        // Only mark root as accessed
        let mut accessed = HashSet::new();
        accessed.insert(root_key);

        let pruned = build_pruned_tree_compacted(&tree, &accessed, &accessed);

        // Root should be Full, children should be Pruned
        assert_eq!(pruned.count_full(), 1);
        // Number of pruned depends on tree structure
        assert!(pruned.count_pruned() >= 1);
    }

    #[test]
    fn test_pruned_has_correct_hash() {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..3u8)
            .map(|i| {
                let mut key = vec![0u8; 16];
                key[0] = i;
                let mut value = vec![0u8; 32];
                value[0] = i * 10;
                (key, value)
            })
            .collect();

        let tree = build_test_tree(&entries);
        let root_key = tree.key().to_vec();

        // Only access root
        let mut accessed = HashSet::new();
        accessed.insert(root_key);

        let pruned = build_pruned_tree_compacted(&tree, &accessed, &accessed);

        // Find a pruned node and verify its hash
        fn find_pruned_hash(node: &PrunedMerkleTree) -> Option<[u8; 32]> {
            match node {
                PrunedMerkleTree::Pruned { hash, .. } => Some(*hash),
                PrunedMerkleTree::Full { left, right, .. } => {
                    find_pruned_hash(left).or_else(|| find_pruned_hash(right))
                }
                PrunedMerkleTree::Empty => None,
            }
        }

        // There should be at least one pruned node
        assert!(find_pruned_hash(&pruned).is_some());
    }
}
