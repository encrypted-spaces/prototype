//! Extract NodeData from a committed merk tree.

use ffproof_tracer_shared::pruned_child;
use merk::{Child, Node};
use std::collections::HashMap;

/// Reference to a child node (for building skeleton trees)
#[derive(Clone, Debug)]
pub struct ChildRef {
    pub key: Vec<u8>,
    pub hash: [u8; 32],
    pub child_heights: (u8, u8),
}

/// Complete data for a single node, extracted from committed tree
#[derive(Clone, Debug)]
pub struct NodeData {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub kv_hash: [u8; 32],
    pub left: Option<ChildRef>,
    pub right: Option<ChildRef>,
}

/// Extract ChildRef from a Child.
pub fn extract_child_ref(child: &Child) -> ChildRef {
    match child {
        Child::Resident(tree) => ChildRef {
            key: tree.key().to_vec(),
            hash: tree.hash(),
            child_heights: tree.child_heights(),
        },
        Child::Pruned(pruned) => ChildRef {
            key: pruned.key().to_vec(),
            hash: *pruned.node_hash(),
            child_heights: pruned.child_heights(),
        },
    }
}

/// Extract NodeData from a single tree node (requires all links to be Loaded).
pub fn extract_node_data(tree: &Node) -> NodeData {
    let key = tree.key().to_vec();
    let value = tree.value().to_vec();
    let kv_hash: [u8; 32] = *tree.kv_hash();

    let left = tree.child_ref(true).map(extract_child_ref);
    let right = tree.child_ref(false).map(extract_child_ref);

    NodeData {
        key,
        value,
        kv_hash,
        left,
        right,
    }
}

/// BST walk to find a node by key in a fully-loaded tree.
/// Returns a reference to the subtree rooted at that key, or None.
pub fn find_node_in_tree<'a>(tree: &'a Node, key: &[u8]) -> Option<&'a Node> {
    let node_key = tree.key();
    if key == node_key {
        return Some(tree);
    }
    let go_left = key < node_key;
    tree.child(go_left)
        .and_then(|child| find_node_in_tree(child, key))
}

/// Convert a child reference to a pruned child (for building skeleton trees).
pub fn child_ref_to_pruned_child(child: &ChildRef) -> Child {
    pruned_child(child.key.clone(), child.hash, child.child_heights)
}

/// Recursively extract all nodes from a tree into a HashMap.
pub fn extract_all_nodes(tree: &Node) -> HashMap<Vec<u8>, NodeData> {
    let mut nodes = HashMap::new();
    extract_recursive(tree, &mut nodes);
    nodes
}

fn extract_recursive(tree: &Node, nodes: &mut HashMap<Vec<u8>, NodeData>) {
    let data = extract_node_data(tree);
    nodes.insert(data.key.clone(), data);

    // Recurse into children (must be Loaded after )
    if let Some(left) = tree.child(true) {
        extract_recursive(left, nodes);
    }
    if let Some(right) = tree.child(false) {
        extract_recursive(right, nodes);
    }
}

/// Extract NodeData from a node that may have Reference children.
fn extract_node_data_any(tree: &Node) -> NodeData {
    NodeData {
        key: tree.key().to_vec(),
        value: tree.value().to_vec(),
        kv_hash: *tree.kv_hash(),
        left: tree.child_ref(true).map(extract_child_ref),
        right: tree.child_ref(false).map(extract_child_ref),
    }
}

/// Look up NodeData by key: overlay first, then BST walk the original tree.
pub fn get_node_data_from_overlay_or_tree(
    tree: &Node,
    overlay: &HashMap<Vec<u8>, NodeData>,
    key: &[u8],
) -> Option<NodeData> {
    if let Some(data) = overlay.get(key) {
        return Some(data.clone());
    }
    find_node_in_tree(tree, key).map(extract_node_data)
}

/// Update an existing node_map with in-memory nodes from a committed skeleton result tree.
/// Only walks Loaded (in-memory) nodes — stops at Reference links since those subtrees
/// are unchanged and already have correct entries in the node_map.
/// This is O(accessed nodes) rather than O(total nodes).
pub fn update_node_map_from_result(tree: &Node, nodes: &mut HashMap<Vec<u8>, NodeData>) {
    let data = extract_node_data_any(tree);
    nodes.insert(data.key.clone(), data);

    if let Some(child) = tree.child(true) {
        update_node_map_from_result(child, nodes);
    }
    if let Some(child) = tree.child(false) {
        update_node_map_from_result(child, nodes);
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
    fn test_extract_single_node() {
        let key = vec![1u8; 16];
        let value = vec![2u8; 32];
        let tree = build_test_tree(&[(key.clone(), value.clone())]);

        let nodes = extract_all_nodes(&tree);
        assert_eq!(nodes.len(), 1);

        let data = nodes.get(&key).unwrap();
        assert_eq!(data.key, key);
        assert_eq!(data.value, value);
        assert!(data.left.is_none());
        assert!(data.right.is_none());
    }

    #[test]
    fn test_extract_multiple_nodes() {
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
        let nodes = extract_all_nodes(&tree);

        assert_eq!(nodes.len(), 5);

        // Verify each node is present
        for (key, value) in &entries {
            let data = nodes.get(key).expect("node should exist");
            assert_eq!(&data.key, key);
            assert_eq!(&data.value, value);
        }
    }

    #[test]
    fn test_extract_preserves_kv_hash() {
        let key = vec![42u8; 16];
        let value = vec![99u8; 32];
        let tree = build_test_tree(&[(key.clone(), value)]);

        let nodes = extract_all_nodes(&tree);
        let data = nodes.get(&key).unwrap();

        // kv_hash should match tree's kv_hash
        assert_eq!(&data.kv_hash, tree.kv_hash());
    }
}
