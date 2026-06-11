//! TracerFetch: Records all accessed nodes and returns skeleton trees.

use crate::extract::{
    child_ref_to_pruned_child, extract_child_ref, extract_node_data, find_node_in_tree, NodeData,
};
use merk::Result;
use merk::{Fetch, Node};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Fetch implementation that records all accessed nodes.
/// Returns trees with Reference children to enable cascade tracing.
///
/// Holds a reference to the original fully-loaded tree and a small overlay
/// HashMap for nodes modified by prior write steps. Lookups check the overlay
/// first, then BST-walk the original tree. This avoids the O(n) upfront
/// `extract_all_nodes` cost.
///
/// All fields are cheap to clone (reference copy + Arc bumps), so merk's
/// Walker can call `clone_source()` at every recursion level without cost.
#[derive(Clone)]
pub struct TracerFetch<'a> {
    tree: &'a Node,
    overlay: Arc<HashMap<Vec<u8>, NodeData>>,
    accessed: Arc<Mutex<HashSet<Vec<u8>>>>,
}

impl<'a> TracerFetch<'a> {
    pub fn new(
        tree: &'a Node,
        overlay: HashMap<Vec<u8>, NodeData>,
        accessed: Arc<Mutex<HashSet<Vec<u8>>>>,
    ) -> Self {
        TracerFetch {
            tree,
            overlay: Arc::new(overlay),
            accessed,
        }
    }

    /// Look up NodeData by key: overlay first, then BST walk the original tree.
    fn get_node_data(&self, key: &[u8]) -> Option<NodeData> {
        if let Some(data) = self.overlay.get(key) {
            return Some(data.clone());
        }
        find_node_in_tree(self.tree, key).map(extract_node_data)
    }

    /// Create a skeleton root tree from NodeData.
    /// Children are pruned to trigger fetch on access.
    pub fn create_skeleton_root(&self, data: &NodeData) -> Node {
        let left = data.left.as_ref().map(child_ref_to_pruned_child);
        let right = data.right.as_ref().map(child_ref_to_pruned_child);

        Node::from_fields(
            data.key.to_vec(),
            data.value.to_vec(),
            data.kv_hash,
            left,
            right,
        )
    }

    /// BST walk starting from root_key, looking up a single key.
    /// Records all visited nodes in self.accessed. Returns value if found.
    ///
    /// Uses overlay for nodes modified by prior write steps, falls back to
    /// BST walk of the original tree for unmodified nodes.
    pub fn trace_key(&self, root_key: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let mut current_key = root_key.to_vec();

        loop {
            self.accessed.lock().unwrap().insert(current_key.clone());

            let data = match self.get_node_data(&current_key) {
                Some(d) => d,
                None => panic!(
                    "Node not found during trace_key: {}",
                    hex::encode(&current_key)
                ),
            };

            if key == data.key.as_slice() {
                return Some(data.value.clone());
            }

            let child_ref = if key < data.key.as_slice() {
                &data.left
            } else {
                &data.right
            };

            match child_ref {
                Some(child) => current_key = child.key.clone(),
                None => return None,
            }
        }
    }

    /// BST range traversal starting from root_key.
    /// Collects all key-value pairs where key >= start and (end is None or key < end).
    /// Records all visited nodes in self.accessed.
    pub fn trace_range(
        &self,
        root_key: &[u8],
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut results = Vec::new();
        self.trace_range_recursive(root_key, start, end, &mut results);
        results
    }

    fn trace_range_recursive(
        &self,
        current_key: &[u8],
        start: &[u8],
        end: Option<&[u8]>,
        results: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) {
        self.accessed.lock().unwrap().insert(current_key.to_vec());

        let data = match self.get_node_data(current_key) {
            Some(d) => d,
            None => panic!(
                "Node not found during trace_range: {}",
                hex::encode(current_key)
            ),
        };

        let node_key = data.key.as_slice();

        if node_key > start {
            if let Some(ref left) = data.left {
                self.trace_range_recursive(&left.key, start, end, results);
            }
        }

        if node_key >= start && (end.is_none() || node_key < end.unwrap()) {
            results.push((data.key.clone(), data.value.clone()));
        }

        if end.is_none() || node_key < end.unwrap() {
            if let Some(ref right) = data.right {
                self.trace_range_recursive(&right.key, start, end, results);
            }
        }
    }
}

impl<'a> Fetch for TracerFetch<'a> {
    fn fetch_by_key(&self, key: &[u8]) -> Result<Option<Node>> {
        let key_vec = key.to_vec();

        // Record this access
        self.accessed.lock().unwrap().insert(key_vec.clone());

        // Check overlay first (nodes modified by prior write steps)
        if let Some(data) = self.overlay.get(&key_vec) {
            let left = data.left.as_ref().map(child_ref_to_pruned_child);
            let right = data.right.as_ref().map(child_ref_to_pruned_child);
            return Ok(Some(Node::from_fields(
                data.key.to_vec(),
                data.value.to_vec(),
                data.kv_hash,
                left,
                right,
            )));
        }

        // BST walk the original tree
        match find_node_in_tree(self.tree, key) {
            Some(node) => {
                let left = node
                    .child_ref(true)
                    .map(extract_child_ref)
                    .map(|child| child_ref_to_pruned_child(&child));
                let right = node
                    .child_ref(false)
                    .map(extract_child_ref)
                    .map(|child| child_ref_to_pruned_child(&child));
                Ok(Some(Node::from_fields(
                    node.key().to_vec(),
                    node.value().to_vec(),
                    *node.kv_hash(),
                    left,
                    right,
                )))
            }
            None => Err(merk::Error::Key(format!(
                "Node not found: {}",
                hex::encode(key)
            ))),
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
    fn test_tracer_records_access() {
        // Build a small tree
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

        // Create tracer
        let accessed = Arc::new(Mutex::new(HashSet::new()));
        let tracer = TracerFetch::new(&tree, HashMap::new(), accessed.clone());

        // Fetch a node
        let key_to_fetch = entries[2].0.clone();
        let result = tracer.fetch_by_key(&key_to_fetch).unwrap();
        assert!(result.is_some());

        // Verify access was recorded
        let accessed_set = accessed.lock().unwrap();
        assert!(accessed_set.contains(&key_to_fetch));
    }

    #[test]
    fn test_tracer_returns_skeleton() {
        use crate::extract::extract_all_nodes;

        // Build a small tree
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
        let node_map = extract_all_nodes(&tree);

        let accessed = Arc::new(Mutex::new(HashSet::new()));
        let tracer = TracerFetch::new(&tree, HashMap::new(), accessed);

        // Fetch any node that has children
        // The returned tree should have Reference children (not Loaded)
        for (key, data) in &node_map {
            if data.left.is_some() || data.right.is_some() {
                let result = tracer.fetch_by_key(key).unwrap().unwrap();

                // Children should be pruned (not in memory)
                if let Some(child) = result.child_ref(true) {
                    assert!(child.is_pruned(), "Left child should be pruned");
                }
                if let Some(child) = result.child_ref(false) {
                    assert!(child.is_pruned(), "Right child should be pruned");
                }
                return;
            }
        }
    }

    #[test]
    fn test_skeleton_root_has_reference_children() {
        use crate::extract::extract_all_nodes;

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
        let node_map = extract_all_nodes(&tree);

        let root_key = tree.key().to_vec();
        let root_data = node_map.get(&root_key).unwrap();

        let accessed = Arc::new(Mutex::new(HashSet::new()));
        let tracer = TracerFetch::new(&tree, HashMap::new(), accessed);

        let skeleton = tracer.create_skeleton_root(root_data);

        // Skeleton should have same key/value/kv_hash as original
        assert_eq!(skeleton.key(), tree.key());
        assert_eq!(skeleton.value(), tree.value());
        assert_eq!(skeleton.kv_hash(), tree.kv_hash());

        // Children should be pruned
        if let Some(child) = skeleton.child_ref(true) {
            assert!(child.is_pruned());
        }
        if let Some(child) = skeleton.child_ref(false) {
            assert!(child.is_pruned());
        }
    }
}
