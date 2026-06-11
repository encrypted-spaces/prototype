//! Create and verify TracerProof by applying ops one-at-a-time (sequential).
//!
//! This matches how the server applies changes and produces identical AVL tree
//! structures. Use this module for tracing operations.

use ffproof_tracer_shared::{
    prefix_successor, BatchOp, InputStep, ProvenRead, ReadOp, TraceStep, TracerProof,
};
use merk::Node;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::extract::{extract_node_data, find_node_in_tree, update_node_map_from_result, NodeData};
use crate::pruned::build_pruned_tree_compacted;
use crate::tracer::TracerFetch;

// Re-export verify_trace from shared crate
pub use ffproof_tracer_shared::verify_trace;

/// Create a TracerProof by running operations SEQUENTIALLY on a skeleton tree.
/// This applies each op one-at-a-time, matching how the server built the tree.
///
/// # Arguments
/// * `full_tree` - A committed merk tree (all links must be Loaded)
/// * `steps` - Input steps to trace (Read and Write steps)
///
/// # Returns
/// A TracerProof containing the pruned tree with only accessed nodes
pub fn create_trace(full_tree: &Node, steps: &[InputStep]) -> TracerProof {
    create_trace_impl(full_tree, steps)
}

/// Compatibility wrapper for callers that used to request no write compaction.
/// All traced writes now carry full values.
pub fn create_trace_full(full_tree: &Node, steps: &[InputStep]) -> TracerProof {
    create_trace_impl(full_tree, steps)
}

fn create_trace_impl(full_tree: &Node, steps: &[InputStep]) -> TracerProof {
    let expected_start_root = full_tree.hash();

    // Small overlay for nodes modified by prior write steps (starts empty).
    // Replaces the old O(n) extract_all_nodes() call.
    let mut overlay: HashMap<Vec<u8>, NodeData> = HashMap::new();

    // Create accessed set with root key (root isn't fetched, so add it manually)
    let mut current_root_key = full_tree.key().to_vec();
    let accessed = Arc::new(Mutex::new(HashSet::new()));
    accessed.lock().unwrap().insert(current_root_key.clone());

    // Read-target keys are still tracked by `trace_read_op` for diagnostics,
    // but all accessed nodes now carry full values.
    let mut read_target_keys: HashSet<Vec<u8>> = HashSet::new();

    let mut expected_end_root = expected_start_root;
    let mut resolved_steps: Vec<TraceStep> = Vec::new();

    for step in steps {
        match step {
            InputStep::Read(read_ops) => {
                let mut proven_reads = Vec::new();
                for read_op in read_ops {
                    let proven_read = trace_read_op(
                        read_op,
                        full_tree,
                        &overlay,
                        &current_root_key,
                        &accessed,
                        &mut read_target_keys,
                    );
                    proven_reads.push(proven_read);
                }
                resolved_steps.push(TraceStep::Read(proven_reads));
            }
            InputStep::Write(ops) => {
                // Get root NodeData from overlay or original tree
                let root_data = get_node_data(full_tree, &overlay, &current_root_key)
                    .expect("root must be in tree or overlay");
                let tracer = TracerFetch::new(full_tree, overlay.clone(), accessed.clone());
                let skeleton_root = tracer.create_skeleton_root(&root_data);

                // Apply the ops in this step as a batch via TracerFetch to record accesses.
                // Sequentiality is controlled by how InputStep::Write groups are constructed
                // (one op per step = sequential; multiple ops = batched).
                let result_tree =
                    ffproof_tracer_shared::apply_batch(Some(skeleton_root), ops, tracer);

                match result_tree {
                    Some(mut tree) => {
                        // Commit result tree to compute end_root
                        tree.commit();

                        expected_end_root = tree.hash();
                        current_root_key = tree.key().to_vec();

                        // Patch overlay with in-memory (changed) nodes — O(accessed) not O(n)
                        update_node_map_from_result(&tree, &mut overlay);
                    }
                    None => {
                        // All keys were deleted → empty tree
                        expected_end_root = [0u8; 32];
                    }
                }

                // Remove deleted keys (after dedup, last-write-wins)
                let mut deduped: BTreeMap<Vec<u8>, &BatchOp> = BTreeMap::new();
                for op in ops {
                    deduped.insert(op.key().to_vec(), op);
                }
                for (key, op) in &deduped {
                    if matches!(op, BatchOp::Delete { .. }) {
                        overlay.remove(key);
                    }
                }

                resolved_steps.push(TraceStep::Write(ops.clone()));
            }
        }
    }

    // Build PrunedMerkleTree from full_tree guided by accessed_keys
    let accessed_keys = accessed.lock().unwrap().clone();

    let pruned_tree = build_pruned_tree_compacted(full_tree, &accessed_keys, &read_target_keys);

    TracerProof {
        pruned_tree,
        steps: resolved_steps,
        expected_start_root,
        expected_end_root,
    }
}

/// Look up NodeData by key: overlay first, then BST walk the original tree.
fn get_node_data(
    tree: &Node,
    overlay: &HashMap<Vec<u8>, NodeData>,
    key: &[u8],
) -> Option<NodeData> {
    if let Some(data) = overlay.get(key) {
        return Some(data.clone());
    }
    find_node_in_tree(tree, key).map(extract_node_data)
}

/// Trace a single ReadOp, recording accessed nodes.
///
/// The actual read results are derived at verification time from the pruned
/// tree, so we discard them in the returned `ProvenRead`.  We do, however,
/// record the keys whose *values* the verifier will consume into
/// `read_target_keys`. All accessed nodes currently ship as full nodes, but
/// retaining this set keeps the tracing flow explicit.
fn trace_read_op(
    read_op: &ReadOp,
    tree: &Node,
    overlay: &HashMap<Vec<u8>, NodeData>,
    root_key: &[u8],
    accessed: &Arc<Mutex<HashSet<Vec<u8>>>>,
    read_target_keys: &mut HashSet<Vec<u8>>,
) -> ProvenRead {
    let tracer = TracerFetch::new(tree, overlay.clone(), accessed.clone());
    match read_op {
        ReadOp::Key(key) => {
            // The verifier only consumes the value if the key is present.
            // For absence reads (returns None), no Full node is needed.
            if tracer.trace_key(root_key, key).is_some() {
                read_target_keys.insert(key.clone());
            }
        }
        ReadOp::Prefix(prefix) => {
            let end = prefix_successor(prefix);
            let collected = tracer.trace_range(root_key, prefix, end.as_deref());
            for (k, _) in collected {
                read_target_keys.insert(k);
            }
        }
        ReadOp::Range { start, end } => {
            let collected = tracer.trace_range(root_key, start, Some(end.as_slice()));
            for (k, _) in collected {
                read_target_keys.insert(k);
            }
        }
    }
    ProvenRead {
        op: read_op.clone(),
        results: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merk::{InMemoryMerk, Node};

    /// Helper: wrap a Vec<BatchOp> into a single-step InputStep::Write slice.
    fn write_steps(ops: Vec<BatchOp>) -> Vec<InputStep> {
        vec![InputStep::Write(ops)]
    }

    /// Helper: wrap each BatchOp into its own InputStep::Write step (sequential application).
    fn sequential_steps(ops: Vec<BatchOp>) -> Vec<InputStep> {
        ops.into_iter()
            .map(|op| InputStep::Write(vec![op]))
            .collect()
    }

    fn build_tree_sequential(entries: &[(Vec<u8>, Vec<u8>)]) -> Node {
        let merk = InMemoryMerk::new();
        for (key, value) in entries {
            merk.put(key.clone(), value.clone()).unwrap();
        }
        merk.snapshot().expect("tree should not be empty")
    }

    /// Test that sequential tracer produces matching roots when server
    /// builds tree sequentially and we trace with sequential application.
    #[test]
    fn test_sequential_tracer_matches_sequential_server() {
        // Build tree sequentially (like the server does)
        let entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"key_01".to_vec(), b"value_01".to_vec()),
            (b"key_02".to_vec(), b"value_02".to_vec()),
            (b"key_03".to_vec(), b"value_03".to_vec()),
        ];

        let snapshot = build_tree_sequential(&entries);
        let snapshot_root = snapshot.hash();
        println!(
            "Snapshot root (after 3 sequential inserts): {}",
            hex::encode(snapshot_root)
        );

        // Continue with 3 more entries sequentially
        let more_entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"key_04".to_vec(), b"value_04".to_vec()),
            (b"key_05".to_vec(), b"value_05".to_vec()),
            (b"key_06".to_vec(), b"value_06".to_vec()),
        ];

        // Build what the server would have after all 6 inserts
        let mut all_entries = entries.clone();
        all_entries.extend(more_entries.clone());
        let final_tree = build_tree_sequential(&all_entries);
        let actual_final_root = final_tree.hash();
        println!(
            "Actual final root (after 6 sequential inserts): {}",
            hex::encode(actual_final_root)
        );

        // Create ops for the second batch
        let ops: Vec<BatchOp> = more_entries
            .iter()
            .map(|(k, v)| BatchOp::Put {
                key: k.clone(),
                value: v.clone(),
            })
            .collect();

        // Use SEQUENTIAL tracer — each op is its own Write step
        let tracer_proof = create_trace(&snapshot, &sequential_steps(ops));

        println!("\nSequential TracerProof:");
        println!(
            "  expected_start_root: {}",
            hex::encode(tracer_proof.expected_start_root)
        );
        println!(
            "  expected_end_root:   {}",
            hex::encode(tracer_proof.expected_end_root)
        );
        println!("\nActual tree state:");
        println!("  actual_final_root:   {}", hex::encode(actual_final_root));

        let roots_match = tracer_proof.expected_end_root == actual_final_root;
        println!("\nRoots match: {}", roots_match);

        // With sequential application, roots SHOULD match!
        assert!(
            roots_match,
            "Sequential tracer should produce matching roots!\n\
             Expected: {}\n\
             Got:      {}",
            hex::encode(actual_final_root),
            hex::encode(tracer_proof.expected_end_root)
        );

        // Verify the proof also works
        verify_trace(&tracer_proof).expect("tracer_proof should verify");
        println!("\n✓ Sequential tracer proof verified successfully!");
    }

    /// Test that unread writes keep full values in the output proof.
    #[test]
    fn test_tracer_proof_compacts_unread_writes() {
        let small_value = vec![0xAAu8; 31];
        let large_value = vec![0xBBu8; 4096];

        // Build identical initial trees (same structure, same key)
        let initial_entries = vec![
            (b"key_01".to_vec(), b"init_01".to_vec()),
            (b"key_02".to_vec(), b"init_02".to_vec()),
        ];
        let tree_small = build_tree_sequential(&initial_entries);
        let tree_large = build_tree_sequential(&initial_entries);
        assert_eq!(
            tree_small.hash(),
            tree_large.hash(),
            "Initial trees must match"
        );

        // Create ops that insert with different value sizes (no reads)
        let ops_small = vec![BatchOp::Put {
            key: b"key_03".to_vec(),
            value: small_value.clone(),
        }];
        let ops_large = vec![BatchOp::Put {
            key: b"key_03".to_vec(),
            value: large_value.clone(),
        }];

        let proof_small = create_trace(&tree_small, &write_steps(ops_small));
        let proof_large = create_trace(&tree_large, &write_steps(ops_large));

        // Both proofs should verify
        verify_trace(&proof_small).expect("proof_small should verify");
        verify_trace(&proof_large).expect("proof_large should verify");

        // Steps should have the same structure
        assert_eq!(proof_small.steps.len(), proof_large.steps.len());
        // Extract ops from the Write steps
        let ops_small = match &proof_small.steps[0] {
            TraceStep::Write(ops) => ops,
            _ => panic!("expected Write step"),
        };
        let ops_large = match &proof_large.steps[0] {
            TraceStep::Write(ops) => ops,
            _ => panic!("expected Write step"),
        };
        assert_eq!(ops_small.len(), ops_large.len());

        // Small value (< threshold) stays as Put
        match &ops_small[0] {
            BatchOp::Put { value, .. } => assert_eq!(value, &small_value),
            other => panic!("Expected Put for small value, got: {other:?}"),
        }
        // Large values are carried as Put now that hash-only write compaction is removed.
        match &ops_large[0] {
            BatchOp::Put { value, .. } => assert_eq!(value, &large_value),
            other => panic!("Expected Put for large unread value, got: {other:?}"),
        }

        // Start roots should match (same initial tree)
        assert_eq!(
            proof_small.expected_start_root, proof_large.expected_start_root,
            "Start roots should match"
        );

        println!("\n✓ Unread writes carry full values and proofs verify");
    }

    /// Verifies unread and read writes both keep full Put values in the proof.
    #[test]
    fn test_selective_compaction_read_vs_unread() {
        let large_value = vec![0xBBu8; 4096]; // 4 KB — above threshold

        // Build initial tree
        let initial_entries = vec![
            (b"key_01".to_vec(), b"init_01".to_vec()),
            (b"key_02".to_vec(), b"init_02".to_vec()),
            (b"key_05".to_vec(), b"init_05".to_vec()),
        ];
        let tree = build_tree_sequential(&initial_entries);

        // Write key_03 (large, NOT read) then Read key_01 (unrelated).
        let steps_unread = vec![
            InputStep::Write(vec![BatchOp::Put {
                key: b"key_03".to_vec(),
                value: large_value.clone(),
            }]),
            InputStep::Read(vec![ReadOp::Key(b"key_01".to_vec())]),
        ];

        let tree2 = build_tree_sequential(&initial_entries);
        // Write key_03 (large, IS read later) also stays as full Put.
        let steps_read = vec![
            InputStep::Write(vec![BatchOp::Put {
                key: b"key_03".to_vec(),
                value: large_value.clone(),
            }]),
            InputStep::Read(vec![ReadOp::Key(b"key_03".to_vec())]),
        ];

        let proof_unread = create_trace(&tree, &steps_unread);
        let proof_read = create_trace(&tree2, &steps_read);

        // Both proofs should verify
        verify_trace(&proof_unread).expect("proof_unread should verify");
        verify_trace(&proof_read).expect("proof_read should verify");

        // Unread write → full Put
        let write_unread = match &proof_unread.steps[0] {
            TraceStep::Write(ops) => &ops[0],
            _ => panic!("expected Write step"),
        };
        match write_unread {
            BatchOp::Put { value, .. } => assert_eq!(value, &large_value),
            other => panic!("Expected Put for unread key, got: {other:?}"),
        }

        // Read write → full Put (preserved)
        let write_read = match &proof_read.steps[0] {
            TraceStep::Write(ops) => &ops[0],
            _ => panic!("expected Write step"),
        };
        match write_read {
            BatchOp::Put { value, .. } => assert_eq!(value, &large_value),
            other => panic!("Expected Put for read key, got: {other:?}"),
        }

        println!("\n✓ Write proof values: unread→Put, read→Put");
    }

    /// Verify that read, write, and delete operations produce O(log n) proof
    /// sizes.  For each op type we build trees of increasing size and check
    /// that the number of Full nodes in the pruned tree stays bounded by a
    /// small multiple of log₂(n), never growing linearly.
    #[test]
    fn test_all_ops_are_logarithmic() {
        println!("\n--- Proof sizes by op type (Full nodes in pruned tree) ---");
        println!(
            "{:>8} {:>12} {:>12} {:>12} {:>12} {:>12}",
            "N", "key_read", "prefix_read", "put_new", "put_update", "delete"
        );

        for &n in &[10usize, 100, 1_000, 10_000] {
            let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
                .map(|i| {
                    (
                        format!("key_{i:06}").into_bytes(),
                        format!("val_{i}").into_bytes(),
                    )
                })
                .collect();
            let tree = build_tree_sequential(&entries);

            // --- Read single key (middle of tree) ---
            let mid_key = format!("key_{:06}", n / 2).into_bytes();
            let read_key_proof = create_trace(
                &tree,
                &[InputStep::Read(vec![ReadOp::Key(mid_key.clone())])],
            );
            verify_trace(&read_key_proof).expect("read_key_proof should verify");

            // --- Read prefix (narrow: matches ~1 key) ---
            let prefix = format!("key_{:06}", n / 2).into_bytes();
            let read_prefix_proof =
                create_trace(&tree, &[InputStep::Read(vec![ReadOp::Prefix(prefix)])]);
            verify_trace(&read_prefix_proof).expect("read_prefix_proof should verify");

            // --- Put new key ---
            let put_new_proof = create_trace(
                &tree,
                &[InputStep::Write(vec![BatchOp::Put {
                    key: b"zzz_new_key".to_vec(),
                    value: b"new_value".to_vec(),
                }])],
            );
            verify_trace(&put_new_proof).expect("put_new_proof should verify");

            // --- Put existing key (update) ---
            let put_upd_proof = create_trace(
                &tree,
                &[InputStep::Write(vec![BatchOp::Put {
                    key: mid_key.clone(),
                    value: b"updated".to_vec(),
                }])],
            );
            verify_trace(&put_upd_proof).expect("put_upd_proof should verify");

            // --- Delete existing key ---
            let del_proof = create_trace(
                &tree,
                &[InputStep::Write(vec![BatchOp::Delete {
                    key: mid_key.clone(),
                }])],
            );
            verify_trace(&del_proof).expect("del_proof should verify");

            println!(
                "{n:>8} {:>12} {:>12} {:>12} {:>12} {:>12}",
                read_key_proof.pruned_tree.count_full(),
                read_prefix_proof.pruned_tree.count_full(),
                put_new_proof.pruned_tree.count_full(),
                put_upd_proof.pruned_tree.count_full(),
                del_proof.pruned_tree.count_full(),
            );
        }

        // ── Final assertions at 10K nodes ──
        //
        // log₂(10000) ≈ 14.  With AVL rotation-safety nodes the constant
        // factor is ≤ 7× per path level, so 14 × 7 ≈ 98.  We use a generous
        // bound of 200 — the point is to fail loudly if anything regresses
        // to O(n).
        let n = 10_000usize;
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
            .map(|i| {
                (
                    format!("key_{i:06}").into_bytes(),
                    format!("val_{i}").into_bytes(),
                )
            })
            .collect();
        let tree = build_tree_sequential(&entries);
        let mid_key = format!("key_{:06}", n / 2).into_bytes();

        let read_key = create_trace(
            &tree,
            &[InputStep::Read(vec![ReadOp::Key(mid_key.clone())])],
        );
        let read_prefix = create_trace(
            &tree,
            &[InputStep::Read(vec![ReadOp::Prefix(
                format!("key_{:06}", n / 2).into_bytes(),
            )])],
        );
        let put_new = create_trace(
            &tree,
            &[InputStep::Write(vec![BatchOp::Put {
                key: b"zzz_new_key".to_vec(),
                value: b"v".to_vec(),
            }])],
        );
        let put_upd = create_trace(
            &tree,
            &[InputStep::Write(vec![BatchOp::Put {
                key: mid_key.clone(),
                value: b"v".to_vec(),
            }])],
        );
        let del = create_trace(
            &tree,
            &[InputStep::Write(vec![BatchOp::Delete {
                key: mid_key.clone(),
            }])],
        );

        let rk = read_key.pruned_tree.count_full();
        let rp = read_prefix.pruned_tree.count_full();
        let pn = put_new.pruned_tree.count_full();
        let pu = put_upd.pruned_tree.count_full();
        let dl = del.pruned_tree.count_full();

        assert!(
            rk < 200,
            "Key read should be O(log n), got {rk} full nodes for {n} tree"
        );
        assert!(
            rp < 200,
            "Prefix read should be O(log n), got {rp} full nodes for {n} tree"
        );
        assert!(
            pn < 200,
            "Put (new key) should be O(log n), got {pn} full nodes for {n} tree"
        );
        assert!(
            pu < 200,
            "Put (update) should be O(log n), got {pu} full nodes for {n} tree"
        );
        assert!(
            dl < 200,
            "Delete should be O(log n), got {dl} full nodes for {n} tree"
        );

        println!("\n✓ All merk tracer ops are O(log n)");
    }

    // ── Negative tests ──────────────────────────────────────────────────

    /// Helper: assert that `verify_trace` returns an error for the
    /// given proof.
    fn assert_rejects(label: &str, proof: &TracerProof) {
        assert!(
            verify_trace(proof).is_err(),
            "{label}: proof should have been rejected but verified OK"
        );
    }

    /// Flip the first non-zero byte of a 32-byte hash (in place).
    fn flip_hash(h: &mut [u8; 32]) {
        for b in h.iter_mut() {
            if *b != 0 {
                *b ^= 0xFF;
                return;
            }
        }
        h[0] ^= 0xFF;
    }

    /// Flip the hash inside the first `Pruned` node found (in place).
    fn flip_pruned_hash(node: &mut PrunedMerkleTree) {
        match node {
            PrunedMerkleTree::Pruned { hash, .. } => flip_hash(hash),
            PrunedMerkleTree::Full { left, right, .. } => {
                if !flip_pruned_hash_inner(left) {
                    flip_pruned_hash_inner(right);
                }
            }
            PrunedMerkleTree::Empty => {}
        }
    }
    fn flip_pruned_hash_inner(node: &mut PrunedMerkleTree) -> bool {
        match node {
            PrunedMerkleTree::Pruned { hash, .. } => {
                flip_hash(hash);
                true
            }
            PrunedMerkleTree::Full { left, right, .. } => {
                flip_pruned_hash_inner(left) || flip_pruned_hash_inner(right)
            }
            PrunedMerkleTree::Empty => false,
        }
    }

    use ffproof_tracer_shared::PrunedMerkleTree;

    /// Clone a TracerProof via serialize/deserialize (no Clone derive).
    fn clone_proof(p: &TracerProof) -> TracerProof {
        let bytes = postcard::to_allocvec(p).expect("serialize");
        postcard::from_bytes(&bytes).expect("deserialize")
    }

    /// Every single-field mutation of a valid proof must be rejected.
    #[test]
    fn test_regular_proof_rejects_tampering() {
        // Build a non-trivial tree so there are Pruned nodes in the proof.
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..8)
            .map(|i| {
                (
                    format!("key_{i:02}").into_bytes(),
                    format!("val_{i}").into_bytes(),
                )
            })
            .collect();
        let tree = build_tree_sequential(&entries);

        let ops = vec![BatchOp::Put {
            key: b"key_04".to_vec(),
            value: b"new_value".to_vec(),
        }];

        let good = create_trace(&tree, &write_steps(ops));
        verify_trace(&good).expect("baseline proof should verify");

        // ── Corrupted start root ──
        let mut bad = clone_proof(&good);
        flip_hash(&mut bad.expected_start_root);
        assert_rejects("corrupted start root", &bad);

        // ── Corrupted end root ──
        let mut bad = clone_proof(&good);
        flip_hash(&mut bad.expected_end_root);
        assert_rejects("corrupted end root", &bad);

        // ── Tampered op value ──
        let mut bad = clone_proof(&good);
        if let TraceStep::Write(ref mut ops) = bad.steps[0] {
            match &mut ops[0] {
                BatchOp::Put { ref mut value, .. } => {
                    // Flip a byte in the raw value
                    if let Some(b) = value.first_mut() {
                        *b ^= 0xFF;
                    }
                }
                _ => panic!("expected Put"),
            }
        } else {
            panic!("expected Write step");
        }
        assert_rejects("tampered op value", &bad);

        // ── Tampered pruned Pruned node hash ──
        let mut bad = clone_proof(&good);
        flip_pruned_hash(&mut bad.pruned_tree);
        assert_rejects("tampered pruned node", &bad);

        // ── Wrong op key (use a different existing key) ──
        let mut bad = clone_proof(&good);
        if let TraceStep::Write(ref mut ops) = bad.steps[0] {
            if let BatchOp::Put { ref mut key, .. } = &mut ops[0] {
                *key = b"key_02".to_vec();
            }
        }
        assert_rejects("wrong op key", &bad);

        // ── Missing node: replace a Full child on the op path with Pruned ──
        let mut bad = clone_proof(&good);
        prune_first_full_child(&mut bad.pruned_tree);
        assert_rejects("missing node (Full→Pruned)", &bad);

        println!("✓ All tampered proofs rejected (regular)");
    }

    /// Replace the first Full *child* (not root) with a Pruned
    /// node, simulating a missing node on the operation path.
    fn prune_first_full_child(node: &mut PrunedMerkleTree) -> bool {
        // Extract the key from a Full node.
        fn child_key(n: &PrunedMerkleTree) -> Option<Vec<u8>> {
            match n {
                PrunedMerkleTree::Full { key, .. } => Some(key.clone()),
                _ => None,
            }
        }
        let (left, right) = match node {
            PrunedMerkleTree::Full { left, right, .. } => (left, right),
            _ => return false,
        };
        if let Some(key) = child_key(left) {
            **left = PrunedMerkleTree::Pruned {
                key,
                hash: [0xAA; 32],
                child_heights: (0, 0),
            };
            return true;
        }
        if let Some(key) = child_key(right) {
            **right = PrunedMerkleTree::Pruned {
                key,
                hash: [0xAA; 32],
                child_heights: (0, 0),
            };
            return true;
        }
        prune_first_full_child(left) || prune_first_full_child(right)
    }

    /// Proof built against one tree must not verify when the start root or
    /// pruned tree comes from a different tree.
    #[test]
    fn test_regular_proof_rejects_wrong_tree() {
        // Tree A
        let entries_a: Vec<(Vec<u8>, Vec<u8>)> = (0..6)
            .map(|i| {
                (
                    format!("key_{i:02}").into_bytes(),
                    format!("a_val_{i}").into_bytes(),
                )
            })
            .collect();
        let tree_a = build_tree_sequential(&entries_a);

        // Tree B — same keys, different values → different root
        let entries_b: Vec<(Vec<u8>, Vec<u8>)> = (0..6)
            .map(|i| {
                (
                    format!("key_{i:02}").into_bytes(),
                    format!("b_val_{i}").into_bytes(),
                )
            })
            .collect();
        let tree_b = build_tree_sequential(&entries_b);

        assert_ne!(tree_a.hash(), tree_b.hash(), "trees must differ");

        let ops = vec![BatchOp::Put {
            key: b"key_03".to_vec(),
            value: b"updated".to_vec(),
        }];

        let proof_a = create_trace(&tree_a, &write_steps(ops.clone()));
        let proof_b = create_trace(&tree_b, &write_steps(ops));
        verify_trace(&proof_a).expect("proof_a should verify");
        verify_trace(&proof_b).expect("proof_b should verify");

        // ── Swap start root from tree B into proof A ──
        let mut bad = clone_proof(&proof_a);
        bad.expected_start_root = proof_b.expected_start_root;
        assert_rejects("swapped start root from different tree", &bad);

        // ── Keep proof A's roots but use pruned tree from proof B ──
        let mut bad = clone_proof(&proof_a);
        bad.pruned_tree = clone_proof(&proof_b).pruned_tree;
        assert_rejects("pruned tree from different tree", &bad);

        println!("✓ Wrong-tree proofs rejected (regular)");
    }

    /// Fake `child_heights` on a Pruned node are NOT part of the Merkle hash,
    /// so the start root still matches.  But if the ops cause AVL rotations
    /// near that node, the wrong heights produce wrong rotation decisions →
    /// different end root → rejection.
    ///
    /// This also documents the known property: if ops do NOT touch the area
    /// with faked heights, the proof still passes (the fake metadata is
    /// harmless for that particular proof).
    #[test]
    fn test_regular_proof_fake_child_heights() {
        // Build a large enough tree that there are Pruned nodes AND rotations
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..20)
            .map(|i| {
                (
                    format!("key_{i:02}").into_bytes(),
                    format!("val_{i}").into_bytes(),
                )
            })
            .collect();
        let tree = build_tree_sequential(&entries);

        // Insert a new key — this will cause rotations along the insertion path
        let ops = vec![BatchOp::Put {
            key: b"key_10".to_vec(),
            value: b"updated_value".to_vec(),
        }];
        let good = create_trace(&tree, &write_steps(ops));
        verify_trace(&good).expect("baseline proof should verify");

        // Corrupt child_heights on a Pruned node
        let mut bad = clone_proof(&good);
        let corrupted = corrupt_pruned_child_heights(&mut bad.pruned_tree);
        if corrupted {
            // The start root should still match (heights aren't hashed).
            // But if the corrupted Pruned node is near the op path, the
            // wrong heights cause wrong rotations → end root mismatch.
            // If it's far from the op path, the proof may still pass
            // (heights are harmless for that verification run).
            let result = verify_trace(&bad);
            println!(
                "Fake child_heights test: verification {} (expected: likely rejected due to \
                 wrong rotation, but may pass if Pruned node is far from op path)",
                if result.is_ok() { "passed" } else { "rejected" }
            );
            // Whether it passes or fails, document the behavior.
            // We DO NOT assert either way — this test documents that
            // child_heights are not hash-committed.
        }

        println!("✓ Fake child_heights test completed");
    }

    /// Set child_heights to (255, 255) on the first Pruned node found.
    fn corrupt_pruned_child_heights(node: &mut PrunedMerkleTree) -> bool {
        match node {
            PrunedMerkleTree::Pruned { child_heights, .. } => {
                *child_heights = (255, 255);
                true
            }
            PrunedMerkleTree::Full { left, right, .. } => {
                corrupt_pruned_child_heights(left) || corrupt_pruned_child_heights(right)
            }
            PrunedMerkleTree::Empty => false,
        }
    }

    /// Swapping keys between two Full nodes should be caught because
    /// kv_hash (recomputed from key+value) binds the key to the value.
    /// With swapped keys, the recomputed kv_hash won't match the original
    /// → start root mismatch after commit.
    #[test]
    fn test_regular_proof_swapped_full_node_keys() {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..8)
            .map(|i| {
                (
                    format!("key_{i:02}").into_bytes(),
                    format!("val_{i}").into_bytes(),
                )
            })
            .collect();
        let tree = build_tree_sequential(&entries);

        let ops = vec![BatchOp::Put {
            key: b"key_04".to_vec(),
            value: b"new_val".to_vec(),
        }];
        let good = create_trace(&tree, &write_steps(ops));
        verify_trace(&good).expect("baseline proof should verify");

        let mut bad = clone_proof(&good);
        let swapped = swap_two_full_keys(&mut bad.pruned_tree);
        assert!(swapped, "need at least 2 Full nodes to swap");
        assert_rejects("swapped Full node keys", &bad);

        println!("✓ Key swap between Full nodes rejected");
    }

    /// Swap the keys of the first two Full nodes found (depth-first).
    fn swap_two_full_keys(root: &mut PrunedMerkleTree) -> bool {
        let mut keys: Vec<*mut Vec<u8>> = Vec::new();
        collect_full_key_ptrs(root, &mut keys);
        if keys.len() < 2 {
            return false;
        }
        // Safety: pointers are to distinct nodes in the same tree
        unsafe {
            std::ptr::swap(keys[0], keys[1]);
        }
        true
    }
    fn collect_full_key_ptrs(node: &mut PrunedMerkleTree, out: &mut Vec<*mut Vec<u8>>) {
        if let PrunedMerkleTree::Full {
            key, left, right, ..
        } = node
        {
            out.push(key as *mut Vec<u8>);
            collect_full_key_ptrs(left, out);
            collect_full_key_ptrs(right, out);
        }
    }

    /// Deleting all keys should leave an empty tree with a zero end root.
    /// A proof that claims a non-zero end root after deleting everything
    /// must be rejected.
    #[test]
    fn test_regular_proof_delete_all_keys() {
        // Use enough keys that the tree has structure but few enough to
        // trace all delete operations efficiently.
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..4)
            .map(|i| {
                (
                    format!("key_{i:02}").into_bytes(),
                    format!("val_{i}").into_bytes(),
                )
            })
            .collect();
        let tree = build_tree_sequential(&entries);

        let ops: Vec<BatchOp> = entries
            .iter()
            .map(|(k, _)| BatchOp::Delete { key: k.clone() })
            .collect();
        let proof = create_trace(&tree, &write_steps(ops));

        // Verify the proof is valid and end root is all-zeros (empty tree)
        verify_trace(&proof).expect("proof should verify");
        assert_eq!(
            proof.expected_end_root, [0u8; 32],
            "deleting all keys should produce zero end root"
        );

        // Tamper: claim the tree didn't change
        let mut bad = clone_proof(&proof);
        bad.expected_end_root = proof.expected_start_root;
        assert_rejects("non-zero end root after delete-all", &bad);

        println!("✓ Delete-all edge case verified");
    }

    /// Verify write proof steps keep full Put values for both short and long
    /// values.
    #[test]
    fn test_proof_selective_compaction() {
        let initial_entries = vec![
            (b"key_01".to_vec(), b"init_01".to_vec()),
            (b"key_02".to_vec(), b"init_02".to_vec()),
        ];

        let short_value = b"42".to_vec();
        let long_value = vec![0xCC; 64];

        // --- Short value: stays as Put even when unread ---
        let tree = build_tree_sequential(&initial_entries);
        let ops_short = vec![BatchOp::Put {
            key: b"key_03".to_vec(),
            value: short_value.clone(),
        }];
        let proof_short = create_trace(&tree, &write_steps(ops_short));
        verify_trace(&proof_short).expect("proof_short should verify");

        match &proof_short.steps[0] {
            TraceStep::Write(ops) => match &ops[0] {
                BatchOp::Put { value, .. } => {
                    assert_eq!(value, &short_value);
                }
                other => panic!("Expected Put for short value, got: {other:?}"),
            },
            _ => panic!("expected Write step"),
        }

        // --- Long value, unread: still Put ---
        let tree = build_tree_sequential(&initial_entries);
        let ops_long = vec![BatchOp::Put {
            key: b"key_03".to_vec(),
            value: long_value.clone(),
        }];
        let proof_long = create_trace(&tree, &write_steps(ops_long));
        verify_trace(&proof_long).expect("proof_long should verify");

        match &proof_long.steps[0] {
            TraceStep::Write(ops) => match &ops[0] {
                BatchOp::Put { value, .. } => {
                    assert_eq!(value, &long_value);
                }
                other => panic!("Expected Put for unread long value, got: {other:?}"),
            },
            _ => panic!("expected Write step"),
        }

        // --- Long value, individually read: stays as full Put ---
        let tree = build_tree_sequential(&initial_entries);
        let steps_read = vec![
            InputStep::Write(vec![BatchOp::Put {
                key: b"key_03".to_vec(),
                value: long_value.clone(),
            }]),
            InputStep::Read(vec![ReadOp::Key(b"key_03".to_vec())]),
        ];
        let proof_read = create_trace(&tree, &steps_read);
        verify_trace(&proof_read).expect("proof_read should verify");

        match &proof_read.steps[0] {
            TraceStep::Write(ops) => match &ops[0] {
                BatchOp::Put { value, .. } => {
                    assert_eq!(value, &long_value);
                }
                other => panic!("Expected Put for read long value, got: {other:?}"),
            },
            _ => panic!("expected Write step"),
        }

        println!("\n✓ Full write values are preserved");
    }
}
