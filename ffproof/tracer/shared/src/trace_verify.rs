//! Verify a TracerProof by reconstructing the tree and applying operations.

use crate::{apply_batch, extract_reads, pruned_to_merk, PrunedMerkleTree, ReadResults, TraceStep};
use merk::{Node, PanicSource};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Complete proof sent to guest for verification
#[derive(Serialize, Deserialize, Clone)]
pub struct TracerProof {
    pub pruned_tree: PrunedMerkleTree,
    pub steps: Vec<TraceStep>,
    pub expected_start_root: [u8; 32],
    pub expected_end_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyTraceError {
    message: String,
}

impl VerifyTraceError {
    fn from_panic(payload: Box<dyn std::any::Any + Send>) -> Self {
        let message = if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else {
            "<unknown panic>".to_string()
        };
        Self { message }
    }
}

impl fmt::Display for VerifyTraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VerifyTraceError {}

/// Verify a TracerProof by:
/// 1. Reconstructing the pruned tree and verifying start root
/// 2. Processing each step (reads verified, writes applied) and verifying end root
///
/// # Returns
/// A `Vec<ReadResults>` — one entry per Read step, each containing per-ProvenRead
/// results extracted from the tree walk.
pub fn verify_trace(trace: &TracerProof) -> Result<Vec<ReadResults>, VerifyTraceError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_trace_internal(trace)
    }))
    .map_err(VerifyTraceError::from_panic)
}

fn verify_trace_internal(trace: &TracerProof) -> Vec<ReadResults> {
    let TracerProof {
        pruned_tree,
        steps,
        expected_start_root,
        expected_end_root,
    } = trace;

    // Count nodes for diagnostics
    let full_count = pruned_tree.count_full();
    let pruned_count = pruned_tree.count_pruned();

    // ─── STAGE 1: Verify Starting State ───────────────────────────────────────

    // Convert PrunedMerkleTree → merk Node
    let mut tree = pruned_to_merk(pruned_tree.clone()).expect("Pruned tree should not be empty");

    // Commit to compute hashes (Modified → Loaded)
    tree.commit();

    // VERIFY: tree.hash() == expected_start_root
    let computed_start = tree.hash();
    if computed_start != *expected_start_root {
        panic!(
            "START ROOT MISMATCH\n\
             Expected: {}\n\
             Computed: {}\n\
             Pruned tree: {} Full nodes, {} Pruned nodes\n\
             This indicates the pruned tree doesn't represent the expected starting state.\n\
             Check: host tree building, node extraction, pruned tree construction.",
            hex::encode(expected_start_root),
            hex::encode(computed_start),
            full_count,
            pruned_count
        );
    }

    // ─── STAGE 2: Process Steps ──────────────────────────────────────────────

    // Apply each TraceStep's ops as a batch with PanicSource, verify reads.
    // Sequentiality is controlled by how InputStep::Write groups are constructed
    // (one op per step = sequential; multiple ops = batched).
    // If tracer missed a node → PanicSource panics → no proof generated
    let mut maybe_tree: Option<Node> = Some(tree);
    let mut all_read_results: Vec<ReadResults> = Vec::new();
    for step in steps {
        match step {
            TraceStep::Read(reads) => {
                let tree_ref = maybe_tree
                    .as_ref()
                    .expect("Cannot verify reads on empty tree");
                let results = extract_reads(tree_ref, reads);
                all_read_results.push(results);
            }
            TraceStep::Write(ops) => {
                maybe_tree = apply_batch(maybe_tree, ops, PanicSource {});
            }
        }
    }

    // ─── STAGE 3: Verify End Root ────────────────────────────────────────────

    let computed_end = match maybe_tree.as_mut() {
        Some(tree) => {
            // Commit to compute final hashes
            tree.commit();
            tree.hash()
        }
        None => {
            // All keys deleted → empty tree → zero hash
            [0u8; 32]
        }
    };

    // VERIFY: tree.hash() == expected_end_root
    if computed_end != *expected_end_root {
        panic!(
            "END ROOT MISMATCH\n\
             Expected: {}\n\
             Computed: {}\n\
             Start root: {}\n\
             Steps: {}\n\
             This indicates either:\n\
             - TracerFetch missed nodes (would have hit PanicSource earlier)\n\
             - apply_batch differs between host and guest\n\
             - Non-determinism (should not happen)\n\
             Check: apply_batch implementation, TracerFetch completeness.",
            hex::encode(expected_end_root),
            hex::encode(computed_end),
            hex::encode(expected_start_root),
            steps.len()
        );
    }

    all_read_results
}
