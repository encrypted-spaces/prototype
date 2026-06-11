//! ffproof_tracer guest: Verify pruned tree, apply operations, commit results.
//!
//! Applies ops one-at-a-time to match server behavior.

use ffproof_tracer_shared::{
    apply_batch, pruned_to_merk, extract_reads, TraceStep, TracerProof,
};
use merk::{PanicSource};
use risc0_zkvm::guest::env;

fn main() {
    // 1. Deserialize TracerProof
    let fixture_len: usize = env::read();
    let mut fixture_bytes = vec![0u8; fixture_len];
    env::read_slice(&mut fixture_bytes);

    let fixture: TracerProof =
        postcard::from_bytes(&fixture_bytes).expect("Failed to deserialize TracerProof");

    let TracerProof {
        pruned_tree,
        steps,
        expected_start_root,
        expected_end_root,
    } = fixture;

    // Count nodes for diagnostics
    let full_count = pruned_tree.count_full();
    let pruned_count = pruned_tree.count_pruned();

    // ─── STAGE 1: Verify Starting State ───────────────────────────────────────

    // 2. Convert PrunedMerkleTree → merk Tree
    let mut tree = pruned_to_merk(pruned_tree).expect("Pruned tree should not be empty");

    // 3. Commit to compute hashes (Modified → Loaded)
    tree.commit();

    // 4. VERIFY: tree.hash() == expected_start_root
    let computed_start = tree.hash();
    if computed_start != expected_start_root {
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

    // 5. Record stage 1 cycles
    let stage1_cycles = env::cycle_count();

    // ─── STAGE 2: Process Steps ──────────────────────────────────────────────

    // 6. Apply each TraceStep's ops as a batch with PanicSource, verify reads.
    // Sequentiality is controlled by how InputStep::Write groups are constructed
    // (one op per step = sequential; multiple ops = batched).
    // If tracer missed a node → PanicSource panics → no proof generated
    for step in &steps {
        match step {
            TraceStep::Read(reads) => {
                let _ = extract_reads(&tree, reads);
            }
            TraceStep::Write(ops) => {
                tree = apply_batch(Some(tree), ops, PanicSource {}).expect("non-empty tree");
            }
        }
    }

    // ─── STAGE 3: Verify End Root ────────────────────────────────────────────

    // 7. Commit to compute final hashes
    tree.commit();
    let computed_end = tree.hash();

    // 8. VERIFY: tree.hash() == expected_end_root
    if computed_end != expected_end_root {
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

    // 9. Commit to journal
    env::commit(&(
        expected_start_root,
        expected_end_root,
        stage1_cycles,
    ));
}
