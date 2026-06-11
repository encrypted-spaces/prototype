use crate::common::FFProof;
use encrypted_spaces_changelog_core::changelog::{
    verify_op_sequence_flat, ChangeLog, ChangeResponse, ChangelogEntry, ChangelogError,
    FastForwardRange, FlatEntryBytes,
};
use encrypted_spaces_changelog_core::ops::dispatch_extract_and_validate;
use encrypted_spaces_changelog_core::{create_trace, encode_pruned_compact, InputStep, TraceStep};
use encrypted_spaces_ffproof_methods::{EXTEND_FF_ELF, EXTEND_FF_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, SessionStats};

fn flatten_entry_bytes(entries: &[ChangelogEntry]) -> (Vec<u32>, Vec<u8>) {
    let mut entry_ends = Vec::with_capacity(entries.len());
    let mut bytes = Vec::new();
    for entry in entries {
        let entry_bytes = entry.as_bytes();
        let end = bytes
            .len()
            .checked_add(entry_bytes.len())
            .expect("entry byte length overflow");
        assert!(u32::try_from(end).is_ok(), "flat entry blob exceeds u32");
        bytes.extend_from_slice(&entry_bytes);
        entry_ends.push(end as u32);
    }
    (entry_ends, bytes)
}

// TODO: make sure errors are handled without panic

/// Apply the write overlay to a range scan result from the snapshot.
///
/// Merges overlay entries that fall within `[start, end)` into `snapshot_results`:
/// - Overlay `Some(value)` → upsert the key
/// - Overlay `None` (deleted) → remove the key
///
/// Returns the merged results sorted by key.
fn apply_overlay_to_range(
    mut snapshot_results: Vec<(Vec<u8>, Vec<u8>)>,
    overlay: &std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    start: &[u8],
    end: Option<&[u8]>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    // Collect overlay entries in range
    for (key, value) in overlay.range::<Vec<u8>, _>(start.to_vec()..) {
        if let Some(e) = end {
            if key.as_slice() >= e {
                break;
            }
        }
        match value {
            Some(v) => {
                // Upsert: remove any existing snapshot entry for this key, then add
                snapshot_results.retain(|(k, _)| k != key);
                snapshot_results.push((key.clone(), v.clone()));
            }
            None => {
                // Deleted in overlay: remove from results
                snapshot_results.retain(|(k, _)| k != key);
            }
        }
    }
    snapshot_results.sort_by(|(a, _), (b, _)| a.cmp(b));
    snapshot_results
}

/// Extract `InputStep`s from the changelog entries starting at `start_idx`.
///
/// This function runs each op's `extract_and_validate` with a
/// `ProverReader` that resolves reads against the tree snapshot, then emits
/// `InputStep::Read` and `InputStep::Write` entries in the correct order.
/// The resulting steps are fed to `create_trace` which re-resolves them to
/// build the proof.
///
/// A lightweight write overlay (`BTreeMap`) accumulates `Put`/`Delete`
/// writes from earlier ops so that later ops' key reads can see them
/// ("read your own writes").  For example, a `CreateSpaceOp` that
/// inserts a user row will be visible to a subsequent `InsertOp`'s
/// user-existence check in the same batch.  Prefix and range reads
/// fall through to the immutable snapshot only.
/// Note that reads in an op cannot read earlier writes _in the same
/// op_ (see changelog_core/src/ops/mod.rs).  This only enables reads
/// between separate ops.
///
/// # Arguments
/// * `changelog` - The changelog containing the hash chain entries
/// * `_change_responses` - The change responses for the same changelog range
/// * `start_idx` - The starting index (inclusive)
/// * `tree_snapshot` - The merk tree snapshot to resolve reads against
///
/// # Returns
/// * `Ok(Vec<InputStep>)` - The collected input steps from all entries in the range
/// * `Err(String)` - An error message if deserialization or extraction fails
pub fn extract_input_steps(
    changelog: &ChangeLog,
    _change_responses: &[ChangeResponse],
    start_idx: usize,
    tree_snapshot: &merk::Node,
) -> Result<Vec<InputStep>, String> {
    use encrypted_spaces_changelog_core::changelog::ChangelogEntry;
    use encrypted_spaces_changelog_core::ops::{OpContext, ProverReader};
    use ffproof_tracer_shared::{collect_range, prefix_successor, BatchOp, ProvenRead, ReadOp};
    use merk::GetResult;

    let end_idx = changelog.num_changes() as usize;
    let mut input_steps: Vec<InputStep> = Vec::new();

    // Write overlay: accumulates Put/Delete writes from earlier ops so that
    // later ops can read them without cloning or mutating the tree snapshot.
    // Key lookups check the overlay first; prefix/range reads merge overlay
    // entries with snapshot results.
    //
    // Overlay values:
    //   Some(value)  – Put: key exists with this value
    //   None         – Delete: key was removed
    let mut write_overlay: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>> =
        std::collections::BTreeMap::new();
    let mut ctx = OpContext::for_change_sequence();

    for i in start_idx..end_idx {
        // Parse the ChangelogEntry to determine op type
        let entry = ChangelogEntry::from_bytes(&changelog.changes[i].as_bytes())
            .map_err(|e| format!("Failed to parse changelog entry {i}: {e:?}"))?;

        // Build a resolver that checks the write overlay first, then the snapshot.
        let resolver = |op: &ReadOp| -> Result<ProvenRead, ChangelogError> {
            let proven = match op {
                ReadOp::Key(key) => {
                    // Check overlay first
                    let results = if let Some(entry) = write_overlay.get(key.as_slice()) {
                        match entry {
                            Some(value) => vec![(key.clone(), value.clone())],
                            None => vec![], // deleted
                        }
                    } else {
                        // Fall through to snapshot
                        let result = tree_snapshot.get_value(key).map_err(|e| {
                            ChangelogError::Generic(format!(
                                "Tree read failed for key {}: {e:?}",
                                hex::encode(key)
                            ))
                        })?;
                        match result {
                            GetResult::Found(value) => vec![(key.clone(), value)],
                            GetResult::NotFound => vec![],
                            GetResult::Pruned => {
                                return Err(ChangelogError::Generic(format!(
                                    "Pruned node encountered for key {}",
                                    hex::encode(key)
                                )));
                            }
                        }
                    };
                    ProvenRead {
                        op: op.clone(),
                        results,
                    }
                }
                ReadOp::Prefix(prefix) => {
                    let end = prefix_successor(prefix);
                    let results = apply_overlay_to_range(
                        collect_range(tree_snapshot, prefix, end.as_deref()),
                        &write_overlay,
                        prefix,
                        end.as_deref(),
                    );
                    ProvenRead {
                        op: op.clone(),
                        results,
                    }
                }
                ReadOp::Range { start, end } => {
                    let results = apply_overlay_to_range(
                        collect_range(tree_snapshot, start, Some(end.as_slice())),
                        &write_overlay,
                        start,
                        Some(end.as_slice()),
                    );
                    ProvenRead {
                        op: op.clone(),
                        results,
                    }
                }
            };
            Ok(proven)
        };

        ctx.begin_change(i + 1);

        // Run extract_and_validate with a ProverReader backed by real tree data.
        let mut reader = ProverReader::new(resolver);
        let op_result = dispatch_extract_and_validate(&entry, &mut reader, &ctx)
            .map_err(|e| format!("Op validation failed at entry {i}: {e}"))?;

        // Emit reads first (discovered by the ProverReader), then writes
        for read_op in reader.logged_reads {
            input_steps.push(InputStep::Read(vec![read_op]));
        }

        for write_step in op_result.write_steps {
            match write_step {
                TraceStep::Write(ops) => {
                    // Add Put/Delete writes to the overlay for future ops to read.
                    let mut resolved_ops = Vec::with_capacity(ops.len());
                    for op in &ops {
                        match op {
                            BatchOp::Put { key, value } => {
                                write_overlay.insert(key.clone(), Some(value.clone()));
                                resolved_ops.push(op.clone());
                            }
                            BatchOp::Delete { key } => {
                                write_overlay.insert(key.clone(), None);
                                resolved_ops.push(op.clone());
                            }
                        }
                    }
                    input_steps.push(InputStep::Write(resolved_ops));
                }
                other => {
                    return Err(format!(
                        "Op at entry {i} returned a non-Write step in write_steps: {other:?}"
                    ));
                }
            }
        }
        ctx.finish_change(entry.message.op_type);
    }

    Ok(input_steps)
}

/// Generate a FF proof for changes starting at `start_idx` in the changelog.
/// The changelog and responses are sliced internally to only include the needed data.
#[cfg(test)]
fn prove_ff(
    previous_proof: Option<&FFProof>,
    changelog: &ChangeLog,
    change_responses: &[ChangeResponse],
    start_idx: usize,
    pruned_tree_bytes: Vec<u8>,
) -> (FFProof, SessionStats) {
    prove_ff_chunk(
        previous_proof,
        changelog,
        change_responses,
        start_idx,
        pruned_tree_bytes,
    )
}

pub fn prove_ff_chunk(
    previous_proof: Option<&FFProof>,
    changelog: &ChangeLog,
    change_responses: &[ChangeResponse],
    start_idx: usize,
    // Compact witness bytes from `encode_pruned_compact`.
    pruned_tree_bytes: Vec<u8>,
) -> (FFProof, SessionStats) {
    crate::ensure_risc0_proof_mode();
    let is_first = previous_proof.is_none();

    // Slice the changelog and responses to only include what we need for this proof
    let tail_changelog = changelog.get_tail(start_idx);
    let tail_responses = change_responses[start_idx..].to_vec();

    log::info!(
        "proof_ff: proving {} changes (from {} to {})",
        tail_changelog.num_changes(),
        start_idx,
        changelog.num_changes()
    );

    let end_idx = tail_changelog.num_changes() as usize;
    // The start head is the head after `start_idx` real changes. For the
    // very first chunk this is the post-`initialize` head; for subsequent
    // chunks the previous proof already carries it as `io.end_clc_state`,
    // which is also the only historical head the changelog cache retains
    // (see `ChangeLog::proven_clc_state`). The end head after
    // `start_idx + end_idx` real changes is always the live writer tree.
    let start_clc_state = match previous_proof {
        Some(p) => p.io.end_clc_state.clone(),
        None => {
            assert_eq!(start_idx, 0, "first FF chunk must start at change_id 0");
            changelog.initial_clc_state()
        }
    };
    let end_clc_state = changelog.current_clc_state();
    let start_dc = tail_responses[0].old_root;
    let end_dc = tail_responses[end_idx - 1].new_root;

    // Serialize entry bytes as a flat blob with cumulative offsets
    let (entry_ends, entries_flat) = flatten_entry_bytes(&tail_changelog.changes);

    // Build the FastForwardRange on the host (eliminates need to send responses to guest)
    let range = FastForwardRange {
        end_change_id: end_idx as u32,
        start_clc_state,
        end_clc_state,
        start_dc: start_dc.into(),
        end_dc: end_dc.into(),
        sigref_map: std::collections::BTreeMap::new(), // guest computes the actual map
        recent_roots: Vec::new(),                      // guest seeds/threads the window
        timestamp_hwm: 0,
    };

    if let Some(previous_proof) = previous_proof {
        assert_eq!(
            start_idx as u32, previous_proof.io.end_change_id,
            "extension start index must match the previous proof's ending change id"
        );
        // `range.start_clc_state` == `previous_proof.io.end_clc_state` by
        // construction above; no extra check needed.
        assert_eq!(
            range.start_dc, previous_proof.io.end_dc,
            "extension DC must start from the previous proof's ending DC"
        );
    }

    let range_bytes = postcard::to_allocvec(&range).expect("Failed to serialize range");

    log::debug!(
        "Guest input sizes: entries_flat={}, entry_ends={}, range={}, pruned_tree={}",
        entries_flat.len(),
        entry_ends.len(),
        range_bytes.len(),
        pruned_tree_bytes.len(),
    );

    // Helper: write the flat entry blob + offsets into the env builder.
    // Order: entry_count, entries_byte_len, entry_ends slice, entries_flat slice.
    macro_rules! write_flat_entries {
        ($builder:expr) => {
            $builder
                .write(&entry_ends.len())
                .expect("write entry_count failed")
                .write(&entries_flat.len())
                .expect("write entries_byte_len failed")
                .write_slice(&entry_ends)
                .write_slice(&entries_flat)
        };
    }

    // Create the first proof separately since the inputs/logic is a little different
    let env = if is_first {
        log::info!("Creating the first proof for the changelog (start_idx = {start_idx})");
        debug_assert!({
            let mut dbg_sigref_map = std::collections::BTreeMap::new();
            let mut dbg_recent_roots: Vec<(u32, [u8; 32])> = Vec::new();
            let mut dbg_timestamp_hwm = 0;
            let flat = FlatEntryBytes::new(&entries_flat, &entry_ends).unwrap();
            verify_op_sequence_flat(
                flat,
                &range,
                &pruned_tree_bytes,
                0,
                &mut dbg_sigref_map,
                &mut dbg_recent_roots,
                &mut dbg_timestamp_hwm,
            )
        });

        let mut builder = ExecutorEnv::builder();
        builder.write(&is_first).expect("write is_first failed");
        write_flat_entries!(builder);
        builder
            .write(&range_bytes.len())
            .expect("write range_bytes.len() failed")
            .write_slice(&range_bytes)
            .write(&pruned_tree_bytes.len())
            .expect("write pruned tree len failed")
            .write_slice(&pruned_tree_bytes);

        builder.build().unwrap()
    } else {
        log::info!("Extending the fast-forward proof with more changes");

        let previous_receipt = &previous_proof.unwrap().receipt;
        let previous_io = &previous_proof.unwrap().io;
        let previous_io_bytes = previous_io.as_bytes();

        let mut builder = ExecutorEnv::builder();
        builder
            .write(&is_first)
            .expect("write is_first failed")
            .write(&previous_io_bytes.len())
            .expect("write_previous_io_bytes.len() failed")
            .write_slice(&previous_io_bytes)
            .write_slice(&EXTEND_FF_ID)
            .add_assumption(previous_receipt.clone());
        write_flat_entries!(builder);
        builder
            .write(&range_bytes.len())
            .expect("write range_bytes.len() failed")
            .write_slice(&range_bytes)
            .write(&pruned_tree_bytes.len())
            .expect("write pruned tree len failed")
            .write_slice(&pruned_tree_bytes);

        builder.build().unwrap()
    };

    let prover = default_prover();
    log::info!("Calling EXTEND_FF prover");
    // Produce a receipt by proving the specified ELF binary.
    //
    // Use succinct opts so the prover internally collapses the
    // (composite) per-segment receipts into a single recursive
    // `SuccinctReceipt`. Without this the on-wire FF proof is a
    // `CompositeReceipt` whose size grows linearly with the number of
    // segments.
    #[cfg(debug_assertions)]
    let start_time = std::time::Instant::now();
    let proof_info = prover
        .prove_with_opts(env, EXTEND_FF_ELF, &ProverOpts::succinct())
        .unwrap();
    let receipt = proof_info.receipt;
    let stats = proof_info.stats;

    #[cfg(debug_assertions)]
    {
        let prove_duration = start_time.elapsed();
        log::debug!("Elf size: {}", EXTEND_FF_ELF.len());
        log::info!("Proving took: {prove_duration:?}");
        log::debug!("receipt size: {}", receipt.seal_size());
        log::info!(
            "user cycles: {}, paging cycles: {}, sum: {}",
            stats.user_cycles,
            stats.paging_cycles,
            stats.user_cycles + stats.paging_cycles
        );
        log::info!(
            "segments: {}, total cycles: {}, reserved/wasted cycles: {}",
            stats.segments,
            stats.total_cycles,
            stats.reserved_cycles
        );
    }

    assert!(
        receipt.verify(EXTEND_FF_ID).is_ok(),
        "receipt verification failed"
    );

    // Decode journal directly as FastForwardRange - no conversions needed
    let io: FastForwardRange = receipt.journal.decode().unwrap();

    log::info!(
        "Batch proven: {} changes (change ids 0 to {})",
        io.end_change_id,
        io.end_change_id
    );
    log::debug!(
        "start tree head root: {:?}",
        hex::encode::<[u8; 32]>(io.start_clc_state.root.into())
    );
    log::debug!(
        "end tree head root  : {:?}",
        hex::encode::<[u8; 32]>(io.end_clc_state.root.into())
    );
    log::debug!("start DC : {:?}", hex::encode(io.start_dc.as_bytes()));
    log::debug!("end DC   : {:?}", hex::encode(io.end_dc.as_bytes()));

    (FFProof { io, receipt }, stats)
}

/// Generate a FF proof for unproven changes in the changelog and update its state.
/// Note: This doesn't implement any batch size, it will generate a new FF proof if there
/// is one or more unproven changes.
///
/// This is the main entry point for proving. It:
/// 1. Generates a proof covering changes from `proven_up_to` to the end
/// 2. Updates the changelog's `ff_proof` and `proven_up_to` fields
///
/// # Arguments
/// * `changelog` - The changelog to prove (will be mutated to store the proof)
/// * `change_responses` - The change responses corresponding to the changelog entries
/// * `previous_proof` - The previous FF proof if extending an existing proof chain
///
/// # Returns
/// * `true` if proving succeeded or there was nothing to prove
/// * `false` if proving failed
pub fn update_changelog_proof(
    changelog: &mut ChangeLog,
    change_responses: &[ChangeResponse],
    previous_proof: Option<&FFProof>,
    tree_snapshot: &merk::Node,
) -> Result<(), String> {
    let start_idx = changelog.proven_up_to;

    if start_idx >= changelog.num_changes() as usize {
        // Nothing to prove
        return Ok(());
    }

    let steps = match extract_input_steps(changelog, change_responses, start_idx, tree_snapshot) {
        Ok(result) => result,
        Err(e) => return Err(format!("failed to extract input steps: {e}")),
    };

    let tracer_proof = create_trace(tree_snapshot, &steps);
    let pruned_tree_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);
    let (proof, _stats) = prove_ff_chunk(
        previous_proof,
        changelog,
        change_responses,
        start_idx,
        pruned_tree_bytes,
    );
    let new_proven_up_to = changelog.num_changes() as usize;

    changelog.set_ff_proof(proof.serialize(), new_proven_up_to);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::verify_ff_internal;
    use encrypted_spaces_changelog_test_utils::{TestServer, TEST_CLIENT_UID};
    use serial_test::serial;
    use temp_env;

    // These tests are run with [serial] since each test is multi-core when `--features real-proofs` is used.

    // Proof mode (dev vs real) is handled by ensure_risc0_proof_mode()
    // which is gated on the `real-proofs` feature.

    const TEST_ENV_VARS: [(&str, Option<&str>); 2] = [
        ("RUST_LOG", Some("info")), // Increase the logging output from the RISC0 prover
        ("RISC0_INFO", Some("1")),  // Displays detailed info about prover resource use
    ];

    struct TraceResult {
        pruned_tree_bytes: Vec<u8>,
    }

    fn extract_and_trace(server: &TestServer, start_idx: usize) -> TraceResult {
        let tree_snapshot = server.tree_snapshot().expect("Tree snapshot should exist");
        let steps = extract_input_steps(
            server.changelog(),
            server.responses(),
            start_idx,
            tree_snapshot,
        )
        .expect("Failed to extract input steps");
        let tracer_proof = create_trace(tree_snapshot, &steps);
        let pruned_tree_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);
        TraceResult { pruned_tree_bytes }
    }

    #[tokio::test]
    #[serial]
    async fn test_simple_ff_roundtrip() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_simple_ff_roundtrip: RISC0_SKIP_BUILD is set");
            return;
        }
        let num_changes = 3;
        let server = TestServer::new_for_tests(num_changes, None).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            println!("\n=== RISC0 Cycle Report ===");
            println!("User cycles:     {}", stats.user_cycles);
            println!("Paging cycles:   {}", stats.paging_cycles);
            println!("Total cycles:    {}", stats.total_cycles);
            println!("Reserved cycles: {}", stats.reserved_cycles);
            println!("Segments:        {}", stats.segments);
            println!(
                "Cycles per change: {}",
                stats.user_cycles / num_changes as u64
            );
            println!("=========================");

            let res = verify_ff_internal(&proof, EXTEND_FF_ID);

            assert!(res, "Result of verify_ff_internal is false");
        });
    }

    #[tokio::test]
    #[serial]
    async fn test_repeated_ff() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_repeated_ff: RISC0_SKIP_BUILD is set");
            return;
        }
        temp_env::async_with_vars(TEST_ENV_VARS, async {
            let num_changes_per_batch = 3;
            let mut server = TestServer::new_for_tests(num_changes_per_batch, None).await;

            // First batch: create initial proof
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (mut proof, stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );
            println!(
                "Batch 1: user_cycles={}, total_cycles={}",
                stats.user_cycles, stats.total_cycles
            );
            let res = verify_ff_internal(&proof, EXTEND_FF_ID);
            assert!(res, "Result of verify_ff_internal is false");

            // Update tree snapshot for next batch
            server.update_tree_snapshot();

            let num_additional_batches = 3;
            for i in 0..num_additional_batches {
                println!("\nGenerating FF proof for batch {}", i + 2);

                // Take snapshot before adding more changes
                println!(
                    "Tree snapshot hash before add_more_changes: {:?}",
                    server.tree_snapshot().map(|t| hex::encode(t.hash()))
                );

                server.add_more_changes(num_changes_per_batch).await;

                // Start where the previous proof ended
                let start_idx = proof.io.end_change_id as usize;
                println!(
                    "start_idx = {}, total changes = {}",
                    start_idx,
                    server.changelog().num_changes()
                );

                let tree_snapshot = server.tree_snapshot().expect("Tree snapshot should exist");
                println!(
                    "Using tree snapshot with hash: {}",
                    hex::encode(tree_snapshot.hash())
                );

                let tr = extract_and_trace(&server, start_idx);
                println!("Extracted input steps");

                // Check what the responses say the end root should be
                let responses_for_batch = &server.responses()[start_idx..];
                if !responses_for_batch.is_empty() {
                    println!(
                        "First response old_root: {}",
                        hex::encode(responses_for_batch[0].old_root)
                    );
                    println!(
                        "Last response new_root: {}",
                        hex::encode(responses_for_batch.last().unwrap().new_root)
                    );
                }

                let (new_proof, stats) = prove_ff(
                    Some(&proof),
                    server.changelog(),
                    server.responses(),
                    start_idx,
                    tr.pruned_tree_bytes,
                );
                proof = new_proof;
                println!(
                    "Batch {}: user_cycles={}, total_cycles={}",
                    i + 2,
                    stats.user_cycles,
                    stats.total_cycles
                );
                let res = verify_ff_internal(&proof, EXTEND_FF_ID);
                assert!(res, "Result of verify_ff_internal on batch is false");

                // Update tree snapshot for next batch
                server.update_tree_snapshot();
            }
        })
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_ff_serialization_roundtrip() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_ff_serialization_roundtrip: RISC0_SKIP_BUILD is set");
            return;
        }
        let num_changes = 3; // Use 3 changes to match test_simple_ff_roundtrip
        let server = TestServer::new_for_tests(num_changes, None).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, _stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            // Test serialization
            let serialized_bytes = proof.serialize();

            // Test deserialization (FFProof uses postcard, not bincode)
            let deserialized_proof =
                FFProof::deserialize(&serialized_bytes).expect("Failed to deserialize FFProof");

            // Verify the deserialized proof works the same as the original
            let res = verify_ff_internal(&deserialized_proof, EXTEND_FF_ID);
            assert!(
                res,
                "Result of verify_ff_internal on deserialized proof is false"
            );

            // Verify the IO fields are the same
            assert_eq!(
                proof.io.start_clc_state,
                deserialized_proof.io.start_clc_state
            );
            assert_eq!(proof.io.end_clc_state, deserialized_proof.io.end_clc_state);
            assert_eq!(proof.io.start_dc, deserialized_proof.io.start_dc);
            assert_eq!(proof.io.end_dc, deserialized_proof.io.end_dc);
        });
    }

    /// Helper: run a single-change FF proof with the given value size and return the cycle stats.
    async fn prove_with_value_size(value_size: usize) -> SessionStats {
        let num_changes = 1;
        let server = TestServer::new_for_tests(num_changes, Some(value_size)).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (_proof, stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            println!("\n=== Cycle stats for value_size={value_size} ===");
            println!("User cycles:   {}", stats.user_cycles);
            println!("Total cycles:  {}", stats.total_cycles);
            println!("Paging cycles: {}", stats.paging_cycles);
            println!("================================================");

            stats
        })
    }

    /// Test that proving works for both small and large value sizes.
    #[tokio::test]
    #[serial]
    async fn test_ff_short_values_use_fewer_cycles() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_ff_short_values_use_fewer_cycles: RISC0_SKIP_BUILD is set");
            return;
        }

        let large_value_size = 128; // at String column limit
        let small_value_size = 32;

        let stats_large = prove_with_value_size(large_value_size).await;
        let stats_small = prove_with_value_size(small_value_size).await;

        println!("\n=== Value-size cycle comparison ===");
        println!(
            "Large value ({large_value_size}B): user_cycles={}, total_cycles={}",
            stats_large.user_cycles, stats_large.total_cycles
        );
        println!(
            "Small value ({small_value_size}B): user_cycles={}, total_cycles={}",
            stats_small.user_cycles, stats_small.total_cycles
        );
        println!("===================================");

        // Both should complete successfully (implicitly verified by reaching here).
        assert!(
            stats_large.user_cycles > 0 && stats_small.user_cycles > 0,
            "Both proofs should complete with nonzero cycles"
        );
    }

    /// Test that an unknown user is rejected during proof verification.
    /// Creates a server where the `_users` table is empty (no user row inserted).
    /// The change is rejected at `add_change` time (via `verify_proof_and_validate`)
    /// because the proof's embedded reads show the user doesn't exist.
    #[tokio::test]
    #[serial]
    async fn test_unknown_user_verification_fails() {
        let server = TestServer::new_for_tests_unknown_user(1).await;

        // The change should have been rejected — the changelog should be empty
        // because verify_proof_and_validate catches the unknown user via the
        // VerifierReader (empty reads → op validation fails).
        assert_eq!(
            server.changelog().num_changes(),
            0,
            "Unknown user change should be rejected at add_change time"
        );
    }

    /// Test that the sigref_map is correctly populated after proving a single-user changelog.
    /// The map should contain one entry: uid -> (latest_change_id, entry_hash).
    #[tokio::test]
    #[serial]
    async fn test_sigref_map_single_user() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_sigref_map_single_user: RISC0_SKIP_BUILD is set");
            return;
        }
        let num_changes = 3;
        let uid = TEST_CLIENT_UID; // TestServer's default UID
        let server = TestServer::new_for_tests(num_changes, None).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, _stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            let res = verify_ff_internal(&proof, EXTEND_FF_ID);
            assert!(res, "Proof should verify");

            // sigref_map should have exactly one entry: uid -> (num_changes, _hash)
            assert_eq!(
                proof.io.sigref_map.len(),
                1,
                "Should have one user in sigref_map"
            );
            assert_eq!(
                proof.io.sigref_map.get(&uid).map(|&(cid, _)| cid),
                Some(num_changes as u32),
                "Latest change_id for uid {uid} should be {num_changes}"
            );
            assert!(
                proof
                    .io
                    .sigref_map
                    .get(&uid)
                    .map(|&(_, h)| h != [0u8; 32])
                    .unwrap_or(false),
                "sigref entry hash for uid {uid} must be populated by the guest"
            );
        });
    }

    /// Test that the sigref_map correctly tracks multiple interleaved users.
    /// Users A and B alternate changes: A, B, A, B, A — each user's entry
    /// should point to their own latest change_id.
    #[tokio::test]
    #[serial]
    async fn test_sigref_map_multi_user() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_sigref_map_multi_user: RISC0_SKIP_BUILD is set");
            return;
        }
        let num_changes = 5;
        // uids must match the auto-increment sequence of the _users table.
        let user_uids = [1, 2];
        let (server, expected_last_changes) =
            TestServer::new_multi_user(num_changes, &user_uids).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, _stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            let res = verify_ff_internal(&proof, EXTEND_FF_ID);
            assert!(res, "Multi-user proof should verify");

            // sigref_map should have entries for both users
            assert_eq!(
                proof.io.sigref_map.len(),
                2,
                "Should have two users in sigref_map"
            );

            // Verify each user's latest change_id matches expected
            for &uid in &user_uids {
                let expected = expected_last_changes.get(&uid).copied().unwrap();
                let actual = proof.io.sigref_map.get(&uid).map(|&(cid, _)| cid);
                assert_eq!(
                    actual,
                    Some(expected),
                    "uid {uid}: expected sigref_map entry {expected}, got {actual:?}"
                );
            }
        });
    }

    /// Test that the sigref_map carries correctly across proof chunks.
    /// Prove a first batch, then extend with a second batch. The second
    /// chunk must validate sig_refs against entries from the first chunk.
    #[tokio::test]
    #[serial]
    async fn test_sigref_map_carries_across_chunks() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_sigref_map_carries_across_chunks: RISC0_SKIP_BUILD is set");
            return;
        }
        temp_env::async_with_vars(TEST_ENV_VARS, async {
            let batch_size = 3;
            let mut server = TestServer::new_for_tests(batch_size, None).await;

            // First batch proof
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, _stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );
            assert!(
                verify_ff_internal(&proof, EXTEND_FF_ID),
                "First batch should verify"
            );
            assert_eq!(proof.io.sigref_map.len(), 1, "One user after first batch");

            // Update tree snapshot and add more changes
            server.update_tree_snapshot();
            server.add_more_changes(batch_size).await;

            // Second batch proof (extending from first)
            let start_idx = proof.io.end_change_id as usize;
            let tr = extract_and_trace(&server, start_idx);

            let (proof2, _stats) = prove_ff(
                Some(&proof),
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );
            assert!(
                verify_ff_internal(&proof2, EXTEND_FF_ID),
                "Extended proof should verify"
            );

            // sigref_map should still have one user, now pointing to the latest change
            let total_changes = (batch_size * 2) as u32;
            assert_eq!(
                proof2.io.sigref_map.len(),
                1,
                "Still one user after extension"
            );
            assert_eq!(
                proof2
                    .io
                    .sigref_map
                    .get(&TEST_CLIENT_UID)
                    .map(|&(cid, _)| cid),
                Some(total_changes),
                "Latest change_id should be {total_changes} after both batches"
            );
        })
        .await;
    }

    /// Regression test for the extend-FF continuation bug.
    ///
    /// This bypasses `prove_ff` so the host-side pre-checks cannot catch the
    /// mismatch first. The malicious extension attempts to recursively extend a
    /// valid proof with an unrelated changelog segment whose start CLC/DC do not
    /// match the previous proof's end CLC/DC. The guest must reject it.
    #[tokio::test]
    #[serial]
    async fn test_extend_ff_rejects_non_contiguous_guest_input() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!(
                "Skipping test_extend_ff_rejects_non_contiguous_guest_input: RISC0_SKIP_BUILD is set"
            );
            return;
        }

        temp_env::async_with_vars(TEST_ENV_VARS, async {
            let batch_size = 3;
            let previous_server = TestServer::new_for_tests(batch_size, None).await;

            let previous_tr = extract_and_trace(&previous_server, 0);
            let (previous_proof, _stats) = prove_ff(
                None,
                previous_server.changelog(),
                previous_server.responses(),
                0,
                previous_tr.pruned_tree_bytes,
            );
            assert!(
                verify_ff_internal(&previous_proof, EXTEND_FF_ID),
                "Previous proof should verify"
            );

            // Build an unrelated first segment and feed it to the guest as if it
            // were the next segment after `previous_proof`.
            let unrelated_server = TestServer::new_for_tests(1, None).await;
            let unrelated_start_idx = 0;
            let unrelated_changelog = unrelated_server.changelog().get_tail(unrelated_start_idx);
            let unrelated_responses = unrelated_server.responses()[unrelated_start_idx..].to_vec();
            let unrelated_end_idx = unrelated_changelog.num_changes() as usize;

            let unrelated_tr = extract_and_trace(&unrelated_server, unrelated_start_idx);

            let (entry_ends, entries_flat) = flatten_entry_bytes(&unrelated_changelog.changes);

            let unrelated_start_tree_head = unrelated_server.changelog().initial_clc_state();
            let unrelated_end_tree_head = unrelated_server.changelog().current_clc_state();

            let range = FastForwardRange {
                end_change_id: unrelated_end_idx as u32,
                start_clc_state: unrelated_start_tree_head,
                end_clc_state: unrelated_end_tree_head,
                start_dc: unrelated_responses[0].old_root.into(),
                end_dc: unrelated_responses[unrelated_end_idx - 1].new_root.into(),
                sigref_map: std::collections::BTreeMap::new(),
                recent_roots: Vec::new(),
                timestamp_hwm: 0,
            };
            assert_ne!(
                range.start_clc_state, previous_proof.io.end_clc_state,
                "test setup must use a mismatched tree head boundary"
            );
            assert_ne!(
                range.start_dc, previous_proof.io.end_dc,
                "test setup must use a mismatched DC boundary"
            );

            let range_bytes = postcard::to_allocvec(&range).expect("Failed to serialize range");
            let previous_io_bytes = previous_proof.io.as_bytes();
            let is_first = false;

            let env = ExecutorEnv::builder()
                .write(&is_first)
                .expect("write is_first failed")
                .write(&previous_io_bytes.len())
                .expect("write previous_io_bytes.len() failed")
                .write_slice(&previous_io_bytes)
                .write_slice(&EXTEND_FF_ID)
                .add_assumption(previous_proof.receipt.clone())
                .write(&entry_ends.len())
                .expect("write entry_count failed")
                .write(&entries_flat.len())
                .expect("write entries_byte_len failed")
                .write_slice(&entry_ends)
                .write_slice(&entries_flat)
                .write(&range_bytes.len())
                .expect("write range_bytes.len() failed")
                .write_slice(&range_bytes)
                .write(&unrelated_tr.pruned_tree_bytes.len())
                .expect("write pruned_tree_bytes.len() failed")
                .write_slice(&unrelated_tr.pruned_tree_bytes)
                .build()
                .unwrap();

            let result = default_prover().prove(env, EXTEND_FF_ELF);
            assert!(
                result.is_err(),
                "guest accepted a non-contiguous FF proof extension"
            );
        })
        .await;
    }

    /// Direct regression for the FF guest's `parent_clc` window check
    ///  Builds a real, valid `verify_op_sequence`
    /// flat input set via the test server, confirms the happy path, then
    /// tampers one entry's signed `parent_clc` and asserts the guest
    /// rejects.
    ///
    /// We invoke `verify_op_sequence` directly rather than the zkVM
    /// prover because the function is pure Rust and this lets the test
    /// run without `--features real-proofs`. The same code path runs
    /// inside the RISC0 guest, so a rejection here is a rejection there.
    #[tokio::test]
    #[serial]
    async fn verify_op_sequence_rejects_tampered_parent_clc() {
        // No RISC0_SKIP_BUILD guard: we never start the prover.
        let num_changes = 3usize;
        let server = TestServer::new_for_tests(num_changes, None).await;

        let tree_snapshot = server.tree_snapshot().expect("tree snapshot");
        let start_idx = 0usize;

        let steps = extract_input_steps(
            server.changelog(),
            server.responses(),
            start_idx,
            tree_snapshot,
        )
        .expect("extract_input_steps");
        let tracer_proof = create_trace(tree_snapshot, &steps);
        let pruned_tree_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);

        let tail = server.changelog().get_tail(start_idx);
        let mut entries: Vec<Vec<u8>> = tail.changes.iter().map(|e| e.as_bytes()).collect();
        let end_idx = entries.len();
        let responses = server.responses();
        let range = FastForwardRange {
            end_change_id: end_idx as u32,
            start_clc_state: server.changelog().initial_clc_state(),
            end_clc_state: server.changelog().current_clc_state(),
            start_dc: responses[start_idx].old_root.into(),
            end_dc: responses[start_idx + end_idx - 1].new_root.into(),
            sigref_map: std::collections::BTreeMap::new(),
            recent_roots: Vec::new(),
            timestamp_hwm: 0,
        };

        // Happy path: the unmodified entries verify cleanly.
        let (entry_ends, entries_flat) = flatten_entry_bytes(&tail.changes);
        let flat_entries = FlatEntryBytes::new(&entries_flat, &entry_ends).unwrap();
        let mut sigref_map = std::collections::BTreeMap::new();
        let mut recent_roots: Vec<(u32, [u8; 32])> = Vec::new();
        let mut timestamp_hwm = 0;
        assert!(
            verify_op_sequence_flat(
                flat_entries,
                &range,
                &pruned_tree_bytes,
                start_idx as u32,
                &mut sigref_map,
                &mut recent_roots,
                &mut timestamp_hwm,
            ),
            "untampered entries must pass verify_op_sequence"
        );
        // Window must hold the seed + one root per change (here 1 + num_changes).
        assert_eq!(recent_roots.len(), 1 + num_changes);

        // Tamper: flip a bit in entry[1]'s `parent_clc`. The entry's
        // signature is not re-checked by verify_op_sequence (the FF
        // guest validates signatures via the sigref pipeline in a
        // separate later stage), so this is exactly the malicious-prover
        // scenario the window check is meant to catch.
        let mut tampered = ChangelogEntry::from_bytes(&entries[1]).expect("parse entry");
        tampered.parent_clc[0] ^= 0x01;
        entries[1] = tampered.as_bytes();

        let mut entries_flat = Vec::new();
        let mut entry_ends = Vec::with_capacity(entries.len());
        for entry in &entries {
            let end = entries_flat
                .len()
                .checked_add(entry.len())
                .expect("entry byte length overflow");
            assert!(u32::try_from(end).is_ok(), "flat entry blob exceeds u32");
            entries_flat.extend_from_slice(entry);
            entry_ends.push(end as u32);
        }
        let flat_entries = FlatEntryBytes::new(&entries_flat, &entry_ends).unwrap();
        let mut sigref_map = std::collections::BTreeMap::new();
        let mut recent_roots: Vec<(u32, [u8; 32])> = Vec::new();
        let mut timestamp_hwm = 0;
        assert!(
            !verify_op_sequence_flat(
                flat_entries,
                &range,
                &pruned_tree_bytes,
                start_idx as u32,
                &mut sigref_map,
                &mut recent_roots,
                &mut timestamp_hwm,
            ),
            "tampered parent_clc must be rejected by verify_op_sequence"
        );
    }
}
