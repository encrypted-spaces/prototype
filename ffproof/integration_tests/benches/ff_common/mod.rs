#![allow(dead_code)]
//! Shared helpers for `ff_*_benchmarks` targets.
//!
//! Provides:
//! - `SharedStateTransport`: an in-process `Transport` backed by a shared
//!   `SpaceState`, so SDK-level `Space` calls drive the same state we then
//!   invoke the prover on.
//! - `ProductRow` / `ProjectRow` / `TaskRow` and `app_schemas()`: the
//!   row/table layout used by both cycle and time benches.
//! - `apply_table_sequence` / `apply_list_sequence`: the exact two
//!   "realistic 100-change" workloads from `ff_cycle_benchmarks.rs`.
//! - `prove_pending_changes`: proves all pending changes and returns both
//!   RISC0 user cycles and wall-clock elapsed time.
//! - `SuppressStderr`: hide prover stderr noise during benches.
//!
//! Placed in `benches/ff_common/` (subdirectory) so cargo's bench
//! autodiscovery doesn't try to compile it as a separate bench target.
//!
//! Included into individual bench files via `#[path = "ff_common/mod.rs"]
//! mod ff_common;`. Each bench uses only a subset of helpers, so suppress
//! dead_code warnings module-wide

pub mod actions;

use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::error::{Result as BackendResult, SdkError};
use encrypted_spaces_backend::merk_storage::proofs::{
    verify_query_proof_with_hashed_values, VerifiedRows,
};
use encrypted_spaces_backend::merk_storage::{column_key, stored_value};
use encrypted_spaces_backend::query::Query;
use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_backend_server::app_config::{BootstrapDataSource, SpaceInitConfig};
use encrypted_spaces_backend_server::SpaceState;
use encrypted_spaces_changelog_core::changelog::{
    initial_clc_state, Change, ChangeLog, ChangeResponse, ChangelogEntry, ClcState, Digest,
    FastForwardData, FastForwardJournal, FastForwardRange,
};
use encrypted_spaces_changelog_core::{create_trace, encode_pruned_compact, PrunedMerkleTreeStats};
use encrypted_spaces_ffproof::common::FFProof;
use encrypted_spaces_ffproof::prover::{extract_input_steps, prove_ff_chunk};
use encrypted_spaces_ffproof_methods_bench::{EXTEND_FF_BENCH_ELF, EXTEND_FF_BENCH_ID};
use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest};
use encrypted_spaces_sdk::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
use encrypted_spaces_sdk::transport::{EphemeralReceiver, Transport};
use encrypted_spaces_sdk::Space;
use encrypted_spaces_sdk::{List, List as ListAlias};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// ─── Stderr suppression ──────────────────────────────────────────────────────

/// Suppress stderr to hide risc0 dev-mode warnings and R0VM guest log lines.
/// Restores stderr on drop.
pub struct SuppressStderr {
    saved_fd: i32,
}

impl SuppressStderr {
    pub fn new() -> Self {
        let saved_fd = unsafe { libc::dup(2) };
        let devnull = std::fs::File::open("/dev/null").unwrap();
        unsafe { libc::dup2(devnull.as_raw_fd(), 2) };
        Self { saved_fd }
    }
}

impl Drop for SuppressStderr {
    fn drop(&mut self) {
        unsafe {
            libc::dup2(self.saved_fd, 2);
            libc::close(self.saved_fd);
        }
    }
}

// ─── Row types & schemas ─────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ProductRow {
    pub id: Option<i64>,
    pub name: String,
    pub price: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectRow {
    pub id: Option<i64>,
    pub name: String,
    pub tasks: List<TaskRow>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskRow {
    pub title: String,
    pub done: bool,
}

pub fn app_schemas() -> Vec<Schema> {
    let products = SchemaBuilder::new("products")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("name", ColumnType::String)
        .unwrap()
        .column("price", ColumnType::Real)
        .unwrap()
        .build()
        .unwrap();

    let projects = SchemaBuilder::new("projects")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("name", ColumnType::String)
        .unwrap()
        .column("tasks", ColumnType::List)
        .unwrap()
        .build()
        .unwrap();

    vec![products, projects]
}

// ─── Shared-state transport ──────────────────────────────────────────────────

pub struct SharedStateTransport {
    state: Arc<Mutex<SpaceState>>,
    auth_context: Mutex<AuthContext>,
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl SharedStateTransport {
    pub fn new(state: Arc<Mutex<SpaceState>>) -> Self {
        Self {
            state,
            auth_context: Mutex::new(AuthContext::new(None, SpaceId::from([0u8; 16]))),
            files: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl Transport for SharedStateTransport {
    async fn submit_change(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> BackendResult<ChangeResponse> {
        let auth_context = self.auth_context.lock().await;
        let mut state = self.state.lock().await;
        state
            .handle_change_with_proofs(change, &auth_context, retention_proofs)
            .await
            .map_err(|e| SdkError::DatabaseError(format!("handle_change failed: {e}")))
    }

    async fn fast_forward(&self, change_id: u32) -> BackendResult<FastForwardData> {
        let auth_context = self.auth_context.lock().await;
        let mut state = self.state.lock().await;
        state
            .handle_fast_forward(change_id, &[], &auth_context)
            .map_err(|e| SdkError::DatabaseError(format!("fast_forward failed: {e}")))
    }

    async fn select(
        &self,
        query: Query,
        commitment: &[u8; 32],
        schemas: &std::collections::HashMap<String, Schema>,
    ) -> BackendResult<VerifiedRows> {
        let state = self.state.lock().await;
        let select_response = state.handle_select(&query, commitment).await?;
        verify_query_proof_with_hashed_values(
            &query,
            &select_response.proof,
            commitment,
            schemas,
            &select_response.hashed_values,
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn fetch_my_key_delivery(&self) -> BackendResult<Option<Vec<u8>>> {
        let auth_context = self.auth_context.lock().await;
        let uid = auth_context.uid.ok_or_else(|| {
            SdkError::ValidationError(
                "fetch_my_key_delivery requires authenticated user".to_string(),
            )
        })?;
        let state = self.state.lock().await;
        Ok(state.key_delivery_slots.get(uid))
    }

    async fn add_member(
        &self,
        request: InviteRequest,
        insert_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> BackendResult<ChangeResponse> {
        let auth_context = self.auth_context.lock().await;
        let mut state = self.state.lock().await;
        state
            .handle_add_member(&request, insert_change, &auth_context, &retention_proofs)
            .await
            .map_err(|e| SdkError::DatabaseError(format!("handle_add_member failed: {e}")))
    }

    async fn remove_member(
        &self,
        request: RekeyRequest,
        remaining_uids: &[i64],
        delete_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> BackendResult<ChangeResponse> {
        let auth_context = self.auth_context.lock().await;
        let mut state = self.state.lock().await;
        state
            .handle_remove_member(
                &request,
                remaining_uids,
                delete_change,
                &auth_context,
                &retention_proofs,
            )
            .await
            .map_err(|e| SdkError::DatabaseError(format!("handle_remove_member failed: {e}")))
    }

    async fn submit_retention(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
        rekey_request: Option<RekeyRequest>,
    ) -> BackendResult<ChangeResponse> {
        let auth_context = self.auth_context.lock().await;
        let mut state = self.state.lock().await;
        state
            .handle_retention(
                change,
                &auth_context,
                retention_proofs,
                rekey_request.as_ref(),
            )
            .await
            .map_err(|e| SdkError::DatabaseError(format!("handle_retention failed: {e}")))
    }

    async fn authenticate(&self, auth_context: &AuthContext) -> BackendResult<()> {
        *self.auth_context.lock().await = auth_context.clone();
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn subscribe_ephemeral(&self) -> BackendResult<EphemeralReceiver> {
        Err(SdkError::ValidationError(
            "subscribe_ephemeral is not supported by this transport".into(),
        ))
    }

    async fn file_upload(&self, hash: &str, data: Vec<u8>) -> BackendResult<()> {
        self.files.lock().await.insert(hash.to_string(), data);
        Ok(())
    }

    async fn file_download(&self, hash: &str) -> BackendResult<Vec<u8>> {
        self.files
            .lock()
            .await
            .get(hash)
            .cloned()
            .ok_or_else(|| SdkError::DatabaseError(format!("file not found: {hash}")))
    }
}

// ─── Prove helper ────────────────────────────────────────────────────────────

pub struct ProveResult {
    pub cycles: u64,
    pub paging_cycles: u64,
    pub total_cycles: u64,
    pub reserved_cycles: u64,
    pub segments: usize,
    pub elapsed: Duration,
}

pub struct BenchProveResult {
    pub cycles: u64,
    pub journal: Option<FastForwardJournal>,
    pub witness: Option<BenchWitnessStats>,
    pub elapsed: Duration,
}

pub struct BenchWitnessStats {
    pub serialized_bytes: usize,
    pub tree: PrunedMerkleTreeStats,
}

pub struct BenchProofChain {
    proof: Option<FFProof>,
}

impl BenchProofChain {
    pub fn new() -> Self {
        Self { proof: None }
    }
}

fn flatten_entry_bytes_from_changes(changes: &[ChangelogEntry]) -> (Vec<u32>, Vec<u8>) {
    let mut entry_ends = Vec::with_capacity(changes.len());
    let mut bytes = Vec::new();
    for entry in changes {
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

/// Keep bench input construction compatible with defaulted FF range fields
/// added after this benchmark branch, such as the recent-roots window.
#[allow(clippy::field_reassign_with_default)]
fn bench_fast_forward_range(
    end_change_id: u32,
    start_clc_state: ClcState,
    end_clc_state: ClcState,
    start_dc: Digest,
    end_dc: Digest,
) -> FastForwardRange {
    let mut range = FastForwardRange::default();
    range.end_change_id = end_change_id;
    range.start_clc_state = start_clc_state;
    range.end_clc_state = end_clc_state;
    range.start_dc = start_dc;
    range.end_dc = end_dc;
    range.sigref_map = std::collections::BTreeMap::new();
    range
}

/// Prove all pending changes and return RISC0 user cycles + wall-clock time.
/// If there are no pending changes, returns zero/zero.
pub async fn prove_pending_changes(state: &Arc<Mutex<SpaceState>>) -> ProveResult {
    let mut state = state.lock().await;
    let start_idx = state.changelog.proven_up_to;
    let num_changes = state.changelog.num_changes() as usize;
    if start_idx >= num_changes {
        return ProveResult {
            cycles: 0,
            paging_cycles: 0,
            total_cycles: 0,
            reserved_cycles: 0,
            segments: 0,
            elapsed: Duration::ZERO,
        };
    }

    let tree_snapshot = state
        .tree_snapshot
        .as_ref()
        .expect("No tree snapshot — state should have one after init");

    let steps = extract_input_steps(
        &state.changelog,
        &state.change_responses,
        start_idx,
        tree_snapshot,
    )
    .expect("extract_input_steps failed");

    let tracer_proof = create_trace(tree_snapshot, &steps);
    let tracer_proof_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);
    let _quiet = std::env::var_os("FF_BENCH_SHOW_STDERR")
        .is_none()
        .then(SuppressStderr::new);
    let t0 = Instant::now();
    let (proof, stats) = prove_ff_chunk(
        state.ff_proof.as_ref(),
        &state.changelog,
        &state.change_responses,
        start_idx,
        tracer_proof_bytes,
    );
    let elapsed = t0.elapsed();
    drop(_quiet);

    state.changelog.set_ff_proof(proof.serialize(), num_changes);
    state.ff_proof = FFProof::deserialize(&state.changelog.ff_proof).ok();

    ProveResult {
        cycles: stats.user_cycles,
        paging_cycles: stats.paging_cycles,
        total_cycles: stats.total_cycles,
        reserved_cycles: stats.reserved_cycles,
        segments: stats.segments,
        elapsed,
    }
}

/// Prove all pending changes with the timing-instrumented bench guest.
///
/// This advances `proven_up_to` so later benchmark proofs extend the same
/// logical chain, but deliberately leaves `changelog.ff_proof` empty. The
/// bench guest commits `FastForwardJournal`, while production SDK verification
/// expects `FastForwardRange`; exposing a bench receipt through normal
/// fast-forward responses would make clients reject it. The private
/// `BenchProofChain` carries the bench receipt for recursive extension.
pub async fn prove_pending_changes_bench(
    state: &Arc<Mutex<SpaceState>>,
    bench_chain: &mut BenchProofChain,
) -> BenchProveResult {
    let mut state = state.lock().await;
    let start_idx = state.changelog.proven_up_to;
    let num_changes = state.changelog.num_changes() as usize;
    if start_idx >= num_changes {
        return BenchProveResult {
            cycles: 0,
            journal: None,
            witness: None,
            elapsed: Duration::ZERO,
        };
    }

    let tree_snapshot = state
        .tree_snapshot
        .as_ref()
        .expect("No tree snapshot — state should have one after init");

    let steps = extract_input_steps(
        &state.changelog,
        &state.change_responses,
        start_idx,
        tree_snapshot,
    )
    .expect("extract_input_steps failed");

    let tracer_proof = create_trace(tree_snapshot, &steps);
    let witness = BenchWitnessStats {
        serialized_bytes: 0,
        tree: tracer_proof.pruned_tree.stats(),
    };
    let tracer_proof_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);
    let witness = BenchWitnessStats {
        serialized_bytes: tracer_proof_bytes.len(),
        ..witness
    };
    let is_first = bench_chain.proof.is_none();

    let tail_changelog = state.changelog.get_tail(start_idx);
    let tail_responses = state.change_responses[start_idx..].to_vec();
    let end_idx = tail_changelog.num_changes() as usize;

    let start_clc_state = match bench_chain.proof.as_ref() {
        Some(previous_proof) => {
            assert_eq!(
                start_idx as u32, previous_proof.io.end_change_id,
                "bench extension start index must match previous proof end"
            );
            previous_proof.io.end_clc_state.clone()
        }
        None => {
            assert_eq!(
                start_idx, 0,
                "bench proof chain is missing proof for already-proven changes"
            );
            state.changelog.initial_clc_state()
        }
    };
    let end_clc_state = state.changelog.current_clc_state();
    let start_dc = tail_responses[0].old_root;
    let end_dc = tail_responses[end_idx - 1].new_root;

    let (entry_ends, entries_flat) = flatten_entry_bytes_from_changes(&tail_changelog.changes);

    let range = bench_fast_forward_range(
        end_idx as u32,
        start_clc_state,
        end_clc_state,
        start_dc.into(),
        end_dc.into(),
    );
    let range_bytes = postcard::to_allocvec(&range).expect("Failed to serialize range");

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

    let bench_env = if is_first {
        let mut builder = ExecutorEnv::builder();
        builder.write(&is_first).expect("write is_first failed");
        write_flat_entries!(builder);
        builder
            .write(&range_bytes.len())
            .expect("write range_bytes.len() failed")
            .write_slice(&range_bytes)
            .write(&tracer_proof_bytes.len())
            .expect("write pruned tree len failed")
            .write_slice(&tracer_proof_bytes);
        builder.build().unwrap()
    } else {
        let previous_proof = bench_chain.proof.as_ref().unwrap();
        let previous_journal: FastForwardJournal = previous_proof.receipt.journal.decode().unwrap();
        let previous_journal_bytes =
            postcard::to_allocvec(&previous_journal).expect("Failed to serialize previous journal");

        let mut builder = ExecutorEnv::builder();
        builder
            .write(&is_first)
            .expect("write is_first failed")
            .write(&previous_journal_bytes.len())
            .expect("write previous_journal_bytes.len() failed")
            .write_slice(&previous_journal_bytes)
            .write_slice(&EXTEND_FF_BENCH_ID)
            .add_assumption(previous_proof.receipt.clone());
        write_flat_entries!(builder);
        builder
            .write(&range_bytes.len())
            .expect("write range_bytes.len() failed")
            .write_slice(&range_bytes)
            .write(&tracer_proof_bytes.len())
            .expect("write pruned tree len failed")
            .write_slice(&tracer_proof_bytes);
        builder.build().unwrap()
    };

    let _quiet = std::env::var_os("FF_BENCH_SHOW_STDERR")
        .is_none()
        .then(SuppressStderr::new);
    let prover = default_prover();
    let t0 = Instant::now();
    let bench_info = prover.prove(bench_env, EXTEND_FF_BENCH_ELF).unwrap();
    let elapsed = t0.elapsed();
    drop(_quiet);

    let bench_receipt = bench_info.receipt;
    let bench_stats = bench_info.stats;
    assert!(
        bench_receipt.verify(EXTEND_FF_BENCH_ID).is_ok(),
        "bench receipt verification failed"
    );
    let journal: FastForwardJournal = bench_receipt.journal.decode().unwrap();

    bench_chain.proof = Some(FFProof {
        io: journal.output.clone(),
        receipt: bench_receipt,
    });

    state.changelog.set_ff_proof(Vec::new(), num_changes);
    state.ff_proof = None;

    BenchProveResult {
        cycles: bench_stats.user_cycles,
        journal: Some(journal),
        witness: Some(witness),
        elapsed,
    }
}

pub fn print_bench_timing(label: &str, result: &BenchProveResult) {
    let Some(journal) = result.journal.as_ref() else {
        return;
    };
    let t = &journal.loop_timings;
    let measured_total = journal.guest_deserialize_cycles
        + journal.guest_recursive_verify_cycles
        + t.value_cache_check_cycles
        + t.pruned_tree_cycles
        + t.entry_decode_cycles
        + t.sigref_parent_cycles
        + t.extract_validate_cycles
        + t.write_prepare_cycles
        + t.overlay_apply_cycles
        + t.final_replay_cycles;

    macro_rules! line {
        ($indent:expr, $name:literal, $value:expr) => {
            eprintln!("{:indent$}{}: {}", "", $name, $value, indent = $indent);
        };
    }

    eprintln!("  [{label}] timing:");
    if let Some(witness) = result.witness.as_ref() {
        eprintln!("    witness:");
        line!(6, "serialized_bytes", witness.serialized_bytes);
        line!(6, "full_nodes", witness.tree.full_nodes);
        line!(6, "pruned_nodes", witness.tree.pruned_nodes);
        line!(6, "empty_slots", witness.tree.empty_slots);
        line!(6, "full_key_bytes", witness.tree.full_key_bytes);
        line!(6, "full_value_bytes", witness.tree.full_value_bytes);
        line!(6, "pruned_key_bytes", witness.tree.pruned_key_bytes);
        line!(6, "max_depth", witness.tree.max_depth);
    }
    eprintln!("    guest_cycles:");
    line!(6, "user_total", result.cycles);
    line!(6, "measured_total", measured_total);
    line!(
        6,
        "unmeasured",
        result.cycles.saturating_sub(measured_total)
    );
    line!(6, "deserialize", journal.guest_deserialize_cycles);
    line!(6, "recursive_verify", journal.guest_recursive_verify_cycles);
    line!(6, "value_cache", t.value_cache_check_cycles);
    eprintln!("      pruned_tree:");
    line!(8, "total", t.pruned_tree_cycles);
    line!(8, "decode_to_merk", t.pruned_tree_decode_cycles);
    line!(8, "rebuild_merk", t.pruned_tree_rebuild_cycles);
    line!(8, "commit", t.pruned_tree_commit_cycles);
    line!(8, "root_check", t.pruned_tree_root_check_cycles);
    line!(6, "entry_decode", t.entry_decode_cycles);
    line!(6, "sigref_parent", t.sigref_parent_cycles);
    eprintln!("      extract_validate:");
    line!(8, "total", t.extract_validate_cycles);
    eprintln!("        reader_read:");
    line!(10, "cycles", t.reader_read_cycles);
    line!(10, "ops", t.reader_read_ops);
    line!(10, "key_ops", t.reader_read_key_ops);
    line!(10, "range_ops", t.reader_read_range_ops);
    line!(10, "prefix_ops", t.reader_read_prefix_ops);
    line!(6, "write_prepare", t.write_prepare_cycles);
    line!(6, "overlay_apply", t.overlay_apply_cycles);
    line!(6, "final_replay", t.final_replay_cycles);
}

/// Pull the most recent FF receipt out of the state (set by
/// `prove_pending_changes`). Useful when you want to bench Groth16
/// compression separately from proof generation.
pub async fn last_receipt(state: &Arc<Mutex<SpaceState>>) -> Receipt {
    state
        .lock()
        .await
        .ff_proof
        .as_ref()
        .expect("no FF proof on state — call prove_pending_changes first")
        .receipt
        .clone()
}

/// Compress a Risc0 succinct receipt to a Groth16 SNARK and return the
/// wall-clock time + resulting seal size in bytes. This is the marginal
/// cost of producing a constant-size on-chain proof from the inner STARK
/// receipt; it should be essentially independent of the inner workload.
pub fn compress_to_groth16(receipt: &Receipt) -> (Duration, usize) {
    let _quiet = SuppressStderr::new();
    let opts = ProverOpts::groth16();
    let prover = default_prover();
    let t0 = Instant::now();
    let compressed = prover
        .compress(&opts, receipt)
        .expect("groth16 compress failed");
    let elapsed = t0.elapsed();
    (elapsed, compressed.seal_size())
}

// ─── Workload preparation ────────────────────────────────────────────────────

/// Fresh `SpaceState` + a `Space` wired to it via `SharedStateTransport`.
pub async fn init_state_and_space() -> (Arc<Mutex<SpaceState>>, Space) {
    let schemas = app_schemas();
    let init_cfg = SpaceInitConfig {
        space_id: SpaceId::from([7u8; 16]),
        artifact_path: None,
        verbose_logfile: None,
        bootstrap_data: BootstrapDataSource::None,
    };
    let state = SpaceState::init_server(Some(&schemas), Some(init_cfg), Some(1_000_000_000))
        .await
        .expect("init_server");
    let state = Arc::new(Mutex::new(state));
    let app_root = state.lock().await.db.root_hash();
    let app_schema = ApplicationSchema::for_testing(schemas, app_root);
    let space = Space::create(SharedStateTransport::new(Arc::clone(&state)), app_schema)
        .await
        .expect("Space::create");
    (state, space)
}

/// Apply the "table workload" — exactly 100 changes:
/// create_space (1) + invite_user × 2 (2) + 25 inserts + 12 updates + 10 deletes
/// + remove_user (1) + 25 inserts + 14 updates + 10 deletes. Returns count.
///
/// Mirrors `run_realistic_sequence(label, use_lists=false, ...)` in
/// `ff_cycle_benchmarks.rs`.
///
/// ~25% of product `name` writes (every 4th, by row index) are long
/// (~50 bytes) so the encoded value exceeds `VALUE_HASH_THRESHOLD = 32`
/// and is stored as `Op::PutHash` rather than `Op::Put`.  This exercises
/// merk's `Node::with_value_hash` path.
fn product_name(prefix: &str, i: usize) -> String {
    if i.is_multiple_of(4) {
        // ~50-byte name → postcard-encoded value exceeds 32 bytes,
        // forcing the changelog encoder to emit `BatchOp::PutHash`.
        format!("{prefix}-{i}-long-name-padding-xxxxxxxxxxxxxxxxxxxxxxxxx")
    } else {
        format!("{prefix}-{i}")
    }
}

/// Same pattern as [`product_name`], used for task titles in the list
/// workload so ~25% of writes exceed `VALUE_HASH_THRESHOLD = 32`.
fn task_title(prefix: &str, i: usize) -> String {
    if i.is_multiple_of(4) {
        format!("{prefix}-{i}-long-title-padding-xxxxxxxxxxxxxxxxxxxxxxxx")
    } else {
        format!("{prefix}-{i}")
    }
}

pub async fn apply_table_sequence(space: &Space) -> usize {
    let _invite1 = space.invite_user().await.expect("invite_user 1");
    let invite2 = space.invite_user().await.expect("invite_user 2");
    let remove_target = invite2.id().expect("invite2 uid");

    let mut count: usize = 3; // create_space + 2 invites

    let products = space.table::<ProductRow>("products");

    // First seed 25 inserts so we have rows to update/delete
    let mut row_ids: Vec<i64> = Vec::with_capacity(50);
    for i in 0..25 {
        let id = products
            .insert(&ProductRow {
                id: None,
                name: product_name("seq", i),
                price: i as f64,
            })
            .execute()
            .await
            .expect("ins exec");
        row_ids.push(id);
        count += 1;
    }
    // 12 updates
    for (i, &row_id) in row_ids.iter().enumerate().take(12) {
        products
            .update()
            .set("name", product_name("seq-upd", i))
            .where_eq("id", row_id)
            .execute()
            .await
            .expect("upd");
        count += 1;
    }
    // 10 deletes (from the seeded rows)
    for &id in row_ids[14..24].iter().rev() {
        products
            .delete()
            .where_eq("id", id)
            .execute()
            .await
            .expect("del");
        count += 1;
    }
    // remove_user
    space.remove_user(remove_target).await.expect("remove_user");
    count += 1;
    // 25 more inserts
    let mut more_ids: Vec<i64> = Vec::with_capacity(25);
    for i in 0..25 {
        let id = products
            .insert(&ProductRow {
                id: None,
                name: product_name("seq2", i),
                price: i as f64,
            })
            .execute()
            .await
            .expect("ins2 exec");
        more_ids.push(id);
        count += 1;
    }
    // 14 updates: target earlier surviving rows + new rows
    for i in 0..14 {
        let id = if i < 12 { row_ids[i] } else { more_ids[i - 12] };
        products
            .update()
            .set("price", (i as f64) * 3.0)
            .where_eq("id", id)
            .execute()
            .await
            .expect("upd2");
        count += 1;
    }
    // 10 deletes from new rows
    for &id in more_ids[15..25].iter().rev() {
        products
            .delete()
            .where_eq("id", id)
            .execute()
            .await
            .expect("del2");
        count += 1;
    }

    count
}

/// Apply the "list workload" — exactly 100 changes:
/// create_space (1) + invite_user × 2 (2) + project insert (1)
/// + 20 append + 8 insert_after + 10 update + 8 delete
/// + remove_user (1) + 20 append + 11 insert_after + 10 update + 8 delete.
///
/// Mirrors `run_realistic_sequence(label, use_lists=true, ...)`.
pub async fn apply_list_sequence(space: &Space) -> usize {
    let _invite1 = space.invite_user().await.expect("invite_user 1");
    let invite2 = space.invite_user().await.expect("invite_user 2");
    let remove_target = invite2.id().expect("invite2 uid");

    let mut count: usize = 3;

    let projects = space.table::<ProjectRow>("projects");
    let project_id = projects
        .insert(&ProjectRow {
            id: None,
            name: "ListProj".to_string(),
            tasks: List::empty(),
        })
        .execute()
        .await
        .expect("proj ins exec");
    count += 1;

    let tasks: ListAlias<TaskRow> = space.list("projects", project_id, "tasks");

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(50);
    for i in 0..20 {
        let k = tasks
            .append(&TaskRow {
                title: task_title("t", i),
                done: false,
            })
            .await
            .expect("append");
        keys.push(k);
        count += 1;
    }
    for i in 0..8 {
        let k = tasks
            .insert_after_key(
                &keys[i * 2],
                &TaskRow {
                    title: task_title("ins", i),
                    done: false,
                },
            )
            .await
            .expect("ins_after");
        keys.push(k);
        count += 1;
    }
    for (i, key) in keys.iter().take(10).enumerate() {
        tasks
            .update_by_key(
                key,
                &TaskRow {
                    title: task_title("upd", i),
                    done: true,
                },
            )
            .await
            .expect("upd");
        count += 1;
    }
    for i in 0..8 {
        let k = keys[20 + (7 - i)].clone();
        tasks.delete_by_key(&k).await.expect("del");
        count += 1;
    }
    space.remove_user(remove_target).await.expect("remove_user");
    count += 1;

    let mut keys2: Vec<Vec<u8>> = Vec::with_capacity(40);
    for i in 0..20 {
        let k = tasks
            .append(&TaskRow {
                title: task_title("t2", i),
                done: false,
            })
            .await
            .expect("append2");
        keys2.push(k);
        count += 1;
    }
    for i in 0..11 {
        let k = tasks
            .insert_after_key(
                &keys2[i],
                &TaskRow {
                    title: task_title("ins2", i),
                    done: false,
                },
            )
            .await
            .expect("ins_after2");
        keys2.push(k);
        count += 1;
    }
    for (i, key) in keys2.iter().take(10).enumerate() {
        tasks
            .update_by_key(
                key,
                &TaskRow {
                    title: task_title("upd2", i),
                    done: true,
                },
            )
            .await
            .expect("upd2");
        count += 1;
    }
    for i in 0..8 {
        let k = keys2[20 + (7 - i)].clone();
        tasks.delete_by_key(&k).await.expect("del2");
        count += 1;
    }

    count
}

// ─── Workload registry ───────────────────────────────────────────────────────
//
// A "workload" is just a function that builds a fresh state + space,
// submits some pending changes, and returns `(state, n_changes)`.  The
// caller then proves once against the state.  All workloads use the
// same shape so different bench harnesses (ff_profile, future
// bulk-cycle benches, …) can iterate the same list without per-name
// dispatch.
//
// A workload may declare a `pre_pop` row count.  When > 0 the harness
// applies a bulk-load of that many extra rows directly into the merk
// tree (via [`prepopulate_products_fast`] / [`prepopulate_parents_fast`]),
// then **rebases the changelog to a fresh genesis** so the measured
// prove starts from a pre-populated tree rather than an empty one.
// `CreateSpace` is wiped from the changelog as part of the rebase, so
// the workload's effective change count is one less than its "empty
// tree" count.

use std::future::Future;
use std::pin::Pin;

pub type WorkloadFuture = Pin<Box<dyn Future<Output = (Arc<Mutex<SpaceState>>, usize)> + Send>>;
pub type WorkloadFn = fn(pre_pop: usize) -> WorkloadFuture;

pub struct Workload {
    pub name: &'static str,
    pub run: WorkloadFn,
    /// Number of extra rows to bulk-load into the relevant table before
    /// the workload submits its measured changes.  0 = no pre-pop, empty
    /// tree when measurement starts.
    pub pre_pop: usize,
}

// ─── Fast bulk pre-population ────────────────────────────────────────────────
//
// Modelled on the fixture in `ff_cycle_benchmarks::build_cycle_fixture`.
// Writes rows directly to merk in one batch (bypassing the changelog /
// SDK / schema indices / id counter), then resets `SpaceState.changelog`
// to a fresh genesis pointing at the new root and patches the SDK
// `Space` snapshot so `current_change_id = 0`, `current_data_commitment
// = new_root`, etc.  Returns a freshly-restored `Space` ready to submit
// measured changes against the pre-populated tree.
//
// CAVEATS:
//  - Bulk-loaded rows are *invisible to SDK queries that go through
//    schema indices* (id counter / plaintext-PK / secondary indices),
//    because those metadata entries are not written.  They contribute
//    tree depth only.
//  - SDK-driven inserts after pre-pop will assign ids starting at 1,
//    silently overwriting bulk rows 1..=k where k is the number of SDK
//    inserts.  The remaining (n − k) bulk rows still deepen the tree.
//  - `CreateSpace` is removed from the changelog by the rebase, so
//    workload `count` values that include `+ 1` for it should subtract
//    1 when `pre_pop > 0`.

async fn fast_apply_and_rebase(
    state: &Arc<Mutex<SpaceState>>,
    space: Space,
    mut batch: Vec<(Vec<u8>, merk::Op)>,
) -> Space {
    let new_root = {
        let mut s = state.lock().await;
        batch.sort_by(|a, b| a.0.cmp(&b.0));
        s.db.merk.apply_batch(&batch).expect("merk apply_batch");
        let current_root = s.get_root_hash().await;
        s.changelog = ChangeLog::new(&current_root);
        s.change_responses.clear();
        s.ff_proof = None;
        s.tree_snapshot = s.db.snapshot();
        // Mirror `reinitialize_changelog`: clear the per-user sigref view
        // alongside the changelog reset so the next SDK change (sig_ref=0)
        // is accepted against a fresh genesis chain.
        s.sigref_map.clear();
        current_root
    };

    let mut snapshot = space.snapshot().await.expect("space snapshot");
    let state_obj = snapshot
        .get_mut("state")
        .and_then(serde_json::Value::as_object_mut)
        .expect("snapshot.state must be an object");
    state_obj.insert(
        "current_data_commitment".to_string(),
        serde_json::to_value(new_root).unwrap(),
    );
    state_obj.insert(
        "initial_dc".to_string(),
        serde_json::to_value(new_root).unwrap(),
    );
    state_obj.insert("current_change_id".to_string(), serde_json::json!(0u32));
    state_obj.insert("my_last_change_id".to_string(), serde_json::json!(0u32));
    // The fast-batch prepopulation rewinds the changelog to genesis, so
    // the client's per-user sigref view (advanced by the CreateSpace
    // above) is stale. Clear it so the first post-restore signed change
    // (sig_ref=0) passes `check_sigref_continuity` on both client and
    // server (issue #30).
    state_obj.insert(
        "sigref_map".to_string(),
        serde_json::json!(serde_json::Map::new()),
    );
    state_obj.insert(
        "key_valid_from_change_id".to_string(),
        serde_json::json!(0u32),
    );
    state_obj.insert(
        "current_clc_state".to_string(),
        serde_json::to_value(initial_clc_state(&new_root)).unwrap(),
    );

    Space::restore(SharedStateTransport::new(Arc::clone(state)), snapshot)
        .await
        .expect("Space::restore after fast pre-pop")
}

/// Bulk-load `n` synthetic rows into the `products` table.
/// Use after `init_state_and_space()` for table/list workloads.
pub async fn prepopulate_products_fast(
    state: &Arc<Mutex<SpaceState>>,
    space: Space,
    n: usize,
) -> Space {
    eprintln!("[ff_common] fast pre-pop: {n} products");
    let mut batch: Vec<(Vec<u8>, merk::Op)> = Vec::with_capacity(n * 2);
    for i in 0..n {
        let row_id = (i + 1) as i64;
        let name = stored_value::value_to_bytes(&serde_json::json!(format!("BulkProduct{i}")))
            .expect("encode name");
        let price =
            stored_value::value_to_bytes(&serde_json::json!(i as f64)).expect("encode price");
        batch.push((column_key("products", row_id, "name"), merk::Op::Put(name)));
        batch.push((
            column_key("products", row_id, "price"),
            merk::Op::Put(price),
        ));
    }
    fast_apply_and_rebase(state, space, batch).await
}

/// Bulk-load `n` synthetic rows into the `parents` table.
/// Use after `actions::init_action_state_and_space()` for action workloads.
pub async fn prepopulate_parents_fast(
    state: &Arc<Mutex<SpaceState>>,
    space: Space,
    n: usize,
) -> Space {
    eprintln!("[ff_common] fast pre-pop: {n} parents");
    let mut batch: Vec<(Vec<u8>, merk::Op)> = Vec::with_capacity(n * 3);
    for i in 0..n {
        let row_id = (i + 1) as i64;
        let name = stored_value::value_to_bytes(&serde_json::json!(format!("BulkParent{i}")))
            .expect("encode name");
        let category =
            stored_value::value_to_bytes(&serde_json::json!("bulk")).expect("encode category");
        let value =
            stored_value::value_to_bytes(&serde_json::json!(i as i64)).expect("encode value");
        batch.push((column_key("parents", row_id, "name"), merk::Op::Put(name)));
        batch.push((
            column_key("parents", row_id, "category"),
            merk::Op::Put(category),
        ));
        batch.push((column_key("parents", row_id, "value"), merk::Op::Put(value)));
    }
    fast_apply_and_rebase(state, space, batch).await
}

/// Wrapper for the existing table workload — fits the registry shape.
pub async fn run_table(pre_pop: usize) -> (Arc<Mutex<SpaceState>>, usize) {
    let (state, space) = init_state_and_space().await;
    let space = if pre_pop > 0 {
        prepopulate_products_fast(&state, space, pre_pop).await
    } else {
        space
    };
    let n = apply_table_sequence(&space).await;
    // The rebase wipes CreateSpace from the changelog; subtract it from
    // the count reported by `apply_table_sequence`.
    let adjusted = if pre_pop > 0 { n.saturating_sub(1) } else { n };
    (state, adjusted)
}

/// Wrapper for the existing list workload — fits the registry shape.
pub async fn run_list(pre_pop: usize) -> (Arc<Mutex<SpaceState>>, usize) {
    let (state, space) = init_state_and_space().await;
    let space = if pre_pop > 0 {
        prepopulate_products_fast(&state, space, pre_pop).await
    } else {
        space
    };
    let n = apply_list_sequence(&space).await;
    let adjusted = if pre_pop > 0 { n.saturating_sub(1) } else { n };
    (state, adjusted)
}

fn box_table(pp: usize) -> WorkloadFuture {
    Box::pin(run_table(pp))
}
fn box_list(pp: usize) -> WorkloadFuture {
    Box::pin(run_list(pp))
}
fn box_pure_insert(pp: usize) -> WorkloadFuture {
    Box::pin(actions::run_pure_insert(pp))
}
fn box_exists_insert(pp: usize) -> WorkloadFuture {
    Box::pin(actions::run_exists_insert(pp))
}
fn box_cascade_delete(pp: usize) -> WorkloadFuture {
    Box::pin(actions::run_cascade_delete(pp))
}
fn box_unchanged_update(pp: usize) -> WorkloadFuture {
    Box::pin(actions::run_unchanged_update(pp))
}

pub const WORKLOADS: &[Workload] = &[
    Workload {
        name: "table",
        run: box_table,
        pre_pop: 100_000,
    },
    Workload {
        name: "list",
        run: box_list,
        pre_pop: 100_000,
    },
    Workload {
        name: "pure_insert",
        run: box_pure_insert,
        pre_pop: 0,
    },
    Workload {
        name: "exists_insert",
        run: box_exists_insert,
        pre_pop: 0,
    },
    Workload {
        name: "cascade_delete",
        run: box_cascade_delete,
        pre_pop: 0,
    },
    Workload {
        name: "unchanged_update",
        run: box_unchanged_update,
        pre_pop: 0,
    },
];

pub fn lookup_workload(name: &str) -> Option<&'static Workload> {
    WORKLOADS.iter().find(|w| w.name == name)
}
