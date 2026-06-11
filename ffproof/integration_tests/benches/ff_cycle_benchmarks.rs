//! Benchmarks measuring RISC0 ZKVM user cycles for FF proof generation.
//!
//! These benchmarks mirror the integration tests, but use a custom Criterion
//! measurement type that reports RISC0 user cycles instead of wall-clock time.
//!
//! Run with:
//!   cargo bench -p encrypted-spaces-ff-test
//!
//! Note: These benchmarks require RISC0_DEV_MODE=1 to run quickly.
//! Without it, real proof generation is very slow.

use criterion::{
    criterion_group, criterion_main,
    measurement::{Measurement, ValueFormatter},
    Criterion, Throughput,
};
use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::error::{Result as BackendResult, SdkError};
use encrypted_spaces_backend::merk_storage::proofs::{
    verify_query_proof_with_hashed_values, VerifiedRows,
};
use encrypted_spaces_backend::merk_storage::{
    build_column_kv_vecs, column_key, column_key_placeholder, get_row_data_from_query, parse_key,
    stored_value, ParsedKey,
};
use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_backend_server::app_config::{BootstrapDataSource, SpaceInitConfig};
use encrypted_spaces_backend_server::SpaceState;
use encrypted_spaces_changelog_core::changelog::{
    initial_clc_state, ChangeLog, ChangeResponse, ChangelogEntry, FastForwardData,
    FastForwardJournal, FastForwardRange, LogMessage,
};
use encrypted_spaces_changelog_core::changelog::{Change, OpType, ROOT_TREE_PATH};
use encrypted_spaces_changelog_core::{create_trace, encode_pruned_compact};
use encrypted_spaces_changelog_test_utils::{init_test_server_state, sign_test_change};
use encrypted_spaces_ffproof::common::FFProof;
use encrypted_spaces_ffproof::prover::{extract_input_steps, prove_ff_chunk};
use encrypted_spaces_ffproof_methods_bench::{EXTEND_FF_BENCH_ELF, EXTEND_FF_BENCH_ID};
use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest, SimpleKeyId};
use encrypted_spaces_sdk::local_transport::LocalTransport;
use encrypted_spaces_sdk::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
use encrypted_spaces_sdk::transport::{EphemeralReceiver, Transport};
use encrypted_spaces_sdk::Space;
use encrypted_spaces_sdk::{List, List as ListAlias};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::any::Any;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

const USERS_TABLE: &str = "_users";
const KEY_HISTORY_TABLE: &str = "_key_history";

// ─── Custom Criterion Measurement: RISC0 User Cycles ─────────────────────────

/// A Criterion measurement that reports RISC0 ZKVM user cycles.
///
/// Since cycle counts are obtained *after* proving (not via start/stop timers),
/// benchmarks use `iter_custom` and return the cycle count directly.
///
/// **Caching strategy:** RISC0 cycle counts are perfectly deterministic — the
/// same guest program with the same inputs always produces the exact same
/// number of user cycles.  Criterion, however, requires a minimum of 10
/// samples and has a warm-up phase, all of which would re-run the (expensive)
/// prover for identical results.  To avoid this, each benchmark keeps a
/// `cached: Option<u64>` that is populated on the first invocation via
/// `get_or_insert_with` and replayed as `cached_value * iters` on all
/// subsequent calls.  This makes warm-up and extra samples essentially free
/// while still producing correct, stable output from Criterion.
struct ZkvmCycles;

struct CyclesFormatter;

impl ValueFormatter for CyclesFormatter {
    fn format_value(&self, value: f64) -> String {
        if value >= 1_000_000.0 {
            format!("{:.2}M cycles", value / 1_000_000.0)
        } else if value >= 1_000.0 {
            format!("{:.2}K cycles", value / 1_000.0)
        } else {
            format!("{:.0} cycles", value)
        }
    }

    fn format_throughput(&self, throughput: &Throughput, value: f64) -> String {
        match throughput {
            Throughput::Elements(n) => {
                let per_elem = value / *n as f64;
                if per_elem >= 1_000_000.0 {
                    format!("{:.2}M cycles/elem", per_elem / 1_000_000.0)
                } else if per_elem >= 1_000.0 {
                    format!("{:.2}K cycles/elem", per_elem / 1_000.0)
                } else {
                    format!("{:.0} cycles/elem", per_elem)
                }
            }
            Throughput::Bytes(n) | Throughput::BytesDecimal(n) => {
                let per_byte = value / *n as f64;
                format!("{:.2} cycles/byte", per_byte)
            }
        }
    }

    fn scale_values(&self, _typical_value: f64, _values: &mut [f64]) -> &'static str {
        "cycles"
    }

    fn scale_throughputs(
        &self,
        _typical_value: f64,
        _throughput: &Throughput,
        _values: &mut [f64],
    ) -> &'static str {
        "cycles/elem"
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "cycles"
    }
}

impl Measurement for ZkvmCycles {
    type Intermediate = ();
    type Value = u64;

    fn start(&self) -> Self::Intermediate {}
    fn end(&self, _i: Self::Intermediate) -> Self::Value {
        0
    }
    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        v1 + v2
    }
    fn zero(&self) -> Self::Value {
        0
    }
    fn to_f64(&self, value: &Self::Value) -> f64 {
        *value as f64
    }
    fn formatter(&self) -> &dyn ValueFormatter {
        &CyclesFormatter
    }
}

// ─── Stderr suppression ──────────────────────────────────────────────────────

/// Suppress stderr to hide risc0 dev-mode warnings and R0VM guest log lines.
/// Returns a guard that restores stderr on drop.
struct SuppressStderr {
    saved_fd: i32,
}

impl SuppressStderr {
    fn new() -> Self {
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

// ─── Server Wrapper ──────────────────────────────────────────────────────────

/// Server that accumulates changes without auto-proving.
/// Benchmarks call the prover directly after accumulating changes.
struct Server {
    pub state: Mutex<SpaceState>,
    pub initial_dc: [u8; 32],
}

impl Server {
    /// Create a server that never auto-proves (batch_size large enough to never trigger, small enough to avoid overflow).
    pub async fn new() -> Self {
        let state = init_test_server_state(Some(1_000_000_000), &[1, 2]).await;
        let initial_dc = state.get_root_hash().await;
        Self {
            state: Mutex::new(state),
            initial_dc,
        }
    }

    pub async fn create_client(&self) -> Space {
        let transport = LocalTransport::in_memory().await.unwrap();
        Space::new_without_schema_init(transport, self.initial_dc)
            .await
            .expect("Failed to create Space")
    }

    /// Invoke the FF prover on accumulated changes and return RISC0 user cycles.
    pub async fn prove_and_get_cycles(&self) -> u64 {
        let mut state = self.state.lock().await;
        let tree_snapshot = state
            .tree_snapshot
            .as_ref()
            .expect("No tree snapshot — server should have one after init");
        let start_idx = state.changelog.proven_up_to;

        let t0 = std::time::Instant::now();
        let steps = extract_input_steps(
            &state.changelog,
            &state.change_responses,
            start_idx,
            tree_snapshot,
        )
        .expect("extract_input_steps failed");
        eprintln!("  [prove] extract_input_steps in {:.2?}", t0.elapsed());

        let t1 = std::time::Instant::now();
        let tracer_proof = create_trace(tree_snapshot, &steps);
        eprintln!("  [prove] create_trace in {:.2?}", t1.elapsed());

        let t2 = std::time::Instant::now();
        let tracer_proof_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);
        eprintln!(
            "  [prove] serialize pruned_tree ({} bytes) in {:.2?}",
            tracer_proof_bytes.len(),
            t2.elapsed()
        );
        let t3 = std::time::Instant::now();
        let _quiet = SuppressStderr::new();
        let (proof, stats) = prove_ff_chunk(
            state.ff_proof.as_ref(),
            &state.changelog,
            &state.change_responses,
            start_idx,
            tracer_proof_bytes,
        );
        drop(_quiet);
        eprintln!(
            "  [prove] prove_ff in {:.2?} ({} user_cycles)",
            t3.elapsed(),
            stats.user_cycles
        );

        let new_proven_up_to = state.changelog.num_changes() as usize;
        state
            .changelog
            .set_ff_proof(proof.serialize(), new_proven_up_to);

        // Update ff_proof so the next prove can extend it.
        // Don't touch tree_snapshot — handle_change takes a fresh one
        // at the start of each new batch (when num_changes == proven_up_to).
        state.ff_proof = FFProof::deserialize(&state.changelog.ff_proof).ok();

        stats.user_cycles
    }
}

// ─── Benchmark Parameters ────────────────────────────────────────────────────

/// Number of rows to pre-populate before benchmarking operations.
const PREPOPULATE_ROWS: usize = 100_000;
/// Number of operations per proving batch in per-operation benchmarks.
const OPS_PER_BATCH: usize = 100;

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn insert_products(server: &Server, client: &Space, auth: &AuthContext, count: usize) {
    let t0 = std::time::Instant::now();
    for i in 0..count {
        let query = Query::new(
            "products".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(0)),
                ("name".to_string(), QueryParam::Text(format!("Product{i}"))),
                ("price".to_string(), QueryParam::Real(i as f64)),
            ]),
        );
        let (_, column_data) = get_row_data_from_query(&query).unwrap();
        let (col_keys, col_values) =
            build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
        let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
        let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();
        let mut change = Change::new(
            OpType::Insert,
            client.uid().unwrap(),
            ROOT_TREE_PATH,
            &key_refs,
            &val_refs,
            client.current_change_id(),
            client.my_last_change_id(),
            client.current_clc(),
        )
        .unwrap();
        sign_test_change(client.uid().unwrap(), &mut change);
        let t_hc = std::time::Instant::now();
        let response = server
            .state
            .lock()
            .await
            .handle_change(&change, auth)
            .await
            .unwrap();
        let t_hc_elapsed = t_hc.elapsed();
        client
            .validate_and_apply_change(&change.entry, &response)
            .unwrap();
        if (i + 1).is_multiple_of(20) || i + 1 == count {
            eprintln!(
                "  [setup: insert_products] {}/{} total={:.2?} (each handle_change={:.2?})",
                i + 1,
                count,
                t0.elapsed(),
                t_hc_elapsed
            );
        }
    }
}

// ─── Benchmarks ──────────────────────────────────────────────────────────────

/// Measures the marginal cost of recursive proof verification.
///
/// Proves two consecutive batches (3 inserts each) and reports only the
/// *difference* in cycle count (second − first). The first proof has no
/// predecessor to verify; the second must verify the first, so the delta
/// isolates the recursive-verification overhead.
fn bench_recursive_verify_cost(c: &mut Criterion<ZkvmCycles>) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut cached: Option<u64> = None;
    c.bench_function("ff_proof/recursive_verify_cost", |b| {
        b.iter_custom(|iters| {
            let cycles = *cached.get_or_insert_with(|| {
                rt.block_on(async {
                    let server = Server::new().await;
                    let client = server.create_client().await;
                    client.authenticate_as_id(1).await.unwrap();
                    let auth = client.get_auth_context();

                    // First batch (no predecessor proof to verify)
                    insert_products(&server, &client, &auth, 3).await;
                    let first = server.prove_and_get_cycles().await;

                    // Second batch (must verify the first proof)
                    insert_products(&server, &client, &auth, 3).await;
                    let second = server.prove_and_get_cycles().await;

                    second.saturating_sub(first)
                })
            });
            cycles * iters
        });
    });
}

// ─── All-op FF cycle fixture (shared DB state) ─────────────────────────────

/// Number of list items to seed before measuring list ops.
const PREPOPULATE_LIST_ITEMS: usize = 32;

#[derive(Debug, Serialize, Deserialize)]
struct ProductRow {
    id: Option<i64>,
    name: String,
    price: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProjectRow {
    id: Option<i64>,
    name: String,
    tasks: List<TaskRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TaskRow {
    title: String,
    done: bool,
}

fn app_schemas() -> Vec<Schema> {
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

struct SharedStateTransport {
    state: Arc<Mutex<SpaceState>>,
    auth_context: Mutex<AuthContext>,
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl SharedStateTransport {
    fn new(state: Arc<Mutex<SpaceState>>) -> Self {
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

// ─── Bench guest prover (Stages 5–6) ────────────────────────────────────────

struct BenchProveResult {
    cycles: u64,
    journal: FastForwardJournal,
}

struct BenchProofChain {
    proof: Option<FFProof>,
}

impl BenchProofChain {
    fn new() -> Self {
        Self { proof: None }
    }
}

async fn prove_pending_changes_bench(
    state: &Arc<Mutex<SpaceState>>,
    bench_chain: &mut BenchProofChain,
) -> BenchProveResult {
    let mut state = state.lock().await;
    let start_idx = state.changelog.proven_up_to;
    let num_changes = state.changelog.num_changes() as usize;
    assert!(start_idx < num_changes, "no pending changes to prove");

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
    let tracer_proof_compact_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);
    let is_first = bench_chain.proof.is_none();

    let tail_changelog = state.changelog.get_tail(start_idx);
    let tail_responses = state.change_responses[start_idx..].to_vec();
    let end_idx = tail_changelog.num_changes() as usize;

    let start_clc_state = match bench_chain.proof.as_ref() {
        Some(p) => p.io.end_clc_state.clone(),
        None => state.changelog.initial_clc_state(),
    };
    let end_clc_state = state.changelog.current_clc_state();
    let start_dc = tail_responses[0].old_root;
    let end_dc = tail_responses[end_idx - 1].new_root;

    let (entry_ends, entries_flat) = flatten_entry_bytes_from_changes(&tail_changelog.changes);

    let range = FastForwardRange {
        end_change_id: end_idx as u32,
        start_clc_state,
        end_clc_state,
        start_dc: start_dc.into(),
        end_dc: end_dc.into(),
        sigref_map: std::collections::BTreeMap::new(),
        recent_roots: Vec::new(),
        timestamp_hwm: bench_chain
            .proof
            .as_ref()
            .map(|proof| proof.io.timestamp_hwm)
            .unwrap_or(0),
    };
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
            .write(&tracer_proof_compact_bytes.len())
            .expect("write pruned tree len failed")
            .write_slice(&tracer_proof_compact_bytes);
        builder.build().unwrap()
    } else {
        let prev = bench_chain.proof.as_ref().unwrap();
        let prev_journal: FastForwardJournal = prev.receipt.journal.decode().unwrap();
        let prev_journal_bytes =
            postcard::to_allocvec(&prev_journal).expect("Failed to serialize previous journal");

        let mut builder = ExecutorEnv::builder();
        builder
            .write(&is_first)
            .expect("write is_first failed")
            .write(&prev_journal_bytes.len())
            .expect("write prev_journal_bytes.len() failed")
            .write_slice(&prev_journal_bytes)
            .write_slice(&EXTEND_FF_BENCH_ID)
            .add_assumption(prev.receipt.clone());
        write_flat_entries!(builder);
        builder
            .write(&range_bytes.len())
            .expect("write range_bytes.len() failed")
            .write_slice(&range_bytes)
            .write(&tracer_proof_compact_bytes.len())
            .expect("write pruned tree len failed")
            .write_slice(&tracer_proof_compact_bytes);
        builder.build().unwrap()
    };

    let _quiet = SuppressStderr::new();
    let prover = default_prover();
    let bench_info = prover.prove(bench_env, EXTEND_FF_BENCH_ELF).unwrap();
    let bench_receipt = bench_info.receipt;
    let bench_stats = bench_info.stats;

    assert!(
        bench_receipt.verify(EXTEND_FF_BENCH_ID).is_ok(),
        "bench receipt verification failed"
    );
    let journal: FastForwardJournal = bench_receipt.journal.decode().unwrap();

    // Store bench proof for chaining (separate from state.ff_proof).
    let bench_io = journal.output.clone();
    bench_chain.proof = Some(FFProof {
        io: bench_io,
        receipt: bench_receipt,
    });

    // Production proof: stored in state for SDK operations (Space::join, etc.).
    let (prod_proof, _prod_stats) = prove_ff_chunk(
        state.ff_proof.as_ref(),
        &state.changelog,
        &state.change_responses,
        start_idx,
        tracer_proof_compact_bytes,
    );
    drop(_quiet);

    state
        .changelog
        .set_ff_proof(prod_proof.serialize(), num_changes);
    state.ff_proof = FFProof::deserialize(&state.changelog.ff_proof).ok();

    BenchProveResult {
        cycles: bench_stats.user_cycles,
        journal,
    }
}

async fn prove_bench_cycles(
    state: &Arc<Mutex<SpaceState>>,
    bench_chain: &mut BenchProofChain,
) -> u64 {
    prove_pending_changes_bench(state, bench_chain).await.cycles
}

fn assert_timed_matches_production(state: &SpaceState, start_idx: usize) {
    use encrypted_spaces_changelog_core::changelog::{
        verify_op_sequence, verify_op_sequence_timed,
    };

    let tree_snapshot = state.tree_snapshot.as_ref().unwrap();
    let steps = extract_input_steps(
        &state.changelog,
        &state.change_responses,
        start_idx,
        tree_snapshot,
    )
    .unwrap();
    let tracer_proof = create_trace(tree_snapshot, &steps);
    let pruned_tree_bytes = postcard::to_allocvec(&tracer_proof.pruned_tree).unwrap();
    let pruned_tree_bench_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);

    let tail = state.changelog.get_tail(start_idx);
    let tail_responses = &state.change_responses[start_idx..];
    let end_idx = tail.num_changes() as usize;
    let range = FastForwardRange {
        end_change_id: end_idx as u32,
        start_clc_state: state.changelog.initial_clc_state(),
        end_clc_state: state.changelog.current_clc_state(),
        start_dc: tail_responses[0].old_root.into(),
        end_dc: tail_responses[end_idx - 1].new_root.into(),
        sigref_map: std::collections::BTreeMap::new(),
        recent_roots: Vec::new(),
        timestamp_hwm: 0,
    };
    let entries: Vec<Vec<u8>> = tail.changes.iter().map(|e| e.as_bytes()).collect();

    let mut sigref_prod = std::collections::BTreeMap::new();
    let mut recent_roots_prod: Vec<(u32, [u8; 32])> = Vec::new();
    let mut timestamp_hwm_prod = 0;
    let result_prod = verify_op_sequence(
        &entries,
        &range,
        &pruned_tree_bytes,
        0,
        &mut sigref_prod,
        &mut recent_roots_prod,
        &mut timestamp_hwm_prod,
    );

    fn zero_cycles() -> u64 {
        0
    }
    let mut sigref_timed = std::collections::BTreeMap::new();
    let mut recent_roots_timed: Vec<(u32, [u8; 32])> = Vec::new();
    let mut timestamp_hwm_timed = 0;
    let (result_timed, _timings) = verify_op_sequence_timed(
        &entries,
        &range,
        &pruned_tree_bench_bytes,
        0,
        &mut sigref_timed,
        &mut recent_roots_timed,
        &mut timestamp_hwm_timed,
        zero_cycles,
    );

    assert!(result_prod, "production verify_op_sequence failed");
    assert!(result_timed, "timed verify_op_sequence failed");
    assert_eq!(sigref_prod, sigref_timed, "sigref maps diverged");
    assert_eq!(
        timestamp_hwm_prod, timestamp_hwm_timed,
        "timestamp HWM diverged"
    );
    assert_eq!(
        recent_roots_prod, recent_roots_timed,
        "recent_roots diverged"
    );
    eprintln!("[parity] verify_op_sequence_timed matches production");
}

fn print_bench_timing(label: &str, result: &BenchProveResult) {
    let t = &result.journal.loop_timings;
    let measured_total = result.journal.guest_deserialize_cycles
        + result.journal.guest_recursive_verify_cycles
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
    eprintln!("    guest_cycles:");
    line!(6, "user_total", result.cycles);
    line!(6, "measured_total", measured_total);
    line!(
        6,
        "unmeasured",
        result.cycles.saturating_sub(measured_total)
    );
    line!(6, "deserialize", result.journal.guest_deserialize_cycles);
    line!(
        6,
        "recursive_verify",
        result.journal.guest_recursive_verify_cycles
    );
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

fn entry_value_for_column<'a>(
    change: &'a ChangelogEntry,
    table_name: &str,
    column_name: &str,
) -> Option<&'a [u8]> {
    change
        .message
        .entries
        .iter()
        .find_map(|entry| match parse_key(&entry.key) {
            Ok(ParsedKey::Column { table, column, .. })
                if table == table_name && column == column_name =>
            {
                Some(entry.value.as_slice())
            }
            _ => None,
        })
}

fn assert_hash_ref_column(
    change: &ChangelogEntry,
    label: &str,
    table_name: &str,
    column_name: &str,
) {
    use encrypted_spaces_storage_encoding::HASH_LEN;

    let value = entry_value_for_column(change, table_name, column_name)
        .unwrap_or_else(|| panic!("{label}: missing {table_name}.{column_name} entry"));
    assert_eq!(
        value.len(),
        HASH_LEN,
        "{label}: {table_name}.{column_name} should be a {}-byte hash reference, got {} bytes",
        HASH_LEN,
        value.len()
    );
}

async fn assert_latest_internal_key_hash_change(
    state: &Arc<Mutex<SpaceState>>,
    expected_op: OpType,
    label: &str,
    expected_hash_columns: &[(&str, &str)],
) {
    let change = {
        let state = state.lock().await;
        state
            .changelog
            .changes
            .last()
            .unwrap_or_else(|| panic!("{label}: no changelog entry recorded"))
            .clone()
    };
    assert_eq!(
        change.message.op_type, expected_op,
        "{label}: expected latest op {:?}, got {:?}",
        expected_op, change.message.op_type
    );
    for (table_name, column_name) in expected_hash_columns {
        assert_hash_ref_column(&change, label, table_name, column_name);
    }
}

#[derive(Clone, Copy)]
enum CycleBenchOp {
    CreateSpace,
    CreateSpaceKeyHash,
    InsertSingle,
    Insert10,
    Insert,
    UpdateSingle,
    Update10,
    Update,
    DeleteSingle,
    Delete10,
    Delete,
    ListAppend,
    ListInsert,
    ListUpdate,
    ListDelete,
    ListAppend10,
    ListAppendBatch,
    ListInsert10,
    ListInsertBatch,
    ListUpdate10,
    ListUpdateBatch,
    ListDelete10,
    ListDeleteBatch,
    InviteUser,
    InviteUserKeyHash,
    RefreshKeys,
    RefreshKeysKeyHash,
    Extend,
    Rekey,
    Reduce,
    RemoveUser,
    RemoveUserKeyHash,
    NoopSingleFirst,
    Noop10First,
    NoopBatchFirst,
    NoopBatchExtend,
}

impl CycleBenchOp {
    const ALL: &'static [CycleBenchOp] = &[
        CycleBenchOp::CreateSpace,
        CycleBenchOp::CreateSpaceKeyHash,
        CycleBenchOp::InsertSingle,
        CycleBenchOp::Insert10,
        CycleBenchOp::Insert,
        CycleBenchOp::UpdateSingle,
        CycleBenchOp::Update10,
        CycleBenchOp::Update,
        CycleBenchOp::DeleteSingle,
        CycleBenchOp::Delete10,
        CycleBenchOp::Delete,
        CycleBenchOp::ListAppend,
        CycleBenchOp::ListInsert,
        CycleBenchOp::ListUpdate,
        CycleBenchOp::ListDelete,
        CycleBenchOp::ListAppend10,
        CycleBenchOp::ListAppendBatch,
        CycleBenchOp::ListInsert10,
        CycleBenchOp::ListInsertBatch,
        CycleBenchOp::ListUpdate10,
        CycleBenchOp::ListUpdateBatch,
        CycleBenchOp::ListDelete10,
        CycleBenchOp::ListDeleteBatch,
        CycleBenchOp::InviteUser,
        CycleBenchOp::InviteUserKeyHash,
        CycleBenchOp::RefreshKeys,
        CycleBenchOp::RefreshKeysKeyHash,
        CycleBenchOp::Extend,
        CycleBenchOp::Rekey,
        CycleBenchOp::Reduce,
        CycleBenchOp::RemoveUser,
        CycleBenchOp::RemoveUserKeyHash,
        CycleBenchOp::NoopSingleFirst,
        CycleBenchOp::Noop10First,
        CycleBenchOp::NoopBatchFirst,
        CycleBenchOp::NoopBatchExtend,
    ];

    fn label(self) -> &'static str {
        match self {
            CycleBenchOp::CreateSpace => "create_space",
            CycleBenchOp::CreateSpaceKeyHash => "create_space_key_hash",
            CycleBenchOp::InsertSingle => "insert_single",
            CycleBenchOp::Insert10 => "insert_10",
            CycleBenchOp::Insert => "insert",
            CycleBenchOp::UpdateSingle => "update_single",
            CycleBenchOp::Update10 => "update_10",
            CycleBenchOp::Update => "update",
            CycleBenchOp::DeleteSingle => "delete_single",
            CycleBenchOp::Delete10 => "delete_10",
            CycleBenchOp::Delete => "delete",
            CycleBenchOp::ListAppend => "list_append",
            CycleBenchOp::ListInsert => "list_insert",
            CycleBenchOp::ListUpdate => "list_update",
            CycleBenchOp::ListDelete => "list_delete",
            CycleBenchOp::ListAppend10 => "list_append_10",
            CycleBenchOp::ListAppendBatch => "list_append_batch",
            CycleBenchOp::ListInsert10 => "list_insert_10",
            CycleBenchOp::ListInsertBatch => "list_insert_batch",
            CycleBenchOp::ListUpdate10 => "list_update_10",
            CycleBenchOp::ListUpdateBatch => "list_update_batch",
            CycleBenchOp::ListDelete10 => "list_delete_10",
            CycleBenchOp::ListDeleteBatch => "list_delete_batch",
            CycleBenchOp::InviteUser => "invite_user",
            CycleBenchOp::InviteUserKeyHash => "invite_user_key_hash",
            CycleBenchOp::RefreshKeys => "refresh_keys",
            CycleBenchOp::RefreshKeysKeyHash => "refresh_keys_key_hash",
            CycleBenchOp::Extend => "extend",
            CycleBenchOp::Rekey => "rekey",
            CycleBenchOp::Reduce => "reduce",
            CycleBenchOp::RemoveUser => "remove_user",
            CycleBenchOp::RemoveUserKeyHash => "remove_user_key_hash",
            CycleBenchOp::NoopSingleFirst => "noop_single_first",
            CycleBenchOp::Noop10First => "noop_10_first",
            CycleBenchOp::NoopBatchFirst => "noop_batch_first",
            CycleBenchOp::NoopBatchExtend => "noop_batch_extend",
        }
    }
}

struct CycleFixture {
    cycles: HashMap<&'static str, u64>,
}

fn cycle_fixture() -> &'static CycleFixture {
    static FIXTURE: OnceLock<CycleFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(build_cycle_fixture())
    })
}

async fn build_cycle_fixture() -> CycleFixture {
    let t0 = std::time::Instant::now();
    let mut bench_chain = BenchProofChain::new();
    let schemas = app_schemas();
    let init_cfg = SpaceInitConfig {
        space_id: SpaceId::from([0u8; 16]),
        artifact_path: None,
        verbose_logfile: None,
        bootstrap_data: BootstrapDataSource::None,
    };
    let state = SpaceState::init_server(Some(&schemas), Some(init_cfg), Some(1_000_000_000))
        .await
        .expect("SpaceState::init_server");
    let state = Arc::new(Mutex::new(state));

    let app_root = {
        let state = state.lock().await;
        state.db.root_hash()
    };
    let app_schema = ApplicationSchema::for_testing(schemas.clone(), app_root);

    eprintln!("[setup] Space::create (CreateSpace)");
    let space = Space::create(SharedStateTransport::new(Arc::clone(&state)), app_schema)
        .await
        .expect("Space::create");

    let mut cycles: HashMap<&'static str, u64> = HashMap::new();
    assert_latest_internal_key_hash_change(
        &state,
        OpType::CreateSpace,
        "create_space_key_hash",
        &[(USERS_TABLE, "auth_key"), (USERS_TABLE, "update_key")],
    )
    .await;
    let create_space_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    cycles.insert("create_space", create_space_cycles);
    cycles.insert("create_space_key_hash", create_space_cycles);

    // Fast pre-populate via one direct Merk transaction (old setup path),
    // then reset changelog baseline and resync the SDK client snapshot.
    eprintln!("[setup] pre-populating {PREPOPULATE_ROWS} products (fast batch)");
    let new_root = {
        let mut s = state.lock().await;
        let mut batch: Vec<(Vec<u8>, merk::Op)> = Vec::with_capacity(PREPOPULATE_ROWS * 2);
        for i in 0..PREPOPULATE_ROWS {
            let row_id = (i + 1) as i64;
            let name_bytes =
                stored_value::value_to_bytes(&serde_json::Value::String(format!("Product{i}")))
                    .unwrap();
            let price_bytes = stored_value::value_to_bytes(&serde_json::json!(i as f64)).unwrap();
            batch.push((
                column_key("products", row_id, "name"),
                merk::Op::Put(name_bytes),
            ));
            batch.push((
                column_key("products", row_id, "price"),
                merk::Op::Put(price_bytes),
            ));
        }
        let t_batch = std::time::Instant::now();
        batch.sort_by(|a, b| a.0.cmp(&b.0));
        eprintln!(
            "  [setup] built+sorted {} kv ops in {:.2?}",
            batch.len(),
            t_batch.elapsed()
        );

        let t_tx = std::time::Instant::now();
        eprint!("  [setup] merk apply_batch ...");
        s.db.merk.apply_batch(&batch).unwrap();
        eprintln!(" done in {:.2?}", t_tx.elapsed());

        let t_snap = std::time::Instant::now();
        eprint!("  [setup] taking tree snapshot ...");
        let current_root = s.get_root_hash().await;
        s.changelog = ChangeLog::new(&current_root);
        s.change_responses.clear();
        s.ff_proof = None;
        bench_chain = BenchProofChain::new();
        s.tree_snapshot = s.db.snapshot();
        // Mirror `reinitialize_changelog`: clear the per-user sigref view
        // alongside the changelog reset. The CreateSpace above advanced
        // sigref_map[creator]; without this the first SDK change (sig_ref=0)
        // fails `check_sigref_continuity` on the server (issue #30).
        s.sigref_map.clear();
        assert!(
            s.tree_snapshot.is_some(),
            "tree should not be empty after prepopulation"
        );
        eprintln!(" done in {:.2?}", t_snap.elapsed());
        current_root
    };

    eprint!("[setup] exporting Space snapshot ...");
    let mut snapshot = space.snapshot().await.expect("snapshot");
    eprintln!(" done");
    let state_obj = snapshot
        .get_mut("state")
        .and_then(Value::as_object_mut)
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
    // The fast-batch prepopulation rewinds the changelog to genesis, so the
    // client's per-user sigref view (advanced by the CreateSpace above) is
    // stale. Clear it so the first post-restore change (sig_ref=0) passes
    // `check_sigref_continuity` on both client and server (issue #30).
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

    eprint!("[setup] importing Space snapshot ...");
    let space = Space::restore(SharedStateTransport::new(Arc::clone(&state)), snapshot)
        .await
        .expect("import snapshot after fast prepopulation");
    eprintln!(" done");

    let products = space.table::<ProductRow>("products");

    // Pre-insert two extra rows (unmeasured) that update_single and delete_single
    // will operate on. Doing this through the SDK ensures they live in the
    // schema-tracked address space (the fast prepop bypasses indexes/counters,
    // so SDK queries on those rows may match nothing).
    eprintln!("[setup] SDK pre-inserting 2 helper rows (unmeasured) ...");
    let helper_update_id: i64 = products
        .insert(&ProductRow {
            id: None,
            name: "HelperUpdate".to_string(),
            price: 0.0,
        })
        .execute()
        .await
        .expect("helper update insert execute");
    let helper_delete_id: i64 = products
        .insert(&ProductRow {
            id: None,
            name: "HelperDelete".to_string(),
            price: 0.0,
        })
        .execute()
        .await
        .expect("helper delete insert execute");
    let _ = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("  [setup] helper rows: update_id={helper_update_id}, delete_id={helper_delete_id}");

    // Parity gate: verify that the timed loop matches production on the same input.
    {
        let s = state.lock().await;
        assert_timed_matches_production(&s, 0);
    }

    // Single-shot insert (one op, one proof) — directly comparable to create_space.
    eprint!("[setup] SDK insert single (1 op) ... ");
    let t_single = std::time::Instant::now();
    products
        .insert(&ProductRow {
            id: None,
            name: "SingleInsert".to_string(),
            price: -1.0,
        })
        .execute()
        .await
        .expect("insert single execute");
    let single_insert_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!(
        "handle_change={:.2?}, {single_insert_cycles} cycles",
        t_single.elapsed()
    );
    cycles.insert("insert_single", single_insert_cycles);

    // Single-shot update (target the SDK-inserted helper row)
    eprint!("[setup] SDK update single (1 op) ... ");
    let t_single = std::time::Instant::now();
    let rows = products
        .update()
        .set("name", "SingleUpdate".to_string())
        .set("price", -2.0)
        .where_eq("id", helper_update_id)
        .execute()
        .await
        .expect("update single execute");
    let single_update_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!(
        "handle_change={:.2?}, rows_affected={rows}, {single_update_cycles} cycles",
        t_single.elapsed()
    );
    cycles.insert("update_single", single_update_cycles);

    // Single-shot delete (target the other SDK-inserted helper row)
    eprint!("[setup] SDK delete single (1 op) ... ");
    let t_single = std::time::Instant::now();
    let rows = products
        .delete()
        .where_eq("id", helper_delete_id)
        .execute()
        .await
        .expect("delete single execute");
    let single_delete_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!(
        "handle_change={:.2?}, rows_affected={rows}, {single_delete_cycles} cycles",
        t_single.elapsed()
    );
    cycles.insert("delete_single", single_delete_cycles);

    // Insert batch
    eprintln!("[setup] SDK insert batch ({OPS_PER_BATCH} ops) ...");
    let t_batch = std::time::Instant::now();
    for i in 0..OPS_PER_BATCH {
        let t_op = std::time::Instant::now();
        products
            .insert(&ProductRow {
                id: None,
                name: format!("BatchInsert{i}"),
                price: i as f64,
            })
            .execute()
            .await
            .expect("insert execute");
        if (i + 1) % 20 == 0 || i + 1 == OPS_PER_BATCH {
            eprintln!(
                "  [setup: insert] {}/{} total={:.2?} (handle_change={:.2?})",
                i + 1,
                OPS_PER_BATCH,
                t_batch.elapsed(),
                t_op.elapsed()
            );
        }
    }
    let insert_result = prove_pending_changes_bench(&state, &mut bench_chain).await;
    let insert_cycles = insert_result.cycles / OPS_PER_BATCH as u64;
    eprintln!("  [prove] insert: {insert_cycles} cycles/op");
    print_bench_timing("insert", &insert_result);
    cycles.insert("insert", insert_cycles);

    // Insert batch (N=10)
    eprintln!("[setup] SDK insert batch (10 ops) ...");
    for i in 0..10 {
        products
            .insert(&ProductRow {
                id: None,
                name: format!("Batch10Insert{i}"),
                price: i as f64,
            })
            .execute()
            .await
            .expect("insert10 execute");
    }
    let insert_10_total = prove_bench_cycles(&state, &mut bench_chain).await;
    let insert_10_cycles = insert_10_total / 10;
    eprintln!("  [prove] insert_10: total={insert_10_total}, {insert_10_cycles} cycles/op");
    cycles.insert("insert_10", insert_10_cycles);

    // Update batch
    eprintln!("[setup] SDK update batch ({OPS_PER_BATCH} ops) ...");
    let t_batch = std::time::Instant::now();
    for i in 0..OPS_PER_BATCH {
        let t_op = std::time::Instant::now();
        let row_id = i as i64 + 1;
        products
            .update()
            .set("name", format!("Updated{i}"))
            .set("price", i as f64 * 1.1)
            .where_eq("id", row_id)
            .execute()
            .await
            .expect("update execute");
        if (i + 1) % 20 == 0 || i + 1 == OPS_PER_BATCH {
            eprintln!(
                "  [setup: update] {}/{} total={:.2?} (handle_change={:.2?})",
                i + 1,
                OPS_PER_BATCH,
                t_batch.elapsed(),
                t_op.elapsed()
            );
        }
    }
    let update_result = prove_pending_changes_bench(&state, &mut bench_chain).await;
    let update_cycles = update_result.cycles / OPS_PER_BATCH as u64;
    eprintln!("  [prove] update: {update_cycles} cycles/op");
    print_bench_timing("update", &update_result);
    cycles.insert("update", update_cycles);

    // Update batch (N=10)
    eprintln!("[setup] SDK update batch (10 ops) ...");
    for i in 0..10i64 {
        let row_id = i + 11; // IDs 11..=20 (already updated once above, that's fine)
        products
            .update()
            .set("name", format!("Updated10_{i}"))
            .set("price", i as f64 * 2.0)
            .where_eq("id", row_id)
            .execute()
            .await
            .expect("update10 execute");
    }
    let update_10_total = prove_bench_cycles(&state, &mut bench_chain).await;
    let update_10_cycles = update_10_total / 10;
    eprintln!("  [prove] update_10: total={update_10_total}, {update_10_cycles} cycles/op");
    cycles.insert("update_10", update_10_cycles);

    // Delete batch (avoid recently inserted rows; delete from pre-populated range)
    eprintln!("[setup] SDK delete batch ({OPS_PER_BATCH} ops) ...");
    let t_batch = std::time::Instant::now();
    for i in 0..OPS_PER_BATCH {
        let t_op = std::time::Instant::now();
        let row_id = (OPS_PER_BATCH + i + 1) as i64;
        products
            .delete()
            .where_eq("id", row_id)
            .execute()
            .await
            .expect("delete execute");
        if (i + 1) % 20 == 0 || i + 1 == OPS_PER_BATCH {
            eprintln!(
                "  [setup: delete] {}/{} total={:.2?} (handle_change={:.2?})",
                i + 1,
                OPS_PER_BATCH,
                t_batch.elapsed(),
                t_op.elapsed()
            );
        }
    }
    let delete_result = prove_pending_changes_bench(&state, &mut bench_chain).await;
    let delete_cycles = delete_result.cycles / OPS_PER_BATCH as u64;
    eprintln!("  [prove] delete: {delete_cycles} cycles/op");
    print_bench_timing("delete", &delete_result);
    cycles.insert("delete", delete_cycles);

    // Delete batch (N=10) — use IDs 201..=210 (untouched by N=100 delete which used 101..=200)
    eprintln!("[setup] SDK delete batch (10 ops) ...");
    for i in 0..10i64 {
        let row_id = (OPS_PER_BATCH as i64 * 2) + i + 1;
        products
            .delete()
            .where_eq("id", row_id)
            .execute()
            .await
            .expect("delete10 execute");
    }
    let delete_10_total = prove_bench_cycles(&state, &mut bench_chain).await;
    let delete_10_cycles = delete_10_total / 10;
    eprintln!("  [prove] delete_10: total={delete_10_total}, {delete_10_cycles} cycles/op");
    cycles.insert("delete_10", delete_10_cycles);

    // Project/list setup (unmeasured)
    eprintln!("[setup] creating project + seeding {PREPOPULATE_LIST_ITEMS} list items ...");
    let projects = space.table::<ProjectRow>("projects");
    let project_id = projects
        .insert(&ProjectRow {
            id: None,
            name: "List Bench Project".to_string(),
            tasks: List::empty(),
        })
        .execute()
        .await
        .expect("project insert execute");
    let tasks: ListAlias<TaskRow> = space.list("projects", project_id, "tasks");
    let mut seeded_keys: Vec<Vec<u8>> = Vec::with_capacity(PREPOPULATE_LIST_ITEMS);
    let t_seed = std::time::Instant::now();
    for i in 0..PREPOPULATE_LIST_ITEMS {
        let t_op = std::time::Instant::now();
        let key = tasks
            .append(&TaskRow {
                title: format!("seed-{i}"),
                done: false,
            })
            .await
            .expect("seed list_append");
        seeded_keys.push(key);
        if (i + 1) % 8 == 0 || i + 1 == PREPOPULATE_LIST_ITEMS {
            eprintln!(
                "  [setup: seed list] {}/{} total={:.2?} (handle_change={:.2?})",
                i + 1,
                PREPOPULATE_LIST_ITEMS,
                t_seed.elapsed(),
                t_op.elapsed()
            );
        }
    }
    let _ = prove_bench_cycles(&state, &mut bench_chain).await;

    // List append
    eprint!("[setup] list_append ... ");
    let appended_key = tasks
        .append(&TaskRow {
            title: "measured-append".to_string(),
            done: false,
        })
        .await
        .expect("list_append");
    let list_append_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{list_append_cycles} cycles");
    cycles.insert("list_append", list_append_cycles);

    // List insert
    eprint!("[setup] list_insert ... ");
    let inserted_key = tasks
        .insert_after_key(
            &seeded_keys[PREPOPULATE_LIST_ITEMS / 2],
            &TaskRow {
                title: "measured-insert".to_string(),
                done: false,
            },
        )
        .await
        .expect("list_insert");
    let list_insert_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{list_insert_cycles} cycles");
    cycles.insert("list_insert", list_insert_cycles);

    // List update
    eprint!("[setup] list_update ... ");
    tasks
        .update_by_key(
            &appended_key,
            &TaskRow {
                title: "measured-updated".to_string(),
                done: true,
            },
        )
        .await
        .expect("list_update");
    let list_update_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{list_update_cycles} cycles");
    cycles.insert("list_update", list_update_cycles);

    // List delete
    eprint!("[setup] list_delete ... ");
    tasks
        .delete_by_key(&inserted_key)
        .await
        .expect("list_delete");
    let list_delete_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{list_delete_cycles} cycles");
    cycles.insert("list_delete", list_delete_cycles);

    // List append batch (amortized over OPS_PER_BATCH ops)
    eprintln!("[setup] SDK list_append batch ({OPS_PER_BATCH} ops) ...");
    let t_batch = std::time::Instant::now();
    let mut batch_appended: Vec<Vec<u8>> = Vec::with_capacity(OPS_PER_BATCH);
    for i in 0..OPS_PER_BATCH {
        let t_op = std::time::Instant::now();
        let k = tasks
            .append(&TaskRow {
                title: format!("batch-append-{i}"),
                done: false,
            })
            .await
            .expect("list_append batch");
        batch_appended.push(k);
        if (i + 1) % 20 == 0 || i + 1 == OPS_PER_BATCH {
            eprintln!(
                "  [setup: list_append] {}/{} total={:.2?} (handle_change={:.2?})",
                i + 1,
                OPS_PER_BATCH,
                t_batch.elapsed(),
                t_op.elapsed()
            );
        }
    }
    let list_append_batch_cycles =
        prove_bench_cycles(&state, &mut bench_chain).await / OPS_PER_BATCH as u64;
    eprintln!("  [prove] list_append: {list_append_batch_cycles} cycles/op");
    cycles.insert("list_append_batch", list_append_batch_cycles);

    // List append (N=10)
    eprintln!("[setup] SDK list_append batch (10 ops) ...");
    let mut batch10_appended: Vec<Vec<u8>> = Vec::with_capacity(10);
    for i in 0..10 {
        let k = tasks
            .append(&TaskRow {
                title: format!("batch10-append-{i}"),
                done: false,
            })
            .await
            .expect("list_append batch10");
        batch10_appended.push(k);
    }
    let list_append_10_total = prove_bench_cycles(&state, &mut bench_chain).await;
    let list_append_10_cycles = list_append_10_total / 10;
    eprintln!(
        "  [prove] list_append_10: total={list_append_10_total}, {list_append_10_cycles} cycles/op"
    );
    cycles.insert("list_append_10", list_append_10_cycles);

    // List insert batch (insert_after_key OPS_PER_BATCH times, anchored on a seeded key)
    eprintln!("[setup] SDK list_insert batch ({OPS_PER_BATCH} ops) ...");
    let t_batch = std::time::Instant::now();
    let anchor_key = seeded_keys[PREPOPULATE_LIST_ITEMS / 2].clone();
    let mut batch_inserted: Vec<Vec<u8>> = Vec::with_capacity(OPS_PER_BATCH);
    let mut prev = anchor_key.clone();
    for i in 0..OPS_PER_BATCH {
        let t_op = std::time::Instant::now();
        let k = tasks
            .insert_after_key(
                &prev,
                &TaskRow {
                    title: format!("batch-insert-{i}"),
                    done: false,
                },
            )
            .await
            .expect("list_insert batch");
        prev = k.clone();
        batch_inserted.push(k);
        if (i + 1) % 20 == 0 || i + 1 == OPS_PER_BATCH {
            eprintln!(
                "  [setup: list_insert] {}/{} total={:.2?} (handle_change={:.2?})",
                i + 1,
                OPS_PER_BATCH,
                t_batch.elapsed(),
                t_op.elapsed()
            );
        }
    }
    let list_insert_batch_cycles =
        prove_bench_cycles(&state, &mut bench_chain).await / OPS_PER_BATCH as u64;
    eprintln!("  [prove] list_insert: {list_insert_batch_cycles} cycles/op");
    cycles.insert("list_insert_batch", list_insert_batch_cycles);

    // List insert (N=10) — anchor on a seeded key, chain insertions
    eprintln!("[setup] SDK list_insert batch (10 ops) ...");
    let mut batch10_inserted: Vec<Vec<u8>> = Vec::with_capacity(10);
    let mut prev10 = seeded_keys[PREPOPULATE_LIST_ITEMS / 4].clone();
    for i in 0..10 {
        let k = tasks
            .insert_after_key(
                &prev10,
                &TaskRow {
                    title: format!("batch10-insert-{i}"),
                    done: false,
                },
            )
            .await
            .expect("list_insert batch10");
        prev10 = k.clone();
        batch10_inserted.push(k);
    }
    let list_insert_10_total = prove_bench_cycles(&state, &mut bench_chain).await;
    let list_insert_10_cycles = list_insert_10_total / 10;
    eprintln!(
        "  [prove] list_insert_10: total={list_insert_10_total}, {list_insert_10_cycles} cycles/op"
    );
    cycles.insert("list_insert_10", list_insert_10_cycles);

    // List update batch (update each of the just-appended keys)
    eprintln!("[setup] SDK list_update batch ({OPS_PER_BATCH} ops) ...");
    let t_batch = std::time::Instant::now();
    for (i, k) in batch_appended.iter().enumerate() {
        let t_op = std::time::Instant::now();
        tasks
            .update_by_key(
                k,
                &TaskRow {
                    title: format!("batch-updated-{i}"),
                    done: true,
                },
            )
            .await
            .expect("list_update batch");
        if (i + 1) % 20 == 0 || i + 1 == OPS_PER_BATCH {
            eprintln!(
                "  [setup: list_update] {}/{} total={:.2?} (handle_change={:.2?})",
                i + 1,
                OPS_PER_BATCH,
                t_batch.elapsed(),
                t_op.elapsed()
            );
        }
    }
    let list_update_batch_cycles =
        prove_bench_cycles(&state, &mut bench_chain).await / OPS_PER_BATCH as u64;
    eprintln!("  [prove] list_update: {list_update_batch_cycles} cycles/op");
    cycles.insert("list_update_batch", list_update_batch_cycles);

    // List update (N=10) — update the just-appended-10 keys
    eprintln!("[setup] SDK list_update batch (10 ops) ...");
    for (i, k) in batch10_appended.iter().enumerate() {
        tasks
            .update_by_key(
                k,
                &TaskRow {
                    title: format!("batch10-updated-{i}"),
                    done: true,
                },
            )
            .await
            .expect("list_update batch10");
    }
    let list_update_10_total = prove_bench_cycles(&state, &mut bench_chain).await;
    let list_update_10_cycles = list_update_10_total / 10;
    eprintln!(
        "  [prove] list_update_10: total={list_update_10_total}, {list_update_10_cycles} cycles/op"
    );
    cycles.insert("list_update_10", list_update_10_cycles);

    // List delete batch (delete each of the just-inserted keys)
    eprintln!("[setup] SDK list_delete batch ({OPS_PER_BATCH} ops) ...");
    let t_batch = std::time::Instant::now();
    for (i, k) in batch_inserted.iter().enumerate() {
        let t_op = std::time::Instant::now();
        tasks.delete_by_key(k).await.expect("list_delete batch");
        if (i + 1) % 20 == 0 || i + 1 == OPS_PER_BATCH {
            eprintln!(
                "  [setup: list_delete] {}/{} total={:.2?} (handle_change={:.2?})",
                i + 1,
                OPS_PER_BATCH,
                t_batch.elapsed(),
                t_op.elapsed()
            );
        }
    }
    let list_delete_batch_cycles =
        prove_bench_cycles(&state, &mut bench_chain).await / OPS_PER_BATCH as u64;
    eprintln!("  [prove] list_delete: {list_delete_batch_cycles} cycles/op");
    cycles.insert("list_delete_batch", list_delete_batch_cycles);

    // List delete (N=10) — delete the just-inserted-10 keys
    eprintln!("[setup] SDK list_delete batch (10 ops) ...");
    for k in batch10_inserted.iter() {
        tasks.delete_by_key(k).await.expect("list_delete batch10");
    }
    let list_delete_10_total = prove_bench_cycles(&state, &mut bench_chain).await;
    let list_delete_10_cycles = list_delete_10_total / 10;
    eprintln!(
        "  [prove] list_delete_10: total={list_delete_10_total}, {list_delete_10_cycles} cycles/op"
    );
    cycles.insert("list_delete_10", list_delete_10_cycles);

    // Retention ops
    eprint!("[setup] extend ... ");
    space.extend().await.expect("extend");
    let extend_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{extend_cycles} cycles");
    cycles.insert("extend", extend_cycles);

    eprint!("[setup] reduce ... ");
    space.reduce(SimpleKeyId(1)).await.expect("reduce");
    let reduce_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{reduce_cycles} cycles");
    cycles.insert("reduce", reduce_cycles);

    eprint!("[setup] rekey ... ");
    space.rekey().await.expect("rekey");
    let rekey_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{rekey_cycles} cycles");
    cycles.insert("rekey", rekey_cycles);

    // User-management ops
    eprint!("[setup] invite_user ... ");
    let invite = space.invite_user().await.expect("invite_user 1");
    assert_latest_internal_key_hash_change(
        &state,
        OpType::InviteUser,
        "invite_user_key_hash",
        &[(USERS_TABLE, "auth_key"), (USERS_TABLE, "update_key")],
    )
    .await;
    let invite_user_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{invite_user_cycles} cycles");
    cycles.insert("invite_user", invite_user_cycles);
    cycles.insert("invite_user_key_hash", invite_user_cycles);

    // The joining Space must share the same initial_dc as the host Space — i.e.,
    // the post-prepopulation root that anchors the start of our proof chain.
    eprint!("[setup] Space::join (refresh_keys) ... ");
    let join_app_schema = ApplicationSchema::for_testing(schemas.clone(), new_root);
    let _joined = Space::join(
        SharedStateTransport::new(Arc::clone(&state)),
        invite,
        join_app_schema,
    )
    .await
    .expect("Space::join");
    assert_latest_internal_key_hash_change(
        &state,
        OpType::RefreshKeys,
        "refresh_keys_key_hash",
        &[
            (KEY_HISTORY_TABLE, "old_auth_key"),
            (USERS_TABLE, "auth_key"),
            (USERS_TABLE, "update_key"),
        ],
    )
    .await;
    let refresh_keys_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{refresh_keys_cycles} cycles");
    cycles.insert("refresh_keys", refresh_keys_cycles);
    cycles.insert("refresh_keys_key_hash", refresh_keys_cycles);

    eprint!("[setup] sync + invite_user 2 ... ");
    space.sync().await.expect("sync after join");
    let invite2 = space.invite_user().await.expect("invite_user 2");
    let _ = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("done");

    eprint!("[setup] remove_user ... ");
    let remove_target_id = invite2.id().expect("invite2 has uid");
    space
        .remove_user(remove_target_id)
        .await
        .expect("remove_user");
    assert_latest_internal_key_hash_change(
        &state,
        OpType::RemoveUser,
        "remove_user_key_hash",
        &[(KEY_HISTORY_TABLE, "old_auth_key")],
    )
    .await;
    let remove_user_cycles = prove_bench_cycles(&state, &mut bench_chain).await;
    eprintln!("{remove_user_cycles} cycles");
    cycles.insert("remove_user", remove_user_cycles);
    cycles.insert("remove_user_key_hash", remove_user_cycles);

    // ─── Noop benchmarks (separate state, bypass server) ─────────────────────
    eprintln!("[setup] building noop benchmarks ...");
    let noop_cycles = build_noop_benchmarks().await;
    for (k, v) in &noop_cycles {
        cycles.insert(k, *v);
    }

    eprintln!("[setup] all-op fixture ready in {:.2?}", t0.elapsed());
    fn fmt_commas(v: i64) -> String {
        let neg = v < 0;
        let s = v.unsigned_abs().to_string();
        let mut out = String::with_capacity(s.len() + s.len() / 3 + 1);
        for (i, ch) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                out.push(',');
            }
            out.push(ch);
        }
        if neg {
            out.push('-');
        }
        out.chars().rev().collect::<String>()
    }
    for op in CycleBenchOp::ALL {
        if let Some(v) = cycles.get(op.label()) {
            eprintln!("  {:>18}: {:>13} cycles", op.label(), fmt_commas(*v as i64));
        }
    }

    // ─── Linear cost model: cycles(N) = fixed + N · marginal ──────────────────
    // For each op family with N=1, N=10, N=100 measurements, fit by least-squares
    // and check linearity by comparing predicted vs measured at N=10.
    eprintln!();
    eprintln!("=== Cost model regression (least-squares fit on N=1, 10, 100) ===");
    eprintln!(
        "  {:>14}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}  {:>9}",
        "op", "total@N=1", "total@N=10", "total@N=100", "fixed", "marginal", "Δ@N=10"
    );
    let families: &[(&str, &str, &str, &str)] = &[
        // (display name, N=1 total key, N=10 per-op key, N=100 per-op key)
        ("insert", "insert_single", "insert_10", "insert"),
        ("update", "update_single", "update_10", "update"),
        ("delete", "delete_single", "delete_10", "delete"),
        (
            "list_append",
            "list_append",
            "list_append_10",
            "list_append_batch",
        ),
        (
            "list_insert",
            "list_insert",
            "list_insert_10",
            "list_insert_batch",
        ),
        (
            "list_update",
            "list_update",
            "list_update_10",
            "list_update_batch",
        ),
        (
            "list_delete",
            "list_delete",
            "list_delete_10",
            "list_delete_batch",
        ),
    ];
    for (name, k1, k10, k100) in families {
        let (Some(&y1), Some(&y10_per), Some(&y100_per)) =
            (cycles.get(k1), cycles.get(k10), cycles.get(k100))
        else {
            continue;
        };
        let y1 = y1 as f64;
        let y10 = (y10_per * 10) as f64;
        let y100 = (y100_per * 100) as f64;
        // Least-squares fit over (N, total) at points (1, y1), (10, y10), (100, y100).
        let xs = [1.0_f64, 10.0, 100.0];
        let ys = [y1, y10, y100];
        let mean_x = (xs[0] + xs[1] + xs[2]) / 3.0;
        let mean_y = (ys[0] + ys[1] + ys[2]) / 3.0;
        let sxx: f64 = xs.iter().map(|x| (x - mean_x).powi(2)).sum();
        let sxy: f64 = xs
            .iter()
            .zip(ys.iter())
            .map(|(x, y)| (x - mean_x) * (y - mean_y))
            .sum();
        let marginal = sxy / sxx;
        let fixed = mean_y - marginal * mean_x;
        let predicted_10 = fixed + 10.0 * marginal;
        let delta_10_pct = (y10 - predicted_10) / predicted_10 * 100.0;
        eprintln!(
            "  {:>14}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}  {:>+8.1}%",
            name,
            fmt_commas(y1 as i64),
            fmt_commas(y10 as i64),
            fmt_commas(y100 as i64),
            fmt_commas(fixed.round() as i64),
            fmt_commas(marginal.round() as i64),
            delta_10_pct,
        );
    }
    eprintln!();

    // ─── Realistic mixed sequences (100 changes, single proof) ────────────────
    eprintln!("=== Realistic 100-change sequences (single proof, all 100 changes) ===");
    run_realistic_sequence("table workload", false, &schemas).await;
    run_realistic_sequence("list workload", true, &schemas).await;
    eprintln!();

    CycleFixture { cycles }
}

async fn run_realistic_sequence(label: &'static str, use_lists: bool, schemas: &[Schema]) {
    let mut bench_chain = BenchProofChain::new();
    let init_cfg = SpaceInitConfig {
        space_id: SpaceId::from([7u8; 16]),
        artifact_path: None,
        verbose_logfile: None,
        bootstrap_data: BootstrapDataSource::None,
    };
    let schemas_vec: Vec<Schema> = schemas.to_vec();
    let state = SpaceState::init_server(Some(&schemas_vec), Some(init_cfg), Some(1_000_000_000))
        .await
        .expect("init_server");
    let state = Arc::new(Mutex::new(state));
    let app_root = state.lock().await.db.root_hash();
    let app_schema = ApplicationSchema::for_testing(schemas_vec, app_root);

    let t_seq = std::time::Instant::now();
    // 1: create_space
    let space = Space::create(SharedStateTransport::new(Arc::clone(&state)), app_schema)
        .await
        .expect("Space::create");
    // 2, 3: invite × 2
    let _invite1 = space.invite_user().await.expect("invite_user 1");
    let invite2 = space.invite_user().await.expect("invite_user 2");
    let remove_target = invite2.id().expect("invite2 uid");

    let mut count: usize = 3;

    if !use_lists {
        let products = space.table::<ProductRow>("products");
        // 4..=50 (47 ops): mix of inserts/updates/deletes
        // First seed 25 inserts so we have rows to update/delete
        let mut row_ids: Vec<i64> = Vec::with_capacity(50);
        for i in 0..25 {
            let id = products
                .insert(&ProductRow {
                    id: None,
                    name: format!("seq-{i}"),
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
                .set("name", format!("seq-upd-{i}"))
                .where_eq("id", row_id)
                .execute()
                .await
                .expect("upd");
            count += 1;
        }
        // 10 deletes (delete the last 10 of seeded rows)
        for (_i, &id) in row_ids[14..24].iter().enumerate().rev() {
            products
                .delete()
                .where_eq("id", id)
                .execute()
                .await
                .expect("del");
            count += 1;
        }
        // 51: remove_user
        space.remove_user(remove_target).await.expect("remove_user");
        count += 1;
        // 52..=100 (49 more ops): 25 inserts, 14 updates, 10 deletes
        let mut more_ids: Vec<i64> = Vec::with_capacity(25);
        for i in 0..25 {
            let id = products
                .insert(&ProductRow {
                    id: None,
                    name: format!("seq2-{i}"),
                    price: i as f64,
                })
                .execute()
                .await
                .expect("ins2 exec");
            more_ids.push(id);
            count += 1;
        }
        // updates: 14 updates targeting earlier surviving rows + new rows
        for (i, _) in (0..14).enumerate() {
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
        // deletes: 10 from new rows
        for (_idx, &id) in more_ids[15..25].iter().enumerate().rev() {
            products
                .delete()
                .where_eq("id", id)
                .execute()
                .await
                .expect("del2");
            count += 1;
        }
    } else {
        // List workload
        // 4: create a project that holds the list
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
        // We've used 4 changes so far; list ops fill the remaining 96 (with one remove_user)
        // 5..=50 (46 ops): 20 append, 8 insert_after, 10 update, 8 delete
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(50);
        for i in 0..20 {
            let k = tasks
                .append(&TaskRow {
                    title: format!("t-{i}"),
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
                        title: format!("ins-{i}"),
                        done: false,
                    },
                )
                .await
                .expect("ins_after");
            keys.push(k);
            count += 1;
        }
        for (i, _) in (0..10).enumerate() {
            tasks
                .update_by_key(
                    &keys[i],
                    &TaskRow {
                        title: format!("upd-{i}"),
                        done: true,
                    },
                )
                .await
                .expect("upd");
            count += 1;
        }
        for (i, _) in (0..8).enumerate() {
            // delete from tail of inserted-after keys (indices 20..28)
            let k = keys[20 + (7 - i)].clone();
            tasks.delete_by_key(&k).await.expect("del");
            count += 1;
        }
        // 51: remove_user
        space.remove_user(remove_target).await.expect("remove_user");
        count += 1;
        // 52..=100 (49 ops): 20 append, 11 insert_after, 10 update, 8 delete
        let mut keys2: Vec<Vec<u8>> = Vec::with_capacity(40);
        for i in 0..20 {
            let k = tasks
                .append(&TaskRow {
                    title: format!("t2-{i}"),
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
                        title: format!("ins2-{i}"),
                        done: false,
                    },
                )
                .await
                .expect("ins_after2");
            keys2.push(k);
            count += 1;
        }
        for (i, _) in (0..10).enumerate() {
            tasks
                .update_by_key(
                    &keys2[i],
                    &TaskRow {
                        title: format!("upd2-{i}"),
                        done: true,
                    },
                )
                .await
                .expect("upd2");
            count += 1;
        }
        for (i, _) in (0..8).enumerate() {
            let k = keys2[20 + (7 - i)].clone();
            tasks.delete_by_key(&k).await.expect("del2");
            count += 1;
        }
    }

    eprintln!(
        "  [{label}] applied {count} changes in {:.2?}",
        t_seq.elapsed()
    );
    let actual = state.lock().await.changelog.num_changes() as u64;
    let total = prove_bench_cycles(&state, &mut bench_chain).await;
    let per_op = total.checked_div(actual).unwrap_or(0);
    fn fmt_c(v: u64) -> String {
        let s = v.to_string();
        let mut out = String::with_capacity(s.len() + s.len() / 3);
        for (i, ch) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                out.push(',');
            }
            out.push(ch);
        }
        out.chars().rev().collect()
    }
    eprintln!(
        "  [{label}] {actual} changes, total {} cycles, {} cycles/op (avg)",
        fmt_c(total),
        fmt_c(per_op),
    );
}

async fn build_noop_benchmarks() -> HashMap<&'static str, u64> {
    use encrypted_spaces_backend::sign_change::sign_change;
    use encrypted_spaces_changelog_test_utils::test_auth_key_pair;

    let mut results: HashMap<&'static str, u64> = HashMap::new();

    const NOOP_UID: u32 = 1;

    /// Append `count` signed noop entries directly to the changelog.
    /// The tree root is unchanged (no reads or writes), so old_root == new_root.
    async fn append_noops(state: &mut SpaceState, count: usize) {
        let key_pair = test_auth_key_pair(NOOP_UID);
        let root = state.get_root_hash().await;

        if state.changelog.num_changes() as usize == state.changelog.proven_up_to {
            state.tree_snapshot = state.db.snapshot();
        }

        for _ in 0..count {
            let current_change_id = state.changelog.num_changes();
            let parent_clc = state.changelog.current_root();

            let mut last_by_user: Option<u32> = None;
            for (idx, c) in state.changelog.changes.iter().enumerate() {
                if c.uid == NOOP_UID {
                    last_by_user = Some((idx + 1) as u32);
                }
            }

            let mut entry = ChangelogEntry {
                timestamp: ChangelogEntry::get_unix_timestamp(),
                uid: NOOP_UID,
                parent_change: current_change_id,
                message: LogMessage {
                    op_type: OpType::Noop,
                    tree_path: ROOT_TREE_PATH.to_vec(),
                    entries: vec![],
                },
                sig_ref: last_by_user.unwrap_or(0),
                parent_clc,
                signature: vec![],
            };

            sign_change(&mut entry, &key_pair);

            let tree_snapshot = state.tree_snapshot.as_ref().expect("tree_snapshot");
            let steps = vec![];
            let tracer_proof = create_trace(tree_snapshot, &steps);
            let pruned_merkle_tree =
                postcard::to_allocvec(&tracer_proof.pruned_tree).expect("serialize pruned tree");

            state
                .changelog
                .add_change(&entry, &pruned_merkle_tree, &root, &root)
                .expect("add_change for noop");

            let change_id = state.changelog.num_changes();
            state.change_responses.push(ChangeResponse {
                change_id,
                old_root: root,
                new_root: root,
                pruned_merkle_tree: Vec::new(),
                rows_affected: 0,
                accepted_at_server_time: entry.timestamp,
                hashed_values: Default::default(),
            });
        }
    }

    // Use init_test_server_state to get a state with user uid=1 already
    // registered (via direct DB inserts, not changelog entries). The
    // changelog is empty and proven_up_to == 0, so the first proof
    // covers only noop entries.

    // noop_single_first: 1 noop, first proof
    eprint!("  [noop] noop_single_first (1 op) ... ");
    {
        let mut state = init_test_server_state(Some(1_000_000_000), &[NOOP_UID]).await;
        append_noops(&mut state, 1).await;
        let state = Arc::new(Mutex::new(state));
        let mut chain = BenchProofChain::new();
        let result = prove_pending_changes_bench(&state, &mut chain).await;
        eprintln!("{} cycles", result.cycles);
        print_bench_timing("noop_single_first", &result);
        results.insert("noop_single_first", result.cycles);
    }

    // noop_10_first: 10 noops, first proof
    eprint!("  [noop] noop_10_first (10 ops) ... ");
    {
        let mut state = init_test_server_state(Some(1_000_000_000), &[NOOP_UID]).await;
        append_noops(&mut state, 10).await;
        let state = Arc::new(Mutex::new(state));
        let mut chain = BenchProofChain::new();
        let result = prove_pending_changes_bench(&state, &mut chain).await;
        let per_op = result.cycles / 10;
        eprintln!("{per_op} cycles/op (total={})", result.cycles);
        print_bench_timing("noop_10_first", &result);
        results.insert("noop_10_first", per_op);
    }

    // noop_batch_first: OPS_PER_BATCH noops, first proof
    // noop_batch_extend: OPS_PER_BATCH noops, extending the first proof
    eprint!("  [noop] noop_batch_first ({OPS_PER_BATCH} ops) ... ");
    {
        let mut state = init_test_server_state(Some(1_000_000_000), &[NOOP_UID]).await;
        append_noops(&mut state, OPS_PER_BATCH).await;
        let state = Arc::new(Mutex::new(state));
        let mut chain = BenchProofChain::new();
        let result = prove_pending_changes_bench(&state, &mut chain).await;
        let per_op = result.cycles / OPS_PER_BATCH as u64;
        eprintln!("{per_op} cycles/op (total={})", result.cycles);
        print_bench_timing("noop_batch_first", &result);
        results.insert("noop_batch_first", per_op);

        // noop_batch_extend: append more noops and extend the previous proof
        eprint!("  [noop] noop_batch_extend ({OPS_PER_BATCH} ops) ... ");
        {
            let mut s = state.lock().await;
            append_noops(&mut s, OPS_PER_BATCH).await;
        }
        let result = prove_pending_changes_bench(&state, &mut chain).await;
        let per_op = result.cycles / OPS_PER_BATCH as u64;
        eprintln!("{per_op} cycles/op (total={})", result.cycles);
        print_bench_timing("noop_batch_extend", &result);
        results.insert("noop_batch_extend", per_op);
    }

    results
}

fn bench_all_ops(c: &mut Criterion<ZkvmCycles>) {
    for op in CycleBenchOp::ALL {
        let label = op.label();
        let bench_name = format!("ff_proof/{label}_R{}_t{}", PREPOPULATE_ROWS, OPS_PER_BATCH);
        // Per-bench cache mirrors the pattern used by bench_recursive_verify_cost.
        // On first call, we do a brief spin to give Criterion a wall-clock signal that
        // keeps iters=1 for all subsequent samples. Without this, cycle_fixture() returns
        // in nanoseconds and Criterion escalates iters until `per_op * iters` overflows u64.
        let mut cached: Option<u64> = None;
        c.bench_function(&bench_name, |b| {
            b.iter_custom(|iters| {
                let cycles = *cached.get_or_insert_with(|| {
                    let v = *cycle_fixture()
                        .cycles
                        .get(label)
                        .unwrap_or_else(|| panic!("missing cycles for op '{label}'"));
                    // Burn ≥1ms so Criterion's calibration anchors at iters=1.
                    let t = std::time::Instant::now();
                    while t.elapsed() < std::time::Duration::from_millis(10) {
                        std::hint::spin_loop();
                    }
                    v
                });
                cycles * iters
            });
        });
    }
}

fn zkvm_cycles_criterion() -> Criterion<ZkvmCycles> {
    // Set RISC0_DEV_MODE so proving is fast; benchmarks measure cycles not wall time.
    // Suppress all RISC0/env logging so benchmark output is readable.
    std::env::set_var("RISC0_DEV_MODE", "1");
    std::env::remove_var("RISC0_INFO");
    std::env::set_var("RUST_LOG", "error"); // suppresses info/debug from log + tracing
    std::env::set_var("RISC0_GUEST_LOGFILE", "/dev/null"); // suppress R0VM[...] guest logs

    Criterion::default()
        .with_measurement(ZkvmCycles)
        // Cycle counts are deterministic — minimize iterations.
        .sample_size(10) // criterion 0.4 minimum
        .nresamples(10) // criterion 0.4 minimum
        .warm_up_time(std::time::Duration::from_millis(1))
        .measurement_time(std::time::Duration::from_millis(1))
        // Suppress statistical change detection — cycle counts are deterministic.
        .significance_level(0.0001)
        .noise_threshold(1.0)
}

criterion_group! {
    name = ff_benchmarks;
    config = zkvm_cycles_criterion();
    targets = bench_recursive_verify_cost, bench_all_ops
}

criterion_main!(ff_benchmarks);
