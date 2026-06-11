//! zkVM-cycle benchmarks comparing primitive ops against action-routed ops.
//!
//! Mirrors `action_proof_size_benchmarks` but measures RISC0 user
//! cycles per op (after FF-prover invocation) instead of pruned-tree
//! bytes.  Each measured op runs once; the result is recorded under a
//! label and replayed by Criterion.
//!
//! Run with:
//!   cargo bench -p encrypted-spaces-ff-test --bench action_cycle_benchmarks
//!
//! Coverage (paired primitive / action):
//!   - pure_insert        : action with 1 insert leg and no asserts vs primitive insert
//!   - exists_insert      : action with 1 insert leg + 1 `exists()` assert vs primitive insert
//!   - cascade_delete     : action with 1 delete + 1 cascade_delete leg vs primitive single delete
//!   - unchanged_update   : action with 2 `unchanged()` asserts vs primitive update

use criterion::{
    criterion_group, criterion_main,
    measurement::{Measurement, ValueFormatter},
    Criterion, Throughput,
};

use async_trait::async_trait;
use encrypted_spaces_acl_types::{
    AccessRule, Action, ActionLeg, Assertion, ColumnNamespace, ComparisonOp, RuleValue,
};
use encrypted_spaces_backend::{
    access_control::AuthContext,
    error::{Result as BackendResult, SdkError},
    merk_storage::proofs::VerifiedRows,
    query::{Query, QueryParam},
    SpaceId,
};
use encrypted_spaces_backend_server::app_config::{BootstrapDataSource, SpaceInitConfig};
use encrypted_spaces_backend_server::SpaceState;
use encrypted_spaces_changelog_core::changelog::{Change, ChangeResponse, FastForwardData};
use encrypted_spaces_changelog_core::{create_trace, encode_pruned_compact};
use encrypted_spaces_ffproof::common::FFProof;
use encrypted_spaces_ffproof::prover::{extract_input_steps, prove_ff_chunk};
use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest};
use encrypted_spaces_sdk::{
    schema::{ApplicationSchema, ColumnType, SchemaBuilder},
    transport::{EphemeralReceiver, Transport},
    Space,
};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

// ─── Stderr suppression ────────────────────────────────────────────────────

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

// ─── ZkvmCycles measurement ────────────────────────────────────────────────

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
            Throughput::Elements(n) => format!("{:.0} cycles/elem", value / *n as f64),
            Throughput::Bytes(n) | Throughput::BytesDecimal(n) => {
                format!("{:.2} cycles/byte", value / *n as f64)
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

// ─── SharedStateTransport ──────────────────────────────────────────────────

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

#[async_trait]
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
        schemas: &HashMap<String, encrypted_spaces_backend::schema::Schema>,
    ) -> BackendResult<VerifiedRows> {
        let state = self.state.lock().await;
        let select_response = state.handle_select(&query, commitment).await?;
        encrypted_spaces_backend::merk_storage::proofs::verify_query_proof_with_hashed_values(
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
            .map_err(|e| SdkError::DatabaseError(format!("add_member failed: {e}")))
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
            .map_err(|e| SdkError::DatabaseError(format!("remove_member failed: {e}")))
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
            .map_err(|e| SdkError::DatabaseError(format!("submit_retention failed: {e}")))
    }

    async fn authenticate(&self, auth_context: &AuthContext) -> BackendResult<()> {
        *self.auth_context.lock().await = auth_context.clone();
        Ok(())
    }

    async fn send_ephemeral(&self, _uid: u32, _kind: &str, _payload: &[u8]) -> BackendResult<()> {
        Ok(())
    }

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

// ─── FF-prover invocation ──────────────────────────────────────────────────

async fn prove_pending_and_get_cycles(state: &Arc<Mutex<SpaceState>>) -> u64 {
    let mut state = state.lock().await;
    let start_idx = state.changelog.proven_up_to;
    let num_changes = state.changelog.num_changes() as usize;
    if start_idx >= num_changes {
        return 0;
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
    let _quiet = SuppressStderr::new();
    let (proof, stats) = prove_ff_chunk(
        state.ff_proof.as_ref(),
        &state.changelog,
        &state.change_responses,
        start_idx,
        tracer_proof_bytes,
    );
    drop(_quiet);

    state.changelog.set_ff_proof(proof.serialize(), num_changes);
    state.ff_proof = FFProof::deserialize(&state.changelog.ff_proof).ok();

    stats.user_cycles
}

// ─── Schema + actions ──────────────────────────────────────────────────────

fn schemas() -> Vec<encrypted_spaces_backend::schema::Schema> {
    let parents = SchemaBuilder::new("parents")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("name", ColumnType::String)
        .unwrap()
        .column("category", ColumnType::String)
        .unwrap()
        .column("value", ColumnType::Integer)
        .unwrap()
        .build()
        .unwrap();

    let children = SchemaBuilder::new("children")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("parent_id", ColumnType::Integer)
        .unwrap()
        .plaintext()
        .index()
        .column("body", ColumnType::String)
        .unwrap()
        .build()
        .unwrap();

    vec![parents, children]
}

fn actions() -> Vec<Action> {
    vec![
        Action {
            name: "passthrough_insert_parent".into(),
            legs: vec![ActionLeg::Insert {
                table: "parents".into(),
            }],
            asserts: vec![],
        },
        Action {
            name: "exists_insert_child".into(),
            legs: vec![ActionLeg::Insert {
                table: "children".into(),
            }],
            asserts: vec![Assertion::Exists {
                table: "parents".into(),
                predicate: AccessRule::comparison(
                    RuleValue::column(ColumnNamespace::Resource, "id"),
                    ComparisonOp::Equal,
                    RuleValue::column(ColumnNamespace::SelfRow, "parent_id"),
                ),
            }],
        },
        Action {
            name: "cascade_delete_parent".into(),
            legs: vec![
                ActionLeg::Delete {
                    table: "parents".into(),
                },
                ActionLeg::CascadeDelete {
                    table: "children".into(),
                    where_column: "parent_id".into(),
                    where_self_column: "id".into(),
                },
            ],
            asserts: vec![],
        },
        Action {
            name: "unchanged_update_parent".into(),
            legs: vec![ActionLeg::Update {
                table: "parents".into(),
                cols: Some(vec!["value".into()]),
            }],
            asserts: vec![],
        },
    ]
}

// ─── Domain types ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Parent {
    id: Option<i64>,
    name: String,
    category: String,
    value: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Child {
    id: Option<i64>,
    parent_id: i64,
    body: String,
}

// ─── Bench parameters ──────────────────────────────────────────────────────

const PREPOPULATE_PARENTS: usize = 100;
const CASCADE_CHILDREN: usize = 3;
/// Batch size for the multi-op variants.  N ops drive one FF-prover
/// call, and we report `total_cycles / N` so the per-batch fixed
/// overhead amortizes.  This is closer to the production per-op cost
/// than the 1-op-per-prove baseline labels.
const MULTI_OP_BATCH: usize = 20;

const LABELS: &[&str] = &[
    "primitive_insert_parent",
    "passthrough_insert_parent",
    "primitive_insert_child",
    "exists_insert_child",
    "primitive_update_parent",
    "unchanged_update_parent",
    "primitive_delete_parent",
    "cascade_delete_parent",
    "primitive_4delete_parent",
    // Multi-op batch variants.  Total cycles for N ops; divide by N
    // for the marginal-per-op estimate.
    "primitive_insert_parent_x20",
    "passthrough_insert_parent_x20",
    "primitive_insert_child_x20",
    "exists_insert_child_x20",
    "primitive_update_parent_x20",
    "unchanged_update_parent_x20",
    "primitive_delete_parent_x20",
    "cascade_delete_parent_x20",
];

/// Display pairs: (primitive, action).  The fair-cascade pair compares
/// the action against four batched primitive deletes (parent + 3
/// children) rather than the single-delete baseline.
const PAIRS: &[(&str, &str)] = &[
    ("primitive_insert_parent", "passthrough_insert_parent"),
    ("primitive_insert_child", "exists_insert_child"),
    ("primitive_update_parent", "unchanged_update_parent"),
    ("primitive_delete_parent", "cascade_delete_parent"),
    ("primitive_4delete_parent", "cascade_delete_parent"),
];

/// Multi-op batch pairs.  The reported metric is the total batch's
/// cycles divided by `MULTI_OP_BATCH` so per-prove fixed overhead is
/// amortized across N ops.
const BATCH_PAIRS: &[(&str, &str)] = &[
    (
        "primitive_insert_parent_x20",
        "passthrough_insert_parent_x20",
    ),
    ("primitive_insert_child_x20", "exists_insert_child_x20"),
    ("primitive_update_parent_x20", "unchanged_update_parent_x20"),
    ("primitive_delete_parent_x20", "cascade_delete_parent_x20"),
];

// ─── Fixture ───────────────────────────────────────────────────────────────

struct CycleFixture {
    cycles: HashMap<&'static str, u64>,
}

fn cycle_fixture() -> &'static CycleFixture {
    static FIXTURE: OnceLock<CycleFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(build_fixture())
    })
}

async fn build_fixture() -> CycleFixture {
    let t0 = std::time::Instant::now();
    let schema_list = schemas();
    let init_cfg = SpaceInitConfig {
        space_id: SpaceId::from([0u8; 16]),
        artifact_path: None,
        verbose_logfile: None,
        bootstrap_data: BootstrapDataSource::None,
    };
    let mut state_raw =
        SpaceState::init_server(Some(&schema_list), Some(init_cfg), Some(1_000_000_000))
            .await
            .expect("init_server");

    // Import actions (no gating in this bench), then re-anchor the
    // changelog to the post-import root so the SDK's initial DC lines
    // up with what the server uses.
    state_raw
        .db
        .import_actions(&actions())
        .await
        .expect("import_actions");
    state_raw
        .db
        .import_acl_only_via_actions(&BTreeMap::new())
        .await
        .expect("import_acl_only_via_actions");
    state_raw
        .reinitialize_changelog()
        .await
        .expect("reinitialize_changelog");
    state_raw.tree_snapshot = state_raw.db.snapshot();
    let app_root = state_raw.db.root_hash();

    let state = Arc::new(Mutex::new(state_raw));
    let app_schema = ApplicationSchema::for_testing(schema_list.clone(), app_root);

    eprintln!("[setup] Space::create");
    let space = Space::create(SharedStateTransport::new(Arc::clone(&state)), app_schema)
        .await
        .expect("Space::create");
    for a in actions() {
        space.register_action(a);
    }

    let mut cycles: HashMap<&'static str, u64> = HashMap::new();
    let _create_cycles = prove_pending_and_get_cycles(&state).await;

    let parents = space.table::<Parent>("parents");
    let children = space.table::<Child>("children");

    eprintln!("[setup] pre-populating {PREPOPULATE_PARENTS} parents");
    let mut parent_ids = Vec::with_capacity(PREPOPULATE_PARENTS);
    for i in 0..PREPOPULATE_PARENTS {
        let id = parents
            .insert(&Parent {
                id: None,
                name: format!("Parent{i}"),
                category: "default".into(),
                value: i as i64,
            })
            .execute()
            .await
            .expect("parent insert execute");
        parent_ids.push(id);
    }
    let _ = prove_pending_and_get_cycles(&state).await;
    eprintln!(
        "  [setup] {} parents in {:.2?}",
        parent_ids.len(),
        t0.elapsed()
    );

    // ─── Pure-dispatch overhead ──────────────────────────────────────────
    parents
        .insert(&Parent {
            id: None,
            name: "primitive-bench".into(),
            category: "default".into(),
            value: -1,
        })
        .execute()
        .await
        .expect("primitive insert execute");
    cycles.insert(
        "primitive_insert_parent",
        prove_pending_and_get_cycles(&state).await,
    );

    space
        .call_insert_action(
            "passthrough_insert_parent",
            vec![
                ("name".into(), QueryParam::Text("action-bench".into())),
                ("category".into(), QueryParam::Text("default".into())),
                ("value".into(), QueryParam::Integer(-2)),
            ],
        )
        .await
        .expect("passthrough action");
    cycles.insert(
        "passthrough_insert_parent",
        prove_pending_and_get_cycles(&state).await,
    );

    // ─── `exists()` cost ─────────────────────────────────────────────────
    let anchor_parent = parent_ids[0];
    children
        .insert(&Child {
            id: None,
            parent_id: anchor_parent,
            body: "primitive-child".into(),
        })
        .execute()
        .await
        .expect("primitive child insert execute");
    cycles.insert(
        "primitive_insert_child",
        prove_pending_and_get_cycles(&state).await,
    );

    space
        .call_insert_action(
            "exists_insert_child",
            vec![
                ("parent_id".into(), QueryParam::Integer(anchor_parent)),
                ("body".into(), QueryParam::Text("action-child".into())),
            ],
        )
        .await
        .expect("exists action");
    cycles.insert(
        "exists_insert_child",
        prove_pending_and_get_cycles(&state).await,
    );

    // ─── `unchanged()` cost ──────────────────────────────────────────────
    let primitive_update_target = parent_ids[PREPOPULATE_PARENTS / 10];
    let action_update_target = parent_ids[PREPOPULATE_PARENTS / 5];
    parents
        .update()
        .set("value", 4242_i64)
        .where_eq("id", primitive_update_target)
        .execute()
        .await
        .expect("primitive update");
    cycles.insert(
        "primitive_update_parent",
        prove_pending_and_get_cycles(&state).await,
    );

    space
        .call_update_action(
            "unchanged_update_parent",
            action_update_target,
            vec![("value".into(), QueryParam::Integer(7777))],
        )
        .await
        .expect("unchanged action");
    cycles.insert(
        "unchanged_update_parent",
        prove_pending_and_get_cycles(&state).await,
    );

    // ─── Cascade-delete cost ─────────────────────────────────────────────
    let primitive_delete_target = parent_ids[(PREPOPULATE_PARENTS * 3) / 10];
    let cascade_delete_target = parent_ids[(PREPOPULATE_PARENTS * 2) / 5];
    let primitive_4delete_target = parent_ids[PREPOPULATE_PARENTS / 2];
    for j in 0..CASCADE_CHILDREN {
        children
            .insert(&Child {
                id: None,
                parent_id: cascade_delete_target,
                body: format!("seed-cascade-{j}"),
            })
            .execute()
            .await
            .expect("seed cascade child execute");
    }
    let mut primitive_4delete_child_ids = Vec::with_capacity(CASCADE_CHILDREN);
    for j in 0..CASCADE_CHILDREN {
        let id = children
            .insert(&Child {
                id: None,
                parent_id: primitive_4delete_target,
                body: format!("seed-4delete-{j}"),
            })
            .execute()
            .await
            .expect("seed 4delete child execute");
        primitive_4delete_child_ids.push(id);
    }
    let _ = prove_pending_and_get_cycles(&state).await;

    parents
        .delete()
        .where_eq("id", primitive_delete_target)
        .execute()
        .await
        .expect("primitive delete");
    cycles.insert(
        "primitive_delete_parent",
        prove_pending_and_get_cycles(&state).await,
    );

    space
        .call_delete_action("cascade_delete_parent", cascade_delete_target)
        .await
        .expect("cascade action");
    cycles.insert(
        "cascade_delete_parent",
        prove_pending_and_get_cycles(&state).await,
    );

    // Fair comparison: 4 primitive deletes (parent + 3 children) proved
    // together in a single FF-prover invocation.  The prover handles
    // multiple pending changes as one batch.
    for child_id in &primitive_4delete_child_ids {
        children
            .delete()
            .where_eq("id", *child_id)
            .execute()
            .await
            .expect("primitive 4delete child");
    }
    parents
        .delete()
        .where_eq("id", primitive_4delete_target)
        .execute()
        .await
        .expect("primitive 4delete parent");
    cycles.insert(
        "primitive_4delete_parent",
        prove_pending_and_get_cycles(&state).await,
    );

    // ─── Multi-op batch overhead ─────────────────────────────────────────
    // N ops, single prove call.  Recorded total is divided by N for
    // the marginal-per-op estimate in the summary table.
    eprintln!("[setup] x{MULTI_OP_BATCH} batch runs");

    let mut batch_primitive_parent_ids = Vec::with_capacity(MULTI_OP_BATCH);
    for i in 0..MULTI_OP_BATCH {
        let id = parents
            .insert(&Parent {
                id: None,
                name: format!("primitive-batch-{i}"),
                category: "default".into(),
                value: 1_000 + i as i64,
            })
            .execute()
            .await
            .expect("primitive insert batch execute");
        batch_primitive_parent_ids.push(id);
    }
    cycles.insert(
        "primitive_insert_parent_x20",
        prove_pending_and_get_cycles(&state).await,
    );

    let mut batch_action_parent_ids = Vec::with_capacity(MULTI_OP_BATCH);
    for i in 0..MULTI_OP_BATCH {
        let id = space
            .call_insert_action(
                "passthrough_insert_parent",
                vec![
                    ("name".into(), QueryParam::Text(format!("action-batch-{i}"))),
                    ("category".into(), QueryParam::Text("default".into())),
                    ("value".into(), QueryParam::Integer(2_000 + i as i64)),
                ],
            )
            .await
            .expect("passthrough action batch");
        batch_action_parent_ids.push(id);
    }
    cycles.insert(
        "passthrough_insert_parent_x20",
        prove_pending_and_get_cycles(&state).await,
    );

    for i in 0..MULTI_OP_BATCH {
        children
            .insert(&Child {
                id: None,
                parent_id: anchor_parent,
                body: format!("primitive-child-batch-{i}"),
            })
            .execute()
            .await
            .expect("primitive child batch execute");
    }
    cycles.insert(
        "primitive_insert_child_x20",
        prove_pending_and_get_cycles(&state).await,
    );

    for i in 0..MULTI_OP_BATCH {
        space
            .call_insert_action(
                "exists_insert_child",
                vec![
                    ("parent_id".into(), QueryParam::Integer(anchor_parent)),
                    (
                        "body".into(),
                        QueryParam::Text(format!("action-child-batch-{i}")),
                    ),
                ],
            )
            .await
            .expect("exists action batch");
    }
    cycles.insert(
        "exists_insert_child_x20",
        prove_pending_and_get_cycles(&state).await,
    );

    // Updates target distinct pre-populated parents to avoid overlap
    // with the 1-op baseline targets.
    for i in 0..MULTI_OP_BATCH {
        let target = parent_ids[(PREPOPULATE_PARENTS * 6) / 10 + i];
        parents
            .update()
            .set("value", 10_000 + i as i64)
            .where_eq("id", target)
            .execute()
            .await
            .expect("primitive update batch");
    }
    cycles.insert(
        "primitive_update_parent_x20",
        prove_pending_and_get_cycles(&state).await,
    );

    for i in 0..MULTI_OP_BATCH {
        let target = parent_ids[(PREPOPULATE_PARENTS * 8) / 10 + i];
        space
            .call_update_action(
                "unchanged_update_parent",
                target,
                vec![("value".into(), QueryParam::Integer(20_000 + i as i64))],
            )
            .await
            .expect("unchanged action batch");
    }
    cycles.insert(
        "unchanged_update_parent_x20",
        prove_pending_and_get_cycles(&state).await,
    );

    // Seed cascade children for the action-batch parents we'll delete
    // below.  Proven before the delete batch so the delete's recorded
    // cycles only cover the delete work.
    for &parent_id in &batch_action_parent_ids {
        for j in 0..CASCADE_CHILDREN {
            children
                .insert(&Child {
                    id: None,
                    parent_id,
                    body: format!("seed-cascade-batch-{parent_id}-{j}"),
                })
                .execute()
                .await
                .expect("seed cascade-batch child execute");
        }
    }
    let _ = prove_pending_and_get_cycles(&state).await;

    for &id in &batch_primitive_parent_ids {
        parents
            .delete()
            .where_eq("id", id)
            .execute()
            .await
            .expect("primitive delete batch");
    }
    cycles.insert(
        "primitive_delete_parent_x20",
        prove_pending_and_get_cycles(&state).await,
    );

    for &id in &batch_action_parent_ids {
        space
            .call_delete_action("cascade_delete_parent", id)
            .await
            .expect("cascade action batch");
    }
    cycles.insert(
        "cascade_delete_parent_x20",
        prove_pending_and_get_cycles(&state).await,
    );

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

    eprintln!("[setup] DONE in {:.2?}. Recorded cycles:", t0.elapsed());
    eprintln!("  1-op-per-prove (per-batch overhead included):");
    for (primitive, action) in PAIRS {
        let p = cycles.get(primitive).copied().unwrap_or(0);
        let r = cycles.get(action).copied().unwrap_or(0);
        let delta = r as i64 - p as i64;
        let delta_pct = if p > 0 {
            (delta as f64 / p as f64) * 100.0
        } else {
            0.0
        };
        let signed_delta = if delta >= 0 {
            format!("+{}", fmt_c(delta as u64))
        } else {
            format!("-{}", fmt_c(delta.unsigned_abs()))
        };
        eprintln!(
            "    {:>26}: {:>12}    {:>26}: {:>12}    Δ {:>12} ({:+.1}%)",
            primitive,
            fmt_c(p),
            action,
            fmt_c(r),
            signed_delta,
            delta_pct
        );
    }
    eprintln!(
        "  Marginal per-op (total batch cycles / {} ops):",
        MULTI_OP_BATCH
    );
    for (primitive, action) in BATCH_PAIRS {
        let p_total = cycles.get(primitive).copied().unwrap_or(0);
        let r_total = cycles.get(action).copied().unwrap_or(0);
        let p = p_total / MULTI_OP_BATCH as u64;
        let r = r_total / MULTI_OP_BATCH as u64;
        let delta = r as i64 - p as i64;
        let delta_pct = if p > 0 {
            (delta as f64 / p as f64) * 100.0
        } else {
            0.0
        };
        let signed_delta = if delta >= 0 {
            format!("+{}", fmt_c(delta as u64))
        } else {
            format!("-{}", fmt_c(delta.unsigned_abs()))
        };
        eprintln!(
            "    {:>26}: {:>12}    {:>26}: {:>12}    Δ {:>12} ({:+.1}%)",
            primitive,
            fmt_c(p),
            action,
            fmt_c(r),
            signed_delta,
            delta_pct
        );
    }

    CycleFixture { cycles }
}

// ─── Benchmarks ────────────────────────────────────────────────────────────

fn bench_all(c: &mut Criterion<ZkvmCycles>) {
    let mut group = c.benchmark_group("action_cycles");
    for &label in LABELS {
        let bench_name = format!("{label}_P{PREPOPULATE_PARENTS}");
        if label.ends_with("_x20") {
            group.throughput(Throughput::Elements(MULTI_OP_BATCH as u64));
        } else {
            group.throughput(Throughput::Elements(1));
        }
        let mut cached: Option<u64> = None;
        group.bench_function(&bench_name, |b| {
            b.iter_custom(|iters| {
                let v = *cached.get_or_insert_with(|| {
                    let v = cycle_fixture()
                        .cycles
                        .get(label)
                        .copied()
                        .unwrap_or_else(|| panic!("missing cycles for label '{label}'"));
                    let t = std::time::Instant::now();
                    while t.elapsed() < std::time::Duration::from_millis(10) {
                        std::hint::spin_loop();
                    }
                    v
                });
                v * iters
            });
        });
    }
    group.finish();
}

// ─── Criterion plumbing ────────────────────────────────────────────────────

fn zkvm_cycles_criterion() -> Criterion<ZkvmCycles> {
    std::env::set_var("RISC0_DEV_MODE", "1");
    std::env::remove_var("RISC0_INFO");
    std::env::set_var("RUST_LOG", "error");
    std::env::set_var("RISC0_GUEST_LOGFILE", "/dev/null");

    Criterion::default()
        .with_measurement(ZkvmCycles)
        .sample_size(10)
        .nresamples(10)
        .warm_up_time(std::time::Duration::from_millis(1))
        .measurement_time(std::time::Duration::from_millis(1))
        .significance_level(0.0001)
        .noise_threshold(1.0)
}

criterion_group! {
    name = action_cycle_benchmarks;
    config = zkvm_cycles_criterion();
    targets = bench_all
}

criterion_main!(action_cycle_benchmarks);
