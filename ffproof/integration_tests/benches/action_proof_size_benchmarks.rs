//! Size benchmarks comparing primitive ops against action-routed ops.
//!
//! Each measured op is run once during a one-shot setup; the
//! `LabelRecorder` transport keys the resulting `pruned_merkle_tree.len()`
//! by a caller-supplied label so paired primitive / action entries
//! can be compared head-to-head.
//!
//! Run with:
//!   cargo bench -p encrypted-spaces-ff-test --bench action_proof_size_benchmarks
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
    error::Result as BackendResult,
    merk_storage::proofs::VerifiedRows,
    query::{Query, QueryParam},
};
use encrypted_spaces_changelog_core::changelog::{Change, ChangeResponse, FastForwardData};
use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest};
use encrypted_spaces_sdk::{
    local_transport::LocalTransport,
    schema::{ApplicationSchema, ColumnType, SchemaBuilder},
    transport::{EphemeralReceiver, Transport},
    Space,
};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex, OnceLock};

// ─── Stdio suppression ──────────────────────────────────────────────────────

struct SuppressStdio {
    saved_stdout: i32,
    saved_stderr: i32,
}

impl SuppressStdio {
    fn new() -> Self {
        let saved_stdout = unsafe { libc::dup(1) };
        let saved_stderr = unsafe { libc::dup(2) };
        let devnull = std::fs::File::open("/dev/null").expect("open /dev/null");
        unsafe {
            libc::dup2(devnull.as_raw_fd(), 1);
            libc::dup2(devnull.as_raw_fd(), 2);
        }
        Self {
            saved_stdout,
            saved_stderr,
        }
    }
}

impl Drop for SuppressStdio {
    fn drop(&mut self) {
        unsafe {
            libc::dup2(self.saved_stdout, 1);
            libc::dup2(self.saved_stderr, 2);
            libc::close(self.saved_stdout);
            libc::close(self.saved_stderr);
        }
    }
}

// ─── ProofBytes measurement ────────────────────────────────────────────────

struct ProofBytes;
struct BytesFormatter;

impl ValueFormatter for BytesFormatter {
    fn format_value(&self, value: f64) -> String {
        if value >= 1_048_576.0 {
            format!("{:.2} MiB", value / 1_048_576.0)
        } else if value >= 1024.0 {
            format!("{:.2} KiB", value / 1024.0)
        } else {
            format!("{:.0} B", value)
        }
    }
    fn format_throughput(&self, throughput: &Throughput, value: f64) -> String {
        match throughput {
            Throughput::Elements(n) => format!("{:.0} B/elem", value / *n as f64),
            Throughput::Bytes(n) | Throughput::BytesDecimal(n) => {
                format!("{:.2} ratio", value / *n as f64)
            }
        }
    }
    fn scale_values(&self, _typical_value: f64, _values: &mut [f64]) -> &'static str {
        "B"
    }
    fn scale_throughputs(
        &self,
        _typical_value: f64,
        _throughput: &Throughput,
        _values: &mut [f64],
    ) -> &'static str {
        "B/elem"
    }
    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "B"
    }
}

impl Measurement for ProofBytes {
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
        &BytesFormatter
    }
}

// ─── Label-keyed recording transport ───────────────────────────────────────

type SizeMap = Arc<Mutex<HashMap<String, usize>>>;

/// Wraps a `LocalTransport`.  When `active_label` is `Some(label)`, the
/// next `submit_change`'s `pruned_merkle_tree.len()` is recorded under that
/// label.  Callers set the label immediately before the measured op.
struct LabelRecorder {
    inner: LocalTransport,
    active_label: Arc<Mutex<Option<String>>>,
    sizes: SizeMap,
}

impl LabelRecorder {
    fn record(&self, response: &ChangeResponse) {
        if let Some(label) = self.active_label.lock().unwrap().clone() {
            *self.sizes.lock().unwrap().entry(label).or_insert(0) +=
                response.pruned_merkle_tree.len();
        }
    }
}

#[async_trait]
impl Transport for LabelRecorder {
    async fn submit_change(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> BackendResult<ChangeResponse> {
        let response = self.inner.submit_change(change, retention_proofs).await?;
        self.record(&response);
        Ok(response)
    }

    async fn fast_forward(&self, change_id: u32) -> BackendResult<FastForwardData> {
        self.inner.fast_forward(change_id).await
    }

    async fn select(
        &self,
        query: Query,
        commitment: &[u8; 32],
        schemas: &std::collections::HashMap<String, encrypted_spaces_backend::schema::Schema>,
    ) -> BackendResult<VerifiedRows> {
        self.inner.select(query, commitment, schemas).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn fetch_my_key_delivery(&self) -> BackendResult<Option<Vec<u8>>> {
        self.inner.fetch_my_key_delivery().await
    }

    async fn add_member(
        &self,
        request: InviteRequest,
        insert_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> BackendResult<ChangeResponse> {
        let response = self
            .inner
            .add_member(request, insert_change, retention_proofs)
            .await?;
        self.record(&response);
        Ok(response)
    }

    async fn remove_member(
        &self,
        request: RekeyRequest,
        remaining_uids: &[i64],
        delete_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> BackendResult<ChangeResponse> {
        let response = self
            .inner
            .remove_member(request, remaining_uids, delete_change, retention_proofs)
            .await?;
        self.record(&response);
        Ok(response)
    }

    async fn submit_retention(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
        rekey_request: Option<RekeyRequest>,
    ) -> BackendResult<ChangeResponse> {
        let response = self
            .inner
            .submit_retention(change, retention_proofs, rekey_request)
            .await?;
        self.record(&response);
        Ok(response)
    }

    async fn authenticate(&self, auth_context: &AuthContext) -> BackendResult<()> {
        self.inner.authenticate(auth_context).await
    }

    async fn send_ephemeral(&self, uid: u32, kind: &str, payload: &[u8]) -> BackendResult<()> {
        self.inner.send_ephemeral(uid, kind, payload).await
    }

    fn subscribe_ephemeral(&self) -> BackendResult<EphemeralReceiver> {
        self.inner.subscribe_ephemeral()
    }

    async fn file_upload(&self, hash: &str, data: Vec<u8>) -> BackendResult<()> {
        self.inner.file_upload(hash, data).await
    }

    async fn file_download(&self, hash: &str) -> BackendResult<Vec<u8>> {
        self.inner.file_download(hash).await
    }
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

const PREPOPULATE_PARENTS: usize = 1_000;
const CASCADE_CHILDREN: usize = 3;

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

// ─── Fixture ───────────────────────────────────────────────────────────────

struct Fixture {
    sizes: HashMap<&'static str, usize>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(build_fixture())
    })
}

async fn build_fixture() -> Fixture {
    let t0 = std::time::Instant::now();
    let schema_list = schemas();
    let inner = LocalTransport::new(&schema_list, None, None)
        .await
        .expect("LocalTransport::new");

    let action_list = actions();
    inner
        .import_actions(&action_list, &BTreeMap::new())
        .await
        .expect("import_actions");

    let app_root = inner.get_root_hash().await.expect("root");
    let app_schema = ApplicationSchema::for_testing(schema_list.clone(), app_root);

    let sizes: SizeMap = Arc::new(Mutex::new(HashMap::new()));
    let active_label: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let transport = LabelRecorder {
        inner: inner.clone(),
        active_label: Arc::clone(&active_label),
        sizes: Arc::clone(&sizes),
    };

    eprintln!("[setup] Space::create");
    let space = Space::create(transport, app_schema)
        .await
        .expect("Space::create");
    for a in &action_list {
        space.register_action(a.clone());
    }

    let parents = space.table::<Parent>("parents");
    let children = space.table::<Child>("children");

    // Pre-populate parents.  Sizes scale ~logarithmically in tree
    // depth, so this brings the tree to a representative depth before
    // any measurement.
    eprintln!("[setup] pre-populating {PREPOPULATE_PARENTS} parents");
    let mut parent_ids = Vec::with_capacity(PREPOPULATE_PARENTS);
    for i in 0..PREPOPULATE_PARENTS {
        let id = {
            let _quiet = SuppressStdio::new();
            parents
                .insert(&Parent {
                    id: None,
                    name: format!("Parent{i}"),
                    category: "default".into(),
                    value: i as i64,
                })
                .execute()
                .await
                .expect("parent insert execute")
        };
        parent_ids.push(id);
        if (i + 1) % 200 == 0 || i + 1 == PREPOPULATE_PARENTS {
            eprintln!(
                "  [setup] {}/{} parents ({:.2?})",
                i + 1,
                PREPOPULATE_PARENTS,
                t0.elapsed()
            );
        }
    }

    let set_label = |label: &str| {
        *active_label.lock().unwrap() = Some(label.to_string());
    };
    let clear_label = || {
        *active_label.lock().unwrap() = None;
    };

    // ─── Pure-dispatch overhead: primitive vs 1-leg passthrough action ───
    set_label("primitive_insert_parent");
    {
        let _quiet = SuppressStdio::new();
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
    }
    clear_label();

    set_label("passthrough_insert_parent");
    {
        let _quiet = SuppressStdio::new();
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
    }
    clear_label();

    // ─── `exists()` cost: primitive child insert vs action with one exists ──
    // Anchor against a real parent so `exists_insert_child` resolves.
    let anchor_parent = parent_ids[0];
    set_label("primitive_insert_child");
    {
        let _quiet = SuppressStdio::new();
        children
            .insert(&Child {
                id: None,
                parent_id: anchor_parent,
                body: "primitive-child".into(),
            })
            .execute()
            .await
            .expect("primitive child insert execute");
    }
    clear_label();

    set_label("exists_insert_child");
    {
        let _quiet = SuppressStdio::new();
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
    }
    clear_label();

    // ─── `unchanged()` cost: primitive update vs action update with asserts ─
    let primitive_update_target = parent_ids[PREPOPULATE_PARENTS / 10];
    let action_update_target = parent_ids[PREPOPULATE_PARENTS / 5];
    set_label("primitive_update_parent");
    {
        let _quiet = SuppressStdio::new();
        parents
            .update()
            .set("value", 4242_i64)
            .where_eq("id", primitive_update_target)
            .execute()
            .await
            .expect("primitive update");
    }
    clear_label();

    set_label("unchanged_update_parent");
    {
        let _quiet = SuppressStdio::new();
        space
            .call_update_action(
                "unchanged_update_parent",
                action_update_target,
                vec![("value".into(), QueryParam::Integer(7777))],
            )
            .await
            .expect("unchanged action");
    }
    clear_label();

    // ─── Cascade-delete: primitive single delete vs action with cascade leg ──
    // Seed children for the action-deleted parent so the cascade leg has
    // FK matches.
    let primitive_delete_target = parent_ids[(PREPOPULATE_PARENTS * 3) / 10];
    let cascade_delete_target = parent_ids[(PREPOPULATE_PARENTS * 2) / 5];
    let primitive_4delete_target = parent_ids[PREPOPULATE_PARENTS / 2];
    for j in 0..CASCADE_CHILDREN {
        let _quiet = SuppressStdio::new();
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

    // Seed children for the 4-delete baseline.  Record their ids so we
    // can delete them by primary key without a secondary-index lookup.
    let mut primitive_4delete_child_ids = Vec::with_capacity(CASCADE_CHILDREN);
    for j in 0..CASCADE_CHILDREN {
        let _quiet = SuppressStdio::new();
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

    set_label("primitive_delete_parent");
    {
        let _quiet = SuppressStdio::new();
        parents
            .delete()
            .where_eq("id", primitive_delete_target)
            .execute()
            .await
            .expect("primitive delete");
    }
    clear_label();

    set_label("cascade_delete_parent");
    {
        let _quiet = SuppressStdio::new();
        space
            .call_delete_action("cascade_delete_parent", cascade_delete_target)
            .await
            .expect("cascade action");
    }
    clear_label();

    // Fair comparison: 4 primitive deletes (parent + 3 children) sharing
    // one label so the recorder accumulates the sum.
    set_label("primitive_4delete_parent");
    for child_id in &primitive_4delete_child_ids {
        let _quiet = SuppressStdio::new();
        children
            .delete()
            .where_eq("id", *child_id)
            .execute()
            .await
            .expect("primitive 4delete child");
    }
    {
        let _quiet = SuppressStdio::new();
        parents
            .delete()
            .where_eq("id", primitive_4delete_target)
            .execute()
            .await
            .expect("primitive 4delete parent");
    }
    clear_label();

    let raw = sizes.lock().unwrap().clone();
    let mut by_label: HashMap<&'static str, usize> = HashMap::new();
    for &label in LABELS {
        if let Some(&n) = raw.get(label) {
            by_label.insert(label, n);
        }
    }

    eprintln!("[setup] DONE in {:.2?}. Recorded sizes:", t0.elapsed());
    for (primitive, action) in PAIRS {
        let p_size = by_label.get(primitive).copied();
        let r_size = by_label.get(action).copied();
        let delta = match (p_size, r_size) {
            (Some(p), Some(r)) => format!("Δ {:+} B", r as i64 - p as i64),
            _ => String::from("<missing>"),
        };
        eprintln!(
            "  {:>26}: {:>6} B    {:>26}: {:>6} B    {delta}",
            primitive,
            p_size.map(|n| n.to_string()).unwrap_or("?".into()),
            action,
            r_size.map(|n| n.to_string()).unwrap_or("?".into()),
        );
    }

    Fixture { sizes: by_label }
}

// ─── Benchmarks ────────────────────────────────────────────────────────────

fn bench_all(c: &mut Criterion<ProofBytes>) {
    for &label in LABELS {
        let bench_name = format!("action_proof_size/{label}_P{PREPOPULATE_PARENTS}");
        c.bench_function(&bench_name, |b| {
            b.iter_custom(|iters| {
                let n = fixture()
                    .sizes
                    .get(label)
                    .copied()
                    .unwrap_or_else(|| panic!("label '{label}' was not recorded during setup"));
                // One-shot setup; size is deterministic.  A 1ms pause
                // per sample keeps Criterion from picking absurd iter
                // counts.
                std::thread::sleep(std::time::Duration::from_millis(1));
                n as u64 * iters
            });
        });
    }
}

// ─── Criterion plumbing ────────────────────────────────────────────────────

fn proof_size_criterion() -> Criterion<ProofBytes> {
    std::env::set_var("RISC0_DEV_MODE", "1");
    std::env::remove_var("RISC0_INFO");
    std::env::set_var("RUST_LOG", "error");
    std::env::set_var("RISC0_GUEST_LOGFILE", "/dev/null");

    Criterion::default()
        .with_measurement(ProofBytes)
        .sample_size(10)
        .nresamples(10)
        .warm_up_time(std::time::Duration::from_millis(1))
        .measurement_time(std::time::Duration::from_millis(1))
        .significance_level(0.0001)
        .noise_threshold(1.0)
}

criterion_group! {
    name = action_proof_size_benchmarks;
    config = proof_size_criterion();
    targets = bench_all
}

criterion_main!(action_proof_size_benchmarks);
