//! Size benchmarks for **per-change pruned tree witnesses** broadcast by the
//! server to all online users after applying a change.
//!
//! `backend/src/merk_storage/proofs.rs` produces the bytes that go on the
//! wire as `ChangeResponse.pruned_merkle_tree`. These benches drive every
//! per-change op type through the SDK end-to-end against an
//! `Arc<dyn Transport>` that wraps `LocalTransport` and intercepts the
//! `ChangeResponse`s flowing back. The intercepted `pruned_merkle_tree.len()`
//! is recorded keyed by the entry's `OpType`, then surfaced by the
//! Criterion bench under a custom `ProofBytes` measurement.
//!
//! Run with:
//!   cargo bench -p encrypted-spaces-ff-test --bench update_proof_size_benchmarks
//!
//! Coverage:
//!   - CreateSpace, Insert, Update, Delete
//!   - InviteUser, RemoveUser, RefreshKeys (via Space::join)
//!   - Extend, Rekey, Reduce
//!   - ListAppend, ListInsert, ListUpdate, ListDelete
//!
//! All ops run **once** during a shared one-shot setup (so we can
//! exercise paths that mutate global state — e.g. RemoveUser, Rekey —
//! in a controlled order). Every Criterion bench then just replays the
//! recorded byte count for its op, since proof sizes are deterministic
//! for a given input.

use criterion::{
    criterion_group, criterion_main,
    measurement::{Measurement, ValueFormatter},
    Criterion, Throughput,
};

use async_trait::async_trait;
use encrypted_spaces_backend::{
    access_control::AuthContext,
    error::Result as BackendResult,
    merk_storage::{parse_key, proofs::VerifiedRows, ParsedKey},
    query::Query,
};
use encrypted_spaces_changelog_core::changelog::{
    Change, ChangeResponse, ChangelogEntry, FastForwardData, OpType,
};
use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest, SimpleKeyId};
use encrypted_spaces_sdk::{
    list::List,
    local_transport::LocalTransport,
    schema::{ApplicationSchema, ColumnType, SchemaBuilder},
    transport::{EphemeralReceiver, Transport},
    List as ListAlias, Space,
};
use ffproof_tracer_shared::PrunedMerkleTree;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, OnceLock};

const USERS_TABLE: &str = "_users";
const KEY_HISTORY_TABLE: &str = "_key_history";
// ─── Stderr suppression ──────────────────────────────────────────────────────
//
// Hides risc0's per-prove "WARNING: proving in dev mode..." messages during
// the heavy one-shot fixture build. Matches the pattern used by
// `action_cycle_benchmarks.rs`.

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

// ─── Custom Criterion Measurement: Proof bytes ───────────────────────────────

/// Criterion measurement reporting **proof size in bytes**.
///
/// Sizes are deterministic for a given input, so benches use
/// `iter_custom` and replay the recorded byte count multiplied by
/// `iters`.
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

// ─── Recorded sizes ──────────────────────────────────────────────────────────

/// Every per-change op type we want to benchmark. The order of variants
/// is the order the setup pipeline drives them.
#[derive(Clone, Copy)]
enum BenchOp {
    CreateSpace,
    CreateSpaceKeyHash,
    Insert,
    Update,
    Delete,
    ListAppend,
    ListInsert,
    ListUpdate,
    ListDelete,
    InviteUser,
    InviteUserKeyHash,
    RefreshKeys,
    RefreshKeysKeyHash,
    Extend,
    Rekey,
    Reduce,
    RemoveUser,
    RemoveUserKeyHash,
}

impl BenchOp {
    const ALL: &'static [BenchOp] = &[
        BenchOp::CreateSpace,
        BenchOp::CreateSpaceKeyHash,
        BenchOp::Insert,
        BenchOp::Update,
        BenchOp::Delete,
        BenchOp::ListAppend,
        BenchOp::ListInsert,
        BenchOp::ListUpdate,
        BenchOp::ListDelete,
        BenchOp::InviteUser,
        BenchOp::InviteUserKeyHash,
        BenchOp::RefreshKeys,
        BenchOp::RefreshKeysKeyHash,
        BenchOp::Extend,
        BenchOp::Rekey,
        BenchOp::Reduce,
        BenchOp::RemoveUser,
        BenchOp::RemoveUserKeyHash,
    ];

    fn label(self) -> &'static str {
        match self {
            BenchOp::CreateSpace => "create_space",
            BenchOp::CreateSpaceKeyHash => "create_space_key_hash",
            BenchOp::Insert => "insert",
            BenchOp::Update => "update",
            BenchOp::Delete => "delete",
            BenchOp::ListAppend => "list_append",
            BenchOp::ListInsert => "list_insert",
            BenchOp::ListUpdate => "list_update",
            BenchOp::ListDelete => "list_delete",
            BenchOp::InviteUser => "invite_user",
            BenchOp::InviteUserKeyHash => "invite_user_key_hash",
            BenchOp::RefreshKeys => "refresh_keys",
            BenchOp::RefreshKeysKeyHash => "refresh_keys_key_hash",
            BenchOp::Extend => "extend",
            BenchOp::Rekey => "rekey",
            BenchOp::Reduce => "reduce",
            BenchOp::RemoveUser => "remove_user",
            BenchOp::RemoveUserKeyHash => "remove_user_key_hash",
        }
    }

    fn op_type(self) -> OpType {
        match self {
            BenchOp::CreateSpace | BenchOp::CreateSpaceKeyHash => OpType::CreateSpace,
            BenchOp::Insert => OpType::Insert,
            BenchOp::Update => OpType::Update,
            BenchOp::Delete => OpType::Delete,
            BenchOp::ListAppend => OpType::ListAppend,
            BenchOp::ListInsert => OpType::ListInsert,
            BenchOp::ListUpdate => OpType::ListUpdate,
            BenchOp::ListDelete => OpType::ListDelete,
            BenchOp::InviteUser | BenchOp::InviteUserKeyHash => OpType::InviteUser,
            BenchOp::RefreshKeys | BenchOp::RefreshKeysKeyHash => OpType::RefreshKeys,
            BenchOp::Extend => OpType::Extend,
            BenchOp::Rekey => OpType::Rekey,
            BenchOp::Reduce => OpType::Reduce,
            BenchOp::RemoveUser | BenchOp::RemoveUserKeyHash => OpType::RemoveUser,
        }
    }
}

/// Map from `OpType as i32` to the most recent `pruned_merkle_tree.len()`
/// observed flowing back from the wrapped transport.
type SizeMap = Arc<Mutex<HashMap<i32, usize>>>;

/// Map from `OpType as i32` to the most recent raw pruned tree witness bytes.
/// Used by the post-setup breakdown dump.
type ProofMap = Arc<Mutex<HashMap<i32, Vec<u8>>>>;

/// Map from `OpType as i32` to the most recent originating `ChangelogEntry`.
/// Used to compare proof size against "just send the entry".
type EntryMap = Arc<Mutex<HashMap<i32, ChangelogEntry>>>;

fn record_response(
    sizes: &SizeMap,
    proofs: &ProofMap,
    entries: &EntryMap,
    change: &ChangelogEntry,
    response: &ChangeResponse,
) {
    let key = change.message.op_type as i32;
    sizes
        .lock()
        .unwrap()
        .insert(key, response.pruned_merkle_tree.len());
    proofs
        .lock()
        .unwrap()
        .insert(key, response.pruned_merkle_tree.clone());
    entries.lock().unwrap().insert(key, change.clone());
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

fn assert_recorded_internal_key_hash_entry(
    entries: &HashMap<i32, ChangelogEntry>,
    op_type: OpType,
    label: &str,
    expected_hash_columns: &[(&str, &str)],
) {
    let change = entries
        .get(&(op_type as i32))
        .unwrap_or_else(|| panic!("{label}: no {op_type:?} entry recorded"));
    for (table_name, column_name) in expected_hash_columns {
        assert_hash_ref_column(change, label, table_name, column_name);
    }
}

// ─── Recording transport wrapper ─────────────────────────────────────────────

/// Wraps a real `LocalTransport` and intercepts every `ChangeResponse`
/// flowing back, recording its pruned tree witness byte length keyed by the
/// originating `ChangelogEntry`'s `OpType`. All other transport methods
/// are forwarded verbatim.
///
/// `Space::create`, `Space::join`, `space.invite_user`, etc. all funnel
/// their writes through one of `submit_change`, `add_member`,
/// `remove_member`, or `submit_retention`, so this is the single place
/// per-change proofs cross the boundary.
struct RecordingTransport {
    inner: LocalTransport,
    sizes: SizeMap,
    proofs: ProofMap,
    entries: EntryMap,
}

#[async_trait]
impl Transport for RecordingTransport {
    async fn submit_change(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> BackendResult<ChangeResponse> {
        let response = self.inner.submit_change(change, retention_proofs).await?;
        record_response(
            &self.sizes,
            &self.proofs,
            &self.entries,
            &change.entry,
            &response,
        );
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
        // Expose ourselves rather than the inner LocalTransport — keeps
        // the recorder reachable via downcast if a caller needs it.
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
        record_response(
            &self.sizes,
            &self.proofs,
            &self.entries,
            &insert_change.entry,
            &response,
        );
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
        record_response(
            &self.sizes,
            &self.proofs,
            &self.entries,
            &delete_change.entry,
            &response,
        );
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
        record_response(
            &self.sizes,
            &self.proofs,
            &self.entries,
            &change.entry,
            &response,
        );
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

// ─── Bench parameters ────────────────────────────────────────────────────────

/// Number of `products` rows to seed before measuring CRUD ops, so the
/// merk tree is meaningfully deep. Each pre-population insert goes
/// through the SDK (encryption, query building, signing, transport),
/// so this is the dominant component of setup wall time. Logarithmic
/// in proof size, so a few thousand rows is already representative.
const PREPOPULATE_ROWS: usize = 1_000;

/// Number of list items to seed before measuring list ops. List ops'
/// proof size scales with the depth of the `_lists` side-tree path, so
/// we want at least a handful of pre-existing entries.
const PREPOPULATE_LIST_ITEMS: usize = 32;

// ─── Domain types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Product {
    id: Option<i64>,
    name: String,
    price: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Project {
    id: Option<i64>,
    name: String,
    tasks: List<Task>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Task {
    title: String,
    done: bool,
}

fn schemas() -> Vec<encrypted_spaces_backend::schema::Schema> {
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

// ─── One-shot setup driving every op ────────────────────────────────────────

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

    // Suppress risc0's per-prove "WARNING: proving in dev mode..." spam that
    // would otherwise repeat for each of the ~1000 pre-population inserts
    // plus every other setup op. Dropped just before the recorded-sizes
    // summary so that output is still visible.
    let quiet = SuppressStderr::new();

    let schemas = schemas();
    let inner = LocalTransport::new(&schemas, None, None)
        .await
        .expect("LocalTransport::new");
    let app_root = inner.get_root_hash().await.expect("root");
    let app_schema = ApplicationSchema::WithDataCommitment(
        schemas.clone(),
        app_root,
        encrypted_spaces_ffproof::EXTEND_FF_ID,
    );

    let sizes: SizeMap = Arc::new(Mutex::new(HashMap::new()));
    let proofs: ProofMap = Arc::new(Mutex::new(HashMap::new()));
    let entries: EntryMap = Arc::new(Mutex::new(HashMap::new()));
    let transport = RecordingTransport {
        inner: inner.clone(),
        sizes: Arc::clone(&sizes),
        proofs: Arc::clone(&proofs),
        entries: Arc::clone(&entries),
    };

    eprintln!("[setup] Space::create (CreateSpace)");
    let space = Space::create(transport, app_schema)
        .await
        .expect("Space::create");

    // ─── Insert: pre-populate products so the merk tree is deep ───────────
    eprintln!("[setup] pre-populating {PREPOPULATE_ROWS} products");
    let products = space.table::<Product>("products");
    let mut last_product_id: i64 = 0;
    for i in 0..PREPOPULATE_ROWS {
        last_product_id = products
            .insert(&Product {
                id: None,
                name: format!("Product{i}"),
                price: i as f64,
            })
            .execute()
            .await
            .expect("insert execute");
        if (i + 1) % 100 == 0 || i + 1 == PREPOPULATE_ROWS {
            eprintln!(
                "  [setup] {}/{} inserted ({:.2?})",
                i + 1,
                PREPOPULATE_ROWS,
                t0.elapsed()
            );
        }
    }

    // ─── Update / Delete: pick distinct existing rows ─────────────────────
    eprintln!("[setup] update product id=1");
    let update_target_id: i64 = 1;
    products
        .update()
        .set("name", "UpdatedName".to_string())
        .set("price", 999.0_f64)
        .where_eq("id", update_target_id)
        .execute()
        .await
        .expect("update execute");

    eprintln!("[setup] delete product id=2");
    products
        .delete()
        .where_eq("id", 2_i64)
        .execute()
        .await
        .expect("delete execute");
    let _ = last_product_id;

    // ─── Project + list ops ───────────────────────────────────────────────
    eprintln!("[setup] insert project + seed list");
    let projects = space.table::<Project>("projects");
    let project_id = projects
        .insert(&Project {
            id: None,
            name: "List Bench Project".into(),
            tasks: List::empty(),
        })
        .execute()
        .await
        .expect("project insert execute");

    let tasks: ListAlias<Task> = space.list::<Task>("projects", project_id, "tasks");
    let mut seeded_keys: Vec<Vec<u8>> = Vec::with_capacity(PREPOPULATE_LIST_ITEMS);
    for i in 0..PREPOPULATE_LIST_ITEMS {
        let key = tasks
            .append(&Task {
                title: format!("seed-{i}"),
                done: false,
            })
            .await
            .expect("seed list_append");
        seeded_keys.push(key);
    }

    eprintln!("[setup] list_append (measured)");
    let appended_key = tasks
        .append(&Task {
            title: "measured-append".into(),
            done: false,
        })
        .await
        .expect("list_append");

    eprintln!("[setup] list_insert (insert_after_key)");
    let inserted_key = tasks
        .insert_after_key(
            &seeded_keys[PREPOPULATE_LIST_ITEMS / 2],
            &Task {
                title: "measured-insert".into(),
                done: false,
            },
        )
        .await
        .expect("list_insert");

    eprintln!("[setup] list_update (update_by_key)");
    tasks
        .update_by_key(
            &appended_key,
            &Task {
                title: "measured-updated".into(),
                done: true,
            },
        )
        .await
        .expect("list_update");

    eprintln!("[setup] list_delete (delete_by_key)");
    tasks
        .delete_by_key(&inserted_key)
        .await
        .expect("list_delete");

    // ─── Retention ops ────────────────────────────────────────────────────
    // Order is significant: do `extend` twice + `reduce` first while the
    // key chain is still in its original linear shape, then `rekey` at the
    // end (rekey rotates the group key and changes the shape).
    eprintln!("[setup] extend (1/2)");
    space.extend().await.expect("extend 1");

    eprintln!("[setup] extend (2/2)");
    space.extend().await.expect("extend 2");

    eprintln!("[setup] reduce(SimpleKeyId(1))");
    space.reduce(SimpleKeyId(1)).await.expect("reduce");

    eprintln!("[setup] rekey");
    space.rekey().await.expect("rekey");

    // ─── User-management: invite + join (RefreshKeys) + remove ────────────
    eprintln!("[setup] invite_user (target for RefreshKeys)");
    let invite = space.invite_user().await.expect("invite_user 1");

    eprintln!("[setup] Space::join (drives RefreshKeys)");
    let join_app_schema = ApplicationSchema::WithDataCommitment(
        schemas.clone(),
        app_root,
        encrypted_spaces_ffproof::EXTEND_FF_ID,
    );
    // Joining piggybacks on the same underlying SpaceState. We construct
    // a *fresh* RecordingTransport over a clone of the LocalTransport so
    // it shares the Arc<Mutex<SpaceState>> of `inner`.
    let join_transport = RecordingTransport {
        inner: inner.clone(),
        sizes: Arc::clone(&sizes),
        proofs: Arc::clone(&proofs),
        entries: Arc::clone(&entries),
    };
    let _joined = Space::join(join_transport, invite, join_app_schema)
        .await
        .expect("Space::join");

    // After join the new user is Full. To exercise remove_user we need
    // another invite to remove (the first was already activated and is
    // a dependency-free remove target, but the SDK requires the host to
    // sync after a join so `_key_history` is up-to-date).
    space.sync().await.expect("sync after join");

    eprintln!("[setup] invite_user (target for RemoveUser)");
    let invite2 = space.invite_user().await.expect("invite_user 2");
    let remove_target_id = invite2.id().expect("invite2 has uid");

    eprintln!("[setup] remove_user uid={remove_target_id}");
    space
        .remove_user(remove_target_id)
        .await
        .expect("remove_user");

    // ─── Surface recorded sizes by label ──────────────────────────────────
    let raw = sizes.lock().unwrap().clone();
    let raw_entries = entries.lock().unwrap().clone();
    assert_recorded_internal_key_hash_entry(
        &raw_entries,
        OpType::CreateSpace,
        "create_space_key_hash",
        &[(USERS_TABLE, "auth_key"), (USERS_TABLE, "update_key")],
    );
    assert_recorded_internal_key_hash_entry(
        &raw_entries,
        OpType::InviteUser,
        "invite_user_key_hash",
        &[(USERS_TABLE, "auth_key"), (USERS_TABLE, "update_key")],
    );
    assert_recorded_internal_key_hash_entry(
        &raw_entries,
        OpType::RefreshKeys,
        "refresh_keys_key_hash",
        &[
            (KEY_HISTORY_TABLE, "old_auth_key"),
            (USERS_TABLE, "auth_key"),
            (USERS_TABLE, "update_key"),
        ],
    );
    assert_recorded_internal_key_hash_entry(
        &raw_entries,
        OpType::RemoveUser,
        "remove_user_key_hash",
        &[(KEY_HISTORY_TABLE, "old_auth_key")],
    );

    let mut by_label: HashMap<&'static str, usize> = HashMap::new();
    for op in BenchOp::ALL {
        if let Some(&n) = raw.get(&(op.op_type() as i32)) {
            by_label.insert(op.label(), n);
        }
    }

    // Release stderr so the summary and breakdown below are visible.
    drop(quiet);

    eprintln!("[setup] DONE in {:.2?}. Recorded sizes:", t0.elapsed());
    for op in BenchOp::ALL {
        match by_label.get(op.label()) {
            Some(n) => eprintln!("  {:>14}: {n} bytes", op.label()),
            None => eprintln!("  {:>14}: <NOT RECORDED>", op.label()),
        }
    }

    // ─── Detailed breakdown for the Insert proof ──────────────────────────
    if let Some(bytes) = proofs
        .lock()
        .unwrap()
        .get(&(OpType::Insert as i32))
        .cloned()
    {
        let entry = entries
            .lock()
            .unwrap()
            .get(&(OpType::Insert as i32))
            .cloned();
        dump_insert_breakdown(&bytes, entry.as_ref());
    }

    Fixture { sizes: by_label }
}

/// Decode a captured `Insert` pruned tree witness and dump a per-component
/// byte breakdown to stderr so we can see exactly where the bytes go.
fn dump_insert_breakdown(bytes: &[u8], entry: Option<&ChangelogEntry>) {
    eprintln!();
    eprintln!(
        "=== Insert pruned tree witness breakdown ({} bytes total) ===",
        bytes.len()
    );

    let pruned_tree = match postcard::from_bytes::<PrunedMerkleTree>(bytes) {
        Ok(tree) => tree,
        Err(e) => {
            eprintln!("  failed to deserialize: {e}");
            return;
        }
    };

    eprintln!(
        "  pruned_merkle_tree       : {:>6} B  ({} Full, {} Pruned nodes)",
        bytes.len(),
        pruned_tree.count_full(),
        pruned_tree.count_pruned(),
    );

    // Walk the pruned tree once and bucket the bytes spent on full vs pruned.
    let mut s = PrunedStats::default();
    walk_pruned(&pruned_tree, &mut s);
    eprintln!(
        "    Full nodes     : {} nodes, key bytes = {}, value bytes = {}",
        s.full_count, s.full_key_bytes, s.full_value_bytes
    );
    eprintln!("    Pruned nodes  : {} nodes, key bytes = {}, hash bytes = {} (={}*32), child_heights = {} (={}*2)",
        s.pruned_count, s.pruned_key_bytes, s.pruned_count*32, s.pruned_count, s.pruned_count*2, s.pruned_count);

    // ─── Classify Full nodes by tag/table ────────────────────────────────
    eprintln!();
    eprintln!("  --- Full-node value attribution ---");

    // Walk every Full node and bucket.
    let mut by_class: std::collections::BTreeMap<String, (usize, usize, usize)> =
        std::collections::BTreeMap::new();
    walk_classify(&pruned_tree, &mut by_class);

    eprintln!(
        "  {:<55} {:>5}  {:>7}  {:>8}",
        "class", "nodes", "key B", "value B"
    );
    let (mut tn, mut tk, mut tv) = (0usize, 0usize, 0usize);
    // Sort by descending value_bytes so the biggest contributors are at the top.
    let mut rows: Vec<(&String, &(usize, usize, usize))> = by_class.iter().collect();
    rows.sort_by_key(|b| std::cmp::Reverse(b.1 .2));
    for (k, b) in rows {
        eprintln!("  {:<55} {:>5}  {:>7}  {:>8}", k, b.0, b.1, b.2);
        tn += b.0;
        tk += b.1;
        tv += b.2;
    }
    eprintln!("  {:-<55} {:->5}  {:->7}  {:->8}", "", "", "", "");
    eprintln!("  {:<55} {:>5}  {:>7}  {:>8}", "TOTAL Full", tn, tk, tv);

    let full_value_bytes: usize = by_class
        .iter()
        .filter(|(k, _)| k.starts_with("full"))
        .map(|(_, b)| b.2)
        .sum();
    eprintln!();
    eprintln!(
        "  Full node value bytes                       : {} value bytes",
        full_value_bytes
    );

    // ─── Compare to "just send the changelog entry" ──────────────────────
    if let Some(e) = entry {
        let entry_bytes = postcard::to_allocvec(e).unwrap_or_default();
        let msg_bytes = postcard::to_allocvec(&e.message).unwrap_or_default();
        let entries_only = postcard::to_allocvec(&e.message.entries).unwrap_or_default();
        let mut kv_value_total = 0usize;
        let mut kv_key_total = 0usize;
        let mut kv_value_count = 0usize;
        for kv in &e.message.entries {
            kv_key_total += kv.key.len();
            kv_value_count += 1;
            kv_value_total += kv.value.len();
        }
        eprintln!();
        eprintln!("=== Compare to ChangelogEntry alone ===");
        eprintln!("  ChangelogEntry (postcard)   : {:>6} B", entry_bytes.len());
        eprintln!("    LogMessage              : {:>6} B", msg_bytes.len());
        eprintln!(
            "      entries (Vec<KvData>) : {:>6} B  ({} kv, {} Value; key={} val={})",
            entries_only.len(),
            e.message.entries.len(),
            kv_value_count,
            kv_key_total,
            kv_value_total,
        );
        eprintln!("    signature             : {:>6} B", e.signature.len());
        eprintln!("    timestamp+uid+parents+sigref+parent_clc: ~57 B (8+4+4+4+32+5 tags)");
        eprintln!();
        let proof_overhead = bytes.len() as i64 - entry_bytes.len() as i64;
        eprintln!(
            "  Pruned tree / Entry ratio : {:.2}x",
            bytes.len() as f64 / entry_bytes.len() as f64
        );
        eprintln!(
            "  Witness overhead vs entry    : {} B ({:+.0}%)",
            proof_overhead,
            100.0 * proof_overhead as f64 / entry_bytes.len() as f64,
        );
    }
    eprintln!();
}

#[derive(Default)]
struct PrunedStats {
    full_count: usize,
    full_key_bytes: usize,
    full_value_bytes: usize,
    pruned_count: usize,
    pruned_key_bytes: usize,
}

fn walk_pruned(node: &PrunedMerkleTree, s: &mut PrunedStats) {
    match node {
        PrunedMerkleTree::Empty => {}
        PrunedMerkleTree::Pruned { key, .. } => {
            s.pruned_count += 1;
            s.pruned_key_bytes += key.len();
        }
        PrunedMerkleTree::Full {
            key,
            value,
            left,
            right,
        } => {
            s.full_count += 1;
            s.full_key_bytes += key.len();
            s.full_value_bytes += value.len();
            walk_pruned(left, s);
            walk_pruned(right, s);
        }
    }
}

/// Classify a merk key into a human-readable bucket label.
/// Decodes the key tuple and groups by (tag, table) where possible.
fn classify_key(key: &[u8]) -> String {
    use encrypted_spaces_storage_encoding::tuple::{decode_tuple, TupleElement};
    let elements = match decode_tuple(key) {
        Ok(e) => e,
        Err(_) => return format!("<undecodable {}B>", key.len()),
    };
    if elements.is_empty() {
        return "<empty>".into();
    }
    let as_str = |e: &TupleElement| -> Option<String> {
        match e {
            TupleElement::String(s) => Some(s.clone()),
            TupleElement::Bytes(b) => std::str::from_utf8(b).ok().map(|s| s.to_string()),
            _ => None,
        }
    };
    let tag = elements
        .first()
        .and_then(as_str)
        .unwrap_or_else(|| format!("{:?}", elements[0]));
    let second = elements.get(1).and_then(as_str);
    let third = elements.get(2).and_then(as_str);
    match (tag.as_str(), second.as_deref(), third.as_deref()) {
        ("S", Some(t), Some(sub)) => format!("Schema({t}.{sub})"),
        ("S", Some(t), None) => format!("Schema({t})"),
        ("R", Some(t), _) => format!("Row({t})"),
        ("I", Some(t), Some(c)) => format!("Index({t}.{c})"),
        ("A", Some(s), _) => format!("ACL({s})"),
        ("A", None, _) => "ACL".into(),
        _ => format!("Tag({tag})"),
    }
}

fn classify_class(key: &[u8]) -> String {
    format!("{:<11} {}", "full", classify_key(key))
}

fn walk_classify(
    node: &PrunedMerkleTree,
    out: &mut std::collections::BTreeMap<String, (usize, usize, usize)>,
) {
    // out value tuple: (nodes, key_bytes, value_bytes)
    fn walk(
        n: &PrunedMerkleTree,
        out: &mut std::collections::BTreeMap<String, (usize, usize, usize)>,
    ) {
        match n {
            PrunedMerkleTree::Empty | PrunedMerkleTree::Pruned { .. } => {}
            PrunedMerkleTree::Full {
                key,
                value,
                left,
                right,
            } => {
                let cls = classify_class(key);
                let entry = out.entry(cls).or_insert((0, 0, 0));
                entry.0 += 1;
                entry.1 += key.len();
                entry.2 += value.len();
                walk(left, out);
                walk(right, out);
            }
        }
    }
    let mut tmp: std::collections::BTreeMap<String, (usize, usize, usize)> = Default::default();
    walk(node, &mut tmp);
    // Convert to caller's Bucket-shaped map (we reuse tuple map; the caller maps it to Bucket).
    *out = tmp;
}

// ─── Benchmarks ──────────────────────────────────────────────────────────────

fn bench_all_ops(c: &mut Criterion<ProofBytes>) {
    for op in BenchOp::ALL {
        let label = op.label();
        let bench_name = format!("pruned_tree_size/{label}_R{PREPOPULATE_ROWS}");
        c.bench_function(&bench_name, |b| {
            b.iter_custom(|iters| {
                let n = fixture()
                    .sizes
                    .get(label)
                    .copied()
                    .unwrap_or_else(|| panic!("op '{label}' was not recorded during setup"));
                // Force Criterion to run this closure exactly once per
                // sample. Without the sleep, the body is so fast (one
                // hash-map lookup) that Criterion picks `iters` in the
                // billions and the per-iter math underflows the reported
                // number to a single-digit "B". A 1ms pause per sample
                // is invisible against the 10s+ of one-time setup.
                std::thread::sleep(std::time::Duration::from_millis(1));
                n as u64 * iters
            });
        });
    }
}

// ─── Criterion plumbing ──────────────────────────────────────────────────────

fn proof_size_criterion() -> Criterion<ProofBytes> {
    Criterion::default()
        .with_measurement(ProofBytes)
        // Sizes are deterministic — minimize iterations.
        .sample_size(10)
        .nresamples(10)
        .warm_up_time(std::time::Duration::from_millis(1))
        .measurement_time(std::time::Duration::from_millis(1))
        .significance_level(0.0001)
        .noise_threshold(1.0)
}

criterion_group! {
    name = proof_size_benchmarks;
    config = proof_size_criterion();
    targets = bench_all_ops
}

criterion_main!(proof_size_benchmarks);
