use crate::app_config::{AppConfig, BootstrapDataSource, SpaceInitConfig};
use crate::key_delivery::GroupKeyDeliverySlots;
use base64::Engine as _;
use encrypted_spaces_acl_types::{Action, ActionBody, ActionLeg};
use encrypted_spaces_backend::internal_schemas::RETENTION_TABLE_NAME;
use encrypted_spaces_backend::internal_schemas::{
    is_internal_table, is_reserved_table_name, LISTS_TABLE_NAME, USERS_TABLE_NAME,
};
use encrypted_spaces_backend::merk_storage::{
    group_columns_into_rows_by_table_resolving_hashes, parse_key, Op, ParsedKey,
};
use encrypted_spaces_backend::sign_change::verify_change_signature;
pub use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_backend::{
    access_control::AuthContext,
    app_schema::{SchemaBundle, SchemaTable},
    error::SdkError,
    internal_schemas,
    merk_storage::{stored_value, MerkStorage},
    proto::{self, db_request, db_response, DbRequest, DbResponse},
    query::{ComparisonOperator, Predicate, Query, QueryOperation, QueryParam},
    schema::{ColumnType, Schema, MAX_STRING_COLUMN_BYTES},
    schema_kdl,
    storage::Storage,
};
use encrypted_spaces_changelog_core::changelog::{
    check_sigref_continuity, validate_parent_change, Change, ChangeLog, ChangeResponse,
    ChangelogEntry, ChangelogError, FastForwardData, FastForwardProof, FastForwardServerHead,
    HashedValues, KvData, OpType, MAX_LOGMSG_ENTRIES, MAX_PARENT_DISTANCE,
};
use encrypted_spaces_changelog_core::ops::extract_row_id_from_invite_user_proof;
use encrypted_spaces_changelog_core::time::validate_change_timestamp_at_acceptance;
use encrypted_spaces_crypto::signature::Ed25519Signature;
use encrypted_spaces_crypto::KeyCommitment;
use encrypted_spaces_crypto::Mkem;
use encrypted_spaces_crypto::Signature;
use encrypted_spaces_ffproof::common::FFProof;
use encrypted_spaces_ffproof::prover::update_changelog_proof;
use encrypted_spaces_key_manager::operation::AsyncReader;
use encrypted_spaces_key_manager::{
    verify_invite, verify_rekey, CollectingOperationBuilder, DefaultMkem, GkDeliveryEnvelope,
    InviteRequest, KeyManagerError, PendingWritesView, RekeyRequest, SpaceKey,
};
use encrypted_spaces_retention::simple_line2::SimpleLine2SpaceKey;
use encrypted_spaces_storage_encoding::{action_storage_key, decode_action_value, hashstore_hash};
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::{fs, io::Write};
use tokio::sync::{mpsc, oneshot, Mutex};

type AuthVerifyingKey = <Ed25519Signature as Signature>::VerificationKey;

#[derive(Clone, Copy)]
struct HashedValuesLimits {
    max_entries: usize,
    max_value_bytes: usize,
    max_total_bytes: usize,
}

const HASHED_VALUES_LIMITS: HashedValuesLimits = HashedValuesLimits {
    max_entries: MAX_LOGMSG_ENTRIES,
    max_value_bytes: 50 * 1024 * 1024,
    max_total_bytes: 50 * 1024 * 1024,
};

/// Upper bound on how many expected-entry inclusion proofs a single
/// fast-forward request may ask the server to generate (issue #212).
///
/// A well-behaved client only requests proofs for its *undischarged in-flight
/// local submissions*, which is small (typically one per concurrent mutation).
/// Without a cap, a malicious client could list every change_id in the proven
/// range and force the server to build — and return — one inclusion proof per
/// change, an O(p·log p) CPU and bandwidth amplification from a tiny request.
///
/// Requests are processed in the order sent; the honest client sends ascending
/// change_ids (it builds the list from a `BTreeMap`), so the lowest/oldest
/// ids — the ones most likely already inside the proven range and thus needing
/// a proof — are prioritized. Expected ids beyond this cap simply do not get a
/// proof-covered discharge from this response; they still discharge via the
/// ragged tail or a subsequent fast-forward. Dropping proofs can only ever make
/// a client fail closed and retry — never produce a false success — so this cap
/// is safe for the issue #212 guarantee.
const MAX_FF_EXPECTED_INCLUSION_PROOFS: usize = 64;

/// Bound and normalize the client-requested expected change_ids for a
/// fast-forward (issue #212): examine at most
/// [`MAX_FF_EXPECTED_INCLUSION_PROOFS`] of them, keep only those inside the
/// proven range `1..=proven_up_to`, and deduplicate. Returns the ids the
/// server should build inclusion proofs for. Capping/dropping is strictly
/// safe — it can only make a client fail closed and retry, never produce a
/// false success.
fn bounded_expected_change_ids(expected: &[u32], proven_up_to: usize) -> Vec<u32> {
    let mut selected = std::collections::BTreeSet::new();
    for &cid in expected.iter().take(MAX_FF_EXPECTED_INCLUSION_PROOFS) {
        if cid >= 1 && (cid as usize) <= proven_up_to {
            selected.insert(cid);
        }
    }
    selected.into_iter().collect()
}

/// Resolve a stored column value: if it's a 32-byte hash present in the
/// sidecar, return the full bytes; otherwise return the value as-is.
fn resolve_from_hashed_values(value: &[u8], hashed_values: &HashedValues) -> Vec<u8> {
    if let Ok(hash) = <[u8; 32]>::try_from(value) {
        if let Some(full_value) = hashed_values.get(&hash) {
            return full_value.clone();
        }
    }
    value.to_vec()
}

pub(crate) fn op_name(op: &Option<db_request::Operation>) -> &'static str {
    if op.is_none() {
        return "<None>";
    }
    match op.as_ref().unwrap() {
        db_request::Operation::Select(_) => "Select",
        db_request::Operation::Change(_) => "Change",
        db_request::Operation::FastForward(_) => "FastForward",
        db_request::Operation::AddMember(_) => "AddMember",
        db_request::Operation::RemoveMember(_) => "RemoveMember",
        db_request::Operation::FetchMyKeyDelivery(_) => "FetchMyKeyDelivery",
        db_request::Operation::Retention(_) => "Retention",
    }
}

/// The state a server has to keep for a [`Space`].
///
/// TODO: Currently persisted in memory only, but should be stored durably.
pub struct SpaceState {
    pub db: MerkStorage,
    pub changelog: ChangeLog,
    pub change_responses: Vec<ChangeResponse>,
    /// The most recent FF proof the server has (deserialized for proof extension)
    pub ff_proof: Option<FFProof>,
    /// A copy of the tree at the time ff_proof was created. When we create the next proof,
    /// we need the tree and a list of operations we'll apply to it.
    pub tree_snapshot: Option<merk::Node>,
    /// Batch size for FF proof generation - a new proof is generated every N changes
    pub ff_batch_size: usize,
    /// Per-recipient GK delivery slots (runtime state, not DB-persisted).
    pub key_delivery_slots: GroupKeyDeliverySlots,
    /// The space this server state belongs to.
    pub space_id: SpaceId,
    /// Optional file store for cleaning up files when rows with FileRef columns are deleted.
    pub file_store: Option<Arc<crate::file_store::FileStore>>,
    /// Per-user sigref view: maps `uid -> change_id` of that user's most
    /// recent accepted change (absent / `0` when the user has not written
    /// before). Used by `handle_change` to enforce sigref-chain continuity
    /// on every submission, closing the window between FF proofs where the
    /// FF guest is otherwise the only enforcer of the chain (issue #30).
    pub sigref_map: BTreeMap<u32, u32>,
    /// Path for verbose file-based logging, if any.
    verbose_logfile: Option<String>,
    /// Per-space store mapping SHA-256 hashes to full values for hash-backed columns.
    pub hash_store: HashMap<[u8; 32], Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SelectProofResponse {
    pub proof: Vec<u8>,
    pub hashed_values: HashedValues,
}

#[derive(Debug)]
struct AppliedChangeProof {
    pruned_merkle_tree: Vec<u8>,
}

fn removed_user_ids_in_change(delete_change: &ChangelogEntry) -> BTreeSet<i64> {
    delete_change
        .message
        .entries
        .iter()
        .filter_map(|entry| match parse_key(&entry.key) {
            Ok(ParsedKey::Column { table, row_id, .. }) if table == USERS_TABLE_NAME => {
                Some(row_id)
            }
            Ok(ParsedKey::Row { table, row_id }) if table == USERS_TABLE_NAME => Some(row_id),
            _ => None,
        })
        .collect()
}

/// Pull the table name from the first parseable column key in `change`.
/// Used to derive the target table for ops where the entry encodes it
/// (Insert / Update / Delete / list ops).
fn first_table_in_change(change: &ChangelogEntry) -> Option<String> {
    change
        .message
        .entries
        .iter()
        .find_map(|kv| match parse_key(&kv.key) {
            Ok(ParsedKey::Column { table, .. })
            | Ok(ParsedKey::Row { table, .. })
            | Ok(ParsedKey::RowPrefix { table }) => Some(table),
            _ => None,
        })
}

/// Resolve the bytes for the first `(table, column)` entry in `change`.
fn column_value_for_table(
    change: &Change,
    table: &str,
    column: &str,
    hashed_values: &HashedValues,
) -> Option<Vec<u8>> {
    for kv in &change.entry.message.entries {
        match parse_key(&kv.key) {
            Ok(ParsedKey::Column {
                table: t,
                column: c,
                ..
            }) if t == table && c == column => {
                return Some(resolve_from_hashed_values(&kv.value, hashed_values));
            }
            _ => {}
        }
    }
    None
}

/// Pull `(retention_key, retention_value_blob)` pairs out of a signed
/// change for ops that write to `_retention` (CreateSpace / InviteUser /
/// RemoveUser / Extend / Reduce / Rekey). Decodes the postcard-encoded
/// `_retention.key` (Text) and `_retention.value` (base64-encoded Text)
/// columns the SDK builds via `append_retention_to_changelog`.
fn extract_retention_writes_from_change(change: &Change) -> Vec<(String, Vec<u8>)> {
    use encrypted_spaces_backend::merk_storage::stored_value;

    let resolve = |kv: &KvData| -> Option<Vec<u8>> { Some(kv.value.clone()) };

    // Group entries by row id (or placeholder), keyed within each row by
    // column name so we can pair "key" with "value" in order.
    let mut per_row: std::collections::BTreeMap<i64, std::collections::BTreeMap<String, Vec<u8>>> =
        std::collections::BTreeMap::new();
    let mut placeholder_pairs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut placeholder_state: Option<(Option<String>, Option<Vec<u8>>)> = None;

    for kv in &change.entry.message.entries {
        match parse_key(&kv.key) {
            Ok(ParsedKey::Column {
                table,
                row_id,
                column,
            }) if table == RETENTION_TABLE_NAME => {
                if column != "key" && column != "value" {
                    continue;
                }
                let bytes = match resolve(kv) {
                    Some(b) => b,
                    None => continue,
                };
                if row_id == 0 {
                    // Placeholder row — pair "key" then "value" in order.
                    let entry = placeholder_state.get_or_insert((None, None));
                    if column == "key" {
                        entry.0 = stored_value::bytes_to_value(&bytes)
                            .ok()
                            .and_then(|v| v.as_str().map(|s| s.to_string()));
                    } else {
                        entry.1 = stored_value::bytes_to_value(&bytes).ok().and_then(|v| {
                            v.as_str().and_then(|b64| {
                                base64::engine::general_purpose::STANDARD.decode(b64).ok()
                            })
                        });
                    }
                    if let (Some(k), Some(v)) = (&entry.0, &entry.1) {
                        placeholder_pairs.push((k.clone(), v.clone()));
                        placeholder_state = None;
                    }
                } else {
                    per_row.entry(row_id).or_default().insert(column, bytes);
                }
            }
            _ => {}
        }
    }

    let mut out = placeholder_pairs;
    for fields in per_row.into_values() {
        let key_bytes = match fields.get("key") {
            Some(b) => b,
            None => continue,
        };
        let value_bytes = match fields.get("value") {
            Some(b) => b,
            None => continue,
        };
        let key_str = match stored_value::bytes_to_value(key_bytes) {
            Ok(serde_json::Value::String(s)) => s,
            _ => continue,
        };
        let value_blob = match stored_value::bytes_to_value(value_bytes) {
            Ok(serde_json::Value::String(b64)) => {
                match base64::engine::general_purpose::STANDARD.decode(&b64) {
                    Ok(b) => b,
                    Err(_) => continue,
                }
            }
            _ => continue,
        };
        out.push((key_str, value_blob));
    }
    out
}

/// Map of space_id → per-space server state. Spaces are created lazily on first connection.
static SPACES: Lazy<Mutex<HashMap<SpaceId, Arc<Mutex<SpaceState>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Build the per-space init config from the global [`AppConfig`].
fn build_init_cfg(space_id: SpaceId, app_cfg: Option<&AppConfig>) -> Option<SpaceInitConfig> {
    app_cfg.map(|cfg| {
        let artifact_path = cfg
            .space_root
            .as_ref()
            .map(|base| format!("{}/{}", base, space_id));

        SpaceInitConfig {
            space_id,
            artifact_path,
            verbose_logfile: cfg.verbose_logfile.clone(),
            bootstrap_data: cfg.bootstrap_data.clone(),
        }
    })
}

/// Get or create the state for the given space.
///
/// The artifact path is derived from `app_cfg.space_root` (or temporary if none),
/// and `bootstrap_data` (from `--schema`) is applied when the space is first
/// created.
pub(crate) async fn get_or_create_space(
    space_id: SpaceId,
    app_cfg: Option<&AppConfig>,
) -> Arc<Mutex<SpaceState>> {
    let mut map = SPACES.lock().await;

    if let Some(existing) = map.get(&space_id) {
        return existing.clone();
    }

    let init_cfg = build_init_cfg(space_id, app_cfg).unwrap_or(SpaceInitConfig {
        space_id,
        artifact_path: None,
        verbose_logfile: None,
        bootstrap_data: BootstrapDataSource::None,
    });
    let state = SpaceState::init_server(None, Some(init_cfg), None)
        .await
        .expect("Failed to initialize space state");
    let arc = Arc::new(Mutex::new(state));
    map.insert(space_id, arc.clone());
    arc
}

/// Log how spaces will be initialized at startup.
///
/// `--schema` is a lazy global template applied to new spaces on first connection.
pub async fn ensure_initialized(app_cfg: &AppConfig) -> Result<(), ServerError> {
    if matches!(app_cfg.bootstrap_data, BootstrapDataSource::SchemaFile(_)) {
        log::info!(
            "ensure_initialized: --schema will be applied to new spaces on first connection"
        );
    } else {
        log::info!("ensure_initialized: spaces will be created lazily on first connection");
    }
    Ok(())
}

/// Outcome of [`SpaceState::server_validation_delete`].
///
/// `NoMatchingRows` is converted to a successful `ChangeResponse`
/// with `rows_affected = 0`; any `Err(ServerError)` is propagated
/// to the client unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeleteValidationOutcome {
    /// At least one targeted row exists, or the entry has no column
    /// keys (E&V will surface that structural error).
    Proceed,
    /// None of the rows named by the change exist in the tree.
    NoMatchingRows,
}

pub async fn dump_tables_to_console(_app_cfg: &AppConfig) -> Result<(), ServerError> {
    let spaces_snapshot: Vec<(SpaceId, Arc<Mutex<SpaceState>>)> = {
        let map = SPACES.lock().await;
        map.iter().map(|(&sid, arc)| (sid, arc.clone())).collect()
    };

    if spaces_snapshot.is_empty() {
        println!("No active spaces");
        return Ok(());
    }

    for (space_id, arc) in spaces_snapshot {
        println!("=== Space {} ===", space_id);
        arc.lock().await.print_tables_to_console();
    }
    Ok(())
}

pub async fn dump_changelog_to_console(_app_cfg: &AppConfig) -> Result<(), ServerError> {
    let spaces_snapshot: Vec<(SpaceId, Arc<Mutex<SpaceState>>)> = {
        let map = SPACES.lock().await;
        map.iter().map(|(&sid, arc)| (sid, arc.clone())).collect()
    };

    if spaces_snapshot.is_empty() {
        println!("No active spaces");
        return Ok(());
    }

    for (space_id, arc) in spaces_snapshot {
        println!("=== Space {} ===", space_id);
        arc.lock().await.print_changelog_to_console();
    }
    Ok(())
}

/// Drop every per-space state held in the global `SPACES` registry.
///
/// Used at shutdown: once the accept loops have stopped and all WS
/// tasks have drained, clearing the map releases the registry's
/// `Arc<Mutex<SpaceState>>` references so that `SpaceState::drop`
/// (releasing the in-memory Merk DB and the file-store handle) runs
/// promptly. Any clones still held by in-flight tasks will drop when
/// those tasks finish.
#[allow(dead_code)] // Only called from the binary; lib build sees it as unused.
pub(crate) async fn shutdown_all_spaces() {
    let mut map = SPACES.lock().await;
    let count = map.len();
    if count > 0 {
        log::info!("shutdown: dropping {count} space(s) from registry");
    }
    map.clear();
}

#[derive(Debug)]
pub enum ServerError {
    // TODO: should we keep this, or use existing  error?
    Generic(String),
    /// Authorization failure surfaced from the storage / validation layer.
    AccessDenied(String),
    /// The submitted change's `parent_change` / `parent_clc` does not
    /// match the server's current view of the changelog — either it is
    /// outside the `MAX_PARENT_DISTANCE` window or its `parent_clc`
    /// disagrees with the server's recorded root at that change. The
    /// client must fast-forward and resign before retrying.
    StaleParent(String),
}
impl From<ChangelogError> for ServerError {
    fn from(e: ChangelogError) -> Self {
        ServerError::Generic(format!("Changelog error: {e:?}"))
    }
}
impl From<SdkError> for ServerError {
    fn from(e: SdkError) -> Self {
        match e {
            SdkError::AccessDenied(msg) => ServerError::AccessDenied(msg),
            other => ServerError::Generic(format!("Storage error: {other}")),
        }
    }
}

impl std::error::Error for ServerError {}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Generic(msg) => write!(f, "{msg}"),
            ServerError::AccessDenied(msg) => write!(f, "Access denied: {msg}"),
            ServerError::StaleParent(msg) => write!(f, "Stale parent: {msg}"),
        }
    }
}

impl SpaceState {
    /// Default batch size for FF proof generation
    pub const DEFAULT_FF_BATCH_SIZE: usize = 5;

    /// Initialize a space with in-memory Merk storage.
    pub async fn init_server(
        schema: Option<&Vec<Schema>>,
        init_cfg: Option<SpaceInitConfig>,
        ff_batch_size: Option<usize>,
    ) -> Result<Self, ServerError> {
        let space_id = init_cfg
            .as_ref()
            .map(|cfg| cfg.space_id)
            .unwrap_or(SpaceId::from([0u8; 16]));

        let db = MerkStorage::new();
        let artifact_path = init_cfg.as_ref().and_then(|cfg| cfg.artifact_path.clone());

        // Always create internal tables first (idempotent — skips if they already exist).
        for internal_schema in internal_schemas::all_internal_schemas() {
            db.create_table(&internal_schema).await.map_err(|e| {
                ServerError::Generic(format!(
                    "Failed to create internal table {}: {}",
                    internal_schema.name, e
                ))
            })?;
        }

        if let Some(schema_vec) = schema {
            for table_schema in schema_vec {
                db.create_table(table_schema).await.map_err(|e| {
                    ServerError::Generic(format!(
                        "Failed to create table {}: {}",
                        table_schema.name, e
                    ))
                })?;
            }
        }

        let initial_root = db.root_hash();
        let changelog = ChangeLog::new(&initial_root);
        let verbose_logfile = init_cfg
            .as_ref()
            .and_then(|cfg| cfg.verbose_logfile.clone());

        let ff_batch_size = ff_batch_size.unwrap_or(Self::DEFAULT_FF_BATCH_SIZE);

        let mut new_server_state = Self {
            db,
            changelog,
            change_responses: vec![],
            ff_proof: None,
            tree_snapshot: None,
            ff_batch_size,
            key_delivery_slots: GroupKeyDeliverySlots::default(),
            space_id,
            file_store: {
                let file_path = if let Some(ref p) = artifact_path {
                    std::path::PathBuf::from(p).join("files")
                } else {
                    std::env::temp_dir()
                        .join(format!("encrypted-spaces-files-{}", uuid::Uuid::new_v4()))
                };
                Some(Arc::new(crate::file_store::FileStore::new(file_path)))
            },
            sigref_map: BTreeMap::new(),
            verbose_logfile,
            hash_store: HashMap::new(),
        };
        let sid = new_server_state.space_id;
        if let Some(config) = &init_cfg {
            log::info!(
                "space={sid} init: bootstrap_data={:?}",
                config.bootstrap_data
            );
            Self::clear_logfile(new_server_state.verbose_logfile.as_deref());
            match &config.bootstrap_data {
                BootstrapDataSource::SchemaFile(schema_path) => {
                    log::info!("space={sid} init: bootstrapping schema from {schema_path}");
                    new_server_state
                        .bootstrap_from_schema_file(schema_path)
                        .await
                        .map_err(|e| {
                            ServerError::Generic(format!(
                                "Failed to bootstrap schema from '{schema_path}': {e}"
                            ))
                        })?;
                    let context =
                        format!("After bootstrapping schema from {schema_path}, database is");
                    new_server_state.log_server_state(&context);
                }
                BootstrapDataSource::None => {
                    log::info!(
                        "space={sid} init: no schema bootstrap configured; starting with empty tables"
                    );
                    new_server_state.log_server_state("After initializing server, state is");
                }
            }
        } else {
            log::info!("space={sid} init: no SpaceInitConfig provided; using bare schema");
        }

        // Finalize the ACL blob — serialize all _access_control rows into the
        // tree for the fast-forward proof verifier. Must happen after any
        // schema bootstrap (which may insert access control rules).
        new_server_state
            .db
            .finalize_acl_blob()
            .await
            .map_err(|e| ServerError::Generic(format!("Failed to finalize ACL blob: {e}")))?;

        // Re-initialize the changelog so its genesis data commitment matches
        // the current Merk root after schema bootstrap and ACL blob
        // finalization.
        if new_server_state.changelog.changes.is_empty() {
            new_server_state.reinitialize_changelog().await?;
        }

        // Take tree snapshot AFTER demo inserts so it matches the state
        // the first tracked change will see as its old_root
        new_server_state.tree_snapshot = new_server_state.db.snapshot();

        log::info!(
            "space={sid} init complete, root={}",
            hex::encode(new_server_state.db.root_hash())
        );

        Ok(new_server_state)
    }

    pub async fn get_root_hash(&self) -> [u8; 32] {
        self.db.root_hash()
    }

    fn clear_logfile(logfile: Option<&str>) {
        let Some(filename) = logfile else { return };
        let mut file = match std::fs::File::create(filename) {
            Ok(f) => f,
            Err(e) => {
                log::error!("failed to create verbose log file '{filename}': {e}");
                return;
            }
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        writeln!(file, "Log file created at Unix timestamp: {timestamp}")
            .unwrap_or_else(|e| log::error!("failed to write log file creation time: {e}"));
        file.flush()
            .unwrap_or_else(|e| log::error!("failed to flush log file: {e}"));
    }

    pub fn log_server_state(&self, context: &str) {
        let Some(filename) = &self.verbose_logfile else {
            return;
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_context = format!("[time: {timestamp}] {context}");
        let log_string = format!("{}\n", self.db.pretty_print_db(false, log_context));

        // TODO: Also log other parts of server state

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)
            .unwrap_or_else(|e| panic!("Failed to open log file: {e}"));
        writeln!(file, "{log_string}").unwrap_or_else(|e| {
            log::error!(
                "space={} failed to write verbose log file: {e}",
                self.space_id
            )
        });
    }

    /// Select rows for a single table, resolving hash-backed columns to full
    /// values via `hash_store`. Fails closed if any hashed value is missing.
    async fn select_table_rows_resolving_hashes(
        &self,
        table_name: &str,
        schema: &Schema,
    ) -> Result<Vec<Value>, ServerError> {
        let has_hash_backed = schema
            .columns
            .iter()
            .any(|c| c.column_type.is_hash_backed());

        if !has_hash_backed {
            let query = Query::new(table_name.to_string(), QueryOperation::Select(vec![]));
            return self.db.select_all(query).await.map_err(ServerError::from);
        }

        let prefix = encrypted_spaces_storage_encoding::keys::row_prefix(table_name);
        let all_entries = self.db.iter_prefix_entries(&prefix)?;

        let schemas: HashMap<String, Schema> =
            std::iter::once((table_name.to_string(), schema.clone())).collect();

        let material: HashedValues = self
            .hash_store
            .iter()
            .map(|(hash, value)| (*hash, value.clone()))
            .collect();

        let rows_by_table =
            group_columns_into_rows_by_table_resolving_hashes(&all_entries, &schemas, &material)
                .map_err(|e| {
                    ServerError::Generic(format!(
                        "failed to resolve hash-backed columns for {table_name}: {e}"
                    ))
                })?;

        Ok(rows_by_table.into_values().next().unwrap_or_default())
    }

    /// Reject a schema bundle if it contains `_lists` rows or any row data for
    /// tables with List columns. Full list-aware schema bootstrap is a follow-up plan.
    fn reject_schema_bundle_with_list_data(
        &self,
        tables: &[SchemaTable],
    ) -> Result<(), ServerError> {
        use std::collections::HashSet;

        // First pass: collect all table names that have List columns.
        // Check both bundle-provided schemas AND existing server schemas
        // to prevent bypass via a spoofed non-list schema in the bundle.
        let mut tables_with_list_cols: HashSet<String> = HashSet::new();
        for bundle in tables {
            if let Some(ref schema) = bundle.schema {
                let has_list_columns = schema
                    .columns
                    .iter()
                    .any(|c| matches!(c.column_type, ColumnType::List));
                if has_list_columns {
                    tables_with_list_cols.insert(bundle.table.clone());
                }
            }
            if !bundle.rows.is_empty() {
                if let Ok(schema) = self.db.get_schema(&bundle.table) {
                    let has_list_columns = schema
                        .columns
                        .iter()
                        .any(|c| matches!(c.column_type, ColumnType::List));
                    if has_list_columns {
                        tables_with_list_cols.insert(bundle.table.clone());
                    }
                }
            }
        }

        // Second pass: reject any entry with rows for tables that have List columns
        // or for the `_lists` internal table.
        for bundle in tables {
            if bundle.table == LISTS_TABLE_NAME && !bundle.rows.is_empty() {
                return Err(ServerError::Generic(
                    "schema bundle rejected: bundle contains _lists rows; list data bootstrap is not yet supported".to_string(),
                ));
            }

            if tables_with_list_cols.contains(&bundle.table) && !bundle.rows.is_empty() {
                return Err(ServerError::Generic(format!(
                    "schema bundle rejected: table '{}' has List columns; list data bootstrap is not yet supported",
                    bundle.table
                )));
            }
        }

        Ok(())
    }

    pub fn print_tables_to_console(&self) {
        let snapshot = self
            .db
            .pretty_print_db(true, "Console print triggered".to_string());
        println!("{snapshot}");
    }

    pub fn print_changelog_to_console(&self) {
        println!("\n=== ChangeLog Dump ===");
        println!("Total changes: {}", self.changelog.changes.len());
        println!("Change responses: {}", self.change_responses.len());
        println!("\nChanges:");
        for (idx, change) in self.changelog.changes.iter().enumerate() {
            println!("\n[{}] Change ID: {}", idx, idx);
            println!("  UID: {}", change.uid);
            println!("  Timestamp: {}", change.timestamp);
            println!("  Parent Change: {}", change.parent_change);
            println!(
                "  Path: {}",
                String::from_utf8_lossy(&change.message.tree_path)
            );
            println!("  Key: {}", hex::encode(&change.message.entries[0].key));
            println!("  Value: {:?}", change.message.entries[0].value);
            println!("  Op Type: {:?}", change.message.op_type);
            if idx < self.change_responses.len() {
                let resp = &self.change_responses[idx];
                println!("  Old Root: {}", hex::encode(resp.old_root));
                println!("  New Root: {}", hex::encode(resp.new_root));
                println!(
                    "  Pruned Merkle Tree Length: {} bytes",
                    resp.pruned_merkle_tree.len()
                );
            }
        }
        println!("\n=== End ChangeLog ===");
    }

    /// Create tables and insert rows from a list of `SchemaTable` bundle entries.
    async fn apply_schema_bundle(
        &self,
        tables: Vec<SchemaTable>,
        auth_context: &AuthContext,
    ) -> Result<(), ServerError> {
        // Fail-closed guard: reject bundles with list data.
        self.reject_schema_bundle_with_list_data(&tables)?;

        for bundle in tables {
            let SchemaTable {
                table,
                schema,
                rows,
            } = bundle;

            log::info!(
                "space={} apply_schema_bundle: loading table '{table}' ({} rows)",
                self.space_id,
                rows.len()
            );

            // Reject developer-defined reserved-name tables (e.g. `_secret`).
            // Known internal tables are exempt because authored schema bundles
            // may seed their rows while relying on built-in schemas.
            if is_reserved_table_name(&table) && !is_internal_table(&table) {
                return Err(ServerError::Generic(format!(
                    "apply_schema_bundle: table '{table}' is reserved: names starting with '_' \
                     are reserved for internal tables and cannot be defined by application schemas"
                )));
            }

            // Internal tables have built-in schemas — only create app tables.
            if !is_internal_table(&table) {
                if let Some(ref schema) = schema {
                    self.db
                        .create_table(schema)
                        .await
                        .map_err(ServerError::from)?;
                }
            }

            for row in rows {
                let query = value_to_insert_query(&table, row)?;
                self.db
                    .insert(query, auth_context)
                    .await
                    .map_err(ServerError::from)?;
            }
        }
        Ok(())
    }

    /// After bootstrapping rows with full values, scan every hash-backed column in
    /// the Merk tree, replace the stored value with its SHA-256 hash, and
    /// populate `hash_store` with the hash→value mapping.
    ///
    /// Durable source for rehydration: schema bootstrap data carries the full
    /// values, so we hash them into the tree the same way
    /// `apply_hash_backed_storage` does on the SDK side, and retain the mapping
    /// for subsequent selects, broadcasts, and FF responses.
    fn rehydrate_hash_store_for_bootstrapped_rows(&mut self) -> Result<(), ServerError> {
        for schema in internal_schemas::all_internal_schemas() {
            let hash_backed_cols: BTreeSet<String> = schema
                .columns
                .iter()
                .filter(|c| c.column_type.is_hash_backed())
                .map(|c| c.name.clone())
                .collect();
            if hash_backed_cols.is_empty() {
                continue;
            }
            self.rehydrate_table_hash_store(&schema.name, &hash_backed_cols)?;
        }

        for table_name in self.app_table_names() {
            let schema = match self.db.get_schema(&table_name) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let hash_backed_cols: BTreeSet<String> = schema
                .columns
                .iter()
                .filter(|c| c.column_type.is_hash_backed())
                .map(|c| c.name.clone())
                .collect();
            if hash_backed_cols.is_empty() {
                continue;
            }
            self.rehydrate_table_hash_store(&table_name, &hash_backed_cols)?;
        }

        Ok(())
    }

    /// Hash every value for hash-backed columns in a single table, replacing
    /// the Merk entry with the 32-byte digest and populating `hash_store`.
    ///
    /// Schema bootstrap data always carries full values, so every stored byte
    /// sequence is treated as full material regardless of length. A 32-byte
    /// stored value is a legitimate full value (not a pre-existing hash ref)
    /// and is hashed like any other.
    fn rehydrate_table_hash_store(
        &mut self,
        table_name: &str,
        hash_backed_cols: &BTreeSet<String>,
    ) -> Result<(), ServerError> {
        let prefix = encrypted_spaces_storage_encoding::keys::row_prefix(table_name);
        let entries = self.db.iter_prefix_entries(&prefix)?;
        let mut ops: Vec<(Vec<u8>, Op)> = Vec::new();

        for (key, value) in &entries {
            let column = match parse_key(key) {
                Ok(ParsedKey::Column { column, .. }) => column,
                _ => continue,
            };
            if !hash_backed_cols.contains(&column) {
                continue;
            }
            let hash = hashstore_hash(value);
            self.hash_store.entry(hash).or_insert_with(|| value.clone());
            ops.push((key.clone(), Op::Put(hash.to_vec())));
        }

        if !ops.is_empty() {
            log::info!(
                "space={} rehydrate: replacing {} hash-backed values in {table_name}",
                self.space_id,
                ops.len()
            );
            self.db.apply_batch_ops(ops).map_err(|e| {
                ServerError::Generic(format!(
                    "rehydrate: failed to apply hash replacement batch for {table_name}: {e}"
                ))
            })?;
        }
        Ok(())
    }

    fn app_table_names(&self) -> Vec<String> {
        let prefix = encrypted_spaces_storage_encoding::keys::schema_prefix();
        let entries = self.db.iter_prefix_entries(&prefix).unwrap_or_default();
        let mut seen = BTreeSet::new();
        for (key, _) in entries {
            if let Ok(ParsedKey::Schema { table }) = parse_key(&key) {
                if !is_internal_table(&table) {
                    seen.insert(table);
                }
            }
        }
        seen.into_iter().collect()
    }

    /// Write declared actions into authenticated state.
    async fn import_actions(&self, actions: &[Action]) -> Result<(), ServerError> {
        self.db
            .import_actions(actions)
            .await
            .map_err(ServerError::from)
    }

    /// Write action-gating ACL constraints into authenticated state.
    async fn import_acl_only_via_actions(
        &self,
        only_via: &std::collections::BTreeMap<(String, String), Vec<String>>,
    ) -> Result<(), ServerError> {
        self.db
            .import_acl_only_via_actions(only_via)
            .await
            .map_err(ServerError::from)
    }

    /// Reset changelog to the current Merk root and clear change history.
    pub async fn reinitialize_changelog(&mut self) -> Result<(), ServerError> {
        let current_root = self.db.root_hash();
        self.changelog = ChangeLog::new(&current_root);
        self.change_responses.clear();
        // Drop the per-user sigref view alongside the changelog; the next
        // signed change is the first in a fresh chain (sig_ref == 0).
        self.sigref_map.clear();
        Ok(())
    }

    pub async fn bootstrap_from_schema_file(
        &mut self,
        schema_path: &str,
    ) -> Result<(), ServerError> {
        log::info!(
            "space={} schema bootstrap: reading {schema_path}",
            self.space_id
        );
        let bytes = fs::read(schema_path).map_err(|e| {
            ServerError::Generic(format!(
                "Failed to read schema bundle file '{schema_path}': {e}"
            ))
        })?;

        let SchemaBundle {
            tables,
            actions,
            acl_only_via_actions,
        } = if schema_path.ends_with(".kdl") {
            let text = std::str::from_utf8(&bytes).map_err(|e| {
                ServerError::Generic(format!(
                    "Schema file '{schema_path}' is not valid UTF-8: {e}"
                ))
            })?;
            schema_kdl::parse_schema_bundle(text).map_err(|e| {
                ServerError::Generic(format!("Failed to parse schema file '{schema_path}': {e}"))
            })?
        } else {
            serde_json::from_slice(&bytes).map_err(|e| {
                ServerError::Generic(format!(
                    "Failed to parse schema bundle file '{schema_path}': {e}"
                ))
            })?
        };

        log::info!(
            "space={} schema bootstrap: parsed schema/data with {} tables, {} actions",
            self.space_id,
            tables.len(),
            actions.len(),
        );
        let auth_context = AuthContext::new(None, self.space_id);
        self.apply_schema_bundle(tables, &auth_context).await?;
        self.rehydrate_hash_store_for_bootstrapped_rows()?;
        self.import_actions(&actions).await?;
        self.import_acl_only_via_actions(&acl_only_via_actions)
            .await?;
        self.reinitialize_changelog().await?;

        log::info!(
            "space={} schema bootstrap: complete, root={}",
            self.space_id,
            hex::encode(self.db.root_hash())
        );

        Ok(())
    }

    /// Check if the given user is provisional (status == 0).
    pub fn is_provisional_user(&self, uid: i64) -> bool {
        let mut query = Query::new(
            USERS_TABLE_NAME.to_string(),
            QueryOperation::Select(vec!["status".to_string()]),
        );
        query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(uid)],
            cursor_id: None,
        });
        self.db
            .query_rows(&query)
            .ok()
            .and_then(|rows| rows.first()?.get("status")?.as_i64())
            == Some(0)
    }

    fn decode_auth_verifying_key(auth_key_b64: &str) -> Result<AuthVerifyingKey, ServerError> {
        // auth_key is stored as base64(json_bytes(VerifyingKey))
        let json_bytes = base64::engine::general_purpose::STANDARD
            .decode(auth_key_b64)
            .map_err(|e| ServerError::Generic(format!("Failed to decode auth_key base64: {e}")))?;
        serde_json::from_slice(&json_bytes)
            .map_err(|e| ServerError::Generic(format!("Failed to deserialize auth_key: {e}")))
    }

    // Find the key-value pair in the change that encodes the auth_key
    fn create_space_auth_key_entry<'a>(
        &self,
        change: &'a ChangelogEntry,
    ) -> Result<&'a KvData, ServerError> {
        change
            .message
            .entries
            .iter()
            .find(|entry| {
                matches!(
                    parse_key(&entry.key),
                    Ok(ParsedKey::Column { table, column, .. })
                        if table == USERS_TABLE_NAME && column == "auth_key"
                )
            })
            .ok_or_else(|| {
                ServerError::Generic(
                    "CreateSpace change is missing the _users.auth_key entry".to_string(),
                )
            })
    }

    // Helper to get the signature verification key from the _users table
    fn user_table_verifying_key(&self, uid: u32) -> Result<AuthVerifyingKey, ServerError> {
        let key = encrypted_spaces_storage_encoding::keys::column_key(
            USERS_TABLE_NAME,
            uid as i64,
            "auth_key",
        );
        let raw_bytes = self
            .db
            .get_value(&key)
            .map_err(|e| ServerError::Generic(format!("Failed to look up user auth_key: {e}")))?
            .ok_or_else(|| ServerError::Generic(format!("auth_key not found for uid {uid}")))?;

        let resolved = if let Ok(hash) = <[u8; 32]>::try_from(raw_bytes.as_slice()) {
            self.hash_store.get(&hash).cloned().ok_or_else(|| {
                ServerError::Generic(format!(
                    "missing hash store material for auth_key of uid {uid}"
                ))
            })?
        } else {
            raw_bytes
        };

        let auth_key_json: serde_json::Value =
            stored_value::bytes_to_value(&resolved).map_err(|e| {
                ServerError::Generic(format!(
                    "Failed to decode auth_key bytes for uid {uid}: {e}"
                ))
            })?;
        let auth_key_b64 = auth_key_json.as_str().ok_or_else(|| {
            ServerError::Generic(format!("auth_key for uid {uid} is not a base64 string"))
        })?;

        Self::decode_auth_verifying_key(auth_key_b64)
    }

    // Extract the signature key from the auth_key entry inside a CreateSpace
    // changelog entry. The signing key is fresh: there is no `_users` row
    // to look it up in yet, so we resolve it from the entry itself.
    fn create_space_verifying_key(
        &self,
        change: &Change,
        hashed_values: &HashedValues,
    ) -> Result<AuthVerifyingKey, ServerError> {
        let auth_key_entry = self.create_space_auth_key_entry(&change.entry)?;
        let auth_key_bytes = auth_key_entry.value.clone();

        let resolved = resolve_from_hashed_values(&auth_key_bytes, hashed_values);

        let auth_key_json: Value = stored_value::bytes_to_value(&resolved).map_err(|e| {
            ServerError::Generic(format!("Failed to decode CreateSpace auth_key bytes: {e}"))
        })?;
        let auth_key_b64 = auth_key_json.as_str().ok_or_else(|| {
            ServerError::Generic("CreateSpace auth_key is not a base64 string".to_string())
        })?;

        Self::decode_auth_verifying_key(auth_key_b64)
    }

    /// Verify a changelog entry signature against the user's auth key.
    ///
    /// `CreateSpace` is special because the signer is introducing their own
    /// `_users` row: the verification key has to come from the entry itself.
    fn verify_change_signature(
        &self,
        change: &Change,
        hashed_values: &HashedValues,
    ) -> Result<(), ServerError> {
        if change.entry.signature.is_empty() {
            return Err(ServerError::Generic(
                "Change is missing a signature".to_string(),
            ));
        }

        let vk = match change.entry.message.op_type {
            OpType::CreateSpace => self.create_space_verifying_key(change, hashed_values)?,
            _ => self.user_table_verifying_key(change.entry.uid)?,
        };

        verify_change_signature::<Ed25519Signature>(&change.entry, &vk).map_err(|error| {
            ServerError::Generic(format!("Signature verification failed: {error}"))
        })
    }

    /// Provisional users (status == 0) may only submit RefreshKeys changes.
    /// All other op types are rejected until the user
    /// rotates keys and transitions to Full (status == 1).
    fn enforce_provisional_restrictions(&self, change: &ChangelogEntry) -> Result<(), ServerError> {
        if self.is_provisional_user(change.uid as i64) {
            let allowed = matches!(change.message.op_type, OpType::RefreshKeys);
            if !allowed {
                return Err(ServerError::Generic(
                    "provisional_user_restricted: only RefreshKeys is allowed until key rotation completes".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn ensure_change_applies(&self, change: &ChangelogEntry) -> Result<(), ServerError> {
        if change.message.entries.is_empty() {
            return Err(ServerError::Generic(
                "LogMessage has no entries".to_string(),
            ));
        }

        if change.message.entries.len() > MAX_LOGMSG_ENTRIES {
            return Err(ServerError::Generic(format!(
                "LogMessage has {} entries, maximum is {MAX_LOGMSG_ENTRIES}",
                change.message.entries.len()
            )));
        }

        // All op types can have multiple entries (one per column).
        // Require at least 1 entry.
        if change.message.entries.is_empty() {
            return Err(ServerError::Generic(
                "LogMessage must have at least one entry".to_string(),
            ));
        }

        // ACL rules and action-gating clauses live at per-(table, op)
        // keys; absence means "no constraint" (default-open).  There is
        // no single sentinel key to check for "finalize completed", so
        // we proceed directly to the op-shape checks below.

        let tree_path = &change.message.tree_path;

        match change.message.op_type {
            OpType::ListAppend | OpType::ListInsert | OpType::ListUpdate | OpType::ListDelete => {
                if tree_path.as_slice() != b"/" {
                    return Err(ServerError::Generic(format!(
                        "List op requires tree_path \"/\", got {:?}",
                        String::from_utf8_lossy(tree_path)
                    )));
                }
                if change.message.entries.is_empty() {
                    return Err(ServerError::Generic(
                        "List op must have at least 1 entry".to_string(),
                    ));
                }
                for kv in &change.message.entries {
                    match parse_key(&kv.key) {
                        Ok(ParsedKey::Column { table, .. }) if table == LISTS_TABLE_NAME => {}
                        Ok(other) => {
                            return Err(ServerError::Generic(format!(
                                "List op entry must be a `_lists` column key, got {other:?}"
                            )));
                        }
                        Err(e) => {
                            return Err(ServerError::Generic(format!(
                                "List op entry key failed to parse: {e:?}"
                            )));
                        }
                    }
                }
                Ok(())
            }
            OpType::Action => {
                // Action entries carry the action-marker kv at
                // position 0 plus one or more column kvs across one or
                // more tables.  Per-table schema validation happens
                // inside `ActionOp::extract_and_validate`; here we
                // only verify the marker shape so a malformed entry
                // fails fast.
                if tree_path.as_slice() != b"/" {
                    return Err(ServerError::Generic(format!(
                        "Action op requires tree_path \"/\", got {:?}",
                        String::from_utf8_lossy(tree_path)
                    )));
                }
                let first = change
                    .message
                    .entries
                    .first()
                    .ok_or_else(|| ServerError::Generic("Action op has no kvs".to_string()))?;
                match parse_key(&first.key) {
                    Ok(ParsedKey::ActionMarker { .. }) => Ok(()),
                    Ok(other) => Err(ServerError::Generic(format!(
                        "Action op's first kv must be the action marker; got {other:?}"
                    ))),
                    Err(e) => Err(ServerError::Generic(format!(
                        "Action op's first kv key failed to parse: {e:?}"
                    ))),
                }
            }
            _ => {
                match tree_path.as_slice() {
                    b"/" => {
                        let parsed_key =
                            parse_key(&change.message.entries[0].key).map_err(|e| {
                                ServerError::Generic(format!("Failed to parse key: {e:?}"))
                            })?;

                        let table = match &parsed_key {
                            ParsedKey::Row { table, .. }
                            | ParsedKey::RowPrefix { table }
                            | ParsedKey::Column { table, .. } => table,
                            _ => {
                                return Err(ServerError::Generic(format!(
                                    "Unsupported key type: {parsed_key:?}"
                                )))
                            }
                        };
                        let schema = self.db.get_schema(table).map_err(|_| {
                            ServerError::Generic(format!("Table not found: {table}"))
                        })?;

                        self.validate_change_entries_against_schema(change, &schema)?;
                    }
                    _ => {
                        return Err(ServerError::Generic(format!(
                            "Unsupported tree_path: {:?}",
                            String::from_utf8_lossy(tree_path)
                        )))
                    }
                }
                Ok(())
            }
        }
    }

    /// Validate that a changelog entry's column keys are consistent with the table schema.
    ///
    /// - **Insert**: must have one entry per non-id column (keys use placeholder row_id=0).
    /// - **Delete**: must cover exactly all non-id columns per row.
    /// - **Update**: every referenced column must exist in the schema, but not all columns must be represented.
    fn validate_change_entries_against_schema(
        &self,
        change: &ChangelogEntry,
        schema: &Schema,
    ) -> Result<(), ServerError> {
        let expected_columns: BTreeSet<String> = schema
            .columns
            .iter()
            .filter(|c| c.name != "id")
            .map(|c| c.name.clone())
            .collect();

        let col_types: HashMap<&str, &ColumnType> = schema
            .columns
            .iter()
            .map(|c| (c.name.as_str(), &c.column_type))
            .collect();

        let mut actual_columns: BTreeSet<String> = BTreeSet::new();
        for kv in &change.message.entries {
            if let Ok(ParsedKey::Column { table, column, .. }) = parse_key(&kv.key) {
                actual_columns.insert(column.clone());

                if col_types.get(column.as_str()) == Some(&&ColumnType::String)
                    && !is_internal_table(&table)
                {
                    if let Ok(json_val) = stored_value::bytes_to_value(&kv.value) {
                        let raw_len = json_val.as_str().map(|s| s.len()).unwrap_or(kv.value.len());
                        if raw_len > MAX_STRING_COLUMN_BYTES {
                            return Err(ServerError::Generic(format!(
                                "String column '{table}.{column}' value is {raw_len} bytes, max is {MAX_STRING_COLUMN_BYTES}",
                            )));
                        }
                    }
                }
            }
        }

        match change.message.op_type {
            OpType::Insert | OpType::Delete => {
                if actual_columns != expected_columns {
                    let missing: Vec<_> = expected_columns.difference(&actual_columns).collect();
                    let extra: Vec<_> = actual_columns.difference(&expected_columns).collect();
                    return Err(ServerError::Generic(format!(
                        "{:?} must cover all columns. Missing: {missing:?}, Extra: {extra:?}",
                        change.message.op_type
                    )));
                }
            }
            OpType::Update => {
                for col in &actual_columns {
                    if !expected_columns.contains(col) {
                        return Err(ServerError::Generic(format!(
                            "{:?} references unknown column '{col}'",
                            change.message.op_type
                        )));
                    }
                }
            }
            _ => {} // CreateSpace, InviteUser, RefreshKeys, list ops — validated elsewhere
        }

        Ok(())
    }

    /// Validate that the change's `parent_clc` matches the changelog
    /// commitment recorded after the `parent_change`-th change was applied.
    fn validate_parent_clc(&self, change: &ChangelogEntry) -> Result<(), ServerError> {
        let expected: [u8; 32] = match self.changelog.root_at(change.parent_change) {
            Some(r) => r,
            None => {
                return Err(ServerError::StaleParent(format!(
                    "parent_change {} refers to a non-existent changelog entry (chain has {} changes)",
                    change.parent_change,
                    self.changelog.num_changes()
                )));
            }
        };

        log::debug!(
            "space={} validate_parent_clc: parent_change={} op={:?} chain_len={} expected={} claimed={} match={}",
            self.space_id,
            change.parent_change,
            change.message.op_type,
            self.changelog.num_changes(),
            hex::encode(expected),
            hex::encode(change.parent_clc),
            change.parent_clc == expected
        );
        if change.parent_clc != expected {
            return Err(ServerError::StaleParent(format!(
                "parent_clc mismatch: change claims {} but server has {} at parent_change {}",
                hex::encode(change.parent_clc),
                hex::encode(expected),
                change.parent_change
            )));
        }

        Ok(())
    }

    /// Server-only validation surface for the per-op dispatch.
    ///
    /// Each `server_validation_*` is a single, named home for any
    /// server-only check that does not belong inside
    /// `extract_and_validate` (e.g. checks that depend on the request
    /// envelope, server state outside the signed entry, or
    /// no-match-row short-circuits). Today most are intentional
    /// no-ops — the dispatcher invokes them so future server-only
    /// checks have an obvious place to land instead of accreting
    /// scattered, ad-hoc validation logic. `server_validation_delete`
    /// is the one non-trivial member; the rest stand as documented
    /// stubs.
    fn server_validation_insert(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    fn server_validation_update(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    fn server_validation_create_space(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    fn server_validation_invite_user(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    fn server_validation_remove_user(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    fn server_validation_refresh_keys(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    fn server_validation_extend(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    fn server_validation_reduce(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    fn server_validation_rekey(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    fn server_validation_list(
        &self,
        _change: &Change,
        _auth: &AuthContext,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    /// Server-only validation for `OpType::Delete`.
    ///
    /// Per design, deleting an individual row that does not exist
    /// is a no-op and not a security concern, so E&V does not gate
    /// on per-row presence.  This check only catches the degenerate
    /// case where *every* targeted row is absent, returning
    /// [`DeleteValidationOutcome::NoMatchingRows`] so the dispatcher
    /// can short-circuit with a successful no-op response instead of
    /// committing an empty change.  Any other failure surfaces as
    /// `Err(ServerError)` and is propagated to the client.
    fn server_validation_delete(
        &self,
        change: &ChangelogEntry,
        _auth: &AuthContext,
    ) -> Result<DeleteValidationOutcome, ServerError> {
        // Client resolved the WHERE clause before signing, so column
        // keys carry `row_id` directly.  One probe per unique row_id
        // is enough to decide presence.
        let mut seen: BTreeSet<i64> = BTreeSet::new();
        let mut probe_keys: Vec<&[u8]> = Vec::new();
        for kv in &change.message.entries {
            if let Ok(ParsedKey::Column { row_id, .. }) = parse_key(&kv.key) {
                if seen.insert(row_id) {
                    probe_keys.push(kv.key.as_slice());
                }
            }
        }
        if probe_keys.is_empty() {
            // No column keys — let E&V surface the structural error.
            return Ok(DeleteValidationOutcome::Proceed);
        }
        for key in &probe_keys {
            if self.db.get_value(key)?.is_some() {
                return Ok(DeleteValidationOutcome::Proceed);
            }
        }
        Ok(DeleteValidationOutcome::NoMatchingRows)
    }

    /// Action parallel of [`Self::server_validation_delete`]: if the
    /// entry invokes an action whose primary leg is `Delete`, probe the
    /// primary row's column keys.  When none exist in merk, the
    /// dispatcher reports a graceful no-op (`rows_affected = 0`).  For
    /// any other primary-leg shape (Insert / Update) we proceed and
    /// let E&V handle the entry.
    fn server_validation_action(
        &self,
        change: &ChangelogEntry,
    ) -> Result<DeleteValidationOutcome, ServerError> {
        // The marker kv is at entry position 0; its key carries the
        // primary table and its value carries the action name.
        let marker_kv = change
            .message
            .entries
            .first()
            .ok_or_else(|| ServerError::Generic("Action entry has no kvs".to_string()))?;
        let primary_table = match parse_key(&marker_kv.key)
            .map_err(|e| ServerError::Generic(format!("Action marker key failed to parse: {e}")))?
        {
            ParsedKey::ActionMarker { primary_table } => primary_table,
            other => {
                return Err(ServerError::Generic(format!(
                    "Action entry's first kv is not an action marker; got {other:?}"
                )));
            }
        };
        let action_name = std::str::from_utf8(&marker_kv.value)
            .map_err(|e| ServerError::Generic(format!("Action action-marker is not utf8: {e}")))?;

        let stored = self
            .db
            .get_value(&action_storage_key(&primary_table, action_name))?;
        let Some(stored_bytes) = stored else {
            return Ok(DeleteValidationOutcome::Proceed);
        };
        let body_bytes = decode_action_value(&stored_bytes).map_err(|e| {
            ServerError::Generic(format!("action '{action_name}': decode failed: {e}"))
        })?;
        let body: ActionBody = postcard::from_bytes(body_bytes).map_err(|e| {
            ServerError::Generic(format!(
                "action '{action_name}': deserialization failed: {e}"
            ))
        })?;
        let primary = body
            .legs
            .first()
            .ok_or_else(|| ServerError::Generic(format!("action '{action_name}': has no legs")))?;
        if !matches!(primary, ActionLeg::Delete { .. }) {
            return Ok(DeleteValidationOutcome::Proceed);
        }

        let mut seen: BTreeSet<i64> = BTreeSet::new();
        let mut probe_keys: Vec<&[u8]> = Vec::new();
        for kv in &change.message.entries {
            if let Ok(ParsedKey::Column { table, row_id, .. }) = parse_key(&kv.key) {
                if table == primary_table && seen.insert(row_id) {
                    probe_keys.push(kv.key.as_slice());
                }
            }
        }
        if probe_keys.is_empty() {
            return Ok(DeleteValidationOutcome::Proceed);
        }
        for key in &probe_keys {
            if self.db.get_value(key)?.is_some() {
                return Ok(DeleteValidationOutcome::Proceed);
            }
        }
        Ok(DeleteValidationOutcome::NoMatchingRows)
    }

    /// Staleness protection: check whether any changelog entry after
    /// `change.parent_change` touches the same (tree_path, key) pair.
    /// If so, the client's view is stale and the change is rejected.
    ///
    /// Set `LAST_WRITER_WINS` to `true` to disable this check and allow
    /// concurrent modifications (the last change to arrive wins).
    fn check_concurrent_conflict(&self, change: &ChangelogEntry) -> Result<(), ServerError> {
        const LAST_WRITER_WINS: bool = false;
        if LAST_WRITER_WINS {
            return Ok(());
        }

        // `parent_change` is a 1-indexed change_id (0 if none), while
        // `changes` is a 0-indexed Vec where change_id `k` lives at
        // `changes[k - 1]`. Changes strictly *after* the parent therefore
        // start at index `parent_idx` (== parent_change). Slicing at
        // `parent_idx + 1` skips the first such change — for
        // `parent_change == 0` it skipped `changes[0]` entirely, letting an
        // exact replay slip past the conflict scan.
        let parent_idx = change.parent_change as usize;
        if parent_idx < self.changelog.changes.len() {
            let changes_after_parent = &self.changelog.changes[parent_idx..];
            for existing in changes_after_parent {
                if existing.message.tree_path != change.message.tree_path {
                    continue;
                }
                for existing_entry in &existing.message.entries {
                    for new_entry in &change.message.entries {
                        if existing_entry.key == new_entry.key {
                            return Err(ServerError::Generic(format!(
                                "Update conflict: a {:?} already modified tree_path={:?} key={} after parent change {}",
                                existing.message.op_type,
                                String::from_utf8_lossy(&change.message.tree_path),
                                hex::encode(&new_entry.key),
                                parent_idx
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Dispatch a change to the underlying op handler and return
    /// the resulting pruned Merkle tree.
    ///
    /// Returns `Ok(None)` only for `OpType::Delete` when
    /// [`Self::server_validation_delete`] reports
    /// [`DeleteValidationOutcome::NoMatchingRows`].  The caller must
    /// then treat the change as a graceful no-op (no changelog entry,
    /// no proof, `rows_affected = 0`).
    async fn do_query_with_pruned_merkle_tree(
        &mut self,
        change: &Change,
        auth: &AuthContext,
    ) -> Result<Option<AppliedChangeProof>, ServerError> {
        // 1-indexed id this change will receive once committed (== num_changes + 1).
        let current_change_id = self.changelog.num_changes() as usize + 1;
        let entry = &change.entry;

        if entry.message.tree_path != b"/" {
            return Err(ServerError::Generic(format!(
                "Op requires tree_path \"/\", got {:?}",
                String::from_utf8_lossy(&entry.message.tree_path)
            )));
        }

        match entry.message.op_type {
            OpType::Noop => {
                return Err(ServerError::Generic(
                    "Noop changes are only supported by the FF prover benchmark".to_string(),
                ));
            }
            OpType::Insert | OpType::Update | OpType::Delete => {
                let entry_table = first_table_in_change(entry).ok_or_else(|| {
                    ServerError::Generic(format!(
                        "{:?} entry has no parseable column key to derive its target table",
                        entry.message.op_type
                    ))
                })?;

                if is_internal_table(&entry_table) {
                    return Err(ServerError::Generic(format!(
                        "table '{}' is reserved and cannot be modified by {:?} — \
                         use the dedicated op instead",
                        entry_table, entry.message.op_type
                    )));
                }

                match entry.message.op_type {
                    OpType::Insert => {
                        self.server_validation_insert(change, auth)?;
                    }
                    OpType::Update => {
                        self.check_concurrent_conflict(entry)?;
                        self.server_validation_update(change, auth)?;
                    }
                    OpType::Delete => {
                        self.check_concurrent_conflict(entry)?;
                        match self.server_validation_delete(entry, auth)? {
                            DeleteValidationOutcome::Proceed => {}
                            DeleteValidationOutcome::NoMatchingRows => return Ok(None),
                        }

                        let file_hashes = self.collect_file_hashes_for_delete(entry).await;

                        let pruned_merkle_tree = self
                            .db
                            .apply_change_with_pruned_tree(change, current_change_id)
                            .await?;

                        if let (Some(store), hashes) = (&self.file_store, file_hashes) {
                            for hash in hashes {
                                if let Err(e) = store.delete(&hash) {
                                    log::warn!("Failed to delete file {hash}: {e}");
                                }
                            }
                        }

                        return Ok(Some(AppliedChangeProof { pruned_merkle_tree }));
                    }
                    _ => unreachable!(),
                }
            }
            OpType::RefreshKeys => {
                self.server_validation_refresh_keys(change, auth)?;
            }
            OpType::Action => {
                self.check_concurrent_conflict(entry)?;
                match self.server_validation_action(entry)? {
                    DeleteValidationOutcome::Proceed => {}
                    DeleteValidationOutcome::NoMatchingRows => return Ok(None),
                }
            }
            OpType::CreateSpace => {
                self.server_validation_create_space(change, auth)?;
            }
            OpType::InviteUser => {
                self.server_validation_invite_user(change, auth)?;
            }
            OpType::RemoveUser => {
                self.check_concurrent_conflict(entry)?;
                self.server_validation_remove_user(change, auth)?;
            }
            OpType::Extend => {
                self.server_validation_extend(change, auth)?;
            }
            OpType::Reduce => {
                self.server_validation_reduce(change, auth)?;
            }
            OpType::Rekey => {
                self.server_validation_rekey(change, auth)?;
            }
            OpType::ListAppend | OpType::ListInsert | OpType::ListUpdate | OpType::ListDelete => {
                self.server_validation_list(change, auth)?;
            }
        }

        let pruned_merkle_tree = self
            .db
            .apply_change_with_pruned_tree(change, current_change_id)
            .await?;

        Ok(Some(AppliedChangeProof { pruned_merkle_tree }))
    }

    fn validate_hashed_values(&self, hashed_values: &HashedValues) -> Result<(), ServerError> {
        self.validate_hashed_values_with_limits(hashed_values, HASHED_VALUES_LIMITS)
    }

    /// Enforce size/count limits and check incoming values against the store.
    /// The map keys are already `hashstore_hash(value)` (re-hashed at the wire
    /// boundary by `values_sidecar_from_proto`), so consumers can read the map
    /// directly once this check passes.
    fn validate_hashed_values_with_limits(
        &self,
        hashed_values: &HashedValues,
        limits: HashedValuesLimits,
    ) -> Result<(), ServerError> {
        if hashed_values.len() > limits.max_entries {
            return Err(ServerError::Generic(format!(
                "hashed-values sidecar has {} entries, maximum is {}",
                hashed_values.len(),
                limits.max_entries
            )));
        }

        let mut total_bytes = 0usize;
        for (hash, value) in hashed_values {
            if value.len() > limits.max_value_bytes {
                return Err(ServerError::Generic(format!(
                    "hashed value is {} bytes, maximum is {}",
                    value.len(),
                    limits.max_value_bytes
                )));
            }
            total_bytes = total_bytes.checked_add(value.len()).ok_or_else(|| {
                ServerError::Generic("hashed-values total size overflow".to_string())
            })?;
            if total_bytes > limits.max_total_bytes {
                return Err(ServerError::Generic(format!(
                    "hashed-values total size is {total_bytes} bytes, maximum is {}",
                    limits.max_total_bytes
                )));
            }
            if let Some(existing) = self.hash_store.get(hash) {
                if existing != value {
                    return Err(ServerError::Generic(format!(
                        "hashed value conflict: hash {} already exists with different value",
                        hex::encode(hash)
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_hashed_values_references(
        &self,
        hashed_values: &HashedValues,
        referenced_hashes: &BTreeSet<[u8; 32]>,
    ) -> Result<(), ServerError> {
        for hash in hashed_values.keys() {
            if !referenced_hashes.contains(hash) {
                return Err(ServerError::Generic(format!(
                    "unreferenced hashed value: hash {} is not used by this change",
                    hex::encode(hash)
                )));
            }
        }
        Ok(())
    }

    fn action_delete_tables(&self, change: &Change) -> Result<BTreeSet<String>, ServerError> {
        let marker_kv = change
            .entry
            .message
            .entries
            .first()
            .ok_or_else(|| ServerError::Generic("action change has no entries".to_string()))?;
        let primary_table = match parse_key(&marker_kv.key) {
            Ok(ParsedKey::ActionMarker { primary_table }) => primary_table,
            _ => return Ok(BTreeSet::new()),
        };
        let action_name = std::str::from_utf8(&marker_kv.value)
            .map_err(|_| ServerError::Generic("action marker value is not UTF-8".to_string()))?;

        let storage_key = action_storage_key(&primary_table, action_name);
        let raw = match self.db.get_value(&storage_key) {
            Ok(Some(bytes)) => bytes,
            _ => return Ok(BTreeSet::new()),
        };
        let body_bytes = decode_action_value(&raw)
            .map_err(|e| ServerError::Generic(format!("action '{action_name}': {e}")))?;
        let body: ActionBody = postcard::from_bytes(body_bytes)
            .map_err(|e| ServerError::Generic(format!("action '{action_name}' deser: {e}")))?;

        let mut first_leg_per_table: BTreeMap<&str, &ActionLeg> = BTreeMap::new();
        for leg in &body.legs {
            first_leg_per_table.entry(leg.table()).or_insert(leg);
        }
        Ok(first_leg_per_table
            .into_iter()
            .filter(|(_, leg)| matches!(leg, ActionLeg::Delete { .. }))
            .map(|(table, _)| table.to_string())
            .collect())
    }

    fn require_hashed_values_for_change(
        &self,
        change: &Change,
    ) -> Result<BTreeSet<[u8; 32]>, ServerError> {
        use encrypted_spaces_storage_encoding::HASH_LEN;

        let op = change.entry.message.op_type;
        let is_delete_only = matches!(op, OpType::Delete | OpType::RemoveUser | OpType::ListDelete);
        let mut referenced_hashes = BTreeSet::new();

        let action_delete_tables = if op == OpType::Action {
            self.action_delete_tables(change)?
        } else {
            BTreeSet::new()
        };

        let request_hashes: HashMap<[u8; 32], &[u8]> = change
            .hashed_values
            .iter()
            .map(|(hash, value)| (*hash, value.as_slice()))
            .collect();

        for kv in &change.entry.message.entries {
            let (table, column) = match parse_key(&kv.key) {
                Ok(ParsedKey::Column { table, column, .. }) => (table, column),
                _ => continue,
            };
            let schema = match self.db.get_schema(&table) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let col_def = match schema.columns.iter().find(|c| c.name == column) {
                Some(c) => c,
                None => continue,
            };
            if !col_def.column_type.is_hash_backed() {
                continue;
            }
            if kv.value.is_empty() {
                if is_delete_only {
                    continue;
                }
                if op == OpType::Action && action_delete_tables.contains(&table) {
                    continue;
                }
                return Err(ServerError::Generic(format!(
                    "hash-backed column {}.{} has empty value in {:?} op",
                    table, column, op
                )));
            }
            let hash: [u8; HASH_LEN] = kv.value.as_slice().try_into().map_err(|_| {
                ServerError::Generic(format!(
                    "hash-backed column {}.{} value must be {} bytes, got {}",
                    table,
                    column,
                    HASH_LEN,
                    kv.value.len()
                ))
            })?;
            if !request_hashes.contains_key(&hash) && !self.hash_store.contains_key(&hash) {
                return Err(ServerError::Generic(format!(
                    "missing hashed value for hash-backed column {}.{}: hash {}",
                    table,
                    column,
                    hex::encode(hash)
                )));
            }
            referenced_hashes.insert(hash);
        }
        Ok(referenced_hashes)
    }

    #[cfg(test)]
    fn insert_hashed_values(&mut self, hashed_values: &HashedValues) {
        for (hash, value) in hashed_values {
            self.hash_store
                .entry(*hash)
                .or_insert_with(|| value.clone());
        }
    }

    fn insert_referenced_hashed_values(
        &mut self,
        hashed_values: &HashedValues,
        referenced_hashes: &BTreeSet<[u8; 32]>,
    ) {
        for (hash, value) in hashed_values {
            if referenced_hashes.contains(hash) {
                self.hash_store
                    .entry(*hash)
                    .or_insert_with(|| value.clone());
            }
        }
    }

    fn collect_hashed_values_for_change(&self, change: &Change) -> HashedValues {
        use encrypted_spaces_storage_encoding::HASH_LEN;

        let mut result = HashedValues::new();

        for kv in &change.entry.message.entries {
            let (table, column) = match parse_key(&kv.key) {
                Ok(ParsedKey::Column { table, column, .. }) => (table, column),
                _ => continue,
            };
            let schema = match self.db.get_schema(&table) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let col_def = match schema.columns.iter().find(|c| c.name == column) {
                Some(c) => c,
                None => continue,
            };
            if !col_def.column_type.is_hash_backed() {
                continue;
            }
            let hash: [u8; HASH_LEN] = match kv.value.as_slice().try_into() {
                Ok(h) => h,
                Err(_) => continue,
            };
            if let Some(value) = self.hash_store.get(&hash) {
                result.entry(hash).or_insert_with(|| value.clone());
            }
        }

        result
    }

    fn collect_hashed_values_for_entries(
        &self,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<HashedValues, SdkError> {
        use encrypted_spaces_storage_encoding::HASH_LEN;

        let mut result = HashedValues::new();

        for (key, value) in entries {
            let (table, column) = match parse_key(key) {
                Ok(ParsedKey::Column { table, column, .. }) => (table, column),
                _ => continue,
            };
            let schema = match self.db.get_schema(&table) {
                Ok(schema) => schema,
                Err(_) => continue,
            };
            let Some(col_def) = schema.columns.iter().find(|c| c.name == column) else {
                continue;
            };
            if !col_def.column_type.is_hash_backed() {
                continue;
            }

            let hash: [u8; HASH_LEN] = value.as_slice().try_into().map_err(|_| {
                SdkError::ValidationError(format!(
                    "hash-backed column {table}.{column} stored {} bytes, expected {HASH_LEN}",
                    value.len()
                ))
            })?;
            if result.contains_key(&hash) {
                continue;
            }

            let full_value = self.hash_store.get(&hash).cloned().ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "missing hashed value for selected column {table}.{column}"
                ))
            })?;
            result.insert(hash, full_value);
        }

        Ok(result)
    }

    fn collect_hashed_values_for_select(
        &self,
        query: &Query,
        proof: &[u8],
        commitment: &[u8; 32],
    ) -> Result<HashedValues, SdkError> {
        let entries = encrypted_spaces_backend::merk_storage::proofs::extract_query_proof_entries_for_response_material(
            query,
            proof,
            commitment,
        )?;
        self.collect_hashed_values_for_entries(&entries)
    }

    pub async fn handle_change(
        &mut self,
        change: &Change,
        auth: &AuthContext,
    ) -> Result<ChangeResponse, ServerError> {
        let entry = &change.entry;
        if auth.uid.is_none() {
            return Err(ServerError::Generic("Missing user's UID".to_string()));
        }
        if auth.uid.unwrap() != (entry.uid as i64) {
            return Err(ServerError::Generic(
                "Change not signed by the authenticated user".to_string(),
            ));
        }
        self.validate_hashed_values(&change.hashed_values)?;
        self.verify_change_signature(change, &change.hashed_values)?;
        self.ensure_change_applies(entry)?;
        self.enforce_provisional_restrictions(entry)?;

        // Reject changes whose parent_change is out of range or further back
        // than MAX_PARENT_DISTANCE. The FF proof enforces the same window
        // (see verify_op_sequence in changelog_core), so any change that
        // failed this check here would also fail proof verification later.
        // Surface this as `StaleParent` so the SDK can fast-forward and
        // re-sign rather than treating it as a hard failure.
        let prospective_change_id = (self.changelog.num_changes() as usize).saturating_add(1);
        if !validate_parent_change(entry.parent_change, prospective_change_id) {
            return Err(ServerError::StaleParent(format!(
                "parent_change {} is invalid for prospective change {} \
                 (MAX_PARENT_DISTANCE={MAX_PARENT_DISTANCE})",
                entry.parent_change, prospective_change_id
            )));
        }

        self.validate_parent_clc(entry)?;

        // Sigref-chain continuity: a change's `sig_ref` must point at the
        // signer's previous accepted change_id (0 if this is their first
        // change). The FF guest enforces this for proven ranges; this check
        // covers the per-change submission path so we don't accept a tail
        // that the next FF proof would reject (issue #30). Mirrors the
        // SDK's pre-state-mutation check via the shared helper in
        // `changelog_core`.
        let expected_sig_ref = self.sigref_map.get(&entry.uid).copied().unwrap_or(0);
        check_sigref_continuity(entry, expected_sig_ref)
            .map_err(|e| ServerError::Generic(e.to_string()))?;

        let accepted_at_server_time = ChangelogEntry::get_unix_timestamp();
        validate_change_timestamp_at_acceptance(entry.timestamp, accepted_at_server_time)
            .map_err(|e| ServerError::Generic(e.to_string()))?;
        log::info!(
            "space={} change received uid={}, type={:?}",
            self.space_id,
            entry.uid,
            entry.message.op_type
        );

        let referenced_hashes = self.require_hashed_values_for_change(change)?;
        self.validate_hashed_values_references(&change.hashed_values, &referenced_hashes)?;

        // Change looks good -- apply it to db
        log::debug!("space={} change valid, inserting", self.space_id);

        // Snapshot the tree before the first change in each new batch.
        // This ensures the tracer starts from the correct root, even if
        //  inserts (setup/schema/access rules) happened since init.
        let num_changes = self.changelog.num_changes() as usize;
        if num_changes == self.changelog.proven_up_to {
            self.tree_snapshot = self.db.snapshot();
        }

        let old_root = self.get_root_hash().await;
        let applied = match self
            .do_query_with_pruned_merkle_tree(change, auth)
            .await
            .map_err(|e| {
                ServerError::Generic(format!("do_query_with_pruned_merkle_tree failed: {e}"))
            })? {
            Some(proof) => proof,
            None => {
                // Graceful no-op (Delete with no matching rows).
                // No tree mutation, no changelog entry, no proof.
                log::info!(
                    "space={} change is a no-op ({:?}); responding with rows_affected=0",
                    self.space_id,
                    entry.message.op_type,
                );
                return Ok(ChangeResponse {
                    old_root,
                    new_root: old_root,
                    pruned_merkle_tree: Vec::new(),
                    change_id: self.changelog.num_changes(),
                    rows_affected: 0,
                    accepted_at_server_time,
                    hashed_values: HashedValues::new(),
                });
            }
        };
        let pruned_merkle_tree = applied.pruned_merkle_tree;
        let new_root = self.get_root_hash().await;
        log::info!(
            "space={} change applied: root {} -> {}",
            self.space_id,
            hex::encode(old_root),
            hex::encode(new_root)
        );

        self.insert_referenced_hashed_values(&change.hashed_values, &referenced_hashes);
        let response_hashed_values = self.collect_hashed_values_for_change(change);
        let change_id =
            self.changelog
                .add_change(entry, &pruned_merkle_tree, &old_root, &new_root)?;

        // Advance the per-user sigref chain for the signer. The change has
        // passed `check_sigref_continuity` against `expected_sig_ref`, so
        // installing `change_id` here makes the next change by this user
        // have to point at this entry. Only updated for accepted (non-no-op)
        // changes — no-op deletes return early above without appending.
        self.sigref_map.insert(entry.uid, change_id);

        let server_new_clc: [u8; 32] = self.changelog.current_root();
        log::debug!(
            "space={} add_change: change_id={} op={:?} entry_len={} new_clc={}",
            self.space_id,
            change_id,
            entry.message.op_type,
            entry.as_bytes().len(),
            hex::encode(server_new_clc)
        );

        let response = ChangeResponse {
            old_root,
            new_root,
            pruned_merkle_tree,
            change_id,
            rows_affected: rows_affected(entry),
            accepted_at_server_time,
            hashed_values: response_hashed_values,
        };
        self.change_responses.push(response.clone());

        self.maybe_generate_ff_proof()?;

        Ok(response)
    }

    /// Check if we should generate a new FF proof and do so if needed.
    fn maybe_generate_ff_proof(&mut self) -> Result<(), ServerError> {
        let num_changes = self.changelog.num_changes() as usize;
        let proven_up_to = self.changelog.proven_up_to;

        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            log::info!(
                "Skipping fast-forward proof generation since server was
            compiled with RISC0_SKIP_BUILD.  Fast-forward data will not be succinct. "
            );
            return Ok(());
        } else if num_changes >= proven_up_to + self.ff_batch_size {
            log::info!(
                "space={} generating FF proof at change {num_changes} (batch_size={})",
                self.space_id,
                self.ff_batch_size
            );
            let tree_snapshot = self.tree_snapshot.as_ref().ok_or_else(|| {
                ServerError::Generic(format!(
                    "space={} cannot generate FF proof at change {}: missing batch-start tree snapshot",
                    self.space_id, num_changes
                ))
            })?;

            update_changelog_proof(
                &mut self.changelog,
                &self.change_responses,
                self.ff_proof.as_ref(),
                tree_snapshot,
            )
            .map_err(|e| {
                ServerError::Generic(format!(
                    "space={} fast-forward proof generation failed at change {}: {}",
                    self.space_id, num_changes, e
                ))
            })?;

            self.ff_proof = Some(FFProof::deserialize(&self.changelog.ff_proof).map_err(|e| {
                ServerError::Generic(format!(
                    "space={} failed to deserialize newly generated FF proof at change {}: {}",
                    self.space_id, num_changes, e
                ))
            })?);
            self.tree_snapshot = Some(self.db.snapshot().ok_or_else(|| {
                ServerError::Generic(format!(
                    "space={} missing tree snapshot after FF proof update at change {}",
                    self.space_id, num_changes
                ))
            })?);
            log::info!(
                "space={} FF proof updated, proven_up_to={}",
                self.space_id,
                self.changelog.proven_up_to
            );
        }

        Ok(())
    }

    /// Collect file hashes from plaintext FileRef columns in the rows the
    /// signed `change` is about to delete. The change's column keys carry
    /// the resolved row_ids, so a SELECT with `id IN […]` reproduces the
    /// same set the client signed against.
    /// Returns an empty vec if the table has no plaintext FileRef columns
    /// or if reading fails.
    async fn collect_file_hashes_for_delete(&self, change: &ChangelogEntry) -> Vec<String> {
        use encrypted_spaces_backend::query::{ComparisonOperator, Predicate};

        // Only proceed if there's a file store configured
        if self.file_store.is_none() {
            return vec![];
        }

        let mut table_name: Option<String> = None;
        let mut row_ids: BTreeSet<i64> = BTreeSet::new();
        for kv in &change.message.entries {
            if let Ok(ParsedKey::Column { table, row_id, .. }) = parse_key(&kv.key) {
                table_name.get_or_insert_with(|| table.clone());
                row_ids.insert(row_id);
            }
        }
        let table_name = match table_name {
            Some(t) => t,
            None => return vec![],
        };
        if row_ids.is_empty() {
            return vec![];
        }

        let schema = match self.db.get_schema(&table_name) {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        let file_ref_columns: Vec<&str> = schema
            .columns
            .iter()
            .filter(|c| matches!(c.column_type, ColumnType::FileRef) && c.plaintext)
            .map(|c| c.name.as_str())
            .collect();

        if file_ref_columns.is_empty() {
            return vec![];
        }

        let mut select_query = Query::new(table_name, QueryOperation::Select(vec!["*".into()]));
        let id_values: Vec<QueryParam> =
            row_ids.iter().map(|&id| QueryParam::Integer(id)).collect();
        select_query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: if id_values.len() == 1 {
                ComparisonOperator::Equal
            } else {
                ComparisonOperator::In
            },
            values: id_values,
            cursor_id: None,
        });

        let rows: Vec<serde_json::Value> = match self.db.select_all(select_query).await {
            Ok(rows) => rows,
            Err(_) => return vec![],
        };

        let mut hashes = Vec::new();
        for row in rows {
            if let Some(obj) = row.as_object() {
                for col_name in &file_ref_columns {
                    if let Some(serde_json::Value::String(hash)) = obj.get(*col_name) {
                        if !hash.is_empty() {
                            hashes.push(hash.clone());
                        }
                    }
                }
            }
        }
        hashes
    }

    /// Verify the client's data commitment matches the server root, then generate
    /// a query proof. Returns `SdkError::FastForwardRequired` on commitment mismatch.
    pub async fn handle_select(
        &self,
        query: &Query,
        commitment: &[u8],
    ) -> Result<SelectProofResponse, SdkError> {
        if commitment.is_empty() {
            return Err(SdkError::ValidationError(
                "select request must include a data commitment".into(),
            ));
        }

        let root = self.db.root_hash();

        // TODO: Support querying against old snapshots
        if commitment != root {
            return Err(SdkError::FastForwardRequired {
                reason: format!(
                    "client data commitment does not match server root \
                     (client={}, server={})",
                    hex::encode(commitment),
                    hex::encode(root),
                ),
            });
        }

        let proof = self
            .db
            .prove_query(query)
            .await
            .map_err(|e| SdkError::DatabaseError(format!("failed to generate proof: {e:?}")))?;
        let hashed_values = self.collect_hashed_values_for_select(query, &proof, &root)?;

        Ok(SelectProofResponse {
            proof,
            hashed_values,
        })
    }

    ///
    /// Returns fast-forward data that includes a RISC0 proof when available:
    /// - If the client is at change_id 0, they get the full proof.
    /// - If the client is behind the proven range, they get the proof + individual changes.
    /// - If there's no proof yet, return individual changes (there will be at most ff_batch_size-1).
    pub fn handle_fast_forward(
        &mut self,
        from_change_id: u32,
        expected_change_ids: &[u32],
        _auth: &AuthContext,
    ) -> Result<FastForwardData, ServerError> {
        // TODO: we can use auth context to decide if this user can see certain changes.
        // E.g., if they are new and should only see a ZKP of past changes, we might have to trigger proof generation

        // Self-check -- we're assuming for now that we store all the changes and responses on the server
        assert!(self.changelog.changes.len() == self.change_responses.len());

        let num_changes = self.changelog.num_changes() as usize;
        let proven_up_to = self.changelog.proven_up_to;
        let from_idx = from_change_id as usize;
        // Server's view of the head, surfaced to the client as 16-byte
        // prefixes only. Just enough for the client to detect divergence;
        // intentionally too short to be adopted as authoritative roots.
        let server_change_id = num_changes as u32;
        let server_clc_full: [u8; 32] = self.changelog.current_root();
        let server_dc_full: [u8; 32] = self.db.root_hash();
        let mut server_clc_prefix = [0u8; 16];
        server_clc_prefix.copy_from_slice(&server_clc_full[..16]);
        let mut server_data_commitment_prefix = [0u8; 16];
        server_data_commitment_prefix.copy_from_slice(&server_dc_full[..16]);

        if from_idx > num_changes {
            return Err(ServerError::Generic(format!(
                "Client change_id {from_change_id} is ahead of server {num_changes}"
            )));
        }

        // Include proof if we have one and client is behind proven_up_to, otherwise just give individual changes.
        let (proof, ragged_start) = if !self.changelog.ff_proof.is_empty()
            && (from_change_id as usize) < proven_up_to
        {
            // Build sigref_entries: for each user's latest change_id in the
            // proof's sigref_map, include the signed ChangelogEntry so the
            // client can verify one signature per user.
            //
            // The map value is `(change_id, entry_hash)`; only the change_id
            // is needed here to look up the entry — the hash is the
            // server-independent binding consumed by the client.
            let sigref_entries = if let Some(ref ff) = self.ff_proof {
                let mut entries = std::collections::BTreeMap::new();
                for &(change_id, _entry_hash) in ff.io.sigref_map.values() {
                    // change_ids are 1-based; changelog.changes is 0-based
                    let idx = change_id as usize - 1;
                    if idx < self.changelog.changes.len() {
                        entries.insert(change_id, self.changelog.changes[idx].clone());
                    }
                }
                entries
            } else {
                std::collections::BTreeMap::new()
            };

            // Build inclusion proofs against the FF proof's proven
            // changelog commitment:
            //
            //   * `from_inclusion_proof` — proves the client's prior
            //     change (`from_change_id`) is on the same branch the
            //     FF proof terminates on. Skipped when `from_change_id
            //     == 0`; the initial DC binding is already enforced by
            //     the start-state checks on the client.
            //   * `end_entry_inclusion_proof` + `end_entry` — gives
            //     the client a fresh anchor when there are no ragged
            //     changes after the proof. If ragged changes are
            //     returned, the last ragged change is already signed
            //     and becomes the next anchor.
            //
            // Both proofs are generated against the *proven*
            // snapshot maintained incrementally on `set_ff_proof`.
            let from_inclusion_proof = if from_change_id == 0 {
                None
            } else {
                Some(
                        self.changelog
                            .prove_included_in_ff_range(from_change_id)
                            .ok_or_else(|| {
                                ServerError::Generic(format!(
                                    "fast_forward: failed to build inclusion proof for from_change_id={from_change_id} (proven_up_to={proven_up_to})"
                                ))
                            })?,
                    )
            };
            // proven_up_to >= 1 here (guarded by the outer `if`,
            // since `from_change_id < proven_up_to` and
            // `from_change_id >= 0`).
            let end_change_id_u32 = proven_up_to as u32;
            let needs_end_anchor = proven_up_to == num_changes;
            let (end_entry, end_entry_inclusion_proof) = if needs_end_anchor {
                let end_entry = self.changelog.changes[proven_up_to - 1].clone();
                let end_entry_inclusion_proof = self
                    .changelog
                    .prove_included_in_ff_range(end_change_id_u32)
                    .ok_or_else(|| {
                        ServerError::Generic(format!(
                            "fast_forward: failed to build inclusion proof for end_change_id={end_change_id_u32}"
                        ))
                    })?;
                (Some(end_entry), Some(end_entry_inclusion_proof))
            } else {
                (None, None)
            };

            // Issue #212: prove the client's *exact* pending local entries are
            // incorporated. For each requested expected change_id that falls
            // inside the proven range, return an inclusion proof against
            // `end_clc_state`; the client verifies it with `h_leaf` of its own
            // submitted entry bytes. Expected ids beyond `proven_up_to` are
            // matched directly by the client against the ragged changes below.
            //
            // `bounded_expected_change_ids` caps the number we examine to
            // `MAX_FF_EXPECTED_INCLUSION_PROOFS` so a client cannot force the
            // server to build a proof per change in the proven range
            // (DoS/amplification). The honest client sends a small, ascending
            // list; the cap only ever causes a fail-closed retry, never a
            // false success.
            let mut expected_inclusion_proofs = std::collections::BTreeMap::new();
            for cid in bounded_expected_change_ids(expected_change_ids, proven_up_to) {
                if let Some(incl) = self.changelog.prove_included_in_ff_range(cid) {
                    expected_inclusion_proofs.insert(cid, incl);
                }
            }

            let ff_proof = FastForwardProof {
                end_change_id: end_change_id_u32,
                proof: self.changelog.ff_proof.clone(),
                sigref_entries,
                from_inclusion_proof,
                end_entry,
                end_entry_inclusion_proof,
                expected_inclusion_proofs,
            };
            (Some(ff_proof), proven_up_to)
        } else {
            (None, from_idx)
        };

        let changes = self.changelog.changes[ragged_start..].to_vec();
        let responses = self.change_responses[ragged_start..].to_vec();

        if proof.is_some() && !changes.is_empty() {
            log::info!(
                "space={} fast_forward: proof up to {proven_up_to} + {} ragged changes",
                self.space_id,
                changes.len()
            );
        } else if proof.is_none() && !changes.is_empty() {
            log::info!(
                "space={} fast_forward: client at {from_change_id}, returning {} individual changes (no proof)",
                self.space_id, changes.len()
            );
        }

        Ok(FastForwardData {
            proof,
            changes,
            responses,
            server_head: Some(FastForwardServerHead {
                change_id: server_change_id,
                clc_prefix: server_clc_prefix,
                data_commitment_prefix: server_data_commitment_prefix,
            }),
        })
    }

    pub async fn handle_add_member(
        &mut self,
        request: &InviteRequest,
        insert_change: &Change,
        auth: &AuthContext,
        retention_proofs: &[Vec<u8>],
    ) -> Result<ChangeResponse, ServerError> {
        self.validate_hashed_values(&insert_change.hashed_values)?;

        // 1. Extract the new member's PK from the signed entry's
        //    `_users.update_key` column. Hash-backed internal key columns
        //    carry their full stored bytes in the hashed-values sidecar.
        let new_member_pk: <DefaultMkem as Mkem>::PublicKey = {
            let update_key_bytes = column_value_for_table(
                insert_change,
                USERS_TABLE_NAME,
                "update_key",
                &insert_change.hashed_values,
            )
            .ok_or_else(|| {
                ServerError::Generic("missing _users.update_key entry in invite_user change".into())
            })?;
            let update_key_json: Value =
                stored_value::bytes_to_value(&update_key_bytes).map_err(|e| {
                    ServerError::Generic(format!("decode _users.update_key bytes: {e}"))
                })?;
            let update_key_b64 = update_key_json.as_str().ok_or_else(|| {
                ServerError::Generic("_users.update_key is not a base64 string".into())
            })?;
            let json_bytes = base64::engine::general_purpose::STANDARD
                .decode(update_key_b64)
                .map_err(|e| ServerError::Generic(format!("base64 decode update_key: {e}")))?;
            serde_json::from_slice(&json_bytes)
                .map_err(|e| ServerError::Generic(format!("deserialize update_key: {e}")))?
        };

        // 2. Verify the invite's commitment matches the server's canonical
        //    current group-key commitment. The MVE proof only checks that the
        //    invite is internally consistent with its own claimed commitment;
        //    without this check, a malicious inviter could wrap a group key
        //    that decrypts successfully but does not match the canonical key,
        //    leaving the invitee unable to access the group. The reader
        //    exposes the pre-op retention state — InviteUser writes no
        //    retention rows, so the canonical commitment read here is the
        //    one the MVE envelope must be bound to.
        let pre_state = self.retention_reader();
        let canonical_commitment =
            <SimpleLine2SpaceKey as SpaceKey>::canonical_group_key_commitment(&pre_state)
                .await
                .map_err(|_| {
                    ServerError::Generic(
                        "failed to load canonical group-key commitment".to_string(),
                    )
                })?;
        if canonical_commitment != request.root_commitment {
            return Err(ServerError::Generic(
                "invite root_commitment does not match canonical current group-key commitment"
                    .to_string(),
            ));
        }

        // 3. Verify the invite MVE proof (no epoch advance for invites).
        let ciphertexts = verify_invite(&new_member_pk, request)
            .map_err(|_| ServerError::Generic("invite MVE verification failed".to_string()))?;

        // 4. Verify retention proofs before applying changes.
        self.verify_retention_proofs_from_change(
            insert_change.entry.message.op_type,
            retention_proofs,
            insert_change,
        )
        .await?;

        // 5. Insert the new user record as a tracked changelog entry.
        let change_response = self.handle_change(insert_change, auth).await?;

        // 6. Extract the newly assigned user ID from the invite user proof.
        let new_user_id = extract_row_id_from_invite_user_proof(
            &insert_change.entry,
            &change_response.pruned_merkle_tree,
            &change_response.old_root,
            &change_response.new_root,
            change_response.change_id as usize,
        )
        .map_err(|e| ServerError::Generic(format!("extract row id failed: {e:?}")))?;

        // 7. Write the invite envelope into the new user's GK delivery slot.
        //    Slot updates are best-effort key-delivery state; the canonical
        //    insert above has already committed.
        let ciphertext = ciphertexts
            .get(0)
            .ok_or_else(|| ServerError::Generic("missing ciphertext for new member".to_string()))?;
        let envelope = GkDeliveryEnvelope {
            binding_commitment: request.root_commitment,
            ciphertext: ciphertext.clone(),
        };
        let envelope_bytes = serde_json::to_vec(&envelope).map_err(|e| {
            ServerError::Generic(format!("delivery envelope serialization failed: {e}"))
        })?;
        self.key_delivery_slots.put(new_user_id, envelope_bytes);

        Ok(change_response)
    }

    pub async fn handle_remove_member(
        &mut self,
        request: &RekeyRequest,
        remaining_uids: &[i64],
        delete_change: &Change,
        auth: &AuthContext,
        retention_proofs: &[Vec<u8>],
    ) -> Result<ChangeResponse, ServerError> {
        // 1. Look up remaining member PKs from _users by UID, preserving the caller's order.
        let users_schema = self.db.get_schema(USERS_TABLE_NAME)?;
        let rows = self
            .select_table_rows_resolving_hashes(USERS_TABLE_NAME, &users_schema)
            .await?;

        let uid_to_pk: HashMap<i64, <DefaultMkem as Mkem>::PublicKey> = rows
            .iter()
            .filter_map(|row| {
                let id = row.get("id")?.as_i64()?;
                let b64 = row.get("update_key")?.as_str()?;
                let json_bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
                let pk = serde_json::from_slice(&json_bytes).ok()?;
                Some((id, pk))
            })
            .collect();

        // Enforce that the client-provided `remaining_uids` exactly equals the
        // authoritative survivor set (_users minus the deleted rows). Otherwise
        // a caller could omit a still-valid survivor from the rekey recipient
        // set and leave them with no delivery slot material.
        let removed_in_change = removed_user_ids_in_change(&delete_change.entry);
        let expected_survivors: BTreeSet<i64> = uid_to_pk
            .keys()
            .copied()
            .filter(|uid| !removed_in_change.contains(uid))
            .collect();
        let requested_survivors: BTreeSet<i64> = remaining_uids.iter().copied().collect();
        if requested_survivors != expected_survivors {
            return Err(ServerError::Generic(format!(
                "remaining_uids does not match authoritative survivor set: \
                 requested={requested_survivors:?} expected={expected_survivors:?}"
            )));
        }

        let remaining_members: Vec<(i64, <DefaultMkem as Mkem>::PublicKey)> = remaining_uids
            .iter()
            .map(|&uid| {
                uid_to_pk
                    .get(&uid)
                    .map(|pk| (uid, pk.clone()))
                    .ok_or_else(|| ServerError::Generic(format!("uid {uid} not found in _users")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // 2. Verify the rekey MVE proof.
        let pks: Vec<_> = remaining_members.iter().map(|(_, pk)| pk.clone()).collect();
        let ciphertexts = verify_rekey(&pks, request)
            .map_err(|_| ServerError::Generic("rekey MVE verification failed".to_string()))?;

        // 3. Verify retention proofs before applying changes.
        self.verify_retention_proofs_from_change(
            delete_change.entry.message.op_type,
            retention_proofs,
            delete_change,
        )
        .await?;

        // 4. Verify the rekey's new_root_commitment matches the canonical
        //    post-rekey group-key commitment that the retention writes
        //    establish. The MVE proof above only checks that the envelope
        //    is internally consistent with its own claimed commitment;
        //    this check binds the envelope's commitment to the rows that
        //    will land in retention storage.
        self.verify_rekey_new_root_commitment_from_change(
            delete_change,
            &request.new_root_commitment,
        )
        .await?;

        // 5. Execute the change.
        let change_response = self.handle_change(delete_change, auth).await?;

        // 7. Clear the removed user's delivery slot.
        for row_id in removed_user_ids_in_change(&delete_change.entry) {
            self.key_delivery_slots.remove(row_id);
        }

        // 8. Refresh each remaining member's GK delivery slot with their
        //    rekey envelope. Slot writes are best-effort; the canonical
        //    retention mutation has already committed above.
        for (i, (uid, _)) in remaining_members.iter().enumerate() {
            let ciphertext = ciphertexts.get(i).ok_or_else(|| {
                ServerError::Generic(format!("missing ciphertext for member index {i}"))
            })?;
            let envelope = GkDeliveryEnvelope {
                binding_commitment: request.new_root_commitment,
                ciphertext,
            };
            let envelope_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                ServerError::Generic(format!("delivery envelope serialization failed: {e}"))
            })?;
            self.key_delivery_slots.put(*uid, envelope_bytes);
        }

        Ok(change_response)
    }

    /// Submit a retention-only operation (Extend, Reduce, standalone Rekey).
    ///
    /// When `rekey_request` is `Some`, verifies the MVE proof and writes
    /// delivery slots for all current members.
    pub async fn handle_retention(
        &mut self,
        change: &Change,
        auth: &AuthContext,
        retention_proofs: Vec<Vec<u8>>,
        rekey_request: Option<&RekeyRequest>,
    ) -> Result<ChangeResponse, ServerError> {
        // 1. Verify retention proofs.
        self.verify_retention_proofs_from_change(
            change.entry.message.op_type,
            &retention_proofs,
            change,
        )
        .await?;

        // 2. If this is a rekey, bind the envelope's new_root_commitment to
        //    the canonical post-rekey commitment, verify MVE, and prepare
        //    delivery slots. The MVE proof only checks the envelope is
        //    internally consistent with its own claimed commitment; the
        //    canonical-commitment check here ensures the envelope binds
        //    members to the same key the retention writes establish.
        let delivery_envelopes = if change.entry.message.op_type == OpType::Rekey {
            let request = rekey_request.ok_or_else(|| {
                ServerError::Generic("rekey op missing delivery envelope".to_string())
            })?;

            self.verify_rekey_new_root_commitment_from_change(change, &request.new_root_commitment)
                .await?;

            // Fetch all current user PKs.
            let users_schema = self.db.get_schema(USERS_TABLE_NAME)?;
            let rows = self
                .select_table_rows_resolving_hashes(USERS_TABLE_NAME, &users_schema)
                .await?;

            let members: Vec<(i64, <DefaultMkem as Mkem>::PublicKey)> = rows
                .iter()
                .filter_map(|row| {
                    let id = row.get("id")?.as_i64()?;
                    let b64 = row.get("update_key")?.as_str()?;
                    let json_bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
                    let pk = serde_json::from_slice(&json_bytes).ok()?;
                    Some((id, pk))
                })
                .collect();

            let pks: Vec<_> = members.iter().map(|(_, pk)| pk.clone()).collect();
            let ciphertexts = verify_rekey(&pks, request)
                .map_err(|_| ServerError::Generic("rekey MVE verification failed".to_string()))?;

            let mut envelopes = Vec::with_capacity(members.len());
            for (i, (uid, _)) in members.iter().enumerate() {
                let ciphertext = ciphertexts.get(i).ok_or_else(|| {
                    ServerError::Generic(format!("missing ciphertext for member index {i}"))
                })?;
                let envelope = GkDeliveryEnvelope {
                    binding_commitment: request.new_root_commitment,
                    ciphertext,
                };
                let envelope_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                    ServerError::Generic(format!("delivery envelope serialization failed: {e}"))
                })?;
                envelopes.push((*uid, envelope_bytes));
            }
            Some(envelopes)
        } else {
            None
        };

        // 3. Execute the change.
        let change_response = self.handle_change(change, auth).await?;

        // 4. Write delivery slots if rekey.
        if let Some(envelopes) = delivery_envelopes {
            for (uid, envelope_bytes) in envelopes {
                self.key_delivery_slots.put(uid, envelope_bytes);
            }
        }

        Ok(change_response)
    }

    /// Submit a changelog entry with retention proof verification.
    ///
    /// Used for CreateSpace and other ops that go through `submit_change`
    /// and may carry retention proofs.
    pub async fn handle_change_with_proofs(
        &mut self,
        change: &Change,
        auth: &AuthContext,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse, ServerError> {
        // Verify retention proofs before applying the change.
        self.verify_retention_proofs_from_change(
            change.entry.message.op_type,
            &retention_proofs,
            change,
        )
        .await?;

        self.handle_change(change, auth).await
    }

    /// Build an OperationBuilder from the pending retention writes in the
    /// signed entry and the existing server retention state, then verify
    /// the proofs.
    async fn verify_retention_proofs_from_change(
        &self,
        op_type: OpType,
        retention_proofs: &[Vec<u8>],
        change: &Change,
    ) -> Result<(), ServerError> {
        let retention_writes = extract_retention_writes_from_change(change);

        // The verifier reads pre-op invariants (canonical current group-key
        // commitment) from pre_state and reads the operation's new rows
        // strictly from retention_writes (see PendingWritesView in the
        // space-key impl) — callers don't synthesize a post-write view here.
        let pre_state = self.retention_reader();
        let pending = PendingWritesView::new(&retention_writes);

        <SimpleLine2SpaceKey as SpaceKey>::verify_retention_proofs(
            op_type,
            retention_proofs,
            &pre_state,
            &pending,
        )
        .await
        .map_err(|_| ServerError::Generic("retention proof verification failed".to_string()))
    }

    /// Verify that `new_root_commitment` from a rekey request matches the
    /// canonical current group-key commitment that the rekey's retention
    /// writes are about to establish.
    ///
    /// The MVE proof only checks that the rekey envelope is internally
    /// consistent with its own claimed commitment; without this check, a
    /// malicious rekey initiator could wrap a group key whose envelope
    /// decrypts successfully but does not match the canonical key written
    /// to retention storage, leaving members with a key that can't decrypt
    /// post-rekey data.
    ///
    /// Reads the canonical commitment from `PendingWritesView`: a rekey
    /// writes the new FGK row, `fgk_next`, and resets `dgk_next` to 0, so
    /// every key `canonical_group_key_commitment` reads is in the pending
    /// payload — no fallback to pre-op state is needed.
    async fn verify_rekey_new_root_commitment_from_change(
        &self,
        change: &Change,
        expected: &KeyCommitment,
    ) -> Result<(), ServerError> {
        let retention_writes = extract_retention_writes_from_change(change);
        let pending = PendingWritesView::new(&retention_writes);
        let canonical = <SimpleLine2SpaceKey as SpaceKey>::canonical_group_key_commitment(&pending)
            .await
            .map_err(|_| {
                ServerError::Generic(
                    "failed to load canonical group-key commitment from rekey writes".to_string(),
                )
            })?;
        if canonical != *expected {
            return Err(ServerError::Generic(
                "rekey new_root_commitment does not match canonical post-rekey \
                 group-key commitment"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Build a `CollectingOperationBuilder` whose reader queries the
    /// `_retention` table on demand via `where_eq("key", k)`, mirroring the
    /// SDK's client-side retention builder.
    ///
    /// The reader clones the merk handle (internally `Arc<Merk>`) so each
    /// lookup does a targeted query, instead of loading all retention rows
    /// into memory upfront. A scalar retention key may be represented by
    /// multiple rows because retention writers use INSERT queries; the
    /// highest-id row is always the most recent write, so the reader
    /// returns that.
    fn retention_reader(&self) -> CollectingOperationBuilder {
        let db = self.db.clone();
        let reader: AsyncReader = Box::new(move |key: &str| {
            let db = db.clone();
            let key = key.to_string();
            Box::pin(async move {
                let mut query = Query::new(
                    RETENTION_TABLE_NAME.to_string(),
                    QueryOperation::Select(vec!["id".to_string(), "value".to_string()]),
                );
                query.predicate = Some(Predicate {
                    column: "key".to_string(),
                    operator: ComparisonOperator::Equal,
                    values: vec![QueryParam::Text(key)],
                    cursor_id: None,
                });

                let latest = db
                    .query_rows(&query)
                    .map_err(|_| KeyManagerError)?
                    .into_iter()
                    .max_by_key(|row| row.get("id").and_then(|v| v.as_i64()).unwrap_or(0));

                match latest {
                    None => Ok(None),
                    Some(row) => {
                        let value_b64 = row
                            .get("value")
                            .and_then(|v| v.as_str())
                            .ok_or(KeyManagerError)?;
                        let value = base64::engine::general_purpose::STANDARD
                            .decode(value_b64)
                            .map_err(|_| KeyManagerError)?;
                        Ok(Some(value))
                    }
                }
            })
        });

        CollectingOperationBuilder::new(reader)
    }
}

/// Compute the number of rows affected by a changelog entry.
///
/// With per-column storage, `entries.len()` counts columns not rows.
/// - **Insert**: always 1 row
/// - **Update / Delete**: count unique row_ids across column keys
/// - **List ops**: always 1 entry
fn rows_affected(change: &ChangelogEntry) -> u64 {
    match change.message.op_type {
        OpType::Insert => 1,
        OpType::Update | OpType::Delete | OpType::RefreshKeys => {
            let unique_rows: BTreeSet<i64> = change
                .message
                .entries
                .iter()
                .filter_map(|kv| match parse_key(&kv.key) {
                    Ok(ParsedKey::Column { row_id, .. }) => Some(row_id),
                    _ => None,
                })
                .collect();
            unique_rows.len().max(1) as u64
        }
        OpType::CreateSpace
        | OpType::InviteUser
        | OpType::RemoveUser
        | OpType::Extend
        | OpType::Reduce
        | OpType::Rekey => 1,
        OpType::ListAppend | OpType::ListInsert | OpType::ListUpdate | OpType::ListDelete => 1,
        OpType::Noop => 0,
        OpType::Action => {
            // Same shape as Update/Delete: count unique column-key row_ids.
            // (The action-marker kv parses as a non-column key and is
            // naturally filtered out by the match arm above.)
            let unique_rows: BTreeSet<i64> = change
                .message
                .entries
                .iter()
                .filter_map(|kv| match parse_key(&kv.key) {
                    Ok(ParsedKey::Column { row_id, .. }) => Some(row_id),
                    _ => None,
                })
                .collect();
            unique_rows.len().max(1) as u64
        }
    }
}

struct QueuedRequest {
    request: DbRequest,
    response_tx: oneshot::Sender<DbResponse>,
    app_cfg: AppConfig,
    auth_context: AuthContext,
}

static REQUEST_QUEUE: Lazy<mpsc::UnboundedSender<QueuedRequest>> = Lazy::new(|| {
    let (tx, mut rx) = mpsc::unbounded_channel::<QueuedRequest>();

    tokio::spawn(async move {
        while let Some(QueuedRequest {
            request,
            response_tx,
            app_cfg,
            auth_context,
        }) = rx.recv().await
        {
            let response = process_request_directly(request, app_cfg, auth_context).await;
            let _ = response_tx.send(response);
        }
    });

    tx
});

pub async fn dispatch(
    request: DbRequest,
    app_cfg: AppConfig,
    auth_context: AuthContext,
) -> DbResponse {
    let request_id = request.request_id.clone();
    let (response_tx, response_rx) = oneshot::channel();

    if REQUEST_QUEUE
        .send(QueuedRequest {
            request,
            response_tx,
            app_cfg,
            auth_context,
        })
        .is_err()
    {
        return error_response(&request_id, "request_queue_closed");
    }

    match response_rx.await {
        Ok(response) => response,
        Err(_) => error_response(&request_id, "request_processing_failed"),
    }
}

async fn process_request_directly(
    request: DbRequest,
    app_cfg: AppConfig,
    auth_context: AuthContext,
) -> DbResponse {
    let opn = op_name(&request.operation);
    log::debug!(
        "space={} process_request: start request_id={} op={}",
        auth_context.space_id,
        request.request_id,
        opn
    );

    let response = match request.operation {
        Some(db_request::Operation::Select(select_req)) => {
            handle_select(&request.request_id, select_req, &app_cfg, &auth_context).await
        }
        Some(db_request::Operation::Change(change_req)) => {
            handle_change(&request.request_id, change_req, &app_cfg, &auth_context).await
        }
        Some(db_request::Operation::FastForward(fast_forward_req)) => {
            handle_fast_forward(
                &request.request_id,
                fast_forward_req,
                &app_cfg,
                &auth_context,
            )
            .await
        }
        Some(db_request::Operation::AddMember(add_member_req)) => {
            handle_add_member_request(&request.request_id, add_member_req, &app_cfg, &auth_context)
                .await
        }
        Some(db_request::Operation::RemoveMember(req)) => {
            handle_remove_member_request(&request.request_id, req, &app_cfg, &auth_context).await
        }
        Some(db_request::Operation::Retention(req)) => {
            handle_retention_request(&request.request_id, req, &app_cfg, &auth_context).await
        }
        Some(db_request::Operation::FetchMyKeyDelivery(req)) => {
            crate::key_delivery::handle_fetch_my_key_delivery_request(
                &request.request_id,
                req,
                &app_cfg,
                &auth_context,
            )
            .await
        }
        None => error_response(&request.request_id, "missing_operation"),
    };

    log::debug!(
        "space={} process_request: response request_id={} status={}",
        auth_context.space_id,
        response.request_id,
        response.status,
    );

    if opn != "Select" && opn != "FastForward" {
        let log_context = format!("After request of type {opn:?}, database is:");
        get_or_create_space(auth_context.space_id, Some(&app_cfg))
            .await
            .lock()
            .await
            .log_server_state(&log_context);
    }

    response
}

async fn handle_select(
    request_id: &str,
    req: proto::SelectRequest,
    app_cfg: &AppConfig,
    auth_context: &AuthContext,
) -> DbResponse {
    let query: Query = match req.query {
        Some(q) => q.into(),
        None => return error_response(request_id, "missing_query"),
    };

    log::info!(
        "space={} select: request_id={request_id} query={query:?}",
        auth_context.space_id
    );

    let space = get_or_create_space(auth_context.space_id, Some(app_cfg)).await;
    let result = space
        .lock()
        .await
        .handle_select(&query, &req.commitment)
        .await;
    match result {
        Ok(select_response) => ok_response(
            request_id,
            db_response::Result::Select(proto::SelectResponse {
                proof: select_response.proof,
                values_sidecar: proto::values_sidecar_to_proto(&select_response.hashed_values),
            }),
        ),
        Err(SdkError::FastForwardRequired { reason, .. }) => {
            fast_forward_required_response(request_id, &reason)
        }
        Err(e) => error_response(request_id, &e.to_string()),
    }
}

async fn handle_change(
    request_id: &str,
    req: proto::ChangeRequest,
    app_cfg: &AppConfig,
    auth_context: &AuthContext,
) -> DbResponse {
    let changelog_entry: ChangelogEntry = match req.change {
        Some(ce) => ce.into(),
        None => return error_response(request_id, "missing_changelog_entry"),
    };

    let retention_proofs = req.retention_proofs;
    let change = Change {
        entry: changelog_entry,
        hashed_values: proto::values_sidecar_from_proto(req.values_sidecar),
    };

    match get_or_create_space(auth_context.space_id, Some(app_cfg))
        .await
        .lock()
        .await
        .handle_change_with_proofs(&change, auth_context, retention_proofs)
        .await
    {
        Ok(change_response) => ok_response(
            request_id,
            db_response::Result::Change(proto::ChangeResponse::from(&change_response)),
        ),
        Err(ServerError::StaleParent(reason)) => {
            fast_forward_required_response(request_id, &reason)
        }
        Err(e) => error_response(request_id, &e.to_string()),
    }
}

async fn handle_fast_forward(
    request_id: &str,
    req: proto::FastForwardRequest,
    app_cfg: &AppConfig,
    auth_context: &AuthContext,
) -> DbResponse {
    let from_change_id = req.from_change_id;
    let expected_change_ids = req.expected_change_ids;

    match get_or_create_space(auth_context.space_id, Some(app_cfg))
        .await
        .lock()
        .await
        .handle_fast_forward(from_change_id, &expected_change_ids, auth_context)
    {
        Ok(ff_data) => ok_response(
            request_id,
            db_response::Result::FastForward(proto::FastForwardResponse::from(&ff_data)),
        ),
        Err(e) => error_response(request_id, &e.to_string()),
    }
}

async fn handle_add_member_request(
    request_id: &str,
    req: proto::AddMemberRequest,
    app_cfg: &AppConfig,
    auth_context: &AuthContext,
) -> DbResponse {
    // Deserialize the InviteRequest from JSON bytes
    let user_add_request: InviteRequest = match serde_json::from_slice(&req.payload) {
        Ok(r) => r,
        Err(e) => return error_response(request_id, &format!("invalid add_member payload: {e}")),
    };

    // Unpack the insert ChangeRequest
    let insert_change_req = match req.insert {
        Some(cr) => cr,
        None => return error_response(request_id, "missing insert change_request"),
    };
    let insert_entry: ChangelogEntry = match insert_change_req.change {
        Some(ce) => ce.into(),
        None => return error_response(request_id, "missing changelog_entry in insert"),
    };
    let insert_change = Change {
        entry: insert_entry,
        hashed_values: proto::values_sidecar_from_proto(insert_change_req.values_sidecar),
    };

    match get_or_create_space(auth_context.space_id, Some(app_cfg))
        .await
        .lock()
        .await
        .handle_add_member(
            &user_add_request,
            &insert_change,
            auth_context,
            &req.retention_proofs,
        )
        .await
    {
        Ok(change_response) => ok_response(
            request_id,
            db_response::Result::AddMember(proto::AddMemberResponse {
                change: Some(proto::ChangeResponse::from(&change_response)),
            }),
        ),
        Err(e) => error_response(request_id, &e.to_string()),
    }
}

async fn handle_remove_member_request(
    request_id: &str,
    req: proto::RemoveMemberRequest,
    app_cfg: &AppConfig,
    auth_context: &AuthContext,
) -> DbResponse {
    // Deserialize the RekeyRequest from JSON bytes
    let user_delete_request: RekeyRequest = match serde_json::from_slice(&req.payload) {
        Ok(r) => r,
        Err(e) => {
            return error_response(request_id, &format!("invalid remove_member payload: {e}"))
        }
    };

    // Unpack the delete ChangeRequest
    let delete_change_req = match req.delete {
        Some(cr) => cr,
        None => return error_response(request_id, "missing delete change_request"),
    };
    let delete_entry: ChangelogEntry = match delete_change_req.change {
        Some(ce) => ce.into(),
        None => return error_response(request_id, "missing changelog_entry in delete"),
    };
    let delete_change = Change {
        entry: delete_entry,
        hashed_values: proto::values_sidecar_from_proto(delete_change_req.values_sidecar),
    };

    match get_or_create_space(auth_context.space_id, Some(app_cfg))
        .await
        .lock()
        .await
        .handle_remove_member(
            &user_delete_request,
            &req.remaining_uids,
            &delete_change,
            auth_context,
            &req.retention_proofs,
        )
        .await
    {
        Ok(change_response) => ok_response(
            request_id,
            db_response::Result::RemoveMember(proto::RemoveMemberResponse {
                change: Some(proto::ChangeResponse::from(&change_response)),
            }),
        ),
        Err(e) => error_response(request_id, &e.to_string()),
    }
}

async fn handle_retention_request(
    request_id: &str,
    req: proto::RetentionRequest,
    app_cfg: &AppConfig,
    auth_context: &AuthContext,
) -> DbResponse {
    // Deserialize the optional RekeyRequest
    let rekey_request: Option<RekeyRequest> = match &req.rekey_payload {
        Some(payload) => match serde_json::from_slice(payload) {
            Ok(r) => Some(r),
            Err(e) => {
                return error_response(
                    request_id,
                    &format!("invalid rekey_payload in retention request: {e}"),
                )
            }
        },
        None => None,
    };

    // Unpack the ChangeRequest
    let change_req = match req.change {
        Some(cr) => cr,
        None => return error_response(request_id, "missing change_request in retention request"),
    };
    let entry: ChangelogEntry = match change_req.change {
        Some(ce) => ce.into(),
        None => return error_response(request_id, "missing changelog_entry in retention request"),
    };
    let change = Change {
        entry,
        hashed_values: proto::values_sidecar_from_proto(change_req.values_sidecar),
    };

    match get_or_create_space(auth_context.space_id, Some(app_cfg))
        .await
        .lock()
        .await
        .handle_retention(
            &change,
            auth_context,
            req.retention_proofs,
            rekey_request.as_ref(),
        )
        .await
    {
        Ok(change_response) => ok_response(
            request_id,
            db_response::Result::Retention(proto::RetentionResponse {
                change: Some(proto::ChangeResponse::from(&change_response)),
            }),
        ),
        Err(e) => error_response(request_id, &e.to_string()),
    }
}

pub(crate) fn ok_response(request_id: &str, result: db_response::Result) -> DbResponse {
    DbResponse {
        request_id: request_id.to_string(),
        status: "ok".to_string(),
        error: String::new(),
        result: Some(result),
    }
}

pub(crate) fn error_response(request_id: &str, error: &str) -> DbResponse {
    log::error!("response:error request_id={request_id} error={error}");
    DbResponse {
        request_id: request_id.to_string(),
        status: "error".to_string(),
        error: error.to_string(),
        result: None,
    }
}

fn fast_forward_required_response(request_id: &str, reason: &str) -> DbResponse {
    log::warn!("response:fast_forward_required request_id={request_id} reason={reason}");
    DbResponse {
        request_id: request_id.to_string(),
        status: "fast_forward_required".to_string(),
        error: reason.to_string(),
        result: None,
    }
}

fn value_to_insert_query(table_name: &str, row: Value) -> Result<Query, ServerError> {
    let serde_json::Value::Object(map) = row else {
        return Err(ServerError::Generic(format!(
            "Row for table '{table_name}' must be a JSON object"
        )));
    };

    let mut fields = Vec::with_capacity(map.len());
    for (key, value) in map {
        fields.push((key, value.into()));
    }

    Ok(Query::new(
        table_name.to_string(),
        QueryOperation::Insert(fields),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::merk_storage::{column_key, column_key_placeholder};
    use encrypted_spaces_backend::schema::ColumnDefinition;
    use encrypted_spaces_changelog_core::changelog::ROOT_TREE_PATH;
    use encrypted_spaces_crypto::signature::{Ed25519Signature, SignatureKeyPair};
    use encrypted_spaces_key_manager::{CollectingOperationBuilder, SimpleKeyId};
    use encrypted_spaces_retention::simple_line2::StarkProver;

    // --- Async state tests ---
    // Use unique byte patterns per test to avoid SPACES map collisions when tests run in parallel.

    // --- Issue #212: expected-change-id bounding (fast-forward DoS guard) ---

    #[test]
    fn bounded_expected_change_ids_filters_out_of_range() {
        // 0 is invalid (change_ids are 1-based); ids > proven_up_to are in the
        // ragged tail and discharge without a server proof.
        let got = bounded_expected_change_ids(&[0, 1, 2, 3, 4, 5], 3);
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn bounded_expected_change_ids_dedups() {
        let got = bounded_expected_change_ids(&[2, 2, 1, 1, 3, 2], 5);
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn bounded_expected_change_ids_caps_examined_inputs() {
        // A client asking for every change_id in a large proven range must not
        // force more than MAX_FF_EXPECTED_INCLUSION_PROOFS proofs: we examine
        // only the first cap entries of the request.
        let proven_up_to = 100_000usize;
        let request: Vec<u32> = (1..=proven_up_to as u32).collect();
        let got = bounded_expected_change_ids(&request, proven_up_to);
        assert_eq!(got.len(), MAX_FF_EXPECTED_INCLUSION_PROOFS);
        // Ascending request => the lowest (oldest, most-likely-in-range) ids win.
        assert_eq!(got.first(), Some(&1));
        assert_eq!(got.last(), Some(&(MAX_FF_EXPECTED_INCLUSION_PROOFS as u32)));
    }

    #[test]
    fn bounded_expected_change_ids_empty_request_is_empty() {
        assert!(bounded_expected_change_ids(&[], 10).is_empty());
        // Nothing proven yet => nothing to prove, even with requests.
        assert!(bounded_expected_change_ids(&[1, 2, 3], 0).is_empty());
    }

    async fn insert_retention_writes(state: &SpaceState, writes: &[(String, Vec<u8>)]) {
        let auth = AuthContext::new(None, state.space_id);
        for (key, value) in writes {
            state
                .db
                .insert(
                    Query::new(
                        RETENTION_TABLE_NAME.to_string(),
                        QueryOperation::Insert(vec![
                            ("key".to_string(), QueryParam::Text(key.clone())),
                            ("value".to_string(), QueryParam::Blob(value.clone())),
                        ]),
                    ),
                    &auth,
                )
                .await
                .unwrap();
        }
    }

    fn noop_collecting_builder() -> CollectingOperationBuilder {
        CollectingOperationBuilder::with_writes(Box::new(|_| Box::pin(async { Ok(None) })), vec![])
    }

    fn collecting_builder_with_writes(
        writes: Vec<(String, Vec<u8>)>,
    ) -> CollectingOperationBuilder {
        CollectingOperationBuilder::with_writes(Box::new(|_| Box::pin(async { Ok(None) })), writes)
    }

    /// Build a synthetic `RemoveUser` `Change` carrying just the supplied
    /// retention writes, encoded the same way the SDK builder does
    /// (postcard-encoded JSON String of key + base64 of value).
    fn change_from_retention_writes(op_type: OpType, writes: &[(String, Vec<u8>)]) -> Change {
        use base64::Engine as _;
        use encrypted_spaces_backend::merk_storage::column_key_placeholder;

        let mut keys: Vec<Vec<u8>> = Vec::new();
        let mut values: Vec<Vec<u8>> = Vec::new();
        for (k, v) in writes {
            let key_bytes = stored_value::value_to_bytes(&Value::String(k.clone())).unwrap();
            let b64 = base64::engine::general_purpose::STANDARD.encode(v);
            let value_bytes = stored_value::value_to_bytes(&Value::String(b64)).unwrap();
            keys.push(column_key_placeholder(RETENTION_TABLE_NAME, "key"));
            values.push(key_bytes);
            keys.push(column_key_placeholder(RETENTION_TABLE_NAME, "value"));
            values.push(value_bytes);
        }
        let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        let value_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();

        Change::new(
            op_type,
            1,
            ROOT_TREE_PATH,
            &key_refs,
            &value_refs,
            0,
            0,
            [0u8; 32],
        )
        .unwrap()
    }

    fn encode_auth_key(key_pair: &SignatureKeyPair<Ed25519Signature>) -> String {
        let json_bytes = serde_json::to_vec(key_pair.verification_key()).unwrap();
        base64::engine::general_purpose::STANDARD.encode(json_bytes)
    }

    #[tokio::test]
    async fn verify_change_signature_uses_auth_key_from_create_space_query_when_change_value_is_hashed(
    ) {
        let state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        let key_pair = SignatureKeyPair::<Ed25519Signature>::new();
        let encoded_auth_key = encode_auth_key(&key_pair);
        let auth_key_value =
            stored_value::value_to_bytes(&serde_json::Value::String(encoded_auth_key)).unwrap();
        let auth_key = column_key_placeholder(USERS_TABLE_NAME, "auth_key");
        let mut change = Change::new(
            OpType::CreateSpace,
            7,
            ROOT_TREE_PATH,
            &[auth_key.as_slice()],
            &[auth_key_value.as_slice()],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();
        change.entry.signature = key_pair.sign(&change.entry.as_bytes()).as_ref().to_vec();

        state
            .verify_change_signature(&change, &HashedValues::new())
            .unwrap();
    }

    #[tokio::test]
    async fn verify_change_signature_uses_auth_key_from_users_table_for_non_create_space() {
        let state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        let key_pair = SignatureKeyPair::<Ed25519Signature>::new();
        let encoded_auth_key = encode_auth_key(&key_pair);
        let auth = AuthContext::new(None, state.space_id);
        let uid = state
            .db
            .insert(
                Query::new(
                    USERS_TABLE_NAME.to_string(),
                    QueryOperation::Insert(vec![
                        ("update_key".to_string(), QueryParam::Text(String::new())),
                        ("auth_key".to_string(), QueryParam::Text(encoded_auth_key)),
                        ("status".to_string(), QueryParam::Integer(1)),
                    ]),
                ),
                &auth,
            )
            .await
            .unwrap();
        let uid = u32::try_from(uid).expect("test uid fits in u32");

        let label_key = column_key_placeholder("seed_rows", "label");
        let label_value =
            serde_json::to_vec(&serde_json::Value::String("seed".to_string())).unwrap();
        let mut change = Change::new(
            OpType::Insert,
            uid,
            ROOT_TREE_PATH,
            &[label_key.as_slice()],
            &[label_value.as_slice()],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();
        change.entry.signature = key_pair.sign(&change.entry.as_bytes()).as_ref().to_vec();

        state
            .verify_change_signature(&change, &HashedValues::new())
            .unwrap();
    }

    #[tokio::test]
    async fn verify_retention_proofs_from_change_accepts_remove_user_after_reduce() {
        let state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        let mut pre_builder = noop_collecting_builder();
        let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut pre_builder)
            .await
            .unwrap();
        sk.extend(&mut pre_builder).await.unwrap();
        sk.reduce(&SimpleKeyId(1), &mut pre_builder).await.unwrap();
        let pre_output = pre_builder.finalize();
        insert_retention_writes(&state, &pre_output.writes).await;

        // Reuse the same space key across the pre/post builders: its HGK tracks
        // the current logical retention state, while the builders model the two
        // storage views needed for verification.
        let mut post_builder = collecting_builder_with_writes(pre_output.writes.clone());
        let (commitment, new_hgk) = sk.generate_group_key(&mut post_builder).await.unwrap();
        sk.apply_new_group_key(new_hgk, commitment, &post_builder)
            .await
            .unwrap();
        let post_output = post_builder.finalize();

        let pending_retention_writes = post_output.writes[pre_output.writes.len()..].to_vec();
        let retention_proofs = post_output.proofs;
        assert_eq!(retention_proofs.len(), 1, "expected one rekey proof");

        let change = change_from_retention_writes(OpType::RemoveUser, &pending_retention_writes);

        state
            .verify_retention_proofs_from_change(OpType::RemoveUser, &retention_proofs, &change)
            .await
            .expect("server-side verification should accept remove_user after reduce");
    }

    #[tokio::test]
    async fn verify_retention_proofs_from_change_rejects_missing_remove_user_writes() {
        let state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        let mut pre_builder = noop_collecting_builder();
        let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut pre_builder)
            .await
            .unwrap();
        sk.extend(&mut pre_builder).await.unwrap();
        sk.reduce(&SimpleKeyId(1), &mut pre_builder).await.unwrap();
        let pre_output = pre_builder.finalize();
        insert_retention_writes(&state, &pre_output.writes).await;

        let mut post_builder = collecting_builder_with_writes(pre_output.writes.clone());
        let (commitment, new_hgk) = sk.generate_group_key(&mut post_builder).await.unwrap();
        sk.apply_new_group_key(new_hgk, commitment, &post_builder)
            .await
            .unwrap();
        let post_output = post_builder.finalize();

        let pending_retention_writes: Vec<(String, Vec<u8>)> = post_output.writes
            [pre_output.writes.len()..]
            .iter()
            .filter(|(key, _)| !key.starts_with("sl2/gbct/row/"))
            .cloned()
            .collect();
        assert!(
            pending_retention_writes.len() < post_output.writes[pre_output.writes.len()..].len(),
            "expected to drop at least one required GBCT row from the request payload"
        );

        let retention_proofs = post_output.proofs;
        assert_eq!(retention_proofs.len(), 1, "expected one rekey proof");

        let change = change_from_retention_writes(OpType::RemoveUser, &pending_retention_writes);

        let result = state
            .verify_retention_proofs_from_change(OpType::RemoveUser, &retention_proofs, &change)
            .await;
        assert!(
            result.is_err(),
            "server-side verification must reject RemoveUser with missing retention rows"
        );
    }

    #[tokio::test]
    async fn same_space_id_returns_same_arc() {
        let space_id = SpaceId::from([0xA1; 16]);
        let arc1 = get_or_create_space(space_id, None).await;
        let arc2 = get_or_create_space(space_id, None).await;
        assert!(Arc::ptr_eq(&arc1, &arc2));
    }

    #[tokio::test]
    async fn different_space_ids_return_different_arcs() {
        let id1 = SpaceId::from([0xA2; 16]);
        let id2 = SpaceId::from([0xA3; 16]);
        let arc1 = get_or_create_space(id1, None).await;
        let arc2 = get_or_create_space(id2, None).await;
        assert!(!Arc::ptr_eq(&arc1, &arc2));
    }

    #[tokio::test]
    async fn spaces_start_with_same_empty_root() {
        let id1 = SpaceId::from([0xA4; 16]);
        let id2 = SpaceId::from([0xA5; 16]);
        let arc1 = get_or_create_space(id1, None).await;
        let arc2 = get_or_create_space(id2, None).await;
        let root1 = arc1.lock().await.get_root_hash().await;
        let root2 = arc2.lock().await.get_root_hash().await;
        assert_eq!(root1, root2);
    }

    #[tokio::test]
    async fn concurrent_init_disk_backed_returns_same_arc() {
        let space_id = SpaceId::random();
        let dir = std::env::temp_dir().join(format!("space_{}", space_id));

        let app_cfg = AppConfig {
            space_root: Some(dir.to_str().unwrap().to_string()),
            verbose_logfile: None,
            bootstrap_data: BootstrapDataSource::None,
        };

        // Run two concurrent first-connections to the same disk-backed space.
        // Initialization must happen once, under the per-space lock.
        let (a, b) = tokio::join!(
            get_or_create_space(space_id, Some(&app_cfg)),
            get_or_create_space(space_id, Some(&app_cfg)),
        );

        assert!(
            Arc::ptr_eq(&a, &b),
            "concurrent inits must return the same Arc"
        );
    }

    #[tokio::test]
    async fn get_delivery_slot_reads_and_reflects_updates() {
        let mut state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        // Fresh state has no slot for anyone.
        assert!(state.get_delivery_slot(1).is_none());

        // Writing a slot is visible via the convenience accessor the fetch
        // handler reads through.
        state.key_delivery_slots.put(1, b"first".to_vec());
        assert_eq!(state.get_delivery_slot(1).as_deref(), Some(&b"first"[..]));

        // Overwrites land in place (matches accepted-rekey behavior).
        state.key_delivery_slots.put(1, b"second".to_vec());
        assert_eq!(state.get_delivery_slot(1).as_deref(), Some(&b"second"[..]));

        // Removal clears the slot (matches removed-user cleanup).
        state.key_delivery_slots.remove(1);
        assert!(state.get_delivery_slot(1).is_none());
    }

    #[tokio::test]
    async fn do_query_with_pruned_merkle_tree_rejects_reserved_table() {
        // Regular Insert/Update/Delete targeting an internal table must be
        // rejected pre-emptively, before any proof generation runs.
        let mut state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        let auth = AuthContext::new(Some(7), state.space_id);
        let col_key = column_key_placeholder(USERS_TABLE_NAME, "status");
        let value = serde_json::to_vec(&serde_json::Value::from(1)).unwrap();

        for op_type in [OpType::Insert, OpType::Update, OpType::Delete] {
            let change = Change::new(
                op_type,
                7,
                ROOT_TREE_PATH,
                &[col_key.as_slice()],
                &[value.as_slice()],
                0,
                0,
                [0u8; 32],
            )
            .unwrap();

            let err = state
                .do_query_with_pruned_merkle_tree(&change, &auth)
                .await
                .expect_err(&format!("{op_type:?} on _users should be rejected"));
            let msg = format!("{err}");
            assert!(
                msg.contains("reserved") && msg.contains(USERS_TABLE_NAME),
                "unexpected error for {op_type:?}: {msg}"
            );
        }
    }

    /// Regression for #30: `SpaceState` enforces sigref-chain continuity
    /// on every submission via the shared `check_sigref_continuity`
    /// helper, using its per-user `sigref_map`. Fresh state must require
    /// `sig_ref == 0`; once the map records `uid -> change_id`, the next
    /// submission for that uid must point at that exact change_id.
    #[tokio::test]
    async fn sigref_map_seeds_and_enforces_continuity() {
        let state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        // Fresh server has no per-user sigref history.
        assert!(state.sigref_map.is_empty());

        // A first-time signer with `sig_ref == 0` matches an empty map.
        let mut entry = ChangelogEntry {
            uid: 7,
            sig_ref: 0,
            ..Default::default()
        };
        let expected = state.sigref_map.get(&entry.uid).copied().unwrap_or(0);
        assert!(check_sigref_continuity(&entry, expected).is_ok());

        // A first-time signer with a nonzero `sig_ref` is rejected.
        entry.sig_ref = 5;
        let expected = state.sigref_map.get(&entry.uid).copied().unwrap_or(0);
        let err = check_sigref_continuity(&entry, expected).unwrap_err();
        assert!(
            err.to_string().contains("Sigref chain broken"),
            "got: {err}"
        );

        // Simulate `handle_change` advancing the chain after acceptance.
        let mut state = state;
        state.sigref_map.insert(7, 12);

        // The next change by uid 7 must point at 12.
        entry.sig_ref = 12;
        let expected = state.sigref_map.get(&entry.uid).copied().unwrap_or(0);
        assert!(check_sigref_continuity(&entry, expected).is_ok());

        // A stale sig_ref (e.g. replay of the first change) is rejected.
        entry.sig_ref = 0;
        let expected = state.sigref_map.get(&entry.uid).copied().unwrap_or(0);
        let err = check_sigref_continuity(&entry, expected).unwrap_err();
        assert!(
            err.to_string().contains("expected sig_ref=12"),
            "got: {err}"
        );

        // Interleaved users keep independent chains: uid 9 still starts at 0.
        let other = ChangelogEntry {
            uid: 9,
            sig_ref: 0,
            ..Default::default()
        };
        let expected = state.sigref_map.get(&other.uid).copied().unwrap_or(0);
        assert!(check_sigref_continuity(&other, expected).is_ok());
    }

    /// Regression for #99: `check_concurrent_conflict` must scan *every*
    /// change after the parent, including the first accepted change when
    /// `parent_change == 0`. A prior off-by-one sliced `changes[(parent_idx
    /// + 1)..]`, which skipped `changes[0]` and let an exact replay of the
    /// first change append a second conflicting write.
    #[tokio::test]
    async fn check_concurrent_conflict_detects_replay_of_first_change() {
        use encrypted_spaces_changelog_core::changelog::LogMessage;

        let mut state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        let make_entry = |key: &[u8], parent_change: u32| ChangelogEntry {
            uid: 7,
            parent_change,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: b"/".to_vec(),
                entries: vec![KvData {
                    key: key.to_vec(),
                    value: b"v".to_vec(),
                }],
            },
            ..Default::default()
        };

        // Seed the changelog with a single accepted change at index 0
        // (change_id 1) that writes `key_a`.
        state.changelog.changes.push(make_entry(b"key_a", 0));

        // Exact replay: parent_change == 0, same tree_path and key. With the
        // off-by-one this slipped through (the scan started at changes[1],
        // which is empty); it must now be rejected against changes[0].
        let replay = make_entry(b"key_a", 0);
        let err = state
            .check_concurrent_conflict(&replay)
            .expect_err("replay of the first change must be detected as a conflict");
        assert!(err.to_string().contains("Update conflict"), "got: {err}");

        // A write to a different key with parent_change == 0 is not a conflict.
        let unrelated = make_entry(b"key_b", 0);
        assert!(
            state.check_concurrent_conflict(&unrelated).is_ok(),
            "writes to distinct keys must not conflict"
        );

        // A change whose parent is change_id 1 must not flag the parent
        // itself (changes[0]) as a conflict — the scan starts strictly after
        // the parent.
        let after_parent = make_entry(b"key_a", 1);
        assert!(
            state.check_concurrent_conflict(&after_parent).is_ok(),
            "the parent change must not be treated as a conflicting successor"
        );
    }

    /// `reinitialize_changelog` drops the per-user sigref view alongside
    /// the changelog, so the next signer is treated as fresh.
    #[tokio::test]
    async fn reinitialize_changelog_clears_sigref_map() {
        let mut state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        state.sigref_map.insert(3, 4);
        state.sigref_map.insert(8, 11);
        state.reinitialize_changelog().await.unwrap();
        assert!(state.sigref_map.is_empty());
    }

    /// End-to-end regression for #30: `handle_change` rejects a signed
    /// change whose `sig_ref` is inconsistent with the server's per-user
    /// view, *before* mutating the tree or changelog. Pins the check's
    /// placement against future refactors of `handle_change` that might
    /// reorder validation.
    #[tokio::test]
    async fn handle_change_rejects_first_signer_with_nonzero_sig_ref() {
        let mut state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        // CreateSpace is self-signed via the auth_key embedded in the
        // entry, so it goes through `verify_change_signature` without
        // needing a prior `_users` row — exercising `handle_change`'s
        // ordering with minimal setup.
        let key_pair = SignatureKeyPair::<Ed25519Signature>::new();
        let encoded_auth_key = encode_auth_key(&key_pair);
        let auth_key_value =
            stored_value::value_to_bytes(&serde_json::Value::String(encoded_auth_key)).unwrap();
        let auth_key = column_key_placeholder(USERS_TABLE_NAME, "auth_key");

        // Fresh state has no prior change for uid 7, but we claim
        // `sig_ref = 5`. The sigref check must reject this before any
        // tree mutation or changelog append.
        let baseline_root = state.db.root_hash();
        let baseline_num_changes = state.changelog.num_changes();
        let mut change = Change::new(
            OpType::CreateSpace,
            7,
            ROOT_TREE_PATH,
            &[auth_key.as_slice()],
            &[auth_key_value.as_slice()],
            0,
            5, // <-- bogus sig_ref; fresh signer must use 0
            state.changelog.current_root(),
        )
        .unwrap();
        change.entry.signature = key_pair.sign(&change.entry.as_bytes()).as_ref().to_vec();

        let auth = AuthContext::new(Some(7), state.space_id);
        let err = state
            .handle_change(&change, &auth)
            .await
            .expect_err("first-time signer with sig_ref != 0 must be rejected");
        assert!(
            err.to_string().contains("Sigref chain broken"),
            "unexpected error: {err}"
        );

        // Rejection must not mutate any of: per-user sigref view, tree
        // root, or changelog length.
        assert!(
            state.sigref_map.is_empty(),
            "rejected change must not advance sigref_map"
        );
        assert_eq!(state.db.root_hash(), baseline_root);
        assert_eq!(state.changelog.num_changes(), baseline_num_changes);
    }

    #[tokio::test]
    async fn apply_schema_bundle_rejects_dev_underscore_table() {
        let state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        let schema = Schema {
            name: "_secret".to_string(),
            columns: vec![ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            }],
            auto_increment: true,
        };
        let tables = vec![SchemaTable {
            table: "_secret".to_string(),
            schema: Some(schema),
            rows: vec![],
        }];

        let auth_context = AuthContext::new(None, state.space_id);
        let err = state
            .apply_schema_bundle(tables, &auth_context)
            .await
            .expect_err("expected reserved-name error");
        let msg = match err {
            ServerError::Generic(m) => m,
            other => panic!("expected ServerError::Generic, got {other:?}"),
        };
        assert!(msg.contains("reserved"), "msg={msg}");
        assert!(msg.contains("_secret"), "msg={msg}");
    }

    #[tokio::test]
    async fn apply_schema_bundle_accepts_known_internal_tables() {
        // Internal tables may appear in authored schema bundles with
        // `schema: None`. The reserved-name guard must not reject them.
        let state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap();

        let tables = vec![SchemaTable {
            table: USERS_TABLE_NAME.to_string(),
            schema: None,
            rows: vec![],
        }];

        let auth_context = AuthContext::new(None, state.space_id);
        state
            .apply_schema_bundle(tables, &auth_context)
            .await
            .expect("known internal table must import cleanly");
    }

    /// Tauri demo config (app_schema.kdl). Run with:
    ///   cargo test -p encrypted-spaces-backend-server print_demo_commitment -- --nocapture
    #[ignore]
    #[tokio::test]
    async fn print_demo_commitment() {
        let schema_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../demos/tauri/app_schema.kdl"
        );
        let state = SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id: SpaceId::from([0u8; 16]),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::SchemaFile(schema_path.to_string()),
            }),
            None,
        )
        .await
        .unwrap();
        let root = state.get_root_hash().await;
        println!("DEMO_COMMITMENT={}", hex::encode(root));
    }

    async fn hash_store_test_state() -> SpaceState {
        use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType, Schema};

        let schema = Schema {
            name: "notes".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "content".to_string(),
                    column_type: ColumnType::Text,
                    plaintext: false,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "title".to_string(),
                    column_type: ColumnType::String,
                    plaintext: false,
                    indexed: false,
                },
            ],
            auto_increment: true,
        };

        SpaceState::init_server(
            Some(&vec![schema]),
            Some(SpaceInitConfig {
                space_id: SpaceId::random(),
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap()
    }

    /// Build a `HashedValues` sidecar from raw values, keyed by `hashstore_hash`
    /// exactly as the wire boundary does.
    fn hashed_values<I: IntoIterator<Item = Vec<u8>>>(values: I) -> HashedValues {
        values
            .into_iter()
            .map(|v| (hashstore_hash(&v), v))
            .collect()
    }

    #[tokio::test]
    async fn hash_store_validate_accepts_valid_material() {
        let state = hash_store_test_state().await;
        let hv = hashed_values([b"hello world".to_vec()]);
        assert!(state.validate_hashed_values(&hv).is_ok());
    }

    #[tokio::test]
    async fn hash_store_insert_is_idempotent() {
        let mut state = hash_store_test_state().await;
        let hv = hashed_values([b"data".to_vec()]);

        state.insert_hashed_values(&hv);
        assert_eq!(state.hash_store.len(), 1);

        state.validate_hashed_values(&hv).unwrap();
        state.insert_hashed_values(&hv);
        assert_eq!(state.hash_store.len(), 1);
        assert_eq!(state.hash_store[&hashstore_hash(b"data")], b"data");
    }

    #[tokio::test]
    async fn hash_store_rejects_conflicting_material() {
        let mut state = hash_store_test_state().await;
        let hv = hashed_values([b"original".to_vec()]);

        // Directly insert a different value under the same hash to simulate a conflict.
        state
            .hash_store
            .insert(hashstore_hash(b"original"), b"tampered".to_vec());

        let err = state.validate_hashed_values(&hv).unwrap_err();
        assert!(
            err.to_string().contains("conflict"),
            "expected conflict error, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_rejects_unreferenced_material() {
        let state = hash_store_test_state().await;
        let hv = hashed_values([b"unused".to_vec()]);
        let err = state
            .validate_hashed_values_references(&hv, &BTreeSet::new())
            .unwrap_err();
        assert!(
            err.to_string().contains("unreferenced hashed value"),
            "expected unreferenced material error, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_validate_rejects_too_many_material_entries() {
        let state = hash_store_test_state().await;
        let hv = hashed_values([b"one".to_vec(), b"two".to_vec()]);
        let limits = HashedValuesLimits {
            max_entries: 1,
            max_value_bytes: 1024,
            max_total_bytes: 2048,
        };

        let err = state
            .validate_hashed_values_with_limits(&hv, limits)
            .unwrap_err();
        assert!(
            err.to_string().contains("maximum"),
            "expected max entries error, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_validate_rejects_oversized_material_value() {
        let state = hash_store_test_state().await;
        let hv = hashed_values([b"abcd".to_vec()]);
        let limits = HashedValuesLimits {
            max_entries: 1,
            max_value_bytes: 3,
            max_total_bytes: 16,
        };

        let err = state
            .validate_hashed_values_with_limits(&hv, limits)
            .unwrap_err();
        assert!(
            err.to_string().contains("maximum"),
            "expected max value size error, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_validate_rejects_excess_total_material_bytes() {
        let state = hash_store_test_state().await;
        let hv = hashed_values([b"abcd".to_vec(), b"efgh".to_vec()]);
        let limits = HashedValuesLimits {
            max_entries: 2,
            max_value_bytes: 4,
            max_total_bytes: 6,
        };

        let err = state
            .validate_hashed_values_with_limits(&hv, limits)
            .unwrap_err();
        assert!(
            err.to_string().contains("total size"),
            "expected max total size error, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_require_rejects_missing_material() {
        let state = hash_store_test_state().await;
        let content_bytes = b"some content value";
        let content_hash = hashstore_hash(content_bytes);
        let content_key = column_key_placeholder("notes", "content");

        let change = Change::new(
            OpType::Insert,
            1,
            ROOT_TREE_PATH,
            &[content_key.as_slice()],
            &[&content_hash],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();

        let err = state.require_hashed_values_for_change(&change).unwrap_err();
        assert!(
            err.to_string().contains("missing hashed value"),
            "expected missing material error, got: {err}"
        );
    }

    /// A peer that ships tampered bytes on the wire cannot satisfy a committed
    /// hash: `values_sidecar_from_proto` re-hashes every value, so the tampered
    /// bytes land under `hashstore_hash(tampered)`, never under the hash the
    /// change references. The server then rejects it as missing material.
    #[tokio::test]
    async fn hash_store_rejects_tampered_wire_material() {
        let state = hash_store_test_state().await;
        let real_value = b"the real content value";
        let committed_hash = hashstore_hash(real_value);
        let content_key = column_key_placeholder("notes", "content");

        // The signed change commits to the hash of the real value.
        let mut change = Change::new(
            OpType::Insert,
            1,
            ROOT_TREE_PATH,
            &[content_key.as_slice()],
            &[&committed_hash],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();

        // The sidecar carries a *different* value, decoded through the real
        // wire path. It is keyed by its own hash, not the committed one.
        let mut tampered = real_value.to_vec();
        tampered.push(0xFF);
        change.hashed_values = proto::values_sidecar_from_proto(vec![tampered]);
        assert!(!change.hashed_values.contains_key(&committed_hash));

        let err = state.require_hashed_values_for_change(&change).unwrap_err();
        assert!(
            err.to_string().contains("missing hashed value"),
            "tampered wire material must not satisfy the committed hash, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_require_accepts_material_from_request() {
        let state = hash_store_test_state().await;
        let content_bytes = b"some content value";
        let hash = hashstore_hash(content_bytes);
        let content_key = column_key_placeholder("notes", "content");

        let mut change = Change::new(
            OpType::Insert,
            1,
            ROOT_TREE_PATH,
            &[content_key.as_slice()],
            &[&hash],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();
        change.hashed_values = hashed_values([content_bytes.to_vec()]);

        state.require_hashed_values_for_change(&change).unwrap();
    }

    #[tokio::test]
    async fn hash_store_require_accepts_material_from_existing_store() {
        let mut state = hash_store_test_state().await;
        let content_bytes = b"already stored";
        let hash = hashstore_hash(content_bytes);
        state.insert_hashed_values(&hashed_values([content_bytes.to_vec()]));

        let content_key = column_key_placeholder("notes", "content");
        let change = Change::new(
            OpType::Insert,
            1,
            ROOT_TREE_PATH,
            &[content_key.as_slice()],
            &[&hash],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();

        state.require_hashed_values_for_change(&change).unwrap();
    }

    #[tokio::test]
    async fn hash_store_inline_columns_skip_validation() {
        let state = hash_store_test_state().await;
        let title_key = column_key_placeholder("notes", "title");
        let title_value = b"any value here";

        let change = Change::new(
            OpType::Insert,
            1,
            ROOT_TREE_PATH,
            &[title_key.as_slice()],
            &[title_value.as_slice()],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();

        state.require_hashed_values_for_change(&change).unwrap();
    }

    #[tokio::test]
    async fn hash_store_collect_returns_stored_material() {
        let mut state = hash_store_test_state().await;
        let content_bytes = b"collected content";
        let hash = hashstore_hash(content_bytes);
        state.insert_hashed_values(&hashed_values([content_bytes.to_vec()]));

        let content_key = column_key_placeholder("notes", "content");
        let change = Change::new(
            OpType::Insert,
            1,
            ROOT_TREE_PATH,
            &[content_key.as_slice()],
            &[&hash],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();

        let collected = state.collect_hashed_values_for_change(&change);
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[&hash], content_bytes);
    }

    #[tokio::test]
    async fn hash_backed_select_response_includes_material_for_proven_rows() {
        let mut state = hash_store_test_state().await;
        let content_bytes =
            stored_value::value_to_bytes(&serde_json::json!("selected content")).unwrap();
        let hash = hashstore_hash(&content_bytes);
        state.insert_hashed_values(&hashed_values([content_bytes.clone()]));

        state
            .db
            .merk
            .apply_batch(&[(
                column_key("notes", 1, "content"),
                merk::Op::Put(hash.to_vec()),
            )])
            .unwrap();

        let root = state.get_root_hash().await;
        let query = Query::new("notes".to_string(), QueryOperation::Select(Vec::new()));
        let response = state.handle_select(&query, &root).await.unwrap();

        assert!(!response.proof.is_empty());
        assert_eq!(response.hashed_values.len(), 1);
        assert_eq!(response.hashed_values[&hash], content_bytes);
    }

    #[tokio::test]
    async fn hash_backed_select_response_rejects_missing_server_material() {
        let mut state = hash_store_test_state().await;
        let content_bytes =
            stored_value::value_to_bytes(&serde_json::json!("missing material")).unwrap();
        let hash = hashstore_hash(&content_bytes);
        state.insert_hashed_values(&hashed_values([content_bytes]));

        state
            .db
            .merk
            .apply_batch(&[(
                column_key("notes", 1, "content"),
                merk::Op::Put(hash.to_vec()),
            )])
            .unwrap();
        state.hash_store.remove(&hash);

        let root = state.get_root_hash().await;
        let query = Query::new("notes".to_string(), QueryOperation::Select(Vec::new()));
        let err = state.handle_select(&query, &root).await.unwrap_err();
        assert!(
            err.to_string().contains("missing hashed value"),
            "expected missing material error, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_delete_with_empty_values_skips_hash_check() {
        let state = hash_store_test_state().await;
        let content_key = column_key_placeholder("notes", "content");
        let title_key = column_key_placeholder("notes", "title");

        let change = Change::new(
            OpType::Delete,
            1,
            ROOT_TREE_PATH,
            &[content_key.as_slice(), title_key.as_slice()],
            &[&[], &[]],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();

        state.require_hashed_values_for_change(&change).expect(
            "delete with empty values on hash-backed columns must not require hashed values",
        );
    }

    #[tokio::test]
    async fn hash_store_insert_rejects_empty_hash_backed_value() {
        let state = hash_store_test_state().await;
        let content_key = column_key_placeholder("notes", "content");

        let mut change = Change::new(
            OpType::Insert,
            1,
            ROOT_TREE_PATH,
            &[content_key.as_slice()],
            &[b"placeholder"],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();
        change.entry.message.entries[0].value = vec![];

        let err = state.require_hashed_values_for_change(&change).unwrap_err();
        assert!(
            err.to_string().contains("empty value"),
            "expected empty-value rejection for Insert, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_update_rejects_empty_hash_backed_value() {
        let state = hash_store_test_state().await;
        let content_key = column_key_placeholder("notes", "content");

        let mut change = Change::new(
            OpType::Update,
            1,
            ROOT_TREE_PATH,
            &[content_key.as_slice()],
            &[b"placeholder"],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();
        change.entry.message.entries[0].value = vec![];

        let err = state.require_hashed_values_for_change(&change).unwrap_err();
        assert!(
            err.to_string().contains("empty value"),
            "expected empty-value rejection for Update, got: {err}"
        );
    }

    async fn hash_store_test_state_with_action(
        action_name: &str,
        legs: Vec<ActionLeg>,
    ) -> SpaceState {
        let state = hash_store_test_state().await;
        let action = Action {
            name: action_name.to_string(),
            asserts: vec![],
            legs,
        };
        state.db.import_actions(&[action]).await.unwrap();
        state
    }

    #[tokio::test]
    async fn hash_store_action_insert_leg_rejects_empty_hash_backed_value() {
        use encrypted_spaces_storage_encoding::keys::{action_marker_key, column_key};

        let state = hash_store_test_state_with_action(
            "add_note",
            vec![ActionLeg::Insert {
                table: "notes".to_string(),
            }],
        )
        .await;

        let marker_key = action_marker_key("notes");
        let content_key = column_key("notes", 1, "content");
        let title_key = column_key("notes", 1, "title");

        let mut change = Change::new(
            OpType::Action,
            1,
            ROOT_TREE_PATH,
            &[
                marker_key.as_slice(),
                content_key.as_slice(),
                title_key.as_slice(),
            ],
            &[b"add_note", b"placeholder", b"inline title"],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();
        change.entry.message.entries[1].value = vec![];

        let err = state.require_hashed_values_for_change(&change).unwrap_err();
        assert!(
            err.to_string().contains("empty value"),
            "expected empty-value rejection for Action insert leg, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_action_insert_leg_rejects_all_empty_hash_backed_values() {
        use encrypted_spaces_storage_encoding::keys::{action_marker_key, column_key};

        let state = hash_store_test_state_with_action(
            "add_note",
            vec![ActionLeg::Insert {
                table: "notes".to_string(),
            }],
        )
        .await;

        let marker_key = action_marker_key("notes");
        let content_key = column_key("notes", 1, "content");
        let title_key = column_key("notes", 1, "title");

        // All values empty on an Insert leg — must still be rejected.
        let mut change = Change::new(
            OpType::Action,
            1,
            ROOT_TREE_PATH,
            &[
                marker_key.as_slice(),
                content_key.as_slice(),
                title_key.as_slice(),
            ],
            &[b"add_note", b"placeholder", b"placeholder"],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();
        change.entry.message.entries[1].value = vec![];
        change.entry.message.entries[2].value = vec![];

        let err = state.require_hashed_values_for_change(&change).unwrap_err();
        assert!(
            err.to_string().contains("empty value"),
            "expected empty-value rejection for Action insert leg with all-empty values, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_store_action_delete_leg_accepts_empty_hash_backed_value() {
        use encrypted_spaces_storage_encoding::keys::{action_marker_key, column_key};

        let state = hash_store_test_state_with_action(
            "remove_note",
            vec![ActionLeg::Delete {
                table: "notes".to_string(),
            }],
        )
        .await;

        let marker_key = action_marker_key("notes");
        let content_key = column_key("notes", 1, "content");
        let title_key = column_key("notes", 1, "title");

        let change = Change::new(
            OpType::Action,
            1,
            ROOT_TREE_PATH,
            &[
                marker_key.as_slice(),
                content_key.as_slice(),
                title_key.as_slice(),
            ],
            &[b"remove_note", b"", b""],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();

        state
            .require_hashed_values_for_change(&change)
            .expect("action delete leg must accept empty hash-backed values");
    }

    #[tokio::test]
    async fn hash_store_action_insert_with_cascade_delete_rejects_empty_hash_backed_value() {
        use encrypted_spaces_storage_encoding::keys::{action_marker_key, column_key};

        // Primary insert on "notes" plus cascade-delete on the same table.
        // Signed kvs belong to the primary insert leg; cascade-delete
        // carries no signed kvs. Empty hash-backed values must be rejected
        // because the primary leg is Insert, not Delete.
        let state = hash_store_test_state_with_action(
            "insert_and_cascade",
            vec![
                ActionLeg::Insert {
                    table: "notes".to_string(),
                },
                ActionLeg::CascadeDelete {
                    table: "notes".to_string(),
                    where_column: "parent_id".to_string(),
                    where_self_column: "id".to_string(),
                },
            ],
        )
        .await;

        let marker_key = action_marker_key("notes");
        let content_key = column_key("notes", 1, "content");
        let title_key = column_key("notes", 1, "title");

        let mut change = Change::new(
            OpType::Action,
            1,
            ROOT_TREE_PATH,
            &[
                marker_key.as_slice(),
                content_key.as_slice(),
                title_key.as_slice(),
            ],
            &[b"insert_and_cascade", b"placeholder", b"placeholder"],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();
        change.entry.message.entries[1].value = vec![];

        let err = state.require_hashed_values_for_change(&change).unwrap_err();
        assert!(
            err.to_string().contains("empty value"),
            "expected empty-value rejection for insert leg with cascade-delete on same table, got: {err}"
        );
    }

    // -- Stage 5: internal hash key server tests --

    #[tokio::test]
    async fn internal_hash_key_rehydrate_populates_hash_store_for_bootstrapped_data() {
        use encrypted_spaces_storage_encoding::{hashstore_hash, HASH_LEN};

        let mut state = SpaceState::init_server(None, None, None).await.unwrap();
        let auth = AuthContext::new(None, state.space_id);

        let auth_key_b64 = base64::engine::general_purpose::STANDARD.encode([0xAA; 64]);
        let update_key_b64 = base64::engine::general_purpose::STANDARD.encode([0xBB; 64]);
        let row_id = state
            .db
            .insert(
                Query::new(
                    USERS_TABLE_NAME.to_string(),
                    QueryOperation::Insert(vec![
                        (
                            "auth_key".to_string(),
                            QueryParam::Text(auth_key_b64.clone()),
                        ),
                        (
                            "update_key".to_string(),
                            QueryParam::Text(update_key_b64.clone()),
                        ),
                        ("status".to_string(), QueryParam::Integer(1)),
                    ]),
                ),
                &auth,
            )
            .await
            .unwrap();

        let auth_key_stored =
            stored_value::value_to_bytes(&serde_json::json!(auth_key_b64)).unwrap();
        let update_key_stored =
            stored_value::value_to_bytes(&serde_json::json!(update_key_b64)).unwrap();

        assert!(
            auth_key_stored.len() > HASH_LEN,
            "full stored value should be longer than a hash"
        );

        state.rehydrate_hash_store_for_bootstrapped_rows().unwrap();

        let auth_hash = hashstore_hash(&auth_key_stored);
        let update_hash = hashstore_hash(&update_key_stored);

        assert_eq!(
            state.hash_store.get(&auth_hash).unwrap(),
            &auth_key_stored,
            "hash_store should contain auth_key full value"
        );
        assert_eq!(
            state.hash_store.get(&update_hash).unwrap(),
            &update_key_stored,
            "hash_store should contain update_key full value"
        );

        let col_key = column_key(USERS_TABLE_NAME, row_id, "auth_key");
        let stored = state.db.get_value(&col_key).unwrap().unwrap();
        assert_eq!(
            stored.len(),
            HASH_LEN,
            "Merk tree should now store the 32-byte hash, not the full value"
        );
        assert_eq!(
            stored.as_slice(),
            auth_hash.as_slice(),
            "Merk stored hash should match computed hash"
        );
    }

    #[tokio::test]
    async fn internal_hash_key_select_after_rehydrate_includes_material() {
        let mut state = SpaceState::init_server(None, None, None).await.unwrap();
        let auth = AuthContext::new(None, state.space_id);

        let auth_key_b64 = base64::engine::general_purpose::STANDARD.encode([0xCC; 64]);
        state
            .db
            .insert(
                Query::new(
                    USERS_TABLE_NAME.to_string(),
                    QueryOperation::Insert(vec![
                        (
                            "auth_key".to_string(),
                            QueryParam::Text(auth_key_b64.clone()),
                        ),
                        (
                            "update_key".to_string(),
                            QueryParam::Text("update-key".to_string()),
                        ),
                        ("status".to_string(), QueryParam::Integer(1)),
                    ]),
                ),
                &auth,
            )
            .await
            .unwrap();

        state.rehydrate_hash_store_for_bootstrapped_rows().unwrap();

        let root = state.db.root_hash();
        let query = Query::new(
            USERS_TABLE_NAME.to_string(),
            QueryOperation::Select(vec![
                "id".to_string(),
                "auth_key".to_string(),
                "status".to_string(),
            ]),
        );

        let response = state.handle_select(&query, &root).await.unwrap();

        assert!(
            !response.hashed_values.is_empty(),
            "select should include hashed values for hash-backed auth_key"
        );
        let auth_key_stored =
            stored_value::value_to_bytes(&serde_json::json!(auth_key_b64)).unwrap();
        let auth_hash = hashstore_hash(&auth_key_stored);
        assert_eq!(
            response.hashed_values.get(&auth_hash),
            Some(&auth_key_stored),
            "material should contain auth_key hash mapping"
        );
    }

    #[tokio::test]
    async fn internal_hash_key_missing_material_fails_closed() {
        let state = SpaceState::init_server(None, None, None).await.unwrap();
        let auth = AuthContext::new(None, state.space_id);

        let auth_key_b64 = base64::engine::general_purpose::STANDARD.encode([0xDD; 64]);
        state
            .db
            .insert(
                Query::new(
                    USERS_TABLE_NAME.to_string(),
                    QueryOperation::Insert(vec![
                        (
                            "auth_key".to_string(),
                            QueryParam::Text(auth_key_b64.clone()),
                        ),
                        ("update_key".to_string(), QueryParam::Text("uk".to_string())),
                        ("status".to_string(), QueryParam::Integer(1)),
                    ]),
                ),
                &auth,
            )
            .await
            .unwrap();

        // Do NOT call rehydrate — hash_store is empty but Merk has full
        // values. The select handler will fail because non-32-byte
        // values can't be resolved as hash references.
        let root = state.db.root_hash();
        let query = Query::new(
            USERS_TABLE_NAME.to_string(),
            QueryOperation::Select(vec![
                "id".to_string(),
                "auth_key".to_string(),
                "status".to_string(),
            ]),
        );

        let result = state.handle_select(&query, &root).await;
        assert!(
            result.is_err(),
            "select should fail when hash_store is missing material for hash-backed columns"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("missing hashed value") || err_msg.contains("expected 32"),
            "error should mention missing hashed value, got: {err_msg}"
        );
    }
}
