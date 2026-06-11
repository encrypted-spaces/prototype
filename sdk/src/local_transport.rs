use crate::transport::Transport;
use encrypted_spaces_acl_types::Action;
use encrypted_spaces_backend::{
    access_control::{AccessOperation, AccessRule, AuthContext},
    error::{Result, SdkError},
    internal_schemas::is_reserved_table_name,
    merk_storage::proofs::{verify_query_proof_with_hashed_values, VerifiedRows},
    query::Query,
    schema::Schema,
    storage::Storage as StorageTrait,
    SpaceId,
};
use encrypted_spaces_backend_server::app_config::{BootstrapDataSource, SpaceInitConfig};
use encrypted_spaces_backend_server::db::ServerError;
use encrypted_spaces_backend_server::SpaceState;
use encrypted_spaces_changelog_core::changelog::ChangeLog;
use encrypted_spaces_changelog_core::changelog::{Change, ChangeResponse, FastForwardData};
use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) async fn bootstrap_restore_state_if_local(
    transport: &dyn Transport,
    state: &mut crate::state::State,
) {
    if state.current_change_id != 0 {
        return;
    }

    if let Some(local) = transport.as_any().downcast_ref::<LocalTransport>() {
        // LocalTransport is special: client and server share the same process,
        // so tests can safely read the server's changelog starting link to
        // simulate the real-world assumption that both sides already share the
        // starting DC/CLC out of band. Do not generalize this to remote
        // transports, where asking the transport for a baseline root would
        // weaken the trust boundary.
        let root = local.changelog_start_root().await;
        state.current_data_commitment = root;
        state.initial_dc = root;
        state.current_clc_state = crate::state::initial_clc_state(&root);
    }
}

/// LocalTransport provides a direct, in-process connection to storage
/// for testing purposes. It bypasses the WebSocket/network layer and calls
/// SpaceState methods directly, supporting changelog and fast-forward operations.
///
/// The underlying [`SpaceState`] is reference-counted, so cloning a
/// `LocalTransport` produces a second handle to the **same** server — useful
/// for simulating multi-user invite flows in unit tests.
pub struct LocalTransport {
    state: Arc<Mutex<SpaceState>>,
    auth_context: Mutex<AuthContext>,
    /// In-memory file store for testing (shared across clones).
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Monotonically increasing count of `fetch_my_key_delivery` calls across
    /// all clones. Shared so tests can assert that a given SDK flow did or
    /// did not hit the delivery-slot fetch path.
    fetch_my_key_delivery_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl Clone for LocalTransport {
    /// Create a second transport connected to the same in-memory server with a
    /// fresh (unauthenticated) auth context.  Authenticate via [`Space::join`]
    /// before use.
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            auth_context: Mutex::new(AuthContext::new(None, SpaceId::from([0u8; 16]))),
            files: Arc::clone(&self.files),
            fetch_my_key_delivery_calls: Arc::clone(&self.fetch_my_key_delivery_calls),
        }
    }
}

impl LocalTransport {
    /// Read the shared `fetch_my_key_delivery` call counter.
    ///
    /// Used by tests that assert which SDK flows trigger a delivery-slot
    /// fetch (and which — e.g. extend-only, DGK-only — must not).
    pub fn fetch_my_key_delivery_calls(&self) -> usize {
        self.fetch_my_key_delivery_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl LocalTransport {
    /// Create a new LocalTransport with an in-memory server (for testing).
    /// Tables can be created dynamically via create_table().
    pub async fn in_memory() -> Result<Self> {
        Self::new(&[], None, Some(SpaceState::DEFAULT_FF_BATCH_SIZE)).await
    }

    /// Create a new LocalTransport with predefined schemas.
    pub async fn new(
        schemas: &[Schema],
        artifact_path: Option<String>,
        ff_batch_size: Option<usize>,
    ) -> Result<Self> {
        let init_cfg = SpaceInitConfig {
            space_id: SpaceId::random(),
            artifact_path,
            verbose_logfile: None,
            bootstrap_data: BootstrapDataSource::None,
        };
        let state = SpaceState::init_server(Some(&schemas.to_vec()), Some(init_cfg), ff_batch_size)
            .await
            .map_err(|e| SdkError::DatabaseError(format!("Failed to init server: {e}")))?;

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            auth_context: Mutex::new(AuthContext::new(None, SpaceId::from([0u8; 16]))),
            files: Arc::new(Mutex::new(HashMap::new())),
            fetch_my_key_delivery_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Create a `LocalTransport` whose initial state mirrors what a real
    /// backend server produces when started with `--schema <path>`.  This
    /// imports pre-populated rows (e.g. ACL rules) so the resulting Merk
    /// root matches the server exactly.
    pub async fn from_schema_file(path: &str) -> Result<Self> {
        let init_cfg = SpaceInitConfig {
            space_id: SpaceId::random(),
            artifact_path: None,
            verbose_logfile: None,
            bootstrap_data: BootstrapDataSource::SchemaFile(path.to_string()),
        };
        let state = SpaceState::init_server(
            None,
            Some(init_cfg),
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await
        .map_err(|e| SdkError::DatabaseError(format!("Failed to init server: {e}")))?;

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            auth_context: Mutex::new(AuthContext::new(None, SpaceId::from([0u8; 16]))),
            files: Arc::new(Mutex::new(HashMap::new())),
            fetch_my_key_delivery_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Get the current root hash (data commitment)
    pub async fn get_root_hash(&self) -> Result<[u8; 32]> {
        let state = self.state.lock().await;
        Ok(state.db.root_hash())
    }

    /// Look up a value in the server's per-space HashStore by its SHA-256 digest.
    pub async fn hash_store_get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let state = self.state.lock().await;
        state.hash_store.get(hash).cloned()
    }

    /// Return the number of entries currently in the server's per-space
    /// HashStore. Test-only helper used to assert that hash-backed columns
    /// actually populate (or skip) the store.
    pub async fn hash_store_len(&self) -> usize {
        let state = self.state.lock().await;
        state.hash_store.len()
    }

    /// Write actions and action-gating constraints into the server's
    /// authenticated state.  Used by test setups that bootstrap via
    /// [`Self::new`] (which only initializes table schemas + ACL
    /// predicates); production code goes through
    /// [`Self::from_schema_file`] which imports everything alongside
    /// tables.
    ///
    /// Reinitializes the changelog anchor to the new merk root so the
    /// initial CLC the SDK derives from the captured commitment
    /// matches what the server uses.
    pub async fn import_actions(
        &self,
        actions: &[Action],
        acl_only_via_actions: &std::collections::BTreeMap<(String, String), Vec<String>>,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        state
            .db
            .import_actions(actions)
            .await
            .map_err(|e| SdkError::DatabaseError(format!("import_actions failed: {e}")))?;
        state
            .db
            .import_acl_only_via_actions(acl_only_via_actions)
            .await
            .map_err(|e| {
                SdkError::DatabaseError(format!("import_acl_only_via_actions failed: {e}"))
            })?;
        state
            .reinitialize_changelog()
            .await
            .map_err(|e| SdkError::DatabaseError(format!("reinitialize_changelog failed: {e}")))
    }

    /// Generate the raw proof bytes for a SELECT query at the current root,
    /// without verifying. Test-only helper used by size benchmarks that
    /// need to measure `select` proof byte length without the verifier
    /// consuming and discarding them on the way back through `Transport`.
    ///
    /// Note: the signature intentionally differs from
    /// [`Transport::select`] (no client-supplied commitment, no
    /// verification) — this is a measurement helper, not a drop-in for
    /// the production select path.
    pub async fn select_proof_bytes(&self, query: &Query) -> Result<Vec<u8>> {
        let state = self.state.lock().await;
        let commitment = state.db.root_hash();
        Ok(state.handle_select(query, &commitment).await?.proof)
    }

    /// Return the locally trusted changelog starting root.
    ///
    /// This is only valid for `LocalTransport`, where the SDK client shares
    /// the same in-process server state. Tests use this to simulate the real
    /// deployment assumption that client and server already agree on the
    /// starting DC/CLC before any tracked changes are replayed.
    pub(crate) async fn changelog_start_root(&self) -> [u8; 32] {
        let state = self.state.lock().await;
        state.changelog.initial_dc
    }

    /// Create a table in the local backend storage.
    ///
    /// This is only available on `LocalTransport` (for testing).
    /// In production, tables are created on the backend via the application schema.
    pub async fn create_table(&self, schema: &Schema) -> Result<()> {
        if is_reserved_table_name(&schema.name) {
            return Err(SdkError::ValidationError(format!(
                "table '{}' is reserved: names starting with '_' are reserved for \
                 internal tables and cannot be defined by application schemas",
                schema.name
            )));
        }
        let mut state = self.state.lock().await;
        state.db.create_table(schema).await?;

        // Creating a table mutates storage outside the tracked changelog flow.
        // Reset the in-process server changelog baseline and tree snapshot so
        // future FF proofs start from the post-schema tree state. This keeps
        // LocalTransport aligned with the test-only dynamic-schema model: once
        // create_table() has mutated storage, subsequent tracked changes should
        // replay from this new baseline rather than from the original empty
        // internal-schema root.
        let current_root = state.get_root_hash().await;
        state.changelog = ChangeLog::new(&current_root);
        state.change_responses.clear();
        state.ff_proof = None;
        state.tree_snapshot = state.db.snapshot();
        // Mirror `reinitialize_changelog`: the per-user sigref view is
        // changelog-scoped, so reset it whenever the in-process server
        // resets its changelog baseline. Without this, prior accepted
        // change_ids would persist past the reset and the next signed
        // change would fail `check_sigref_continuity` on the server.
        state.sigref_map.clear();
        Ok(())
    }

    /// Inject an access-control rule into the local backend storage and
    /// re-finalize the ACL blob.
    ///
    /// This is only available on `LocalTransport` (for testing). In
    /// production, ACL rules are populated server-side at space init from
    /// the schema bundle (see `SpaceState::bootstrap_from_schema_file`); the SDK has
    /// no client-facing write path to `_access_control`.
    ///
    /// Resets the changelog baseline like [`Self::create_table`] does, so
    /// subsequent tracked changes replay from the new post-rule tree.
    pub async fn add_access_rule(
        &self,
        resource_name: &str,
        operation: AccessOperation,
        rule: AccessRule,
    ) -> Result<()> {
        use encrypted_spaces_backend::access_control::ACCESS_CONTROL_TABLE_NAME;
        use encrypted_spaces_backend::query::{QueryOperation, QueryParam};

        let mut state = self.state.lock().await;
        let auth = AuthContext::new(None, state.space_id);

        let rule_json = serde_json::to_string(&rule)
            .map_err(|e| SdkError::SerializationError(e.to_string()))?;

        let insert = Query::new(
            ACCESS_CONTROL_TABLE_NAME.to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Null),
                (
                    "resource_name".to_string(),
                    QueryParam::Text(resource_name.to_string()),
                ),
                (
                    "operation".to_string(),
                    QueryParam::Text(operation.to_string()),
                ),
                ("rule_json".to_string(), QueryParam::Text(rule_json)),
            ]),
        );
        state.db.insert(insert, &auth).await?;
        state.db.finalize_acl_blob().await?;

        let current_root = state.get_root_hash().await;
        state.changelog = ChangeLog::new(&current_root);
        state.change_responses.clear();
        state.ff_proof = None;
        state.tree_snapshot = state.db.snapshot();
        // Mirror `reinitialize_changelog`: clear the per-user sigref
        // view alongside the changelog reset (see `create_table`).
        state.sigref_map.clear();
        Ok(())
    }
}

#[async_trait::async_trait]
impl Transport for LocalTransport {
    async fn submit_change(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse> {
        let auth_context = self.auth_context.lock().await;
        let mut state = self.state.lock().await;
        state
            .handle_change_with_proofs(change, &auth_context, retention_proofs)
            .await
            .map_err(|e| match e {
                ServerError::StaleParent(reason) => SdkError::FastForwardRequired { reason },
                other => SdkError::DatabaseError(format!("handle_change failed: {other}")),
            })
    }

    async fn fast_forward(&self, change_id: u32) -> Result<FastForwardData> {
        self.fast_forward_with_expected(change_id, &[]).await
    }

    async fn fast_forward_with_expected(
        &self,
        change_id: u32,
        expected_change_ids: &[u32],
    ) -> Result<FastForwardData> {
        let auth_context = self.auth_context.lock().await;
        let mut state = self.state.lock().await;
        state
            .handle_fast_forward(change_id, expected_change_ids, &auth_context)
            .map_err(|e| SdkError::DatabaseError(format!("fast_forward failed: {e}")))
    }

    async fn select(
        &self,
        query: Query,
        commitment: &[u8; 32],
        schemas: &HashMap<String, Schema>,
    ) -> Result<VerifiedRows> {
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

    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn fetch_my_key_delivery(&self) -> Result<Option<Vec<u8>>> {
        self.fetch_my_key_delivery_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    ) -> Result<ChangeResponse> {
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
    ) -> Result<ChangeResponse> {
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
    ) -> Result<ChangeResponse> {
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

    async fn authenticate(&self, auth_context: &AuthContext) -> Result<()> {
        *self.auth_context.lock().await = auth_context.clone();
        Ok(())
    }

    async fn file_upload(&self, hash: &str, data: Vec<u8>) -> Result<()> {
        let mut files = self.files.lock().await;
        files.insert(hash.to_string(), data);
        Ok(())
    }

    async fn file_download(&self, hash: &str) -> Result<Vec<u8>> {
        let files = self.files.lock().await;
        files
            .get(hash)
            .cloned()
            .ok_or_else(|| SdkError::DatabaseError(format!("file not found: {hash}")))
    }
}

impl crate::Space {
    /// Create a table in the local backend and register its schema.
    ///
    /// This is only available with `LocalTransport` (for testing).
    /// In production, tables are created on the backend via the application schema.
    ///
    /// # Panics
    ///
    /// Panics if this `Space` was not constructed with a `LocalTransport`. This
    /// is a programmer error: `create_table` is a test-only helper and should
    /// never be invoked on a `Space` backed by a remote transport.
    pub async fn create_table(&self, schema: &Schema) -> Result<()> {
        let local = self
            .transport
            .as_any()
            .downcast_ref::<LocalTransport>()
            .expect("Space::create_table requires a LocalTransport-backed Space");
        local.create_table(schema).await?;
        self.register_table_schema(schema.clone());

        // Local create_table mutates server state outside the tracked changelog
        // flow and resets the in-process server's changelog baseline. Mirror
        // that reset in the client state so subsequent local changes start from
        // the new root with parent_change=0.
        let new_root = local.get_root_hash().await?;
        self.with_state_mut(|state| {
            state.current_data_commitment = new_root;
            state.initial_dc = new_root;
            state.current_change_id = 0;
            state.my_last_change_id = 0;
            // Server changelog baseline was reset out-of-band; per-user
            // sigref chains must restart so the next tracked change
            // (sig_ref=0) is accepted by `check_sigref_continuity`.
            state.sigref_map.clear();
            state.current_clc_state = crate::state::initial_clc_state(&new_root);
        });
        Ok(())
    }

    /// Inject an access-control rule into the local backend. Test-only;
    /// requires a `LocalTransport`-backed `Space`. See
    /// [`LocalTransport::add_access_rule`] for the underlying behaviour.
    ///
    /// Resets the client state to match the new server root, just like
    /// [`Self::create_table`] does — both code paths reset the in-process
    /// server's changelog baseline outside the tracked changelog flow.
    ///
    /// # Panics
    ///
    /// Panics if this `Space` was not constructed with a `LocalTransport`.
    pub async fn add_access_rule(
        &self,
        resource_name: &str,
        operation: AccessOperation,
        rule: AccessRule,
    ) -> Result<()> {
        let local = self
            .transport
            .as_any()
            .downcast_ref::<LocalTransport>()
            .expect("Space::add_access_rule requires a LocalTransport-backed Space");
        local
            .add_access_rule(resource_name, operation, rule)
            .await?;

        let new_root = local.get_root_hash().await?;
        self.with_state_mut(|state| {
            state.current_data_commitment = new_root;
            state.initial_dc = new_root;
            state.current_change_id = 0;
            state.my_last_change_id = 0;
            // Server changelog baseline was reset out-of-band; per-user
            // sigref chains must restart so the next tracked change
            // (sig_ref=0) is accepted by `check_sigref_continuity`.
            state.sigref_map.clear();
            state.current_clc_state = crate::state::initial_clc_state(&new_root);
        });
        Ok(())
    }

    /// Install an action into the local backend's authenticated state
    /// and register it in the SDK's local cache.  Test-only; requires
    /// a `LocalTransport`-backed `Space`.  Mirrors the bootstrap path
    /// that production schemas use (`import_actions`), but on a single
    /// action so the fuzzer can add them incrementally during bootstrap.
    ///
    /// Optionally records an `only_via_actions` gating clause that
    /// restricts direct ops on `(table, op_str)` to the action names in
    /// `gating`.  Pass `None` to skip.  Action-gating is the only ACL-
    /// adjacent state we set here; per-row ACL predicates are installed
    /// separately via [`Self::add_access_rule`].
    ///
    /// Resets the client state to match the new server root, same as
    /// [`Self::create_table`] / [`Self::add_access_rule`].
    ///
    /// # Panics
    ///
    /// Panics if this `Space` was not constructed with a `LocalTransport`.
    pub async fn add_action(
        &self,
        action: Action,
        gating: Option<(String, String, Vec<String>)>,
    ) -> Result<()> {
        let local = self
            .transport
            .as_any()
            .downcast_ref::<LocalTransport>()
            .expect("Space::add_action requires a LocalTransport-backed Space");
        let mut only_via: std::collections::BTreeMap<(String, String), Vec<String>> =
            std::collections::BTreeMap::new();
        if let Some((table, op, names)) = gating {
            only_via.insert((table, op), names);
        }
        local
            .import_actions(std::slice::from_ref(&action), &only_via)
            .await?;
        self.register_action(action);

        let new_root = local.get_root_hash().await?;
        self.with_state_mut(|state| {
            state.current_data_commitment = new_root;
            state.initial_dc = new_root;
            state.current_change_id = 0;
            state.my_last_change_id = 0;
            // Server changelog baseline was reset out-of-band; per-user
            // sigref chains must restart so the next tracked change
            // (sig_ref=0) is accepted by `check_sigref_continuity`.
            state.sigref_map.clear();
            state.current_clc_state = crate::state::initial_clc_state(&new_root);
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType};

    #[tokio::test]
    async fn create_table_rejects_reserved_name() {
        let transport = LocalTransport::in_memory().await.unwrap();
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
        let err = transport
            .create_table(&schema)
            .await
            .expect_err("expected reserved-name error");
        match err {
            SdkError::ValidationError(msg) => assert!(msg.contains("reserved"), "msg={msg}"),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
