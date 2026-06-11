//! Test-only helpers, kept out of the production API surface.
//!
//! Everything in this module is gated on `cfg(feature = "testing")`
//! (the parent `pub mod testing;` declaration handles the gate, so
//! individual items don't repeat it).  Downstream crates opt in via
//! the SDK's `testing` Cargo feature, which also pulls in the
//! prover-side surface of `encrypted-spaces-ffproof` so receipts produced
//! by the in-tree guest verify against the constants baked in here.
//!
//! Keeping these helpers in their own module means a developer reading
//! `lib.rs` sees the production API — `Space::create`, `Space::join`,
//! etc. — without a forest of `#[cfg(...)]` attributes interleaved with
//! it.

#[cfg(not(target_arch = "wasm32"))]
use std::collections::{BTreeMap, HashMap};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Mutex};

#[cfg(not(target_arch = "wasm32"))]
use encrypted_spaces_backend::error::Result;
#[cfg(not(target_arch = "wasm32"))]
use encrypted_spaces_backend::internal_schemas::{
    key_history_schema, users_schema, KEY_HISTORY_TABLE_NAME,
};
#[cfg(not(target_arch = "wasm32"))]
use encrypted_spaces_ffproof::EXTEND_FF_ID;
#[cfg(not(target_arch = "wasm32"))]
use encrypted_spaces_key_manager::{CollectingOperationBuilder, KeyManager};
#[cfg(not(target_arch = "wasm32"))]
use encrypted_spaces_retention::simple_line2::SimpleLine2SpaceKey;

#[cfg(test)]
use crate::cache::Cache;
#[cfg(not(target_arch = "wasm32"))]
use crate::{state, AuthContext, Space, SpaceId, Transport, UserWithSecrets};
use crate::{ApplicationSchema, DataCommitment, Schema};

/// Hardcoded merk root of a freshly-initialised internal-schemas
/// backend.  Guards against silent drift: changes to the internal
/// schema bundle will fail `Space::new`'s sanity expectation and the
/// dedicated test in `lib.rs`, prompting an intentional update.
const INITIAL_INTERNAL_DATA_COMMITMENT_HEX: &str =
    "ee8d222228e87c4e768cca7f601b9f2f2af1ee4fa3594af0592d2b022d5aa103";

/// Decoded form of [`INITIAL_INTERNAL_DATA_COMMITMENT_HEX`], used as
/// the starting commitment for in-tree tests and the `Space::new`
/// convenience constructor.
pub fn initial_internal_data_commitment() -> DataCommitment {
    hex::decode(INITIAL_INTERNAL_DATA_COMMITMENT_HEX.trim())
        .expect("valid hex")
        .try_into()
        .expect("32 bytes")
}

/// KDL schema parser, re-exported here (rather than at the SDK crate
/// root) because it's only used by test harnesses and demo `#[cfg(test)]`
/// blocks that hand-roll a `LocalTransport` from the bundle's tables,
/// actions, and action-gating map.  Production callers use
/// [`ApplicationSchema::FromBytes`], which parses the KDL internally.
pub use encrypted_spaces_backend::schema_kdl::parse_schema_bundle;

impl ApplicationSchema {
    /// Testing helper: bake in the in-tree FF-proof guest image ID so
    /// receipts produced by this build verify against this schema
    /// without the caller having to thread `EXTEND_FF_ID` through.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn for_testing(schemas: Vec<Schema>, commitment: DataCommitment) -> Self {
        Self::WithDataCommitment(schemas, commitment, EXTEND_FF_ID)
    }

    /// Same as [`Self::for_testing`] but for the `FromBytes` variant.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn for_testing_from_bytes(bytes: &'static [u8], commitment: DataCommitment) -> Self {
        Self::FromBytes(bytes, commitment, EXTEND_FF_ID)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Space {
    /// Create a [`Space`] with a freshly generated random identity and
    /// [`SpaceId`].  Convenience shortcut around [`Space::create`] with
    /// an empty schema and the in-tree FF-proof guest image ID; prefer
    /// `Space::create` with an explicit schema for production.
    pub async fn new(transport: impl Transport) -> Result<Self> {
        let dc = initial_internal_data_commitment();
        Self::create(transport, ApplicationSchema::for_testing(vec![], dc)).await
    }

    /// Create a Space from a transport that already has schemas
    /// initialised.  Used by tests where the transport wraps a
    /// pre-existing `SpaceState`; the caller supplies the initial
    /// commitment directly and the FF-proof guest image ID is baked in
    /// from the in-tree build.
    pub async fn new_without_schema_init(
        transport: impl Transport,
        initial_dc: [u8; 32],
    ) -> Result<Self> {
        let user = UserWithSecrets::new();
        let mut stub_builder = CollectingOperationBuilder::noop();
        let key_manager = KeyManager::new(
            user.update_key_pair.clone(),
            user.auth_key_pair.clone(),
            SimpleLine2SpaceKey::new(&mut stub_builder)
                .await
                .expect("stub space key init"),
        );
        let sid = SpaceId::random();
        let space = Self {
            id: sid,
            transport: Arc::new(transport),
            state: Arc::new(Mutex::new(state::State {
                auth_context: AuthContext::anonymous(sid),
                current_data_commitment: initial_dc,
                initial_dc,
                current_change_id: 0,
                my_last_change_id: 0,
                sigref_map: BTreeMap::new(),
                timestamp_hwm: 0,
                key_valid_from_change_id: 0,
                table_schemas: HashMap::new(),
                actions: HashMap::new(),
                current_clc_state: state::initial_clc_state(&initial_dc),
                current_change_entry: None,
                ff_image_id: EXTEND_FF_ID,
                pending_local_changes: Default::default(),
                cache: Default::default(),
            })),
            key_manager: Arc::new(tokio::sync::Mutex::new(key_manager)),
            updates_tx: tokio::sync::broadcast::channel(64).0,
            serialize_mutations: Arc::new(tokio::sync::Mutex::new(())),
            ff_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        crate::broadcast::start_listener(&space);
        Ok(space)
    }
}

/// Cross-module test accessors on [`Cache`].
///
/// Sibling modules' `mod tests` blocks (e.g. `list`, `changelog`) need
/// to peek at the cache from outside `cache::tests`, and helpers
/// defined inside `cache::tests` aren't visible to them.  Keeping these
/// methods here — rather than on the production `impl Cache` under
/// `#[cfg(test)]` — concentrates all test-only surface in this module.
///
/// Each method is gated to match the union of its callers' cfgs (not
/// the looser module-level `cfg(feature = "testing")`), because
/// leaving them visible under bare `feature = "testing"` makes them
/// dead code (`Cache` is `pub(crate)`, so downstream
/// `feature = "testing"` consumers can't reach them).
#[cfg(test)]
impl Cache {
    /// Check if a single row exists in cache by id.
    ///
    /// Callers: `cache::tests` (`cfg(test)`),
    /// `list::tests` and `changelog::broadcast_cache_tests`
    /// (`cfg(all(test, feature = "local-transport"))`).
    pub fn get_row(&self, table: &str, id: i64) -> Option<&serde_json::Value> {
        self.tables.get(table)?.rows.get(&id)
    }
}

/// Return all cached row IDs for a table.
///
/// Only called from `list::tests` and
/// `changelog::broadcast_cache_tests`, both gated on
/// `cfg(all(test, feature = "local-transport"))`.
#[cfg(all(test, feature = "local-transport"))]
impl Cache {
    pub fn row_ids(&self, table: &str) -> std::collections::HashSet<i64> {
        self.tables
            .get(table)
            .map(|t| t.rows.keys().copied().collect())
            .unwrap_or_default()
    }
}

/// Test-only changelog/state accessors on [`Space`].
///
/// Used by the ffproof integration tests / benches and by in-crate
/// `mod tests` blocks (the SDK's self-dev-dep enables this feature for
/// `cargo test`).  Kept here rather than on the production `impl Space`
/// in [`crate::state`] so the default public surface doesn't expose
/// internal changelog bookkeeping.
#[cfg(not(target_arch = "wasm32"))]
impl Space {
    /// Get the current data commitment.
    pub fn current_data_commitment(&self) -> [u8; 32] {
        self.with_state(|state| state.current_data_commitment)
    }

    /// Get the current changelog commitment root.
    pub fn current_clc(&self) -> [u8; 32] {
        self.with_state(|state| state.current_clc_state.root.into())
    }

    /// Get the current change ID.
    pub fn current_change_id(&self) -> u32 {
        self.with_state(|state| state.current_change_id)
    }

    /// Get my last change ID (for constructing ChangelogEntry).
    pub fn my_last_change_id(&self) -> u32 {
        self.with_state(|state| state.my_last_change_id)
    }

    /// Seed the local `_users` cache with user IDs and their auth keys.
    ///
    /// Registers the internal `_users` schema, initializes `_key_history` as
    /// an empty complete table, and inserts a stub row for each
    /// `(uid, auth_key_b64)` pair so that `make_local_reader` and
    /// `resolve_signing_key_for_change` can resolve user-existence and
    /// signature-key reads.  The `auth_key_b64` must be the base64-encoded
    /// JSON representation of the user's Ed25519 verification key (the same
    /// format used in the server's `_users` table).
    ///
    /// Only needed when the `Space` was created via
    /// `new_without_schema_init` with a transport that doesn't share the
    /// real server state.
    pub fn seed_user_cache(&self, users: &[(i64, String)]) {
        self.register_table_schema(users_schema());
        self.register_table_schema(key_history_schema());
        self.with_state_mut(|state| {
            state.cache.init_table("_users", &["id".to_string()]);
            state
                .cache
                .populate_full(KEY_HISTORY_TABLE_NAME, vec![], &[]);
            for (uid, auth_key_b64) in users {
                let row = serde_json::json!({ "id": uid, "auth_key": auth_key_b64, "status": 1 });
                state.cache.insert_row("_users", row);
            }
        });
    }
}
