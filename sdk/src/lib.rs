pub mod action;
pub mod authentication;
mod broadcast;
pub(crate) mod cache;
pub(crate) mod changelog;
mod crypto;
pub mod file;
mod key_manager;
pub mod list;
#[cfg(feature = "local-transport")]
pub mod local_transport;
pub(crate) mod retention;
pub mod schema;
mod state;
pub mod table;
#[cfg(feature = "testing")]
pub mod testing;
pub mod textarea;
#[cfg(not(target_arch = "wasm32"))]
pub mod tls_trust;
pub mod transport;
pub mod users;
pub mod websocket_transport;

pub use crate::file::File;
pub(crate) use crate::key_manager::KeyManagerHandle;
pub use crate::list::{List, ListEntry};
#[cfg(feature = "local-transport")]
pub use crate::local_transport::LocalTransport;
pub use crate::schema::{ApplicationSchema, ColumnType, Schema, SchemaBuilder};
pub use crate::table::Table;
pub use crate::textarea::TextArea;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::tls_trust::load_trust_cert;
pub use crate::transport::EphemeralEvent;
use crate::transport::Transport;
pub(crate) use crate::users::UserWithSecrets;
pub use crate::users::{SpaceInvite, UserRecord, UserStatus};
pub use crate::websocket_transport::{BroadcastEvent, WebSocketTransport};
pub use encrypted_spaces_acl_types::{Action, ActionLeg, Assertion};
// `AccessOperation` and `AccessRule` appear in the public signatures of
// `LocalTransport::add_access_rule` and `Space::add_access_rule` (both
// gated to `feature = "local-transport"`). Re-export so callers don't
// need a direct `encrypted_spaces_backend` dependency.
#[cfg(any(test, feature = "testing"))]
pub use encrypted_spaces_backend::access_control::AuthContext;
#[cfg(feature = "local-transport")]
pub use encrypted_spaces_backend::access_control::{AccessOperation, AccessRule};
use encrypted_spaces_backend::error::Result;
use encrypted_spaces_backend::error::SdkError;
pub use encrypted_spaces_backend::error::{Result as SdkResult, SdkError as SdkErrorType};
use encrypted_spaces_backend::internal_schemas::access_control_schema;
pub use encrypted_spaces_backend::internal_schemas::USERS_TABLE_NAME;
pub use encrypted_spaces_backend::query::QueryParam;
// `Query` appears in `LocalTransport::select_proof_bytes(query: &Query)`.
#[cfg(feature = "local-transport")]
pub use encrypted_spaces_backend::query::Query;
// `SpaceId` appears in unconditional public signatures (`Space::id`,
// `SpaceInvite::space_id`). Re-export so callers don't need a direct
// `encrypted_spaces_backend` dependency.
pub use encrypted_spaces_backend::SpaceId;
pub use encrypted_spaces_changelog_core::changelog::OpType;
use encrypted_spaces_key_manager::{CollectingOperationBuilder, GkDeliveryEnvelope, KeyManager};
// `SimpleKeyId` appears in `Space::reduce(before: SimpleKeyId)` (an
// unconditional public retention API). Re-export so callers don't need a
// direct `encrypted_spaces_key_manager` dependency.
pub use encrypted_spaces_key_manager::SimpleKeyId;
use encrypted_spaces_retention::simple_line2::SimpleLine2SpaceKey;

/// Concrete KeyManager type used throughout the SDK.
pub(crate) type SpaceKeyManager = KeyManager<SimpleLine2SpaceKey>;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// The current data commitment (Merk root).
///
/// This commitment is used for read queries.
pub type DataCommitment = [u8; 32];

/// RISC0 image ID identifying the FF-proof guest binary the app trusts.
///
/// The verifier checks each FF-proof receipt against this value.  It must
/// be supplied by the app at `Space::create` / `Space::join` time (the
/// `sdk-codegen` build script emits it as `FF_GUEST_IMAGE_ID` so the
/// constant is anchored to the binary the app was built with, not to a
/// value the prover supplies in-band).
///
/// Open follow-up: rotating this constant when the guest binary changes
/// is a hard app-release event.  Old apps will reject proofs from a new
/// prover and vice versa.  A future iteration may want to accept a set
/// of trusted image IDs to allow rolling upgrades; the current API takes
/// a single value because that's the smallest correct surface for the
/// immediate security fix.
pub type FfImageId = [u32; 8];

/// Client interface to a specific Encrypted Space.
///
/// - [`Table<T>`] for relational tables
///
/// # Examples
///
/// ```ignore
/// use encrypted_spaces_sdk::{local_transport::LocalTransport, Space, Table};
///
/// // Create a Space backed by an in-process server.
/// let space = Space::new(LocalTransport::in_memory().await?).await?;
///
/// // Get a typed table handle
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct UserRow { id: Option<i64>, name: String }
/// let users: Table<UserRow> = space.table("users");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub struct Space {
    /// Unique identifier for this space.
    pub(crate) id: SpaceId,
    /// Shared reference to the transport layer (WebSocket, local, etc.).
    ///
    /// Type-erased so that `Space` and its handles don't need a transport
    /// type parameter. Wrapped in an `Arc` so that `Space` and `Table`
    /// clones remain inexpensive and can be used safely across threads.
    pub(crate) transport: Arc<dyn Transport>,

    pub(crate) state: Arc<Mutex<state::State>>,

    /// Key manager behind an async-aware lock, separate from state so that
    /// async SpaceKey methods can be awaited without blocking the sync state mutex.
    pub(crate) key_manager: Arc<tokio::sync::Mutex<SpaceKeyManager>>,

    /// Fan-out channel for broadcast events that the SDK has already applied.
    /// App consumers subscribe via [`Space::subscribe_updates`] to trigger UI
    /// refresh, logout, etc. The SDK-owned broadcast listener pushes here
    /// after each successful `handle_broadcast`.
    pub(crate) updates_tx: tokio::sync::broadcast::Sender<BroadcastEvent>,

    /// Serializes fast-forward application against change *signing* so a
    /// concurrent signer never captures provisional, not-yet-verified
    /// changelog-position state (`current_change_id` / `my_last_change_id` /
    /// `sigref_map` / `current_clc_state`) that a failed fast-forward would
    /// roll back. Held for the whole of `apply_fast_forward_from_anchor`
    /// (including deferred signature verification) and briefly while reading
    /// the signing anchor. Shared across all clones of a Space (including the
    /// broadcast listener's temporary Space). See issue #212, fix #4.
    pub(crate) serialize_mutations: Arc<tokio::sync::Mutex<()>>,

    /// True while an `apply_fast_forward_from_anchor` call is in flight on this
    /// Space. A deferred-verification table read can itself hit a stale select
    /// and try to auto-recover via fast-forward; because `serialize_mutations`
    /// is a non-reentrant async mutex held for the whole apply, that nested
    /// recovery would deadlock. This flag makes such re-entrant recovery
    /// fail fast (the outer apply then rolls back and the caller retries)
    /// instead of deadlocking. See issue #212, fix #4.
    pub(crate) ff_in_progress: Arc<std::sync::atomic::AtomicBool>,
}

impl Space {
    /// Send a generic ephemeral message to all peers in the space.
    ///
    /// The SDK automatically fills in the sender's UID from the auth context.
    /// `kind` discriminates the message type (e.g. "cursor"); `payload` is the
    /// application-defined body.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn send_ephemeral(&self, kind: &str, payload: &[u8]) -> Result<()> {
        let uid = self.with_state(|s| s.auth_context.uid.unwrap_or(0) as u32);
        self.transport.send_ephemeral(uid, kind, payload).await
    }

    /// Subscribe to ephemeral events from other users.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn subscribe_ephemeral(&self) -> Result<crate::transport::EphemeralReceiver> {
        self.transport.subscribe_ephemeral()
    }

    /// Subscribe to broadcast events that the SDK has already applied.
    ///
    /// Use this to drive UI refreshes, auto-logout on self-removal, or any
    /// other app-level reaction to remote changes. The SDK keeps its own
    /// transport-level subscription so the listener stays alive for the
    /// lifetime of the Space; this method just hands the caller another
    /// receiver on the same fan-out channel.
    pub fn subscribe_updates(&self) -> tokio::sync::broadcast::Receiver<BroadcastEvent> {
        self.updates_tx.subscribe()
    }

    /// Create a new space adhering to a schema specification as the initial user.
    ///
    /// Generates a random [`SpaceId`] and coordinated keypairs so the user's
    /// identity and group ratchet key are consistent (required for the invite flow).
    ///
    /// Returns the live [`Space`]
    pub async fn create(transport: impl Transport, schema: ApplicationSchema) -> Result<Self> {
        let transport: Arc<dyn Transport> = Arc::new(transport);
        let mut user = UserWithSecrets::new();
        user.id = Some(1);

        let mut create_builder = CollectingOperationBuilder::noop();
        let space_key = SimpleLine2SpaceKey::new(&mut create_builder)
            .await
            .map_err(|e| SdkError::ValidationError(format!("failed to init space key: {e:?}")))?;
        let create_output = create_builder.finalize();
        let create_writes = create_output.writes;
        let create_proofs = create_output.proofs;
        let key_manager = KeyManager::new(
            user.update_key_pair.clone(),
            user.auth_key_pair.clone(),
            space_key,
        );
        let (dc, table_schemas, actions, ff_image_id) = schema.into_parts().await?;

        let space_id = SpaceId::random();
        let auth_context = user.as_auth_context(space_id);
        transport.authenticate(&auth_context).await?;

        let space = Self {
            id: space_id,
            transport,
            state: Arc::new(Mutex::new(state::State {
                auth_context: auth_context.clone(),
                current_data_commitment: dc,
                initial_dc: dc,
                current_change_id: 0,
                my_last_change_id: 0,
                sigref_map: BTreeMap::new(),
                timestamp_hwm: 0,
                key_valid_from_change_id: 0,
                table_schemas,
                actions,
                current_clc_state: state::initial_clc_state(&dc),
                current_change_entry: None,
                ff_image_id,
                pending_local_changes: Default::default(),
                cache: Default::default(),
            })),
            key_manager: Arc::new(tokio::sync::Mutex::new(key_manager)),
            updates_tx: tokio::sync::broadcast::channel(64).0,
            serialize_mutations: Arc::new(tokio::sync::Mutex::new(())),
            ff_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        // Build the insert without an explicit id so `_users` (an auto-
        // increment table) assigns it.  Signing still uses `user.id = 1`
        // because the counter's first allocation is guaranteed to be 1.
        let mut user_record = user.as_record();
        user_record.id = None;
        let mut insert_builder = space.users().insert(&user_record);
        insert_builder.take_pending_error()?;

        // Register internal table schemas locally (tables are auto-created on the backend)
        space.register_table_schema(access_control_schema());
        space.initialize_key_history();
        space.initialize_lists();
        space.initialize_users().await?;
        space.initialize_retention().await?;

        crate::crypto::encrypt_query_fields(&mut insert_builder.query, &space).await?;
        let change = {
            use crate::changelog::ChangeBuilder;
            ChangeBuilder::new(&mut insert_builder.query, Arc::new(space.clone()))
                .build_create_space(&create_writes)
                .await?
        };

        let change_response = space
            .transport
            .submit_change(&change, create_proofs)
            .await?;

        let writes = space.validate_and_apply_change(&change.entry, &change_response)?;
        crate::cache::update_cache_from_proven_writes(&space, &change, &writes).await;
        let new_user_id =
            crate::cache::new_row_id_for_table(&space, &writes, users::USERS_TABLE_NAME)
                .ok_or_else(|| {
                    SdkError::InsertError("missing new user id in change response".to_string())
                })?;
        assert!(Some(new_user_id) == user.id);

        crate::broadcast::start_listener(&space);
        Ok(space)
    }

    /// Join an existing space as an invited member.
    ///
    /// The `invite` is the [`SpaceInvite`] returned by the inviter's
    /// [`Space::invite_user`] call. `join` authenticates, fetches the GK
    /// delivery slot deposited by the server, bootstraps the key chain,
    /// fast-forwards to the latest state, and rotates the provisional
    /// invite keypairs to fresh permanent ones.
    pub async fn join(
        transport: impl Transport,
        invite: SpaceInvite,
        schema: ApplicationSchema,
    ) -> Result<Self> {
        let transport: Arc<dyn Transport> = Arc::new(transport);
        let auth_context = invite.user.as_auth_context(invite.space_id);
        transport.authenticate(&auth_context).await?;

        // Fetch the bootstrap envelope from the GK delivery slot deposited
        // by the server when the invite was accepted.
        let envelope_bytes = transport.fetch_my_key_delivery().await?.ok_or_else(|| {
            SdkError::JoinError("no GK delivery slot found for invitee".to_string())
        })?;
        let envelope: GkDeliveryEnvelope = serde_json::from_slice(&envelope_bytes)
            .map_err(|e| SdkError::JoinError(format!("invalid delivery envelope: {e}")))?;

        // Bootstrap the key chain directly from the delivered envelope.
        // Canonical retention state is fetched from `_retention` during
        // `restore()` below; no retention rows are written locally here.
        let key_manager: SpaceKeyManager = KeyManager::from_delivery_envelope(
            invite.user.update_key_pair,
            invite.user.auth_key_pair,
            &envelope,
        )
        .map_err(|e| SdkError::JoinError(format!("failed to process invite: {e:?}")))?;

        let (dc, table_schemas, actions, ff_image_id) = schema.into_parts().await?;

        let space = Self::restore_internal(
            transport,
            invite.space_id,
            state::State {
                auth_context,
                current_data_commitment: dc,
                initial_dc: dc,
                current_change_id: 0,
                my_last_change_id: 0,
                sigref_map: BTreeMap::new(),
                timestamp_hwm: 0,
                key_valid_from_change_id: 0,
                table_schemas,
                actions,
                current_clc_state: state::initial_clc_state(&dc),
                current_change_entry: None,
                ff_image_id,
                pending_local_changes: Default::default(),
                cache: Default::default(),
            },
            key_manager,
        )
        .await?;

        // Rotate provisional invite keypairs → fresh permanent keypairs.
        space.rotate_user_keys().await?;

        Ok(space)
    }

    /// Internal helper used by [`Space::restore`] (snapshot-based restore)
    /// and [`Space::join`] to construct a `Space` from raw state and a
    /// pre-built key manager. This signature exposes crate-internal types
    /// (`state::State`, `SpaceKeyManager`) and is therefore not part of
    /// the public API.
    pub(crate) async fn restore_internal(
        transport: Arc<dyn Transport>,
        id: SpaceId,
        state: state::State,
        key_manager: SpaceKeyManager,
    ) -> Result<Self> {
        #[cfg(feature = "local-transport")]
        let state = {
            let mut state = state;
            crate::local_transport::bootstrap_restore_state_if_local(&*transport, &mut state).await;
            state
        };

        #[cfg(not(feature = "local-transport"))]
        let state = state;

        let needs_anchor_resync = state.needs_changelog_anchor_resync();

        transport.authenticate(&state.auth_context).await?;

        let space = Self {
            id,
            transport,
            state: Arc::new(Mutex::new(state)),
            key_manager: Arc::new(tokio::sync::Mutex::new(key_manager)),
            updates_tx: tokio::sync::broadcast::channel(64).0,
            serialize_mutations: Arc::new(tokio::sync::Mutex::new(())),
            ff_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        // Register internal table schemas locally (tables are auto-created on the backend)
        space.register_table_schema(access_control_schema());
        space.initialize_key_history();
        space.initialize_lists();
        space.initialize_users().await?;
        space.initialize_retention().await?;

        if needs_anchor_resync {
            log::warn!(
                "restored snapshot is missing current_change_entry for change_id > 0; resyncing changelog anchor from genesis"
            );
            space.with_state_mut(|state| {
                state.reset_changelog_anchor_to_genesis();
                state.cache.clear_all();
            });
        }

        // Fast-forward the public state. The FF path itself runs a single
        // data-driven delivery-slot recovery against the final retention
        // snapshot if the batch introduced a fresh FGK — no separate ad hoc
        // key-sync call here. Silently leaving a stale local HGK is exactly
        // the bug the delivery-slot model is meant to prevent, so we
        // propagate any FF or recovery failure out of `restore`.
        space.recover_via_fast_forward().await?;

        crate::broadcast::start_listener(&space);
        Ok(space)
    }

    /// Returns the [`SpaceId`] for this space.
    pub fn id(&self) -> SpaceId {
        self.id
    }

    /// Return a typed handle to a SQL table named `name`.
    ///
    /// This does **not** create the underlying table. You must initialize the table
    /// with a [`Schema`] before first use.
    ///
    /// The generic `T` is your row model for this table. It must be `Send + Sync`
    /// so that queries can be executed safely across threads.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// #[derive(serde::Serialize, serde::Deserialize)]
    /// struct Widget { id: Option<i64>, name: String }
    ///
    /// let widgets: Table<Widget, _> = space.table("widgets");
    /// let widget_id = widgets.insert(&Widget { id: None, name: "foo".into() }).execute();
    /// ```
    pub fn table<T>(&self, name: &str) -> Table<T>
    where
        T: Send + Sync,
    {
        Table::new(name.to_string(), Arc::new(self.clone()))
    }

    /// Return a hydrated `List<T>` for a list column on a table row.
    ///
    /// The returned list is ready for operations (get, append, etc.).
    pub fn list<T>(&self, table: &str, row_id: i64, column: &str) -> list::List<T>
    where
        T: Send + Sync,
    {
        let mut l = list::List::empty();
        l.hydrate(
            Arc::new(self.clone()),
            table.to_string(),
            row_id,
            column.to_string(),
        );
        l
    }

    /// Return a hydrated `TextArea` for a list column on a table row.
    pub fn textarea(&self, table: &str, row_id: i64, column: &str) -> textarea::TextArea {
        let mut ta = textarea::TextArea::empty();
        ta.hydrate(
            Arc::new(self.clone()),
            table.to_string(),
            row_id,
            column.to_string(),
        );
        ta
    }

    /// Return a handle for uploading and downloading encrypted files.
    pub fn file(&self) -> file::FileHandle {
        file::FileHandle {
            space: Arc::new(self.clone()),
        }
    }

    /// Returns a handle to the space's key manager.
    pub(crate) fn key_manager(&self) -> KeyManagerHandle {
        KeyManagerHandle::new(Arc::new(self.clone()))
    }

    /// Synchronize local state with the latest server state.
    ///
    /// Fast-forwards the changelog / `_retention` snapshot. If the batch
    /// introduces a fresh FGK row (i.e. a fresh-random HGK has been
    /// installed), the FF path runs a single delivery-slot-capable
    /// recovery against the final snapshot; otherwise there is no slot
    /// fetch.
    pub async fn sync(&self) -> Result<()> {
        self.recover_via_fast_forward().await
    }
}

impl Clone for Space {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            transport: Arc::clone(&self.transport),
            state: Arc::clone(&self.state),
            key_manager: Arc::clone(&self.key_manager),
            updates_tx: self.updates_tx.clone(),
            serialize_mutations: Arc::clone(&self.serialize_mutations),
            ff_in_progress: Arc::clone(&self.ff_in_progress),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "local-transport"))]
mod tests {
    use super::*;
    use crate::local_transport::LocalTransport;
    use crate::schema::Schema;
    use crate::users::UserStatus;
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend::schema_kdl::parse_schema_bundle;
    use encrypted_spaces_backend::sign_change::sign_change;
    use encrypted_spaces_changelog_core::changelog::{initial_clc_state, Change, FastForwardData};
    use encrypted_spaces_ffproof::EXTEND_FF_ID;
    use encrypted_spaces_key_manager::DefaultSignature;
    use expect_test::expect;
    use serde::{Deserialize, Serialize};
    use std::sync::Once;

    fn init_test_logging() {
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            let _ =
                env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                    .is_test(true)
                    .try_init();
        });
    }

    /// Build a schema using the transport's actual current root as the initial
    /// data commitment.  Must be called on a fresh (empty) transport.
    fn schema() -> ApplicationSchema {
        ApplicationSchema::for_testing(vec![], crate::testing::initial_internal_data_commitment())
    }

    /// Guards the hardcoded fresh-space root used by `Space::new()`.
    ///
    /// Changes to the internal schema can legitimately change that root.
    /// `expect!` makes those changes easy to spot because the failure shows the new hex value.
    /// If the change is intentional, run the test with `UPDATE_EXPECT=1` and then copy the same
    /// value into `INITIAL_INTERNAL_DATA_COMMITMENT_HEX` in `testing.rs`.
    #[tokio::test]
    async fn initial_internal_data_commitment_matches_fresh_transport_root() -> Result<()> {
        let transport = LocalTransport::in_memory().await?;
        let actual = transport.get_root_hash().await?;
        let actual_hex = hex::encode(actual);
        expect!["ee8d222228e87c4e768cca7f601b9f2f2af1ee4fa3594af0592d2b022d5aa103"]
            .assert_eq(&actual_hex);
        assert_eq!(crate::testing::initial_internal_data_commitment(), actual);
        Ok(())
    }

    /// Create an in-memory space.
    async fn create_space() -> Result<(LocalTransport, Space)> {
        let transport = LocalTransport::in_memory().await?;
        let space = Space::create(transport.clone(), schema()).await?;
        Ok((transport, space))
    }

    fn changelog_anchor_bytes(space: &Space) -> Option<Vec<u8>> {
        space.with_state(|state| {
            state
                .current_change_entry
                .as_ref()
                .map(|entry| entry.as_bytes())
        })
    }

    #[allow(clippy::type_complexity)]
    fn changelog_snapshot(
        space: &Space,
    ) -> (u32, [u8; 32], [u8; 32], Option<Vec<u8>>, BTreeMap<u32, u32>) {
        (
            space.current_change_id(),
            space.current_data_commitment(),
            space.current_clc(),
            changelog_anchor_bytes(space),
            space.with_state(|state| state.sigref_map.clone()),
        )
    }

    async fn nonzero_anchor_fast_forward() -> Result<(Space, FastForwardData, u32)> {
        let (transport, alice) = create_space().await?;
        let invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), invite, schema()).await?;

        let _charlie = bob.invite_user().await?;
        let _dana = bob.invite_user().await?;

        let from_change_id = alice.current_change_id();
        assert!(
            from_change_id > 0,
            "test setup must request FF from a real changelog anchor"
        );
        transport
            .authenticate(&AuthContext::new(
                Some(alice.uid().expect("alice uid") as i64),
                alice.id(),
            ))
            .await?;
        let ff_data = transport.fast_forward(from_change_id).await?;
        let proof = ff_data.proof.as_ref().expect("expected FF proof");
        assert_eq!(
            proof.end_change_id, 5,
            "test setup should prove through change 5"
        );

        Ok((alice, ff_data, from_change_id))
    }

    async fn ragged_fast_forward_from_nonzero_anchor() -> Result<(Space, FastForwardData)> {
        let (transport, alice) = create_space().await?;
        let invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), invite, schema()).await?;

        let _charlie = bob.invite_user().await?;
        let _dana = bob.invite_user().await?;
        let _erin = bob.invite_user().await?;

        transport
            .authenticate(&AuthContext::new(
                Some(alice.uid().expect("alice uid") as i64),
                alice.id(),
            ))
            .await?;
        let ff_data = transport.fast_forward(alice.current_change_id()).await?;
        let proof = ff_data.proof.as_ref().expect("expected FF proof");
        assert_eq!(
            proof.end_change_id, 5,
            "test setup should prove through change 5"
        );
        assert_eq!(
            ff_data.changes.len(),
            1,
            "test setup should leave one ragged change after the proof"
        );

        Ok((alice, ff_data))
    }

    async fn ragged_only_fast_forward_from_alice() -> Result<(Space, FastForwardData)> {
        use crate::changelog::ChangeBuilder;
        use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};

        let schema = SchemaBuilder::new("server_head_rows")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;
        let transport =
            LocalTransport::new(std::slice::from_ref(&schema), None, Some(10_000)).await?;
        let root = transport.get_root_hash().await?;
        let app_schema = ApplicationSchema::WithDataCommitment(vec![schema], root, EXTEND_FF_ID);
        let alice = Space::create(transport.clone(), app_schema).await?;

        let mut insert_query = Query::new(
            "server_head_rows".to_string(),
            QueryOperation::Insert(vec![(
                "name".to_string(),
                QueryParam::Text("unapplied".to_string()),
            )]),
        );
        crate::crypto::encrypt_query_fields(&mut insert_query, &alice).await?;
        let change = ChangeBuilder::new(&mut insert_query, std::sync::Arc::new(alice.clone()))
            .build()
            .await?
            .expect("insert should produce a change");
        alice.transport.submit_change(&change, vec![]).await?;

        let ff_data = transport.fast_forward(alice.current_change_id()).await?;
        assert!(ff_data.proof.is_none(), "test setup should avoid FF proofs");
        assert!(
            !ff_data.changes.is_empty(),
            "test setup should produce ragged changes"
        );
        assert!(
            ff_data.server_head.is_some(),
            "test setup should include server head"
        );

        Ok((alice, ff_data))
    }

    #[tokio::test]
    async fn fast_forward_from_nonzero_anchor_includes_prior_inclusion() -> Result<()> {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping fast_forward_from_nonzero_anchor_includes_prior_inclusion: RISC0_SKIP_BUILD is set");
            return Ok(());
        }
        let (_alice, ff_data, from_change_id) = nonzero_anchor_fast_forward().await?;

        let proof = ff_data.proof.as_ref().expect("expected FF proof");
        let prior_proof = proof
            .from_inclusion_proof
            .as_ref()
            .expect("non-zero FF request must include prior-anchor proof");
        assert_eq!(prior_proof.i, from_change_id);

        Ok(())
    }

    #[tokio::test]
    async fn ragged_fast_forward_omits_end_anchor() -> Result<()> {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping ragged_fast_forward_omits_end_anchor: RISC0_SKIP_BUILD is set");
            return Ok(());
        }
        let (_alice, ff_data) = ragged_fast_forward_from_nonzero_anchor().await?;
        let proof = ff_data.proof.as_ref().expect("expected FF proof");

        assert!(proof.end_entry.is_none());
        assert!(proof.end_entry_inclusion_proof.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn fast_forward_rejects_missing_prior_inclusion_without_state_change() -> Result<()> {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping fast_forward_rejects_missing_prior_inclusion_without_state_change: RISC0_SKIP_BUILD is set");
            return Ok(());
        }
        let (alice, mut ff_data, _) = nonzero_anchor_fast_forward().await?;
        let before = changelog_snapshot(&alice);
        ff_data
            .proof
            .as_mut()
            .expect("expected FF proof")
            .from_inclusion_proof = None;

        let err = alice.apply_fast_forward(ff_data).await.unwrap_err();

        assert!(
            err.to_string().contains("omitted from_inclusion_proof"),
            "unexpected error: {err}"
        );
        assert_eq!(changelog_snapshot(&alice), before);

        Ok(())
    }

    #[tokio::test]
    async fn fast_forward_rejects_bad_end_anchor_without_state_change() -> Result<()> {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping fast_forward_rejects_bad_end_anchor_without_state_change: RISC0_SKIP_BUILD is set");
            return Ok(());
        }
        let (alice, mut ff_data, _) = nonzero_anchor_fast_forward().await?;
        let before = changelog_snapshot(&alice);
        let proof = ff_data.proof.as_mut().expect("expected FF proof");
        proof
            .end_entry_inclusion_proof
            .as_mut()
            .expect("proof-only response must include end anchor proof")
            .i = proof.end_change_id.saturating_sub(1);

        let err = alice.apply_fast_forward(ff_data).await.unwrap_err();

        assert!(
            err.to_string().contains("end_entry_inclusion_proof.i"),
            "unexpected error: {err}"
        );
        assert_eq!(changelog_snapshot(&alice), before);

        Ok(())
    }

    #[tokio::test]
    async fn fast_forward_rejects_missing_end_anchor_for_proof_only_response() -> Result<()> {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping fast_forward_rejects_missing_end_anchor_for_proof_only_response: RISC0_SKIP_BUILD is set");
            return Ok(());
        }
        let (alice, mut ff_data, _) = nonzero_anchor_fast_forward().await?;
        let before = changelog_snapshot(&alice);
        let proof = ff_data.proof.as_mut().expect("expected FF proof");
        proof.end_entry = None;
        proof.end_entry_inclusion_proof = None;

        let err = alice.apply_fast_forward(ff_data).await.unwrap_err();

        assert!(
            err.to_string().contains("omitted end_entry"),
            "unexpected error: {err}"
        );
        assert_eq!(changelog_snapshot(&alice), before);

        Ok(())
    }

    #[tokio::test]
    async fn fast_forward_sigref_failure_rolls_back_verified_anchor_state() -> Result<()> {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping fast_forward_sigref_failure_rolls_back_verified_anchor_state: RISC0_SKIP_BUILD is set");
            return Ok(());
        }
        let (alice, mut ff_data, _) = nonzero_anchor_fast_forward().await?;
        let before = changelog_snapshot(&alice);
        let proof = ff_data.proof.as_mut().expect("expected FF proof");
        assert!(
            !proof.sigref_entries.is_empty(),
            "test setup must produce sigref entries"
        );
        proof.sigref_entries.clear();

        let err = alice.apply_fast_forward(ff_data).await.unwrap_err();

        assert!(
            err.to_string().contains("sigref_entries missing entry"),
            "unexpected error: {err}"
        );
        assert_eq!(changelog_snapshot(&alice), before);

        Ok(())
    }

    /// Regression for #100: if ragged proof verification fails after one
    /// ragged change has already applied, the whole fast-forward must roll
    /// back to the pre-call changelog state.
    #[tokio::test]
    async fn apply_fast_forward_rollback_on_ragged_proof_failure() -> Result<()> {
        let (transport, alice) = create_space().await?;
        let invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), invite, schema()).await?;
        let _u = bob.invite_user().await?.user;

        assert_eq!(alice.current_change_id(), 2);
        let mut ff_data = transport.fast_forward(alice.current_change_id()).await?;
        assert!(
            ff_data.proof.is_none(),
            "test setup should produce ragged-only fast-forward data"
        );
        assert_eq!(
            ff_data.responses.len(),
            2,
            "test setup should produce two ragged changes"
        );

        ff_data.responses[1].new_root[0] ^= 0xff;
        let before = changelog_snapshot(&alice);

        let err = alice.apply_fast_forward(ff_data).await.unwrap_err();

        assert!(
            err.to_string().contains("verify_pruned_merkle_tree failed"),
            "unexpected error: {err}"
        );
        assert_eq!(changelog_snapshot(&alice), before);

        Ok(())
    }

    /// Regression for #30: a ragged change whose `sig_ref` does not match
    /// the signer's previously accepted `change_id` (as tracked in the
    /// client's `sigref_map`) must be rejected, and any prior ragged
    /// state must roll back.
    #[tokio::test]
    async fn apply_fast_forward_rejects_ragged_with_broken_sigref() -> Result<()> {
        let (transport, alice) = create_space().await?;
        let invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), invite, schema()).await?;
        let _u = bob.invite_user().await?.user;

        assert_eq!(alice.current_change_id(), 2);
        let mut ff_data = transport.fast_forward(alice.current_change_id()).await?;
        assert!(
            ff_data.proof.is_none(),
            "test setup should produce ragged-only fast-forward data"
        );
        assert_eq!(
            ff_data.changes.len(),
            2,
            "test setup should produce two ragged changes (bob's RefreshKeys then his InviteUser)"
        );

        // The second ragged change is Bob's InviteUser, signed by Bob with
        // `sig_ref` = Bob's RefreshKeys change_id. Unlike RefreshKeys (which
        // independently re-validates sig_ref against `_key_history` inside
        // `verify_proof_and_validate`), InviteUser does not — so this is the
        // narrowest case that exercises the new client-side sigref check
        // without being short-circuited by op-specific proof checks.
        let original = ff_data.changes[1].sig_ref;
        ff_data.changes[1].sig_ref = original.wrapping_add(1);

        let before = changelog_snapshot(&alice);
        let err = alice.apply_fast_forward(ff_data).await.unwrap_err();

        assert!(
            err.to_string().contains("Sigref chain broken"),
            "expected sigref-chain rejection, got: {err}"
        );
        assert_eq!(
            changelog_snapshot(&alice),
            before,
            "failed ragged change must leave changelog state untouched"
        );

        Ok(())
    }

    /// Regression for #30: a ragged tail interleaving multiple signers
    /// must advance `sigref_map` per-uid independently. Tampering the
    /// last change's `sig_ref` after several valid interleaved changes
    /// have applied in-flight must roll back ALL per-uid sigref state,
    /// not just the failing signer's.
    #[tokio::test]
    async fn apply_fast_forward_rolls_back_interleaved_sigref_map_on_tail_failure() -> Result<()> {
        // Use a huge FF batch size so the server never emits an FF proof
        // during this test — we need a pure ragged tail of interleaved
        // signers to exercise the per-uid `check_sigref_continuity`
        // rollback path (the proof-seeded path is covered separately).
        let transport = LocalTransport::new(&[], None, Some(1024)).await?;
        let alice = Space::create(transport.clone(), schema()).await?;

        let bob_invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), bob_invite, schema()).await?;
        // Bob froze at his own RefreshKeys (change_id=3); his join-time
        // FF seed populated sigref_map with {alice: 2, bob: 3}.
        let bob_anchor = bob.current_change_id();

        // Build a ragged tail [alice.IU, carol.RK, alice.IU] from two
        // different signers. `invite_user` doesn't auto-retry on
        // `FastForwardRequired`, so alice must `sync()` between phases.
        alice.sync().await?;
        let carol_invite = alice.invite_user().await?; // change_id=4
        let _carol = Space::join(transport.clone(), carol_invite, schema()).await?; // change_id=5
        alice.sync().await?;
        let _dana = alice.invite_user().await?.user; // change_id=6

        let mut ff_data = transport.fast_forward(bob_anchor).await?;
        assert!(
            ff_data.proof.is_none(),
            "ff_batch_size=1024 must keep this test purely ragged"
        );
        assert_eq!(
            ff_data.changes.len(),
            3,
            "expected interleaved ragged tail [alice.IU, carol.RK, alice.IU]"
        );

        let alice_uid = ff_data.changes[0].uid;
        let carol_uid = ff_data.changes[1].uid;
        assert_ne!(alice_uid, carol_uid, "ragged tail must contain two signers");
        assert_eq!(
            ff_data.changes[2].uid, alice_uid,
            "third change must be alice's second invite, interleaving past carol's RK"
        );

        // Tamper the LAST change (alice's second InviteUser): its
        // `expected_sig_ref` is alice's first InviteUser's change_id
        // (already advanced into `sigref_map[alice]` two iterations
        // earlier). Bumping it breaks the chain and must roll the
        // whole ragged tail back — including carol's sigref entry
        // that had successfully applied mid-flight.
        let original = ff_data.changes[2].sig_ref;
        ff_data.changes[2].sig_ref = original.wrapping_add(1);

        let before = changelog_snapshot(&bob);
        let err = bob.apply_fast_forward(ff_data).await.unwrap_err();

        assert!(
            err.to_string().contains("Sigref chain broken"),
            "expected sigref-chain rejection, got: {err}"
        );
        assert_eq!(
            changelog_snapshot(&bob),
            before,
            "tail failure must roll back per-uid sigref_map advances for ALL signers \
             (changelog_snapshot now includes sigref_map, so this asserts \
             SavedChangelogState restores it on rollback)"
        );

        Ok(())
    }

    #[tokio::test]
    async fn fast_forward_server_head_divergence_rolls_back_applied_ragged_changes() -> Result<()> {
        let (alice, mut ff_data) = ragged_only_fast_forward_from_alice().await?;
        let before = changelog_snapshot(&alice);
        ff_data
            .server_head
            .as_mut()
            .expect("test setup should include server head")
            .clc_prefix[0] ^= 0xff;

        let err = alice.apply_fast_forward(ff_data).await.unwrap_err();

        match err {
            SdkError::StateDiverged(_) => {}
            other => panic!("expected StateDiverged, got {other:?}"),
        }
        assert_eq!(changelog_snapshot(&alice), before);

        Ok(())
    }

    #[tokio::test]
    async fn fast_forward_rejects_response_beyond_server_head_without_state_change() -> Result<()> {
        let (alice, mut ff_data) = ragged_only_fast_forward_from_alice().await?;
        let before = changelog_snapshot(&alice);
        let target_change_id = ff_data
            .responses
            .iter()
            .map(|response| response.change_id)
            .max()
            .expect("test setup should produce responses");
        ff_data
            .server_head
            .as_mut()
            .expect("test setup should include server head")
            .change_id = target_change_id.saturating_sub(1);

        let err = alice.apply_fast_forward(ff_data).await.unwrap_err();

        assert!(
            err.to_string().contains("beyond server head"),
            "unexpected error: {err}"
        );
        assert_eq!(changelog_snapshot(&alice), before);

        Ok(())
    }

    #[tokio::test]
    async fn space_create_inserts_owner() -> Result<()> {
        let (_, space) = create_space().await?;

        let users = space.users().select().all().await?;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].id, Some(1));
        assert_eq!(users[0].status, UserStatus::Full);

        Ok(())
    }

    #[tokio::test]
    async fn invite_user_creates_provisional_member() -> Result<()> {
        let (_, space) = create_space().await?;

        let invite = space.invite_user().await?;

        // The returned invite carries provisional status.
        assert_eq!(invite.user.status, UserStatus::Provisional);

        // The users table should now have two rows.
        let users = space.users().select().all().await?;
        assert_eq!(users.len(), 2);

        let bob = users.iter().find(|u| u.id != Some(1)).unwrap();
        assert_eq!(bob.status, UserStatus::Provisional);

        Ok(())
    }

    #[tokio::test]
    async fn add_member_rejects_invite_with_wrong_root_commitment() -> Result<()> {
        use crate::changelog::ChangeBuilder;
        use crate::users::UserWithSecrets;
        use encrypted_spaces_crypto::KeyCommitment;

        let (transport, space) = create_space().await?;

        // Build a real invite (valid MVE proof) exactly like `invite_user`,
        // then tamper with the commitment before sending — models a
        // malicious inviter who wraps a group key that is *not* the
        // canonical current group key.
        let new_user = UserWithSecrets::provisional();
        let mut invite_builder = space.retention_builder();
        let mut add_request = space
            .key_manager()
            .create_invite(new_user.update_key_pair.public(), &mut invite_builder)
            .await?;
        let invite_output = invite_builder.finalize();
        let invite_retention_writes = invite_output.writes;
        let invite_proofs = invite_output.proofs;

        // Tamper with the commitment.  `[0u8; 32]` is a canonical zero
        // commitment that won't match the real group key.
        add_request.root_commitment =
            KeyCommitment::from_bytes(&[0u8; 32]).expect("zero bytes are canonical");

        let mut pending_record = new_user.as_record();
        pending_record.status = UserStatus::Provisional;
        let mut insert_builder = space.users().insert(&pending_record);
        insert_builder.take_pending_error()?;
        crate::crypto::encrypt_query_fields(&mut insert_builder.query, &space).await?;
        let change = ChangeBuilder::new(
            &mut insert_builder.query,
            std::sync::Arc::new(space.clone()),
        )
        .build_invite_user(&invite_retention_writes)
        .await?;

        let err = transport
            .add_member(add_request, &change, invite_proofs)
            .await
            .expect_err("server must reject invite with wrong root commitment");

        let msg = format!("{err}");
        assert!(
            msg.contains("root_commitment does not match"),
            "expected commitment-mismatch rejection, got: {msg}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn space_join_activates_invited_member() -> Result<()> {
        let (transport, space) = create_space().await?;

        let invite = space.invite_user().await?;
        let bob_id = invite.user.id;
        let bob_space = Space::join(transport.clone(), invite, schema()).await?;

        // Bob's space sees both members and Bob is now Active.
        let users = bob_space.users().select().all().await?;
        assert_eq!(users.len(), 2);

        let bob = users.iter().find(|u| u.id == bob_id).unwrap();
        assert_eq!(bob.status, UserStatus::Full);

        Ok(())
    }

    #[tokio::test]
    async fn remove_user_deletes_member_and_rekeys() -> Result<()> {
        let (transport, space) = create_space().await?;

        // Alice invites Bob.
        let invite = space.invite_user().await?;
        let _bob_space = Space::join(transport.clone(), invite, schema()).await?;

        // Verify both members exist.
        let users = space.users().select().all().await?;
        assert_eq!(users.len(), 2);
        let bob_id = users.iter().find(|u| u.id != Some(1)).unwrap().id.unwrap();

        // Alice syncs to pick up Bob's RefreshKeys rotation from join, so
        // `remove_user` builds `_key_history` against Bob's current auth key.
        space.sync().await?;

        // Alice removes Bob. The server verifies the rekey, writes a
        // GK delivery slot for Alice (the initiator), and `remove_user`
        // recovers the new HGK from that slot before returning. If the
        // slot path fails, `remove_user` surfaces the error here.
        space.remove_user(bob_id).await?;

        let users_after = space.users().select().all().await?;
        assert_eq!(users_after.len(), 1);
        assert_eq!(users_after[0].id, Some(1));

        // Post-rekey sync must be a no-op: Alice's HGK should already be
        // current against the new retention snapshot. Any residual drift
        // (stale HGK, missing slot) would surface via the sync's tri-state
        // check + slot fetch.
        space.sync().await?;

        Ok(())
    }

    /// Stage 5 — the data-driven post-apply hook only fetches a delivery
    /// slot when an actual SL2 fresh-FGK write was applied. Extend, invite,
    /// RefreshKeys, and no-op syncs must not hit the slot fetch path.
    #[tokio::test]
    async fn delivery_slot_fetches_only_when_fresh_fgk_applies() -> Result<()> {
        let (transport, alice) = create_space().await?;

        // Fresh create: the creator's HGK is constructed locally; no slot
        // fetch is ever needed.
        assert_eq!(
            transport.fetch_my_key_delivery_calls(),
            0,
            "Space::create must not fetch a slot"
        );

        // Pure no-op sync — nothing new on the server for Alice to catch
        // up on, so the FF-driven hook must stay inert.
        alice.sync().await?;
        assert_eq!(
            transport.fetch_my_key_delivery_calls(),
            0,
            "no-op Space::sync must not fetch a slot"
        );

        // invite_user does not rekey; the inviter path writes only
        // `sl2/fgk/next` / D-row metadata (no fresh FGK row for the
        // inviter). Data-driven detection must keep the counter at 0.
        let invite = alice.invite_user().await?;
        let after_invite = transport.fetch_my_key_delivery_calls();
        assert_eq!(
            after_invite, 0,
            "invite_user on the inviter must not fetch a slot (no fresh FGK applies)"
        );

        // Space::join must fetch exactly once — that is the invitee's
        // bootstrap slot read. Any additional fetch beyond the single
        // bootstrap is a regression of the data-driven gating.
        let bob = Space::join(transport.clone(), invite, schema()).await?;
        let after_join = transport.fetch_my_key_delivery_calls();
        assert_eq!(
            after_join, 1,
            "Space::join must fetch the bootstrap slot exactly once; got {after_join}"
        );

        // Sync the inviter over Bob's join + RefreshKeys. Neither
        // InviteUser nor RefreshKeys writes a fresh `sl2/fgk/row/`, so
        // the aggregated FF hook must not fetch.
        alice.sync().await?;
        assert_eq!(
            transport.fetch_my_key_delivery_calls(),
            after_join,
            "FF batch with only InviteUser + RefreshKeys must not fetch a slot"
        );

        // remove_user rekeys — the local accepted-change path sees a
        // fresh `sl2/fgk/row/` write and fetches Alice's slot exactly
        // once. (Bob's space may catch up via its own broadcast/FF path,
        // which is why we measure the delta against `alice.remove_user`
        // specifically rather than the full post-test count.)
        let bob_id = alice
            .users()
            .select()
            .all()
            .await?
            .into_iter()
            .find(|u| u.id != Some(1))
            .unwrap()
            .id
            .unwrap();
        let before_remove = transport.fetch_my_key_delivery_calls();
        alice.remove_user(bob_id).await?;
        let delta = transport.fetch_my_key_delivery_calls() - before_remove;
        assert!(
            delta >= 1,
            "remove_user must fetch the initiator's slot (fresh FGK was written); delta={delta}"
        );

        // Silence unused warning; `bob` is only held to keep its cached
        // transport alive so broadcast routing doesn't drop the
        // connection mid-test.
        drop(bob);
        Ok(())
    }

    /// Stage 6 — a client that missed a fresh-random rekey recovers its HGK
    /// from the delivery slot on the next `sync()`.
    #[tokio::test]
    async fn sync_after_missed_rekey_recovers_via_slot() -> Result<()> {
        let (transport, alice) = create_space().await?;

        // Alice invites Bob; Bob joins and rotates his provisional keypair.
        let bob_invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), bob_invite, schema()).await?;
        alice.sync().await?;

        // Alice invites Carol; Carol joins.
        let carol_invite = alice.invite_user().await?;
        let carol = Space::join(transport.clone(), carol_invite, schema()).await?;
        alice.sync().await?;

        // Baseline fetch count. `Space::join` already fetched bootstrap
        // slots for Bob and Carol; we measure deltas from here.
        let before_rekey = transport.fetch_my_key_delivery_calls();

        // Alice removes Carol. rekey writes a fresh FGK row; Alice's local
        // apply path runs the data-driven hook and fetches her own slot.
        let carol_id = alice
            .users()
            .select()
            .all()
            .await?
            .into_iter()
            .map(|u| u.id.unwrap())
            .max()
            .expect("at least one user");
        alice.remove_user(carol_id).await?;

        let after_alice_remove = transport.fetch_my_key_delivery_calls();
        assert!(
            after_alice_remove > before_rekey,
            "initiator's local accepted-change path must fetch the slot"
        );

        // Bob has not synced since the rekey. His local HGK is stale.
        // A sync FFs over the RemoveUser change and the post-apply hook
        // detects the fresh FGK, fetches Bob's slot, and recovers.
        let before_bob_sync = transport.fetch_my_key_delivery_calls();
        bob.sync().await?;
        let bob_delta = transport.fetch_my_key_delivery_calls() - before_bob_sync;
        assert!(
            bob_delta >= 1,
            "Bob's sync over a missed rekey must fetch his delivery slot; delta={bob_delta}"
        );

        // Bob's state is coherent post-recovery: a follow-up table read
        // (which requires a valid current key for decryption) succeeds.
        let bobs_view = bob.users().select().all().await?;
        assert_eq!(
            bobs_view.len(),
            2,
            "Bob should see two users (himself + Alice) after syncing the RemoveUser"
        );

        drop(carol);
        Ok(())
    }

    #[tokio::test]
    async fn space_join_alice_sees_bob_as_active_after_fast_forward() -> Result<()> {
        let (transport, space) = create_space().await?;

        let invite = space.invite_user().await?;
        let bob_id = invite.user.id;
        Space::join(transport, invite, schema()).await?;

        // Alice fast-forwards to pick up Bob's key rotation.
        space.recover_via_fast_forward().await?;

        let users = space.users().select().all().await?;
        let bob = users.iter().find(|u| u.id == bob_id).unwrap();
        assert_eq!(bob.status, UserStatus::Full);

        Ok(())
    }

    #[tokio::test]
    async fn provisional_user_cannot_insert() -> Result<()> {
        let (transport, space) = create_space().await?;
        let invite = space.invite_user().await?;
        let bob_uid = invite.user.id.unwrap() as u32;

        // Bob is provisional — try to submit an insert as Bob directly
        // via the transport (bypassing Space::join which would rotate keys).
        let bob_transport = transport.clone();
        bob_transport
            .authenticate(&invite.user.as_auth_context(space.id()))
            .await?;

        // Build a changelog entry for a table insert as Bob.
        // Use the "products" table (not _users) so we don't hit schema
        // issues with internal tables.  First register the schema so the
        // server knows about it.
        use encrypted_spaces_backend::merk_storage::column_key_placeholder;
        use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType, Schema};
        use encrypted_spaces_changelog_core::changelog::{OpType, ROOT_TREE_PATH};

        let products_schema = Schema {
            name: "products".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "name".to_string(),
                    column_type: ColumnType::String,
                    plaintext: true,
                    indexed: false,
                },
            ],
            auto_increment: true,
        };
        bob_transport.create_table(&products_schema).await?;

        let keys = [column_key_placeholder("products", "name")];
        let vals: Vec<&[u8]> = vec![b"\"widget\""];
        let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        // create_table resets the changelog; compute the CLC at change 0
        // from the server's post-reset initial data commitment.
        let initial_dc = bob_transport.changelog_start_root().await;
        let initial_clc: [u8; 32] = initial_clc_state(&initial_dc).root.into();
        let mut change = Change::new(
            OpType::Insert,
            bob_uid,
            ROOT_TREE_PATH,
            &key_refs,
            &vals,
            0,
            0,
            initial_clc,
        )
        .unwrap();
        sign_change(&mut change.entry, &invite.user.auth_key_pair);

        let result: Result<_> = bob_transport.submit_change(&change, vec![]).await;
        assert!(result.is_err(), "provisional user should be blocked");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("provisional_user_restricted") || err.contains("provisional user"),
            "unexpected error: {err}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn provisional_user_can_refresh_keys_via_join() -> Result<()> {
        let (transport, space) = create_space().await?;
        let invite = space.invite_user().await?;
        let bob_id = invite.user.id;

        // Space::join performs RefreshKeys — this must succeed even though
        // Bob starts as provisional.
        let bob_space = Space::join(transport, invite, schema()).await?;

        let users = bob_space.users().select().all().await?;
        let bob = users.iter().find(|u| u.id == bob_id).unwrap();
        assert_eq!(bob.status, UserStatus::Full);

        Ok(())
    }

    #[tokio::test]
    async fn resolve_signing_key_finds_historical_key() -> Result<()> {
        let (_, space) = create_space().await?;
        // CreateSpace is change 1. After create, my_last_change_id = 1.

        // Capture K1 (current auth key before rotation).
        let k1_vk = *space
            .key_manager
            .lock()
            .await
            .auth_key_pair()
            .verification_key();

        // Create a data change so my_last_change_id advances.
        let _extra_user = space.invite_user().await?.user;
        let c1 = space.my_last_change_id(); // change that K1 signed

        // Rotate K1 → K2.  Key history now has [K1 valid_from=0, valid_to=c1].
        space.rotate_user_keys().await?;
        let k2_vk = *space
            .key_manager
            .lock()
            .await
            .auth_key_pair()
            .verification_key();
        assert_ne!(k1_vk, k2_vk, "keys should differ after rotation");

        // Create a data change signed by K2 so we can test current-key resolution.
        let _extra_user2 = space.invite_user().await?.user;
        let c2 = space.my_last_change_id();

        let uid = space.uid().unwrap();

        // resolve_signing_key for c1 should return K1 (historical).
        let resolved_for_c1 = space.resolve_signing_key(uid, c1).await?;
        assert_eq!(
            resolved_for_c1, k1_vk,
            "change {c1} should resolve to K1 (historical key)"
        );

        // resolve_signing_key for c2 (a data change signed by K2) should return K2.
        let resolved_for_c2 = space.resolve_signing_key(uid, c2).await?;
        assert_eq!(
            resolved_for_c2, k2_vk,
            "change {c2} should resolve to K2 (current key)"
        );

        Ok(())
    }

    #[tokio::test]
    async fn resolve_signing_key_for_refresh_keys_change_uses_predecessor_key() -> Result<()> {
        use encrypted_spaces_changelog_core::changelog::OpType;

        let (_, space) = create_space().await?;
        let uid = space.uid().unwrap();

        let k1_vk = *space
            .key_manager
            .lock()
            .await
            .auth_key_pair()
            .verification_key();
        let _extra_user = space.invite_user().await?.user;
        let pre_refresh_change = space.my_last_change_id();

        space.rotate_user_keys().await?;

        let refresh_change_id = space.with_state(|state| state.current_change_id);

        let resolved = space
            .resolve_signing_key_for_change(
                uid,
                refresh_change_id,
                OpType::RefreshKeys,
                pre_refresh_change,
            )
            .await?;

        assert_eq!(
            resolved, k1_vk,
            "RefreshKeys change should resolve to the predecessor signing key"
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_invite_join_flow_verifies_real_refresh_keys_and_followup_change() -> Result<()>
    {
        use encrypted_spaces_backend::access_control::AuthContext;
        use encrypted_spaces_backend::sign_change::verify_change_signature;
        use encrypted_spaces_changelog_core::changelog::OpType;

        let (transport, alice) = create_space().await?;
        let alice_uid = alice.uid().unwrap();

        let invite = alice.invite_user().await?;
        let bob_uid = invite.user.id.unwrap() as u32;
        let bob_provisional_vk = *invite.user.auth_key_pair.verification_key();

        let bob = Space::join(transport.clone(), invite, schema()).await?;
        let bob_current_vk = *bob
            .key_manager
            .lock()
            .await
            .auth_key_pair()
            .verification_key();
        assert_ne!(bob_provisional_vk, bob_current_vk);

        alice.recover_via_fast_forward().await?;

        transport
            .authenticate(&AuthContext::new(Some(alice_uid as i64), alice.id()))
            .await?;
        let ff_after_join = transport.fast_forward(0).await?;
        let (bob_refresh_change, bob_refresh_response) = ff_after_join
            .changes
            .iter()
            .zip(ff_after_join.responses.iter())
            .find(|(change, _)| {
                change.uid == bob_uid && change.message.op_type == OpType::RefreshKeys
            })
            .expect("expected Bob RefreshKeys change in changelog");

        let resolved_refresh_signer = alice
            .resolve_signing_key_for_change(
                bob_uid,
                bob_refresh_response.change_id,
                bob_refresh_change.message.op_type,
                bob_refresh_change.sig_ref,
            )
            .await?;
        assert_eq!(
            resolved_refresh_signer, bob_provisional_vk,
            "Bob's join-generated RefreshKeys change should verify with the provisional key"
        );
        verify_change_signature::<DefaultSignature>(bob_refresh_change, &resolved_refresh_signer)
            .unwrap();

        let _charlie_invite = bob.invite_user().await?;
        let bob_followup_change_id = bob.my_last_change_id();

        alice.recover_via_fast_forward().await?;
        transport
            .authenticate(&AuthContext::new(Some(alice_uid as i64), alice.id()))
            .await?;
        let ff_after_bob_invite = transport.fast_forward(0).await?;
        let (bob_invite_change, bob_invite_response) = ff_after_bob_invite
            .changes
            .iter()
            .zip(ff_after_bob_invite.responses.iter())
            .find(|(change, response)| {
                change.uid == bob_uid
                    && change.message.op_type == OpType::InviteUser
                    && response.change_id == bob_followup_change_id
            })
            .expect("expected Bob InviteUser change in changelog");

        let resolved_followup_signer = alice
            .resolve_signing_key(bob_uid, bob_invite_response.change_id)
            .await?;
        assert_eq!(
            resolved_followup_signer, bob_current_vk,
            "Bob's post-join InviteUser change should verify with Bob's permanent key"
        );
        verify_change_signature::<DefaultSignature>(bob_invite_change, &resolved_followup_signer)
            .unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn end_to_end_verify_deep_history() -> Result<()> {
        use encrypted_spaces_backend::sign_change::verify_change_signature;

        let (transport, alice) = create_space().await?;
        let alice_uid = alice.uid().unwrap();

        // -- K1: Alice creates a data change --
        let k1_vk = *alice
            .key_manager
            .lock()
            .await
            .auth_key_pair()
            .verification_key();
        let _user_a = alice.invite_user().await?.user;
        let c1 = alice.my_last_change_id();

        // -- Rotate K1 → K2 --
        alice.rotate_user_keys().await?;
        let k2_vk = *alice
            .key_manager
            .lock()
            .await
            .auth_key_pair()
            .verification_key();

        // -- K2: Alice creates a data change --
        let _user_b = alice.invite_user().await?.user;
        let c2 = alice.my_last_change_id();

        // -- Rotate K2 → K3 --
        alice.rotate_user_keys().await?;
        let k3_vk = *alice
            .key_manager
            .lock()
            .await
            .auth_key_pair()
            .verification_key();

        // -- K3: Alice creates a data change --
        let _user_c = alice.invite_user().await?.user;
        let c3 = alice.my_last_change_id();

        // -- Rotate K3 → K4 --
        alice.rotate_user_keys().await?;
        let k4_vk = *alice
            .key_manager
            .lock()
            .await
            .auth_key_pair()
            .verification_key();
        assert_ne!(k1_vk, k2_vk);
        assert_ne!(k2_vk, k3_vk);
        assert_ne!(k3_vk, k4_vk);

        // -- Bob joins the space --
        let invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), invite, schema()).await?;

        // Bob resolves Alice's key for c2 (2nd-oldest key, K2) — deep history lookup.
        let resolved_c2 = bob.resolve_signing_key(alice_uid, c2).await?;
        assert_eq!(resolved_c2, k2_vk, "change {c2} should resolve to K2");

        // Bob resolves Alice's key for c1 (oldest key, K1).
        let resolved_c1 = bob.resolve_signing_key(alice_uid, c1).await?;
        assert_eq!(resolved_c1, k1_vk, "change {c1} should resolve to K1");

        // Bob resolves Alice's key for c3 (K3).
        let resolved_c3 = bob.resolve_signing_key(alice_uid, c3).await?;
        assert_eq!(resolved_c3, k3_vk, "change {c3} should resolve to K3");

        // Verify that each change's signature actually passes cryptographic
        // verification against the resolved key. We grab the full changelog via
        // fast-forward and pick out the changes by change_id.
        use encrypted_spaces_backend::access_control::AuthContext;
        let bob_uid = bob.uid().unwrap();
        transport
            .authenticate(&AuthContext::new(Some(bob_uid as i64), bob.id()))
            .await?;
        let ff = transport.fast_forward(0).await?;
        for (change, response) in ff.changes.iter().zip(ff.responses.iter()) {
            if change.uid != alice_uid {
                continue;
            }
            let resolved = bob
                .resolve_signing_key_for_change(
                    alice_uid,
                    response.change_id,
                    change.message.op_type,
                    change.sig_ref,
                )
                .await?;
            verify_change_signature::<DefaultSignature>(change, &resolved).unwrap_or_else(|e| {
                panic!(
                    "signature verification failed for Alice's change {}: {e:?}",
                    response.change_id
                )
            });
        }

        Ok(())
    }

    const DEMO_SCHEMA_FILE: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../demos/tauri/app_schema.kdl");
    const DEMO_SCHEMA_BYTES: &[u8] = include_bytes!("../../demos/tauri/app_schema.kdl");

    #[derive(Debug, Serialize, Deserialize)]
    struct DemoChannel {
        id: Option<i64>,
        name: String,
        description: Option<String>,
        tasks: crate::List,
        notes: crate::TextArea,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct DemoUsersMeta {
        id: Option<i64>,
        name: String,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct DemoUserInfo {
        id: i64,
        name: String,
        status: String,
    }

    fn demo_schemas_from_kdl() -> Vec<Schema> {
        let text = std::str::from_utf8(DEMO_SCHEMA_BYTES).expect("schema is utf-8");
        let bundle = parse_schema_bundle(text).expect("valid demo schema KDL");
        bundle
            .tables
            .into_iter()
            .filter_map(|entry| entry.schema)
            .collect()
    }

    async fn demo_schema() -> ApplicationSchema {
        let transport = LocalTransport::from_schema_file(DEMO_SCHEMA_FILE)
            .await
            .expect("demo schema transport");
        let commitment = transport
            .get_root_hash()
            .await
            .expect("demo schema commitment");
        ApplicationSchema::for_testing(demo_schemas_from_kdl(), commitment)
    }

    async fn create_demo_space() -> Result<(LocalTransport, Space)> {
        let transport = LocalTransport::from_schema_file(DEMO_SCHEMA_FILE).await?;
        let commitment = transport.get_root_hash().await?;
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing(demo_schemas_from_kdl(), commitment),
        )
        .await?;
        Ok((transport, space))
    }

    async fn bootstrap_demo_like(space: &Space, user_name: &str) -> Result<i64> {
        let uid = space.get_auth_context().uid.unwrap();

        let existing_meta: Option<DemoUsersMeta> = space
            .table::<DemoUsersMeta>("users_meta")
            .select()
            .where_eq("id", uid)
            .first()
            .await?;
        if existing_meta.is_none() {
            space
                .table::<DemoUsersMeta>("users_meta")
                .insert(&DemoUsersMeta {
                    id: Some(uid),
                    name: user_name.to_string(),
                })
                .execute()
                .await?;
        }

        let channel_name = "general".to_string();
        let existing_channel: Option<DemoChannel> = space
            .table::<DemoChannel>("channels")
            .select()
            .filter("name", move |value| value.as_str() == Some(&channel_name))
            .first()
            .await?;

        if let Some(channel) = existing_channel {
            return Ok(channel.id.expect("channel id"));
        }

        space
            .table::<DemoChannel>("channels")
            .insert(&DemoChannel {
                id: None,
                name: "general".to_string(),
                description: None,
                tasks: crate::List::empty(),
                notes: crate::TextArea::empty(),
            })
            .execute()
            .await
    }

    async fn load_demo_users_like_member_panel(space: &Space) -> Result<Vec<DemoUserInfo>> {
        space.sync().await?;

        let records: Vec<crate::users::UserRecord> = space.users().select().all().await?;
        let meta_records: Vec<DemoUsersMeta> = space
            .table::<DemoUsersMeta>("users_meta")
            .select()
            .all()
            .await?;
        let name_map: std::collections::HashMap<i64, String> = meta_records
            .into_iter()
            .map(|record| (record.id.expect("users_meta id"), record.name))
            .collect();

        Ok(records
            .into_iter()
            .map(|user| {
                let uid = user.id.unwrap_or(0);
                DemoUserInfo {
                    id: uid,
                    name: name_map
                        .get(&uid)
                        .cloned()
                        .unwrap_or_else(|| format!("user_{uid}")),
                    status: match user.status {
                        UserStatus::Provisional => "pending".to_string(),
                        UserStatus::Full => "member".to_string(),
                    },
                }
            })
            .collect())
    }

    #[tokio::test]
    async fn demo_style_bootstrap_shows_joined_member_name_via_sdk_test() -> Result<()> {
        let (transport, alice) = create_demo_space().await?;

        bootstrap_demo_like(&alice, "alice").await?;

        let invite = alice.invite_user().await?;
        let pending_users = load_demo_users_like_member_panel(&alice).await?;
        let pending_bob = pending_users
            .iter()
            .find(|user| user.id == invite.user.id.unwrap())
            .expect("expected invited member before join");
        assert_eq!(pending_bob.status, "pending");

        let bob = Space::join(transport.clone(), invite, demo_schema().await).await?;
        let bob_channel_id = bootstrap_demo_like(&bob, "bob").await?;

        let users = load_demo_users_like_member_panel(&alice).await?;
        let bob_user = users
            .iter()
            .find(|user| user.name == "bob")
            .expect("expected Alice to see Bob's chosen name after join");
        assert_eq!(bob_user.status, "member");

        let general_channels: Vec<DemoChannel> =
            bob.table::<DemoChannel>("channels").select().all().await?;
        let matching_general: Vec<&DemoChannel> = general_channels
            .iter()
            .filter(|channel| channel.name == "general")
            .collect();
        assert_eq!(
            matching_general.len(),
            1,
            "expected a single general channel"
        );
        assert_eq!(matching_general[0].id, Some(bob_channel_id));

        Ok(())
    }

    /// `.filter(...).first()` must apply LIMIT before the client filter so
    /// the result matches what the server would return regardless of
    /// cache state.  With two rows ("alpha" at id=1, "general" at id=2),
    /// `.filter(name == "general").first()` translates to "ask the server
    /// for ORDER BY id ASC LIMIT 1, then accept-or-reject client-side":
    /// the server returns id=1 ("alpha"), the client filter rejects it,
    /// result = None.  Cache hit must produce the same answer; pre-fix
    /// it returned `Some(id=2)` because the cache returned all rows and
    /// LIMIT was applied after the client filter.
    #[tokio::test]
    async fn filter_first_after_cache_hit_matches_server_semantics() -> Result<()> {
        let (_transport, space) = create_demo_space().await?;
        bootstrap_demo_like(&space, "alice").await?;

        // Insert "alpha" so it precedes any "general" channel by row id.
        space
            .table::<DemoChannel>("channels")
            .insert(&DemoChannel {
                id: None,
                name: "alpha".to_string(),
                description: None,
                tasks: crate::List::empty(),
                notes: crate::TextArea::empty(),
            })
            .execute()
            .await?;

        // Fully populate the cache for the channels table.
        let _all: Vec<DemoChannel> = space
            .table::<DemoChannel>("channels")
            .select()
            .all()
            .await?;

        // Two channels exist now: id=1 "general" (from bootstrap) and
        // id=2 "alpha". With ORDER BY id ASC LIMIT 1 the server returns
        // id=1 ("general"), so the filter for name == "alpha" rejects it.
        let target_name = "alpha".to_string();
        let result: Option<DemoChannel> = space
            .table::<DemoChannel>("channels")
            .select()
            .filter("name", move |v| v.as_str() == Some(&target_name))
            .first()
            .await?;

        assert!(
            result.is_none(),
            "cache-hit `.filter(...).first()` must apply LIMIT before \
             the client filter (matching server semantics) but returned: \
             {result:?}",
        );
        Ok(())
    }

    /// After Bob joins (RefreshKeys) and then Alice removes Bob, the
    /// _key_history table must contain contiguous, non-overlapping rows that
    /// cover Bob's entire key lifetime.  Validates that `remove_user` computes
    /// a correct `valid_from_change_id` when it reads _key_history.
    ///
    /// NOTE: This test exercises the FF-based synchronisation path.  The
    /// broadcast-specific `_key_history` row-id extraction is covered by the
    /// proof decoding unit tests in `changelog_core`.
    #[tokio::test]
    async fn remove_user_after_join_produces_contiguous_key_history() -> Result<()> {
        use encrypted_spaces_backend::internal_schemas::KEY_HISTORY_TABLE_NAME;

        let (transport, alice) = create_space().await?;

        // Alice invites Bob; Bob joins (triggers RefreshKeys → _key_history row).
        let invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), invite, schema()).await?;
        let bob_uid = bob.uid().unwrap();

        // Alice catches up and removes Bob.
        alice.recover_via_fast_forward().await?;
        alice.remove_user(bob_uid as i64).await?;

        // Re-sync so the _key_history cache includes the RemoveUser
        // insert (which goes to the server but is not applied to the
        // local cache by remove_user).
        alice.recover_via_fast_forward().await?;

        // Read all _key_history rows for Bob from Alice's view.
        let kh: Vec<serde_json::Value> = alice
            .table::<serde_json::Value>(KEY_HISTORY_TABLE_NAME)
            .select()
            .all()
            .await?;

        let mut bob_rows: Vec<&serde_json::Value> = kh
            .iter()
            .filter(|r| r.get("uid").and_then(|v| v.as_i64()) == Some(bob_uid as i64))
            .collect();

        // Bob joined (provisional → full, one RefreshKeys) then was removed
        // (one final key_history entry). We expect at least 2 rows.
        assert!(
            bob_rows.len() >= 2,
            "expected at least 2 key_history rows for Bob after join + removal, got {}",
            bob_rows.len()
        );

        // Sort by valid_from_change_id ascending.
        bob_rows.sort_by_key(|r| {
            r.get("valid_from_change_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        });

        // Assert contiguous, non-overlapping ranges.
        for window in bob_rows.windows(2) {
            let prev_to = window[0]
                .get("valid_to_change_id")
                .and_then(|v| v.as_u64())
                .expect("valid_to_change_id");
            let next_from = window[1]
                .get("valid_from_change_id")
                .and_then(|v| v.as_u64())
                .expect("valid_from_change_id");
            assert_eq!(
                next_from,
                prev_to + 1,
                "key_history ranges must be contiguous: prev valid_to={prev_to}, next valid_from={next_from}"
            );
        }

        // First row should start at 0 (original key from creation).
        let first_from = bob_rows[0]
            .get("valid_from_change_id")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(first_from, 0, "first key_history row should start at 0");

        Ok(())
    }

    /// Repro for UID reuse after removing the highest-numbered invited user.
    #[tokio::test]
    async fn reinvite_after_removal_gets_new_uid() -> Result<()> {
        let (transport, alice) = create_space().await?;

        let bob_invite = alice.invite_user().await?;
        let bob_uid = bob_invite.user.id.expect("bob uid");
        let _bob = Space::join(transport.clone(), bob_invite, schema()).await?;

        alice.recover_via_fast_forward().await?;
        alice.remove_user(bob_uid).await?;
        alice.recover_via_fast_forward().await?;

        let charlie_invite = alice.invite_user().await?;
        let charlie_uid = charlie_invite.user.id.expect("charlie uid");

        assert_ne!(
            charlie_uid, bob_uid,
            "re-invited member must receive a fresh uid after the previous highest uid was removed"
        );

        Ok(())
    }

    /// Multi-user lifecycle test that exercises FF proof verification across
    /// invite, join, mixed-user changes, and remove_user boundaries.
    ///
    /// With DEFAULT_FF_BATCH_SIZE = 5, FF proofs are generated at changes
    /// 5, 10, 15, etc.  Each `recover_via_fast_forward` call is structured so
    /// that Alice is BEHIND the proof boundary (another user crossed it),
    /// ensuring the proof is actually returned and verified, with ragged
    /// changes (individually-verified changes after the proof boundary) in
    /// every FF response.
    ///
    /// The third FF proof covers changes 11-15, including RemoveUser
    /// (change 13), InviteUser (change 14), and RefreshKeys (change 15).
    #[tokio::test]
    async fn multi_user_lifecycle_with_ff_proofs() -> Result<()> {
        init_test_logging();

        // -- Phase 1: Alice creates space, invites Bob, Bob joins + makes a change --
        // Changes: 1=CreateSpace, 2-3=Alice invites two users, 4=InviteUser (Bob),
        //          5=Bob RefreshKeys (→ proof #1), 6=Bob invites another user (ragged)
        let (transport, alice) = create_space().await?; // change 1
        let _u1 = alice.invite_user().await?.user; // change 2
        let _u2 = alice.invite_user().await?.user; // change 3
        let invite = alice.invite_user().await?; // change 4
        let bob = Space::join(transport.clone(), invite, schema()).await?; // change 5 → proof #1
        let bob_uid = bob.uid().unwrap();
        let _u3 = bob.invite_user().await?.user; // change 6 (ragged after proof #1)

        // Alice is at current_change_id=4 (doesn't know about Bob's join or his invite).
        // FF: 4 < proven_up_to(5) → proof #1 returned + 1 ragged change.
        alice.recover_via_fast_forward().await?;
        assert_eq!(
            alice.current_change_id(),
            6,
            "Phase 1: expected change_id 6"
        );

        // -- Phase 2: Bob makes more changes, crossing FF boundary at 10 --
        // Changes: 7-10=Bob invites users (→ proof #2 at 10), 11-12=Bob invites users (ragged)
        let _u4 = bob.invite_user().await?.user; // change 7
        let _u5 = bob.invite_user().await?.user; // change 8
        let _u6 = bob.invite_user().await?.user; // change 9
        let _u7 = bob.invite_user().await?.user; // change 10 → proof #2
        let _u8 = bob.invite_user().await?.user; // change 11 (ragged)
        let _u9 = bob.invite_user().await?.user; // change 12 (ragged)

        // Alice at 6, proven_up_to=10 → proof #2 + 2 ragged changes
        alice.recover_via_fast_forward().await?;
        assert_eq!(
            alice.current_change_id(),
            12,
            "Phase 2: expected change_id 12"
        );

        // -- Phase 3: Alice removes Bob --
        alice.remove_user(bob_uid as i64).await?; // change 13

        // -- Phase 4: Alice invites Charlie, Charlie joins + makes changes --
        // Changes: 14=InviteUser, 15=Charlie RefreshKeys (→ proof #3),
        //          16-17=Charlie invites users (ragged)
        let charlie_invite = alice.invite_user().await?; // change 14
        let charlie = Space::join(transport.clone(), charlie_invite, schema()).await?; // change 15 → proof #3
        let _u10 = charlie.invite_user().await?.user; // change 16 (ragged)
        let _u11 = charlie.invite_user().await?.user; // change 17 (ragged)

        // Alice at 14, proven_up_to=15 → proof #3 + 2 ragged changes.
        // Proof #3 covers changes 11-15, including RemoveUser at 13.
        alice.recover_via_fast_forward().await?;
        assert_eq!(
            alice.current_change_id(),
            17,
            "Phase 4: expected change_id 17"
        );

        // -- Final verification --
        assert_ne!(
            alice.current_data_commitment(),
            [0u8; 32],
            "data commitment should be non-zero"
        );

        Ok(())
    }

    /// Reproduces a 3-user scenario where User 2 removes User 3 and
    /// User 1 (who didn't initiate the rekey) must still be able to
    /// decrypt data written after the rekey.
    ///
    /// Steps:
    /// 1. Alice creates space, writes data to "messages" table
    /// 2. Alice invites Bob, Bob joins, writes messages
    /// 3. Alice invites Carol, Carol joins, writes messages
    /// 4. Everyone syncs
    /// 5. Bob removes Carol (rekey — Bob gets new HGK)
    /// 6. Bob writes messages with the new key
    /// 7. Alice syncs — must recover the new HGK and decrypt Bob's messages
    /// 8. Alice writes messages — Bob must be able to read them
    #[tokio::test]
    async fn three_user_rekey_sync_after_non_initiator_remove() -> Result<()> {
        use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType};

        init_test_logging();

        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        struct Message {
            id: Option<i64>,
            body: String,
        }

        let messages_schema = Schema {
            name: "messages".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "body".to_string(),
                    column_type: ColumnType::String,
                    plaintext: false, // encrypted
                    indexed: false,
                },
            ],
            auto_increment: true,
        };

        // -- Setup: Alice creates space --
        let (transport, alice) = create_space().await?;
        alice.create_table(&messages_schema).await?;

        // Alice writes a message
        alice
            .table::<Message>("messages")
            .insert(&Message {
                id: None,
                body: "hello from alice".to_string(),
            })
            .execute()
            .await?;

        // -- Alice invites Bob --
        let bob_invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), bob_invite, schema()).await?;
        bob.register_table_schema(messages_schema.clone());

        // Bob writes a message
        bob.sync().await?;
        bob.table::<Message>("messages")
            .insert(&Message {
                id: None,
                body: "hello from bob".to_string(),
            })
            .execute()
            .await?;

        // -- Alice invites Carol --
        alice.sync().await?;
        let carol_invite = alice.invite_user().await?;
        let carol = Space::join(transport.clone(), carol_invite, schema()).await?;
        carol.register_table_schema(messages_schema.clone());
        let carol_uid = carol.uid().unwrap();

        // Carol writes a message
        carol.sync().await?;
        carol
            .table::<Message>("messages")
            .insert(&Message {
                id: None,
                body: "hello from carol".to_string(),
            })
            .execute()
            .await?;

        // -- Everyone syncs to a consistent state --
        alice.sync().await?;
        bob.sync().await?;

        // Verify all messages visible
        let alice_msgs: Vec<Message> = alice.table("messages").select().all().await?;
        assert_eq!(
            alice_msgs.len(),
            3,
            "Alice should see 3 messages before remove"
        );

        // -- Bob removes Carol (rekey) --
        bob.remove_user(carol_uid as i64).await?;

        // Bob writes a message after the rekey (encrypted with new key)
        bob.table::<Message>("messages")
            .insert(&Message {
                id: None,
                body: "bob after rekey".to_string(),
            })
            .execute()
            .await?;

        // -- Alice syncs — she must recover the new HGK from her delivery slot --
        alice.sync().await?;

        // Alice should be able to read all messages (including Bob's post-rekey write)
        let alice_msgs_after: Vec<Message> = alice.table("messages").select().all().await?;
        assert_eq!(
            alice_msgs_after.len(),
            4,
            "Alice should see all 4 messages after syncing"
        );
        assert!(
            alice_msgs_after.iter().any(|m| m.body == "bob after rekey"),
            "Alice must be able to decrypt Bob's post-rekey message"
        );

        // -- Alice writes a message — Bob must be able to read it --
        alice
            .table::<Message>("messages")
            .insert(&Message {
                id: None,
                body: "alice after sync".to_string(),
            })
            .execute()
            .await?;
        bob.sync().await?;

        let bob_msgs: Vec<Message> = bob.table("messages").select().all().await?;
        assert_eq!(bob_msgs.len(), 5, "Bob should see all 5 messages");
        assert!(
            bob_msgs.iter().any(|m| m.body == "alice after sync"),
            "Bob must be able to decrypt Alice's post-sync message"
        );

        drop(carol);
        Ok(())
    }

    // -- Stage 5: key hash broadcast and fast-forward tests --

    #[tokio::test]
    async fn key_hash_broadcast_receiver_caches_full_key_material() -> Result<()> {
        use encrypted_spaces_backend::access_control::AuthContext;
        use encrypted_spaces_changelog_core::changelog::OpType;

        let (transport, alice) = create_space().await?;
        let alice_uid = alice.uid().unwrap();

        let invite = alice.invite_user().await?;
        let bob_uid = invite.user.id.unwrap() as u32;
        let bob = Space::join(transport.clone(), invite, schema()).await?;

        // Fetch ragged changes from the server, which include Bob's
        // InviteUser and RefreshKeys entries with hashed_values in the
        // responses.
        transport
            .authenticate(&AuthContext::new(Some(alice_uid as i64), alice.id()))
            .await?;
        let ff = transport.fast_forward(alice.current_change_id()).await?;
        assert!(
            !ff.changes.is_empty(),
            "should have ragged changes after Bob's join"
        );

        // Find Bob's RefreshKeys change — this writes the permanent
        // _users.auth_key and _users.update_key for Bob, and is the
        // change Alice has NOT yet applied locally.
        let (bob_change, bob_response) = ff
            .changes
            .iter()
            .zip(ff.responses.iter())
            .find(|(c, _)| c.uid == bob_uid && c.message.op_type == OpType::RefreshKeys)
            .expect("should find Bob's RefreshKeys change in FF data");

        assert!(
            !bob_response.hashed_values.is_empty(),
            "RefreshKeys response should carry hashed values for key columns"
        );

        // Simulate broadcast reception: apply the change using the
        // response's hashed_values, then update the cache — the same
        // steps handle_broadcast performs.
        let writes = alice.validate_and_apply_change(bob_change, bob_response)?;
        let broadcast_change = Change {
            entry: bob_change.clone(),
            hashed_values: bob_response.hashed_values.clone(),
        };
        alice
            .apply_broadcast_cache_updates(&broadcast_change, &writes)
            .await;

        // Verify the broadcast receiver's cache now contains the full
        // decoded auth_key (a base64 string), not a 32-byte hash.
        let cached_auth_key = alice.with_state(|state| {
            state
                .cache
                .get_row("_users", bob_uid as i64)
                .and_then(|r| r.get("auth_key").cloned())
        });
        assert!(
            cached_auth_key.is_some(),
            "broadcast receiver should have Bob's auth_key cached"
        );
        assert!(
            cached_auth_key.unwrap().is_string(),
            "cached auth_key should be a decoded string, not raw hash bytes"
        );

        drop(bob);
        Ok(())
    }

    #[tokio::test]
    async fn key_hash_broadcast_submitter_caches_full_material_after_invite() -> Result<()> {
        let (_transport, alice) = create_space().await?;

        let invite = alice.invite_user().await?;
        let new_uid = invite.user.id.unwrap();

        let cached_auth_key = alice.with_state(|state| {
            state
                .cache
                .get_row("_users", new_uid)
                .and_then(|r| r.get("auth_key").cloned())
        });
        assert!(
            cached_auth_key.is_some(),
            "submitter should cache invited user's auth_key"
        );
        assert!(
            cached_auth_key.unwrap().is_string(),
            "cached auth_key should be a decoded string, not 32-byte hash"
        );

        Ok(())
    }

    #[tokio::test]
    async fn key_hash_broadcast_submitter_caches_full_material_after_refresh() -> Result<()> {
        let (_transport, space) = create_space().await?;
        let uid = space.uid().unwrap();

        space.rotate_user_keys().await?;

        let cached_auth_key = space.with_state(|state| {
            state
                .cache
                .get_row("_users", uid as i64)
                .and_then(|r| r.get("auth_key").cloned())
        });
        assert!(
            cached_auth_key.is_some(),
            "submitter should cache own auth_key after key rotation"
        );
        assert!(
            cached_auth_key.unwrap().is_string(),
            "cached auth_key should be a decoded string after rotation"
        );

        Ok(())
    }

    #[tokio::test]
    async fn key_hash_fast_forward_stale_client_verifies_signatures() -> Result<()> {
        use encrypted_spaces_backend::access_control::AuthContext;
        use encrypted_spaces_backend::sign_change::verify_change_signature;

        let (transport, alice) = create_space().await?;
        let alice_uid = alice.uid().unwrap();

        let invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), invite, schema()).await?;

        let charlie_invite = bob.invite_user().await?;
        let _charlie = Space::join(transport.clone(), charlie_invite, schema()).await?;

        alice.recover_via_fast_forward().await?;

        transport
            .authenticate(&AuthContext::new(Some(alice_uid as i64), alice.id()))
            .await?;
        let ff = transport.fast_forward(0).await?;

        for (change, response) in ff.changes.iter().zip(ff.responses.iter()) {
            let uid = change.uid;
            let op = change.message.op_type;
            let resolved_key = alice
                .resolve_signing_key_for_change(uid, response.change_id, op, change.sig_ref)
                .await?;
            verify_change_signature::<DefaultSignature>(change, &resolved_key).unwrap();
        }

        let alice_users: Vec<crate::users::UserRecord> = alice.users().select().all().await?;
        assert!(
            alice_users.len() >= 3,
            "Alice should see at least 3 users after FF (alice, bob, charlie)"
        );

        Ok(())
    }

    #[tokio::test]
    async fn key_hash_fast_forward_select_users_after_recovery() -> Result<()> {
        let (transport, alice) = create_space().await?;

        let invite = alice.invite_user().await?;
        let bob = Space::join(transport.clone(), invite, schema()).await?;

        // Bob invites Charlie, which means Alice is stale and needs FF.
        let charlie_invite = bob.invite_user().await?;
        let _charlie = Space::join(transport.clone(), charlie_invite, schema()).await?;

        alice.recover_via_fast_forward().await?;

        let users: Vec<crate::users::UserRecord> = alice.users().select().all().await?;
        assert!(
            users.len() >= 3,
            "Alice should see at least 3 users after FF recovery"
        );
        for user in &users {
            assert!(user.id.is_some(), "user row should have an ID");
            // auth_key deserialized successfully as a VerificationKey,
            // which means the full material was resolved, not a 32-byte hash.
            let _ = user.auth_key;
        }

        Ok(())
    }
}
