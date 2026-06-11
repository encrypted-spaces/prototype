use std::sync::Arc;

use crate::Space;
use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_crypto::Mkem;
use encrypted_spaces_key_manager::traits::GroupKeySync;
use encrypted_spaces_key_manager::{
    DefaultMkem, GkDeliveryEnvelope, InviteRequest, OperationBuilder, RekeyRequest, SimpleKeyId,
};
pub(crate) type SpacePublicKey = <DefaultMkem as Mkem>::PublicKey;

/// Handle for interacting with the key manager for a Space.
pub(crate) struct KeyManagerHandle {
    space: Arc<Space>,
}

impl KeyManagerHandle {
    pub(crate) fn new(space: Arc<Space>) -> Self {
        Self { space }
    }
}

impl KeyManagerHandle {
    pub async fn create_invite(
        &self,
        new_member_pk: &SpacePublicKey,
        builder: &mut dyn OperationBuilder,
    ) -> Result<InviteRequest> {
        let mut km = self.space.key_manager.lock().await;
        km.create_invite(new_member_pk, builder)
            .await
            .map_err(|_| SdkError::ValidationError("create_invite failed".to_string()))
    }

    pub async fn rekey(
        &self,
        remaining_members: &[SpacePublicKey],
        builder: &mut dyn OperationBuilder,
    ) -> Result<RekeyRequest> {
        let km = self.space.key_manager.lock().await;
        km.rekey(remaining_members, builder)
            .await
            .map_err(|_| SdkError::ValidationError("rekey failed".to_string()))
    }

    pub async fn extend(&self, builder: &mut dyn OperationBuilder) -> Result<SimpleKeyId> {
        let mut km = self.space.key_manager.lock().await;
        km.extend(builder)
            .await
            .map_err(|_| SdkError::DatabaseError("key_manager extend failed".to_string()))
    }

    pub async fn reduce(
        &self,
        before: &SimpleKeyId,
        builder: &mut dyn OperationBuilder,
    ) -> Result<()> {
        let mut km = self.space.key_manager.lock().await;
        km.reduce(before, builder)
            .await
            .map_err(|_| SdkError::DatabaseError("key_manager reduce failed".to_string()))
    }
}

impl Space {
    /// Perform a standalone rekey: rotate the group key without removing a user.
    pub async fn rekey(&self) -> Result<()> {
        use crate::users::UserRecord;

        // 1. Gather all current member public keys.
        let all_users: Vec<UserRecord> = self.users().select().all().await?;
        let remaining_pks: Vec<SpacePublicKey> =
            all_users.iter().map(|u| u.update_key.clone()).collect();

        // 2. Build the rekey request via key_manager.
        let mut rekey_builder = self.retention_builder();
        let rekey_request = self
            .key_manager()
            .rekey(&remaining_pks, &mut rekey_builder)
            .await?;
        let rekey_output = rekey_builder.finalize();
        let retention_writes = rekey_output.writes;
        let retention_proofs = rekey_output.proofs;

        // 3. Build changelog entry.
        let change = {
            use crate::changelog::ChangeBuilder;
            ChangeBuilder::retention_only(std::sync::Arc::new(self.clone()))
                .build_rekey(&retention_writes)
                .await?
        };

        // 4. Submit to the server with rekey request for delivery slots.
        let change_response = self
            .transport
            .submit_retention(&change, retention_proofs, Some(rekey_request))
            .await?;

        // 5. Apply the changelog entry to local state. Issue #212: fail closed
        //    unless the exact rekey entry is proven incorporated.
        let completed = self.complete_submitted(change, change_response).await?;
        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(self, &completed.change, writes).await;
        }

        // 6. Post-apply delivery-slot recovery if the builder flagged it.
        self.post_apply_delivery_slot_recovery(rekey_output.needs_delivery)
            .await?;

        Ok(())
    }

    /// Extend the retention system, this advances the data key forward
    /// (e.g. ratchet to a new data key within the current epoch). Returns the new key id.
    pub async fn extend(&self) -> Result<()> {
        // 1. Build the extend request via key_manager.
        let mut extend_builder = self.retention_builder();
        self.key_manager().extend(&mut extend_builder).await?;
        let extend_output = extend_builder.finalize();
        let retention_writes = extend_output.writes;
        let retention_proofs = extend_output.proofs;

        // 2. Build changelog entry.
        let change = {
            use crate::changelog::ChangeBuilder;
            ChangeBuilder::retention_only(std::sync::Arc::new(self.clone()))
                .build_extend(&retention_writes)
                .await?
        };

        // 3. Submit to the server (no rekey request for extend).
        let change_response = self
            .transport
            .submit_retention(&change, retention_proofs, None)
            .await?;

        // 4. Apply the changelog entry to local state. Issue #212: fail closed
        //    unless the exact extend entry is proven incorporated.
        let completed = self.complete_submitted(change, change_response).await?;
        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(self, &completed.change, writes).await;
        }

        // 5. Post-apply delivery-slot recovery if the builder flagged it.
        self.post_apply_delivery_slot_recovery(extend_output.needs_delivery)
            .await?;

        Ok(())
    }

    /// Reduce (prune) old retention keys before a given key ID, preventing
    /// access for new users to old data encrypted with keys before that ID.
    pub async fn reduce(&self, before: SimpleKeyId) -> Result<()> {
        // 1. Build the reduce request via key_manager.
        let mut reduce_builder = self.retention_builder();
        self.key_manager()
            .reduce(&before, &mut reduce_builder)
            .await?;
        let reduce_output = reduce_builder.finalize();
        let retention_writes = reduce_output.writes;
        let retention_proofs = reduce_output.proofs;

        // 2. Build changelog entry.
        let change = {
            use crate::changelog::ChangeBuilder;
            ChangeBuilder::retention_only(std::sync::Arc::new(self.clone()))
                .build_reduce(&retention_writes)
                .await?
        };

        // 3. Submit to the server (no rekey request for reduce).
        let change_response = self
            .transport
            .submit_retention(&change, retention_proofs, None)
            .await?;

        // 4. Apply the changelog entry to local state. Issue #212: fail closed
        //    unless the exact reduce entry is proven incorporated.
        let _completed = self.complete_submitted(change, change_response).await?;

        // 5. Reduce prunes old retention keys — data encrypted with
        //    those keys can no longer be decrypted, so just purge all
        //    cached plaintext rather than updating it from the writes.
        self.with_state_mut(|state| state.cache.clear_all());

        // 6. Post-apply delivery-slot recovery if the builder flagged it.
        self.post_apply_delivery_slot_recovery(reduce_output.needs_delivery)
            .await?;

        Ok(())
    }

    /// Sync the locally-held group key to the canonical retention snapshot,
    /// fetching the GK delivery slot when forward derivation cannot reach
    /// the target.
    ///
    /// Caller must have advanced the local retention snapshot (e.g. via
    /// `recover_via_fast_forward`) before invoking; the canonical
    /// commitment is read from `_retention`.
    ///
    /// Releases the key-manager mutex around the delivery-slot fetch so the
    /// network call does not contend with other key-manager users, then
    /// re-checks state under the re-acquired lock — if a concurrent caller
    /// already recovered, the freshly-fetched envelope is dropped.
    pub(crate) async fn sync_via_delivery_slot(&self) -> Result<()> {
        let builder = self.retention_builder();

        // First check: do we even need a slot fetch?
        {
            let mut km = self.key_manager.lock().await;
            match km
                .sync_group_key(&builder)
                .await
                .map_err(|_| SdkError::ValidationError("group key sync failed".to_string()))?
            {
                GroupKeySync::AlreadyCurrent | GroupKeySync::DerivedForward => {
                    return Ok(());
                }
                GroupKeySync::NeedsDelivery => {}
            }
        }

        // Lock dropped — fetch the slot without blocking other key-manager users.
        let envelope_bytes = self
            .transport
            .fetch_my_key_delivery()
            .await?
            .ok_or_else(|| {
                SdkError::ValidationError(
                    "no GK delivery slot available for current user".to_string(),
                )
            })?;
        let envelope: GkDeliveryEnvelope = serde_json::from_slice(&envelope_bytes)?;

        // Re-acquire and re-check in case another caller already recovered.
        let mut km = self.key_manager.lock().await;
        match km
            .sync_group_key(&builder)
            .await
            .map_err(|_| SdkError::ValidationError("group key sync failed".to_string()))?
        {
            GroupKeySync::AlreadyCurrent | GroupKeySync::DerivedForward => Ok(()),
            GroupKeySync::NeedsDelivery => km
                .recover_group_key_from_delivery(&envelope, &builder)
                .await
                .map_err(|_| {
                    SdkError::ValidationError("delivery-slot recovery failed".to_string())
                }),
        }
    }

    /// Run delivery-slot-driven group key recovery iff the caller's detection
    /// indicated it is needed. When not needed, this is a no-op and saves
    /// a round-trip to the server for the slot fetch.
    pub(crate) async fn post_apply_delivery_slot_recovery(
        &self,
        needs_slot_check: bool,
    ) -> Result<()> {
        if needs_slot_check {
            self.sync_via_delivery_slot().await
        } else {
            Ok(())
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "local-transport"))]
mod tests {
    use super::*;
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, Schema};
    use crate::Space;
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Message {
        id: Option<i64>,
        body: String,
    }

    fn messages_schema() -> Schema {
        Schema {
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
                    plaintext: false,
                    indexed: false,
                },
            ],
            auto_increment: true,
        }
    }

    fn schema() -> ApplicationSchema {
        ApplicationSchema::for_testing(vec![], crate::testing::initial_internal_data_commitment())
    }

    async fn create_space() -> Result<Space> {
        let (_transport, space) = create_space_with_transport().await?;
        Ok(space)
    }

    async fn create_space_with_transport() -> Result<(LocalTransport, Space)> {
        let transport = LocalTransport::in_memory().await?;
        let space = Space::create(transport.clone(), schema()).await?;
        space.create_table(&messages_schema()).await?;
        Ok((transport, space))
    }

    async fn join_space(
        transport: LocalTransport,
        invite: crate::users::SpaceInvite,
    ) -> Result<Space> {
        let space = Space::join(transport, invite, schema()).await?;
        // The messages table was created before the invitee joined; register
        // its schema locally so the joined space can access the table.
        space.register_table_schema(messages_schema());
        Ok(space)
    }

    async fn insert_message(space: &Space, body: &str) -> Result<i64> {
        let messages = space.table::<Message>("messages");
        let id = messages
            .insert(&Message {
                id: None,
                body: body.to_string(),
            })
            .execute()
            .await?;
        Ok(id)
    }

    async fn read_messages(space: &Space) -> Result<Vec<Message>> {
        space.table::<Message>("messages").select().all().await
    }

    #[tokio::test]
    async fn extend_succeeds_and_data_survives() -> Result<()> {
        let space = create_space().await?;

        insert_message(&space, "before extend").await?;
        space.extend().await?;
        insert_message(&space, "after extend").await?;

        let msgs = read_messages(&space).await?;
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].body, "before extend");
        assert_eq!(msgs[1].body, "after extend");
        Ok(())
    }

    #[tokio::test]
    async fn multiple_extends() -> Result<()> {
        let space = create_space().await?;

        insert_message(&space, "msg 1").await?;
        space.extend().await?;

        insert_message(&space, "msg 2").await?;
        space.extend().await?;

        insert_message(&space, "msg 3").await?;
        space.extend().await?;

        let msgs = read_messages(&space).await?;
        assert_eq!(msgs.len(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn extend_then_reduce_makes_old_data_unreadable() -> Result<()> {
        let space = create_space().await?;

        // Write data at key 0 (initial key)
        insert_message(&space, "old secret").await?;

        // Verify it's readable before reduce
        let msgs = read_messages(&space).await?;
        assert_eq!(msgs.len(), 1);

        // Extend a few times to build up keys
        space.extend().await?;
        space.extend().await?;

        // Reduce: prune key 0
        space.reduce(SimpleKeyId(1)).await?;

        // Reading should fail — the row encrypted with key 0 can't be decrypted
        let msgs = read_messages(&space).await?;
        assert_eq!(msgs.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn reduce_allows_new_writes() -> Result<()> {
        let space = create_space().await?;

        space.extend().await?;
        space.extend().await?;

        // Reduce prunes key 0 (no data was written with it)
        space.reduce(SimpleKeyId(1)).await?;

        // New writes after reduce should work
        insert_message(&space, "post-reduce").await?;
        let msgs = read_messages(&space).await?;
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "post-reduce");

        Ok(())
    }

    #[tokio::test]
    async fn rekey_succeeds_and_data_survives() -> Result<()> {
        let space = create_space().await?;

        insert_message(&space, "before rekey").await?;
        space.rekey().await?;
        insert_message(&space, "after rekey").await?;

        let msgs = read_messages(&space).await?;
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].body, "before rekey");
        assert_eq!(msgs[1].body, "after rekey");
        Ok(())
    }

    #[tokio::test]
    async fn rekey_then_extend_then_reduce() -> Result<()> {
        let space = create_space().await?;

        insert_message(&space, "before rekey").await?;

        space.rekey().await?;

        insert_message(&space, "before reduce").await?;

        // Extend to build up keys after rekey
        space.extend().await?;
        space.extend().await?;
        space.extend().await?;

        // Reduce: prune old keys
        space.reduce(SimpleKeyId(2)).await?;

        // New data after reduce works
        insert_message(&space, "after reduce").await?;

        let msgs = read_messages(&space).await?;
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "after reduce");
        Ok(())
    }

    #[tokio::test]
    async fn extend_rekey_extend_cycle() -> Result<()> {
        let space = create_space().await?;

        // Write some data, extend, write more
        insert_message(&space, "a").await?;
        space.extend().await?;
        insert_message(&space, "b").await?;

        // Rekey in the middle
        space.rekey().await?;
        insert_message(&space, "c").await?;

        // Extend more after rekey
        space.extend().await?;
        insert_message(&space, "d").await?;
        space.extend().await?;
        insert_message(&space, "e").await?;

        let msgs = read_messages(&space).await?;
        assert_eq!(msgs.len(), 5);
        let bodies: Vec<&str> = msgs.iter().map(|m| m.body.as_str()).collect();
        assert_eq!(bodies, vec!["a", "b", "c", "d", "e"]);
        Ok(())
    }

    #[tokio::test]
    async fn rekey_with_multiple_members_all_read_and_write() -> Result<()> {
        let (transport, alice) = create_space_with_transport().await?;

        // Alice invites Bob and Carol; both join.
        // Alice must sync after each join to pick up the invitee's
        // post-bootstrap RefreshKeys before issuing the next invite.
        let bob_invite = alice.invite_user().await?;
        let bob = join_space(transport.clone(), bob_invite).await?;
        alice.sync().await?;
        let carol_invite = alice.invite_user().await?;
        let carol = join_space(transport.clone(), carol_invite).await?;
        alice.sync().await?;

        // Pre-rekey data written by Alice, readable by all members.
        insert_message(&alice, "pre-rekey").await?;
        bob.sync().await?;
        carol.sync().await?;
        assert_eq!(read_messages(&bob).await?.len(), 1);
        assert_eq!(read_messages(&carol).await?.len(), 1);

        // Alice rotates the group key; Bob and Carol pick up the new key via
        // their delivery slots on sync.
        alice.rekey().await?;
        insert_message(&alice, "post-rekey-alice").await?;

        bob.sync().await?;
        insert_message(&bob, "post-rekey-bob").await?;

        carol.sync().await?;
        alice.sync().await?;
        bob.sync().await?;

        for space in [&alice, &bob, &carol] {
            let bodies: Vec<String> = read_messages(space)
                .await?
                .into_iter()
                .map(|m| m.body)
                .collect();
            assert_eq!(
                bodies,
                vec!["pre-rekey", "post-rekey-alice", "post-rekey-bob"]
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn extend_and_reduce_with_multiple_members() -> Result<()> {
        let (transport, alice) = create_space_with_transport().await?;

        // Alice must sync after each join to pick up the invitee's
        // post-bootstrap RefreshKeys before issuing the next invite.
        let bob_invite = alice.invite_user().await?;
        let bob = join_space(transport.clone(), bob_invite).await?;
        alice.sync().await?;
        let carol_invite = alice.invite_user().await?;
        let carol = join_space(transport.clone(), carol_invite).await?;
        alice.sync().await?;

        // Build up a few keys with writes between each extend.
        insert_message(&alice, "at key 0").await?;
        alice.extend().await?;
        insert_message(&alice, "at key 1").await?;
        alice.extend().await?;
        insert_message(&alice, "at key 2").await?;

        // Prune key 0 — rows encrypted at key 0 become unreadable for everyone.
        alice.reduce(SimpleKeyId(1)).await?;

        // A post-reduce write must still be readable by the whole group.
        insert_message(&alice, "post-reduce").await?;

        bob.sync().await?;
        carol.sync().await?;

        for space in [&alice, &bob, &carol] {
            let bodies: Vec<String> = read_messages(space)
                .await?
                .into_iter()
                .map(|m| m.body)
                .collect();
            assert_eq!(bodies, vec!["at key 1", "at key 2", "post-reduce"]);
        }
        Ok(())
    }
}
