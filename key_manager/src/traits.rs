use std::fmt::{Debug, Display};
use std::hash::Hash;

use encrypted_spaces_changelog_core::changelog::OpType;
use encrypted_spaces_crypto::{KeyCommitment, KeyMaterial};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::KeyManagerError;
use crate::operation::{OperationBuilder, OperationReader};

/// Result of syncing the local group key to the canonical retention state.
pub enum GroupKeySync {
    /// Local key matches canonical — no action needed.
    AlreadyCurrent,
    /// Local key was derived forward to match canonical — no action needed.
    DerivedForward,
    /// Cannot reach canonical via derivation — caller must fetch a
    /// delivery slot and call [`SpaceKey::recover_group_key_from_candidate`].
    NeedsDelivery,
}

/// Opaque identifier for a key within the group state.
/// Must be serializable and comparable.
///
/// Different retention backends can define their own key id types.
/// The stub implementation uses a simple sequence number.
pub trait KeyId:
    Clone + Debug + Display + PartialEq + Eq + Hash + Serialize + DeserializeOwned + Send + Sync
{
}

/// The space's key state. Opaque to the key manager -- it just needs to
/// derive data keys and serialize for invites. Could represent a simple progression
/// of root keys (e.g. [`NoRetentionSpaceKey`]) or more complex retention systems (e.g. SimpleLine2).
#[async_trait::async_trait]
pub trait SpaceKey: Clone + Serialize + DeserializeOwned + Send + Sync {
    type KeyId: KeyId;

    /// Build a local space-key state from a delivered group key.
    ///
    /// Used during invite/bootstrap: the invited member receives the current
    /// group key via mVE and installs it with this constructor. The new state
    /// must **not** write any canonical retention rows — public state is
    /// fetched from the server's retention tables after bootstrap.
    fn from_group_key(group_key: KeyMaterial) -> Self;

    /// Current key identifier.
    async fn current_key_id(
        &self,
        reader: &dyn OperationReader,
    ) -> Result<Self::KeyId, KeyManagerError>;

    /// Derive a data encryption key for the given key id.
    async fn data_key_for_key_id(
        &self,
        key_id: &Self::KeyId,
        reader: &dyn OperationReader,
    ) -> Result<[u8; 32], KeyManagerError>;

    /// Produce the current usable group key (for MVE encryption during
    /// invite/rekey), together with its commitment. May mutate self for
    /// caching, may write derived material to the builder.
    async fn produce_group_key(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError>;

    /// Generate a fresh group key, write its commitments and retention state
    /// to the builder. Returns (commitment, key_material) for MVE distribution.
    /// The caller must later call `apply_new_group_key` to activate locally.
    async fn generate_group_key(
        &self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError>;

    /// Activate a group key locally. Called by both the generator and receivers.
    /// May read from the builder to verify commitments, but must not write.
    async fn apply_new_group_key(
        &mut self,
        new_group_key: KeyMaterial,
        commitment: KeyCommitment,
        reader: &dyn OperationReader,
    ) -> Result<(), KeyManagerError>;

    /// Extend -- advance the data key forward (e.g. ratchet to a new data key
    /// within the current epoch). Returns the new key id.
    async fn extend(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<Self::KeyId, KeyManagerError>;

    /// Reduce -- prune old keys before a given key id (retention/cleanup).
    async fn reduce(
        &mut self,
        before: &Self::KeyId,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(), KeyManagerError>;

    /// Sync the local group key against the canonical retention snapshot.
    ///
    /// Returns [`GroupKeySync::AlreadyCurrent`] or [`GroupKeySync::DerivedForward`]
    /// when the local key can be reconciled without external help, or
    /// [`GroupKeySync::NeedsDelivery`] when the caller must fetch a delivery
    /// slot and call [`Self::recover_group_key_from_candidate`].
    async fn sync_group_key(
        &mut self,
        reader: &dyn OperationReader,
    ) -> Result<GroupKeySync, KeyManagerError>;

    /// Install a recovered group key candidate (from a decrypted delivery
    /// envelope), deriving forward through any intermediate steps if needed.
    async fn recover_group_key_from_candidate(
        &mut self,
        candidate: KeyMaterial,
        reader: &dyn OperationReader,
    ) -> Result<(), KeyManagerError>;

    /// Whether this op type may require delivery-slot recovery even when
    /// individual retention keys are not visible (broadcast/FF paths).
    /// This is the canonical list of ops that need optimistic slot checks.
    fn op_may_need_delivery(op_type: OpType) -> bool;

    /// Verify retention proofs for a given operation type.
    ///
    /// Stateless: checks the expected number of proofs for the op and verifies
    /// each against the relevant retention state. Callers pass the pre-op
    /// state view plus the operation's retention payload; implementations
    /// treat `pre_state` as read-only.
    ///
    /// Returns `Ok(())` if all proofs are valid, or an error if any fail.
    async fn verify_retention_proofs(
        op_type: OpType,
        proofs: &[Vec<u8>],
        pre_state: &dyn OperationReader,
        pending_writes: &dyn OperationReader,
    ) -> Result<(), KeyManagerError>;

    /// Return the canonical current group-key commitment from the retention
    /// state snapshot in `reader`. Used by the server to verify that an
    /// invite's claimed commitment matches the group's current canonical key
    /// before delivering it to a new member.
    async fn canonical_group_key_commitment(
        reader: &dyn OperationReader,
    ) -> Result<KeyCommitment, KeyManagerError>;
}
