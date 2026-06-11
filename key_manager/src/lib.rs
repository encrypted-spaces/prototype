pub mod error;
pub mod no_retention;
pub mod operation;
pub mod traits;
pub mod types;

// Re-exports for convenience.
pub use error::KeyManagerError;
pub use no_retention::{NoRetentionSpaceKey, SimpleKeyId};
pub use operation::{
    CollectingOperationBuilder, MemoryOperationBuilder, OperationBuilder, OperationOutput,
    OperationReader, PendingWritesView,
};
pub use traits::{GroupKeySync, KeyId, SpaceKey};
pub use types::*;

use encrypted_spaces_changelog_core::changelog::OpType;
use encrypted_spaces_crypto::key_derivation::DerivationKoalaBearPoseidon2_16;
use encrypted_spaces_crypto::pke::{KemKeyPair, Mkem};
use encrypted_spaces_crypto::signature::SignatureKeyPair;
use encrypted_spaces_crypto::{KeyCommitment, KeyDerivation, KeyMaterial};
use encrypted_spaces_zkp::mve::{MveCiphertext, MveRecipientCiphertext, PoseidonMve};
use serde::{Deserialize, Serialize};

/// The default public-key encryption scheme used.
pub use encrypted_spaces_crypto::pke::DefaultMkem;
/// The default signature scheme used.
pub type DefaultSignature = encrypted_spaces_crypto::signature::Ed25519Signature;

/// Session identifier for the mVE Fiat-Shamir transformation during rekeys.
pub const REKEY_SESSION_ID: &str = "key-manager-rekey-v1";

/// Session identifier for the mVE Fiat-Shamir transformation during invites.
pub const INVITE_SESSION_ID: &str = "key-manager-invite-v1";

// =========================================================================
// KeyManager
// =========================================================================

/// Client-side key manager.
///
/// Serializable and persisted by the SDK. Generic over the [`SpaceKey`]
/// implementation; defaults to [`NoRetentionSpaceKey`].
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct KeyManager<G: SpaceKey = NoRetentionSpaceKey> {
    /// Space key (retention-system-managed).
    pub(crate) space_key: G,
    /// User's KEM keypair (for MVE decryption).
    update_key_pair: KemKeyPair<DefaultMkem>,
    /// User's signing keypair (for auth).
    auth_key_pair: SignatureKeyPair<DefaultSignature>,
}

impl<G: SpaceKey> KeyManager<G> {
    /// Create a new key manager with the given keypairs.
    pub fn new(
        update_key_pair: KemKeyPair<DefaultMkem>,
        auth_key_pair: SignatureKeyPair<DefaultSignature>,
        space_key: G,
    ) -> Self {
        Self {
            space_key,
            update_key_pair,
            auth_key_pair,
        }
    }

    /// Build a [`KeyManager`] by decrypting a GK delivery envelope.
    ///
    /// Decrypts the delivered group key via mVE using `update_key_pair`,
    /// verifies `commit(group_key) == envelope.binding_commitment`, and
    /// installs `G::from_group_key(group_key)` as the local space key.
    /// Public retention state must be fetched separately from canonical
    /// server state; no serialized `SpaceKey` is decrypted here.
    pub fn from_delivery_envelope(
        update_key_pair: KemKeyPair<DefaultMkem>,
        auth_key_pair: SignatureKeyPair<DefaultSignature>,
        envelope: &GkDeliveryEnvelope,
    ) -> Result<Self, KeyManagerError> {
        let root_key = PoseidonMve::<DefaultMkem>::decrypt(
            update_key_pair.secret(),
            &envelope.ciphertext,
            envelope.binding_commitment,
        )
        .map_err(|_| KeyManagerError)?;

        let derivation = DerivationKoalaBearPoseidon2_16::default();
        if derivation.commit(&root_key) != envelope.binding_commitment {
            return Err(KeyManagerError);
        }

        Ok(Self {
            space_key: G::from_group_key(root_key),
            update_key_pair,
            auth_key_pair,
        })
    }

    /// Generate a rekey request (for removing users).
    ///
    /// Generates a fresh group key, MVE-wraps it for the remaining members
    /// (including sender), and returns the request. The local commit happens
    /// when the sender processes their own delivered envelope, either directly
    /// through [`Self::apply_delivered_group_key`] or through a
    /// delivery-slot recovery helper.
    pub async fn rekey(
        &self,
        remaining_members_pks: &[<DefaultMkem as Mkem>::PublicKey],
        builder: &mut dyn OperationBuilder,
    ) -> Result<RekeyRequest, KeyManagerError> {
        let (new_root_commitment, new_root_key) =
            self.space_key.generate_group_key(builder).await?;

        let proof = PoseidonMve::<DefaultMkem>::prove(
            remaining_members_pks,
            &new_root_commitment,
            &new_root_key,
            REKEY_SESSION_ID,
        );

        Ok(RekeyRequest {
            new_root_commitment,
            proof,
        })
    }

    /// Decrypt an mVE-wrapped group-key envelope and verify its commitment.
    ///
    /// Returns the decapsulated group key. This is the primitive shared by
    /// direct delivered-envelope application ([`Self::apply_delivered_group_key`])
    /// and the delivery-slot recovery path
    /// ([`Self::recover_group_key_from_delivery`]): both wrap the same mVE
    /// ciphertext + binding commitment shape, so the decrypt primitive is
    /// operation-agnostic.
    fn decrypt_group_key_envelope(
        &self,
        ciphertext: &MveRecipientCiphertext<DefaultMkem, KeyMaterial>,
        binding_commitment: KeyCommitment,
    ) -> Result<KeyMaterial, KeyManagerError> {
        let root_key = PoseidonMve::<DefaultMkem>::decrypt(
            self.update_key_pair.secret(),
            ciphertext,
            binding_commitment,
        )
        .map_err(|_| KeyManagerError)?;

        let derivation = DerivationKoalaBearPoseidon2_16::default();
        if derivation.commit(&root_key) != binding_commitment {
            return Err(KeyManagerError);
        }

        Ok(root_key)
    }

    /// Apply a delivered group-key envelope to the local space key.
    ///
    /// Decrypts the mVE-wrapped group key with `update_key_pair`, verifies
    /// `commit(group_key) == new_root_commitment`, and integrates it into
    /// the space key. The new key id is assigned by the space-key impl
    /// internally.
    ///
    /// This is the generic "apply a delivered group key" primitive — it has
    /// no coupling to any particular delivery channel. The delivery-slot
    /// recovery path ([`Self::recover_group_key_from_delivery`]) calls
    /// [`Self::decrypt_group_key_envelope`] directly and hands the recovered
    /// key to [`SpaceKey::recover_group_key_from_candidate`] which
    /// reconciles it against the canonical retention snapshot. Both paths
    /// share the same mVE ciphertext + binding-commitment envelope shape.
    pub async fn apply_delivered_group_key(
        &mut self,
        ciphertext: &MveRecipientCiphertext<DefaultMkem, KeyMaterial>,
        new_root_commitment: KeyCommitment,
        reader: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        let root_key = self.decrypt_group_key_envelope(ciphertext, new_root_commitment)?;
        self.space_key
            .apply_new_group_key(root_key, new_root_commitment, reader)
            .await
    }

    /// Generate an invite request for a new member.
    ///
    /// MVE-wraps the current group key to the invited user's public key. The
    /// invited member reconstructs local state from the delivered group key
    /// (`SpaceKey::from_group_key`) plus canonical retention state fetched
    /// from the server; no serialized `SpaceKey` is shipped.
    pub async fn create_invite(
        &mut self,
        new_member_pk: &<DefaultMkem as Mkem>::PublicKey,
        builder: &mut dyn OperationBuilder,
    ) -> Result<InviteRequest, KeyManagerError> {
        let (root_commitment, root_key) = self.space_key.produce_group_key(builder).await?;

        let proof = PoseidonMve::<DefaultMkem>::prove(
            std::slice::from_ref(new_member_pk),
            &root_commitment,
            &root_key,
            INVITE_SESSION_ID,
        );

        Ok(InviteRequest {
            root_commitment,
            proof,
        })
    }

    /// Current key identifier.
    pub async fn current_key_id(
        &self,
        reader: &dyn OperationReader,
    ) -> Result<G::KeyId, KeyManagerError> {
        self.space_key.current_key_id(reader).await
    }

    /// Produce the current usable group key together with its commitment.
    pub async fn produce_group_key(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError> {
        self.space_key.produce_group_key(builder).await
    }

    /// Derive a data encryption key for the given key id.
    pub async fn data_key_for_key_id(
        &self,
        key_id: &G::KeyId,
        reader: &dyn OperationReader,
    ) -> Result<[u8; 32], KeyManagerError> {
        self.space_key.data_key_for_key_id(key_id, reader).await
    }

    /// Extend the active space key state.
    pub async fn extend(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<G::KeyId, KeyManagerError> {
        self.space_key.extend(builder).await
    }

    /// Prune old keys before a given key id.
    pub async fn reduce(
        &mut self,
        before: &G::KeyId,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(), KeyManagerError> {
        self.space_key.reduce(before, builder).await
    }

    /// Sync the local group key against the canonical retention snapshot.
    pub async fn sync_group_key(
        &mut self,
        reader: &dyn OperationReader,
    ) -> Result<GroupKeySync, KeyManagerError> {
        self.space_key.sync_group_key(reader).await
    }

    /// Decrypt a GK delivery envelope and install the recovered group key,
    /// deriving forward through any intermediate steps if needed.
    pub async fn recover_group_key_from_delivery(
        &mut self,
        envelope: &GkDeliveryEnvelope,
        reader: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        let candidate =
            self.decrypt_group_key_envelope(&envelope.ciphertext, envelope.binding_commitment)?;
        self.space_key
            .recover_group_key_from_candidate(candidate, reader)
            .await
    }

    /// Whether this op type may require delivery-slot recovery.
    pub fn op_may_need_delivery(op_type: OpType) -> bool {
        G::op_may_need_delivery(op_type)
    }

    /// Reference to the user's update (KEM) public key.
    pub fn update_key(&self) -> &<DefaultMkem as Mkem>::PublicKey {
        self.update_key_pair.public()
    }

    /// Shared access to the underlying [`SpaceKey`].
    pub fn space_key(&self) -> &G {
        &self.space_key
    }

    /// Mutable access to the underlying [`SpaceKey`]; see [`Self::space_key`].
    pub fn space_key_mut(&mut self) -> &mut G {
        &mut self.space_key
    }

    /// Reference to the user's auth (signing) keypair.
    pub fn auth_key_pair(&self) -> &SignatureKeyPair<DefaultSignature> {
        &self.auth_key_pair
    }

    /// Replace update keypair (for key rotation).
    pub fn set_update_key_pair(&mut self, update_key_pair: KemKeyPair<DefaultMkem>) {
        self.update_key_pair = update_key_pair;
    }

    /// Replace auth keypair (for key rotation).
    pub fn set_auth_key_pair(&mut self, auth_key_pair: SignatureKeyPair<DefaultSignature>) {
        self.auth_key_pair = auth_key_pair;
    }
}

// =========================================================================
// Verification (stateless, used by server)
// =========================================================================

/// Verify a rekey MVE proof and return the per-recipient ciphertexts.
///
/// Stateless -- does not require any server-side state. The server calls this
/// to verify the proof before distributing ciphertexts to remaining members.
pub fn verify_rekey(
    recipients: &[<DefaultMkem as Mkem>::PublicKey],
    request: &RekeyRequest,
) -> Result<MveCiphertext<DefaultMkem, KeyMaterial>, KeyManagerError> {
    PoseidonMve::<DefaultMkem>::verify(
        &request.proof,
        recipients,
        &request.new_root_commitment,
        REKEY_SESSION_ID,
    )
    .map_err(|_| KeyManagerError)
}

/// Verify an invite MVE proof and return the per-recipient ciphertexts.
///
/// Stateless -- does not require any server-side state.
pub fn verify_invite(
    new_member_pk: &<DefaultMkem as Mkem>::PublicKey,
    request: &InviteRequest,
) -> Result<MveCiphertext<DefaultMkem, KeyMaterial>, KeyManagerError> {
    PoseidonMve::<DefaultMkem>::verify(
        &request.proof,
        std::slice::from_ref(new_member_pk),
        &request.root_commitment,
        INVITE_SESSION_ID,
    )
    .map_err(|_| KeyManagerError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation::MemoryOperationBuilder;
    use encrypted_spaces_crypto::pke::KemKeyPair;

    #[tokio::test]
    async fn sender_rekey_then_apply_delivered_group_key_succeeds() {
        let mut rng = rand::rng();

        // Two members: us (the sender) and another member.
        let our_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
        let other_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
        let auth_kp = SignatureKeyPair::<DefaultSignature>::new();

        let mut builder = MemoryOperationBuilder::new();
        let space_key = NoRetentionSpaceKey::new(&mut builder).await;
        let mut km = KeyManager::new(our_kp, auth_kp, space_key);

        let id_before = km.current_key_id(&builder).await.unwrap();

        // Sender generates a rekey request (includes the other member's PK + our own).
        let remaining_pks = [km.update_key().clone(), other_kp.public().clone()];
        let rekey_request = km.rekey(&remaining_pks, &mut builder).await.unwrap();

        // Verify the rekey proof and get per-recipient ciphertexts.
        let ciphertexts = verify_rekey(&remaining_pks, &rekey_request).unwrap();

        // The sender processes their own delivered envelope (ciphertext at index 0).
        let our_ciphertext = ciphertexts.get(0).unwrap();
        km.apply_delivered_group_key(&our_ciphertext, rekey_request.new_root_commitment, &builder)
            .await
            .unwrap();

        let id_after = km.current_key_id(&builder).await.unwrap();
        assert_eq!(id_after.0, id_before.0 + 1);
    }

    #[tokio::test]
    async fn decrypt_group_key_envelope_returns_root_key_matching_commitment() {
        let mut rng = rand::rng();
        let our_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
        let auth_kp = SignatureKeyPair::<DefaultSignature>::new();

        let mut builder = MemoryOperationBuilder::new();
        let space_key = NoRetentionSpaceKey::new(&mut builder).await;
        let km = KeyManager::new(our_kp, auth_kp, space_key);

        let recipients = [km.update_key().clone()];
        let request = km.rekey(&recipients, &mut builder).await.unwrap();
        let ciphertexts = verify_rekey(&recipients, &request).unwrap();

        let ciphertext = ciphertexts.get(0).unwrap();
        let root_key = km
            .decrypt_group_key_envelope(&ciphertext, request.new_root_commitment)
            .unwrap();

        let derivation = DerivationKoalaBearPoseidon2_16::default();
        assert_eq!(derivation.commit(&root_key), request.new_root_commitment);
    }

    #[tokio::test]
    async fn decrypt_group_key_envelope_rejects_wrong_commitment() {
        let mut rng = rand::rng();
        let our_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
        let auth_kp = SignatureKeyPair::<DefaultSignature>::new();

        let mut builder = MemoryOperationBuilder::new();
        let space_key = NoRetentionSpaceKey::new(&mut builder).await;
        let km = KeyManager::new(our_kp, auth_kp, space_key);

        let recipients = [km.update_key().clone()];
        let request = km.rekey(&recipients, &mut builder).await.unwrap();
        let ciphertexts = verify_rekey(&recipients, &request).unwrap();

        let derivation = DerivationKoalaBearPoseidon2_16::default();
        let bogus_commitment = derivation.commit(&KeyMaterial::random_with(&mut rng));
        assert_ne!(bogus_commitment, request.new_root_commitment);

        let ciphertext = ciphertexts.get(0).unwrap();
        assert!(km
            .decrypt_group_key_envelope(&ciphertext, bogus_commitment)
            .is_err());
    }

    #[tokio::test]
    async fn extend_and_reduce_delegate_to_space_key_with_explicit_prover() {
        let mut rng = rand::rng();
        let our_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
        let auth_kp = SignatureKeyPair::<DefaultSignature>::new();

        let mut builder = MemoryOperationBuilder::new();
        let space_key = NoRetentionSpaceKey::new(&mut builder).await;
        let mut km = KeyManager::new(our_kp, auth_kp, space_key);

        let id_before = km.current_key_id(&builder).await.unwrap();
        let id_after = km.extend(&mut builder).await.unwrap();
        assert_eq!(id_after.0, id_before.0);

        km.reduce(&id_before, &mut builder).await.unwrap();
        let id_final = km.current_key_id(&builder).await.unwrap();
        assert_eq!(id_final.0, id_before.0);
    }
}
