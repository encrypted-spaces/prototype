use std::collections::HashMap;

use encrypted_spaces_crypto::encryption::{decrypt_field, encrypt_field, EncryptionKey};
use encrypted_spaces_crypto::key_derivation::DerivationKoalaBearPoseidon2_16;
use encrypted_spaces_crypto::{KeyCommitment, KeyDerivation, KeyMaterial};
use serde::{Deserialize, Serialize};

use encrypted_spaces_changelog_core::changelog::OpType;

use crate::error::KeyManagerError;
use crate::operation::{OperationBuilder, OperationReader};
use crate::traits::{GroupKeySync, KeyId, SpaceKey};

/// Simple sequence-number key id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct SimpleKeyId(pub u64);

impl KeyId for SimpleKeyId {}

impl std::fmt::Display for SimpleKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// No-retention space key: simple key progression without forward-secure
/// key erasure.
///
/// Each historic key is stored encrypted under the next key in the chain
/// (`ekey/{N}` encrypted under key N+1). The current root key is never
/// stored — it's delivered via the invite/rekey delivery slot. To resolve
/// an old key, walk backwards from the root: decrypt N-1 from N, N-2 from
/// N-1, etc.
///
/// No retention proofs are generated. This is the simple baseline for
/// spaces that don't need key erasure guarantees.
#[derive(Clone, Serialize, Deserialize)]
pub struct NoRetentionSpaceKey {
    root_key: KeyMaterial,
    /// Local cache of resolved keys. Populated lazily from chain storage.
    #[serde(default)]
    keys: HashMap<SimpleKeyId, KeyMaterial>,
}

impl NoRetentionSpaceKey {
    /// Create initial space key with a random root key at key id 0.
    /// Writes the initial commitment and current id to the builder.
    pub async fn new(builder: &mut dyn OperationBuilder) -> Self {
        let root_key = KeyMaterial::random_with(&mut rand::rng());

        let derivation = DerivationKoalaBearPoseidon2_16::default();
        let commitment = derivation.commit(&root_key);
        builder
            .put(
                &commitment_key(&SimpleKeyId(0)),
                commitment.as_bytes().to_vec(),
            )
            .await;
        save_current_id(0, builder).await;

        let mut keys = HashMap::new();
        keys.insert(SimpleKeyId(0), root_key.clone());

        Self { root_key, keys }
    }
}

#[async_trait::async_trait]
impl SpaceKey for NoRetentionSpaceKey {
    type KeyId = SimpleKeyId;

    fn from_group_key(group_key: KeyMaterial) -> Self {
        Self {
            root_key: group_key,
            keys: HashMap::new(),
        }
    }

    async fn current_key_id(
        &self,
        builder: &dyn OperationReader,
    ) -> Result<SimpleKeyId, KeyManagerError> {
        Ok(SimpleKeyId(current_id(builder).await?))
    }

    async fn data_key_for_key_id(
        &self,
        key_id: &SimpleKeyId,
        builder: &dyn OperationReader,
    ) -> Result<[u8; 32], KeyManagerError> {
        let root_id = current_id(builder).await?;
        let key = if let Some(k) = self.keys.get(key_id) {
            k.clone()
        } else {
            resolve_key_from_chain(&self.root_key, root_id, key_id.0, builder).await?
        };

        let info = format!(
            "encrypted_spaces/key_manager/simple/data_key/v1/id:{}",
            key_id.0
        );
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, key.as_bytes());
        let mut okm = [0u8; 32];
        hkdf.expand(info.as_bytes(), &mut okm)
            .map_err(|_| KeyManagerError)?;
        Ok(okm)
    }

    async fn produce_group_key(
        &mut self,
        _builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError> {
        let derivation = DerivationKoalaBearPoseidon2_16::default();
        let commitment = derivation.commit(&self.root_key);
        Ok((commitment, self.root_key.clone()))
    }

    async fn generate_group_key(
        &self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError> {
        let cur = current_id(builder).await?;
        let new_key = KeyMaterial::random_with(&mut rand::rng());
        let new_id = cur + 1;

        let derivation = DerivationKoalaBearPoseidon2_16::default();
        let commitment = derivation.commit(&new_key);
        builder
            .put(
                &commitment_key(&SimpleKeyId(new_id)),
                commitment.as_bytes().to_vec(),
            )
            .await;

        // Encrypt the current root under the new key and store it.
        save_encrypted_key(cur, &self.root_key, &new_key, builder).await;
        save_current_id(new_id, builder).await;

        Ok((commitment, new_key))
    }

    async fn apply_new_group_key(
        &mut self,
        new_group_key: KeyMaterial,
        commitment: KeyCommitment,
        builder: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        let new_id = current_id(builder).await?;

        // Verify the commitment matches.
        let stored = builder
            .get(&commitment_key(&SimpleKeyId(new_id)))
            .await?
            .ok_or(KeyManagerError)?;
        if stored != commitment.as_bytes() {
            return Err(KeyManagerError);
        }

        self.keys.insert(SimpleKeyId(new_id), new_group_key.clone());
        self.root_key = new_group_key;
        Ok(())
    }

    async fn extend(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<SimpleKeyId, KeyManagerError> {
        Ok(SimpleKeyId(current_id(builder).await?))
    }

    async fn reduce(
        &mut self,
        before: &SimpleKeyId,
        _builder: &mut dyn OperationBuilder,
    ) -> Result<(), KeyManagerError> {
        self.keys.retain(|id, _| id.0 >= before.0);
        Ok(())
    }

    async fn sync_group_key(
        &mut self,
        builder: &dyn OperationReader,
    ) -> Result<GroupKeySync, KeyManagerError> {
        let derivation = DerivationKoalaBearPoseidon2_16::default();
        let canonical = current_id(builder).await?;
        let stored = builder
            .get(&commitment_key(&SimpleKeyId(canonical)))
            .await?;
        match stored {
            None => Ok(GroupKeySync::AlreadyCurrent),
            Some(bytes) => {
                let local_commitment = derivation.commit(&self.root_key);
                if bytes == local_commitment.as_bytes() {
                    Ok(GroupKeySync::AlreadyCurrent)
                } else {
                    Ok(GroupKeySync::NeedsDelivery)
                }
            }
        }
    }

    async fn recover_group_key_from_candidate(
        &mut self,
        candidate: KeyMaterial,
        builder: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        let root_id = current_id(builder).await?;
        self.root_key = candidate.clone();
        self.keys.clear();
        self.keys.insert(SimpleKeyId(root_id), candidate);
        // Walk the chain backwards and populate all historic keys.
        for target in (0..root_id).rev() {
            let key = resolve_key_from_chain(&self.root_key, root_id, target, builder).await?;
            self.keys.insert(SimpleKeyId(target), key);
        }
        Ok(())
    }

    fn op_may_need_delivery(op_type: OpType) -> bool {
        matches!(op_type, OpType::RemoveUser)
    }

    async fn verify_retention_proofs(
        _op_type: OpType,
        proofs: &[Vec<u8>],
        _pre_state: &dyn OperationReader,
        _pending_writes: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        if !proofs.is_empty() {
            return Err(KeyManagerError);
        }
        Ok(())
    }

    async fn canonical_group_key_commitment(
        reader: &dyn OperationReader,
    ) -> Result<KeyCommitment, KeyManagerError> {
        let canonical = current_id(reader).await?;
        let stored = reader
            .get(&commitment_key(&SimpleKeyId(canonical)))
            .await?
            .ok_or(KeyManagerError)?;
        KeyCommitment::from_bytes(&stored).ok_or(KeyManagerError)
    }
}

/// Build the storage key for a commitment at a given key index.
fn commitment_key(key_id: &SimpleKeyId) -> String {
    format!("noretention/commitment/{}", key_id.0)
}

/// Storage key for the current key id counter.
const CURRENT_ID_KEY: &str = "noretention/current_id";

/// Dummy key ID for the chain encryption (not a real column key).
const CHAIN_KEY_ID: u8 = 0;

/// Storage key for a single encrypted historic key.
/// Key N is encrypted under key N+1.
fn encrypted_key_storage_key(id: u64) -> String {
    format!("noretention/ekey/{id}")
}

/// Derive a 32-byte AES key from a KeyMaterial for encrypting the previous key.
fn chain_encryption_key(parent_key: &KeyMaterial) -> EncryptionKey {
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, parent_key.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(b"noretention/chain_key/v1", &mut okm)
        .expect("32-byte output");
    EncryptionKey::new(okm, &CHAIN_KEY_ID)
}

/// Encrypt `child_key` under `parent_key` and store it.
async fn save_encrypted_key(
    child_id: u64,
    child_key: &KeyMaterial,
    parent_key: &KeyMaterial,
    builder: &mut dyn OperationBuilder,
) {
    let enc_key = chain_encryption_key(parent_key);
    let encrypted = encrypt_field(child_key.as_bytes(), &enc_key);
    builder
        .put(&encrypted_key_storage_key(child_id), encrypted)
        .await;
}

/// Load and decrypt a single historic key from the builder.
fn decrypt_stored_key(
    data: &[u8],
    parent_key: &KeyMaterial,
) -> Result<KeyMaterial, KeyManagerError> {
    let enc_key = chain_encryption_key(parent_key);
    let plaintext = decrypt_field(data, &enc_key).map_err(|_| KeyManagerError)?;
    KeyMaterial::from_bytes(&plaintext).ok_or(KeyManagerError)
}

/// Walk the chain backwards from `root_key` (at `root_id`) to resolve
/// the key at `target_id`. Each step decrypts `ekey/{id}` using the key
/// at `id+1`.
async fn resolve_key_from_chain(
    root_key: &KeyMaterial,
    root_id: u64,
    target_id: u64,
    builder: &dyn OperationReader,
) -> Result<KeyMaterial, KeyManagerError> {
    if target_id > root_id {
        return Err(KeyManagerError);
    }
    if target_id == root_id {
        return Ok(root_key.clone());
    }
    let mut current_key = root_key.clone();
    let mut current_id = root_id;
    while current_id > target_id {
        let child_id = current_id - 1;
        let data = builder
            .get(&encrypted_key_storage_key(child_id))
            .await?
            .ok_or(KeyManagerError)?;
        current_key = decrypt_stored_key(&data, &current_key)?;
        current_id = child_id;
    }
    Ok(current_key)
}

/// Save the current key id counter to the builder.
async fn save_current_id(id: u64, builder: &mut dyn OperationBuilder) {
    builder.put(CURRENT_ID_KEY, id.to_le_bytes().to_vec()).await;
}

/// Load the current key id counter from the builder.
async fn load_current_id(builder: &dyn OperationReader) -> Result<Option<u64>, KeyManagerError> {
    match builder.get(CURRENT_ID_KEY).await? {
        Some(data) if data.len() == 8 => Ok(Some(u64::from_le_bytes(data.try_into().unwrap()))),
        Some(_) => Err(KeyManagerError),
        None => Ok(None),
    }
}

/// Load the current key id, returning 0 if not yet stored.
async fn current_id(builder: &dyn OperationReader) -> Result<u64, KeyManagerError> {
    Ok(load_current_id(builder).await?.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation::MemoryOperationBuilder;

    #[tokio::test]
    async fn new_writes_initial_commitment() {
        let mut builder = MemoryOperationBuilder::new();
        let mut sk = NoRetentionSpaceKey::new(&mut builder).await;

        let key_id = sk.current_key_id(&builder).await.unwrap();
        let key = commitment_key(&key_id);
        let stored = builder
            .get(&key)
            .await
            .unwrap()
            .expect("commitment should be written");
        let (commitment, _) = sk.produce_group_key(&mut builder).await.unwrap();
        assert_eq!(stored, commitment.as_bytes());
    }

    #[tokio::test]
    async fn generate_group_key_writes_commitment() {
        let mut builder = MemoryOperationBuilder::new();
        let sk = NoRetentionSpaceKey::new(&mut builder).await;

        let (commitment, _key) = sk.generate_group_key(&mut builder).await.unwrap();

        // generate advances current_id, so the commitment is at the new id.
        let new_id = sk.current_key_id(&builder).await.unwrap();
        let stored = builder
            .get(&commitment_key(&new_id))
            .await
            .unwrap()
            .expect("commitment should be written");
        assert_eq!(stored, commitment.as_bytes());
    }

    #[tokio::test]
    async fn apply_new_group_key_advances_id() {
        let mut builder = MemoryOperationBuilder::new();
        let mut sk = NoRetentionSpaceKey::new(&mut builder).await;

        let (commitment, new_key) = sk.generate_group_key(&mut builder).await.unwrap();
        let id_after_gen = sk.current_key_id(&builder).await.unwrap();
        assert_eq!(id_after_gen.0, 1);

        sk.apply_new_group_key(new_key, commitment, &builder)
            .await
            .unwrap();

        let id_after = sk.current_key_id(&builder).await.unwrap();
        assert_eq!(id_after.0, 1);
    }

    #[tokio::test]
    async fn produce_group_key_returns_current_key() {
        let mut builder = MemoryOperationBuilder::new();
        let mut sk = NoRetentionSpaceKey::new(&mut builder).await;

        let (c1, k1) = sk.produce_group_key(&mut builder).await.unwrap();
        let (c2, k2) = sk.produce_group_key(&mut builder).await.unwrap();
        assert_eq!(k1, k2);
        assert_eq!(c1, c2);
    }

    #[tokio::test]
    async fn data_key_derivation_is_deterministic() {
        let mut builder = MemoryOperationBuilder::new();
        let sk = NoRetentionSpaceKey::new(&mut builder).await;
        let key_id = sk.current_key_id(&builder).await.unwrap();

        let dk1 = sk.data_key_for_key_id(&key_id, &builder).await.unwrap();
        let dk2 = sk.data_key_for_key_id(&key_id, &builder).await.unwrap();
        assert_eq!(dk1, dk2);
    }

    #[tokio::test]
    async fn generate_and_apply_produces_different_data_keys() {
        let mut builder = MemoryOperationBuilder::new();
        let mut sk = NoRetentionSpaceKey::new(&mut builder).await;

        let id_before = sk.current_key_id(&builder).await.unwrap();
        let dk_before = sk.data_key_for_key_id(&id_before, &builder).await.unwrap();

        let (commitment, new_key) = sk.generate_group_key(&mut builder).await.unwrap();
        sk.apply_new_group_key(new_key, commitment, &builder)
            .await
            .unwrap();

        let id_after = sk.current_key_id(&builder).await.unwrap();
        let dk_after = sk.data_key_for_key_id(&id_after, &builder).await.unwrap();
        assert_ne!(dk_before, dk_after);

        // Old key should still be derivable.
        assert_eq!(
            sk.data_key_for_key_id(&id_before, &builder).await.unwrap(),
            dk_before
        );
    }

    #[tokio::test]
    async fn sync_group_key_already_current() {
        let mut builder = MemoryOperationBuilder::new();
        let mut sk = NoRetentionSpaceKey::new(&mut builder).await;
        assert!(matches!(
            sk.sync_group_key(&builder).await.unwrap(),
            GroupKeySync::AlreadyCurrent
        ));
    }

    #[tokio::test]
    async fn op_may_need_delivery_for_remove_user() {
        assert!(NoRetentionSpaceKey::op_may_need_delivery(
            OpType::RemoveUser
        ));
        assert!(!NoRetentionSpaceKey::op_may_need_delivery(OpType::Insert));
        assert!(!NoRetentionSpaceKey::op_may_need_delivery(
            OpType::InviteUser
        ));
    }
}
