//! Namespaced key-value stores. See `docs/schema.md` for the user-facing
//! reference and [`Space::store`](crate::Space::store) for the entry point.
//!
//! A store is an open key-value collection: any member may read, write,
//! overwrite, or delete any key. Keys are opaque plaintext bytes; values
//! are opaque bytes, encrypted client-side unless the store was declared
//! `encrypted=#false`.

use std::sync::Arc;

use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_changelog_core::changelog::OpType;
use encrypted_spaces_changelog_core::ReadOp;
use encrypted_spaces_crypto::encryption::{
    ciphertext_key_id, decrypt_field, encrypt_field, EncryptionKey,
};
use encrypted_spaces_key_manager::SimpleKeyId;
use encrypted_spaces_storage_encoding::keys::{parse_key, store_entry_key, store_prefix, ParsedKey};

use crate::changelog::ChangeBuilder;
use crate::kv_cache::CacheResult;
use crate::Space;

/// Handle to a namespaced key-value store. Construct via [`Space::store`].
pub struct Store {
    space: Arc<Space>,
    name: String,
    encrypted: bool,
}

impl Store {
    pub(crate) fn new(space: Arc<Space>, name: String, encrypted: bool) -> Self {
        Self {
            space,
            name,
            encrypted,
        }
    }

    /// Insert or overwrite `key` with `value`.
    pub async fn put(&self, key: impl AsRef<[u8]>, value: Vec<u8>) -> Result<()> {
        let stored = if self.encrypted {
            let ek = crate::crypto::current_encryption_key(&self.space).await?;
            encrypt_field(&value, &ek)
        } else {
            value
        };
        let entry_key = store_entry_key(&self.name, key.as_ref());
        let change = ChangeBuilder::retention_only(Arc::clone(&self.space))
            .build_store_write(OpType::StorePut, vec![(entry_key, stored)])
            .await?;
        self.space.submit_and_complete(change).await?;
        Ok(())
    }

    /// Delete `key`. Deleting an absent key is accepted (idempotent).
    pub async fn delete(&self, key: impl AsRef<[u8]>) -> Result<()> {
        let entry_key = store_entry_key(&self.name, key.as_ref());
        let change = ChangeBuilder::retention_only(Arc::clone(&self.space))
            .build_store_write(OpType::StoreDelete, vec![(entry_key, Vec::new())])
            .await?;
        self.space.submit_and_complete(change).await?;
        Ok(())
    }

    /// Read `key`, returning `None` if it is absent. Served from the cache
    /// when possible; otherwise fetches and verifies a proof from the
    /// server, splices it into the cache, and re-reads.
    pub async fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        let key = key.as_ref();
        let raw = match self.cache_get(key) {
            CacheResult::Hit(value) => value,
            CacheResult::Miss => self.fetch_get(key).await?,
        };
        match raw {
            Some(bytes) => Ok(Some(self.decrypt(bytes).await?)),
            None => Ok(None),
        }
    }

    /// List every `(key, value)` whose key starts with `prefix`, in key
    /// order. An empty prefix returns the whole store. Values are decrypted.
    pub async fn list_prefix(
        &self,
        prefix: impl AsRef<[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let prefix = prefix.as_ref();
        let raw = match self.space.with_state(|s| s.kv_cache.store_scan(&self.name)) {
            CacheResult::Hit(pairs) => pairs,
            CacheResult::Miss => self.fetch_scan().await?,
        };
        let mut out = Vec::new();
        for (k, v) in raw {
            if k.starts_with(prefix) {
                out.push((k, self.decrypt(v).await?));
            }
        }
        Ok(out)
    }

    fn cache_get(&self, key: &[u8]) -> CacheResult<Option<Vec<u8>>> {
        self.space
            .with_state(|s| s.kv_cache.store_get(&self.name, key))
    }

    async fn fetch_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let commitment = self.space.current_data_commitment();
        let read_op = ReadOp::Key(store_entry_key(&self.name, key));
        let verified = self.space.transport.store_read(read_op, &commitment).await?;
        self.space
            .with_state_mut(|s| s.kv_cache.apply_select(commitment, &verified));
        match self.cache_get(key) {
            CacheResult::Hit(value) => Ok(value),
            // The proof authenticated presence/absence; a miss here means the
            // anchor advanced mid-fetch, so fall back to the verified pairs.
            CacheResult::Miss => Ok(verified
                .kv_pairs
                .into_iter()
                .next()
                .map(|(_, v)| v)),
        }
    }

    async fn fetch_scan(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let commitment = self.space.current_data_commitment();
        let read_op = ReadOp::Prefix(store_prefix(&self.name));
        let verified = self.space.transport.store_read(read_op, &commitment).await?;
        self.space
            .with_state_mut(|s| s.kv_cache.apply_select(commitment, &verified));
        match self.space.with_state(|s| s.kv_cache.store_scan(&self.name)) {
            CacheResult::Hit(pairs) => Ok(pairs),
            CacheResult::Miss => {
                // Anchor advanced mid-fetch; decode the freshly verified pairs.
                let mut out = Vec::new();
                for (k, v) in verified.kv_pairs {
                    if let Ok(ParsedKey::StoreEntry { key, .. }) = parse_key(&k) {
                        out.push((key, v));
                    }
                }
                Ok(out)
            }
        }
    }

    /// Decrypt a stored value. No-op for plaintext stores. Resolves the
    /// historical key by the `key_id` embedded in the ciphertext, so values
    /// written before a rekey still decrypt.
    async fn decrypt(&self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        if !self.encrypted {
            return Ok(bytes);
        }
        let key_id: SimpleKeyId = ciphertext_key_id(&bytes)
            .ok_or_else(|| SdkError::DecryptionError("store value missing key_id".into()))?;
        let builder = self.space.retention_builder();
        let km = self.space.key_manager.lock().await;
        let key = km
            .data_key_for_key_id(&key_id, &builder)
            .await
            .map(|kb| EncryptionKey::new(kb, &key_id))
            .map_err(|_| {
                SdkError::DecryptionError(format!("missing key for key_id {key_id:?}"))
            })?;
        decrypt_field(&bytes, &key).map_err(|e| SdkError::DecryptionError(e.to_string()))
    }
}
