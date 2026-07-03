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
use encrypted_spaces_changelog_core::{prefix_successor, ReadOp, StoreReadOp};
use encrypted_spaces_crypto::encryption::{
    ciphertext_key_id, decrypt_field, encrypt_field, EncryptionKey,
};
use encrypted_spaces_key_manager::SimpleKeyId;
use encrypted_spaces_storage_encoding::keys::{
    parse_key, store_entry_key, store_prefix, ParsedKey,
};

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

    /// Start a read. Returns a [`GetBuilder`] that defaults to the whole store
    /// in ascending key order; narrow it with `key`/`prefix`/`range`, order it
    /// with `ascending`/`descending`, bound it with `limit`, and run it with
    /// `all`/`first`/`last`.
    ///
    /// ```ignore
    /// let all   = store.get().all().await?;                 // whole store
    /// let one   = store.get().key("theme").first().await?;  // point read
    /// let ui    = store.get().prefix("ui/").all().await?;   // prefix scan
    /// let head  = store.get().range("a", "m").limit(10).all().await?;
    /// let newest = store.get().last().await?;               // largest key
    /// ```
    pub fn get(&self) -> GetBuilder<'_> {
        GetBuilder {
            store: self,
            op: ReadOp::Prefix(store_prefix(&self.name)),
            descending: false,
            limit: None,
        }
    }

    /// Fetch a store read from the server, verify its tracer proof, splice it
    /// into the cache, and return the authenticated `(entry_key, value)` pairs
    /// in `read`'s order, already truncated to `read.limit`.
    async fn fetch_read(&self, read: &StoreReadOp) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let commitment = self.space.current_data_commitment();
        let verified = self
            .space
            .transport
            .store_read(read.clone(), &commitment)
            .await?;
        self.space
            .with_state_mut(|s| s.kv_cache.apply_select(commitment, &verified));
        match self
            .space
            .with_state(|s| s.kv_cache.store_read(&read.op, read.descending, read.limit))
        {
            CacheResult::Hit(pairs) => Ok(pairs),
            CacheResult::Miss => {
                // Anchor advanced mid-fetch; the verified pairs are still
                // authoritative for this read. They arrive ascending.
                let mut pairs = verified.kv_pairs;
                if read.descending {
                    pairs.reverse();
                }
                if let Some(limit) = read.limit {
                    pairs.truncate(limit as usize);
                }
                Ok(pairs)
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
            .map_err(|_| SdkError::DecryptionError(format!("missing key for key_id {key_id:?}")))?;
        decrypt_field(&bytes, &key).map_err(|e| SdkError::DecryptionError(e.to_string()))
    }
}

/// A store read in progress. Build a selector + order + limit, then run it.
///
/// Selectors are mutually exclusive (the last one wins); the default is the
/// whole store. `limit` bounds the result to the first (ascending) or last
/// (descending) N keys, and — because the store proves reads with a tracer
/// proof — a limited read proves and transfers only the keys it returns.
pub struct GetBuilder<'a> {
    store: &'a Store,
    op: ReadOp,
    descending: bool,
    limit: Option<u32>,
}

impl GetBuilder<'_> {
    /// Read a single key.
    pub fn key(mut self, key: impl AsRef<[u8]>) -> Self {
        self.op = ReadOp::Key(store_entry_key(&self.store.name, key.as_ref()));
        self
    }

    /// Read every key beginning with `prefix`. An empty prefix is the whole store.
    pub fn prefix(mut self, prefix: impl AsRef<[u8]>) -> Self {
        let name = &self.store.name;
        let p = prefix.as_ref();
        self.op = if p.is_empty() {
            ReadOp::Prefix(store_prefix(name))
        } else {
            // Keys starting with `p` are the half-open user-key range
            // `[p, prefix_successor(p))`, mapped into entry-key space.
            let start = store_entry_key(name, p);
            let end = match prefix_successor(p) {
                Some(next) => store_entry_key(name, &next),
                // `p` is all-0xFF: no user-key upper bound, so scan to the
                // end of the store.
                None => prefix_successor(&store_prefix(name))
                    .expect("store prefix always has a successor"),
            };
            ReadOp::Range { start, end }
        };
        self
    }

    /// Read the half-open key range `[start, end)`.
    pub fn range(mut self, start: impl AsRef<[u8]>, end: impl AsRef<[u8]>) -> Self {
        self.op = ReadOp::Range {
            start: store_entry_key(&self.store.name, start.as_ref()),
            end: store_entry_key(&self.store.name, end.as_ref()),
        };
        self
    }

    /// Ascending key order (the default).
    pub fn ascending(mut self) -> Self {
        self.descending = false;
        self
    }

    /// Descending key order.
    pub fn descending(mut self) -> Self {
        self.descending = true;
        self
    }

    /// Keep only the first (or last, if descending) `n` keys.
    pub fn limit(mut self, n: u32) -> Self {
        self.limit = Some(n);
        self
    }

    /// Run the read and return every matching `(key, value)`, decrypted, in the
    /// selected order.
    pub async fn all(self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.execute().await
    }

    /// Smallest matching `(key, value)` (ascending). Forces `.ascending().limit(1)`.
    pub async fn first(mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.descending = false;
        self.limit = Some(1);
        Ok(self.execute().await?.into_iter().next())
    }

    /// Largest matching `(key, value)` (descending). Forces `.descending().limit(1)`.
    pub async fn last(mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.descending = true;
        self.limit = Some(1);
        Ok(self.execute().await?.into_iter().next())
    }

    async fn execute(self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let store = self.store;
        let read = StoreReadOp {
            op: self.op,
            descending: self.descending,
            limit: self.limit,
        };
        // Cache-first (coverage-aware for limited reads); else fetch a proof.
        let raw = match store
            .space
            .with_state(|s| s.kv_cache.store_read(&read.op, read.descending, read.limit))
        {
            CacheResult::Hit(pairs) => pairs,
            CacheResult::Miss => store.fetch_read(&read).await?,
        };
        // `raw` is `(entry_key, still-encrypted value)` in the requested order.
        let mut out = Vec::with_capacity(raw.len());
        for (entry_key, value) in raw {
            let Ok(ParsedKey::StoreEntry { key, .. }) = parse_key(&entry_key) else {
                continue;
            };
            out.push((key, store.decrypt(value).await?));
        }
        Ok(out)
    }
}
