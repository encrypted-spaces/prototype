use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use encrypted_spaces_backend::error::{Result as SdkResult, SdkError};
use encrypted_spaces_backend::merk_storage::stored_value;
use encrypted_spaces_crypto::encryption::{
    ciphertext_key_id, decrypt_field, EncryptionKey, FieldType,
};
use encrypted_spaces_key_manager::SimpleKeyId;

use crate::kv_cache::SyncDecryptResolver;
use crate::DataCommitment;

/// Pre-resolved key material for synchronous cache-hit decryption.
///
/// Built asynchronously via [`Space::sync_decrypt_context`] before a cache-hit
/// attempt, then passed to [`KvCache::try_select`] so the cache materializer
/// can decrypt encrypted columns without async key resolution.
#[derive(Clone)]
pub(crate) struct SyncDecryptContext {
    anchor: DataCommitment,
    keys: HashMap<SimpleKeyId, [u8; 32]>,
}

impl SyncDecryptContext {
    pub(crate) fn new(anchor: DataCommitment, keys: HashMap<SimpleKeyId, [u8; 32]>) -> Self {
        Self { anchor, keys }
    }
}

impl SyncDecryptResolver for SyncDecryptContext {
    fn anchor(&self) -> DataCommitment {
        self.anchor
    }

    fn decrypt_column_bytes(&self, encoded: &str, field_type: &FieldType) -> SdkResult<Vec<u8>> {
        let encrypted = STANDARD
            .decode(encoded)
            .map_err(|e| SdkError::DecryptionError(format!("invalid base64: {e}")))?;

        let key_id: SimpleKeyId = ciphertext_key_id(&encrypted)
            .ok_or_else(|| SdkError::DecryptionError("invalid ciphertext header".into()))?;

        let key_bytes = self.keys.get(&key_id).ok_or_else(|| {
            SdkError::DecryptionError(format!("no pre-resolved key for id {key_id}"))
        })?;
        let key = EncryptionKey::new(*key_bytes, &key_id);

        let plaintext_bytes = decrypt_field(&encrypted, &key)
            .map_err(|e| SdkError::DecryptionError(format!("decrypt failed: {e}")))?;

        let value = plaintext_bytes_to_value(&plaintext_bytes, field_type)?;
        stored_value::value_to_bytes(&value)
            .map_err(|e| SdkError::SerializationError(format!("value encoding failed: {e}")))
    }
}

fn plaintext_bytes_to_value(bytes: &[u8], field_type: &FieldType) -> SdkResult<serde_json::Value> {
    match field_type {
        FieldType::Integer => {
            if bytes.len() == 8 {
                let arr: [u8; 8] = bytes.try_into().unwrap();
                Ok(serde_json::Value::Number(i64::from_be_bytes(arr).into()))
            } else if bytes.len() == 1 {
                Ok(serde_json::Value::Number((bytes[0] as i64).into()))
            } else {
                Err(SdkError::DecryptionError(format!(
                    "unexpected integer byte length: {}",
                    bytes.len()
                )))
            }
        }
        FieldType::Real => {
            if bytes.len() == 8 {
                let arr: [u8; 8] = bytes.try_into().unwrap();
                let f = f64::from_be_bytes(arr);
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| SdkError::DecryptionError("non-finite float".into()))
            } else {
                Err(SdkError::DecryptionError(format!(
                    "unexpected real byte length: {}",
                    bytes.len()
                )))
            }
        }
        FieldType::Text | FieldType::FileRef | FieldType::List => String::from_utf8(bytes.to_vec())
            .map(serde_json::Value::String)
            .map_err(|e| SdkError::DecryptionError(format!("invalid utf-8: {e}"))),
        FieldType::Blob => Ok(serde_json::Value::String(STANDARD.encode(bytes))),
    }
}

impl crate::Space {
    /// Build a [`SyncDecryptContext`] capturing the current anchor and all
    /// resolvable data keys.
    ///
    /// Key resolution walks `0..=current_key_id`. Keys that fail to resolve
    /// (e.g. pruned by a reduce) are silently skipped; cached entries encrypted
    /// with those keys will miss cleanly during materialization.
    pub(crate) async fn sync_decrypt_context(&self) -> SdkResult<SyncDecryptContext> {
        let anchor = self.current_data_commitment();
        let builder = self.retention_builder();
        let km = self.key_manager.lock().await;

        let mut keys = HashMap::new();
        if let Ok(current) = km.current_key_id(&builder).await {
            for seq in 0..=current.0 {
                let id = SimpleKeyId(seq);
                if let Ok(key_bytes) = km.data_key_for_key_id(&id, &builder).await {
                    keys.insert(id, key_bytes);
                }
            }
        }

        Ok(SyncDecryptContext::new(anchor, keys))
    }

    /// Cache-aware variant of [`Space::sync_decrypt_context`] for the read path.
    ///
    /// Reuses a context cached on [`State`](crate::state::State) while the data
    /// anchor is unchanged, so repeated cache-hit reads of encrypted tables do
    /// not re-take the async key-manager lock or re-scan keys. The expensive
    /// build runs once per anchor; subsequent reads only clone the pre-resolved
    /// key set. The cached entry is keyed by the context's own anchor, so an
    /// anchor advance (write/broadcast/reanchor) transparently forces a rebuild.
    pub(crate) async fn cached_sync_decrypt_context(&self) -> SdkResult<SyncDecryptContext> {
        let anchor = self.current_data_commitment();
        if let Some(context) = self.with_state(|state| match &state.cached_decrypt_context {
            Some((cached_anchor, context)) if *cached_anchor == anchor => Some(context.clone()),
            _ => None,
        }) {
            return Ok(context);
        }

        let context = self.sync_decrypt_context().await?;
        let key_anchor = context.anchor;
        self.with_state_mut(|state| {
            state.cached_decrypt_context = Some((key_anchor, context.clone()));
        });
        Ok(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_crypto::encryption::encrypt_field;

    fn anchor(byte: u8) -> DataCommitment {
        [byte; 32]
    }

    fn make_context_with_keys(
        a: DataCommitment,
        entries: &[(u64, [u8; 32])],
    ) -> SyncDecryptContext {
        let keys = entries
            .iter()
            .map(|(id, bytes)| (SimpleKeyId(*id), *bytes))
            .collect();
        SyncDecryptContext::new(a, keys)
    }

    fn encrypt_and_encode(plaintext: &[u8], key_id: u64, key_bytes: [u8; 32]) -> String {
        let key = EncryptionKey::new(key_bytes, &SimpleKeyId(key_id));
        let encrypted = encrypt_field(plaintext, &key);
        STANDARD.encode(&encrypted)
    }

    #[test]
    fn anchor_is_returned() {
        let ctx = make_context_with_keys(anchor(7), &[]);
        assert_eq!(ctx.anchor(), anchor(7));
    }

    #[test]
    fn decrypt_text_column() {
        let key_bytes = [0x42; 32];
        let encoded = encrypt_and_encode(b"hello", 0, key_bytes);

        let ctx = make_context_with_keys(anchor(1), &[(0, key_bytes)]);
        let result = ctx
            .decrypt_column_bytes(&encoded, &FieldType::Text)
            .unwrap();

        let value = stored_value::bytes_to_value(&result).unwrap();
        assert_eq!(value, serde_json::json!("hello"));
    }

    #[test]
    fn decrypt_integer_column() {
        let key_bytes = [0x42; 32];
        let encoded = encrypt_and_encode(&42i64.to_be_bytes(), 0, key_bytes);

        let ctx = make_context_with_keys(anchor(1), &[(0, key_bytes)]);
        let result = ctx
            .decrypt_column_bytes(&encoded, &FieldType::Integer)
            .unwrap();

        let value = stored_value::bytes_to_value(&result).unwrap();
        assert_eq!(value, serde_json::json!(42));
    }

    #[test]
    fn decrypt_real_column() {
        let key_bytes = [0x42; 32];
        let test_value = 42.5_f64;
        let encoded = encrypt_and_encode(&test_value.to_be_bytes(), 0, key_bytes);

        let ctx = make_context_with_keys(anchor(1), &[(0, key_bytes)]);
        let result = ctx
            .decrypt_column_bytes(&encoded, &FieldType::Real)
            .unwrap();

        let value = stored_value::bytes_to_value(&result).unwrap();
        assert_eq!(value, serde_json::json!(test_value));
    }

    #[test]
    fn decrypt_blob_column() {
        let key_bytes = [0x42; 32];
        let blob = b"\x00\x01\x02\x03";
        let encoded = encrypt_and_encode(blob, 0, key_bytes);

        let ctx = make_context_with_keys(anchor(1), &[(0, key_bytes)]);
        let result = ctx
            .decrypt_column_bytes(&encoded, &FieldType::Blob)
            .unwrap();

        let value = stored_value::bytes_to_value(&result).unwrap();
        assert_eq!(value, serde_json::json!(STANDARD.encode(blob)));
    }

    #[test]
    fn missing_key_id_returns_error() {
        let key_bytes = [0x42; 32];
        let encoded = encrypt_and_encode(b"secret", 5, key_bytes);

        let ctx = make_context_with_keys(anchor(1), &[(0, key_bytes)]);
        let result = ctx.decrypt_column_bytes(&encoded, &FieldType::Text);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_base64_returns_error() {
        let ctx = make_context_with_keys(anchor(1), &[(0, [0x42; 32])]);
        let result = ctx.decrypt_column_bytes("not-valid-b64!!!", &FieldType::Text);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_ciphertext_returns_error() {
        let ctx = make_context_with_keys(anchor(1), &[(0, [0x42; 32])]);
        let result = ctx.decrypt_column_bytes(&STANDARD.encode([0x02, 0x00]), &FieldType::Text);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_key_ids_resolve_correctly() {
        let key_a = [0x42; 32];
        let key_b = [0x43; 32];
        let encoded_a = encrypt_and_encode(b"from_a", 0, key_a);
        let encoded_b = encrypt_and_encode(b"from_b", 1, key_b);

        let ctx = make_context_with_keys(anchor(1), &[(0, key_a), (1, key_b)]);

        let val_a = stored_value::bytes_to_value(
            &ctx.decrypt_column_bytes(&encoded_a, &FieldType::Text)
                .unwrap(),
        )
        .unwrap();
        let val_b = stored_value::bytes_to_value(
            &ctx.decrypt_column_bytes(&encoded_b, &FieldType::Text)
                .unwrap(),
        )
        .unwrap();

        assert_eq!(val_a, serde_json::json!("from_a"));
        assert_eq!(val_b, serde_json::json!("from_b"));
    }
}
