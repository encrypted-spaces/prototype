//! AES-256-CTR field-level encryption with key-ID tagging.
//!
//! Integrity is provided by the changelog's Merkle tree commitment over the
//! full ciphertext (including nonce), so no MAC/authentication tag is needed
//! at this layer.
//!
//! Ciphertext layout (before base64):
//! ```text
//! [ version: 1 byte (0x02) ] [ key_id_len: 2 bytes (u16 LE) ] [ key_id: N bytes (postcard) ] [ nonce: 16 bytes ] [ ciphertext: M bytes ]
//! ```

use aes::cipher::{KeyIvInit, StreamCipher};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::EncryptionError;

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const VERSION: u8 = 0x02;
const NONCE_LEN: usize = 16;
/// Minimum header: version (1) + key_id_len (2) + nonce (16)
const MIN_HEADER_LEN: usize = 1 + 2 + NONCE_LEN;

/// A derived AES-256 key tagged with a serialized key ID.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey {
    key: [u8; 32],
    /// Postcard-serialized key ID bytes.
    #[zeroize(skip)]
    key_id_bytes: Vec<u8>,
}

impl EncryptionKey {
    /// Construct from a 32-byte key and any serializable key ID.
    /// The key ID is serialized via postcard internally.
    pub fn new<K: Serialize>(key: [u8; 32], key_id: &K) -> Self {
        let key_id_bytes =
            postcard::to_allocvec(key_id).expect("key ID serialization should not fail");
        Self { key, key_id_bytes }
    }
}

/// Column type metadata for encryption/decryption serialization.
/// Mirrors backend `ColumnType` so the crypto crate stays independent.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldType {
    Integer,
    Real,
    Text,
    Blob,
    /// Content-addressed file reference. Stored and encrypted as Text (hex hash).
    FileRef,
    /// Ordered list reference. Stored as Text (hex root hash). Always plaintext.
    List,
}

/// Describes a column that should be encrypted/decrypted.
#[derive(Debug, Clone)]
pub struct EncryptedColumn {
    pub name: String,
    pub field_type: FieldType,
}

/// Encrypt a single field value, returning `version || key_id_len || key_id || nonce || ciphertext`.
pub fn encrypt_field(plaintext: &[u8], key: &EncryptionKey) -> Vec<u8> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes);

    let mut buffer = plaintext.to_vec();
    let mut cipher = Aes256Ctr::new((&key.key).into(), (&nonce_bytes).into());
    cipher.apply_keystream(&mut buffer);

    let key_id_len = (key.key_id_bytes.len() as u16).to_le_bytes();

    let mut out = Vec::with_capacity(1 + 2 + key.key_id_bytes.len() + NONCE_LEN + buffer.len());
    out.push(VERSION);
    out.extend_from_slice(&key_id_len);
    out.extend_from_slice(&key.key_id_bytes);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buffer);
    out
}

/// Decrypt a single field value produced by [`encrypt_field`].
///
/// CTR mode is symmetric — encryption and decryption are the same operation.
pub fn decrypt_field(data: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, EncryptionError> {
    if data.len() < MIN_HEADER_LEN {
        return Err(EncryptionError::InvalidCiphertext);
    }

    let version = data[0];
    if version != VERSION {
        return Err(EncryptionError::UnsupportedVersion(version));
    }

    let key_id_len = u16::from_le_bytes([data[1], data[2]]) as usize;
    let header_len = 1 + 2 + key_id_len + NONCE_LEN;
    if data.len() < header_len {
        return Err(EncryptionError::InvalidCiphertext);
    }

    let nonce_start = 1 + 2 + key_id_len;
    let nonce = &data[nonce_start..nonce_start + NONCE_LEN];
    let ciphertext = &data[header_len..];

    let mut buffer = ciphertext.to_vec();
    let mut cipher = Aes256Ctr::new((&key.key).into(), nonce.into());
    cipher.apply_keystream(&mut buffer);

    Ok(buffer)
}

/// Extract and deserialize the key ID from a ciphertext header without decrypting.
pub fn ciphertext_key_id<K: DeserializeOwned>(data: &[u8]) -> Option<K> {
    if data.len() < MIN_HEADER_LEN {
        return None;
    }
    if data[0] != VERSION {
        return None;
    }
    let key_id_len = u16::from_le_bytes([data[1], data[2]]) as usize;
    let end = 1 + 2 + key_id_len;
    if data.len() < end + NONCE_LEN {
        return None;
    }
    postcard::from_bytes(&data[3..end]).ok()
}

/// Encrypt row fields in-place. For each column in `columns`, serializes the JSON
/// value to bytes, encrypts, and replaces with a base64-encoded string.
pub fn encrypt_row(
    row: &mut serde_json::Map<String, serde_json::Value>,
    columns: &[EncryptedColumn],
    key: &EncryptionKey,
) {
    for col in columns {
        let value = match row.get(&col.name) {
            Some(v) => v.clone(),
            None => continue,
        };

        let bytes: Option<Vec<u8>> = match (&col.field_type, &value) {
            (FieldType::Integer, serde_json::Value::Number(n)) => {
                n.as_i64().map(|i| i.to_be_bytes().to_vec())
            }
            (FieldType::Integer, serde_json::Value::Bool(b)) => Some(vec![if *b { 1 } else { 0 }]),
            (FieldType::Real, serde_json::Value::Number(n)) => {
                n.as_f64().map(|f| f.to_be_bytes().to_vec())
            }
            (
                FieldType::Text | FieldType::FileRef | FieldType::List,
                serde_json::Value::String(s),
            ) => Some(s.as_bytes().to_vec()),
            (FieldType::Blob, serde_json::Value::String(s)) => STANDARD.decode(s).ok(),
            (_, serde_json::Value::Null) => None,
            _ => None,
        };

        if let Some(plaintext_bytes) = bytes {
            let encrypted = encrypt_field(&plaintext_bytes, key);
            row.insert(
                col.name.clone(),
                serde_json::Value::String(STANDARD.encode(&encrypted)),
            );
        }
    }
}

/// Decrypt row fields in-place. For each encrypted column, extracts and
/// deserializes the key ID from the ciphertext header, resolves the key
/// via `key_for_id`, and decrypts.
///
/// Returns an error if key resolution or decryption fails for any field.
pub async fn decrypt_row<K, F, Fut>(
    row: &mut serde_json::Map<String, serde_json::Value>,
    columns: &[EncryptedColumn],
    key_for_id: &F,
) -> Result<(), EncryptionError>
where
    K: DeserializeOwned,
    F: Fn(K) -> Fut,
    Fut: std::future::Future<Output = Result<EncryptionKey, EncryptionError>>,
{
    for col in columns {
        let encoded = match row.get(&col.name) {
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => continue,
        };

        let encrypted = match STANDARD.decode(&encoded) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let key_id: K = ciphertext_key_id(&encrypted).ok_or(EncryptionError::InvalidCiphertext)?;
        let key = key_for_id(key_id).await?;
        let decrypted = decrypt_field(&encrypted, &key)?;

        let value: Option<serde_json::Value> = match col.field_type {
            FieldType::Integer => {
                if decrypted.len() == 8 {
                    <[u8; 8]>::try_from(decrypted.as_slice())
                        .ok()
                        .map(|bytes| serde_json::Value::Number(i64::from_be_bytes(bytes).into()))
                } else if decrypted.len() == 1 {
                    Some(serde_json::Value::Number((decrypted[0] as i64).into()))
                } else {
                    None
                }
            }
            FieldType::Real => {
                if decrypted.len() == 8 {
                    <[u8; 8]>::try_from(decrypted.as_slice())
                        .ok()
                        .and_then(|bytes| {
                            let f = f64::from_be_bytes(bytes);
                            serde_json::Number::from_f64(f).map(serde_json::Value::Number)
                        })
                } else {
                    None
                }
            }
            FieldType::Text | FieldType::FileRef | FieldType::List => String::from_utf8(decrypted)
                .ok()
                .map(serde_json::Value::String),
            FieldType::Blob => Some(serde_json::Value::String(STANDARD.encode(&decrypted))),
        };

        if let Some(v) = value {
            row.insert(col.name.clone(), v);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> EncryptionKey {
        EncryptionKey::new([0x42; 32], &0u64)
    }

    async fn test_key_resolver(id: u64) -> Result<EncryptionKey, EncryptionError> {
        if id == 0 {
            Ok(test_key())
        } else {
            Err(EncryptionError::MissingKey(
                postcard::to_allocvec(&id).unwrap(),
            ))
        }
    }

    #[test]
    fn test_roundtrip() {
        let key = test_key();
        let data = b"hello world";
        let encrypted = encrypt_field(data, &key);
        let decrypted = decrypt_field(&encrypted, &key).unwrap();
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_data_is_actually_encrypted() {
        let key = test_key();
        let data = b"hello world";
        let encrypted = encrypt_field(data, &key);
        let header_len = 1 + 2 + key.key_id_bytes.len() + NONCE_LEN;
        assert_ne!(data.to_vec(), encrypted[header_len..].to_vec());
        let decrypted = decrypt_field(&encrypted, &key).unwrap();
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_empty_data() {
        let key = test_key();
        let data = b"";
        let encrypted = encrypt_field(data, &key);
        let header_len = 1 + 2 + key.key_id_bytes.len() + NONCE_LEN;
        assert_eq!(encrypted.len(), header_len);
        let decrypted = decrypt_field(&encrypted, &key).unwrap();
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_ciphertext_key_id() {
        let key = EncryptionKey::new([0x42; 32], &42u64);
        let encrypted = encrypt_field(b"test", &key);
        assert_eq!(ciphertext_key_id::<u64>(&encrypted), Some(42u64));
    }

    #[test]
    fn test_nonces_differ() {
        let key = test_key();
        let a = encrypt_field(b"same", &key);
        let b = encrypt_field(b"same", &key);
        let nonce_start = 1 + 2 + key.key_id_bytes.len();
        assert_ne!(
            a[nonce_start..nonce_start + NONCE_LEN],
            b[nonce_start..nonce_start + NONCE_LEN]
        );
    }

    #[test]
    fn test_wrong_key_produces_wrong_plaintext() {
        let key1 = EncryptionKey::new([0x42; 32], &0u64);
        let key2 = EncryptionKey::new([0x43; 32], &0u64);
        let data = b"secret";
        let encrypted = encrypt_field(data, &key1);
        let decrypted = decrypt_field(&encrypted, &key2).unwrap();
        assert_ne!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_invalid_version() {
        let key = test_key();
        let mut encrypted = encrypt_field(b"test", &key);
        encrypted[0] = 0x99;
        match decrypt_field(&encrypted, &key) {
            Err(EncryptionError::UnsupportedVersion(0x99)) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn test_too_short() {
        let key = test_key();
        match decrypt_field(&[0x02, 0x00, 0x00], &key) {
            Err(EncryptionError::InvalidCiphertext) => {}
            other => panic!("expected InvalidCiphertext, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_missing_key() {
        let key = EncryptionKey::new([0x42; 32], &5u64);
        let encrypted = encrypt_field(b"test", &key);

        let mut row = serde_json::Map::new();
        row.insert(
            "data".to_string(),
            serde_json::Value::String(STANDARD.encode(&encrypted)),
        );
        let columns = vec![EncryptedColumn {
            name: "data".to_string(),
            field_type: FieldType::Text,
        }];

        let result = decrypt_row(&mut row, &columns, &test_key_resolver).await;
        assert!(matches!(result, Err(EncryptionError::MissingKey(_))));
    }

    #[tokio::test]
    async fn test_encrypt_row_roundtrip() {
        let key = test_key();
        let columns = vec![
            EncryptedColumn {
                name: "name".to_string(),
                field_type: FieldType::Text,
            },
            EncryptedColumn {
                name: "age".to_string(),
                field_type: FieldType::Integer,
            },
            EncryptedColumn {
                name: "score".to_string(),
                field_type: FieldType::Real,
            },
        ];

        let mut row = serde_json::Map::new();
        row.insert(
            "name".to_string(),
            serde_json::Value::String("Alice".to_string()),
        );
        row.insert("age".to_string(), serde_json::Value::Number(30.into()));
        row.insert(
            "score".to_string(),
            serde_json::json!(95.5)
                .as_f64()
                .and_then(serde_json::Number::from_f64)
                .map(serde_json::Value::Number)
                .unwrap(),
        );
        row.insert("id".to_string(), serde_json::Value::Number(1.into()));

        let original = row.clone();
        encrypt_row(&mut row, &columns, &key);

        assert_ne!(row.get("name"), original.get("name"));
        assert_ne!(row.get("age"), original.get("age"));
        assert_eq!(row.get("id"), original.get("id"));

        decrypt_row(&mut row, &columns, &test_key_resolver)
            .await
            .unwrap();

        assert_eq!(row.get("name"), original.get("name"));
        assert_eq!(row.get("age"), original.get("age"));
        assert_eq!(row.get("id"), original.get("id"));
    }

    #[test]
    fn test_encrypt_row_null_values() {
        let key = test_key();
        let columns = vec![EncryptedColumn {
            name: "name".to_string(),
            field_type: FieldType::Text,
        }];

        let mut row = serde_json::Map::new();
        row.insert("name".to_string(), serde_json::Value::Null);

        encrypt_row(&mut row, &columns, &key);
        assert_eq!(row.get("name"), Some(&serde_json::Value::Null));
    }

    #[tokio::test]
    async fn test_encrypt_row_boolean_as_integer() {
        let key = test_key();
        let columns = vec![EncryptedColumn {
            name: "active".to_string(),
            field_type: FieldType::Integer,
        }];

        let mut row = serde_json::Map::new();
        row.insert("active".to_string(), serde_json::Value::Bool(true));

        encrypt_row(&mut row, &columns, &key);
        assert!(row.get("active").unwrap().is_string());

        decrypt_row(&mut row, &columns, &test_key_resolver)
            .await
            .unwrap();
        assert_eq!(
            row.get("active"),
            Some(&serde_json::Value::Number(1.into()))
        );
    }
}
