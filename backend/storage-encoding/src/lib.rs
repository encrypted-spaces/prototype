//! Storage key encoding for the Merk-based storage backend.
//!
//! This crate provides the canonical key encoding and decoding functions shared
//! across the storage layer and proof verification code. It uses FoundationDB-style
//! tuple encoding for order-preserving serialization.
//!
//! This is a leaf crate with no workspace dependencies, so it can be used from
//! both the backend and the ZK guest programs.

pub mod id_validation;
pub mod keys;
pub mod stored_value;
pub mod tuple;

// Re-export commonly used types and functions
pub use id_validation::{classify_insert_id, IdValidationError, InsertId};
pub use keys::{
    acl_only_via_actions_key, acl_rule_key, action_marker_key, action_storage_key, bytes_to_row_id,
    column_key_placeholder, decode_action_value, encode_action_value, index_column_prefix,
    index_key, index_value_prefix, parse_column_key_ref, parse_key, row_id_to_bytes, row_key,
    row_prefix, schema_columns_key, schema_indexes_key, schema_key, users_row_key, ColumnKeyRef,
    KeyError, ParsedKey, TupleConversionError, ACTION_STORAGE_VERSION, RETENTION_TABLE,
    USERS_TABLE,
};
pub use tuple::{decode_tuple, encode_tuple, DecodeError, TupleElement};

use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;

pub fn hashstore_hash(value: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher.finalize().into()
}

/// Extract non-id column names from a JSON-serialized schema stored in the merk tree.
/// Returns `None` if the schema bytes can't be parsed.
pub fn extract_non_id_columns_from_schema(
    schema_bytes: &[u8],
) -> Option<std::collections::BTreeSet<String>> {
    let schema: serde_json::Value = serde_json::from_slice(schema_bytes).ok()?;
    let columns = schema.get("columns")?.as_array()?;
    Some(
        columns
            .iter()
            .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
            .filter(|name| *name != "id")
            .map(|s| s.to_string())
            .collect(),
    )
}

/// Encode non-id column names as a null-separated UTF-8 byte string.
///
/// E.g. `["name", "price"]` → `b"name\0price"`.
pub fn encode_column_names(names: &std::collections::BTreeSet<String>) -> Vec<u8> {
    let mut buf = Vec::new();
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            buf.push(0);
        }
        buf.extend_from_slice(name.as_bytes());
    }
    buf
}

/// Decode a null-separated UTF-8 column-names value back to a `BTreeSet`.
///
/// Returns `None` if the bytes aren't valid UTF-8.
pub fn decode_column_names(bytes: &[u8]) -> Option<std::collections::BTreeSet<String>> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.is_empty() {
        return Some(std::collections::BTreeSet::new());
    }
    Some(s.split('\0').map(|n| n.to_string()).collect())
}

#[cfg(test)]
mod hash_tests {
    use super::*;

    #[test]
    fn hashstore_hash_is_deterministic() {
        let data = b"hello world";
        let h1 = hashstore_hash(data);
        let h2 = hashstore_hash(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), HASH_LEN);
    }

    #[test]
    fn hashstore_hash_differs_for_different_inputs() {
        let h1 = hashstore_hash(b"hello");
        let h2 = hashstore_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hashstore_hash_empty_input() {
        let h = hashstore_hash(b"");
        assert_eq!(h.len(), HASH_LEN);
        assert_ne!(h, [0u8; HASH_LEN]);
    }
}
