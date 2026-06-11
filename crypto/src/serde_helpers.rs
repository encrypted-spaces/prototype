//! Serde helpers for serializing data structures that are not directly
//! representable in JSON (e.g. `HashMap` with non-string keys).

/// Serialize/deserialize a `HashMap<K, V>` as a `Vec<(K, V)>`.
///
/// JSON requires object keys to be strings. This module works around
/// that limitation by encoding the map as a sequence of key-value pairs,
/// which is valid in any serde format.
///
/// Usage: `#[serde(with = "encrypted_spaces_crypto::serde_helpers::hashmap_as_pairs")]`
pub mod hashmap_as_pairs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;
    use std::hash::Hash;

    pub fn serialize<S, K, V>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        K: Serialize + Eq + Hash,
        V: Serialize,
    {
        let pairs: Vec<(&K, &V)> = map.iter().collect();
        pairs.serialize(serializer)
    }

    pub fn deserialize<'de, D, K, V>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
    where
        D: Deserializer<'de>,
        K: Deserialize<'de> + Eq + Hash,
        V: Deserialize<'de>,
    {
        let pairs: Vec<(K, V)> = Vec::deserialize(deserializer)?;
        Ok(pairs.into_iter().collect())
    }
}
