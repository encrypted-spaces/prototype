use crate::error::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    pub name: String,
    pub columns: Vec<ColumnDefinition>,
    /// Whether the server auto-assigns the `id` column from an authenticated
    /// per-table counter (`true`), or the client must supply an explicit id
    /// on every insert (`false`).  The two modes are mutually exclusive per
    /// table; see the `InsertOp` verifier for enforcement.
    ///
    /// Defaults to `true` so schemas serialized before this field existed
    /// deserialize as auto-increment tables.
    #[serde(default = "default_true")]
    pub auto_increment: bool,
}

fn default_true() -> bool {
    true
}

impl Schema {
    /// Convert the schema definition into a JSON representation.
    pub fn to_json(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(Into::into)
    }

    /// Get the names of all indexed columns.
    pub fn indexed_columns(&self) -> Vec<&str> {
        self.columns
            .iter()
            .filter(|c| c.indexed)
            .map(|c| c.name.as_str())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDefinition {
    pub name: String,
    pub column_type: ColumnType,
    /// Whether this column is stored in plaintext (not encrypted).
    /// Indexed columns must be plaintext.
    pub plaintext: bool,
    /// Whether this column has a secondary index.
    #[serde(default)]
    pub indexed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnType {
    Integer,
    String,
    Real,
    /// Content-addressed out-of-band file storage.
    /// Stored in the row as a text value (hex-encoded SHA-256 hash).
    FileRef,
    /// Ordered list backed by the internal `_lists` table.
    /// Cell value is an i64 `list_number` allocated at insert time.
    List,
    /// Always hashed: Merk stores SHA-256(value), full value lives in HashStore.
    Text,
    /// Always hashed: Merk stores SHA-256(value), full value lives in HashStore.
    Blob,
}

pub const MAX_STRING_COLUMN_BYTES: usize = 128;

impl ColumnType {
    pub fn is_hash_backed(&self) -> bool {
        matches!(self, ColumnType::Text | ColumnType::Blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_json_contains_expected_fields() {
        let schema = Schema {
            name: "projects".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "owner_id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: true,
                },
            ],
            auto_increment: true,
        };

        let json = schema.to_json().expect("schema should serialize");
        assert_eq!(json["name"], "projects");
        assert_eq!(json["columns"].as_array().unwrap().len(), 2);
        assert_eq!(schema.indexed_columns(), vec!["owner_id"]);
    }

    #[test]
    fn schema_deserializes_legacy_without_auto_increment_field() {
        // Schemas serialized before auto_increment existed must deserialize as
        // auto-increment tables so existing app_schema bundles keep working.
        let legacy = r#"{
            "name": "projects",
            "columns": [
                {
                    "name": "id",
                    "column_type": "Integer",
                    "plaintext": true,
                    "indexed": false
                }
            ]
        }"#;

        let schema: Schema = serde_json::from_str(legacy).expect("legacy JSON should parse");
        assert!(schema.auto_increment);
    }
}
