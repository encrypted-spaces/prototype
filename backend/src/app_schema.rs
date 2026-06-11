//! Application schema types shared between the server and SDK.
//!
//! A [`SchemaBundle`] defines an application's table structure and
//! access control rules.  The SDK imports it (via `parse_schema_bundle`
//! in `schema_kdl`) to populate its local schema cache.

use crate::schema::Schema;
use encrypted_spaces_acl_types::Action;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single table entry in an application schema bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaTable {
    pub table: String,
    pub schema: Option<Schema>,
    #[serde(default)]
    pub rows: Vec<Value>,
}

/// Application schema format: table schemas + access control rules.
///
/// This is the preferred format for defining an application's schema.
/// Internal tables (`_users`, `_access_control`, `_retention`) should not
/// be included in authored schemas; bundles imported by the server may
/// include internal table rows with no schema so they can be replayed
/// during import.
///
/// The initial merk root (data commitment) is *not* carried in the
/// bundle.  `sdk-codegen` computes it at build time from the parsed
/// schema and emits it as a const; callers pair that const with the
/// bundle bytes via `ApplicationSchema::FromBytes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaBundle {
    pub tables: Vec<SchemaTable>,
    /// App-defined actions declared in the schema.  Resolved at op time
    /// by the `Action` dispatch path; empty for schemas that don't
    /// declare any.
    #[serde(default)]
    pub actions: Vec<Action>,
    /// Action-gating clauses declared in `acl` blocks via
    /// `write_only_via_actions` / `delete_only_via_actions`.  Keyed by
    /// `(table, op_str)` where `op_str` is `"write"` or `"delete"`; the
    /// value is the list of action names allowed to perform that op
    /// on that table.  When a key is present, direct primitive ops on
    /// the table are rejected by the verifier.
    #[serde(default)]
    pub acl_only_via_actions: std::collections::BTreeMap<(String, String), Vec<String>>,
}
