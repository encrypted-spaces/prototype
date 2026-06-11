//! Canonical schema definitions for built-in ("internal") tables.
//!
//! The shapes live in `internal_schemas.kdl` alongside this file; this
//! module is a typed wrapper that parses the KDL once and exposes the
//! table-name constants plus per-table accessors.

use crate::schema::Schema;
use crate::schema_kdl::parse_schema_bundle;
use std::collections::HashMap;
use std::sync::OnceLock;

pub const USERS_TABLE_NAME: &str = "_users";
pub const ACCESS_CONTROL_TABLE_NAME: &str = "_access_control";
pub const KEY_HISTORY_TABLE_NAME: &str = "_key_history";
pub const RETENTION_TABLE_NAME: &str = "_retention";
pub const LISTS_TABLE_NAME: &str = "_lists";

// Column names for the `_key_history` table.
pub const KEY_HISTORY_COL_UID: &str = "uid";
pub const KEY_HISTORY_COL_OLD_AUTH_KEY: &str = "old_auth_key";
pub const KEY_HISTORY_COL_VALID_FROM: &str = "valid_from_change_id";
pub const KEY_HISTORY_COL_VALID_TO: &str = "valid_to_change_id";

const INTERNAL_SCHEMAS_KDL: &str = include_str!("internal_schemas.kdl");

fn schemas_by_name() -> &'static HashMap<String, Schema> {
    static CACHE: OnceLock<HashMap<String, Schema>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let bundle =
            parse_schema_bundle(INTERNAL_SCHEMAS_KDL).expect("internal_schemas.kdl must parse");
        bundle
            .tables
            .into_iter()
            .map(|entry| {
                let schema = entry.schema.unwrap_or_else(|| {
                    panic!("internal table '{}' has no schema body", entry.table)
                });
                (entry.table, schema)
            })
            .collect()
    })
}

fn schema_named(name: &str) -> Schema {
    schemas_by_name()
        .get(name)
        .unwrap_or_else(|| panic!("internal table '{name}' not declared in internal_schemas.kdl"))
        .clone()
}

pub fn users_schema() -> Schema {
    schema_named(USERS_TABLE_NAME)
}

pub fn access_control_schema() -> Schema {
    schema_named(ACCESS_CONTROL_TABLE_NAME)
}

pub fn key_history_schema() -> Schema {
    schema_named(KEY_HISTORY_TABLE_NAME)
}

pub fn retention_schema() -> Schema {
    schema_named(RETENTION_TABLE_NAME)
}

pub fn lists_schema() -> Schema {
    schema_named(LISTS_TABLE_NAME)
}

/// Returns all internal table schemas in creation order.
pub fn all_internal_schemas() -> Vec<Schema> {
    vec![
        access_control_schema(),
        key_history_schema(),
        lists_schema(),
        retention_schema(),
        users_schema(),
    ]
}

/// Returns `true` if the given table name is an internal (built-in) table.
pub fn is_internal_table(name: &str) -> bool {
    schemas_by_name().contains_key(name)
}

/// Returns `true` if the name is reserved for internal use.
///
/// Names beginning with ASCII `_` are reserved; developer schemas must not
/// define such tables.
pub fn is_reserved_table_name(name: &str) -> bool {
    name.starts_with('_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ColumnType;

    #[test]
    fn all_internal_schemas_covers_all_tables() {
        let schemas = all_internal_schemas();
        let names: Vec<&str> = schemas.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&USERS_TABLE_NAME));
        assert!(names.contains(&ACCESS_CONTROL_TABLE_NAME));
        assert!(names.contains(&KEY_HISTORY_TABLE_NAME));
        assert!(names.contains(&RETENTION_TABLE_NAME));
        assert!(names.contains(&LISTS_TABLE_NAME));
        assert_eq!(
            schemas.len(),
            5,
            "update this test when adding new internal tables"
        );
        for schema in &schemas {
            assert!(
                is_reserved_table_name(&schema.name),
                "internal table '{}' must use a reserved (_-prefixed) name",
                schema.name
            );
        }
    }

    #[test]
    fn is_reserved_table_name_matches_underscore_prefix() {
        assert!(is_reserved_table_name("_users"));
        assert!(is_reserved_table_name("_secret"));
        assert!(!is_reserved_table_name("users"));
        assert!(!is_reserved_table_name(""));
    }

    #[test]
    fn id_columns_are_plaintext() {
        for schema in all_internal_schemas() {
            if let Some(id_col) = schema.columns.iter().find(|c| c.name == "id") {
                assert!(id_col.plaintext, "{}.id should be plaintext", schema.name);
            }
        }
    }

    #[test]
    fn users_schema_columns_match() {
        let s = users_schema();
        let names: Vec<&str> = s.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["id", "update_key", "auth_key", "status"]);
        for c in &s.columns {
            assert!(c.plaintext, "_users.{} should be plaintext", c.name);
            assert!(!c.indexed, "_users.{} should not be indexed", c.name);
        }
        assert!(matches!(s.columns[0].column_type, ColumnType::Integer));
        assert!(matches!(s.columns[1].column_type, ColumnType::Blob));
        assert!(matches!(s.columns[2].column_type, ColumnType::Blob));
        assert!(matches!(s.columns[3].column_type, ColumnType::Integer));
        assert!(s.auto_increment);
    }

    #[test]
    fn key_history_schema_columns_match() {
        let s = key_history_schema();
        let names: Vec<&str> = s.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "uid",
                "old_auth_key",
                "valid_from_change_id",
                "valid_to_change_id"
            ]
        );
        assert!(matches!(s.columns[0].column_type, ColumnType::Integer));
        assert!(matches!(s.columns[1].column_type, ColumnType::Blob));
        assert!(matches!(s.columns[2].column_type, ColumnType::Integer));
        assert!(matches!(s.columns[3].column_type, ColumnType::Integer));
        for c in &s.columns {
            assert!(c.plaintext, "_key_history.{} should be plaintext", c.name);
        }
        assert!(s.columns[0].indexed, "_key_history.uid should be indexed");
        assert!(
            !s.columns[1].indexed,
            "_key_history.old_auth_key should not be indexed"
        );
    }

    #[test]
    fn access_control_schema_indexes_resource_name() {
        let s = access_control_schema();
        let resource_name = s
            .columns
            .iter()
            .find(|c| c.name == "resource_name")
            .expect("resource_name column");
        assert!(resource_name.indexed);
        assert!(resource_name.plaintext);
    }

    #[test]
    fn lists_value_column_is_encrypted() {
        let s = lists_schema();
        let value = s
            .columns
            .iter()
            .find(|c| c.name == "value")
            .expect("value column");
        assert!(!value.plaintext, "_lists.value must be encrypted");
    }
}
