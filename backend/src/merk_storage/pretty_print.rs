//! Pretty printing utilities for MerkStorage.
//!
//! Provides JSON-formatted output of the database structure, tables, rows, and indexes.

// Written by Claude

use super::keys::{self, ParsedKey};
use super::MerkStorage;
use serde_json::json;
use std::collections::{BTreeMap, HashSet};

#[cfg(feature = "merk")]
impl MerkStorage {
    /// Helper function to build a JSON object with a single table's details
    fn format_table_details(&self, table_name: &str, print_schemas: bool) -> serde_json::Value {
        let mut table_json = json!({
            "name": table_name,
        });

        // Get the table's rows using prefix iteration
        let row_prefix = keys::row_prefix(table_name);
        match self.iter_prefix(&row_prefix) {
            Ok(key_values) => {
                // Group column entries by row_id
                let mut row_map: BTreeMap<i64, serde_json::Map<String, serde_json::Value>> =
                    BTreeMap::new();
                let mut row_sizes: BTreeMap<i64, usize> = BTreeMap::new();

                for (key, bytes) in &key_values {
                    if let Ok(ParsedKey::Column { row_id, column, .. }) = keys::parse_key(key) {
                        *row_sizes.entry(row_id).or_default() += bytes.len();
                        let columns = row_map.entry(row_id).or_default();
                        if let Ok(s) = String::from_utf8(bytes.clone()) {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                                columns.insert(column, v);
                            } else {
                                columns.insert(column, json!(s));
                            }
                        } else {
                            columns.insert(column, json!("<binary data>"));
                        }
                    }
                }

                let mut rows_array = Vec::new();
                for (row_id, columns) in &row_map {
                    let size = row_sizes.get(row_id).copied().unwrap_or(0);
                    let mut row_entry = json!({
                        "row_id": row_id,
                        "size_bytes": size,
                    });
                    row_entry["data"] = json!(columns);
                    rows_array.push(row_entry);
                }

                let row_count = rows_array.len();
                table_json["rows"] = json!(rows_array);
                table_json["row_count"] = json!(row_count);
            }
            Err(e) => {
                table_json["rows_error"] = json!(format!("{:?}", e));
            }
        }

        // Get schema if requested
        if print_schemas {
            match self.get_schema(table_name) {
                Ok(schema) => {
                    if let Ok(schema_json) = serde_json::to_value(&schema) {
                        table_json["schema"] = schema_json;
                    } else {
                        table_json["schema_error"] = json!("could not serialize schema");
                    }
                }
                Err(e) => {
                    table_json["schema_error"] = json!(format!("{:?}", e));
                }
            }
        }

        // Get indexes from the schema
        if let Ok(schema) = self.get_schema(table_name) {
            let mut indexes_array = Vec::new();

            for index_col in schema.indexed_columns() {
                // Count distinct values by scanning the column entries and grouping by row
                let row_prefix = keys::row_prefix(table_name);
                let mut distinct_values = HashSet::new();
                let mut row_ids = HashSet::new();

                if let Ok(key_values) = self.iter_prefix(&row_prefix) {
                    for (key, bytes) in &key_values {
                        if let Ok(ParsedKey::Column { row_id, column, .. }) = keys::parse_key(key) {
                            row_ids.insert(row_id);
                            // Check if this column is the indexed column
                            if column == index_col {
                                if let Ok(s) = String::from_utf8(bytes.clone()) {
                                    distinct_values.insert(s);
                                }
                            }
                        }
                    }
                }
                let total_entries = row_ids.len();

                indexes_array.push(json!({
                    "column": index_col,
                    "distinct_values": distinct_values.len(),
                    "total_entries": total_entries,
                }));
            }

            table_json["indexes"] = json!(indexes_array);
        }

        table_json
    }

    /// Pretty print a specific table's rows as JSON
    pub fn pretty_print_table_rows(&self, table_name: &str, print_schemas: bool) -> String {
        let table_json = self.format_table_details(table_name, print_schemas);

        serde_json::to_string_pretty(&table_json)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize JSON: {e}\"}}"))
    }

    /// Pretty print the entire MerkStorage database structure with optional log context
    pub fn pretty_print_db(&self, print_schemas: bool, log_context: String) -> String {
        let mut db_json = json!({});

        // Add log context as first field if provided
        if !log_context.is_empty() {
            db_json["log_context"] = json!(log_context);
        }

        // Get root hash
        db_json["root_hash"] = json!(hex::encode(self.merk.root_hash()));

        // Discover all tables by scanning schema keys
        // Schema keys have the format: tuple("S", table_name)
        let schema_prefix =
            super::tuple::encode_tuple(&[super::tuple::TupleElement::String("S".to_string())]);

        let mut table_names: Vec<String> = vec![];

        match self.iter_prefix(&schema_prefix) {
            Ok(key_values) => {
                for (key, _value) in key_values {
                    if let Ok(ParsedKey::Schema { table }) = keys::parse_key(&key) {
                        if !table_names.contains(&table) {
                            table_names.push(table);
                        }
                    }
                }
            }
            Err(e) => {
                db_json["table_discovery_error"] = json!(format!("{:?}", e));
            }
        }

        db_json["table_count"] = json!(table_names.len());
        db_json["table_names"] = json!(table_names);

        // Build tables object
        let mut tables_json = serde_json::Map::new();
        for table in &table_names {
            tables_json.insert(
                table.clone(),
                self.format_table_details(table, print_schemas),
            );
        }

        db_json["tables"] = json!(tables_json);

        serde_json::to_string_pretty(&db_json)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize JSON: {e}\"}}"))
    }

    /// Pretty print the schema for a specific table as JSON
    pub fn pretty_print_table_schema(&self, table_name: &str) -> String {
        let schema_json = match self.get_schema(table_name) {
            Ok(schema) => {
                if let Ok(schema_value) = serde_json::to_value(&schema) {
                    json!({
                        "table_name": table_name,
                        "schema": schema_value
                    })
                } else {
                    json!({
                        "table_name": table_name,
                        "error": "could not serialize schema"
                    })
                }
            }
            Err(e) => json!({
                "table_name": table_name,
                "error": format!("{:?}", e)
            }),
        };

        serde_json::to_string_pretty(&schema_json)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize JSON: {e}\"}}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_control::AuthContext;
    use crate::query::QueryParam;
    use crate::query::{Query, QueryOperation};
    use crate::schema::{ColumnDefinition, ColumnType, Schema};
    use crate::storage::Storage;
    use crate::SpaceId;

    #[tokio::test]
    async fn test_pretty_print_db() {
        // Create in-memory database
        let db = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, SpaceId::from([0u8; 16]));

        // Create users table
        let users_schema = Schema {
            name: "users".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "name".to_string(),
                    column_type: ColumnType::String,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "age".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
            ],
            auto_increment: true,
        };

        // Create posts table
        let posts_schema = Schema {
            name: "posts".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "title".to_string(),
                    column_type: ColumnType::String,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "user_id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: true,
                },
            ],
            auto_increment: true,
        };

        // Create tables
        db.create_table(&users_schema).await.unwrap();
        db.create_table(&posts_schema).await.unwrap();

        // Insert users
        for (name, age) in [("Alice", 30), ("Bob", 25), ("Charlie", 35)].iter() {
            let insert_query = Query::new(
                "users".to_string(),
                QueryOperation::Insert(vec![
                    ("name".to_string(), QueryParam::Text(name.to_string())),
                    ("age".to_string(), QueryParam::Integer(*age)),
                ]),
            );
            db.insert(insert_query, &auth).await.unwrap();
        }

        // Insert posts
        for (title, user_id) in [
            ("Hello World", 1),
            ("Rust is Great", 1),
            ("Database Design", 2),
            ("Testing 101", 3),
        ]
        .iter()
        {
            let insert_query = Query::new(
                "posts".to_string(),
                QueryOperation::Insert(vec![
                    ("title".to_string(), QueryParam::Text(title.to_string())),
                    ("user_id".to_string(), QueryParam::Integer(*user_id)),
                ]),
            );
            db.insert(insert_query, &auth).await.unwrap();
        }

        // Pretty print the database
        let output = db.pretty_print_db(true, "database after inserts".to_string());
        println!("\n{output}");

        // Parse the JSON output to verify structure
        let json: serde_json::Value =
            serde_json::from_str(&output).expect("Output should be valid JSON");

        // Verify output contains expected content
        assert!(json["root_hash"].is_string(), "Should have root_hash");
        assert_eq!(json["table_count"], 3, "Should have 3 tables");

        let table_names = json["table_names"]
            .as_array()
            .expect("table_names should be an array");
        assert_eq!(table_names.len(), 3);

        let tables = json["tables"]
            .as_object()
            .expect("tables should be an object");
        assert!(tables.contains_key("posts"), "Should contain posts table");
        assert!(tables.contains_key("users"), "Should contain users table");

        // Check users table structure
        let users_table = &tables["users"];
        assert_eq!(users_table["name"], "users");
        assert_eq!(users_table["row_count"], 3);

        // Check posts table structure
        let posts_table = &tables["posts"];
        assert_eq!(posts_table["name"], "posts");
        assert_eq!(posts_table["row_count"], 4);

        // Verify indexes in posts table
        let indexes = posts_table["indexes"]
            .as_array()
            .expect("Should have indexes array");
        assert_eq!(indexes.len(), 1);
        assert_eq!(indexes[0]["column"], "user_id");

        // Also test individual table printing
        let users_output = db.pretty_print_table_rows("users", true);
        println!("\n{users_output}");

        let users_json: serde_json::Value =
            serde_json::from_str(&users_output).expect("Output should be valid JSON");
        assert_eq!(users_json["name"], "users");
        assert!(users_json["schema"].is_object());
        assert_eq!(users_json["row_count"], 3);
    }
}
