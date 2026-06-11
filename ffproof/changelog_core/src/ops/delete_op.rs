use super::{
    column_keys_from_entry, evaluate_acl, make_index_delete, read_acl_rule, read_columns_from_tree,
    read_schema_columns, read_schema_indexes, table_from_column_keys, validate_max_entries,
    validate_not_internal_table, validate_sorted_entries, validate_user_access, AclCheck,
    OpContext, OpReader, OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::{BatchOp, ReadOp, TraceStep};
use encrypted_spaces_storage_encoding::keys::{column_key, parse_key, ParsedKey};
use std::collections::{BTreeMap, BTreeSet};

/// Delete operation verifier.
pub struct DeleteOp;

impl OpVerifier for DeleteOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        let column_keys = column_keys_from_entry(entry);

        validate_max_entries(entry, "delete")?;
        validate_sorted_entries(entry, "delete")?;
        validate_user_access(entry, OpType::Delete, "delete", reader)?;

        // Verify that the delete covers all columns for each row
        let table = table_from_column_keys(&column_keys, "delete")?;
        validate_not_internal_table(&table, "delete")?;
        let expected_columns = read_schema_columns(&table, "delete", reader, ctx)?;

        // Group entry column names by row_id
        let mut columns_by_row: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
        for kv in &entry.message.entries {
            if let Ok(ParsedKey::Column { row_id, column, .. }) = parse_key(&kv.key) {
                columns_by_row.entry(row_id).or_default().insert(column);
            }
        }
        // Verify each row has all expected columns
        for (rid, actual_columns) in &columns_by_row {
            if *actual_columns != expected_columns {
                let missing: Vec<_> = expected_columns.difference(actual_columns).collect();
                return Err(ChangelogError::Generic(format!(
                    "delete: row {rid} is missing columns {missing:?} — \
                     deletes must cover all columns"
                )));
            }
        }

        let acl = read_acl_rule(reader, &table, "delete", ctx)?.map(|rule| {
            let mut needed = Vec::new();
            rule.collect_resource_columns(&mut needed);
            AclCheck {
                rule,
                resource_name: table.clone(),
                needed_columns: needed,
            }
        });
        if let Some(acl) = &acl {
            for &row_id in columns_by_row.keys() {
                let existing_values =
                    read_columns_from_tree(&table, row_id, &acl.needed_columns, reader)?;
                evaluate_acl(acl, entry.uid, &existing_values, "delete")?;
            }
        }

        // Build column delete ops
        let mut delete_ops: Vec<BatchOp> = column_keys
            .iter()
            .map(|key| BatchOp::Delete { key: key.clone() })
            .collect();

        // Read indexed columns and construct index Delete ops
        let indexed_columns = read_schema_indexes(&table, reader, ctx)?;
        if !indexed_columns.is_empty() {
            // Get unique row_ids
            let row_ids: BTreeSet<i64> = columns_by_row.keys().cloned().collect();

            for row_id in &row_ids {
                for idx_col in &indexed_columns {
                    let col_key = column_key(&table, *row_id, idx_col);
                    let col_read = reader.read(ReadOp::Key(col_key))?;

                    if let Some((_, val)) = col_read.results.first() {
                        delete_ops
                            .push(make_index_delete(&table, idx_col, val, *row_id, "delete")?);
                    }
                }
            }
        }

        Ok(OpVerifyResult {
            write_steps: vec![TraceStep::Write(delete_ops)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage, OpType};
    use crate::ops::VerifierReader;
    use crate::{ProvenRead, ReadOp};
    use encrypted_spaces_storage_encoding::keys::{
        acl_rule_key, column_key, schema_columns_key, schema_indexes_key,
    };
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;

    /// Compact column-names value for table "t" with columns name, age.
    fn schema_columns_value() -> Vec<u8> {
        b"age\0name".to_vec()
    }

    fn user_status_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "status")
    }

    fn stored_i64(value: i64) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    /// ProvenRead for `acl_rule_key(table, op)` returning no rule
    /// (default-open semantics).
    fn no_acl_rule_read(table: &str, op: &str) -> ProvenRead {
        let key = acl_rule_key(table, op);
        ProvenRead {
            op: ReadOp::Key(key),
            results: vec![],
        }
    }

    /// ProvenRead for `acl_rule_key(table, op)` returning a specific rule.
    fn acl_rule_read(table: &str, op: &str, rule: &AccessRule) -> ProvenRead {
        let key = acl_rule_key(table, op);
        let blob = postcard::to_allocvec(rule).unwrap();
        ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, blob)],
        }
    }

    /// Helper: build proven reads with a found user and schema.
    fn reads_with_user_and_schema(uid: u32, table: &str) -> Vec<ProvenRead> {
        let sk = user_status_key(uid);
        vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key(table)),
                results: vec![(schema_columns_key(table), schema_columns_value())],
            },
            no_acl_rule_read(table, "delete"),
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key(table)),
                results: vec![],
            },
        ]
    }

    /// Helper: build proven reads with a found user.
    fn reads_with_user(uid: u32) -> Vec<ProvenRead> {
        let sk = user_status_key(uid);
        vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }]
    }

    /// Helper: build proven reads with an empty user read result.
    fn reads_with_empty_user(uid: u32) -> Vec<ProvenRead> {
        let sk = user_status_key(uid);
        vec![ProvenRead {
            op: ReadOp::Key(sk),
            results: vec![],
        }]
    }

    #[test]
    fn test_delete_op_requires_column_key_entry() {
        let col_key = column_key("t", 7, "name");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_key.clone(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        // Schema with only "name" (non-id) so a single-column delete is complete
        let schema_one_col = b"name".to_vec();
        let sk = user_status_key(1);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("t")),
                results: vec![(schema_columns_key("t"), schema_one_col)],
            },
            no_acl_rule_read("t", "delete"),
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        assert!(DeleteOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            }
        )
        .is_ok());

        // Invalid: not a column key
        let bad_entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![KvData {
                    key: b"not_a_column_key".to_vec(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads2 = reads_with_user(1);
        let mut reader2 = VerifierReader::new(&reads2);
        let err = DeleteOp::extract_and_validate(
            &bad_entry,
            &mut reader2,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
    }

    #[test]
    fn test_delete_op_returns_correct_result() {
        let col_key = column_key("t", 9, "age");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 42,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_key.clone(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let schema_one_col = b"age".to_vec();
        let sk = user_status_key(42);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("t")),
                results: vec![(schema_columns_key("t"), schema_one_col)],
            },
            no_acl_rule_read("t", "delete"),
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = DeleteOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.write_steps.len(), 1);
        match &result.write_steps[0] {
            TraceStep::Write(ops) => {
                assert_eq!(ops.len(), 1);
                assert!(matches!(&ops[0], BatchOp::Delete { key } if *key == col_key));
            }
            other => panic!("Expected Write step, got: {other:?}"),
        }
    }

    #[test]
    fn test_delete_op_requires_existing_user_row() {
        let col_key = column_key("t", 11, "name");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 42,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_key.clone(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };

        let schema_one_col = b"name".to_vec();
        let sk = user_status_key(42);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("t")),
                results: vec![(schema_columns_key("t"), schema_one_col)],
            },
            no_acl_rule_read("t", "delete"),
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        assert!(DeleteOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            }
        )
        .is_ok());

        let reads2 = reads_with_empty_user(42);
        let mut reader2 = VerifierReader::new(&reads2);
        let err = DeleteOp::extract_and_validate(
            &entry,
            &mut reader2,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_delete_op_multi_column_entry() {
        let key1 = column_key("t", 1, "age");
        let key2 = column_key("t", 1, "name");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 10,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![
                    KvData {
                        key: key1.clone(),
                        value: vec![],
                    },
                    KvData {
                        key: key2.clone(),
                        value: vec![],
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = reads_with_user_and_schema(10, "t");
        let mut reader = VerifierReader::new(&reads);
        let result = DeleteOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        )
        .unwrap();
        match &result.write_steps[0] {
            TraceStep::Write(ops) => {
                assert_eq!(ops.len(), 2);
                assert!(matches!(&ops[0], BatchOp::Delete { key } if *key == key1));
                assert!(matches!(&ops[1], BatchOp::Delete { key } if *key == key2));
            }
            other => panic!("Expected Write step, got: {other:?}"),
        }
    }

    #[test]
    fn test_delete_op_rejects_unsorted_entries() {
        let key1 = column_key("t", 1, "name");
        let key2 = column_key("t", 1, "age"); // "age" < "name" lexicographically, so this is out of order
                                              // Construct entries in wrong order
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 10,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![
                    KvData {
                        key: key1.clone(),
                        value: vec![],
                    },
                    KvData {
                        key: key2.clone(),
                        value: vec![],
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = reads_with_user(10);
        let mut reader = VerifierReader::new(&reads);
        let err = DeleteOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("sorted"), "unexpected error: {msg}");
    }

    #[test]
    fn test_delete_op_rejects_missing_columns() {
        // Schema expects name + age, but delete only provides name for row 1
        let key1 = column_key("t", 1, "name");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 10,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![KvData {
                    key: key1.clone(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = reads_with_user_and_schema(10, "t"); // schema has name + age
        let mut reader = VerifierReader::new(&reads);
        let err = DeleteOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("missing columns"), "unexpected error: {msg}");
    }

    #[test]
    fn test_delete_op_rejects_reserved_table() {
        let col = column_key("_users", 5, "status");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col.clone(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = reads_with_user(1);
        let mut reader = VerifierReader::new(&reads);
        let err = DeleteOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        );
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("reserved"), "unexpected error: {msg}");
        assert!(msg.contains("_users"), "unexpected error: {msg}");
    }

    // ─── ACL tests ────────────────────────────────────────────────────────

    use encrypted_spaces_acl_types::{AccessRule, ColumnNamespace, ComparisonOp, RuleValue};

    /// Test 4: Attacker (uid=99) tries to delete a row owned by uid=42.
    /// The existing tree value for author_id is 42, so the "delete" ACL
    /// check must deny the operation.
    #[test]
    fn test_delete_acl_denies_unauthorized_delete() {
        // Schema: single column "author_id" so the delete covers all columns.
        let col_author = column_key("posts", 5, "author_id");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 99, // attacker
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_author.clone(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        );
        let reads = vec![
            // user existence
            ProvenRead {
                op: ReadOp::Key(user_status_key(99)),
                results: vec![(vec![1], vec![2])],
            },
            // schema — single column
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("posts")),
                results: vec![(schema_columns_key("posts"), b"author_id".to_vec())],
            },
            acl_rule_read("posts", "delete", &rule),
            // existing author_id from tree — owned by uid 42
            ProvenRead {
                op: ReadOp::Key(column_key("posts", 5, "author_id")),
                results: vec![(column_key("posts", 5, "author_id"), stored_i64(42))],
            },
        ];
        let ctx = OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let err = DeleteOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("ACL denied: delete"),
            "unexpected error: {msg}"
        );
    }

    /// Regression: ACL rules referencing `ResourceColumn("id")` must
    /// resolve to the row_id from the column key, since `id` is never
    /// stored as a separate column value. The owner (uid=1) deleting
    /// row id=1 under `id == AuthUserId` must succeed in the prover,
    /// matching SDK behavior.
    #[test]
    fn test_delete_acl_resolves_id_column_from_row_id() {
        let col_name = column_key("posts", 1, "name");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_name.clone(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        );
        // No column read for "id" — the prover must synthesize it.
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(1)),
                results: vec![(user_status_key(1), stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("posts")),
                results: vec![(schema_columns_key("posts"), b"name".to_vec())],
            },
            acl_rule_read("posts", "delete", &rule),
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key("posts")),
                results: vec![],
            },
        ];
        let ctx = OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let result = DeleteOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    /// Same `id == AuthUserId` rule as the test above, but uid=2 trying to
    /// delete row id=1 must be denied.
    #[test]
    fn test_delete_acl_id_column_denies_other_actor() {
        let col_name = column_key("posts", 1, "name");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 2,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_name.clone(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        );
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(2)),
                results: vec![(user_status_key(2), stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("posts")),
                results: vec![(schema_columns_key("posts"), b"name".to_vec())],
            },
            acl_rule_read("posts", "delete", &rule),
        ];
        let ctx = OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let err = DeleteOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("ACL denied: delete"),
            "unexpected error: {msg}"
        );
    }
}
