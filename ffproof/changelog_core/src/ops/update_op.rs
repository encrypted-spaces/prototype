use super::{
    column_name_set, evaluate_acl, make_index_delete, make_index_put, parse_column_entries,
    read_acl_rule, read_schema_columns, read_schema_indexes, read_schema_list_columns,
    unique_row_ids, validate_max_entries, validate_not_internal_table, validate_same_table,
    validate_sorted_entries, validate_user_access, AclCheck, OpContext, OpReader, OpVerifier,
    OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::{ReadOp, WriteOp};
use encrypted_spaces_storage_encoding::keys::column_key;
use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
use std::collections::BTreeMap;
/// Update operation verifier.
pub struct UpdateOp;

impl OpVerifier for UpdateOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_max_entries(entry, "update")?;
        validate_sorted_entries(entry, "update")?;
        validate_user_access(entry, OpType::Update, "update", reader)?;
        let parsed_entries = parse_column_entries(entry, "update")?;

        // Verify all updated columns exist in the schema
        let table = validate_same_table(&parsed_entries, "update")?;
        validate_not_internal_table(table, "update")?;
        let valid = read_schema_columns(table, "update", reader, ctx)?;
        let actual = column_name_set(&parsed_entries);
        for col_name in &actual {
            if !valid.contains(*col_name) {
                return Err(ChangelogError::Generic(format!(
                    "update: column '{col_name}' \
                     does not exist in schema"
                )));
            }
        }

        // Reject updates to List columns — they are managed by list operations.
        let list_cols = read_schema_list_columns(table, reader, ctx)?;
        for col_name in &actual {
            if list_cols.contains(*col_name) {
                return Err(ChangelogError::Generic(format!(
                    "update: column '{col_name}' is a List column \
                     and cannot be modified by UPDATE — use list operations instead"
                )));
            }
        }

        // Collect unique row_ids from column keys, keeping one representative
        // updated column key per row for a fallback existence check.
        let update_row_ids = unique_row_ids(&parsed_entries);
        let mut row_representatives: BTreeMap<i64, (&str, &[u8])> = BTreeMap::new();
        let mut updated_by_row_col = BTreeMap::new();
        for parsed in &parsed_entries {
            let column = parsed.column.as_ref();
            row_representatives
                .entry(parsed.row_id)
                .or_insert((column, parsed.key));
            updated_by_row_col.insert((parsed.row_id, column), parsed.kv);
        }

        let acl = read_acl_rule(reader, table, "write", ctx)?.map(|rule| {
            let mut needed = Vec::new();
            rule.collect_resource_columns(&mut needed);
            AclCheck {
                rule,
                resource_name: table.to_string(),
                needed_columns: needed,
            }
        });

        let indexed_columns = read_schema_indexes(table, reader, ctx)?;

        // Plan every old column value read once. Any real old column value
        // proves row existence under the dense-row invariant, so ACL/index
        // reads double as presence reads. Synthetic ACL `id` is derived from
        // row_id and must not count as existence evidence.
        let mut old_value_reads: BTreeMap<(i64, &str), Vec<u8>> = BTreeMap::new();
        if let Some(acl) = &acl {
            for row_id in &update_row_ids {
                for column in &acl.needed_columns {
                    if column == "id" {
                        continue;
                    }
                    old_value_reads
                        .entry((*row_id, column.as_str()))
                        .or_insert_with(|| column_key(table, *row_id, column));
                }
            }
        }
        for &(row_id, column) in updated_by_row_col.keys() {
            if indexed_columns.contains(column) {
                old_value_reads
                    .entry((row_id, column))
                    .or_insert_with(|| column_key(table, row_id, column));
            }
        }
        for row_id in &update_row_ids {
            let has_real_old_value_read = old_value_reads.keys().any(|(rid, _)| rid == row_id);
            if !has_real_old_value_read {
                let (column, key) = row_representatives.get(row_id).ok_or_else(|| {
                    ChangelogError::Generic(format!(
                        "update: missing representative column for row_id={row_id}"
                    ))
                })?;
                old_value_reads.insert((*row_id, *column), key.to_vec());
            }
        }

        let mut old_values: BTreeMap<(i64, &str), Option<Vec<u8>>> = BTreeMap::new();
        for ((row_id, column), key) in old_value_reads {
            let read = reader.read(ReadOp::Key(key))?;
            let value = read.results.first().map(|(_, bytes)| bytes.clone());
            old_values.insert((row_id, column), value);
        }

        for row_id in &update_row_ids {
            let row_exists = old_values
                .iter()
                .any(|((rid, _), value)| rid == row_id && value.is_some());
            if !row_exists {
                return Err(ChangelogError::Generic(format!(
                    "update: {table} row_id={row_id} does not exist; \
                     all planned old column reads were absent"
                )));
            }
        }

        if let Some(acl) = &acl {
            for &row_id in &update_row_ids {
                let mut existing_values = Vec::new();
                for column in &acl.needed_columns {
                    if column == "id" {
                        let bytes =
                            value_to_bytes(&serde_json::Value::from(row_id)).map_err(|e| {
                                ChangelogError::Generic(format!(
                                    "encode synthesized id for row {row_id}: {e}"
                                ))
                            })?;
                        existing_values.push((column.clone(), bytes));
                    } else if let Some(Some(bytes)) = old_values.get(&(row_id, column.as_str())) {
                        existing_values.push((column.clone(), bytes.clone()));
                    }
                }
                evaluate_acl(acl, entry.uid, &existing_values, "update existing")?;
            }

            // Validation: check new values per row. Only rows whose updated
            // columns intersect needed_columns (excluding synthesized `id`)
            // need the "update new" check. Evaluating per-row prevents a
            // multi-row entry from hiding a forbidden value behind a later
            // allowed one for the same column name.
            for &row_id in &update_row_ids {
                let touches_needed_column = parsed_entries.iter().any(|parsed| {
                    parsed.row_id == row_id
                        && parsed.column != "id"
                        && acl
                            .needed_columns
                            .iter()
                            .any(|c| c == parsed.column.as_ref())
                });
                if !touches_needed_column {
                    continue;
                }
                let row_values = super::extract_acl_columns_from_entry(
                    entry,
                    table,
                    Some(row_id),
                    Some(row_id),
                    &acl.needed_columns,
                )?;
                evaluate_acl(acl, entry.uid, &row_values, "update new")?;
            }
        }

        // Emit one Put per changed column
        let mut batch_ops: Vec<WriteOp> = parsed_entries
            .iter()
            .map(|parsed| parsed.kv.to_batch_op(parsed.key))
            .collect();

        // Construct index Delete+Put ops
        if !indexed_columns.is_empty() {
            for ((row_id, column), kv) in &updated_by_row_col {
                if !indexed_columns.contains(*column) {
                    continue;
                }

                if let Some(Some(old_val)) = old_values.get(&(*row_id, *column)) {
                    batch_ops.push(make_index_delete(
                        table, column, old_val, *row_id, "update",
                    )?);
                }

                batch_ops.push(make_index_put(table, column, &kv.value, *row_id, "update")?);
            }
        }

        Ok(OpVerifyResult {
            write_steps: batch_ops,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage, OpType};
    use crate::ops::VerifierReader;
    use crate::{ProvenRead, ReadOp};
    use encrypted_spaces_acl_types::AccessRule;
    use encrypted_spaces_storage_encoding::keys::{
        acl_rule_key, column_key, schema_columns_key as make_schema_key,
        schema_indexes_key as make_schema_indexes_key,
        schema_list_columns_key as make_schema_list_columns_key,
    };

    /// Compact column-names value for table "t" with columns name, age.
    fn schema_columns_value() -> Vec<u8> {
        b"age\0name".to_vec()
    }

    fn make_entry_with_columns(
        uid: u32,
        column_keys: &[Vec<u8>],
        values: &[Vec<u8>],
    ) -> ChangelogEntry {
        let entries: Vec<KvData> = column_keys
            .iter()
            .zip(values.iter())
            .map(|(key, value)| KvData {
                key: key.clone(),
                value: value.clone(),
            })
            .collect();
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn make_update_entry(uid: u32, entries: Vec<KvData>) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn user_status_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "status")
    }

    fn stored_i64(value: i64) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    /// Build a `ProvenRead` for a column read that can prove row presence
    /// under the dense-row invariant.
    fn column_present_read(table: &str, row_id: i64, column: &str) -> ProvenRead {
        let ck = column_key(table, row_id, column);
        ProvenRead {
            op: ReadOp::Key(ck.clone()),
            results: vec![(ck, vec![1])],
        }
    }

    fn column_absent_read(table: &str, row_id: i64, column: &str) -> ProvenRead {
        let ck = column_key(table, row_id, column);
        ProvenRead {
            op: ReadOp::Key(ck),
            results: vec![],
        }
    }

    fn column_value_read(table: &str, row_id: i64, column: &str, value: Vec<u8>) -> ProvenRead {
        let ck = column_key(table, row_id, column);
        ProvenRead {
            op: ReadOp::Key(ck.clone()),
            results: vec![(ck, value)],
        }
    }

    /// ProvenRead for `acl_rule_key(table, "write")` returning no rule
    /// (default-open semantics).
    fn no_acl_rule_read(table: &str) -> ProvenRead {
        ProvenRead {
            op: ReadOp::Key(acl_rule_key(table, "write")),
            results: vec![],
        }
    }

    /// ProvenRead for `acl_rule_key(table, "write")` returning a specific rule.
    fn acl_rule_read(table: &str, rule: &AccessRule) -> ProvenRead {
        let key = acl_rule_key(table, "write");
        let blob = postcard::to_allocvec(rule).unwrap();
        ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, blob)],
        }
    }

    fn schema_indexes_read(table: &str, columns: &[&str]) -> ProvenRead {
        let key = make_schema_indexes_key(table);
        let value = columns.join("\0").into_bytes();
        let results = if columns.is_empty() {
            vec![]
        } else {
            vec![(key.clone(), value)]
        };
        ProvenRead {
            op: ReadOp::Key(key),
            results,
        }
    }

    fn reads_with_user_and_schema(
        uid: u32,
        table: &str,
        row_id: i64,
        rep_column: &str,
    ) -> Vec<ProvenRead> {
        let sk = user_status_key(uid);
        vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key(table)),
                results: vec![(make_schema_key(table), schema_columns_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key(table)),
                results: vec![],
            },
            no_acl_rule_read(table),
            schema_indexes_read(table, &[]),
            column_present_read(table, row_id, rep_column),
        ]
    }

    fn reads_with_empty_user(uid: u32) -> Vec<ProvenRead> {
        let sk = user_status_key(uid);
        vec![ProvenRead {
            op: ReadOp::Key(sk),
            results: vec![],
        }]
    }

    #[test]
    fn test_update_op_key_exact_match() {
        let col = column_key("t", 5, "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&col), &[vec![0u8; 32]]);

        // Column key is taken from the signed entry; the verifier always
        // operates on the entry's keys directly.
        let reads = reads_with_user_and_schema(1, "t", 5, "name");
        let mut reader = VerifierReader::new(&reads);
        assert!(UpdateOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            }
        )
        .is_ok());
    }

    #[test]
    fn test_update_op_returns_correct_result_multi_column() {
        let value1 = vec![1u8; 32];
        let value2 = vec![2u8; 32];
        // Keys must be sorted: "age" < "name" lexicographically
        let col_a = column_key("t", 5, "age");
        let col_b = column_key("t", 5, "name");
        let entry = make_entry_with_columns(
            42,
            &[col_a.clone(), col_b.clone()],
            &[value1.clone(), value2.clone()],
        );
        let reads = reads_with_user_and_schema(42, "t", 5, "age");
        let mut reader = VerifierReader::new(&reads);
        let result = UpdateOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        )
        .unwrap();
        let ops = &result.write_steps;
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_update_op_requires_existing_user_row() {
        let col = column_key("t", 5, "name");
        let entry = make_entry_with_columns(42, std::slice::from_ref(&col), &[vec![0u8; 32]]);

        let reads = reads_with_user_and_schema(42, "t", 5, "name");
        let mut reader = VerifierReader::new(&reads);
        assert!(UpdateOp::extract_and_validate(
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
        let err = UpdateOp::extract_and_validate(
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
        assert!(
            msg.contains("not found in users table"),
            "unexpected error: {msg}"
        );
    }

    /// Update targeting a non-existent row must fail: the representative
    /// column key read returns empty, proving the row is absent under the
    /// dense-row invariant.
    #[test]
    fn test_update_op_rejects_missing_row_via_representative_column() {
        let col = column_key("t", 5, "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&col), &[[0u8; 32].to_vec()]);

        let sk = user_status_key(1);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), schema_columns_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            schema_indexes_read("t", &[]),
            // Representative column absent — row does not exist.
            column_absent_read("t", 5, "name"),
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = UpdateOp::extract_and_validate(
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
        assert!(
            msg.contains("does not exist") && msg.contains("planned old column reads"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_update_op_rejects_unknown_column() {
        // Schema has name + age, but update references "nonexistent"
        let col = column_key("t", 5, "nonexistent");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&col), &[vec![0u8; 32]]);
        let reads = reads_with_user_and_schema(1, "t", 5, "name"); // schema has name + age
        let mut reader = VerifierReader::new(&reads);
        let err = UpdateOp::extract_and_validate(
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
        assert!(
            msg.contains("does not exist in schema"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_update_op_rejects_reserved_table() {
        let col = column_key("_users", 5, "status");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&col), &[vec![0u8; 32]]);
        let sk = user_status_key(1);
        let reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        let mut reader = VerifierReader::new(&reads);
        let err = UpdateOp::extract_and_validate(
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

    #[test]
    fn test_update_op_rejects_mixed_tables() {
        let col_a = column_key("a", 5, "name");
        let col_b = column_key("b", 5, "name");
        let entry = make_entry_with_columns(
            1,
            &[col_a, col_b],
            &[[1u8; 32].to_vec(), [2u8; 32].to_vec()],
        );
        let sk = user_status_key(1);
        let reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        let mut reader = VerifierReader::new(&reads);
        let err = UpdateOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        );
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("all column_keys must refer to the same table"),
            "unexpected error: {msg}"
        );
    }

    /// Verify that short Value entries produce WriteOp::Put.
    #[test]
    fn test_update_op_emits_put_for_short_values() {
        use crate::WriteOp;
        let col = column_key("t", 5, "name");
        let short_value = b"\"Ada\"".to_vec(); // 5 bytes

        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col.clone(),
                    value: short_value.clone(),
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = reads_with_user_and_schema(1, "t", 5, "name");
        let mut reader = VerifierReader::new(&reads);
        let result = UpdateOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        )
        .unwrap();

        let ops = &result.write_steps;
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &col);
                assert_eq!(value, &short_value);
            }
            other => panic!("Expected Put for short value, got: {other:?}"),
        }
    }

    #[test]
    fn test_update_nonindexed_column_on_indexed_table_skips_old_index_reads() {
        let col_name = column_key("t", 5, "name");
        let entry =
            make_entry_with_columns(1, std::slice::from_ref(&col_name), &[[7u8; 32].to_vec()]);

        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(1)),
                results: vec![(user_status_key(1), stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), schema_columns_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            schema_indexes_read("t", &["age"]),
            column_present_read("t", 5, "name"),
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = UpdateOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        )
        .unwrap();
        reader.assert_all_consumed().unwrap();

        let ops = &result.write_steps;
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_update_indexed_column_uses_old_indexed_value_for_presence() {
        let col_age = column_key("t", 5, "age");
        let entry = make_update_entry(
            1,
            vec![KvData {
                key: col_age,
                value: stored_i64(30),
            }],
        );

        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(1)),
                results: vec![(user_status_key(1), stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), schema_columns_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            schema_indexes_read("t", &["age"]),
            column_value_read("t", 5, "age", stored_i64(25)),
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = UpdateOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        )
        .unwrap();
        reader.assert_all_consumed().unwrap();

        let ops = &result.write_steps;
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn test_update_multirow_plans_presence_independently() {
        let col_r1_age = column_key("t", 1, "age");
        let col_r2_name = column_key("t", 2, "name");
        let entry = make_update_entry(
            1,
            vec![
                KvData {
                    key: col_r1_age,
                    value: stored_i64(30),
                },
                KvData {
                    key: col_r2_name,
                    value: vec![8u8; 32],
                },
            ],
        );

        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(1)),
                results: vec![(user_status_key(1), stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), schema_columns_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            schema_indexes_read("t", &["age"]),
            column_value_read("t", 1, "age", stored_i64(25)),
            column_present_read("t", 2, "name"),
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = UpdateOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext {
                current_change_id: 0,
                action_name: None,
                ..Default::default()
            },
        )
        .unwrap();
        reader.assert_all_consumed().unwrap();

        let ops = &result.write_steps;
        assert_eq!(ops.len(), 4);
    }

    // ─── ACL tests ────────────────────────────────────────────────────────

    use encrypted_spaces_acl_types::{ColumnNamespace, ComparisonOp, RuleValue};

    /// Helper: ResourceColumn("author_id") == AuthUserId.
    fn author_id_acl_rule() -> AccessRule {
        AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        )
    }

    /// Helper: ResourceColumn("id") == AuthUserId.
    fn id_acl_rule() -> AccessRule {
        AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        )
    }

    /// Schema for "posts" table: columns author_id, title (null-separated, sorted).
    fn posts_schema_value() -> Vec<u8> {
        b"author_id\0title".to_vec()
    }

    /// Test 1: Attacker (uid=99) tries to update a row owned by uid=42.
    /// The existing tree value for author_id is 42, so the "update existing"
    /// check must deny the operation.
    #[test]
    fn test_update_acl_denies_unauthorized_update() {
        let col_title = column_key("posts", 5, "title");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 99, // attacker
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_title.clone(),
                    value: vec![0u8; 32],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            // user existence
            ProvenRead {
                op: ReadOp::Key(user_status_key(99)),
                results: vec![(vec![1], vec![2])],
            },
            // schema
            ProvenRead {
                op: ReadOp::Key(make_schema_key("posts")),
                results: vec![(make_schema_key("posts"), posts_schema_value())],
            },
            // list columns (none)
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("posts")),
                results: vec![],
            },
            // ACL blob
            acl_rule_read("posts", &author_id_acl_rule()),
            schema_indexes_read("posts", &[]),
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
        let err = UpdateOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("ACL denied: update existing"),
            "unexpected error: {msg}"
        );
    }

    /// Test 2: Owner (uid=42) updates a non-ACL column ("title") on their own row.
    /// The "update existing" check passes (tree author_id=42 == uid=42).
    /// The "update new" check must NOT fire because the entry doesn't touch
    /// author_id.
    #[test]
    fn test_update_acl_allows_owner_update_non_acl_column() {
        let col_title = column_key("posts", 5, "title");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 42, // owner
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_title.clone(),
                    value: vec![0u8; 32],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            // user existence
            ProvenRead {
                op: ReadOp::Key(user_status_key(42)),
                results: vec![(vec![1], vec![2])],
            },
            // schema
            ProvenRead {
                op: ReadOp::Key(make_schema_key("posts")),
                results: vec![(make_schema_key("posts"), posts_schema_value())],
            },
            // list columns (none)
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("posts")),
                results: vec![],
            },
            // ACL blob
            acl_rule_read("posts", &author_id_acl_rule()),
            // schema indexes (none for this table)
            schema_indexes_read("posts", &[]),
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
        let result = UpdateOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
        reader.assert_all_consumed().unwrap();
    }

    #[test]
    fn test_update_acl_and_index_same_column_read_once() {
        let col_author = column_key("posts", 5, "author_id");
        let entry = make_update_entry(
            42,
            vec![KvData {
                key: col_author,
                value: stored_i64(42),
            }],
        );

        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(42)),
                results: vec![(vec![1], vec![2])],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("posts")),
                results: vec![(make_schema_key("posts"), posts_schema_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("posts")),
                results: vec![],
            },
            acl_rule_read("posts", &author_id_acl_rule()),
            schema_indexes_read("posts", &["author_id"]),
            column_value_read("posts", 5, "author_id", stored_i64(42)),
        ];
        let ctx = OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let result = UpdateOp::extract_and_validate(&entry, &mut reader, &ctx).unwrap();
        reader.assert_all_consumed().unwrap();

        let ops = &result.write_steps;
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn test_update_missing_row_fails_when_planned_old_acl_read_absent() {
        let col_title = column_key("posts", 5, "title");
        let entry =
            make_entry_with_columns(42, std::slice::from_ref(&col_title), &[[9u8; 32].to_vec()]);

        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(42)),
                results: vec![(vec![1], vec![2])],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("posts")),
                results: vec![(make_schema_key("posts"), posts_schema_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("posts")),
                results: vec![],
            },
            acl_rule_read("posts", &author_id_acl_rule()),
            schema_indexes_read("posts", &[]),
            column_absent_read("posts", 5, "author_id"),
        ];
        let ctx = OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let err = UpdateOp::extract_and_validate(&entry, &mut reader, &ctx).unwrap_err();
        reader.assert_all_consumed().unwrap();
        let msg = format!("{err}");
        assert!(
            msg.contains("does not exist") && msg.contains("planned old column reads"),
            "unexpected error: {msg}"
        );
    }

    /// Test 3: Owner (uid=42) tries to reassign authorship by setting
    /// author_id=99 in the update entry. The "update existing" check passes
    /// (tree author_id=42 == uid=42) but the "update new" check must deny
    /// (new author_id=99 != uid=42).
    #[test]
    fn test_update_acl_rejects_authorship_reassignment() {
        let col_author = column_key("posts", 5, "author_id");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 42,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_author.clone(),
                    value: stored_i64(99), // forged new owner
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(42)),
                results: vec![(vec![1], vec![2])],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("posts")),
                results: vec![(make_schema_key("posts"), posts_schema_value())],
            },
            // list columns (none)
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("posts")),
                results: vec![],
            },
            // ACL blob
            acl_rule_read("posts", &author_id_acl_rule()),
            schema_indexes_read("posts", &[]),
            // existing tree value: owned by uid 42
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
        let err = UpdateOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("ACL denied: update new"),
            "unexpected error: {msg}"
        );
    }

    /// Regression: `id` is encoded in column keys, never stored as a column
    /// value. The prover must synthesize it from row_id so `id`-column ACL
    /// rules behave like the SDK side. Owner (uid=1) updates row id=1 →
    /// allowed.
    #[test]
    fn test_update_acl_resolves_id_column_from_row_id() {
        let col_title = column_key("posts", 1, "title");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_title.clone(),
                    value: vec![0u8; 32],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        // No column read for "id" — the prover must synthesize it.
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(1)),
                results: vec![(vec![1], vec![2])],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("posts")),
                results: vec![(make_schema_key("posts"), posts_schema_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("posts")),
                results: vec![],
            },
            acl_rule_read("posts", &id_acl_rule()),
            schema_indexes_read("posts", &[]),
            column_present_read("posts", 1, "title"),
        ];
        let ctx = OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let result = UpdateOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    /// Same `id == AuthUserId` rule, but uid=2 trying to update row id=1
    /// must be denied.
    #[test]
    fn test_update_acl_id_column_denies_other_actor() {
        let col_title = column_key("posts", 1, "title");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 2,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_title.clone(),
                    value: vec![0u8; 32],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(2)),
                results: vec![(vec![1], vec![2])],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("posts")),
                results: vec![(make_schema_key("posts"), posts_schema_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("posts")),
                results: vec![],
            },
            acl_rule_read("posts", &id_acl_rule()),
            schema_indexes_read("posts", &[]),
            column_present_read("posts", 1, "title"),
        ];
        let ctx = OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let err = UpdateOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("ACL denied: update existing"),
            "unexpected error: {msg}"
        );
    }

    /// Updating a non-ACL column when the ACL references `id` must NOT
    /// trigger "update new" denial. uid=5 owns row id=5, updates only
    /// `title` — the "existing" check passes and "update new" must not
    /// fire since no actual updated column is in needed_columns.
    #[test]
    fn test_update_acl_id_rule_non_acl_column_no_false_denial() {
        let col_title = column_key("posts", 5, "title");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 5,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries: vec![KvData {
                    key: col_title.clone(),
                    value: vec![0u8; 32],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(5)),
                results: vec![(vec![1], vec![2])],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("posts")),
                results: vec![(make_schema_key("posts"), posts_schema_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("posts")),
                results: vec![],
            },
            acl_rule_read("posts", &id_acl_rule()),
            schema_indexes_read("posts", &[]),
            column_present_read("posts", 5, "title"),
        ];
        let ctx = OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let result = UpdateOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    /// Multi-row update: row 1 author_id=99 (forbidden) and row 2
    /// author_id=42 (allowed). Both rows are owned by uid=42. The per-row
    /// "update new" check must deny row 1 even though row 2's value passes.
    #[test]
    fn test_update_acl_multirow_forbidden_value_not_hidden() {
        let col_r1 = column_key("posts", 1, "author_id");
        let col_r2 = column_key("posts", 2, "author_id");
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 42,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: vec![],
                entries: vec![
                    KvData {
                        key: col_r1.clone(),
                        value: stored_i64(99), // forbidden
                    },
                    KvData {
                        key: col_r2.clone(),
                        value: stored_i64(42), // allowed
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(user_status_key(42)),
                results: vec![(vec![1], vec![2])],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("posts")),
                results: vec![(make_schema_key("posts"), posts_schema_value())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("posts")),
                results: vec![],
            },
            // ACL blob
            acl_rule_read("posts", &author_id_acl_rule()),
            schema_indexes_read("posts", &[]),
            // existing values: both rows owned by uid 42
            ProvenRead {
                op: ReadOp::Key(column_key("posts", 1, "author_id")),
                results: vec![(column_key("posts", 1, "author_id"), stored_i64(42))],
            },
            ProvenRead {
                op: ReadOp::Key(column_key("posts", 2, "author_id")),
                results: vec![(column_key("posts", 2, "author_id"), stored_i64(42))],
            },
        ];
        let ctx = OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let err = UpdateOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("ACL denied: update new"),
            "unexpected error: {msg}"
        );
    }
}
