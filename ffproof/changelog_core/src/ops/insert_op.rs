use super::{
    column_name_set, evaluate_acl, extract_acl_columns_from_entry, make_index_put, next_id_after,
    next_id_put, parse_column_entries, read_acl_rule, read_auto_increment, read_next_id,
    read_schema_columns, read_schema_indexes, read_schema_list_columns,
    require_all_acl_columns_present, validate_max_entries, validate_not_internal_table,
    validate_same_table_row, validate_sorted_entries, validate_user_access, verify_column_absent,
    AclCheck, OpContext, OpReader, OpVerifier, OpVerifyResult, ParsedColumnEntry,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::{ReadOp, WriteOp};
use encrypted_spaces_storage_encoding::keys::{
    column_key, encode_list_parent, list_head_key, list_parent_key, list_tail_key,
    schema_next_list_number_key,
};
use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
use encrypted_spaces_storage_encoding::{classify_insert_id, InsertId};
use std::collections::{BTreeMap, BTreeSet};
/// Insert operation verifier.
///
/// # Row-ID policy
///
/// Each table declares its id-allocation mode at `create_table` time via
/// the `auto_increment` schema flag, persisted at the authenticated Merk
/// key `schema_id_mode_key(table)` and read by the verifier on dispatch:
///
/// - **AutoIncrement tables** (default): the client signs column keys
///   with the auto-ID placeholder (`row_id = 0`); the server allocates
///   `row_id` from the per-table `schema_next_id_key` counter.  The
///   verifier reads the same counter and uses its value as the row_id,
///   then emits the counter-bump Put.  Non-zero `row_id`s in the signed
///   entry are rejected.
/// - **Explicit tables**: the client signs with the real `row_id` in
///   every column key.  Any `row_id` in `[1, i64::MAX]` is accepted; the
///   verifier checks proof-of-absence for that row and does not touch
///   the counter.  `row_id = 0` is rejected.
///
/// The mode comes from the authenticated schema, not the signed entry,
/// so the server cannot pick a different mode per insert.
pub struct InsertOp;

impl OpVerifier for InsertOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_sorted_entries(entry, "insert")?;
        let parsed_entries = parse_column_entries(entry, "insert")?;

        // Derive the table from the signed entry — the entry is the
        // source of truth for everything except the auto-assigned row_id.
        let (table, entry_row_id) = validate_same_table_row(&parsed_entries, "insert", "insert")?;
        validate_not_internal_table(table, "insert")?;

        // Resolve row_id from authenticated state: for AutoAssign read
        // the `schema_next_id` counter; for Explicit take the value the
        // client baked into the signed entry.
        let auto_increment = read_auto_increment(table, "insert", reader, ctx)?;
        let row_id = match classify_insert_id(Some(entry_row_id), auto_increment)
            .map_err(|e| ChangelogError::KeyMismatch(format!("insert: {}", e.describe(table))))?
        {
            InsertId::AutoAssign => read_next_id(table, "insert", reader)?,
            InsertId::Explicit(signed_id) => signed_id,
        };

        // Reconstruct per-column keys with the resolved row_id.  For
        // AutoAssign this substitutes the placeholder `0` with the
        // counter value; for Explicit it just rebuilds keys with the
        // same row_id, returning whatever the entry already carries.
        let column_keys: Vec<Vec<u8>> = if auto_increment {
            parsed_entries
                .iter()
                .map(|parsed| column_key(table, row_id, parsed.column.as_ref()))
                .collect()
        } else {
            parsed_entries
                .iter()
                .map(|parsed| parsed.key.to_vec())
                .collect()
        };

        validate_max_entries(entry, "insert")?;

        validate_user_access(entry, OpType::Insert, "insert", reader)?;

        // Verify insert covers all columns
        let expected = read_schema_columns(table, "insert", reader, ctx)?;
        let actual = column_name_set(&parsed_entries);
        if actual.len() != expected.len() || !actual.iter().all(|col| expected.contains(*col)) {
            let missing: Vec<_> = expected
                .iter()
                .filter(|col| !actual.contains(col.as_str()))
                .collect();
            return Err(ChangelogError::Generic(format!(
                "insert: missing columns {missing:?} — \
                 inserts must cover all columns"
            )));
        }

        // Determine which columns are List columns (alphabetical order).
        let list_cols = read_schema_list_columns(table, reader, ctx)?;

        // Validate that List columns carry the placeholder value 0.
        if !list_cols.is_empty() {
            let zero_stored =
                value_to_bytes(&serde_json::json!(0)).expect("serializing 0 cannot fail");
            for parsed in &parsed_entries {
                let col_name = parsed.column.as_ref();
                if list_cols.contains(col_name) && parsed.kv.value != zero_stored {
                    return Err(ChangelogError::Generic(format!(
                        "insert: List column '{col_name}' \
                         must carry placeholder value 0"
                    )));
                }
            }
        }

        // Allocate list_numbers for List columns.
        let list_number_base = if !list_cols.is_empty() {
            let key = schema_next_list_number_key();
            let read = reader.read(ReadOp::Key(key))?;
            match read.results.first() {
                Some((_, bytes)) => {
                    if bytes.len() != 8 {
                        return Err(ChangelogError::Generic(format!(
                            "insert: schema_next_list_number_key \
                             has invalid length {}",
                            bytes.len()
                        )));
                    }
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(bytes);
                    i64::from_be_bytes(buf)
                }
                None => 1i64,
            }
        } else {
            0
        };

        let acl = read_acl_rule(reader, table, "write", ctx)?.map(|rule| {
            let mut needed = Vec::new();
            rule.collect_resource_columns(&mut needed);
            AclCheck {
                rule,
                resource_name: table.to_string(),
                needed_columns: needed,
            }
        });
        if let Some(acl) = &acl {
            let col_values = extract_acl_columns_from_entry(
                entry,
                table,
                None,
                Some(row_id),
                &acl.needed_columns,
            )?;
            require_all_acl_columns_present(&col_values, &acl.needed_columns)?;
            evaluate_acl(acl, entry.uid, &col_values, "insert")?;
        }

        // Emit one Put per column. List columns get a derived
        // Put with the allocated list_number instead of the signed placeholder.
        // Track (col_name, list_number) so the list-metadata loop below can
        // emit the per-list head/tail/parent writes in one place.
        let mut batch_ops: Vec<WriteOp> = Vec::new();
        let mut allocated_lists: Vec<(String, i64)> = Vec::new();
        for (parsed, col_key) in parsed_entries.iter().zip(column_keys.iter()) {
            let col_name = parsed.column.as_ref();
            if list_cols.contains(col_name) {
                let list_number = list_number_base
                    .checked_add(allocated_lists.len() as i64)
                    .ok_or_else(|| {
                        ChangelogError::Generic(format!(
                            "insert: list_number overflow \
                             at base={list_number_base}+offset={}",
                            allocated_lists.len()
                        ))
                    })?;
                let stored_bytes =
                    value_to_bytes(&serde_json::json!(list_number)).map_err(|e| {
                        ChangelogError::Generic(format!(
                            "insert: failed to serialize \
                             list_number {list_number}: {e}"
                        ))
                    })?;
                batch_ops.push(WriteOp::Put {
                    key: col_key.clone(),
                    value: stored_bytes,
                });
                allocated_lists.push((col_name.to_string(), list_number));
            } else {
                batch_ops.push(parsed.kv.to_batch_op(col_key));
            }
        }

        append_insert_index_puts_parsed_skip(
            &mut batch_ops,
            (table, row_id),
            &parsed_entries,
            "insert",
            reader,
            &list_cols,
            ctx,
        )?;

        if auto_increment {
            // The counter was already read to derive `row_id`; just emit
            // the bump Put.  This mirrors the server, which writes
            // `next_id = row_id + 1` after allocating from the counter.
            let next = next_id_after(row_id, table, "insert")?;
            batch_ops.push(next_id_put(table, next));
        } else {
            // Prove the target row doesn't exist via one representative
            // inserted column key. Dense-row invariant: if the row exists
            // then every schema column exists, so any single column key
            // suffices as an absence witness.
            let rep_key = column_keys
                .first()
                .ok_or_else(|| ChangelogError::Generic("insert: no column keys".to_string()))?;
            let rep_column = parsed_entries
                .first()
                .ok_or_else(|| ChangelogError::Generic("insert: no column keys".to_string()))?
                .column
                .as_ref();
            verify_column_absent(rep_key.clone(), table, row_id, rep_column, "insert", reader)?;
        }

        // Bump the list_number counter and initialize head/tail/parent
        // for each newly-allocated list.
        if !allocated_lists.is_empty() {
            let num_lists = allocated_lists.len() as i64;
            let new_counter = list_number_base.checked_add(num_lists).ok_or_else(|| {
                ChangelogError::Generic(format!(
                    "insert: list_number counter overflow \
                     at base={list_number_base}+{num_lists}"
                ))
            })?;
            batch_ops.push(WriteOp::Put {
                key: schema_next_list_number_key(),
                value: new_counter.to_be_bytes().to_vec(),
            });
            for (col_name, ln) in &allocated_lists {
                batch_ops.push(WriteOp::Put {
                    key: list_head_key(*ln),
                    value: 0i64.to_be_bytes().to_vec(),
                });
                batch_ops.push(WriteOp::Put {
                    key: list_tail_key(*ln),
                    value: 0i64.to_be_bytes().to_vec(),
                });
                batch_ops.push(WriteOp::Put {
                    key: list_parent_key(*ln),
                    value: encode_list_parent(table, row_id, col_name),
                });
            }
        }

        Ok(OpVerifyResult {
            write_steps: batch_ops,
        })
    }
}

fn inline_values_by_parsed_column<'e, 'a>(
    entries: &'e [ParsedColumnEntry<'a>],
    indexed_columns: &BTreeSet<String>,
) -> Result<BTreeMap<&'e str, &'e [u8]>, ChangelogError> {
    let mut values = BTreeMap::new();
    for parsed in entries {
        let column = parsed.column.as_ref();
        if !indexed_columns.contains(column) {
            continue;
        }
        values.insert(column, parsed.kv.value.as_slice());
    }
    Ok(values)
}

fn append_insert_index_puts_parsed_skip(
    batch_ops: &mut Vec<WriteOp>,
    target: (&str, i64),
    entries: &[ParsedColumnEntry<'_>],
    op_name: &str,
    reader: &mut dyn OpReader,
    skip_columns: &BTreeSet<String>,
    ctx: &OpContext,
) -> Result<(), ChangelogError> {
    let (table, row_id) = target;
    let indexed_columns = read_schema_indexes(table, reader, ctx)?;
    if indexed_columns.is_empty() {
        return Ok(());
    }

    let values_by_column = inline_values_by_parsed_column(entries, &indexed_columns)?;

    for indexed_column in &indexed_columns {
        if skip_columns.contains(indexed_column) {
            continue;
        }
        let value_bytes = values_by_column
            .get(indexed_column.as_str())
            .ok_or_else(|| {
                ChangelogError::Generic(format!(
                    "{op_name}: missing indexed {table} column '{indexed_column}'"
                ))
            })?;
        batch_ops.push(make_index_put(
            table,
            indexed_column,
            value_bytes,
            row_id,
            op_name,
        )?);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage, OpType};
    use crate::ops::VerifierReader;
    use crate::{ProvenRead, ReadOp};
    use encrypted_spaces_storage_encoding::encode_column_names;
    use encrypted_spaces_storage_encoding::keys::{
        acl_rule_key, column_key, column_key_placeholder, index_key,
        schema_columns_key as make_schema_key, schema_id_mode_key as make_schema_id_mode_key,
        schema_indexes_key as make_schema_indexes_key,
        schema_list_columns_key as make_schema_list_columns_key,
        schema_next_id_key as make_schema_next_id_key,
    };

    /// Proven-read for `schema_id_mode_key(table)` resolving to AutoIncrement.
    fn id_mode_auto_read(table: &str) -> ProvenRead {
        ProvenRead {
            op: ReadOp::Key(make_schema_id_mode_key(table)),
            results: vec![(make_schema_id_mode_key(table), vec![0u8])],
        }
    }

    /// Proven-read for `schema_id_mode_key(table)` resolving to Explicit.
    fn id_mode_explicit_read(table: &str) -> ProvenRead {
        ProvenRead {
            op: ReadOp::Key(make_schema_id_mode_key(table)),
            results: vec![(make_schema_id_mode_key(table), vec![1u8])],
        }
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
                op_type: OpType::Insert,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

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

    fn stored_str(value: &str) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(value)).unwrap()
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

    fn reads_with_user_and_schema(uid: u32, table: &str) -> Vec<ProvenRead> {
        let sk = user_status_key(uid);
        vec![
            id_mode_auto_read(table),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key(table)),
                results: vec![(make_schema_next_id_key(table), 5i64.to_be_bytes().to_vec())],
            },
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
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key(table)),
                results: vec![],
            },
        ]
    }

    fn reads_with_empty_user(uid: u32, table: &str) -> Vec<ProvenRead> {
        let sk = user_status_key(uid);
        vec![
            id_mode_auto_read(table),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key(table)),
                results: vec![(make_schema_next_id_key(table), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk),
                results: vec![],
            },
        ]
    }

    #[test]
    fn test_insert_op_key_prefix_validation() {
        // Entry keys use placeholder (row_id=0); the verifier rebuilds
        // per-column keys from `input.new_row_id`.
        let entry_col = column_key_placeholder("t", "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&entry_col), &[vec![0u8; 32]]);

        let schema_one_col = b"name".to_vec();
        let sk = user_status_key(1);
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(make_schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk.clone(), stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), schema_one_col.clone())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        assert!(
            InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default())
                .is_ok()
        );
    }

    #[test]
    fn test_insert_op_returns_correct_result_multi_column() {
        let value1 = vec![1u8; 32];
        let value2 = vec![2u8; 32];
        // Keys must be sorted: "age" < "name" lexicographically
        let entry_key_a = column_key_placeholder("t", "age");
        let entry_key_b = column_key_placeholder("t", "name");
        let proof_key_a = column_key("t", 5, "age");
        let proof_key_b = column_key("t", 5, "name");
        let entry = make_entry_with_columns(
            42,
            &[entry_key_a.clone(), entry_key_b.clone()],
            &[value1.clone(), value2.clone()],
        );
        let reads = reads_with_user_and_schema(42, "t");
        let mut reader = VerifierReader::new(&reads);
        let result =
            InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default())
                .unwrap();
        let ops = &result.write_steps;
        // 2 column Put + 1 counter bump Put
        assert_eq!(ops.len(), 3);
        match &ops[0] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_key_a);
                assert_eq!(value, &value1);
            }
            other => panic!("Expected Put, got: {other:?}"),
        }
        match &ops[1] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_key_b);
                assert_eq!(value, &value2);
            }
            other => panic!("Expected Put, got: {other:?}"),
        }
        match &ops[2] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_schema_next_id_key("t"));
                assert_eq!(value, &6i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected counter Put, got: {other:?}"),
        }
    }

    #[test]
    fn test_insert_op_requires_existing_user_row() {
        let entry_col = column_key_placeholder("t", "name");
        let _proof_col = column_key("t", 5, "name");
        let entry = make_entry_with_columns(42, std::slice::from_ref(&entry_col), &[vec![0u8; 32]]);

        let schema_one_col = b"name".to_vec();
        let sk = user_status_key(42);
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(make_schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), schema_one_col)],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        assert!(
            InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default())
                .is_ok()
        );

        let reads2 = reads_with_empty_user(42, "t");
        let mut reader2 = VerifierReader::new(&reads2);
        let err =
            InsertOp::extract_and_validate(&entry, &mut reader2, &super::OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("not found in users table"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_insert_op_rejects_missing_columns() {
        // Schema expects name + age, but insert only provides name
        let entry_col = column_key_placeholder("t", "name");
        let _proof_col = column_key("t", 5, "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&entry_col), &[vec![0u8; 32]]);
        let reads = reads_with_user_and_schema(1, "t"); // schema has name + age
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("missing columns"), "unexpected error: {msg}");
    }

    #[test]
    fn test_insert_op_rejects_mixed_row_ids() {
        let col_a = column_key("t", 1, "age");
        let col_b = column_key("t", 2, "name");
        let entry = make_entry_with_columns(
            1,
            &[col_a, col_b],
            &[[1u8; 32].to_vec(), [2u8; 32].to_vec()],
        );
        let reads = vec![];
        let mut reader = VerifierReader::new(&reads);

        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("one insert must bind all columns"),
            "unexpected error: {msg}"
        );
    }

    /// Verify that short Value entries produce WriteOp::Put.
    #[test]
    fn test_insert_op_emits_put_for_short_values() {
        use crate::WriteOp;
        // Two columns with short raw values (< 32 bytes)
        let entry_a = column_key_placeholder("t", "age");
        let entry_b = column_key_placeholder("t", "name");
        let proof_a = column_key("t", 5, "age");
        let proof_b = column_key("t", 5, "name");

        let age_value = stored_i64(25);
        let name_value = stored_str("Ada");

        let entries = vec![
            KvData {
                key: entry_a,
                value: age_value.clone(),
            },
            KvData {
                key: entry_b,
                value: name_value.clone(),
            },
        ];
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = reads_with_user_and_schema(1, "t");
        let mut reader = VerifierReader::new(&reads);
        let result =
            InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default())
                .unwrap();

        let ops = &result.write_steps;
        // 2 column Puts + 1 counter bump Put (schema_next_id_key)
        assert_eq!(ops.len(), 3);
        // Both column puts should be Put since values are short
        match &ops[0] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_a);
                assert_eq!(value, &age_value);
            }
            other => panic!("Expected Put for short value, got: {other:?}"),
        }
        match &ops[1] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_b);
                assert_eq!(value, &name_value);
            }
            other => panic!("Expected Put for short value, got: {other:?}"),
        }
        // Counter bump: row_id 5 → next_id 6
        match &ops[2] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_schema_next_id_key("t"));
                assert_eq!(value, &6i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected counter Put, got: {other:?}"),
        }
    }

    #[test]
    fn test_insert_op_allows_large_nonindexed_columns_with_indexed_table() {
        let entry_a = column_key_placeholder("t", "age");
        let entry_b = column_key_placeholder("t", "name");
        let proof_a = column_key("t", 5, "age");
        let proof_b = column_key("t", 5, "name");

        let age_value = stored_i64(25);
        let long_name_value = vec![b'a'; 64];

        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries: vec![
                    KvData {
                        key: entry_a,
                        value: age_value.clone(),
                    },
                    KvData {
                        key: entry_b,
                        value: long_name_value.clone(),
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(make_schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
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
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![(make_schema_indexes_key("t"), b"age".to_vec())],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let result =
            InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default())
                .unwrap();

        let ops = &result.write_steps;
        // 2 columns + 1 index (age) + 1 counter bump
        assert_eq!(ops.len(), 4);
        assert!(
            matches!(&ops[0], WriteOp::Put { key, value } if key == &proof_a && value == &age_value)
        );
        assert!(
            matches!(&ops[1], WriteOp::Put { key, value } if key == &proof_b && value == &long_name_value)
        );

        let expected_index_key = index_key("t", "age", 25i64, 5).unwrap();
        assert!(
            matches!(&ops[2], WriteOp::Put { key, value } if key == &expected_index_key && value == &5i64.to_be_bytes().to_vec())
        );

        // Counter bump: row_id 5 → next_id 6
        assert!(
            matches!(&ops[3], WriteOp::Put { key, value } if key == &make_schema_next_id_key("t") && value == &6i64.to_be_bytes().to_vec())
        );
    }

    #[test]
    fn test_insert_op_rejects_reserved_table() {
        let entry_col = column_key_placeholder("_users", "name");
        let _proof_col = column_key("_users", 5, "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&entry_col), &[vec![0u8; 32]]);
        let sk = user_status_key(1);
        let reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("reserved"), "unexpected error: {msg}");
        assert!(msg.contains("_users"), "unexpected error: {msg}");
    }

    // ─── ACL tests ────────────────────────────────────────────────────────

    use encrypted_spaces_acl_types::{AccessRule, ColumnNamespace, ComparisonOp, RuleValue};

    /// Schema for "posts" table: columns author_id, title (null-separated, sorted).
    fn posts_schema_value() -> Vec<u8> {
        b"author_id\0title".to_vec()
    }

    /// Test 5a: Insert with mismatched author_id should be denied.
    /// Entry uid=42 but the entry carries author_id=99.
    #[test]
    fn test_insert_acl_denies_mismatched_author_id() {
        let entry_author = column_key_placeholder("posts", "author_id");
        let entry_title = column_key_placeholder("posts", "title");
        let _proof_author = column_key("posts", 5, "author_id");
        let _proof_title = column_key("posts", 5, "title");

        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 42,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries: vec![
                    KvData {
                        key: entry_author,
                        value: stored_i64(99), // mismatched!
                    },
                    KvData {
                        key: entry_title,
                        value: stored_str("hello"),
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            id_mode_auto_read("posts"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("posts")),
                results: vec![(
                    make_schema_next_id_key("posts"),
                    5i64.to_be_bytes().to_vec(),
                )],
            },
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
            acl_rule_read(
                "posts",
                &AccessRule::comparison(
                    RuleValue::column(ColumnNamespace::Resource, "author_id"),
                    ComparisonOp::Equal,
                    RuleValue::AuthUserId,
                ),
            ),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("posts")),
                results: vec![],
            },
        ];
        let ctx = super::OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("ACL denied: insert"),
            "unexpected error: {msg}"
        );
    }

    /// Test 5b: Insert with matching author_id should be allowed.
    #[test]
    fn test_insert_acl_allows_matching_author_id() {
        let entry_author = column_key_placeholder("posts", "author_id");
        let entry_title = column_key_placeholder("posts", "title");
        let _proof_author = column_key("posts", 5, "author_id");
        let _proof_title = column_key("posts", 5, "title");

        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 42,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries: vec![
                    KvData {
                        key: entry_author,
                        value: stored_i64(42), // matches uid
                    },
                    KvData {
                        key: entry_title,
                        value: stored_str("hello"),
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            id_mode_auto_read("posts"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("posts")),
                results: vec![(
                    make_schema_next_id_key("posts"),
                    5i64.to_be_bytes().to_vec(),
                )],
            },
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
            acl_rule_read(
                "posts",
                &AccessRule::comparison(
                    RuleValue::column(ColumnNamespace::Resource, "author_id"),
                    ComparisonOp::Equal,
                    RuleValue::AuthUserId,
                ),
            ),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("posts")),
                results: vec![],
            },
        ];
        let ctx = super::OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let result = InsertOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    /// Auto-increment insert with `id == AuthUserId` ACL: the resolved
    /// row_id (5) must be used for evaluation, not the placeholder (0).
    /// uid=5 inserting into a table where next_id=5 → allowed.
    #[test]
    fn test_insert_acl_id_column_uses_resolved_row_id() {
        let entry_author = column_key_placeholder("posts", "author_id");
        let entry_title = column_key_placeholder("posts", "title");

        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 5,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries: vec![
                    KvData {
                        key: entry_author,
                        value: stored_i64(5),
                    },
                    KvData {
                        key: entry_title,
                        value: stored_str("hello"),
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            id_mode_auto_read("posts"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("posts")),
                results: vec![(
                    make_schema_next_id_key("posts"),
                    5i64.to_be_bytes().to_vec(),
                )],
            },
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
            acl_rule_read(
                "posts",
                &AccessRule::comparison(
                    RuleValue::column(ColumnNamespace::Resource, "id"),
                    ComparisonOp::Equal,
                    RuleValue::AuthUserId,
                ),
            ),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("posts")),
                results: vec![],
            },
        ];
        let ctx = super::OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let result = InsertOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(
            result.is_ok(),
            "expected Ok but got: {:?}",
            result.unwrap_err()
        );
    }

    /// Auto-increment insert with `id == AuthUserId` ACL: uid=99 but
    /// resolved row_id is 5 → denied.
    #[test]
    fn test_insert_acl_id_column_denies_wrong_uid() {
        let entry_author = column_key_placeholder("posts", "author_id");
        let entry_title = column_key_placeholder("posts", "title");

        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 99,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries: vec![
                    KvData {
                        key: entry_author,
                        value: stored_i64(99),
                    },
                    KvData {
                        key: entry_title,
                        value: stored_str("hello"),
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![
            id_mode_auto_read("posts"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("posts")),
                results: vec![(
                    make_schema_next_id_key("posts"),
                    5i64.to_be_bytes().to_vec(),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(user_status_key(99)),
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
            acl_rule_read(
                "posts",
                &AccessRule::comparison(
                    RuleValue::column(ColumnNamespace::Resource, "id"),
                    ComparisonOp::Equal,
                    RuleValue::AuthUserId,
                ),
            ),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("posts")),
                results: vec![],
            },
        ];
        let ctx = super::OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        };
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &ctx);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("ACL denied: insert"),
            "unexpected error: {msg}"
        );
    }

    /// Auto-increment tables reject any insert whose signed entry carries
    /// an explicit row_id.
    #[test]
    fn test_insert_op_rejects_explicit_id_on_autoincrement_table() {
        let col_name = column_key("t", i64::MAX, "name");
        // Explicit-ID signed entry on an AutoIncrement table.
        let entry = make_entry_with_columns(1, std::slice::from_ref(&col_name), &[vec![0u8; 32]]);

        // Only the id_mode read is consumed before the dispatch rejects.
        let reads = vec![id_mode_auto_read("t")];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("auto-increment") && msg.contains("remove the explicit id"),
            "unexpected error: {msg}"
        );
    }

    /// Negative row_ids are nonsense — the counter never allocates them.
    #[test]
    fn test_insert_op_rejects_negative_entry_row_id() {
        let col_name = column_key("t", -7, "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&col_name), &[vec![0u8; 32]]);

        // The id_mode read happens before the negative-id check; seed it.
        let reads = vec![id_mode_explicit_read("t")];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("must be non-negative"),
            "unexpected error: {msg}"
        );
    }

    /// Explicit-ID tables accept an insert at `row_id == i64::MAX`: with no
    /// auto-ID counter to corrupt, the previous attack vector is gone.
    #[test]
    fn test_insert_op_explicit_table_allows_i64_max() {
        let explicit_id = i64::MAX;
        let col_name = column_key("t", explicit_id, "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&col_name), &[vec![0u8; 32]]);

        let schema_one_col = b"name".to_vec();
        let sk = user_status_key(1);
        let rep_key = column_key("t", explicit_id, "name");
        let reads = vec![
            id_mode_explicit_read("t"),
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), schema_one_col)],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Key(rep_key),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let result =
            InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default())
                .expect("explicit-mode insert at i64::MAX should succeed");

        let ops = &result.write_steps;
        // One column Put; no counter Put at schema_next_id_key.
        for op in ops {
            assert_ne!(
                crate::ops::write_op_key(op),
                make_schema_next_id_key("t").as_slice(),
                "explicit-mode insert must not bump next_id"
            );
        }
    }

    /// Explicit-ID tables reject an auto-ID signed entry (row_id = 0).
    #[test]
    fn test_insert_op_rejects_auto_id_on_explicit_table() {
        let entry_col = column_key_placeholder("t", "name");
        let _proof_col = column_key("t", 5, "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&entry_col), &[vec![0u8; 32]]);

        let reads = vec![id_mode_explicit_read("t")];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("requires an explicit id"),
            "unexpected error: {msg}"
        );
    }

    /// Explicit-mode inserts still enforce proof-of-absence — rejecting an
    /// insert that would overwrite an existing row.
    #[test]
    fn test_insert_op_explicit_table_verifies_row_absent_still_enforced() {
        let explicit_id = 7i64;
        let col_name = column_key("t", explicit_id, "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&col_name), &[vec![0u8; 32]]);

        let schema_one_col = b"name".to_vec();
        let sk = user_status_key(1);
        let rep_key = column_key("t", explicit_id, "name");
        let reads = vec![
            id_mode_explicit_read("t"),
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), schema_one_col)],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Key(rep_key.clone()),
                // Non-empty result: the representative column already exists.
                results: vec![(rep_key, b"\"existing\"".to_vec())],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("already exists"), "unexpected error: {msg}");
    }

    /// Auto-ID insert where the stored counter is already `i64::MAX` must
    /// be rejected as counter exhaustion.  Honest exhaustion — not an
    /// attack — since auto-mode tables no longer accept explicit ids.
    #[test]
    fn test_insert_op_rejects_auto_id_when_counter_at_i64_max() {
        let entry_col = column_key_placeholder("t", "name");
        let _proof_col = column_key("t", i64::MAX, "name");
        let entry = make_entry_with_columns(1, std::slice::from_ref(&entry_col), &[vec![0u8; 32]]);

        let schema_one_col = b"name".to_vec();
        let sk = user_status_key(1);
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(
                    make_schema_next_id_key("t"),
                    i64::MAX.to_be_bytes().to_vec(),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), schema_one_col)],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("next_id counter exhausted"),
            "unexpected error: {msg}"
        );
    }

    // ─── List column allocation tests ──────────────────────────────────────

    use encrypted_spaces_storage_encoding::keys::{
        encode_list_parent as make_encode_list_parent, list_head_key as make_list_head_key,
        list_parent_key as make_list_parent_key, list_tail_key as make_list_tail_key,
        schema_next_list_number_key as make_schema_next_list_number_key,
    };

    fn list_columns_value(cols: &[&str]) -> Vec<u8> {
        let set: std::collections::BTreeSet<String> = cols.iter().map(|s| s.to_string()).collect();
        encode_column_names(&set)
    }

    /// Insert a row with one List column. The placeholder 0 is accepted,
    /// list_number is allocated from a missing counter (starts at 1), and
    /// head/tail keys are initialized.
    #[test]
    fn test_insert_op_list_column_allocates_from_missing_counter() {
        let entry_name = column_key_placeholder("t", "items");
        let entry_title = column_key_placeholder("t", "title");
        let proof_items = column_key("t", 5, "items");
        let proof_title = column_key("t", 5, "title");

        let zero_stored = stored_i64(0);
        let title_value = stored_str("hello");

        let entries = vec![
            KvData {
                key: entry_name,
                value: zero_stored.clone(),
            },
            KvData {
                key: entry_title,
                value: title_value.clone(),
            },
        ];
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let sk = user_status_key(1);
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(make_schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), b"items\0title".to_vec())],
            },
            // schema_list_columns_key: "items" is a List column
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![(
                    make_schema_list_columns_key("t"),
                    list_columns_value(&["items"]),
                )],
            },
            // schema_next_list_number_key: missing → starts at 1
            ProvenRead {
                op: ReadOp::Key(make_schema_next_list_number_key()),
                results: vec![],
            },
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let result =
            InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default())
                .unwrap();

        let ops = &result.write_steps;
        // Expected ops:
        // 0: Put items column with list_number=1 (derived)
        // 1: Put title column (normal)
        // 2: counter bump (schema_next_id_key → 6)
        // 3: list_number counter bump (→ 2)
        // 4: list_head_key(1) = 0
        // 5: list_tail_key(1) = 0
        // 6: list_parent_key(1) = encode_list_parent("t", 5, "items")
        assert_eq!(ops.len(), 7, "ops: {ops:?}");

        // List column gets stored list_number=1
        let expected_list_stored = value_to_bytes(&serde_json::json!(1)).unwrap();
        match &ops[0] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_items);
                assert_eq!(value, &expected_list_stored);
            }
            other => panic!("Expected Put for list column, got: {other:?}"),
        }

        // Normal column
        match &ops[1] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_title);
                assert_eq!(value, &title_value);
            }
            other => panic!("Expected Put for title, got: {other:?}"),
        }

        // Row ID counter bump
        match &ops[2] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_schema_next_id_key("t"));
                assert_eq!(value, &6i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected counter Put, got: {other:?}"),
        }

        // List number counter bump (1 + 1 = 2)
        match &ops[3] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_schema_next_list_number_key());
                assert_eq!(value, &2i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected list counter Put, got: {other:?}"),
        }

        // list_head_key(1) = 0
        match &ops[4] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_list_head_key(1));
                assert_eq!(value, &0i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected head Put, got: {other:?}"),
        }

        // list_tail_key(1) = 0
        match &ops[5] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_list_tail_key(1));
                assert_eq!(value, &0i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected tail Put, got: {other:?}"),
        }

        // list_parent_key(1) = encode_list_parent("t", 5, "items")
        match &ops[6] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_list_parent_key(1));
                assert_eq!(value, &make_encode_list_parent("t", 5, "items"));
            }
            other => panic!("Expected parent Put, got: {other:?}"),
        }
    }

    /// Insert with multiple List columns allocates consecutive list_numbers
    /// in alphabetical order.
    #[test]
    fn test_insert_op_multiple_list_columns_consecutive() {
        // Schema: "notes" and "tasks" are both List columns, "title" is normal
        // Alphabetical order: notes < tasks < title
        let entry_notes = column_key_placeholder("t", "notes");
        let entry_tasks = column_key_placeholder("t", "tasks");
        let entry_title = column_key_placeholder("t", "title");
        let proof_notes = column_key("t", 5, "notes");
        let proof_tasks = column_key("t", 5, "tasks");
        let proof_title = column_key("t", 5, "title");

        let zero_stored = stored_i64(0);
        let title_value = stored_str("hi");

        let entries = vec![
            KvData {
                key: entry_notes,
                value: zero_stored.clone(),
            },
            KvData {
                key: entry_tasks,
                value: zero_stored.clone(),
            },
            KvData {
                key: entry_title,
                value: title_value.clone(),
            },
        ];
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let sk = user_status_key(1);
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(make_schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), b"notes\0tasks\0title".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![(
                    make_schema_list_columns_key("t"),
                    list_columns_value(&["notes", "tasks"]),
                )],
            },
            // Counter at 5 → allocates 5 and 6
            ProvenRead {
                op: ReadOp::Key(make_schema_next_list_number_key()),
                results: vec![(
                    make_schema_next_list_number_key(),
                    5i64.to_be_bytes().to_vec(),
                )],
            },
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let result =
            InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default())
                .unwrap();

        let ops = &result.write_steps;
        // 3 columns + 1 row counter + 1 list counter + 2*(head + tail + parent) = 11
        assert_eq!(ops.len(), 11, "ops: {ops:?}");

        let stored_5 = value_to_bytes(&serde_json::json!(5)).unwrap();
        let stored_6 = value_to_bytes(&serde_json::json!(6)).unwrap();

        // "notes" gets list_number=5 (first alphabetically)
        match &ops[0] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_notes);
                assert_eq!(value, &stored_5);
            }
            other => panic!("Expected Put for notes, got: {other:?}"),
        }
        // "tasks" gets list_number=6 (second alphabetically)
        match &ops[1] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_tasks);
                assert_eq!(value, &stored_6);
            }
            other => panic!("Expected Put for tasks, got: {other:?}"),
        }
        // "title" is normal
        match &ops[2] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_title);
                assert_eq!(value, &title_value);
            }
            other => panic!("Expected Put for title, got: {other:?}"),
        }

        // Row ID counter bump → 6
        match &ops[3] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_schema_next_id_key("t"));
                assert_eq!(value, &6i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected row counter Put, got: {other:?}"),
        }

        // List number counter: 5 + 2 = 7
        match &ops[4] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_schema_next_list_number_key());
                assert_eq!(value, &7i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected list counter Put, got: {other:?}"),
        }

        // For each allocated list (in alphabetical order: notes=5, tasks=6):
        // head, tail, parent
        match &ops[5] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_list_head_key(5));
                assert_eq!(value, &0i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected head(5) Put, got: {other:?}"),
        }
        match &ops[6] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_list_tail_key(5));
                assert_eq!(value, &0i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected tail(5) Put, got: {other:?}"),
        }
        match &ops[7] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_list_parent_key(5));
                assert_eq!(value, &make_encode_list_parent("t", 5, "notes"));
            }
            other => panic!("Expected parent(5) Put, got: {other:?}"),
        }
        match &ops[8] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_list_head_key(6));
                assert_eq!(value, &0i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected head(6) Put, got: {other:?}"),
        }
        match &ops[9] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_list_tail_key(6));
                assert_eq!(value, &0i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected tail(6) Put, got: {other:?}"),
        }
        match &ops[10] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_list_parent_key(6));
                assert_eq!(value, &make_encode_list_parent("t", 5, "tasks"));
            }
            other => panic!("Expected parent(6) Put, got: {other:?}"),
        }
    }

    /// Non-zero placeholder for a List column is rejected.
    #[test]
    fn test_insert_op_rejects_nonzero_list_column() {
        let entry_items = column_key_placeholder("t", "items");
        let entry_title = column_key_placeholder("t", "title");

        let nonzero_stored = stored_i64(42);
        let title_value = stored_str("hi");

        let entries = vec![
            KvData {
                key: entry_items,
                value: nonzero_stored,
            },
            KvData {
                key: entry_title,
                value: title_value,
            },
        ];
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let sk = user_status_key(1);
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(make_schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), b"items\0title".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![(
                    make_schema_list_columns_key("t"),
                    list_columns_value(&["items"]),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("List column") && msg.contains("placeholder value 0"),
            "unexpected error: {msg}"
        );
    }

    /// A non-zero List column placeholder is rejected.
    #[test]
    fn test_insert_op_rejects_nonzero_list_column_raw_bytes() {
        let entry_items = column_key_placeholder("t", "items");
        let entry_title = column_key_placeholder("t", "title");

        let title_value = stored_str("hi");

        let entries = vec![
            KvData {
                key: entry_items,
                value: vec![1u8; 32],
            },
            KvData {
                key: entry_title,
                value: title_value,
            },
        ];
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let sk = user_status_key(1);
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(make_schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), b"items\0title".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![(
                    make_schema_list_columns_key("t"),
                    list_columns_value(&["items"]),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("List column") && msg.contains("placeholder value 0"),
            "unexpected error: {msg}"
        );
    }

    /// Insert with no List columns still works as before (no extra reads).
    #[test]
    fn test_insert_op_no_list_columns_unchanged() {
        let entry_col = column_key_placeholder("t", "name");
        let proof_col = column_key("t", 5, "name");
        let name_value = stored_str("Ada");

        let entries = vec![KvData {
            key: entry_col,
            value: name_value.clone(),
        }];
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let sk = user_status_key(1);
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(make_schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), b"name".to_vec())],
            },
            // No list columns → empty result
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![],
            },
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let result =
            InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default())
                .unwrap();

        let ops = &result.write_steps;
        // 1 column Put + 1 counter bump = 2 (no list ops)
        assert_eq!(ops.len(), 2, "ops: {ops:?}");
        match &ops[0] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &proof_col);
                assert_eq!(value, &name_value);
            }
            other => panic!("Expected Put, got: {other:?}"),
        }
        match &ops[1] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &make_schema_next_id_key("t"));
                assert_eq!(value, &6i64.to_be_bytes().to_vec());
            }
            other => panic!("Expected counter Put, got: {other:?}"),
        }
    }

    /// List number counter overflow is detected and rejected.
    #[test]
    fn test_insert_op_list_number_counter_overflow() {
        let entry_items = column_key_placeholder("t", "items");
        let entry_title = column_key_placeholder("t", "title");

        let zero_stored = stored_i64(0);
        let title_value = stored_str("hi");

        let entries = vec![
            KvData {
                key: entry_items,
                value: zero_stored,
            },
            KvData {
                key: entry_title,
                value: title_value,
            },
        ];
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let sk = user_status_key(1);
        let reads = vec![
            id_mode_auto_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_next_id_key("t")),
                results: vec![(make_schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_key("t")),
                results: vec![(make_schema_key("t"), b"items\0title".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(make_schema_list_columns_key("t")),
                results: vec![(
                    make_schema_list_columns_key("t"),
                    list_columns_value(&["items"]),
                )],
            },
            // Counter at i64::MAX → overflow when adding 1
            ProvenRead {
                op: ReadOp::Key(make_schema_next_list_number_key()),
                results: vec![(
                    make_schema_next_list_number_key(),
                    i64::MAX.to_be_bytes().to_vec(),
                )],
            },
            no_acl_rule_read("t"),
            ProvenRead {
                op: ReadOp::Key(make_schema_indexes_key("t")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("list_number counter overflow"),
            "unexpected error: {msg}"
        );
    }

    /// A missing `schema_id_mode_key` is an authenticated error — every
    /// table created by `create_table` writes one.
    #[test]
    fn test_id_mode_absence_is_rejected() {
        let entry_col = column_key_placeholder("t", "name");
        let _proof_col = column_key("t", 5, "name");
        let entry = make_entry_with_columns(42, std::slice::from_ref(&entry_col), &[vec![0u8; 32]]);

        let reads = vec![ProvenRead {
            op: ReadOp::Key(make_schema_id_mode_key("t")),
            results: vec![],
        }];
        let mut reader = VerifierReader::new(&reads);
        let err = InsertOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("id_mode") && msg.contains("missing"),
            "unexpected error: {msg}"
        );
    }
}
