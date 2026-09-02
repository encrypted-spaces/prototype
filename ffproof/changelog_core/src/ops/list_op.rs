use super::{
    decode_i64_column_value, evaluate_acl, extract_i64_column_from_entry, make_index_delete,
    make_index_put, next_id_after, next_id_put, read_acl_rule, read_columns_from_tree,
    read_next_id, read_schema_indexes, validate_not_internal_table, validate_user_access, AclCheck,
    OpContext, OpReader, OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::{ReadOp, WriteOp};
use encrypted_spaces_storage_encoding::keys::{
    column_key, column_key_placeholder, decode_list_parent, list_head_key, list_parent_key,
    list_tail_key, parse_key, ParsedKey, LISTS_TABLE,
};
use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
pub struct ListAppendOp;
pub struct ListInsertOp;
pub struct ListUpdateOp;
pub struct ListDeleteOp;

const LISTS: &str = LISTS_TABLE;

fn read_i64_key(
    reader: &mut dyn OpReader,
    key: Vec<u8>,
    op_name: &str,
    desc: &str,
) -> Result<i64, ChangelogError> {
    let read = reader.read(ReadOp::Key(key))?;
    let Some((_, bytes)) = read.results.first() else {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: {desc} is missing"
        )));
    };
    if bytes.len() != 8 {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: {desc} has {} bytes, expected 8",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(i64::from_be_bytes(buf))
}

fn read_i64_column(
    reader: &mut dyn OpReader,
    row_id: i64,
    column: &str,
    op_name: &str,
) -> Result<i64, ChangelogError> {
    let key = column_key(LISTS, row_id, column);
    let read = reader.read(ReadOp::Key(key))?;
    let Some((_, bytes)) = read.results.first() else {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: _lists row {row_id} column '{column}' is missing"
        )));
    };
    decode_i64_column_value(bytes, op_name, &format!("_lists.{column} (row {row_id})"))
}

fn i64_put(key: Vec<u8>, value: i64) -> WriteOp {
    WriteOp::Put {
        key,
        value: value.to_be_bytes().to_vec(),
    }
}

fn stored_i64_put(key: Vec<u8>, value: i64) -> Result<WriteOp, ChangelogError> {
    let bytes = value_to_bytes(&serde_json::json!(value))
        .map_err(|e| ChangelogError::Generic(format!("failed to serialize i64 {value}: {e}")))?;
    Ok(WriteOp::Put { key, value: bytes })
}

fn read_list_number(
    reader: &mut dyn OpReader,
    target_id: i64,
    op_name: &str,
) -> Result<i64, ChangelogError> {
    let ln = read_i64_column(reader, target_id, "list_number", op_name)?;
    if ln <= 0 {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: target row {target_id} has invalid \
             list_number {ln}"
        )));
    }
    Ok(ln)
}

/// Resolve `list_parent_key(list_number)` to the parent
/// `(table, row_id, column)`, reject internal-table parents, and verify
/// the parent row still exists. Run unconditionally for every list op:
/// a list whose parent row was deleted (or never existed) must reject
/// every mutation, regardless of whether the parent table carries an
/// ACL rule.
fn resolve_list_parent(
    list_number: i64,
    op_name: &str,
    reader: &mut dyn OpReader,
) -> Result<(String, i64, String), ChangelogError> {
    let read = reader.read(ReadOp::Key(list_parent_key(list_number)))?;
    let (_, bytes) = read.results.first().ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{op_name}: list_parent_key({list_number}) is missing"
        ))
    })?;
    let (parent_table, parent_row_id, parent_column) = decode_list_parent(bytes).map_err(|e| {
        ChangelogError::Generic(format!(
            "{op_name}: failed to decode list_parent_key({list_number}): {e}"
        ))
    })?;
    validate_not_internal_table(&parent_table, op_name)?;
    let parent_column_key = column_key(&parent_table, parent_row_id, &parent_column);
    let parent_column_read = reader.read(ReadOp::Key(parent_column_key))?;
    if parent_column_read.results.is_empty() {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: parent row {parent_table}/{parent_row_id} does not exist; \
             parent column '{parent_column}' is absent"
        )));
    }
    Ok((parent_table, parent_row_id, parent_column))
}

fn list_acl_check(
    parent_table: &str,
    parent_row_id: i64,
    uid: u32,
    access_op: &str,
    op_name: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<(), ChangelogError> {
    let Some(rule) = read_acl_rule(reader, parent_table, access_op, ctx)? else {
        return Ok(());
    };
    let mut needed_columns = Vec::new();
    rule.collect_resource_columns(&mut needed_columns);
    let acl = AclCheck {
        rule,
        resource_name: parent_table.to_string(),
        needed_columns,
    };
    let col_values =
        read_columns_from_tree(parent_table, parent_row_id, &acl.needed_columns, reader)?;
    evaluate_acl(&acl, uid, &col_values, op_name)?;
    Ok(())
}

fn new_row_puts(
    new_id: i64,
    list_number: i64,
    prev_id: i64,
    next_id: i64,
    value: Vec<u8>,
) -> Result<Vec<WriteOp>, ChangelogError> {
    Ok(vec![
        stored_i64_put(column_key(LISTS, new_id, "list_number"), list_number)?,
        stored_i64_put(column_key(LISTS, new_id, "next_id"), next_id)?,
        stored_i64_put(column_key(LISTS, new_id, "prev_id"), prev_id)?,
        WriteOp::Put {
            key: column_key(LISTS, new_id, "value"),
            value,
        },
    ])
}

fn list_number_index_put(
    list_number: i64,
    row_id: i64,
    op_name: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<Vec<WriteOp>, ChangelogError> {
    let indexed = read_schema_indexes(LISTS, reader, ctx)?;
    if !indexed.contains("list_number") {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: _lists schema is missing required \
             list_number index"
        )));
    }
    let ln_bytes = value_to_bytes(&serde_json::json!(list_number)).map_err(|e| {
        ChangelogError::Generic(format!(
            "{op_name}: failed to serialize list_number for index: {e}"
        ))
    })?;
    Ok(vec![make_index_put(
        LISTS,
        "list_number",
        &ln_bytes,
        row_id,
        op_name,
    )?])
}

fn placeholder_value(entry: &ChangelogEntry, op_name: &str) -> Result<Vec<u8>, ChangelogError> {
    let value_key = column_key_placeholder(LISTS, "value");
    entry
        .message
        .entries
        .iter()
        .find(|kv| kv.key == value_key)
        .map(|kv| kv.value.clone())
        .ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{op_name}: missing placeholder \
                 column entry for `_lists.value`"
            ))
        })
}

/// Validate that a Append/Insert entry contains exactly the expected set of
/// placeholder column entries on `_lists` (no extras, no row-keyed entries).
fn validate_placeholder_columns(
    entry: &ChangelogEntry,
    expected: &[&str],
    op_name: &str,
) -> Result<(), ChangelogError> {
    use std::collections::BTreeSet;
    let expected_set: BTreeSet<&str> = expected.iter().copied().collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for kv in &entry.message.entries {
        match parse_key(&kv.key) {
            Ok(ParsedKey::Column {
                table,
                row_id: 0,
                column,
            }) if table == LISTS => {
                if !expected_set.contains(column.as_str()) {
                    return Err(ChangelogError::Generic(format!(
                        "{op_name}: unexpected placeholder \
                         column `_lists.{column}`"
                    )));
                }
                if !seen.insert(column.clone()) {
                    return Err(ChangelogError::Generic(format!(
                        "{op_name}: duplicate placeholder \
                         column `_lists.{column}`"
                    )));
                }
            }
            other => {
                return Err(ChangelogError::Generic(format!(
                    "{op_name}: entry must be a `_lists` \
                     placeholder column key, got {other:?}"
                )));
            }
        }
    }
    for col in expected {
        if !seen.contains(*col) {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: missing required placeholder \
                 column `_lists.{col}`"
            )));
        }
    }
    Ok(())
}

impl OpVerifier for ListAppendOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_user_access(entry, OpType::ListAppend, "list_append", reader)?;
        validate_placeholder_columns(entry, &["value", "list_number"], "list_append")?;

        let list_number =
            extract_i64_column_from_entry(entry, LISTS, "list_number", "list_append")?;
        if list_number <= 0 {
            return Err(ChangelogError::Generic(format!(
                "list_append: list_number {list_number} \
                 must be positive"
            )));
        }

        let (parent_table, parent_row_id, _) =
            resolve_list_parent(list_number, "list_append", reader)?;
        list_acl_check(
            &parent_table,
            parent_row_id,
            entry.uid,
            "write",
            "list_append",
            reader,
            ctx,
        )?;

        let new_id = read_next_id(LISTS, "list_append", reader)?;

        let tail = read_i64_key(
            reader,
            list_tail_key(list_number),
            "list_append",
            &format!("list_tail_key({list_number})"),
        )?;

        let value = placeholder_value(entry, "list_append")?;

        let mut batch_ops: Vec<WriteOp> = Vec::new();

        if tail == 0 {
            // Empty list: new row becomes both head and tail.
            batch_ops.extend(new_row_puts(new_id, list_number, 0, 0, value)?);
            batch_ops.push(i64_put(list_head_key(list_number), new_id));
            batch_ops.push(i64_put(list_tail_key(list_number), new_id));
        } else {
            // Non-empty: link after current tail.
            batch_ops.extend(new_row_puts(new_id, list_number, tail, 0, value)?);
            batch_ops.push(stored_i64_put(column_key(LISTS, tail, "next_id"), new_id)?);
            batch_ops.push(i64_put(list_tail_key(list_number), new_id));
        }

        batch_ops.extend(list_number_index_put(
            list_number,
            new_id,
            "list_append",
            reader,
            ctx,
        )?);
        batch_ops.push(next_id_put(
            LISTS,
            next_id_after(new_id, LISTS, "list_append")?,
        ));

        Ok(OpVerifyResult {
            write_steps: batch_ops,
        })
    }
}

impl OpVerifier for ListInsertOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_user_access(entry, OpType::ListInsert, "list_insert", reader)?;
        validate_placeholder_columns(entry, &["value", "list_number", "prev_id"], "list_insert")?;

        let list_number =
            extract_i64_column_from_entry(entry, LISTS, "list_number", "list_insert")?;
        if list_number <= 0 {
            return Err(ChangelogError::Generic(format!(
                "list_insert: list_number {list_number} \
                 must be positive"
            )));
        }
        let predecessor_id = extract_i64_column_from_entry(entry, LISTS, "prev_id", "list_insert")?;
        if predecessor_id < 0 {
            return Err(ChangelogError::Generic(format!(
                "list_insert: predecessor id {predecessor_id} is negative"
            )));
        }
        let (parent_table, parent_row_id, _) =
            resolve_list_parent(list_number, "list_insert", reader)?;
        list_acl_check(
            &parent_table,
            parent_row_id,
            entry.uid,
            "write",
            "list_insert",
            reader,
            ctx,
        )?;

        let value = placeholder_value(entry, "list_insert")?;

        let new_id = read_next_id(LISTS, "list_insert", reader)?;

        let mut batch_ops: Vec<WriteOp> = Vec::new();

        if predecessor_id == 0 {
            // Prepend (sentinel).
            let head = read_i64_key(
                reader,
                list_head_key(list_number),
                "list_insert",
                &format!("list_head_key({list_number})"),
            )?;

            if head == 0 {
                // Empty list.
                batch_ops.extend(new_row_puts(new_id, list_number, 0, 0, value)?);
                batch_ops.push(i64_put(list_head_key(list_number), new_id));
                batch_ops.push(i64_put(list_tail_key(list_number), new_id));
            } else {
                // Non-empty: link before current head.
                batch_ops.extend(new_row_puts(new_id, list_number, 0, head, value)?);
                batch_ops.push(stored_i64_put(column_key(LISTS, head, "prev_id"), new_id)?);
                batch_ops.push(i64_put(list_head_key(list_number), new_id));
            }
        } else {
            // Insert-after.
            let pred_ln = read_i64_column(reader, predecessor_id, "list_number", "list_insert")?;
            if pred_ln != list_number {
                return Err(ChangelogError::Generic(format!(
                    "list_insert: predecessor row {predecessor_id} \
                     belongs to list {pred_ln}, expected {list_number}"
                )));
            }
            let successor = read_i64_column(reader, predecessor_id, "next_id", "list_insert")?;

            batch_ops.extend(new_row_puts(
                new_id,
                list_number,
                predecessor_id,
                successor,
                value,
            )?);
            batch_ops.push(stored_i64_put(
                column_key(LISTS, predecessor_id, "next_id"),
                new_id,
            )?);
            if successor != 0 {
                batch_ops.push(stored_i64_put(
                    column_key(LISTS, successor, "prev_id"),
                    new_id,
                )?);
            } else {
                // Inserting after the tail.
                batch_ops.push(i64_put(list_tail_key(list_number), new_id));
            }
        }

        batch_ops.extend(list_number_index_put(
            list_number,
            new_id,
            "list_insert",
            reader,
            ctx,
        )?);
        batch_ops.push(next_id_put(
            LISTS,
            next_id_after(new_id, LISTS, "list_insert")?,
        ));

        Ok(OpVerifyResult {
            write_steps: batch_ops,
        })
    }
}

impl OpVerifier for ListUpdateOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_user_access(entry, OpType::ListUpdate, "list_update", reader)?;
        if entry.message.entries.len() != 1 {
            return Err(ChangelogError::Generic(format!(
                "list_update: expected exactly 1 entry, got {}",
                entry.message.entries.len()
            )));
        }
        let kv = &entry.message.entries[0];
        let target_id = match parse_key(&kv.key) {
            Ok(ParsedKey::Column {
                table,
                row_id,
                column,
            }) if table == LISTS && column == "value" => row_id,
            other => {
                return Err(ChangelogError::Generic(format!(
                    "list_update: entry must address \
                     `_lists.<id>.value`, got {other:?}"
                )));
            }
        };
        if target_id <= 0 {
            return Err(ChangelogError::Generic(format!(
                "list_update: target id {target_id} must be positive"
            )));
        }

        let list_number = read_list_number(reader, target_id, "list_update")?;
        let (parent_table, parent_row_id, _) =
            resolve_list_parent(list_number, "list_update", reader)?;
        list_acl_check(
            &parent_table,
            parent_row_id,
            entry.uid,
            "write",
            "list_update",
            reader,
            ctx,
        )?;

        let batch_ops = vec![WriteOp::Put {
            key: column_key(LISTS, target_id, "value"),
            value: kv.value.clone(),
        }];

        Ok(OpVerifyResult {
            write_steps: batch_ops,
        })
    }
}

impl OpVerifier for ListDeleteOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_user_access(entry, OpType::ListDelete, "list_delete", reader)?;
        // Standard delete shape: tombstones (empty `Value` payloads) on every
        // non-id `_lists` column for a single target row id.
        use std::collections::BTreeSet;
        const REQUIRED: &[&str] = &["list_number", "next_id", "prev_id", "value"];
        let required_set: BTreeSet<&str> = REQUIRED.iter().copied().collect();
        let mut target_id: Option<i64> = None;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for kv in &entry.message.entries {
            let (row_id, column) = match parse_key(&kv.key) {
                Ok(ParsedKey::Column {
                    table,
                    row_id,
                    column,
                }) if table == LISTS => (row_id, column),
                other => {
                    return Err(ChangelogError::Generic(format!(
                        "list_delete: entry must be a `_lists` \
                         column key, got {other:?}"
                    )));
                }
            };
            if row_id <= 0 {
                return Err(ChangelogError::Generic(format!(
                    "list_delete: target id {row_id} must be positive"
                )));
            }
            match target_id {
                None => target_id = Some(row_id),
                Some(existing) if existing != row_id => {
                    return Err(ChangelogError::Generic(format!(
                        "list_delete: all entries must address \
                         the same row id ({existing} vs {row_id})"
                    )));
                }
                _ => {}
            }
            if !required_set.contains(column.as_str()) {
                return Err(ChangelogError::Generic(format!(
                    "list_delete: unexpected column \
                     `_lists.{column}`"
                )));
            }
            if !seen.insert(column.clone()) {
                return Err(ChangelogError::Generic(format!(
                    "list_delete: duplicate column \
                     `_lists.{column}`"
                )));
            }
            if !kv.value.is_empty() {
                return Err(ChangelogError::Generic(format!(
                    "list_delete: column `_lists.{column}` \
                     must carry an empty value payload (tombstone)"
                )));
            }
        }
        for col in REQUIRED {
            if !seen.contains(*col) {
                return Err(ChangelogError::Generic(format!(
                    "list_delete: missing tombstone for \
                     `_lists.{col}`"
                )));
            }
        }
        let target_id = target_id.ok_or_else(|| {
            ChangelogError::Generic(
                "list_delete: at least one tombstone entry required".to_string(),
            )
        })?;

        let list_number = read_list_number(reader, target_id, "list_delete")?;
        let (parent_table, parent_row_id, _) =
            resolve_list_parent(list_number, "list_delete", reader)?;
        list_acl_check(
            &parent_table,
            parent_row_id,
            entry.uid,
            "delete",
            "list_delete",
            reader,
            ctx,
        )?;
        let prev = read_i64_column(reader, target_id, "prev_id", "list_delete")?;
        let next = read_i64_column(reader, target_id, "next_id", "list_delete")?;

        let mut batch_ops: Vec<WriteOp> = vec![
            WriteOp::Delete {
                key: column_key(LISTS, target_id, "list_number"),
            },
            WriteOp::Delete {
                key: column_key(LISTS, target_id, "next_id"),
            },
            WriteOp::Delete {
                key: column_key(LISTS, target_id, "prev_id"),
            },
            WriteOp::Delete {
                key: column_key(LISTS, target_id, "value"),
            },
        ];

        // Relink adjacent rows.
        if prev != 0 {
            batch_ops.push(stored_i64_put(column_key(LISTS, prev, "next_id"), next)?);
        }
        if next != 0 {
            batch_ops.push(stored_i64_put(column_key(LISTS, next, "prev_id"), prev)?);
        }

        // Update head/tail pointers.
        if prev == 0 {
            batch_ops.push(i64_put(list_head_key(list_number), next));
        }
        if next == 0 {
            batch_ops.push(i64_put(list_tail_key(list_number), prev));
        }

        // Index delete for target's list_number.
        let indexed = read_schema_indexes(LISTS, reader, ctx)?;
        if !indexed.contains("list_number") {
            return Err(ChangelogError::Generic(
                "list_delete: _lists schema is missing required \
                 list_number index"
                    .to_string(),
            ));
        }
        let ln_bytes = value_to_bytes(&serde_json::json!(list_number)).map_err(|e| {
            ChangelogError::Generic(format!(
                "list_delete: failed to serialize list_number \
                 for index delete: {e}"
            ))
        })?;
        batch_ops.push(make_index_delete(
            LISTS,
            "list_number",
            &ln_bytes,
            target_id,
            "list_delete",
        )?);

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
    use encrypted_spaces_storage_encoding::keys::{
        acl_rule_key, column_key, column_key_placeholder, encode_list_parent, schema_indexes_key,
        schema_next_id_key,
    };

    const UID: u32 = 1;

    fn stored_i64_val(value: i64) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    fn proven(key: Vec<u8>, value: Vec<u8>) -> ProvenRead {
        ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, value)],
        }
    }

    fn user_status_read(uid: u32) -> ProvenRead {
        proven(
            column_key("_users", uid as i64, "status"),
            stored_i64_val(1),
        )
    }

    fn list_parent_read(
        list_number: i64,
        parent_table: &str,
        parent_row_id: i64,
        parent_column: &str,
    ) -> ProvenRead {
        proven(
            list_parent_key(list_number),
            encode_list_parent(parent_table, parent_row_id, parent_column),
        )
    }

    /// Column read that proves the parent row still exists under the
    /// dense-row invariant.
    fn parent_column_present_read(
        parent_table: &str,
        parent_row_id: i64,
        parent_column: &str,
    ) -> ProvenRead {
        let key = column_key(parent_table, parent_row_id, parent_column);
        ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, vec![1])],
        }
    }

    fn parent_column_absent_read(
        parent_table: &str,
        parent_row_id: i64,
        parent_column: &str,
    ) -> ProvenRead {
        let key = column_key(parent_table, parent_row_id, parent_column);
        ProvenRead {
            op: ReadOp::Key(key),
            results: vec![],
        }
    }

    fn lists_schema_read() -> ProvenRead {
        proven(schema_indexes_key(LISTS), b"list_number".to_vec())
    }

    fn placeholder_value_kv(value: Vec<u8>) -> KvData {
        KvData {
            key: column_key_placeholder(LISTS, "value"),
            value,
        }
    }

    fn placeholder_i64_kv(column: &str, value: i64) -> KvData {
        KvData {
            key: column_key_placeholder(LISTS, column),
            value: stored_i64_val(value),
        }
    }

    fn make_entry(op_type: OpType, entries: Vec<KvData>) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid: UID,
            parent_change: 0,
            message: LogMessage {
                op_type,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn make_append_entry(list_number: i64, value: Vec<u8>) -> ChangelogEntry {
        make_entry(
            OpType::ListAppend,
            vec![
                placeholder_value_kv(value),
                placeholder_i64_kv("list_number", list_number),
            ],
        )
    }

    fn make_insert_entry(list_number: i64, prev_id: i64, value: Vec<u8>) -> ChangelogEntry {
        make_entry(
            OpType::ListInsert,
            vec![
                placeholder_value_kv(value),
                placeholder_i64_kv("list_number", list_number),
                placeholder_i64_kv("prev_id", prev_id),
            ],
        )
    }

    fn make_update_entry(target_id: i64, value: Vec<u8>) -> ChangelogEntry {
        make_entry(
            OpType::ListUpdate,
            vec![KvData {
                key: column_key(LISTS, target_id, "value"),
                value,
            }],
        )
    }

    fn make_delete_entry(target_id: i64) -> ChangelogEntry {
        let tomb = |col: &str| KvData {
            key: column_key(LISTS, target_id, col),
            value: vec![],
        };
        make_entry(
            OpType::ListDelete,
            vec![
                tomb("list_number"),
                tomb("next_id"),
                tomb("prev_id"),
                tomb("value"),
            ],
        )
    }

    fn next_id_read(current: i64) -> ProvenRead {
        proven(schema_next_id_key(LISTS), current.to_be_bytes().to_vec())
    }

    fn tail_read(list_number: i64, tail_id: i64) -> ProvenRead {
        proven(list_tail_key(list_number), tail_id.to_be_bytes().to_vec())
    }

    fn head_read(list_number: i64, head_id: i64) -> ProvenRead {
        proven(list_head_key(list_number), head_id.to_be_bytes().to_vec())
    }

    fn col_read(row_id: i64, column: &str, value: i64) -> ProvenRead {
        proven(column_key(LISTS, row_id, column), stored_i64_val(value))
    }

    fn no_acl_ctx() -> OpContext {
        OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        }
    }

    /// ProvenRead for `acl_rule_key(table, op)` returning no rule
    /// (default-open semantics).
    fn no_acl_rule_read(table: &str, op: &str) -> ProvenRead {
        ProvenRead {
            op: ReadOp::Key(acl_rule_key(table, op)),
            results: vec![],
        }
    }

    // ─── ListAppendOp tests ────────────────────────────────────────────

    #[test]
    fn test_append_to_empty_list() {
        let list_number = 5i64;
        let entry = make_append_entry(list_number, vec![42u8; 32]);

        let reads = vec![
            user_status_read(UID),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "write"),
            next_id_read(1),
            tail_read(list_number, 0),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListAppendOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        // 4 column puts + head + tail + index + counter bump = 8
        assert_eq!(ops.len(), 8, "got {} ops: {ops:?}", ops.len());
    }

    #[test]
    fn test_append_to_nonempty_list() {
        let list_number = 5i64;
        let old_tail = 10i64;
        let entry = make_append_entry(list_number, vec![42u8; 32]);

        let reads = vec![
            user_status_read(UID),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "write"),
            next_id_read(11),
            tail_read(list_number, old_tail),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListAppendOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        // 4 column puts + link old tail next_id + tail update + index + counter = 8
        assert_eq!(ops.len(), 8, "got {} ops: {ops:?}", ops.len());
    }

    // ─── ListInsertOp tests ────────────────────────────────────────────

    #[test]
    fn test_prepend_to_empty_list() {
        let list_number = 5i64;
        let entry = make_insert_entry(list_number, 0, vec![42u8; 32]);

        let reads = vec![
            user_status_read(UID),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "write"),
            next_id_read(1),
            head_read(list_number, 0),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListInsertOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        assert_eq!(ops.len(), 8);
    }

    #[test]
    fn test_prepend_to_nonempty_list() {
        let list_number = 5i64;
        let old_head = 10i64;
        let entry = make_insert_entry(list_number, 0, vec![42u8; 32]);

        let reads = vec![
            user_status_read(UID),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "write"),
            next_id_read(11),
            head_read(list_number, old_head),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListInsertOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        assert_eq!(ops.len(), 8);
    }

    #[test]
    fn test_insert_after_middle() {
        let list_number = 5i64;
        let predecessor = 10i64;
        let successor = 20i64;
        let entry = make_insert_entry(list_number, predecessor, vec![42u8; 32]);

        let reads = vec![
            user_status_read(UID),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "write"),
            next_id_read(30),
            col_read(predecessor, "list_number", list_number),
            col_read(predecessor, "next_id", successor),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListInsertOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        assert_eq!(ops.len(), 8);
    }

    #[test]
    fn test_insert_after_tail() {
        let list_number = 5i64;
        let predecessor = 10i64;
        let entry = make_insert_entry(list_number, predecessor, vec![42u8; 32]);

        let reads = vec![
            user_status_read(UID),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "write"),
            next_id_read(30),
            col_read(predecessor, "list_number", list_number),
            col_read(predecessor, "next_id", 0),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListInsertOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        assert_eq!(ops.len(), 8);
    }

    #[test]
    fn test_insert_predecessor_wrong_list() {
        let list_number = 5i64;
        let predecessor = 10i64;
        let entry = make_insert_entry(list_number, predecessor, vec![42u8; 32]);

        let reads = vec![
            user_status_read(UID),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "write"),
            next_id_read(30),
            col_read(predecessor, "list_number", 99),
        ];

        let mut reader = VerifierReader::new(&reads);
        let err =
            ListInsertOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("belongs to list 99"),
            "unexpected: {err}"
        );
    }

    // ─── ListUpdateOp tests ───────────────────────────────────────────

    #[test]
    fn test_update_value() {
        let target = 10i64;
        let list_number = 5i64;
        let entry = make_update_entry(target, vec![77u8; 32]);

        let reads = vec![
            user_status_read(UID),
            col_read(target, "list_number", list_number),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "write"),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListUpdateOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            WriteOp::Put { key, value } => {
                assert_eq!(key, &column_key(LISTS, target, "value"));
                assert_eq!(value, &vec![77u8; 32]);
            }
            other => panic!("expected Put, got {other:?}"),
        }
    }

    #[test]
    fn test_update_zero_target_rejected() {
        let entry = make_update_entry(0, vec![77u8; 32]);
        let err = ListUpdateOp::extract_and_validate(
            &entry,
            &mut VerifierReader::new(&[user_status_read(UID)]),
            &no_acl_ctx(),
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("must be positive"),
            "unexpected: {err}"
        );
    }

    // ─── ListDeleteOp tests ───────────────────────────────────────────

    #[test]
    fn test_delete_middle() {
        let target = 20i64;
        let prev = 10i64;
        let next = 30i64;
        let list_number = 5i64;
        let entry = make_delete_entry(target);

        let reads = vec![
            user_status_read(UID),
            col_read(target, "list_number", list_number),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "delete"),
            col_read(target, "prev_id", prev),
            col_read(target, "next_id", next),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListDeleteOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        // 4 deletes + relink prev.next_id + relink next.prev_id + index delete = 7
        assert_eq!(ops.len(), 7, "got {} ops: {ops:?}", ops.len());
    }

    #[test]
    fn test_delete_head() {
        let target = 10i64;
        let next = 20i64;
        let list_number = 5i64;
        let entry = make_delete_entry(target);

        let reads = vec![
            user_status_read(UID),
            col_read(target, "list_number", list_number),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "delete"),
            col_read(target, "prev_id", 0),
            col_read(target, "next_id", next),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListDeleteOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        assert_eq!(ops.len(), 7, "got {} ops: {ops:?}", ops.len());
    }

    #[test]
    fn test_delete_tail() {
        let target = 30i64;
        let prev = 20i64;
        let list_number = 5i64;
        let entry = make_delete_entry(target);

        let reads = vec![
            user_status_read(UID),
            col_read(target, "list_number", list_number),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "delete"),
            col_read(target, "prev_id", prev),
            col_read(target, "next_id", 0),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListDeleteOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        assert_eq!(ops.len(), 7, "got {} ops: {ops:?}", ops.len());
    }

    #[test]
    fn test_delete_only_element() {
        let target = 10i64;
        let list_number = 5i64;
        let entry = make_delete_entry(target);

        let reads = vec![
            user_status_read(UID),
            col_read(target, "list_number", list_number),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_present_read("tasks", 1, "items"),
            no_acl_rule_read("tasks", "delete"),
            col_read(target, "prev_id", 0),
            col_read(target, "next_id", 0),
            lists_schema_read(),
        ];

        let mut reader = VerifierReader::new(&reads);
        let result =
            ListDeleteOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap();
        let ops = &result.write_steps;
        assert_eq!(ops.len(), 7, "got {} ops: {ops:?}", ops.len());
    }

    #[test]
    fn test_delete_zero_target_rejected() {
        let entry = make_delete_entry(0);
        let err = ListDeleteOp::extract_and_validate(
            &entry,
            &mut VerifierReader::new(&[user_status_read(UID)]),
            &no_acl_ctx(),
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("must be positive"),
            "unexpected: {err}"
        );
    }

    /// `list_parent_key(list_number)` resolving to an internal table is rejected.
    #[test]
    fn test_internal_table_rejected() {
        let list_number = 5i64;
        let entry = make_append_entry(list_number, vec![42u8; 32]);
        let reads = vec![
            user_status_read(UID),
            list_parent_read(list_number, "_users", 1, "items"),
        ];
        let mut reader = VerifierReader::new(&reads);
        let err =
            ListAppendOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap_err();
        assert!(format!("{err}").contains("reserved"), "unexpected: {err}");
    }

    /// Missing `list_parent_key(list_number)` is rejected (no such list).
    #[test]
    fn test_parent_missing_rejected() {
        let list_number = 5i64;
        let entry = make_append_entry(list_number, vec![42u8; 32]);
        let parent_key = list_parent_key(list_number);
        let reads = vec![
            user_status_read(UID),
            ProvenRead {
                op: ReadOp::Key(parent_key),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err =
            ListAppendOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap_err();
        assert!(format!("{err}").contains("missing"), "unexpected: {err}");
    }

    #[test]
    fn test_placeholder_list_number_rejected() {
        let entry = make_append_entry(0, vec![42u8; 32]);
        let reads = vec![user_status_read(UID)];
        let mut reader = VerifierReader::new(&reads);
        let err =
            ListAppendOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("must be positive"),
            "unexpected: {err}"
        );
    }

    /// Parent row resolved by `list_parent_key` no longer exists (e.g.
    /// the parent row was deleted but its lists were not cleaned up).
    /// Every list mutation must reject, even when no ACL rule is
    /// registered for the parent table.
    #[test]
    fn test_parent_row_missing_rejected_no_acl() {
        let list_number = 5i64;
        let entry = make_append_entry(list_number, vec![42u8; 32]);

        let reads = vec![
            user_status_read(UID),
            list_parent_read(list_number, "tasks", 1, "items"),
            parent_column_absent_read("tasks", 1, "items"),
        ];

        let mut reader = VerifierReader::new(&reads);
        let err =
            ListAppendOp::extract_and_validate(&entry, &mut reader, &no_acl_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("does not exist"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_negative_predecessor_rejected() {
        let entry = make_insert_entry(5, -1, vec![42u8; 32]);
        let err = ListInsertOp::extract_and_validate(
            &entry,
            &mut VerifierReader::new(&[user_status_read(UID)]),
            &no_acl_ctx(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("negative"), "unexpected: {err}");
    }
}
