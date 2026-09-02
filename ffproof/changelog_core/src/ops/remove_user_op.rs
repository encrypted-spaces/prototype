use super::{
    append_insert_index_puts, append_multi_row_insert_index_puts, bump_next_id_after_chain,
    column_names_from_keys, derive_column_keys_for_chain, derive_column_keys_with_row_id,
    extract_i64_from_kh_entries, extract_value_from_kh_entries, partition_composite_entry,
    read_kh_ranges_indexed, read_next_id, read_schema_columns,
    validate_consistent_column_key_row_id, validate_key_history_entries, validate_user_access,
    OpReader, OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::{ReadOp, WriteOp};
use encrypted_spaces_storage_encoding::keys::{
    column_key, parse_key, ParsedKey, KEY_HISTORY_TABLE, USERS_TABLE,
};
use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
use std::collections::{BTreeMap, BTreeSet};

/// RemoveUser operation verifier.
pub struct RemoveUserOp;

impl OpVerifier for RemoveUserOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &super::OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        let parts = partition_composite_entry(entry, "remove_user")?;
        let kh_entries = parts.key_history;
        let retention_entries = parts.retention;
        let user_entries = parts.users;

        if kh_entries.is_empty() {
            return Err(ChangelogError::Generic(
                "remove_user: \
                 _key_history entries must not be empty"
                    .to_string(),
            ));
        }
        if user_entries.is_empty() {
            return Err(ChangelogError::Generic(
                "remove_user: \
                 _users entries must not be empty"
                    .to_string(),
            ));
        }

        // Authoritative valid_to_change_id is `current_change_id - 1`.
        let valid_to: i64 = if ctx.current_change_id > 0 {
            (ctx.current_change_id - 1) as i64
        } else {
            return Err(ChangelogError::Generic(
                "remove_user: cannot derive \
                 valid_to_change_id from current_change_id=0"
                    .to_string(),
            ));
        };

        // --- Validate user columns target _users table ---
        let user_column_keys = column_keys_from_entry_subset(&user_entries);
        let (user_table, deleted_uid_i64) =
            validate_consistent_column_key_row_id(&user_column_keys, "remove_user", "user")?;
        if user_table != crate::USERS_TABLE {
            return Err(ChangelogError::Generic(format!(
                "remove_user: user columns target table '{user_table}', \
                 expected '{}'",
                crate::USERS_TABLE
            )));
        }
        let deleted_uid = deleted_uid_i64 as u32;

        // --- Validate the invoking user is a full member ---
        validate_user_access(entry, OpType::RemoveUser, "remove_user", reader)?;

        // --- Validate user delete covers all schema columns per row ---
        let expected_user_cols = read_schema_columns(&user_table, "remove_user", reader, ctx)?;
        let mut columns_by_row: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
        for kv in &user_entries {
            if let Ok(ParsedKey::Column { row_id, column, .. }) = parse_key(&kv.key) {
                columns_by_row.entry(row_id).or_default().insert(column);
            }
        }
        if columns_by_row.len() != 1 {
            return Err(ChangelogError::Generic(format!(
                "remove_user: expected exactly 1 deleted _users row, got {}",
                columns_by_row.len()
            )));
        }
        for (rid, actual_columns) in &columns_by_row {
            if *actual_columns != expected_user_cols {
                let missing: Vec<_> = expected_user_cols.difference(actual_columns).collect();
                return Err(ChangelogError::Generic(format!(
                    "remove_user: row {rid} is missing columns {missing:?} — \
                     deletes must cover all columns"
                )));
            }
        }

        let mut batch_ops: Vec<WriteOp> = Vec::new();

        // User columns: WriteOp::Delete (no counter bump — delete doesn't allocate ids)
        for kv in &user_entries {
            batch_ops.push(WriteOp::Delete {
                key: kv.key.clone(),
            });
        }

        // --- Derive _key_history column keys from authenticated counter ---
        let kh_row_id = read_next_id(KEY_HISTORY_TABLE, "remove_user", reader)?;
        let kh_column_keys = derive_column_keys_with_row_id(&kh_entries, kh_row_id, "remove_user")?;
        // Validate kh structure (column tuples, required columns, uid).
        let kh_row_id_check =
            validate_key_history_entries(&kh_column_keys, &kh_entries, deleted_uid, "remove_user")?;
        debug_assert_eq!(kh_row_id, kh_row_id_check);

        // --- Semantic validation of _key_history values ---
        let valid_from =
            extract_i64_from_kh_entries(&kh_entries, "valid_from_change_id", "remove_user")?;

        // valid_from must be <= valid_to.
        if valid_from > valid_to {
            return Err(ChangelogError::Generic(format!(
                "remove_user: \
                 _key_history.valid_from_change_id={valid_from} \
                 must be <= valid_to_change_id={valid_to}"
            )));
        }

        // old_auth_key must match the deleted user's current _users.auth_key.
        let old_auth_key =
            extract_value_from_kh_entries(&kh_entries, "old_auth_key", "remove_user")?;
        let auth_key_key = column_key(USERS_TABLE, deleted_uid as i64, "auth_key");
        let auth_read = reader.read(ReadOp::Key(auth_key_key))?;
        let (_, current_auth_key_bytes) = auth_read.results.first().ok_or_else(|| {
            ChangelogError::Generic(format!(
                "remove_user: \
                 _users.auth_key not found for deleted uid={deleted_uid}"
            ))
        })?;
        if old_auth_key.as_slice() != current_auth_key_bytes.as_slice() {
            return Err(ChangelogError::Generic(format!(
                "remove_user: \
                 _key_history.old_auth_key does not match \
                 current _users.auth_key for deleted uid={deleted_uid}"
            )));
        }

        // New _key_history range must not overlap any existing rows for this uid
        // and must be contiguous with the previous range (no gaps).
        let existing_ranges = read_kh_ranges_indexed(deleted_uid, reader, "remove_user")?;
        for (prev_from, prev_to) in &existing_ranges {
            if valid_from <= *prev_to && *prev_from <= valid_to {
                return Err(ChangelogError::Generic(format!(
                    "remove_user: \
                     new _key_history range [{valid_from}, {valid_to}] \
                     overlaps existing range [{prev_from}, {prev_to}] \
                     for uid={deleted_uid}"
                )));
            }
        }

        if !existing_ranges.is_empty() {
            // Continuity: new valid_from must equal max(existing valid_to) + 1.
            let max_prev_to = existing_ranges.iter().map(|(_, to)| *to).max().unwrap();
            let expected_from = max_prev_to + 1;
            if valid_from != expected_from {
                return Err(ChangelogError::Generic(format!(
                    "remove_user: \
                     _key_history.valid_from_change_id={valid_from} \
                     must be {expected_from} (previous valid_to + 1) \
                     for uid={deleted_uid}"
                )));
            }
        } else if valid_from != 0 {
            // For the first entry (no prior rows), valid_from must be 0.
            return Err(ChangelogError::Generic(format!(
                "remove_user: \
                 _key_history.valid_from_change_id={valid_from} \
                 must be 0 for the first history entry of uid={deleted_uid}"
            )));
        }

        // _key_history columns: WriteOp::Put (insert).
        // For valid_to_change_id, substitute the server-authoritative value
        // (`current_change_id - 1`) instead of the client's changelog
        // entry value.  The server patches kh_query.valid_to_change_id
        // without modifying the changelog entry, so the entry may carry a
        // stale client guess while the verifier computes the corrected
        // value.
        let authoritative_valid_to_bytes = value_to_bytes(&serde_json::Value::Number(
            serde_json::Number::from(valid_to),
        ))
        .expect("serialize integer");
        for (col_key, kv) in kh_column_keys.iter().zip(kh_entries.iter()) {
            let is_valid_to = parse_key(col_key)
                .map(|pk| matches!(pk, ParsedKey::Column { column, .. } if column == "valid_to_change_id"))
                .unwrap_or(false);
            if is_valid_to {
                batch_ops.push(WriteOp::Put {
                    key: col_key.clone(),
                    value: authoritative_valid_to_bytes.clone(),
                });
            } else {
                batch_ops.push(kv.to_batch_op(col_key));
            }
        }
        append_insert_index_puts(
            &mut batch_ops,
            KEY_HISTORY_TABLE,
            kh_row_id,
            &kh_entries,
            "remove_user",
            reader,
            ctx,
        )?;

        // Counter bump for _key_history (we already read the counter above).
        bump_next_id_after_chain(
            &mut batch_ops,
            KEY_HISTORY_TABLE,
            kh_row_id,
            1,
            "remove_user",
        )?;

        // --- Validate retention insert + derive keys from counter ---
        if !retention_entries.is_empty() {
            let expected_retention_cols =
                read_schema_columns(crate::RETENTION_TABLE, "remove_user", reader, ctx)?;
            let retention_entry_keys: Vec<Vec<u8>> =
                retention_entries.iter().map(|kv| kv.key.clone()).collect();
            let actual_retention_cols = column_names_from_keys(&retention_entry_keys);
            if actual_retention_cols != expected_retention_cols {
                let missing: Vec<_> = expected_retention_cols
                    .difference(&actual_retention_cols)
                    .collect();
                return Err(ChangelogError::Generic(format!(
                    "remove_user: _retention insert missing columns {missing:?}"
                )));
            }
            let retention_col_count = expected_retention_cols.len();
            if retention_col_count == 0 {
                return Err(ChangelogError::Generic(
                    "remove_user: _retention has no schema columns".to_string(),
                ));
            }
            if retention_entries.len() % retention_col_count != 0 {
                return Err(ChangelogError::Generic(format!(
                    "remove_user: _retention entry count {} is not a \
                     multiple of col_count={retention_col_count}",
                    retention_entries.len()
                )));
            }

            let retention_counter = read_next_id(crate::RETENTION_TABLE, "remove_user", reader)?;
            let retention_column_keys = derive_column_keys_for_chain(
                &retention_entries,
                retention_counter,
                retention_col_count,
                "remove_user",
            )?;
            for (col_key, kv) in retention_column_keys.iter().zip(retention_entries.iter()) {
                batch_ops.push(kv.to_batch_op(col_key));
            }

            append_multi_row_insert_index_puts(
                &mut batch_ops,
                crate::RETENTION_TABLE,
                &retention_column_keys,
                &retention_entries,
                "remove_user",
                reader,
                ctx,
            )?;

            let num_rows = (retention_entries.len() / retention_col_count) as i64;
            bump_next_id_after_chain(
                &mut batch_ops,
                crate::RETENTION_TABLE,
                retention_counter,
                num_rows,
                "remove_user",
            )?;
        }

        Ok(OpVerifyResult {
            write_steps: batch_ops,
        })
    }
}

fn column_keys_from_entry_subset(entries: &[crate::changelog::KvData]) -> Vec<Vec<u8>> {
    entries.iter().map(|kv| kv.key.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage};
    use crate::ops::VerifierReader;
    use crate::{ProvenRead, ReadOp};
    use encrypted_spaces_storage_encoding::stored_value::{bytes_to_value, value_to_bytes};
    use encrypted_spaces_storage_encoding::{
        encode_column_names, hashstore_hash,
        keys::{
            column_key, column_key_placeholder, index_key, index_value_prefix, schema_columns_key,
            schema_indexes_key, schema_next_id_key, KEY_HISTORY_TABLE,
        },
        row_id_to_bytes,
    };

    fn user_status_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "status")
    }

    fn stored_i64(value: i64) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    fn stored_str(value: &str) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    fn test_auth_key() -> Vec<u8> {
        stored_str("base64key")
    }

    fn make_kh_kvs(uid: u32) -> Vec<KvData> {
        let uid_json = stored_i64(uid as i64);
        let mut kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: stored_str("base64key"),
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(0),
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(5),
            },
        ];
        kvs.sort_by(|a, b| a.key.cmp(&b.key));
        kvs
    }

    fn make_kh_column_keys() -> Vec<Vec<u8>> {
        let mut keys = vec![
            column_key("_key_history", 1, "old_auth_key"),
            column_key("_key_history", 1, "uid"),
            column_key("_key_history", 1, "valid_from_change_id"),
            column_key("_key_history", 1, "valid_to_change_id"),
        ];
        keys.sort();
        keys
    }

    /// Build a RemoveUser entry with kh + retention + user entries sorted by key.
    fn make_remove_entry_with_kh(
        uid: u32,
        kh_kvs: Vec<KvData>,
        retention_keys: &[Vec<u8>],
        user_keys: &[Vec<u8>],
    ) -> ChangelogEntry {
        let retention_entries = retention_keys.iter().map(|key| {
            // The "key" column is indexed, so it must be stored inline.
            let is_key_column = parse_key(key)
                .map(|pk| matches!(pk, ParsedKey::Column { column, .. } if column == "key"))
                .unwrap_or(false);
            KvData {
                key: key.clone(),
                value: if is_key_column {
                    stored_str("test_retention_key")
                } else {
                    vec![0xAA; 32]
                },
            }
        });
        let user_entries = user_keys.iter().map(|key| KvData {
            key: key.clone(),
            value: vec![],
        });

        // Sorted order: _key_history < _retention < _users
        let mut entries: Vec<KvData> = kh_kvs;
        entries.extend(retention_entries);
        entries.extend(user_entries);

        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::RemoveUser,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn user_auth_key_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "auth_key")
    }

    /// Build verifier reads for RemoveUser.
    ///
    /// Read order matches the verifier's call order:
    /// 1. status key (validate_user_access)
    /// 2. schema _users
    /// 3. schema_next_id _key_history (used to derive kh column keys)
    /// 4. auth_key for deleted user (old_auth_key semantic check)
    /// 5. _key_history uid index scan (overlap/continuity check)
    /// 6. targeted _key_history valid_from/valid_to reads
    /// 7. schema _key_history indexes (append_insert_index_puts)
    /// 8. schema _retention
    /// 9. schema_next_id _retention (used to derive retention column keys)
    /// 10. schema _retention (inside append_multi_row_insert_index_puts)
    /// 11. schema _retention indexes
    fn verifier_reads(
        remover_uid: u32,
        deleted_uid: u32,
        auth_key_value: &[u8],
        existing_kh_rows: Vec<(i64, i64, i64)>,
    ) -> Vec<ProvenRead> {
        let user_cols: BTreeSet<String> = ["auth_key", "status", "update_key"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let retention_cols: BTreeSet<String> =
            ["key", "value"].into_iter().map(str::to_string).collect();
        let sk = user_status_key(remover_uid);
        let ak = user_auth_key_key(deleted_uid);

        // Pick the smallest unused row_id as the kh next_id (rows start at 1).
        let used: std::collections::BTreeSet<i64> =
            existing_kh_rows.iter().map(|(rid, _, _)| *rid).collect();
        let kh_next_id = (1i64..).find(|i| !used.contains(i)).unwrap();

        let mut reads = vec![
            // 1. validate_user_access
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            // 2. schema _users
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_users")),
                results: vec![(
                    schema_columns_key("_users"),
                    encode_column_names(&user_cols),
                )],
            },
            // 3. schema_next_id _key_history (derive kh column keys from counter)
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key(KEY_HISTORY_TABLE)),
                results: vec![(
                    schema_next_id_key(KEY_HISTORY_TABLE),
                    kh_next_id.to_be_bytes().to_vec(),
                )],
            },
            // 4. old_auth_key semantic check
            ProvenRead {
                op: ReadOp::Key(ak.clone()),
                results: vec![(ak, auth_key_value.to_vec())],
            },
            // 5. _key_history uid index scan
            ProvenRead {
                op: ReadOp::Prefix(
                    index_value_prefix(KEY_HISTORY_TABLE, "uid", deleted_uid as i64).unwrap(),
                ),
                results: existing_kh_rows
                    .iter()
                    .map(|(row_id, _, _)| {
                        (
                            index_key(KEY_HISTORY_TABLE, "uid", deleted_uid as i64, *row_id)
                                .unwrap(),
                            row_id_to_bytes(*row_id).to_vec(),
                        )
                    })
                    .collect(),
            },
        ];

        // 5. targeted _key_history valid_from/valid_to reads
        for (row_id, valid_from, valid_to) in existing_kh_rows {
            let valid_from_key = column_key(KEY_HISTORY_TABLE, row_id, "valid_from_change_id");
            let valid_to_key = column_key(KEY_HISTORY_TABLE, row_id, "valid_to_change_id");
            reads.push(ProvenRead {
                op: ReadOp::Key(valid_from_key.clone()),
                results: vec![(valid_from_key, stored_i64(valid_from))],
            });
            reads.push(ProvenRead {
                op: ReadOp::Key(valid_to_key.clone()),
                results: vec![(valid_to_key, stored_i64(valid_to))],
            });
        }

        reads.extend([
            // 7. _key_history schema indexes (for emitted index writes)
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key(KEY_HISTORY_TABLE)),
                results: vec![(schema_indexes_key(KEY_HISTORY_TABLE), b"uid".to_vec())],
            },
            // 8. schema _retention
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_retention")),
                results: vec![(
                    schema_columns_key("_retention"),
                    encode_column_names(&retention_cols),
                )],
            },
            // 9. schema_next_id _retention (derive retention column keys)
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key("_retention")),
                results: vec![(
                    schema_next_id_key("_retention"),
                    1i64.to_be_bytes().to_vec(),
                )],
            },
            // 10. _retention schema indexes (for emitted retention index writes)
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key("_retention")),
                results: vec![(schema_indexes_key("_retention"), b"key".to_vec())],
            },
        ]);

        reads
    }

    #[test]
    fn test_remove_user_accepts_single_deleted_row() {
        let remover_uid = 1u32;
        let deleted_uid = 5u32;
        let row_id = deleted_uid as i64;
        let user_keys = vec![
            column_key("_users", row_id, "auth_key"),
            column_key("_users", row_id, "status"),
            column_key("_users", row_id, "update_key"),
        ];
        let retention_keys = vec![
            column_key_placeholder("_retention", "key"),
            column_key_placeholder("_retention", "value"),
        ];
        let kh_kvs = make_kh_kvs(deleted_uid);
        let _kh_column_keys = make_kh_column_keys();
        let entry = make_remove_entry_with_kh(remover_uid, kh_kvs, &retention_keys, &user_keys);
        let reads = verifier_reads(remover_uid, deleted_uid, &test_auth_key(), vec![]);
        let mut reader = VerifierReader::new(&reads);

        let result = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 1,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_remove_user_rejects_multiple_deleted_rows() {
        let remover_uid = 1u32;
        let deleted_uid = 5u32;
        let user_keys = vec![
            column_key("_users", 5, "auth_key"),
            column_key("_users", 5, "status"),
            column_key("_users", 5, "update_key"),
            column_key("_users", 6, "auth_key"),
            column_key("_users", 6, "status"),
            column_key("_users", 6, "update_key"),
        ];
        let retention_keys = vec![
            column_key_placeholder("_retention", "key"),
            column_key_placeholder("_retention", "value"),
        ];
        let kh_kvs = make_kh_kvs(deleted_uid);
        let _kh_column_keys = make_kh_column_keys();
        let entry = make_remove_entry_with_kh(remover_uid, kh_kvs, &retention_keys, &user_keys);
        let reads = verifier_reads(remover_uid, deleted_uid, &test_auth_key(), vec![]);
        let mut reader = VerifierReader::new(&reads);

        let err = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 1,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("one insert must bind all columns to a single (table, row_id)"),
            "unexpected error: {msg}"
        );
    }

    // ─── Semantic rejection tests ────────────────────────────────────────────

    /// Helper: build a standard RemoveUser scenario with customisable kh data.
    fn setup_remove_user(
        kh_kvs: Vec<KvData>,
        auth_key_value: &[u8],
        existing_kh_rows: Vec<(i64, i64, i64)>,
    ) -> (ChangelogEntry, Vec<ProvenRead>) {
        let remover_uid = 1u32;
        let deleted_uid = 5u32;
        let row_id = deleted_uid as i64;
        let user_keys = vec![
            column_key("_users", row_id, "auth_key"),
            column_key("_users", row_id, "status"),
            column_key("_users", row_id, "update_key"),
        ];
        let retention_keys = vec![
            column_key_placeholder("_retention", "key"),
            column_key_placeholder("_retention", "value"),
        ];
        let _kh_column_keys = make_kh_column_keys();
        let entry = make_remove_entry_with_kh(remover_uid, kh_kvs, &retention_keys, &user_keys);
        let reads = verifier_reads(remover_uid, deleted_uid, auth_key_value, existing_kh_rows);
        (entry, reads)
    }

    #[test]
    fn test_remove_user_rejects_tampered_old_auth_key() {
        let deleted_uid = 5u32;
        let uid_json = stored_i64(deleted_uid as i64);
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: stored_str("TAMPERED_KEY"),
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(0),
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(0),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        // Tree has the real auth key, entry has a tampered one → must reject.
        let (entry, reads) = setup_remove_user(kh_kvs, &test_auth_key(), vec![]);
        let mut reader = VerifierReader::new(&reads);

        let err = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 1,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("old_auth_key does not match"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_remove_user_rejects_valid_from_gap() {
        let deleted_uid = 5u32;
        let uid_json = stored_i64(deleted_uid as i64);
        // valid_from=5 but no prior history exists → should be 0
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: test_auth_key(),
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(5),
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(10),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        let (entry, reads) = setup_remove_user(kh_kvs, &test_auth_key(), vec![]);
        // Set valid_to high enough so valid_from <= valid_to passes
        let mut reader = VerifierReader::new(&reads);

        let err = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 11,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("must be 0 for the first history entry"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_remove_user_rejects_overlapping_range() {
        let deleted_uid = 5u32;
        let uid_json = stored_i64(deleted_uid as i64);
        // New row: valid_from=0, valid_to=0 (input.valid_to_change_id)
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: test_auth_key(),
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(0),
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(0),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        // Existing _key_history row for uid=5 with range [0, 3]
        let existing_kh_rows = vec![(99, 0, 3)];

        let (entry, reads) = setup_remove_user(kh_kvs, &test_auth_key(), existing_kh_rows);
        let mut reader = VerifierReader::new(&reads);

        let err = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 1,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("overlaps existing range"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_remove_user_rejects_valid_from_discontinuity_after_prior_row() {
        let deleted_uid = 5u32;
        let uid_json = stored_i64(deleted_uid as i64);
        // New row: valid_from=10, valid_to should come from input (we'll set to 15)
        // Prior row ends at valid_to=3 → expected valid_from = 4, not 10
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: test_auth_key(),
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(10),
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(15),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        // Existing _key_history row for uid=5 with range [0, 3]
        let existing_kh_rows = vec![(99, 0, 3)];

        let (entry, reads) = setup_remove_user(kh_kvs, &test_auth_key(), existing_kh_rows);
        let mut reader = VerifierReader::new(&reads);

        let err = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 16,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("must be 4 (previous valid_to + 1)"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_remove_user_accepts_contiguous_range_after_prior_row() {
        let deleted_uid = 5u32;
        let uid_json = stored_i64(deleted_uid as i64);
        // New row: valid_from=4, valid_to=0 (input.valid_to_change_id)
        // Prior row ends at valid_to=3 → expected valid_from = 4 → OK
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: test_auth_key(),
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(4),
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(10),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        // Existing _key_history row for uid=5 with range [0, 3]
        let existing_kh_rows = vec![(99, 0, 3)];

        let (entry, reads) = setup_remove_user(kh_kvs, &test_auth_key(), existing_kh_rows);
        let mut reader = VerifierReader::new(&reads);

        let result = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 11,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    fn hash_ref(data: &[u8]) -> Vec<u8> {
        hashstore_hash(data).to_vec()
    }

    #[test]
    fn test_remove_user_key_hash_matching_stored_hashes_accepted() {
        let deleted_uid = 5u32;
        let full_key_bytes = test_auth_key();
        let hash = hash_ref(&full_key_bytes);

        let uid_json = stored_i64(deleted_uid as i64);
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: hash.clone(),
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(0),
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(5),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        let (entry, reads) = setup_remove_user(kh_kvs, &hash, vec![]);
        let mut reader = VerifierReader::new(&reads);

        let result = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 6,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_remove_user_key_hash_mismatched_stored_hashes_rejected() {
        let deleted_uid = 5u32;
        let hash_a = hash_ref(b"key_a");
        let hash_b = hash_ref(b"key_b");

        let uid_json = stored_i64(deleted_uid as i64);
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: hash_a,
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(0),
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(5),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        let (entry, reads) = setup_remove_user(kh_kvs, &hash_b, vec![]);
        let mut reader = VerifierReader::new(&reads);

        let err = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 6,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("old_auth_key does not match"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_remove_user_key_hash_no_hashed_values_required() {
        let deleted_uid = 5u32;
        let hash = hash_ref(&test_auth_key());
        assert_eq!(hash.len(), 32);

        let uid_json = stored_i64(deleted_uid as i64);
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: hash.clone(),
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(4),
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(10),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        let existing_kh_rows = vec![(99, 0, 3)];
        let (entry, reads) = setup_remove_user(kh_kvs, &hash, existing_kh_rows);
        let mut reader = VerifierReader::new(&reads);

        let result = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 11,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(
            result.is_ok(),
            "E&V should accept matching 32-byte hash references \
             without HashedValues: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_remove_user_write_uses_authoritative_valid_to() {
        // The entry carries valid_to=5 (client's stale guess), but input
        // carries the server-authoritative valid_to=8.  The emitted batch
        // op for valid_to_change_id must contain the server value "8", not
        // the client's "5".
        let deleted_uid = 5u32;
        let uid_json = stored_i64(deleted_uid as i64);
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_key_history", "old_auth_key"),
                value: test_auth_key(),
            },
            KvData {
                key: column_key_placeholder("_key_history", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_key_history", "valid_from_change_id"),
                value: stored_i64(0),
            },
            KvData {
                // Client's stale guess
                key: column_key_placeholder("_key_history", "valid_to_change_id"),
                value: stored_i64(5),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        let (entry, reads) = setup_remove_user(kh_kvs, &test_auth_key(), vec![]);
        // Server-authoritative value differs from the entry's "5"
        let mut reader = VerifierReader::new(&reads);

        let result = RemoveUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext {
                current_change_id: 9,
                action_name: None,
                ..Default::default()
            },
        );
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );

        // Inspect the emitted batch ops for the _key_history valid_to column.
        let batch_ops = result.unwrap().write_steps;

        let valid_to_key = column_key("_key_history", 1, "valid_to_change_id");
        let valid_to_op = batch_ops
            .iter()
            .find(|op| crate::ops::write_op_key(op) == valid_to_key)
            .expect("valid_to_change_id batch op not found");

        match valid_to_op {
            WriteOp::Put { value, .. } => {
                let decoded = bytes_to_value(value).expect("valid_to_change_id should decode");
                assert_eq!(
                    decoded.as_i64(),
                    Some(8),
                    "valid_to_change_id should use server-authoritative value 8"
                );
            }
            other => panic!("expected Put for valid_to_change_id, got {:?}", other),
        }
    }
}
