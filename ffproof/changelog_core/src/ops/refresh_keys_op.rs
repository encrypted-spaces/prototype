use super::{
    append_insert_index_puts, bump_next_id_after_chain, column_names_from_keys,
    derive_column_keys_with_row_id, extract_i64_from_kh_entries, extract_value_from_kh_entries,
    partition_composite_entry, read_kh_ranges_indexed, read_next_id, table_from_column_keys,
    validate_key_history_entries, validate_sorted_entries, validate_user_access, OpContext,
    OpReader, OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::{ReadOp, TraceStep};
use encrypted_spaces_storage_encoding::keys::{column_key, KEY_HISTORY_TABLE, USERS_TABLE};
/// Columns that a RefreshKeys operation is allowed to modify on `_users`.
pub const REFRESH_KEYS_ALLOWED_COLUMNS: &[&str] = &["update_key", "auth_key", "status"];

/// RefreshKeys operation verifier.
///
/// Like UpdateOp, but additionally validates:
/// - The target table is `_users`
/// - Only `update_key`, `auth_key`, and `status` columns are modified
pub struct RefreshKeysOp;

impl OpVerifier for RefreshKeysOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_sorted_entries(entry, "refresh_keys")?;

        // Partition the signed entry into _key_history + _users portions.
        let parts = partition_composite_entry(entry, "refresh_keys")?;
        if !parts.retention.is_empty() {
            return Err(ChangelogError::Generic(
                "refresh_keys: unexpected _retention entries".to_string(),
            ));
        }
        let kh_entries = parts.key_history;
        let users_entries = parts.users;
        if kh_entries.is_empty() {
            return Err(ChangelogError::Generic(
                "refresh_keys: \
                 _key_history entries must not be empty"
                    .to_string(),
            ));
        }
        if users_entries.is_empty() {
            return Err(ChangelogError::Generic(
                "refresh_keys: \
                 _users entries must not be empty"
                    .to_string(),
            ));
        }

        validate_user_access(entry, OpType::RefreshKeys, "refresh_keys", reader)?;

        // Read the authenticated _key_history next-id counter and derive
        // the real _key_history column keys from the placeholder keys.
        let kh_row_id = read_next_id(KEY_HISTORY_TABLE, "refresh_keys", reader)?;
        let kh_column_keys =
            derive_column_keys_with_row_id(&kh_entries, kh_row_id, "refresh_keys")?;

        // Validate kh structure (column tuples, required columns, uid).
        let kh_row_id_check =
            validate_key_history_entries(&kh_column_keys, &kh_entries, entry.uid, "refresh_keys")?;
        debug_assert_eq!(kh_row_id, kh_row_id_check);

        // _users column keys come straight from the (signed) entry.
        let users_column_keys: Vec<Vec<u8>> =
            users_entries.iter().map(|kv| kv.key.clone()).collect();

        // Must target the _users table
        let table = table_from_column_keys(&users_column_keys, "refresh_keys")?;
        if table != "_users" {
            return Err(ChangelogError::Generic(format!(
                "refresh_keys: must target _users table, got '{table}'"
            )));
        }

        // Only allowed _users columns
        let actual = column_names_from_keys(&users_column_keys);
        for column in &actual {
            if !REFRESH_KEYS_ALLOWED_COLUMNS.contains(&column.as_str()) {
                return Err(ChangelogError::Generic(format!(
                    "refresh_keys: column '{column}' \
                     is not allowed (only {:?})",
                    REFRESH_KEYS_ALLOWED_COLUMNS
                )));
            }
        }

        // --- Semantic validation of _key_history values ---

        // valid_to_change_id must equal entry.sig_ref (the signer's last
        // change before this rotation).
        let valid_to =
            extract_i64_from_kh_entries(&kh_entries, "valid_to_change_id", "refresh_keys")?;
        if valid_to != entry.sig_ref as i64 {
            return Err(ChangelogError::Generic(format!(
                "refresh_keys: \
                 _key_history.valid_to_change_id={valid_to} \
                 does not match entry.sig_ref={}",
                entry.sig_ref
            )));
        }

        // valid_from_change_id must be <= valid_to_change_id.
        let valid_from =
            extract_i64_from_kh_entries(&kh_entries, "valid_from_change_id", "refresh_keys")?;
        if valid_from > valid_to {
            return Err(ChangelogError::Generic(format!(
                "refresh_keys: \
                 _key_history.valid_from_change_id={valid_from} \
                 must be <= valid_to_change_id={valid_to}"
            )));
        }

        // old_auth_key must match the current _users.auth_key for this user.
        let old_auth_key =
            extract_value_from_kh_entries(&kh_entries, "old_auth_key", "refresh_keys")?;
        let auth_key_key = column_key(USERS_TABLE, entry.uid as i64, "auth_key");
        let auth_read = reader.read(ReadOp::Key(auth_key_key))?;
        let (_, current_auth_key_bytes) = auth_read.results.first().ok_or_else(|| {
            ChangelogError::Generic(format!(
                "refresh_keys: \
                 _users.auth_key not found for uid={}",
                entry.uid
            ))
        })?;
        if old_auth_key.as_slice() != current_auth_key_bytes.as_slice() {
            return Err(ChangelogError::Generic(format!(
                "refresh_keys: \
                 _key_history.old_auth_key does not match \
                 current _users.auth_key for uid={}",
                entry.uid
            )));
        }

        // New _key_history range must not overlap any existing rows for this uid
        // and must be contiguous with the previous range (no gaps).
        let existing_ranges = read_kh_ranges_indexed(entry.uid, reader, "refresh_keys")?;
        for (prev_from, prev_to) in &existing_ranges {
            if valid_from <= *prev_to && *prev_from <= valid_to {
                return Err(ChangelogError::Generic(format!(
                    "refresh_keys: \
                     new _key_history range [{valid_from}, {valid_to}] \
                     overlaps existing range [{prev_from}, {prev_to}] \
                     for uid={}",
                    entry.uid
                )));
            }
        }

        if !existing_ranges.is_empty() {
            // Continuity: new valid_from must equal max(existing valid_to) + 1.
            let max_prev_to = existing_ranges.iter().map(|(_, to)| *to).max().unwrap();
            let expected_from = max_prev_to + 1;
            if valid_from != expected_from {
                return Err(ChangelogError::Generic(format!(
                    "refresh_keys: \
                     _key_history.valid_from_change_id={valid_from} \
                     must be {expected_from} (previous valid_to + 1) \
                     for uid={}",
                    entry.uid
                )));
            }
        } else if valid_from != 0 {
            // For the first rotation (no prior rows), valid_from must be 0.
            return Err(ChangelogError::Generic(format!(
                "refresh_keys: \
                 _key_history.valid_from_change_id={valid_from} \
                 must be 0 for the first rotation of uid={}",
                entry.uid
            )));
        }

        // Emit batch ops in the canonical (kh-then-users) order, sorted by key.
        let mut batch_ops: Vec<_> = kh_column_keys
            .iter()
            .zip(kh_entries.iter())
            .chain(users_column_keys.iter().zip(users_entries.iter()))
            .map(|(col_key, kv)| kv.to_batch_op(col_key))
            .collect();
        append_insert_index_puts(
            &mut batch_ops,
            KEY_HISTORY_TABLE,
            kh_row_id,
            &kh_entries,
            "refresh_keys",
            reader,
            ctx,
        )?;

        // Counter bump (we already read the counter above).
        bump_next_id_after_chain(
            &mut batch_ops,
            KEY_HISTORY_TABLE,
            kh_row_id,
            1,
            "refresh_keys",
        )?;

        batch_ops.sort_by(|a, b| a.key().cmp(b.key()));

        Ok(OpVerifyResult {
            write_steps: vec![TraceStep::Write(batch_ops)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage};
    use crate::ops::VerifierReader;
    use crate::{ProvenRead, ReadOp};
    use encrypted_spaces_storage_encoding::keys::{
        column_key, column_key_placeholder, index_key, index_value_prefix, schema_indexes_key,
        schema_next_id_key, KEY_HISTORY_TABLE,
    };
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
    use encrypted_spaces_storage_encoding::{hashstore_hash, row_id_to_bytes};

    fn user_status_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "status")
    }

    fn user_auth_key_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "auth_key")
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

    /// Build a combined entry with _key_history (sorted first) + _users entries.
    fn make_combined_entry(uid: u32, kh_kvs: Vec<KvData>, user_keys: &[Vec<u8>]) -> ChangelogEntry {
        make_combined_entry_with_sig_ref(uid, kh_kvs, user_keys, 0)
    }

    fn make_combined_entry_with_sig_ref(
        uid: u32,
        kh_kvs: Vec<KvData>,
        user_keys: &[Vec<u8>],
        sig_ref: u32,
    ) -> ChangelogEntry {
        let user_kvs: Vec<KvData> = user_keys
            .iter()
            .map(|key| KvData {
                key: key.clone(),
                value: vec![0xAA; 32],
            })
            .collect();
        let mut entries = kh_kvs;
        entries.extend(user_kvs);
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::RefreshKeys,
                tree_path: vec![],
                entries,
            },
            sig_ref,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn kh_kv(col: &str, _uid: u32, value: &[u8]) -> KvData {
        KvData {
            key: column_key_placeholder(KEY_HISTORY_TABLE, col),
            value: value.to_vec(),
        }
    }

    /// Build _key_history KvData entries with custom parameters.
    fn make_kh_kvs_with(uid: u32, auth_key: &[u8], valid_from: i64, valid_to: i64) -> Vec<KvData> {
        let uid_json = stored_i64(uid as i64);
        let from_json = stored_i64(valid_from);
        let to_json = stored_i64(valid_to);
        let mut kvs = vec![
            kh_kv("old_auth_key", uid, auth_key),
            kh_kv("uid", uid, &uid_json),
            kh_kv("valid_from_change_id", uid, &from_json),
            kh_kv("valid_to_change_id", uid, &to_json),
        ];
        kvs.sort_by(|a, b| a.key.cmp(&b.key));
        kvs
    }

    /// Default _key_history entries: first rotation (valid_from=0, valid_to=0, sig_ref=0).
    fn make_kh_kvs(uid: u32) -> Vec<KvData> {
        make_kh_kvs_with(uid, &test_auth_key(), 0, 0)
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

    /// Build the ProvenRead entries for the semantic validation reads:
    /// _key_history next_id read + auth_key read + _key_history uid index scan.
    ///
    /// Read order matches the verifier:
    ///   1. _key_history next_id (to derive the kh row_id)
    ///   2. _users.auth_key (for the old_auth_key check)
    ///   3. _key_history uid index prefix (existing-range scan)
    ///   4. _key_history schema_indexes (for index puts)
    fn make_semantic_reads(uid: u32, auth_key_value: &[u8]) -> Vec<ProvenRead> {
        let ak = user_auth_key_key(uid);
        vec![
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key(KEY_HISTORY_TABLE)),
                results: vec![(
                    schema_next_id_key(KEY_HISTORY_TABLE),
                    1i64.to_be_bytes().to_vec(),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(ak.clone()),
                results: vec![(ak, auth_key_value.to_vec())],
            },
            ProvenRead {
                op: ReadOp::Prefix(
                    index_value_prefix(KEY_HISTORY_TABLE, "uid", uid as i64).unwrap(),
                ),
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key(KEY_HISTORY_TABLE)),
                results: vec![(schema_indexes_key(KEY_HISTORY_TABLE), b"uid".to_vec())],
            },
        ]
    }

    /// Build the ProvenRead entries for semantic validation with existing
    /// _key_history rows discovered via the uid index.
    fn make_semantic_reads_with_existing(
        uid: u32,
        auth_key_value: &[u8],
        existing_rows: Vec<(i64, i64, i64)>,
    ) -> Vec<ProvenRead> {
        let ak = user_auth_key_key(uid);
        // Pick the smallest unused row_id as the next_id (rows start at 1).
        let used: std::collections::BTreeSet<i64> =
            existing_rows.iter().map(|(rid, _, _)| *rid).collect();
        let next_id = (1i64..).find(|i| !used.contains(i)).unwrap();
        let mut reads = vec![
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key(KEY_HISTORY_TABLE)),
                results: vec![(
                    schema_next_id_key(KEY_HISTORY_TABLE),
                    next_id.to_be_bytes().to_vec(),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(ak.clone()),
                results: vec![(ak, auth_key_value.to_vec())],
            },
            ProvenRead {
                op: ReadOp::Prefix(
                    index_value_prefix(KEY_HISTORY_TABLE, "uid", uid as i64).unwrap(),
                ),
                results: existing_rows
                    .iter()
                    .map(|(row_id, _, _)| {
                        (
                            index_key(KEY_HISTORY_TABLE, "uid", uid as i64, *row_id).unwrap(),
                            row_id_to_bytes(*row_id).to_vec(),
                        )
                    })
                    .collect(),
            },
        ];
        for (row_id, valid_from, valid_to) in existing_rows {
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
        reads.push(ProvenRead {
            op: ReadOp::Key(schema_indexes_key(KEY_HISTORY_TABLE)),
            results: vec![(schema_indexes_key(KEY_HISTORY_TABLE), b"uid".to_vec())],
        });
        reads
    }

    #[test]
    fn test_provisional_user_allowed_for_refresh_keys() {
        let uid = 1u32;
        let col = column_key("_users", uid as i64, "update_key");
        let kh_kvs = make_kh_kvs(uid);
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&col));
        let _kh_column_keys = make_kh_column_keys();

        // Provisional user (status=0) should be allowed for RefreshKeys
        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(0))],
        }];
        reads.extend(make_semantic_reads(uid, &test_auth_key()));
        let mut reader = VerifierReader::new(&reads);
        assert!(RefreshKeysOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext::default(),
        )
        .is_ok());
    }

    #[test]
    fn test_provisional_user_rejected_for_update() {
        use crate::ops::UpdateOp;
        use encrypted_spaces_storage_encoding::keys::schema_columns_key;

        let uid = 1u32;
        let col = column_key("t", 5, "name");
        let entries = vec![KvData {
            key: col.clone(),
            value: vec![0xBB; 32],
        }];
        let entry = ChangelogEntry {
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
        };

        // Provisional user (status=0) should be rejected for Update
        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(0))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("t")),
                results: vec![(schema_columns_key("t"), b"name".to_vec())],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = UpdateOp::extract_and_validate(&entry, &mut reader, &super::OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("provisional user"), "unexpected error: {msg}");
    }

    #[test]
    fn test_non_provisional_user_allowed_for_refresh_keys() {
        let uid = 1u32;
        let col = column_key("_users", uid as i64, "update_key");
        let kh_kvs = make_kh_kvs(uid);
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&col));
        let _kh_column_keys = make_kh_column_keys();

        // Non-provisional user (status=1) should also be allowed for RefreshKeys
        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads(uid, &test_auth_key()));
        let mut reader = VerifierReader::new(&reads);
        assert!(RefreshKeysOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::OpContext::default(),
        )
        .is_ok());
    }

    #[test]
    fn test_kh_correct_entry_accepted() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        let kh_kvs = make_kh_kvs(uid);
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&user_col));
        let _kh_column_keys = make_kh_column_keys();

        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads(uid, &test_auth_key()));
        let mut reader = VerifierReader::new(&reads);
        let result =
            RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(result.is_ok(), "expected ok, got: {:?}", result.err());
    }

    /// Second rotation with non-zero sig_ref and existing history rows is accepted
    /// when ranges are contiguous.
    #[test]
    fn test_kh_second_rotation_accepted() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // Second rotation: existing row ends at 0, so new range starts at 1.
        let kh_kvs = make_kh_kvs_with(uid, &test_auth_key(), 1, 8);
        let entry =
            make_combined_entry_with_sig_ref(uid, kh_kvs, std::slice::from_ref(&user_col), 8);
        let _kh_column_keys = make_kh_column_keys();

        // Existing _key_history row from the first rotation: uid=1, [0, 0]
        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads_with_existing(
            uid,
            &test_auth_key(),
            vec![(1, 0, 0)],
        ));
        let mut reader = VerifierReader::new(&reads);
        let result =
            RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(result.is_ok(), "expected ok, got: {:?}", result.err());
    }

    #[test]
    fn test_kh_gap_after_previous_range_rejected() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // Existing history ends at 0, so the next range must start at 1.
        // The current verifier only checks for overlap, so it incorrectly
        // accepts this gap.
        let kh_kvs = make_kh_kvs_with(uid, &test_auth_key(), 5, 8);
        let entry =
            make_combined_entry_with_sig_ref(uid, kh_kvs, std::slice::from_ref(&user_col), 8);
        let _kh_column_keys = make_kh_column_keys();

        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads_with_existing(
            uid,
            &test_auth_key(),
            vec![(1, 0, 0)],
        ));
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err(), "gap in key history should be rejected");
    }

    #[test]
    fn test_kh_uid_mismatch_rejected() {
        let uid = 1u32;
        let attacker_uid = 2u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // _key_history has uid=2 but the change is from uid=1
        let kh_kvs = make_kh_kvs(attacker_uid);
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&user_col));
        let _kh_column_keys = make_kh_column_keys();

        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key(KEY_HISTORY_TABLE)),
                results: vec![(
                    schema_next_id_key(KEY_HISTORY_TABLE),
                    1i64.to_be_bytes().to_vec(),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("uid=2") && msg.contains("does not match"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_kh_missing_required_column_rejected() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // Only include 2 of 4 required _key_history columns
        let uid_json = stored_i64(uid as i64);
        let mut kh_kvs = vec![
            kh_kv("uid", uid, &uid_json),
            kh_kv("old_auth_key", uid, &stored_str("key")),
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&user_col));

        let mut kh_keys = [
            column_key("_key_history", 1, "uid"),
            column_key("_key_history", 1, "old_auth_key"),
        ];
        kh_keys.sort();

        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key(KEY_HISTORY_TABLE)),
                results: vec![(
                    schema_next_id_key(KEY_HISTORY_TABLE),
                    1i64.to_be_bytes().to_vec(),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("missing required column"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_kh_wrong_table_rejected() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // _key_history entries target wrong table (_bad sorts before _users)
        let uid_json = stored_i64(uid as i64);
        let mut kh_kvs = vec![
            KvData {
                key: column_key_placeholder("_bad", "old_auth_key"),
                value: vec![0xBB; 32],
            },
            KvData {
                key: column_key_placeholder("_bad", "uid"),
                value: uid_json,
            },
            KvData {
                key: column_key_placeholder("_bad", "valid_from_change_id"),
                value: stored_i64(0),
            },
            KvData {
                key: column_key_placeholder("_bad", "valid_to_change_id"),
                value: stored_i64(0),
            },
        ];
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));

        // Note: must put kh_ entries before user entries for sorted order
        let mut all_entries = kh_kvs;
        all_entries.push(KvData {
            key: user_col.clone(),
            value: vec![0xAA; 32],
        });
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::RefreshKeys,
                tree_path: vec![],
                entries: all_entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };

        let mut kh_keys = [
            column_key("_bad", 1, "old_auth_key"),
            column_key("_bad", 1, "uid"),
            column_key("_bad", 1, "valid_from_change_id"),
            column_key("_bad", 1, "valid_to_change_id"),
        ];
        kh_keys.sort();

        let sk = user_status_key(uid);
        let reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("_bad"), "unexpected error: {msg}");
    }

    // ── New semantic validation rejection tests ──────────────────────────

    /// Reject when old_auth_key does not match the current _users.auth_key.
    #[test]
    fn test_kh_old_auth_key_tampered_rejected() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // Tampered auth key in _key_history entry
        let kh_kvs = make_kh_kvs_with(uid, b"\"wrong_key\"", 0, 0);
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&user_col));
        let _kh_column_keys = make_kh_column_keys();

        // The tree has the real auth_key, which differs from "wrong_key"
        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads(uid, &test_auth_key()));
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("old_auth_key does not match"),
            "unexpected error: {msg}"
        );
    }

    /// Reject when valid_to_change_id != entry.sig_ref.
    #[test]
    fn test_kh_valid_to_mismatch_rejected() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // valid_to=5 but sig_ref will be 0 → mismatch
        let kh_kvs = make_kh_kvs_with(uid, &test_auth_key(), 0, 5);
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&user_col));
        // entry.sig_ref is 0, but valid_to is 5
        let _kh_column_keys = make_kh_column_keys();

        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key(KEY_HISTORY_TABLE)),
                results: vec![(
                    schema_next_id_key(KEY_HISTORY_TABLE),
                    1i64.to_be_bytes().to_vec(),
                )],
            },
        ];
        // No semantic reads needed beyond next_id — fails before auth_key read
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("valid_to_change_id=5") && msg.contains("sig_ref=0"),
            "unexpected error: {msg}"
        );
    }

    /// Reject when valid_from_change_id > valid_to_change_id.
    #[test]
    fn test_kh_valid_from_greater_than_valid_to_rejected() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // valid_from=10 > valid_to=5, sig_ref=5
        let kh_kvs = make_kh_kvs_with(uid, &test_auth_key(), 10, 5);
        let entry =
            make_combined_entry_with_sig_ref(uid, kh_kvs, std::slice::from_ref(&user_col), 5);
        let _kh_column_keys = make_kh_column_keys();

        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key(KEY_HISTORY_TABLE)),
                results: vec![(
                    schema_next_id_key(KEY_HISTORY_TABLE),
                    1i64.to_be_bytes().to_vec(),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("valid_from_change_id=10") && msg.contains("must be <="),
            "unexpected error: {msg}"
        );
    }

    /// Reject when new _key_history range overlaps an existing row.
    #[test]
    fn test_kh_range_overlap_rejected() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // New range [0, 5], but existing row covers [3, 7] → overlap
        let kh_kvs = make_kh_kvs_with(uid, &test_auth_key(), 0, 5);
        let entry =
            make_combined_entry_with_sig_ref(uid, kh_kvs, std::slice::from_ref(&user_col), 5);
        let _kh_column_keys = make_kh_column_keys();

        // Existing _key_history row for uid=1 covers [3, 7]
        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads_with_existing(
            uid,
            &test_auth_key(),
            vec![(1, 3, 7)],
        ));
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("overlaps existing range"),
            "unexpected error: {msg}"
        );
    }

    /// Existing _key_history rows for a *different* uid should not block.
    #[test]
    fn test_kh_other_uid_rows_do_not_block() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        let kh_kvs = make_kh_kvs(uid);
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&user_col));
        let _kh_column_keys = make_kh_column_keys();

        // The uid index scan only returns rows for uid=1, so other users' history
        // rows are naturally excluded from consideration.
        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads(uid, &test_auth_key()));
        let mut reader = VerifierReader::new(&reads);
        let result =
            RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(result.is_ok(), "expected ok, got: {:?}", result.err());
    }

    /// First rotation must have valid_from_change_id == 0.
    #[test]
    fn test_kh_first_rotation_nonzero_valid_from_rejected() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        // First rotation but valid_from=3 instead of 0, sig_ref=5
        let kh_kvs = make_kh_kvs_with(uid, &test_auth_key(), 3, 5);
        let entry =
            make_combined_entry_with_sig_ref(uid, kh_kvs, std::slice::from_ref(&user_col), 5);
        let _kh_column_keys = make_kh_column_keys();

        // No existing rows → first rotation
        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads(uid, &test_auth_key()));
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("must be 0") && msg.contains("first rotation"),
            "unexpected error: {msg}"
        );
    }

    fn hash_ref(data: &[u8]) -> Vec<u8> {
        hashstore_hash(data).to_vec()
    }

    #[test]
    fn test_refresh_keys_key_hash_matching_stored_hashes_accepted() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");

        let full_key_bytes = test_auth_key();
        let hash = hash_ref(&full_key_bytes);

        let kh_kvs = make_kh_kvs_with(uid, &hash, 0, 0);
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&user_col));

        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads(uid, &hash));
        let mut reader = VerifierReader::new(&reads);
        let result =
            RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(result.is_ok(), "expected ok, got: {:?}", result.err());
    }

    #[test]
    fn test_refresh_keys_key_hash_mismatched_stored_hashes_rejected() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");

        let hash_a = hash_ref(b"key_a");
        let hash_b = hash_ref(b"key_b");

        let kh_kvs = make_kh_kvs_with(uid, &hash_a, 0, 0);
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&user_col));

        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads(uid, &hash_b));
        let mut reader = VerifierReader::new(&reads);
        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("old_auth_key does not match"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_refresh_keys_key_hash_no_hashed_values_required() {
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");

        let hash = hash_ref(&test_auth_key());
        assert_eq!(hash.len(), 32);

        let kh_kvs = make_kh_kvs_with(uid, &hash, 1, 8);
        let entry =
            make_combined_entry_with_sig_ref(uid, kh_kvs, std::slice::from_ref(&user_col), 8);

        let sk = user_status_key(uid);
        let mut reads = vec![ProvenRead {
            op: ReadOp::Key(sk.clone()),
            results: vec![(sk, stored_i64(1))],
        }];
        reads.extend(make_semantic_reads_with_existing(
            uid,
            &hash,
            vec![(1, 0, 0)],
        ));
        let mut reader = VerifierReader::new(&reads);
        let result =
            RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default());
        assert!(
            result.is_ok(),
            "E&V should accept matching 32-byte hash references \
             without HashedValues: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_refresh_keys_rejects_key_history_keys_for_multiple_rows() {
        // After the OpInput cleanup, kh column_keys are derived from the entry,
        // not supplied by the proof. The "split row" attack now manifests as
        // an entry whose _key_history entries carry a non-zero (i.e. real)
        // row_id instead of the placeholder row_id=0. That is rejected by
        // `rebuild_column_key_with_row_id` on the placeholder check.
        let uid = 1u32;
        let user_col = column_key("_users", uid as i64, "update_key");
        let mut kh_kvs = make_kh_kvs(uid);
        // Tamper one _key_history entry to use row_id=2 instead of placeholder=0.
        kh_kvs[0].key = column_key("_key_history", 2, "old_auth_key");
        kh_kvs.sort_by(|a, b| a.key.cmp(&b.key));
        let entry = make_combined_entry(uid, kh_kvs, std::slice::from_ref(&user_col));

        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, stored_i64(1))],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key(KEY_HISTORY_TABLE)),
                results: vec![(
                    schema_next_id_key(KEY_HISTORY_TABLE),
                    1i64.to_be_bytes().to_vec(),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let err = RefreshKeysOp::extract_and_validate(&entry, &mut reader, &OpContext::default())
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("expected the placeholder row_id=0"),
            "unexpected error: {msg}"
        );
    }
}
