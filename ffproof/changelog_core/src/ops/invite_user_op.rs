use super::{
    append_multi_row_insert_index_puts, bump_next_id_after_chain, column_names_from_keys,
    derive_column_keys_for_chain, derive_column_keys_with_row_id, extract_i64_column_from_entry,
    is_provisional_status, next_id_after, next_id_put, partition_composite_entry, read_next_id,
    read_schema_columns, validate_user_access, OpReader, OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::WriteOp;
/// InviteUser operation verifier.
///
/// # User-ID allocation
///
/// New-user UIDs are allocated the same way as any other insert — read
/// from the `_users` table's `schema_next_id_key` counter and bumped
/// with a counter `Put`.  UIDs are therefore sequential and
/// monotonically increasing, not randomized.
pub struct InviteUserOp;

impl OpVerifier for InviteUserOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &super::OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        let parts = partition_composite_entry(entry, "invite_user")?;
        if !parts.key_history.is_empty() {
            return Err(ChangelogError::Generic(
                "invite_user: unexpected _key_history entries".to_string(),
            ));
        }
        let user_entries = parts.users;
        let retention_entries = parts.retention;
        if user_entries.is_empty() {
            return Err(ChangelogError::Generic(
                "invite_user: _users entries must not be empty".to_string(),
            ));
        }

        validate_user_access(entry, OpType::InviteUser, "invite_user", reader)?;

        let expected_user_cols =
            read_schema_columns(crate::USERS_TABLE, "invite_user", reader, ctx)?;
        let user_entry_keys: Vec<Vec<u8>> = user_entries.iter().map(|kv| kv.key.clone()).collect();
        let actual_user_cols = column_names_from_keys(&user_entry_keys);
        if actual_user_cols != expected_user_cols {
            let missing: Vec<_> = expected_user_cols.difference(&actual_user_cols).collect();
            return Err(ChangelogError::Generic(format!(
                "invite_user: _users insert missing columns {missing:?}"
            )));
        }

        // --- Validate that the status of the new user row is set to provisional ---
        let inserted_status =
            extract_i64_column_from_entry(entry, crate::USERS_TABLE, "status", "invite_user")?;
        if !is_provisional_status(inserted_status) {
            return Err(ChangelogError::Generic(format!(
                "invite_user: inserted _users.status must be provisional (0), got {inserted_status}"
            )));
        }

        let user_row_id = read_next_id(crate::USERS_TABLE, "invite_user", reader)?;
        let user_column_keys =
            derive_column_keys_with_row_id(&user_entries, user_row_id, "invite_user")?;

        let mut batch_ops: Vec<WriteOp> =
            Vec::with_capacity(user_column_keys.len() + retention_entries.len());
        for (col_key, kv) in user_column_keys.iter().zip(user_entries.iter()) {
            batch_ops.push(kv.to_batch_op(col_key));
        }

        // Counter was already read to derive `user_row_id`; emit the bump Put.
        let next_user_id = next_id_after(user_row_id, crate::USERS_TABLE, "invite_user")?;
        batch_ops.push(next_id_put(crate::USERS_TABLE, next_user_id));

        if !retention_entries.is_empty() {
            let expected_retention_cols =
                read_schema_columns(crate::RETENTION_TABLE, "invite_user", reader, ctx)?;
            let retention_entry_keys: Vec<Vec<u8>> =
                retention_entries.iter().map(|kv| kv.key.clone()).collect();
            let actual_retention_cols = column_names_from_keys(&retention_entry_keys);
            if actual_retention_cols != expected_retention_cols {
                let missing: Vec<_> = expected_retention_cols
                    .difference(&actual_retention_cols)
                    .collect();
                return Err(ChangelogError::Generic(format!(
                    "invite_user: _retention insert missing columns {missing:?}"
                )));
            }
            let retention_col_count = expected_retention_cols.len();
            if retention_col_count == 0 {
                return Err(ChangelogError::Generic(
                    "invite_user: _retention has no schema columns".to_string(),
                ));
            }
            if retention_entries.len() % retention_col_count != 0 {
                return Err(ChangelogError::Generic(format!(
                    "invite_user: _retention entry count {} is not a \
                     multiple of col_count={retention_col_count}",
                    retention_entries.len()
                )));
            }

            let retention_counter = read_next_id(crate::RETENTION_TABLE, "invite_user", reader)?;
            let retention_column_keys = derive_column_keys_for_chain(
                &retention_entries,
                retention_counter,
                retention_col_count,
                "invite_user",
            )?;
            for (col_key, kv) in retention_column_keys.iter().zip(retention_entries.iter()) {
                batch_ops.push(kv.to_batch_op(col_key));
            }

            append_multi_row_insert_index_puts(
                &mut batch_ops,
                crate::RETENTION_TABLE,
                &retention_column_keys,
                &retention_entries,
                "invite_user",
                reader,
                ctx,
            )?;

            let num_rows = (retention_entries.len() / retention_col_count) as i64;
            bump_next_id_after_chain(
                &mut batch_ops,
                crate::RETENTION_TABLE,
                retention_counter,
                num_rows,
                "invite_user",
            )?;
        }

        Ok(OpVerifyResult {
            write_steps: batch_ops,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage};
    use crate::ops::VerifierReader;
    use crate::{ProvenRead, ReadOp};
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
    use encrypted_spaces_storage_encoding::{
        encode_column_names,
        keys::{column_key, schema_columns_key},
    };
    use std::collections::BTreeSet;

    fn user_status_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "status")
    }

    fn make_invite_entry(
        uid: u32,
        user_keys: &[Vec<u8>],
        retention_keys: &[Vec<u8>],
    ) -> ChangelogEntry {
        let entries: Vec<KvData> = user_keys
            .iter()
            .chain(retention_keys.iter())
            .map(|key| KvData {
                key: key.clone(),
                value: vec![0xAA; 32],
            })
            .collect();
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::InviteUser,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn make_invite_entry_with_status(
        uid: u32,
        user_keys: &[Vec<u8>],
        retention_keys: &[Vec<u8>],
        status: i64,
    ) -> ChangelogEntry {
        let status_bytes = value_to_bytes(&serde_json::json!(status)).unwrap();
        let status_key = &user_keys[1];
        let entries: Vec<KvData> = user_keys
            .iter()
            .chain(retention_keys.iter())
            .map(|key| KvData {
                key: key.clone(),
                value: if key == status_key {
                    status_bytes.clone()
                } else {
                    vec![0xAA; 32]
                },
            })
            .collect();
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::InviteUser,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn test_provisional_user_rejected_for_invite_user() {
        let uid = 1u32;
        let user_row_id = 5i64;
        let user_keys = vec![
            column_key("_users", user_row_id, "auth_key"),
            column_key("_users", user_row_id, "status"),
            column_key("_users", user_row_id, "update_key"),
        ];
        let retention_keys = vec![
            column_key("_retention", 0, "key"),
            column_key("_retention", 0, "value"),
        ];
        let entry = make_invite_entry(uid, &user_keys, &retention_keys);

        let user_cols: BTreeSet<String> = ["auth_key", "status", "update_key"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let retention_cols: BTreeSet<String> =
            ["key", "value"].into_iter().map(str::to_string).collect();
        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, value_to_bytes(&serde_json::json!(0)).unwrap())],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_users")),
                results: vec![(
                    schema_columns_key("_users"),
                    encode_column_names(&user_cols),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_retention")),
                results: vec![(
                    schema_columns_key("_retention"),
                    encode_column_names(&retention_cols),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let err = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("provisional user"), "unexpected error: {msg}");
    }

    #[test]
    fn test_invited_user_must_be_provisional() {
        let uid = 1u32;
        let user_row_id = 5i64;
        let user_keys = vec![
            column_key("_users", user_row_id, "auth_key"),
            column_key("_users", user_row_id, "status"),
            column_key("_users", user_row_id, "update_key"),
        ];
        let retention_keys = vec![
            column_key("_retention", 0, "key"),
            column_key("_retention", 0, "value"),
        ];
        let entry = make_invite_entry_with_status(uid, &user_keys, &retention_keys, 1);

        let user_cols: BTreeSet<String> = ["auth_key", "status", "update_key"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let retention_cols: BTreeSet<String> =
            ["key", "value"].into_iter().map(str::to_string).collect();
        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, value_to_bytes(&serde_json::json!(1)).unwrap())],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_users")),
                results: vec![(
                    schema_columns_key("_users"),
                    encode_column_names(&user_cols),
                )],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("_retention")),
                results: vec![(
                    schema_columns_key("_retention"),
                    encode_column_names(&retention_cols),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let err = InviteUserOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("inserted _users.status must be provisional"),
            "unexpected error: {msg}"
        );
    }
}
