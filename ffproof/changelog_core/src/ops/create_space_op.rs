use super::{
    append_multi_row_insert_index_puts, bump_next_id_after_chain, column_names_from_keys,
    derive_column_keys_for_chain, derive_column_keys_with_row_id, next_id_after, next_id_put,
    partition_composite_entry, read_next_id, read_schema_columns, OpReader, OpVerifier,
    OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError};
use crate::{ReadOp, WriteOp};
/// CreateSpace operation verifier.
pub struct CreateSpaceOp;

impl OpVerifier for CreateSpaceOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &super::OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        let parts = partition_composite_entry(entry, "create_space")?;
        if !parts.key_history.is_empty() {
            return Err(ChangelogError::Generic(
                "create_space: unexpected _key_history entries".to_string(),
            ));
        }
        let user_entries = parts.users;
        let retention_entries = parts.retention;
        if user_entries.is_empty() {
            return Err(ChangelogError::Generic(
                "create_space: _users entries must not be empty".to_string(),
            ));
        }

        // --- Verify no users exist yet ---
        let users_read = reader.read(ReadOp::Prefix(crate::row_prefix(crate::USERS_TABLE)))?;
        if !users_read.results.is_empty() {
            return Err(ChangelogError::Generic(
                "create_space: users table is not empty — \
                 CreateSpace can only be called on an empty space"
                    .to_string(),
            ));
        }

        // --- Validate user insert covers all schema columns ---
        let expected_user_cols =
            read_schema_columns(crate::USERS_TABLE, "create_space", reader, ctx)?;
        let user_entry_keys: Vec<Vec<u8>> = user_entries.iter().map(|kv| kv.key.clone()).collect();
        let actual_user_cols = column_names_from_keys(&user_entry_keys);
        if actual_user_cols != expected_user_cols {
            let missing: Vec<_> = expected_user_cols.difference(&actual_user_cols).collect();
            return Err(ChangelogError::Generic(format!(
                "create_space: _users insert missing columns {missing:?}"
            )));
        }

        // Read the authenticated _users next_id counter and derive real
        // _users column keys with that row_id.
        let user_row_id = read_next_id(crate::USERS_TABLE, "create_space", reader)?;
        let user_column_keys =
            derive_column_keys_with_row_id(&user_entries, user_row_id, "create_space")?;

        let mut batch_ops: Vec<WriteOp> =
            Vec::with_capacity(user_column_keys.len() + retention_entries.len());
        for (col_key, kv) in user_column_keys.iter().zip(user_entries.iter()) {
            batch_ops.push(kv.to_batch_op(col_key));
        }

        // Counter was already read to derive `user_row_id`; emit the bump Put.
        let next_user_id = next_id_after(user_row_id, crate::USERS_TABLE, "create_space")?;
        batch_ops.push(next_id_put(crate::USERS_TABLE, next_user_id));

        if !retention_entries.is_empty() {
            let expected_retention_cols =
                read_schema_columns(crate::RETENTION_TABLE, "create_space", reader, ctx)?;
            let retention_entry_keys: Vec<Vec<u8>> =
                retention_entries.iter().map(|kv| kv.key.clone()).collect();
            let actual_retention_cols = column_names_from_keys(&retention_entry_keys);
            if actual_retention_cols != expected_retention_cols {
                let missing: Vec<_> = expected_retention_cols
                    .difference(&actual_retention_cols)
                    .collect();
                return Err(ChangelogError::Generic(format!(
                    "create_space: _retention missing columns {missing:?}"
                )));
            }
            let retention_col_count = expected_retention_cols.len();
            if retention_col_count == 0 {
                return Err(ChangelogError::Generic(
                    "create_space: _retention has no schema columns".to_string(),
                ));
            }
            if retention_entries.len() % retention_col_count != 0 {
                return Err(ChangelogError::Generic(format!(
                    "create_space: _retention entry count {} is not a \
                     multiple of col_count={retention_col_count}",
                    retention_entries.len()
                )));
            }

            // Read the retention counter and derive real per-row keys.
            let retention_counter = read_next_id(crate::RETENTION_TABLE, "create_space", reader)?;
            let retention_column_keys = derive_column_keys_for_chain(
                &retention_entries,
                retention_counter,
                retention_col_count,
                "create_space",
            )?;
            for (col_key, kv) in retention_column_keys.iter().zip(retention_entries.iter()) {
                batch_ops.push(kv.to_batch_op(col_key));
            }

            append_multi_row_insert_index_puts(
                &mut batch_ops,
                crate::RETENTION_TABLE,
                &retention_column_keys,
                &retention_entries,
                "create_space",
                reader,
                ctx,
            )?;

            let num_rows = (retention_entries.len() / retention_col_count) as i64;
            bump_next_id_after_chain(
                &mut batch_ops,
                crate::RETENTION_TABLE,
                retention_counter,
                num_rows,
                "create_space",
            )?;
        }

        Ok(OpVerifyResult {
            write_steps: batch_ops,
        })
    }
}
