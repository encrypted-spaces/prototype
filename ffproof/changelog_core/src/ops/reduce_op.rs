use super::{
    append_multi_row_insert_index_puts, bump_next_id_after_chain, column_names_from_keys,
    derive_column_keys_for_chain, read_next_id, read_schema_columns, table_from_column_keys,
    validate_user_access, OpReader, OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::{BatchOp, TraceStep};
/// Reduce operation verifier.
pub struct ReduceOp;

impl OpVerifier for ReduceOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &super::OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        if entry.message.entries.is_empty() {
            return Err(ChangelogError::Generic(
                "reduce: no retention columns".to_string(),
            ));
        }

        let entry_keys: Vec<Vec<u8>> = entry
            .message
            .entries
            .iter()
            .map(|kv| kv.key.clone())
            .collect();
        let retention_table = table_from_column_keys(&entry_keys, "reduce")?;
        if retention_table != crate::RETENTION_TABLE {
            return Err(ChangelogError::Generic(format!(
                "reduce: retention columns target table \
                 '{retention_table}', expected '{}'",
                crate::RETENTION_TABLE
            )));
        }

        validate_user_access(entry, OpType::Reduce, "reduce", reader)?;

        let expected_retention_cols =
            read_schema_columns(crate::RETENTION_TABLE, "reduce", reader, ctx)?;
        let actual_retention_cols = column_names_from_keys(&entry_keys);
        if actual_retention_cols != expected_retention_cols {
            let missing: Vec<_> = expected_retention_cols
                .difference(&actual_retention_cols)
                .collect();
            return Err(ChangelogError::Generic(format!(
                "reduce: _retention operations missing columns {missing:?}"
            )));
        }
        let retention_col_count = expected_retention_cols.len();
        if retention_col_count == 0 {
            return Err(ChangelogError::Generic(
                "reduce: _retention has no schema columns".to_string(),
            ));
        }
        if !entry
            .message
            .entries
            .len()
            .is_multiple_of(retention_col_count)
        {
            return Err(ChangelogError::Generic(format!(
                "reduce: entry count {} is not a multiple of \
                 _retention col_count={retention_col_count}",
                entry.message.entries.len()
            )));
        }

        let counter = read_next_id(crate::RETENTION_TABLE, "reduce", reader)?;
        let retention_column_keys = derive_column_keys_for_chain(
            &entry.message.entries,
            counter,
            retention_col_count,
            "reduce",
        )?;

        let mut batch_ops: Vec<BatchOp> = retention_column_keys
            .iter()
            .zip(entry.message.entries.iter())
            .map(|(col_key, kv)| kv.to_batch_op(col_key))
            .collect();

        append_multi_row_insert_index_puts(
            &mut batch_ops,
            crate::RETENTION_TABLE,
            &retention_column_keys,
            &entry.message.entries,
            "reduce",
            reader,
            ctx,
        )?;

        let num_rows = (entry.message.entries.len() / retention_col_count) as i64;
        bump_next_id_after_chain(
            &mut batch_ops,
            crate::RETENTION_TABLE,
            counter,
            num_rows,
            "reduce",
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
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
    use encrypted_spaces_storage_encoding::{
        encode_column_names,
        keys::{column_key, schema_columns_key},
    };
    use std::collections::BTreeSet;

    fn user_status_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "status")
    }

    fn make_reduce_entry(uid: u32, retention_keys: &[Vec<u8>]) -> ChangelogEntry {
        let entries: Vec<KvData> = retention_keys
            .iter()
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
                op_type: OpType::Reduce,
                tree_path: vec![],
                entries,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn test_provisional_user_rejected_for_reduce() {
        let uid = 1u32;
        let retention_keys = vec![
            column_key("_retention", 0, "key"),
            column_key("_retention", 0, "value"),
        ];
        let entry = make_reduce_entry(uid, &retention_keys);

        let retention_cols: BTreeSet<String> =
            ["key", "value"].into_iter().map(str::to_string).collect();
        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, value_to_bytes(&serde_json::json!(0)).unwrap())],
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

        let err = ReduceOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("provisional user"), "unexpected error: {msg}");
    }

    #[test]
    fn test_wrong_table_rejected_for_reduce() {
        let uid = 1u32;
        let wrong_keys = vec![
            column_key("_users", 0, "key"),
            column_key("_users", 0, "value"),
        ];
        let entry = make_reduce_entry(uid, &wrong_keys);

        let reads = vec![];
        let mut reader = VerifierReader::new(&reads);

        let err = ReduceOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("retention columns target table"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_empty_retention_rejected_for_reduce() {
        let uid = 1u32;
        let entry = make_reduce_entry(uid, &[]);

        let reads = vec![];
        let mut reader = VerifierReader::new(&reads);

        let err = ReduceOp::extract_and_validate(
            &entry,
            &mut reader,
            &super::super::OpContext::default(),
        );
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("no retention columns"),
            "unexpected error: {msg}"
        );
    }
}
