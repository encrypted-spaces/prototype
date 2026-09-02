use super::{
    validate_max_entries, validate_sorted_entries, validate_store_declared, validate_user_access,
    OpContext, OpReader, OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::WriteOp;
use encrypted_spaces_storage_encoding::keys::{parse_key, ParsedKey};

/// Write (insert or overwrite) entries into a declared key-value store.
pub struct StorePutOp;

/// Delete entries from a declared key-value store.
pub struct StoreDeleteOp;

/// Validate a store write's well-formedness, the writer's membership, and
/// that the target store is declared.  Returns the single target store.
///
/// Stores are **open**: this performs no per-key access control.  What it
/// does authenticate:
///   - entry count and sort order (`validate_max_entries` /
///     `validate_sorted_entries`);
///   - every entry key is a `StoreEntry` for the *same* store (so a store
///     write can never touch schema/row/index keys, and can't span stores);
///   - the writer is a real, non-provisional member (`validate_user_access`);
///   - the target store is declared (`store_schema_key` is present) — a
///     client cannot fabricate a namespace.
///
/// Tree reads are issued in a fixed, data-independent order so the prover
/// and verifier request identical reads: first the writer's `_users`
/// status (inside `validate_user_access`), then the store declaration key.
/// The declaration read is cached on the `OpContext`, so repeated writes to
/// the same store skip it (see [`validate_store_declared`]); the prover and
/// verifier share that cache, keeping their read sequences identical.
fn validate_store_write(
    entry: &ChangelogEntry,
    op_type: OpType,
    op_name: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<String, ChangelogError> {
    validate_max_entries(entry, op_name)?;
    validate_sorted_entries(entry, op_name)?;

    if entry.message.entries.is_empty() {
        return Err(ChangelogError::Generic(format!("{op_name}: no entries")));
    }

    // Resolve the single target store from the entry keys.  This reads no
    // tree state, so it does not affect read ordering.
    let mut store: Option<String> = None;
    for kv in &entry.message.entries {
        let parsed = parse_key(&kv.key)
            .map_err(|e| ChangelogError::Generic(format!("{op_name}: invalid key: {e}")))?;
        let ParsedKey::StoreEntry { store: s, .. } = parsed else {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: entry key is not a store entry key"
            )));
        };
        match &store {
            None => store = Some(s),
            Some(existing) if *existing != s => {
                return Err(ChangelogError::Generic(format!(
                    "{op_name}: all entries must target the same store \
                     (got '{existing}' and '{s}')"
                )));
            }
            Some(_) => {}
        }
    }
    let store = store.expect("entries are non-empty");

    // Authenticate membership (rejects provisional/absent users).  Issues
    // the user-status read first.
    validate_user_access(entry, op_type, op_name, reader)?;

    // Authenticate that the target store is declared.  One deterministic
    // read on a cache miss; absence => reject.
    validate_store_declared(&store, op_name, reader, ctx)?;

    Ok(store)
}

impl OpVerifier for StorePutOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_store_write(entry, OpType::StorePut, "store_put", reader, ctx)?;

        let ops: Vec<WriteOp> = entry
            .message
            .entries
            .iter()
            .map(|kv| WriteOp::Put {
                key: kv.key.clone(),
                value: kv.value.clone(),
            })
            .collect();

        Ok(OpVerifyResult { write_steps: ops })
    }
}

impl OpVerifier for StoreDeleteOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_store_write(entry, OpType::StoreDelete, "store_delete", reader, ctx)?;

        let ops: Vec<WriteOp> = entry
            .message
            .entries
            .iter()
            .map(|kv| WriteOp::Delete {
                key: kv.key.clone(),
            })
            .collect();

        Ok(OpVerifyResult { write_steps: ops })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage};
    use crate::ops::VerifierReader;
    use crate::{ProvenRead, ReadOp};
    use encrypted_spaces_storage_encoding::keys::{
        acl_rule_key, column_key, store_entry_key, store_schema_key,
    };
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;

    const USERS_TABLE: &str = "_users";

    fn user_status_key(uid: u32) -> Vec<u8> {
        column_key(USERS_TABLE, uid as i64, "status")
    }

    fn stored_i64(value: i64) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    fn ctx() -> OpContext {
        OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        }
    }

    /// Proven read for a present user (status = full member).
    fn user_read(uid: u32) -> ProvenRead {
        let key = user_status_key(uid);
        ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, stored_i64(1))],
        }
    }

    /// Proven read for a declared store.
    fn store_declared_read(store: &str) -> ProvenRead {
        let key = store_schema_key(store);
        ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, vec![1])],
        }
    }

    fn put_entry(store: &str, entries: Vec<(&[u8], &[u8])>) -> ChangelogEntry {
        entry_with(OpType::StorePut, store, entries)
    }

    fn entry_with(op_type: OpType, store: &str, entries: Vec<(&[u8], &[u8])>) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid: 7,
            parent_change: 0,
            message: LogMessage {
                op_type,
                tree_path: vec![],
                entries: entries
                    .into_iter()
                    .map(|(k, v)| KvData {
                        key: store_entry_key(store, k),
                        value: v.to_vec(),
                    })
                    .collect(),
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn store_put_emits_put_ops() {
        let entry = put_entry("prefs", vec![(b"a", b"1"), (b"b", b"2")]);
        let reads = vec![user_read(7), store_declared_read("prefs")];
        let mut reader = VerifierReader::new(&reads);
        let result = StorePutOp::extract_and_validate(&entry, &mut reader, &ctx()).unwrap();
        reader.assert_all_consumed().unwrap();

        let ops = &result.write_steps;
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0], WriteOp::Put { key, value }
            if *key == store_entry_key("prefs", b"a") && value == b"1"));
        assert!(matches!(&ops[1], WriteOp::Put { key, value }
            if *key == store_entry_key("prefs", b"b") && value == b"2"));
    }

    #[test]
    fn store_delete_emits_delete_ops() {
        let entry = entry_with(OpType::StoreDelete, "prefs", vec![(b"a", b"")]);
        let reads = vec![user_read(7), store_declared_read("prefs")];
        let mut reader = VerifierReader::new(&reads);
        let result = StoreDeleteOp::extract_and_validate(&entry, &mut reader, &ctx()).unwrap();

        let ops = &result.write_steps;
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], WriteOp::Delete { key }
            if *key == store_entry_key("prefs", b"a")));
    }

    #[test]
    fn store_put_rejects_undeclared_store() {
        let entry = put_entry("prefs", vec![(b"a", b"1")]);
        // store_schema_key read returns empty => undeclared.
        let reads = vec![
            user_read(7),
            ProvenRead {
                op: ReadOp::Key(store_schema_key("prefs")),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = StorePutOp::extract_and_validate(&entry, &mut reader, &ctx()).unwrap_err();
        assert!(err.to_string().contains("not declared"), "got: {err}");
    }

    #[test]
    fn store_schema_read_is_cached_across_writes() {
        // Two writes to the same store share one OpContext, so the
        // `store_schema_key` read is issued once (first write) and reused from
        // the cache (second write). Only one `store_declared_read` is provided;
        // the second entry passing proves it never re-read the declaration.
        let ctx = ctx();
        let e1 = put_entry("prefs", vec![(b"a", b"1")]);
        let e2 = put_entry("prefs", vec![(b"b", b"2")]);
        let reads = vec![
            user_read(7),
            store_declared_read("prefs"),
            user_read(7), // second write re-checks membership but not the store decl
        ];
        let mut reader = VerifierReader::new(&reads);
        StorePutOp::extract_and_validate(&e1, &mut reader, &ctx).unwrap();
        StorePutOp::extract_and_validate(&e2, &mut reader, &ctx).unwrap();
        reader.assert_all_consumed().unwrap();
    }

    #[test]
    fn store_put_rejects_absent_user() {
        let entry = put_entry("prefs", vec![(b"a", b"1")]);
        let reads = vec![ProvenRead {
            op: ReadOp::Key(user_status_key(7)),
            results: vec![],
        }];
        let mut reader = VerifierReader::new(&reads);
        let err = StorePutOp::extract_and_validate(&entry, &mut reader, &ctx()).unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }

    #[test]
    fn store_put_rejects_unsorted_entries() {
        // "b" then "a" is out of order.
        let entry = put_entry("prefs", vec![(b"b", b"2"), (b"a", b"1")]);
        let reads = vec![user_read(7)];
        let mut reader = VerifierReader::new(&reads);
        let err = StorePutOp::extract_and_validate(&entry, &mut reader, &ctx()).unwrap_err();
        assert!(err.to_string().contains("sorted"), "got: {err}");
    }

    #[test]
    fn store_put_rejects_entries_spanning_two_stores() {
        // Hand-build an entry whose two keys target different stores. The
        // keys must still be globally sorted for the sort check to pass, so
        // the "same store" check is what rejects it.
        let k1 = store_entry_key("prefs", b"a");
        let k2 = store_entry_key("other", b"a");
        let (lo, hi) = if k1 < k2 { (k1, k2) } else { (k2, k1) };
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 7,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::StorePut,
                tree_path: vec![],
                entries: vec![
                    KvData {
                        key: lo,
                        value: b"1".to_vec(),
                    },
                    KvData {
                        key: hi,
                        value: b"2".to_vec(),
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![user_read(7)];
        let mut reader = VerifierReader::new(&reads);
        let err = StorePutOp::extract_and_validate(&entry, &mut reader, &ctx()).unwrap_err();
        assert!(err.to_string().contains("same store"), "got: {err}");
    }

    #[test]
    fn store_put_rejects_non_store_key() {
        // A column key is not a store entry key.
        let entry = ChangelogEntry {
            timestamp: 1000,
            uid: 7,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::StorePut,
                tree_path: vec![],
                entries: vec![KvData {
                    key: column_key("posts", 1, "name"),
                    value: b"x".to_vec(),
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        };
        let reads = vec![user_read(7)];
        let mut reader = VerifierReader::new(&reads);
        let err = StorePutOp::extract_and_validate(&entry, &mut reader, &ctx()).unwrap_err();
        assert!(
            err.to_string().contains("not a store entry key"),
            "got: {err}"
        );
    }

    /// Stores are open: no ACL read is issued even if a like-named ACL rule
    /// exists.  The verifier requests exactly `[user_status, store_schema]`,
    /// so an `acl_rule_key` read left in the proven set stays unconsumed and
    /// `assert_all_consumed` fails — proving the op never asked for it.
    #[test]
    fn store_put_reads_no_acl_rule() {
        let entry = put_entry("prefs", vec![(b"a", b"1")]);
        let reads = vec![
            user_read(7),
            store_declared_read("prefs"),
            ProvenRead {
                op: ReadOp::Key(acl_rule_key("prefs", "write")),
                results: vec![(acl_rule_key("prefs", "write"), vec![0u8])],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        StorePutOp::extract_and_validate(&entry, &mut reader, &ctx()).unwrap();
        // The ACL read was never requested, so it remains unconsumed.
        assert!(reader.assert_all_consumed().is_err());
    }
}
