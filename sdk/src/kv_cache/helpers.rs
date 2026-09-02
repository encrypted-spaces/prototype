//! Pure helpers around [`crate::kv_cache::KvCache`].

use std::collections::{BTreeMap, BTreeSet, HashMap};

use encrypted_spaces_backend::merk_storage::{parse_key, ParsedKey};
use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_changelog_core::{changelog::Change, prefix_successor, WriteOp};
use encrypted_spaces_storage_encoding::keys;

use super::CacheUpdate;

/// Convert a verified write batch into a [`CacheUpdate`] ready for
/// [`super::KvCache::advance_anchor`].
///
/// A hash-backed column (`Text`/`Blob`) stores a 32-byte digest in its
/// `WriteOp::Put`; the actual bytes live in `change.hashed_values`. We
/// resolve those to the full value before splicing so the cache holds the
/// same representation a SELECT proof yields and the decrypt path reads it
/// back identically. A hash-backed write whose digest is absent from the
/// sidecar is skipped, and its row is marked tainted so it does not get a
/// coverage extension (an id-read must not return a row with a hole).
///
/// When `writes` cover *every* non-id column of a row's schema (i.e. a
/// full insert or a complete replacement update) and no column was
/// tainted, the row's byte range `[row_key, prefix_successor)` is added to
/// `coverage_extensions` so a later id-read hits the cache. Same shape for
/// deletes: a delete naming every non-id column authenticates the absence.
///
/// Returns `None` when `writes` contain any non-point operation
/// (`DeleteRange`/`DeletePrefix`/`MovePrefix`): the cache cannot splice
/// those incrementally, and silently skipping them would retain entries the
/// operation invalidated. Callers must treat `None` as "cannot splice" and
/// [`reanchor`](super::KvCache::reanchor) (clear) instead. Today's p2 ops
/// emit only point writes, so this is a fail-safe for future ops; full
/// range/move splicing can replace it if the performance ever matters.
pub fn cache_update_from_writes(
    change: &Change,
    writes: &[WriteOp],
    schemas: &HashMap<String, Schema>,
) -> Option<CacheUpdate> {
    let mut update = CacheUpdate::new();
    let mut tainted_rows: BTreeSet<(String, i64)> = BTreeSet::new();
    for op in writes {
        match op {
            WriteOp::Put { key, value } => match resolve_put_value(key, value, schemas, change) {
                Some(bytes) => update.put(key.clone(), bytes),
                None => {
                    if let Ok(ParsedKey::Column { table, row_id, .. }) = parse_key(key) {
                        tainted_rows.insert((table, row_id));
                    }
                }
            },
            WriteOp::Delete { key } => update.delete(key.clone()),
            WriteOp::DeleteRange { .. }
            | WriteOp::DeletePrefix { .. }
            | WriteOp::MovePrefix { .. } => return None,
        }
    }
    for range in full_row_coverage(writes, schemas, /* deletes = */ false, &tainted_rows) {
        update.extend_coverage(range.0, range.1);
    }
    for range in full_row_coverage(writes, schemas, /* deletes = */ true, &tainted_rows) {
        update.extend_coverage(range.0, range.1);
    }
    Some(update)
}

/// Resolve a `Put`'s stored bytes to the value the cache should hold.
///
/// For a hash-backed column the stored bytes are a 32-byte digest that
/// indexes `change.hashed_values`; returns `Some(full_value)` when the
/// sidecar can resolve it, or `None` (skip + taint) when it can't. For
/// every other column the stored bytes are the value itself.
fn resolve_put_value(
    key: &[u8],
    value: &[u8],
    schemas: &HashMap<String, Schema>,
    change: &Change,
) -> Option<Vec<u8>> {
    if let Ok(ParsedKey::Column { table, column, .. }) = parse_key(key) {
        if let Some(col) = schemas
            .get(&table)
            .and_then(|s| s.columns.iter().find(|c| c.name == column))
        {
            if col.column_type.is_hash_backed() {
                let hash: [u8; 32] = value.try_into().ok()?;
                return match change.hashed_values.get(&hash) {
                    Some(bytes) => Some(bytes.clone()),
                    None => {
                        log::warn!(
                            "cache_update_from_writes: hash-backed {table}.{column} digest \
                             missing from sidecar; row not spliced or coverage-extended"
                        );
                        None
                    }
                };
            }
        }
    }
    Some(value.to_vec())
}

/// Row byte ranges produced by writes that cover every non-id column of a
/// row's schema. `deletes = true` runs the same test against Delete ops so
/// a full-row delete extends coverage (the row is now an authenticated
/// absence). Rows in `tainted` (a hash-backed value couldn't be resolved)
/// are skipped so we never claim coverage over an incomplete row.
fn full_row_coverage(
    writes: &[WriteOp],
    schemas: &HashMap<String, Schema>,
    deletes: bool,
    tainted: &BTreeSet<(String, i64)>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let id_field = encrypted_spaces_backend::merk_storage::ID_FIELD;
    let mut per_row: BTreeMap<(String, i64), BTreeSet<String>> = BTreeMap::new();
    for op in writes {
        let key = match (op, deletes) {
            (WriteOp::Put { key, .. }, false) => key,
            (WriteOp::Delete { key }, true) => key,
            _ => continue,
        };
        if let Ok(ParsedKey::Column {
            table,
            row_id,
            column,
        }) = parse_key(key)
        {
            per_row.entry((table, row_id)).or_default().insert(column);
        }
    }

    per_row
        .into_iter()
        .filter_map(|((table, row_id), columns)| {
            if tainted.contains(&(table.clone(), row_id)) {
                return None;
            }
            let schema = schemas.get(&table)?;
            let schema_columns: BTreeSet<String> = schema
                .columns
                .iter()
                .filter(|c| c.name != id_field)
                .map(|c| c.name.clone())
                .collect();
            if columns == schema_columns {
                let start = keys::row_key(&table, row_id);
                let end = prefix_successor(&start)?;
                Some((start, end))
            } else {
                None
            }
        })
        .collect()
}

/// Last new-row id touching `table` in `writes`. A row counts as new when its
/// puts cover every non-id column declared in `schema`.
pub fn new_row_id_for_table(writes: &[WriteOp], table: &str, schema: &Schema) -> Option<i64> {
    let schema_non_id_cols: BTreeSet<String> = schema
        .columns
        .iter()
        .filter(|c| c.name != "id")
        .map(|c| c.name.clone())
        .collect();
    if schema_non_id_cols.is_empty() {
        return None;
    }

    let mut per_row: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    for op in writes {
        let key = match op {
            WriteOp::Put { key, .. } => key,
            _ => continue,
        };
        if let Ok(ParsedKey::Column {
            table: t,
            row_id,
            column,
        }) = parse_key(key)
        {
            if t == table {
                per_row.entry(row_id).or_default().insert(column);
            }
        }
    }

    per_row
        .into_iter()
        .filter(|(_, cols)| schema_non_id_cols.iter().all(|c| cols.contains(c)))
        .map(|(row_id, _)| row_id)
        .next_back()
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType};
    use encrypted_spaces_changelog_core::changelog::{
        ChangelogEntry, HashedValues, LogMessage, OpType,
    };

    // `small` is plaintext-inline (Integer); `large` is hash-backed (Text).
    fn schema_with_hashed() -> Schema {
        Schema {
            name: "t".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "small".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "large".to_string(),
                    column_type: ColumnType::Text,
                    plaintext: true,
                    indexed: false,
                },
            ],
            auto_increment: true,
        }
    }

    fn change_with_sidecar(values: HashedValues) -> Change {
        Change {
            entry: ChangelogEntry {
                timestamp: 0u64,
                uid: 0,
                parent_change: 0,
                message: LogMessage {
                    op_type: OpType::Insert,
                    tree_path: Vec::new(),
                    entries: Vec::new(),
                },
                sig_ref: 0,
                parent_clc: [0u8; 32],
                signature: Vec::new(),
            },
            hashed_values: values,
        }
    }

    #[test]
    fn resolved_hash_backed_full_row_yields_coverage_extension() {
        // Both columns are written and the hash-backed `large` digest
        // resolves from the sidecar, so the row is full-covered and the
        // spliced value is the resolved bytes (not the 32-byte digest).
        let mut schemas = HashMap::new();
        schemas.insert("t".to_string(), schema_with_hashed());

        let mut sidecar = HashedValues::new();
        sidecar.insert([0xAB; 32], vec![9, 9, 9]);
        let change = change_with_sidecar(sidecar);

        let writes = vec![
            WriteOp::Put {
                key: keys::column_key("t", 7, "small"),
                value: vec![1, 2, 3],
            },
            WriteOp::Put {
                key: keys::column_key("t", 7, "large"),
                value: [0xAB; 32].to_vec(),
            },
        ];

        let update = cache_update_from_writes(&change, &writes, &schemas)
            .expect("point-only writes must be spliceable");

        assert_eq!(update.writes.len(), 2);
        assert_eq!(update.coverage_extensions.len(), 1);
    }

    #[test]
    fn unresolvable_hash_backed_taints_row_and_skips_coverage() {
        // The hash-backed `large` digest is missing from the sidecar, so it
        // is not spliced and the row must not be coverage-extended (an
        // id-read would otherwise return the row missing `large`).
        let mut schemas = HashMap::new();
        schemas.insert("t".to_string(), schema_with_hashed());

        let change = change_with_sidecar(HashedValues::new());

        let writes = vec![
            WriteOp::Put {
                key: keys::column_key("t", 7, "small"),
                value: vec![1, 2, 3],
            },
            WriteOp::Put {
                key: keys::column_key("t", 7, "large"),
                value: [0xAB; 32].to_vec(),
            },
        ];

        let update = cache_update_from_writes(&change, &writes, &schemas)
            .expect("point-only writes must be spliceable");

        assert_eq!(update.writes.len(), 1, "only the resolvable Put is spliced");
        assert!(
            update.coverage_extensions.is_empty(),
            "tainted row must not receive a coverage extension"
        );
    }

    /// Any non-point write op makes the batch unspliceable: the helper must
    /// return `None` so callers reanchor (clear) instead of silently
    /// retaining entries the operation may have invalidated.
    #[test]
    fn non_point_write_ops_force_reanchor() {
        let schemas = HashMap::new();
        let change = change_with_sidecar(HashedValues::new());
        let point = WriteOp::Put {
            key: keys::column_key("t", 1, "c"),
            value: b"v".to_vec(),
        };
        for non_point in [
            WriteOp::DeleteRange {
                start: b"a".to_vec(),
                end: b"z".to_vec(),
            },
            WriteOp::DeletePrefix {
                prefix: b"a".to_vec(),
            },
            WriteOp::MovePrefix {
                from: b"a".to_vec(),
                to: b"b".to_vec(),
            },
        ] {
            let writes = vec![point.clone(), non_point.clone()];
            assert!(
                cache_update_from_writes(&change, &writes, &schemas).is_none(),
                "batch containing {non_point:?} must be unspliceable"
            );
        }
    }
}
