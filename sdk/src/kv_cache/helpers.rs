//! Pure helpers around [`crate::kv_cache::KvCache`].

use std::collections::{BTreeMap, BTreeSet, HashMap};

use encrypted_spaces_backend::merk_storage::{parse_key, ParsedKey};
use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_changelog_core::{changelog::Change, prefix_successor, BatchOp};
use encrypted_spaces_storage_encoding::keys;

use super::CacheUpdate;

/// Convert a verified write batch into a [`CacheUpdate`] ready for
/// [`super::KvCache::advance_anchor`].
///
/// `PutHash` references the sidecar in `change.hashed_values`; entries the
/// sidecar can't resolve are skipped with a warning (the cache will refetch
/// on the next read since coverage wasn't extended for those keys).
///
/// When `writes` cover *every* non-id column of a row's schema (i.e. a
/// full insert or a complete replacement update), the row's byte range
/// [`row_key, prefix_successor)` is added to `coverage_extensions`. After
/// the splice, a subsequent id-read of that row hits the cache without
/// needing a server round-trip — matches Trevor's `full_row_coverage`.
/// Same shape for deletes: a delete that names every non-id column of a
/// row extends coverage so the absence is authenticated.
pub fn cache_update_from_writes(
    change: &Change,
    writes: &[BatchOp],
    schemas: &HashMap<String, Schema>,
) -> CacheUpdate {
    let mut update = CacheUpdate::new();
    // Track which (table, row_id) pairs had at least one PutHash whose
    // sidecar value couldn't be resolved. We splice everything we *could*
    // resolve, but those rows must NOT get a coverage extension — the
    // row's cache state is incomplete, so claiming full coverage would
    // make a subsequent id-read return the row with missing columns.
    let mut tainted_rows: BTreeSet<(String, i64)> = BTreeSet::new();
    for op in writes {
        match op {
            BatchOp::Put { key, value } => update.put(key.clone(), value.clone()),
            BatchOp::PutHash { key, value_hash } => {
                if let Some(bytes) = change.hashed_values.get(value_hash) {
                    update.put(key.clone(), bytes.clone());
                } else {
                    log::warn!(
                        "cache_update_from_writes: PutHash for {} missing from sidecar; \
                         key not spliced and the row will not be coverage-extended",
                        hex::encode(key)
                    );
                    if let Ok(ParsedKey::Column { table, row_id, .. }) = parse_key(key) {
                        tainted_rows.insert((table, row_id));
                    }
                }
            }
            BatchOp::Delete { key } => update.delete(key.clone()),
        }
    }
    for range in full_row_coverage(writes, schemas, /* deletes = */ false, &tainted_rows) {
        update.extend_coverage(range.0, range.1);
    }
    for range in full_row_coverage(writes, schemas, /* deletes = */ true, &tainted_rows) {
        update.extend_coverage(range.0, range.1);
    }
    update
}

/// Row byte ranges produced by writes that cover every non-id column of a
/// row's schema. `deletes = true` runs the same test against Delete ops so
/// a full-row delete extends coverage (the row is now an authenticated
/// absence). Rows in `tainted` (one of their PutHash values was not
/// resolvable from the sidecar) are skipped so we never claim coverage
/// over a row whose cache state is incomplete. Ports Trevor's
/// `full_row_coverage` helper with the taint guard.
fn full_row_coverage(
    writes: &[BatchOp],
    schemas: &HashMap<String, Schema>,
    deletes: bool,
    tainted: &BTreeSet<(String, i64)>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let id_field = encrypted_spaces_backend::merk_storage::ID_FIELD;
    let mut per_row: BTreeMap<(String, i64), BTreeSet<String>> = BTreeMap::new();
    for op in writes {
        let key = match (op, deletes) {
            (BatchOp::Put { key, .. }, false) | (BatchOp::PutHash { key, .. }, false) => key,
            (BatchOp::Delete { key }, true) => key,
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

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType};
    use encrypted_spaces_changelog_core::changelog::{
        ChangelogEntry, HashedValues, LogMessage, OpType,
    };

    fn schema(name: &str, cols: &[&str]) -> Schema {
        Schema {
            name: name.to_string(),
            columns: cols
                .iter()
                .map(|c| ColumnDefinition {
                    name: (*c).to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                })
                .collect(),
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
    fn tainted_row_is_excluded_from_coverage_extension() {
        // A row with both a Put AND a PutHash. The PutHash's sidecar entry
        // is missing, so the row's `large` column is never spliced. The
        // coverage extension MUST be suppressed for that row — otherwise an
        // id-read would hit and return the row missing `large`.
        let mut schemas = HashMap::new();
        schemas.insert("t".to_string(), schema("t", &["id", "small", "large"]));

        let writes = vec![
            BatchOp::Put {
                key: keys::column_key("t", 7, "small"),
                value: vec![1, 2, 3],
            },
            BatchOp::PutHash {
                key: keys::column_key("t", 7, "large"),
                value_hash: [0xAB; 32],
            },
        ];
        // Empty sidecar → PutHash unresolved.
        let change = change_with_sidecar(HashedValues::new());

        let update = cache_update_from_writes(&change, &writes, &schemas);

        assert_eq!(update.writes.len(), 1, "only the Put should be spliced");
        assert!(
            update.coverage_extensions.is_empty(),
            "tainted row must not receive a coverage extension"
        );
    }

    #[test]
    fn resolved_puthash_still_yields_coverage_extension() {
        // Same row shape but the sidecar has the value. Both writes splice,
        // both columns are present, so the row IS full-covered.
        let mut schemas = HashMap::new();
        schemas.insert("t".to_string(), schema("t", &["id", "small", "large"]));

        let mut sidecar = HashedValues::new();
        sidecar.insert([0xAB; 32], vec![9, 9, 9]);

        let writes = vec![
            BatchOp::Put {
                key: keys::column_key("t", 7, "small"),
                value: vec![1, 2, 3],
            },
            BatchOp::PutHash {
                key: keys::column_key("t", 7, "large"),
                value_hash: [0xAB; 32],
            },
        ];
        let change = change_with_sidecar(sidecar);

        let update = cache_update_from_writes(&change, &writes, &schemas);

        assert_eq!(update.writes.len(), 2);
        assert_eq!(update.coverage_extensions.len(), 1);
    }
}

/// Last new-row id touching `table` in `writes`. A row counts as new when its
/// puts cover every non-id column declared in `schema`.
pub fn new_row_id_for_table(writes: &[BatchOp], table: &str, schema: &Schema) -> Option<i64> {
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
            BatchOp::Put { key, .. } | BatchOp::PutHash { key, .. } => key,
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
