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
    for op in writes {
        match op {
            BatchOp::Put { key, value } => update.put(key.clone(), value.clone()),
            BatchOp::PutHash { key, value_hash } => {
                if let Some(bytes) = change.hashed_values.get(value_hash) {
                    update.put(key.clone(), bytes.clone());
                } else {
                    log::warn!(
                        "cache_update_from_writes: PutHash for {} missing from sidecar; \
                         key not spliced",
                        hex::encode(key)
                    );
                }
            }
            BatchOp::Delete { key } => update.delete(key.clone()),
        }
    }
    for range in full_row_coverage(writes, schemas, /* deletes = */ false) {
        update.extend_coverage(range.0, range.1);
    }
    for range in full_row_coverage(writes, schemas, /* deletes = */ true) {
        update.extend_coverage(range.0, range.1);
    }
    update
}

/// Row byte ranges produced by writes that cover every non-id column of a
/// row's schema. `deletes = true` runs the same test against Delete ops so
/// a full-row delete extends coverage (the row is now an authenticated
/// absence). Ports Trevor's `full_row_coverage` helper.
fn full_row_coverage(
    writes: &[BatchOp],
    schemas: &HashMap<String, Schema>,
    deletes: bool,
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
