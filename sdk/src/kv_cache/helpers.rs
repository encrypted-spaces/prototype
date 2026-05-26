//! Pure helpers around [`crate::kv_cache::KvCache`].

use std::collections::{BTreeMap, BTreeSet};

use encrypted_spaces_backend::merk_storage::{parse_key, ParsedKey};
use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_changelog_core::{changelog::Change, BatchOp};

use super::CacheUpdate;

/// Convert a verified write batch into a [`CacheUpdate`] ready for
/// [`super::KvCache::advance_anchor`].
///
/// `PutHash` references the sidecar in `change.hashed_values`; entries the
/// sidecar can't resolve are skipped with a warning (the cache will refetch
/// on the next read since coverage wasn't extended for those keys).
pub fn cache_update_from_writes(change: &Change, writes: &[BatchOp]) -> CacheUpdate {
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
    update
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
