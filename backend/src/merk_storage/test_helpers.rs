//! Test/bench-only helpers that fabricate signed-looking artifacts so
//! direct callers of `apply_change_with_pruned_tree` don't have to
//! drive the full client signing pipeline.
//!
//! Production callers receive the `ChangelogEntry` from the client over
//! the wire — they must never use anything in this module.

use encrypted_spaces_changelog_core::changelog::Change;
use encrypted_spaces_storage_encoding::keys::column_key_placeholder;

use super::{build_column_kv_vecs, get_row_data_from_query};
use crate::{
    error::{Result, SdkError},
    query::Query,
    schema::Schema,
};

/// Build a synthetic `Change` for an Insert query.
///
/// Used by tests and benches that exercise `apply_change_with_pruned_tree`
/// directly (no signing key, no on-the-wire change).  Real callers
/// receive the change from the client.
pub fn insert_change_for_query(query: &Query, uid: u32) -> Result<Change> {
    use encrypted_spaces_changelog_core::changelog::{OpType, ROOT_TREE_PATH};
    let (_, column_data) = get_row_data_from_query(query)?;
    let (keys, values) = build_column_kv_vecs(&column_data, |col| {
        column_key_placeholder(&query.table, col)
    });
    let mut kv: Vec<(Vec<u8>, Vec<u8>)> = keys.into_iter().zip(values).collect();
    kv.sort_by(|(left, _), (right, _)| left.cmp(right));
    let keys: Vec<Vec<u8>> = kv.iter().map(|(key, _)| key.clone()).collect();
    let values: Vec<Vec<u8>> = kv.into_iter().map(|(_, value)| value).collect();
    let key_refs: Vec<&[u8]> = keys.iter().map(|key| key.as_slice()).collect();
    let value_refs: Vec<&[u8]> = values.iter().map(|value| value.as_slice()).collect();
    Change::new(
        OpType::Insert,
        uid,
        ROOT_TREE_PATH,
        &key_refs,
        &value_refs,
        0,
        0,
        [0u8; 32],
    )
    .map_err(|e| SdkError::DatabaseError(format!("Failed to build Change: {e}")))
}

/// Build a synthetic `Change` for an Update query.
///
/// Used by tests and benches that exercise `apply_change_with_pruned_tree`
/// directly. The query must carry a `Predicate` with a single integer
/// row_id (the row to update); column keys are built with that row_id
/// baked in so they match what the server's E&V pipeline expects.
pub fn update_change_for_query(query: &Query, uid: u32) -> Result<Change> {
    use crate::query::{ComparisonOperator, QueryParam};
    use encrypted_spaces_changelog_core::changelog::{OpType, ROOT_TREE_PATH};
    use encrypted_spaces_storage_encoding::keys::column_key;

    let row_id = match query.predicate.as_ref() {
        Some(p) if matches!(p.operator, ComparisonOperator::Equal) => match p.values.first() {
            Some(QueryParam::Integer(id)) => *id,
            _ => {
                return Err(SdkError::DatabaseError(
                    "update_change_for_query requires Predicate value Integer(row_id)".to_string(),
                ))
            }
        },
        _ => {
            return Err(SdkError::DatabaseError(
                "update_change_for_query requires an Equal Predicate on row_id".to_string(),
            ))
        }
    };

    let (_, column_data) = get_row_data_from_query(query)?;
    let (keys, values) =
        build_column_kv_vecs(&column_data, |col| column_key(&query.table, row_id, col));
    let mut kv: Vec<(Vec<u8>, Vec<u8>)> = keys.into_iter().zip(values).collect();
    kv.sort_by(|(left, _), (right, _)| left.cmp(right));
    let keys: Vec<Vec<u8>> = kv.iter().map(|(key, _)| key.clone()).collect();
    let values: Vec<Vec<u8>> = kv.into_iter().map(|(_, value)| value).collect();
    let key_refs: Vec<&[u8]> = keys.iter().map(|key| key.as_slice()).collect();
    let value_refs: Vec<&[u8]> = values.iter().map(|value| value.as_slice()).collect();
    Change::new(
        OpType::Update,
        uid,
        ROOT_TREE_PATH,
        &key_refs,
        &value_refs,
        0,
        0,
        [0u8; 32],
    )
    .map_err(|e| SdkError::DatabaseError(format!("Failed to build Change: {e}")))
}

/// Build a synthetic `Change` for a Delete query.
///
/// Used by tests and benches that exercise `apply_change_with_pruned_tree`
/// directly. The query must carry a `Predicate` with a single integer
/// row_id; the entry enumerates every non-id column from `schema` for
/// that row, which is what `DeleteOp::extract_and_validate` requires
/// (deletes must cover all schema columns).
pub fn delete_change_for_query(query: &Query, uid: u32, schema: &Schema) -> Result<Change> {
    use crate::query::{ComparisonOperator, QueryParam};
    use encrypted_spaces_changelog_core::changelog::{OpType, ROOT_TREE_PATH};
    use encrypted_spaces_storage_encoding::keys::column_key;

    let row_id = match query.predicate.as_ref() {
        Some(p) if matches!(p.operator, ComparisonOperator::Equal) => match p.values.first() {
            Some(QueryParam::Integer(id)) => *id,
            _ => {
                return Err(SdkError::DatabaseError(
                    "delete_change_for_query requires Predicate value Integer(row_id)".to_string(),
                ))
            }
        },
        _ => {
            return Err(SdkError::DatabaseError(
                "delete_change_for_query requires an Equal Predicate on row_id".to_string(),
            ))
        }
    };

    let mut keys: Vec<Vec<u8>> = schema
        .columns
        .iter()
        .filter(|c| c.name != "id")
        .map(|c| column_key(&query.table, row_id, &c.name))
        .collect();
    keys.sort();
    let values: Vec<Vec<u8>> = vec![vec![]; keys.len()];

    let key_refs: Vec<&[u8]> = keys.iter().map(|key| key.as_slice()).collect();
    let value_refs: Vec<&[u8]> = values.iter().map(|value| value.as_slice()).collect();
    Change::new(
        OpType::Delete,
        uid,
        ROOT_TREE_PATH,
        &key_refs,
        &value_refs,
        0,
        0,
        [0u8; 32],
    )
    .map_err(|e| SdkError::DatabaseError(format!("Failed to build Change: {e}")))
}
