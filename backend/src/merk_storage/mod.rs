//! Merk-based storage using a single global Merk tree.
//!
//! This storage backend uses the standalone `merk` crate directly with a single
//! flat Merk tree, providing efficient authenticated key-value storage.
//!
//! Key features:
//! - Single global Merk tree with prefixed keys
//! - Simpler proof generation (direct Merk proofs)
//! - In-memory storage

pub mod keys;
#[cfg(feature = "merk")]
pub mod pretty_print;
pub mod proofs;
#[cfg(feature = "merk")]
pub mod test_helpers;
pub mod tuple;

pub use encrypted_spaces_storage_encoding::stored_value;

use crate::{
    error::{Result, SdkError},
    query::{ComparisonOperator, Order, Query, QueryOperation, QueryParam},
    schema::Schema,
};
use base64::{engine::general_purpose::STANDARD, Engine};
#[cfg(feature = "merk")]
use encrypted_spaces_acl_types::Action;
#[cfg(any(feature = "merk", feature = "merk_verify"))]
use encrypted_spaces_changelog_core::changelog::HashedValues;
#[cfg(any(feature = "merk", feature = "merk_verify"))]
use encrypted_spaces_storage_encoding::HASH_LEN;
#[cfg(feature = "merk")]
use encrypted_spaces_storage_encoding::{
    action_storage_key, classify_insert_id, encode_action_value, encode_column_names,
    schema_indexes_key, InsertId,
};
pub use keys::{
    acl_only_via_actions_key, acl_rule_key, bytes_to_row_id, column_key, column_key_placeholder,
    parse_key, row_id_to_bytes, row_key, row_prefix, ParsedKey,
};
#[cfg(feature = "merk")]
pub use merk::Op;
use serde_json::Value;
use std::{cmp::Ordering, collections::HashMap};

#[cfg(feature = "merk")]
use {
    crate::{
        access_control::{load_access_rule, AuthContext},
        query::Predicate,
        storage::Storage,
    },
    merk::{InMemoryMerk, Node},
    serde::Deserialize,
    std::sync::Arc,
};

#[cfg(feature = "merk")]
type Operation = (Vec<u8>, Op);

/// Row data from a query: (JSON fields map, per-column serialized data).
pub type RowData = (
    serde_json::Map<String, serde_json::Value>,
    Vec<(String, Vec<u8>)>,
);

/// Primary key field for all tables
pub const ID_FIELD: &str = "id";

/// Merk-based storage using a single global tree.
///
/// The current backend serializes requests per space, so this uses Merk's
/// in-memory tree directly and applies each sorted batch to the live tree.
#[derive(Clone)]
#[cfg(feature = "merk")]
pub struct MerkStorage {
    /// The Merk tree wrapped in Arc for shared ownership.
    pub merk: Arc<InMemoryMerk>,
}

#[cfg(feature = "merk")]
impl MerkStorage {
    /// Create a new in-memory MerkStorage.
    pub fn new() -> Self {
        let merk = InMemoryMerk::new();

        Self {
            merk: Arc::new(merk),
        }
    }

    /// Create an in-memory MerkStorage with internal tables (e.g. `_access_control`)
    /// already created. Convenience for tests.
    #[cfg(test)]
    pub(crate) async fn in_memory_with_internal_tables() -> Result<Self> {
        let storage = Self::new();
        storage
            .create_table(&crate::internal_schemas::access_control_schema())
            .await?;
        Ok(storage)
    }

    /// Clone the current Merk root node. Returns `None` if the tree is empty.
    pub fn snapshot(&self) -> Option<Node> {
        self.merk.snapshot()
    }

    /// Get the current root hash of the Merk tree.
    pub fn root_hash(&self) -> [u8; 32] {
        self.merk.root_hash()
    }

    /// Get a value by key.
    pub fn get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.merk.get(key))
    }

    /// Iterate over a key range using the current in-memory tree.
    fn iter_range(&self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let Some(tree) = self.merk.snapshot() else {
            return Ok(Vec::new());
        };

        if let Some(end) = end {
            if start >= end {
                return Ok(Vec::new());
            }

            Ok(tree
                .iter_from(start)
                .take_while(|(key, _)| key.as_slice() < end)
                .collect())
        } else {
            Ok(tree.iter_from(start).collect())
        }
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        match self.merk.snapshot() {
            Some(tree) => Ok(tree
                .iter_from(prefix)
                .take_while(|(key, _)| key.starts_with(prefix))
                .collect()),
            None => Ok(Vec::new()),
        }
    }

    pub fn iter_prefix_entries(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.iter_prefix(prefix)
    }

    pub fn apply_batch_ops(&self, ops: Vec<Operation>) -> Result<()> {
        self.apply_batch(ops)
    }

    /// Execute a batch of operations against the in-memory tree.
    fn apply_batch(&self, mut ops: Vec<Operation>) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }

        ops.sort_by(|a, b| a.0.cmp(&b.0));

        // Dedup: last-write-wins for duplicate keys
        let mut seen = std::collections::HashSet::new();
        let mut batch = Vec::new();
        for op in ops.into_iter().rev() {
            if seen.insert(op.0.clone()) {
                batch.push(op);
            }
        }
        batch.reverse();

        self.merk
            .apply_batch(&batch)
            .map_err(|e| SdkError::DatabaseError(format!("Failed to apply batch: {e:?}")))?;

        Ok(())
    }
    /// Get schema for a table.
    /// Validate that a column is indexed on the given table. Returns an error
    /// if the column is not found in any index.
    pub fn validate_column_indexed(&self, table_name: &str, column: &str) -> Result<()> {
        let is_indexed = self
            .get_schema(table_name)
            .map(|s| s.indexed_columns().contains(&column))
            .unwrap_or(false);
        if !is_indexed {
            return Err(SdkError::InvalidQuery(format!(
                "Predicate column '{column}' is not indexed on table '{table_name}'",
            )));
        }
        Ok(())
    }

    pub fn get_schema(&self, table_name: &str) -> Result<Schema> {
        let schema_key = keys::schema_key(table_name);

        match self.get_value(&schema_key)? {
            Some(bytes) => {
                let schema: Schema = serde_json::from_slice(&bytes)
                    .map_err(|e| {
                        eprintln!("ERROR get_schema: from_slice failed for table={table_name} value_len={} value_preview={:?}",
                            bytes.len(), String::from_utf8_lossy(&bytes[..bytes.len().min(100)]));
                        SdkError::SerializationError(e.to_string())
                    })?;
                Ok(schema)
            }
            None => Err(SdkError::NotFound),
        }
    }

    /// Get indexed columns and their declared types from schema.
    fn get_indexed_columns(
        &self,
        table_name: &str,
    ) -> Result<Vec<(String, crate::schema::ColumnType)>> {
        match self.get_schema(table_name) {
            Ok(schema) => Ok(schema
                .columns
                .iter()
                .filter(|column| column.indexed)
                .map(|column| (column.name.clone(), column.column_type.clone()))
                .collect()),
            Err(SdkError::NotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Read the authenticated id-allocation mode for a table.
    ///
    /// Returns `true` for auto-increment tables and `false` for explicit-ID
    /// tables.
    fn read_auto_increment(&self, table_name: &str) -> Result<bool> {
        let key = keys::schema_id_mode_key(table_name);
        match self.get_value(&key)? {
            Some(bytes) if bytes.as_slice() == [0u8] => Ok(true),
            Some(bytes) if bytes.as_slice() == [1u8] => Ok(false),
            Some(bytes) => Err(SdkError::DatabaseError(format!(
                "id_mode for '{table_name}' has {} bytes / value {:?}, expected a single byte 0 or 1",
                bytes.len(),
                bytes
            ))),
            None => Err(SdkError::DatabaseError(format!(
                "id_mode for '{table_name}' is missing"
            ))),
        }
    }

    /// Read the authenticated next-row-id counter from the tree.
    ///
    /// Absence is treated as `1`.  The value is a big-endian `i64` stored at
    /// `schema_next_id_key(table)`.  Binding the inserted row_id to this
    /// counter is what lets the client verify that the row_id is provably
    /// unused.
    fn read_next_id(&self, table_name: &str) -> Result<i64> {
        let key = keys::schema_next_id_key(table_name);
        match self.get_value(&key)? {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(SdkError::DatabaseError(format!(
                        "next_id for '{table_name}' has {} bytes, expected 8",
                        bytes.len()
                    )));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes);
                Ok(i64::from_be_bytes(buf))
            }
            None => Ok(1),
        }
    }

    /// Build a counter-write operation that stores `next_id` as the new
    /// authenticated next-id for `table`.
    fn next_id_put_op(table_name: &str, next_id: i64) -> Operation {
        (
            keys::schema_next_id_key(table_name),
            Op::Put(next_id.to_be_bytes().to_vec()),
        )
    }

    /// Return `id + 1` or a counter-exhaustion error.
    ///
    /// Used by every path that advances the next-id counter so every
    /// call site reports overflow with one consistent error.
    fn next_id_after(table_name: &str, id: i64) -> Result<i64> {
        id.checked_add(1).ok_or_else(|| {
            SdkError::InsertError(format!(
                "{table_name} next_id counter exhausted at row_id={id}"
            ))
        })
    }

    /// Get a single row by ID.
    fn get_row_by_id(&self, table_name: &str, row_id: i64) -> Result<Option<serde_json::Value>> {
        let prefix = keys::row_key(table_name, row_id);
        let column_entries = self.iter_prefix(&prefix)?;
        if column_entries.is_empty() {
            return Ok(None);
        }
        reassemble_row(row_id, &column_entries).map(Some)
    }

    /// Query rows from a table.
    pub fn query_rows(&self, query: &Query) -> Result<Vec<serde_json::Value>> {
        let strategy = self.determine_query_strategy(query)?;

        let main_rows = match strategy {
            QueryStrategy::ById(id) => {
                if let Some(row) = self.get_row_by_id(&query.table, id)? {
                    vec![row]
                } else {
                    vec![]
                }
            }
            QueryStrategy::ByIds(ids) => {
                let mut rows = Vec::new();
                for id in ids {
                    if let Some(row) = self.get_row_by_id(&query.table, id)? {
                        rows.push(row);
                    }
                }
                rows
            }
            QueryStrategy::ByIdRange {
                start,
                end,
                inclusive_start,
                inclusive_end,
            } => self.query_rows_by_id_range(
                &query.table,
                start,
                end,
                inclusive_start,
                inclusive_end,
            )?,
            QueryStrategy::ByIndex { ref predicate, .. } => {
                let row_keys = self.index_row_keys_for_predicate(&query.table, predicate)?;
                let mut all_entries = Vec::new();
                for row_key in &row_keys {
                    all_entries.extend(self.iter_prefix(row_key)?);
                }
                group_columns_into_rows(&all_entries)?
            }
            QueryStrategy::TableScan => self.scan_table(&query.table)?,
        };

        // Apply ORDER BY, LIMIT, OFFSET, column selection
        process_query_results(main_rows, query)
    }

    /// Query rows while decoding only the requested columns plus any predicate
    /// column needed for ordering/limit semantics.
    ///
    /// This is used by proof construction for join discovery: the server only
    /// needs the main-table FK values, and hash-backed payload columns may not
    /// be decodable without response material yet.
    pub(crate) fn query_rows_projecting_columns(
        &self,
        query: &Query,
        columns: &[String],
    ) -> Result<Vec<serde_json::Value>> {
        let strategy = self.determine_query_strategy(query)?;
        let mut required_columns: std::collections::BTreeSet<String> =
            columns.iter().cloned().collect();
        if let Some(predicate) = &query.predicate {
            if predicate.column != ID_FIELD {
                required_columns.insert(predicate.column.clone());
            }
        }

        let main_rows = match strategy {
            QueryStrategy::ById(id) => self
                .get_row_by_id_projecting_columns(&query.table, id, &required_columns)?
                .into_iter()
                .collect(),
            QueryStrategy::ByIds(ids) => {
                let mut rows = Vec::new();
                for id in ids {
                    if let Some(row) =
                        self.get_row_by_id_projecting_columns(&query.table, id, &required_columns)?
                    {
                        rows.push(row);
                    }
                }
                rows
            }
            QueryStrategy::ByIdRange {
                start,
                end,
                inclusive_start,
                inclusive_end,
            } => self.query_rows_by_id_range_projecting_columns(
                &query.table,
                start,
                end,
                inclusive_start,
                inclusive_end,
                &required_columns,
            )?,
            QueryStrategy::ByIndex { ref predicate, .. } => {
                let row_keys = self.index_row_keys_for_predicate(&query.table, predicate)?;
                let mut all_entries = Vec::new();
                for row_key in &row_keys {
                    all_entries.extend(self.iter_prefix(row_key)?);
                }
                group_columns_into_rows_projecting_columns(&all_entries, &required_columns)?
            }
            QueryStrategy::TableScan => {
                self.scan_table_projecting_columns(&query.table, &required_columns)?
            }
        };

        Ok(apply_server_view(main_rows, query))
    }

    /// Determine query strategy based on the predicate. Returns an error if
    /// the predicate targets a non-id, non-indexed column.
    fn determine_query_strategy(&self, query: &Query) -> Result<QueryStrategy> {
        let pred = match &query.predicate {
            Some(p) => p,
            None => return Ok(QueryStrategy::TableScan),
        };

        let id_err = || SdkError::InvalidQuery("id predicate requires integer value(s)".into());

        if pred.column == ID_FIELD {
            return match &pred.operator {
                ComparisonOperator::Equal => match pred.values.first() {
                    Some(QueryParam::Integer(id)) => Ok(QueryStrategy::ById(*id)),
                    _ => Err(id_err()),
                },
                ComparisonOperator::In => {
                    let ids: Vec<i64> = pred
                        .values
                        .iter()
                        .map(|v| match v {
                            QueryParam::Integer(id) => Ok(*id),
                            _ => Err(id_err()),
                        })
                        .collect::<Result<_>>()?;
                    Ok(QueryStrategy::ByIds(ids))
                }
                ComparisonOperator::GreaterThan => match pred.values.first() {
                    Some(QueryParam::Integer(id)) => Ok(QueryStrategy::ByIdRange {
                        start: Some(*id),
                        end: None,
                        inclusive_start: false,
                        inclusive_end: true,
                    }),
                    _ => Err(id_err()),
                },
                ComparisonOperator::GreaterThanOrEqual => match pred.values.first() {
                    Some(QueryParam::Integer(id)) => Ok(QueryStrategy::ByIdRange {
                        start: Some(*id),
                        end: None,
                        inclusive_start: true,
                        inclusive_end: true,
                    }),
                    _ => Err(id_err()),
                },
                ComparisonOperator::LessThan => match pred.values.first() {
                    Some(QueryParam::Integer(id)) => Ok(QueryStrategy::ByIdRange {
                        start: None,
                        end: Some(*id),
                        inclusive_start: true,
                        inclusive_end: false,
                    }),
                    _ => Err(id_err()),
                },
                ComparisonOperator::LessThanOrEqual => match pred.values.first() {
                    Some(QueryParam::Integer(id)) => Ok(QueryStrategy::ByIdRange {
                        start: None,
                        end: Some(*id),
                        inclusive_start: true,
                        inclusive_end: true,
                    }),
                    _ => Err(id_err()),
                },
                ComparisonOperator::Between => match (pred.values.first(), pred.values.get(1)) {
                    (Some(QueryParam::Integer(lo)), Some(QueryParam::Integer(hi))) => {
                        Ok(QueryStrategy::ByIdRange {
                            start: Some(*lo),
                            end: Some(*hi),
                            inclusive_start: true,
                            inclusive_end: true,
                        })
                    }
                    _ => Err(id_err()),
                },
            };
        }

        // Non-id column — must be indexed.
        self.validate_column_indexed(&query.table, &pred.column)?;
        Ok(QueryStrategy::ByIndex {
            predicate: pred.clone(),
        })
    }

    /// Scan all rows in a table using Merk's efficient prefix iteration.
    fn scan_table(&self, table_name: &str) -> Result<Vec<serde_json::Value>> {
        let prefix = keys::row_prefix(table_name);
        let key_values = self.iter_prefix(&prefix)?;
        group_columns_into_rows(&key_values)
    }

    fn scan_table_projecting_columns(
        &self,
        table_name: &str,
        columns: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<serde_json::Value>> {
        let prefix = keys::row_prefix(table_name);
        let key_values = self.iter_prefix(&prefix)?;
        group_columns_into_rows_projecting_columns(&key_values, columns)
    }

    /// Query rows by ID range using Merk's efficient range iteration.
    /// Single contiguous range read - no individual key lookups.
    fn query_rows_by_id_range(
        &self,
        table_name: &str,
        start: Option<i64>,
        end: Option<i64>,
        inclusive_start: bool,
        inclusive_end: bool,
    ) -> Result<Vec<serde_json::Value>> {
        let start_key = match start {
            Some(row_id) if inclusive_start => keys::row_key(table_name, row_id),
            Some(row_id) => proofs::prefix_successor_required(&keys::row_key(table_name, row_id))?,
            None => keys::row_prefix(table_name),
        };

        let end_key = match end {
            Some(row_id) if inclusive_end => {
                proofs::prefix_successor_required(&keys::row_key(table_name, row_id))?
            }
            Some(row_id) => keys::row_key(table_name, row_id),
            None => proofs::prefix_successor_required(&keys::row_prefix(table_name))?,
        };

        // Single efficient range read
        let key_values = self.iter_range(&start_key, Some(&end_key))?;

        group_columns_into_rows(&key_values)
    }

    fn get_row_by_id_projecting_columns(
        &self,
        table_name: &str,
        row_id: i64,
        columns: &std::collections::BTreeSet<String>,
    ) -> Result<Option<serde_json::Value>> {
        let prefix = keys::row_key(table_name, row_id);
        let column_entries = self.iter_prefix(&prefix)?;
        if column_entries.is_empty() {
            return Ok(None);
        }
        reassemble_row_projecting_columns(row_id, &column_entries, columns).map(Some)
    }

    fn query_rows_by_id_range_projecting_columns(
        &self,
        table_name: &str,
        start: Option<i64>,
        end: Option<i64>,
        inclusive_start: bool,
        inclusive_end: bool,
        columns: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<serde_json::Value>> {
        let start_key = match start {
            Some(row_id) if inclusive_start => keys::row_key(table_name, row_id),
            Some(row_id) => proofs::prefix_successor_required(&keys::row_key(table_name, row_id))?,
            None => keys::row_prefix(table_name),
        };

        let end_key = match end {
            Some(row_id) if inclusive_end => {
                proofs::prefix_successor_required(&keys::row_key(table_name, row_id))?
            }
            Some(row_id) => keys::row_key(table_name, row_id),
            None => proofs::prefix_successor_required(&keys::row_prefix(table_name))?,
        };

        let key_values = self.iter_range(&start_key, Some(&end_key))?;
        group_columns_into_rows_projecting_columns(&key_values, columns)
    }

    /// Scan the index for `(table, column, value)` and return the row keys
    /// Look up row keys matching a predicate on an indexed column.
    ///
    /// Computes index key ranges based on the predicate operator and returns
    /// the row keys that the matching index entries point to.
    ///
    /// Shared by `query_rows` (read path) and `prove_query_tracer` (proof path).
    pub(crate) fn index_row_keys_for_predicate(
        &self,
        table_name: &str,
        predicate: &Predicate,
    ) -> Result<Vec<Vec<u8>>> {
        let column = &predicate.column;
        let prefix_for = |v: &QueryParam| -> Result<Vec<u8>> {
            keys::index_value_prefix(table_name, column, keys::query_param_to_tuple_element(v))
                .map_err(|e| SdkError::InvalidQuery(format!("Invalid index value: {e}")))
        };
        let all_start = keys::index_column_prefix(table_name, column);
        let all_end = proofs::prefix_successor_required(&all_start)?;
        let first = predicate.values.first();

        let index_entries = match &predicate.operator {
            ComparisonOperator::Equal | ComparisonOperator::In => {
                let mut entries = Vec::new();
                for val in &predicate.values {
                    entries.extend(self.iter_prefix(&prefix_for(val)?)?);
                }
                entries
            }
            ComparisonOperator::GreaterThan => {
                let v = first
                    .ok_or_else(|| SdkError::InvalidQuery("GreaterThan requires a value".into()))?;
                self.iter_range(
                    &proofs::prefix_successor_required(&prefix_for(v)?)?,
                    Some(&all_end),
                )?
            }
            ComparisonOperator::GreaterThanOrEqual => {
                let v = first.ok_or_else(|| {
                    SdkError::InvalidQuery("GreaterThanOrEqual requires a value".into())
                })?;
                self.iter_range(&prefix_for(v)?, Some(&all_end))?
            }
            ComparisonOperator::LessThan => {
                let v = first
                    .ok_or_else(|| SdkError::InvalidQuery("LessThan requires a value".into()))?;
                self.iter_range(&all_start, Some(&prefix_for(v)?))?
            }
            ComparisonOperator::LessThanOrEqual => {
                let v = first.ok_or_else(|| {
                    SdkError::InvalidQuery("LessThanOrEqual requires a value".into())
                })?;
                self.iter_range(
                    &all_start,
                    Some(&proofs::prefix_successor_required(&prefix_for(v)?)?),
                )?
            }
            ComparisonOperator::Between => {
                let lo = first
                    .ok_or_else(|| SdkError::InvalidQuery("Between requires two values".into()))?;
                let hi = predicate
                    .values
                    .get(1)
                    .ok_or_else(|| SdkError::InvalidQuery("Between requires two values".into()))?;
                self.iter_range(
                    &prefix_for(lo)?,
                    Some(&proofs::prefix_successor_required(&prefix_for(hi)?)?),
                )?
            }
        };

        let mut row_keys = Vec::with_capacity(index_entries.len());
        for (key, _) in &index_entries {
            if let Ok(keys::ParsedKey::Index { row_id, .. }) = keys::parse_key(key) {
                row_keys.push(keys::row_key(table_name, row_id));
            }
        }
        Ok(row_keys)
    }

    /// Build direct insert operations for writes that bypass the changelog.
    ///
    /// Emits only column and index Puts; the caller appends the
    /// `schema_next_id_key` Put when the table is auto-incrementing.
    fn direct_insert_operations(&self, query: &Query) -> Result<(Vec<Operation>, i64)> {
        let (row, column_data) = get_row_data_from_query(query)?;

        let raw_id = row.get(ID_FIELD).and_then(|v| v.as_i64());
        let auto_increment = self.read_auto_increment(&query.table)?;

        let (id_num, is_explicit) = match classify_insert_id(raw_id, auto_increment)
            .map_err(|e| SdkError::InsertError(e.describe(&query.table)))?
        {
            InsertId::Explicit(id) => (id, true),
            InsertId::AutoAssign => {
                let id = self.read_next_id(&query.table)?;
                (id, false)
            }
        };

        // Explicit-ID inserts must not overwrite an existing row.
        if is_explicit && self.get_row_by_id(&query.table, id_num)?.is_some() {
            return Err(SdkError::InsertError(format!(
                "row {}.id={id_num} already exists — explicit-ID insert would overwrite",
                query.table
            )));
        }

        let mut ops = Vec::new();

        // Determine List columns for this table and allocate list_numbers.
        // NOTE: For user-table inserts this code is unreachable — those go
        // through apply_change_with_pruned_tree / InsertOp::extract_and_validate.
        // This path only fires for internal-table inserts (_users,
        // _key_history, _retention), none of which have List columns.
        let list_col_names: std::collections::BTreeSet<String> = self
            .get_schema(&query.table)
            .map(|schema| {
                schema
                    .columns
                    .iter()
                    .filter(|c| matches!(c.column_type, crate::schema::ColumnType::List))
                    .map(|c| c.name.clone())
                    .collect()
            })
            .unwrap_or_default();

        let list_number_base = if !list_col_names.is_empty() {
            let key = keys::schema_next_list_number_key();
            match self.get_value(&key)? {
                Some(bytes) => {
                    if bytes.len() != 8 {
                        return Err(SdkError::DatabaseError(format!(
                            "schema_next_list_number_key has invalid length {}",
                            bytes.len()
                        )));
                    }
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes);
                    i64::from_be_bytes(buf)
                }
                None => 1i64,
            }
        } else {
            0
        };

        // Insert per-column entries. List columns get the allocated
        // list_number instead of the client's placeholder 0.
        let zero_placeholder =
            stored_value::value_to_bytes(&serde_json::json!(0)).expect("serializing 0 cannot fail");
        let mut list_col_offset: i64 = 0;
        for (col_name, col_bytes) in &column_data {
            let col_key = keys::column_key(&query.table, id_num, col_name);
            if list_col_names.contains(col_name) {
                if col_bytes != &zero_placeholder {
                    return Err(SdkError::InsertError(format!(
                        "List column '{}' must carry placeholder value 0, got different bytes",
                        col_name
                    )));
                }
                let list_number =
                    list_number_base
                        .checked_add(list_col_offset)
                        .ok_or_else(|| {
                            SdkError::DatabaseError(format!(
                        "list_number overflow at base={list_number_base}+offset={list_col_offset}"
                    ))
                        })?;
                list_col_offset += 1;
                let stored_bytes = stored_value::value_to_bytes(&serde_json::json!(list_number))
                    .map_err(|e| {
                        SdkError::SerializationError(format!(
                            "failed to serialize list_number: {e}"
                        ))
                    })?;
                ops.push((col_key, Op::Put(stored_bytes)));
            } else {
                ops.push((col_key, Op::Put(col_bytes.clone())));
            }
        }

        // Insert index entries (skip List columns — their placeholder value
        // is not the stored value, and the SDK queries _lists by list_number).
        let indexed_columns = self.get_indexed_columns(&query.table).unwrap_or_default();
        for (column_name, column_type) in &indexed_columns {
            if list_col_names.contains(column_name) {
                continue;
            }
            if let Some(column_value) = row.get(column_name) {
                let idx_key = keys::typed_index_key(
                    &query.table,
                    column_name,
                    column_value,
                    id_num,
                    column_type,
                )?;
                // Store row_id as value for quick reference
                ops.push((idx_key, Op::Put(row_id_to_bytes(id_num).to_vec())));
            }
        }

        // Emit list_number counter bump and per-list head/tail initialization.
        if !list_col_names.is_empty() {
            let num_lists = list_col_names.len() as i64;
            let new_counter = list_number_base.checked_add(num_lists).ok_or_else(|| {
                SdkError::DatabaseError(format!(
                    "list_number counter overflow at base={list_number_base}+{num_lists}"
                ))
            })?;
            ops.push((
                keys::schema_next_list_number_key(),
                Op::Put(new_counter.to_be_bytes().to_vec()),
            ));
            for i in 0..num_lists {
                let ln = list_number_base.checked_add(i).ok_or_else(|| {
                    SdkError::DatabaseError(format!(
                        "list_number overflow at base={list_number_base}+{i}"
                    ))
                })?;
                ops.push((
                    keys::list_head_key(ln),
                    Op::Put(0i64.to_be_bytes().to_vec()),
                ));
                ops.push((
                    keys::list_tail_key(ln),
                    Op::Put(0i64.to_be_bytes().to_vec()),
                ));
            }
        }

        Ok((ops, id_num))
    }

    /// Write each action into authenticated state under
    /// `action_storage_key(primary_table, name)` with a version-byte
    /// prefixed postcard body.  Called during space setup (once actions
    /// are known) and must complete before any `OpType::Action` entry
    /// is applied.
    pub async fn import_actions(&self, actions: &[Action]) -> Result<()> {
        if actions.is_empty() {
            return Ok(());
        }
        // Action names are the signed identifier for app-defined ops;
        // duplicate names would let the later import silently shadow
        // the earlier one.  Reject at the storage chokepoint so both
        // KDL and JSON import paths are covered.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for action in actions {
            if !seen.insert(action.name.as_str()) {
                return Err(SdkError::ValidationError(format!(
                    "import_actions: action '{}' is listed more than once; action names must \
                     be unique",
                    action.name
                )));
            }
        }
        let mut ops: Vec<Operation> = Vec::with_capacity(actions.len());
        for action in actions {
            let primary_table = action
                .legs
                .first()
                .ok_or_else(|| {
                    SdkError::ValidationError(format!(
                        "import_actions: action '{}' has no legs",
                        action.name
                    ))
                })?
                .table();
            let body = postcard::to_allocvec(&action.body()).map_err(|e| {
                SdkError::SerializationError(format!(
                    "Failed to serialize action '{}': {e}",
                    action.name
                ))
            })?;
            let value = encode_action_value(body);
            let key = action_storage_key(primary_table, &action.name);
            ops.push((key, Op::Put(value)));
        }
        self.apply_batch(ops)
    }

    /// Write the action-gating list for each `(table, op)` to its own
    /// merk entry at `acl_only_via_actions_key(table, op)`.  An empty
    /// map is a no-op; absent keys are interpreted by the verifier as
    /// "no action-gating applies for this (table, op)."
    pub async fn import_acl_only_via_actions(
        &self,
        only_via: &std::collections::BTreeMap<(String, String), Vec<String>>,
    ) -> Result<()> {
        if only_via.is_empty() {
            return Ok(());
        }
        let mut ops: Vec<Operation> = Vec::with_capacity(only_via.len());
        for ((table, op), actions) in only_via {
            let blob = postcard::to_allocvec(actions).map_err(|e| {
                SdkError::SerializationError(format!(
                    "Failed to serialize only_via_actions for ({table}, {op}): {e}"
                ))
            })?;
            let key = acl_only_via_actions_key(table, op);
            ops.push((key, Op::Put(blob)));
        }
        self.apply_batch(ops)
    }

    /// Read the `_access_control` table, group rules by `(table, op)`
    /// (AND-combined when multiple apply), and write each combined rule
    /// to its own merk entry at `acl_rule_key(table, op)`.
    ///
    /// Must be called once during space setup, after all
    /// `_access_control` rows have been inserted.  Tables / ops with no
    /// rule produce no merk entry; the verifier treats absence as
    /// "no ACL rule applies."
    pub async fn finalize_acl_blob(&self) -> Result<()> {
        use crate::access_control::{AccessControlRecord, AccessRule, ACCESS_CONTROL_TABLE_NAME};
        use std::collections::BTreeMap;

        let query = Query::new(
            ACCESS_CONTROL_TABLE_NAME.to_string(),
            QueryOperation::Select(vec![]),
        );
        let rows: Vec<serde_json::Value> = self.select_all(query).await?;

        // Group and AND-combine rules by (resource_name, operation).
        let mut map: BTreeMap<(String, String), AccessRule> = BTreeMap::new();
        for row in rows {
            let record: AccessControlRecord = serde_json::from_value(row).map_err(|e| {
                SdkError::SerializationError(format!("Failed to parse access control row: {e}"))
            })?;
            let key = (record.resource_name, record.operation.to_string());
            map.entry(key)
                .and_modify(|existing| *existing = existing.clone().and(record.rule.clone()))
                .or_insert(record.rule);
        }

        // Lint: every column referenced by a rule must be of a type whose
        // postcard encoding is guaranteed to stay below `value-size limit`
        // (currently 32 bytes). Otherwise the value can be replaced by a
        // hash in the changelog entry, and ACL evaluation would lose
        // visibility into the column. We restrict to `ColumnType::Integer`
        // because (a) `AccessRule::evaluate` only reasons about i64 values
        // and (b) postcard-encoded i64 is at most 10 bytes (varint), well
        // below the threshold. This matches the runtime fail-closed guard
        // in `extract_acl_columns_from_entry` — both must agree.
        for ((resource_name, operation), rule) in &map {
            let mut cols = Vec::new();
            rule.collect_resource_columns(&mut cols);
            if cols.is_empty() {
                continue;
            }
            let schema = self.get_schema(resource_name).map_err(|e| {
                SdkError::ValidationError(format!(
                    "ACL rule for ({resource_name}, {operation}) references unknown table: {e}"
                ))
            })?;
            for col_name in &cols {
                let col_def = schema
                    .columns
                    .iter()
                    .find(|c| &c.name == col_name)
                    .ok_or_else(|| {
                        SdkError::ValidationError(format!(
                            "ACL rule for ({resource_name}, {operation}) references column \
                             '{col_name}' that does not exist in table '{resource_name}'"
                        ))
                    })?;
                if !matches!(col_def.column_type, crate::schema::ColumnType::Integer) {
                    return Err(SdkError::ValidationError(format!(
                        "ACL rule for ({resource_name}, {operation}) references column \
                         '{col_name}' of type {:?}; only Integer columns are allowed in ACL \
                         rules because larger types may exceed the value-hash threshold and \
                         become invisible to in-proof ACL evaluation",
                        col_def.column_type
                    )));
                }
            }
        }

        // One merk entry per (table, op).  Absent (table, op) pairs
        // mean "no rule applies."
        let mut ops: Vec<Operation> = Vec::with_capacity(map.len());
        for ((table, op), rule) in &map {
            let blob = postcard::to_allocvec(rule).map_err(|e| {
                SdkError::SerializationError(format!(
                    "Failed to serialize ACL rule for ({table}, {op}): {e}"
                ))
            })?;
            ops.push((keys::acl_rule_key(table, op), Op::Put(blob)));
        }
        self.apply_batch(ops)
    }

    /// Read the ACL rule for a single `(table, op)` pair.  Returns
    /// `Ok(None)` if no rule is declared for this pair (default-open
    /// semantics).  `Err` if the stored blob fails to deserialize.
    pub fn read_acl_rule(
        &self,
        table: &str,
        op: &str,
    ) -> Result<Option<crate::access_control::AccessRule>> {
        let key = keys::acl_rule_key(table, op);
        let bytes = match self.get_value(&key)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        let rule = postcard::from_bytes(&bytes).map_err(|e| {
            SdkError::SerializationError(format!(
                "Failed to deserialize ACL rule for ({table}, {op}): {e}"
            ))
        })?;
        Ok(Some(rule))
    }
}

#[cfg(feature = "merk")]
impl Default for MerkStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Query strategy based on predicate.
#[cfg(feature = "merk")]
enum QueryStrategy {
    ById(i64),
    ByIds(Vec<i64>),
    ByIdRange {
        start: Option<i64>,
        end: Option<i64>,
        inclusive_start: bool,
        inclusive_end: bool,
    },
    ByIndex {
        predicate: Predicate,
    },
    TableScan,
}

#[async_trait::async_trait]
#[cfg(feature = "merk")]
impl Storage for MerkStorage {
    async fn create_table(&self, schema: &Schema) -> Result<()> {
        // Check if schema already exists
        if self.get_schema(&schema.name).is_ok() {
            return Ok(());
        }

        // Store schema
        let schema_key = keys::schema_key(&schema.name);
        let schema_json =
            serde_json::to_vec(schema).map_err(|e| SdkError::SerializationError(e.to_string()))?;

        // Store compact column-names list (null-separated, non-id columns only)
        let col_names: std::collections::BTreeSet<String> = schema
            .columns
            .iter()
            .filter(|c| c.name != "id")
            .map(|c| c.name.clone())
            .collect();
        let columns_key = keys::schema_columns_key(&schema.name);
        let columns_value = encode_column_names(&col_names);

        // Store compact indexed-column-names list (null-separated)
        let idx_names: std::collections::BTreeSet<String> = schema
            .indexed_columns()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let indexes_key = schema_indexes_key(&schema.name);
        let indexes_value = encode_column_names(&idx_names);

        // Store the authenticated id-allocation mode (one byte).
        let id_mode_key = keys::schema_id_mode_key(&schema.name);
        let id_mode_byte: u8 = if schema.auto_increment { 0 } else { 1 };

        let mut ops = vec![
            (schema_key, Op::Put(schema_json)),
            (columns_key, Op::Put(columns_value)),
            (id_mode_key, Op::Put(vec![id_mode_byte])),
        ];
        // Only write the indexes key if the table has indexes
        if !idx_names.is_empty() {
            ops.push((indexes_key, Op::Put(indexes_value)));
        }

        // Store compact list-column-names list (null-separated)
        let list_col_names: std::collections::BTreeSet<String> = schema
            .columns
            .iter()
            .filter(|c| matches!(c.column_type, crate::schema::ColumnType::List))
            .map(|c| c.name.clone())
            .collect();
        if !list_col_names.is_empty() {
            let list_columns_key = keys::schema_list_columns_key(&schema.name);
            let list_columns_value = encode_column_names(&list_col_names);
            ops.push((list_columns_key, Op::Put(list_columns_value)));
        }

        self.apply_batch(ops)
    }

    /// Insert a row directly into the tree, bypassing the changelog.
    ///
    /// Only used by tests and schema bootstrap. Production client writes never
    /// use this method.
    async fn insert(&self, query: Query, _auth_context: &AuthContext) -> Result<i64> {
        let (mut ops, id) = self.direct_insert_operations(&query)?;

        // Auto-increment tables bump the authenticated next-id counter
        // past this row when the id is at or above the current counter.
        // Explicit-ID tables never touch the counter.
        if self.read_auto_increment(&query.table)? {
            let counter = self.read_next_id(&query.table)?;
            let next = Self::next_id_after(&query.table, id)?;
            if next > counter {
                ops.push(Self::next_id_put_op(&query.table, next));
            }
        }

        self.apply_batch(ops)?;
        Ok(id)
    }

    async fn select_one<T>(&self, query: Query) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let rows = self.query_rows(&query)?;

        if let Some(first) = rows.into_iter().next() {
            let result: T = serde_json::from_value(first)
                .map_err(|e| SdkError::SerializationError(e.to_string()))?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    async fn select_all<T>(&self, query: Query) -> Result<Vec<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let rows = self.query_rows(&query)?;

        let results: Vec<T> = rows
            .into_iter()
            .map(|row| match serde_json::from_value(row) {
                Ok(v) => Ok(v),
                Err(e) => {
                    eprintln!("ERROR select_all: deserialization failed: {e}");
                    Err(SdkError::SerializationError(e.to_string()))
                }
            })
            .collect::<Result<Vec<T>>>()?;

        Ok(results)
    }

    async fn update_or_delete(&self, query: Query, auth_context: &AuthContext) -> Result<usize> {
        let access_rule = load_access_rule(self, &query).await?;

        let access_control = access_rule.as_ref().map(|rule| (rule, auth_context));
        let all_rows = self.query_rows(&query)?;

        // Filter rows by access control if provided.
        let rows: Vec<Value> = if let Some((rule, auth)) = access_control {
            all_rows
                .into_iter()
                .filter(|row| rule.evaluate(auth.uid, Some(row)).unwrap_or(false))
                .collect()
        } else {
            all_rows
        };

        let row_count = rows.len();
        if row_count == 0 {
            return Ok(0);
        }

        let mut ops = Vec::new();
        let indexed_columns = self.get_indexed_columns(&query.table).unwrap_or_default();

        match &query.operation {
            QueryOperation::Update(updates) => {
                for row in &rows {
                    let id = row[ID_FIELD]
                        .as_i64()
                        .ok_or_else(|| SdkError::DatabaseError("Row missing id".into()))?;

                    // Build updated row for index change detection.
                    let mut updated_row = row.as_object().unwrap().clone();
                    for (col, param) in updates {
                        apply_update_to_row(&mut updated_row, col, param)?;
                    }
                    updated_row.remove(ID_FIELD);

                    for (col, param) in updates {
                        if col == ID_FIELD {
                            continue;
                        }
                        let col_value = param_to_json(param);
                        let col_bytes = stored_value::value_to_bytes(&col_value)?;
                        let col_key = keys::column_key(&query.table, id, col);
                        ops.push((col_key, Op::Put(col_bytes)));
                    }

                    for (column_name, column_type) in &indexed_columns {
                        let old_value_opt = row.get(column_name);
                        let new_value_opt = updated_row.get(column_name);

                        if old_value_opt != new_value_opt
                            && updates.iter().any(|(col, _)| col == column_name)
                        {
                            if let Some(old_value) = row.get(column_name) {
                                let idx_key = keys::typed_index_key(
                                    &query.table,
                                    column_name,
                                    old_value,
                                    id,
                                    column_type,
                                )?;
                                ops.push((idx_key, Op::Delete));
                            }

                            if let Some(new_value) = updated_row.get(column_name) {
                                let idx_key = keys::typed_index_key(
                                    &query.table,
                                    column_name,
                                    new_value,
                                    id,
                                    column_type,
                                )?;
                                ops.push((idx_key, Op::Put(row_id_to_bytes(id).to_vec())));
                            }
                        }
                    }
                }
            }
            QueryOperation::Delete => {
                for row in &rows {
                    let id = row[ID_FIELD]
                        .as_i64()
                        .ok_or_else(|| SdkError::DatabaseError("Row missing id".into()))?;

                    if let Some(row_obj) = row.as_object() {
                        for col_name in row_obj.keys() {
                            if col_name != ID_FIELD {
                                let col_key = keys::column_key(&query.table, id, col_name);
                                ops.push((col_key, Op::Delete));
                            }
                        }
                    }

                    for (column_name, column_type) in &indexed_columns {
                        if let Some(column_value) = row.get(column_name) {
                            let idx_key = keys::typed_index_key(
                                &query.table,
                                column_name,
                                column_value,
                                id,
                                column_type,
                            )?;
                            ops.push((idx_key, Op::Delete));
                        }
                    }
                }
            }
            _ => {
                return Err(SdkError::InvalidQuery(
                    "Expected UPDATE or DELETE operation".into(),
                ))
            }
        }

        self.apply_batch(ops)?;
        Ok(row_count)
    }
}

/// Given a Query, return per-column serialized data for the row.
///
/// Returns `(full_row_map, Vec<(column_name, serialized_column_value)>)`.
/// Each column value is individually serialized via `serde_json::to_vec`.
/// The ID field is excluded from the column data (it's encoded in the key).
pub fn get_row_data_from_query(query: &Query) -> Result<RowData> {
    let fields = match &query.operation {
        QueryOperation::Insert(fields) => fields.clone(),
        QueryOperation::Update(fields) => fields.clone(),
        QueryOperation::Delete => {
            // Extract id(s) from the predicate so the changelog entry can be built.
            let mut id_fields = vec![];
            if let Some(pred) = &query.predicate {
                if pred.column == ID_FIELD {
                    match pred.operator {
                        ComparisonOperator::Equal => {
                            if let Some(v) = pred.values.first() {
                                id_fields.push((ID_FIELD.to_string(), v.clone()));
                            }
                        }
                        ComparisonOperator::In => {
                            for v in &pred.values {
                                id_fields.push((ID_FIELD.to_string(), v.clone()));
                            }
                        }
                        _ => {
                            return Err(SdkError::InvalidQuery(
                                "Delete predicate on id must use Equal or In operator".into(),
                            ));
                        }
                    }
                }
            }
            id_fields
        }
        _ => {
            return Err(SdkError::InvalidQuery(
                "Expected INSERT or UPDATE operation".into(),
            ));
        }
    };

    // Build row from the query's fields
    let mut row = serde_json::Map::new();
    for (col, param) in &fields {
        row.insert(col.clone(), param_to_json(param));
    }

    // Serialize each column individually (without ID)
    let mut column_data: Vec<(String, Vec<u8>)> = Vec::new();
    for (col_name, col_value) in &row {
        if col_name == ID_FIELD {
            continue;
        }
        let col_bytes = stored_value::value_to_bytes(col_value)?;
        column_data.push((col_name.clone(), col_bytes));
    }

    Ok((row, column_data))
}

/// Build parallel key and value vectors from per-column data.
///
/// `key_fn` maps each column name to its encoded key (e.g. `column_key` or
/// `column_key_placeholder`).  Returns `(keys, values)` where both vectors
/// are in the same order as `column_data`.
pub fn build_column_kv_vecs(
    column_data: &[(String, Vec<u8>)],
    key_fn: impl Fn(&str) -> Vec<u8>,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let keys = column_data.iter().map(|(col, _)| key_fn(col)).collect();
    let values = column_data.iter().map(|(_, v)| v.clone()).collect();
    (keys, values)
}

/// Reassemble a row from per-column key-value entries.
///
/// Takes the row_id and a slice of (key, value) pairs where each key is a column key
/// and each value is the serialized column value.
/// Returns the assembled JSON object with the `id` field injected.
pub fn reassemble_row(
    row_id: i64,
    column_entries: &[(Vec<u8>, Vec<u8>)],
) -> Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    obj.insert(
        ID_FIELD.to_string(),
        serde_json::Value::Number(row_id.into()),
    );

    for (key, value_bytes) in column_entries {
        let column_name = match keys::parse_key(key) {
            Ok(keys::ParsedKey::Column { column, .. }) => column,
            _ => continue, // Skip non-column keys (shouldn't happen with prefix scan)
        };

        let col_value = stored_value::bytes_to_value(value_bytes).map_err(|e| {
            SdkError::SerializationError(format!(
                "Failed to deserialize column '{column_name}': {e}"
            ))
        })?;
        obj.insert(column_name, col_value);
    }

    Ok(serde_json::Value::Object(obj))
}

fn reassemble_row_projecting_columns(
    row_id: i64,
    column_entries: &[(Vec<u8>, Vec<u8>)],
    columns: &std::collections::BTreeSet<String>,
) -> Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    obj.insert(
        ID_FIELD.to_string(),
        serde_json::Value::Number(row_id.into()),
    );

    for (key, value_bytes) in column_entries {
        let column_name = match keys::parse_key(key) {
            Ok(keys::ParsedKey::Column { column, .. }) => column,
            _ => continue,
        };
        if !columns.contains(&column_name) {
            continue;
        }

        let col_value = stored_value::bytes_to_value(value_bytes).map_err(|e| {
            SdkError::SerializationError(format!(
                "Failed to deserialize column '{column_name}': {e}"
            ))
        })?;
        obj.insert(column_name, col_value);
    }

    Ok(serde_json::Value::Object(obj))
}

/// Group consecutive per-column entries into complete rows.
///
/// Assumes entries are sorted by key (which means all columns for a given row_id
/// are contiguous). Returns a Vec of reassembled row JSON objects.
pub fn group_columns_into_rows(
    column_entries: &[(Vec<u8>, Vec<u8>)],
) -> Result<Vec<serde_json::Value>> {
    if column_entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut rows = Vec::new();
    let mut current_row_id: Option<i64> = None;
    let mut current_group: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for (key, value) in column_entries {
        let row_id = match keys::parse_key(key) {
            Ok(keys::ParsedKey::Column { row_id, .. }) => row_id,
            _ => continue, // Skip non-column keys
        };

        if current_row_id == Some(row_id) {
            current_group.push((key.clone(), value.clone()));
        } else {
            // Flush previous group
            if let Some(prev_id) = current_row_id {
                rows.push(reassemble_row(prev_id, &current_group)?);
            }
            current_row_id = Some(row_id);
            current_group = vec![(key.clone(), value.clone())];
        }
    }

    // Flush last group
    if let Some(prev_id) = current_row_id {
        rows.push(reassemble_row(prev_id, &current_group)?);
    }

    Ok(rows)
}

fn group_columns_into_rows_projecting_columns(
    column_entries: &[(Vec<u8>, Vec<u8>)],
    columns: &std::collections::BTreeSet<String>,
) -> Result<Vec<serde_json::Value>> {
    if column_entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut rows = Vec::new();
    let mut current_row_id: Option<i64> = None;
    let mut current_group: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for (key, value) in column_entries {
        let row_id = match keys::parse_key(key) {
            Ok(keys::ParsedKey::Column { row_id, .. }) => row_id,
            _ => continue,
        };

        if current_row_id == Some(row_id) {
            current_group.push((key.clone(), value.clone()));
        } else {
            if let Some(prev_id) = current_row_id {
                rows.push(reassemble_row_projecting_columns(
                    prev_id,
                    &current_group,
                    columns,
                )?);
            }
            current_row_id = Some(row_id);
            current_group = vec![(key.clone(), value.clone())];
        }
    }

    if let Some(prev_id) = current_row_id {
        rows.push(reassemble_row_projecting_columns(
            prev_id,
            &current_group,
            columns,
        )?);
    }

    Ok(rows)
}

/// Group column entries into rows, organized by table.
///
/// Unlike [`group_columns_into_rows`] (which assumes a single table with
/// contiguous entries), this handles entries from multiple tables and
/// non-contiguous row_ids. Returns rows sorted by ID within each table.
pub fn group_columns_into_rows_by_table(
    column_entries: &[(Vec<u8>, Vec<u8>)],
) -> Result<HashMap<String, Vec<serde_json::Value>>> {
    // Group raw entries by (table, row_id)
    type ColumnGroup = Vec<(Vec<u8>, Vec<u8>)>;
    let mut groups: HashMap<(String, i64), ColumnGroup> = HashMap::new();
    for (key, value) in column_entries {
        if let Ok(keys::ParsedKey::Column { table, row_id, .. }) = keys::parse_key(key) {
            groups
                .entry((table, row_id))
                .or_default()
                .push((key.clone(), value.clone()));
        }
    }

    // Reassemble each group and organize by table
    let mut rows_by_table: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    for ((table, row_id), columns) in groups {
        let row = reassemble_row(row_id, &columns)?;
        rows_by_table.entry(table).or_default().push(row);
    }

    // Sort rows by ID within each table for deterministic ordering
    for rows in rows_by_table.values_mut() {
        rows.sort_by_key(|r| r.get(ID_FIELD).and_then(|v| v.as_i64()).unwrap_or(0));
    }

    Ok(rows_by_table)
}

fn is_hash_backed_column(schemas: &HashMap<String, Schema>, table: &str, column: &str) -> bool {
    schemas
        .get(table)
        .and_then(|schema| schema.columns.iter().find(|c| c.name == column))
        .is_some_and(|column_def| column_def.column_type.is_hash_backed())
}

fn resolve_hash_backed_bytes(
    table: &str,
    column: &str,
    value_bytes: &[u8],
    material_by_hash: &HashedValues,
) -> Result<Vec<u8>> {
    let hash: [u8; HASH_LEN] = value_bytes.try_into().map_err(|_| {
        SdkError::ValidationError(format!(
            "Hash-backed column {table}.{column} stored {} bytes, expected {}",
            value_bytes.len(),
            HASH_LEN
        ))
    })?;

    material_by_hash.get(&hash).cloned().ok_or_else(|| {
        SdkError::ValidationError(format!(
            "Missing hashed value for hash-backed column {table}.{column}"
        ))
    })
}

fn reassemble_row_resolving_hashes(
    row_id: i64,
    column_entries: &[(Vec<u8>, Vec<u8>)],
    schemas: &HashMap<String, Schema>,
    material_by_hash: &HashedValues,
) -> Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    obj.insert(
        ID_FIELD.to_string(),
        serde_json::Value::Number(row_id.into()),
    );

    for (key, value_bytes) in column_entries {
        let (table_name, column_name) = match keys::parse_key(key) {
            Ok(keys::ParsedKey::Column { table, column, .. }) => (table, column),
            _ => continue,
        };

        let resolved_bytes = if is_hash_backed_column(schemas, &table_name, &column_name) {
            resolve_hash_backed_bytes(&table_name, &column_name, value_bytes, material_by_hash)?
        } else {
            value_bytes.clone()
        };

        let col_value = stored_value::bytes_to_value(&resolved_bytes).map_err(|e| {
            SdkError::SerializationError(format!(
                "Failed to deserialize column '{column_name}': {e}"
            ))
        })?;
        obj.insert(column_name, col_value);
    }

    Ok(serde_json::Value::Object(obj))
}

/// Group column entries into rows, resolving schema-selected hash-backed columns
/// through supplied hashed values before JSON value decoding.
pub fn group_columns_into_rows_by_table_resolving_hashes(
    column_entries: &[(Vec<u8>, Vec<u8>)],
    schemas: &HashMap<String, Schema>,
    hashed_values: &HashedValues,
) -> Result<HashMap<String, Vec<serde_json::Value>>> {
    type ColumnGroup = Vec<(Vec<u8>, Vec<u8>)>;
    let mut groups: HashMap<(String, i64), ColumnGroup> = HashMap::new();
    for (key, value) in column_entries {
        if let Ok(keys::ParsedKey::Column { table, row_id, .. }) = keys::parse_key(key) {
            groups
                .entry((table, row_id))
                .or_default()
                .push((key.clone(), value.clone()));
        }
    }

    let mut rows_by_table: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    for ((table, row_id), columns) in groups {
        let row = reassemble_row_resolving_hashes(row_id, &columns, schemas, hashed_values)?;
        rows_by_table.entry(table).or_default().push(row);
    }

    for rows in rows_by_table.values_mut() {
        rows.sort_by_key(|r| r.get(ID_FIELD).and_then(|v| v.as_i64()).unwrap_or(0));
    }

    Ok(rows_by_table)
}

/// Convert QueryParam to JSON value.
fn param_to_json(p: &QueryParam) -> serde_json::Value {
    match p {
        QueryParam::Text(s) => serde_json::Value::String(s.clone()),
        QueryParam::Integer(i) => serde_json::Value::Number((*i).into()),
        QueryParam::Boolean(b) => serde_json::Value::Bool(*b),
        QueryParam::Null => serde_json::Value::Null,
        QueryParam::Real(f) => serde_json::Value::Number(serde_json::Number::from_f64(*f).unwrap()),
        QueryParam::Blob(b) => serde_json::Value::String(STANDARD.encode(b)),
    }
}

/// Sort rows by the predicate's implicit sort key in the requested direction.
///
/// The primary key is the predicate's column (or row id when there's no
/// predicate / it's an id predicate). Row id is always the tiebreaker — this
/// matches the index layout `(table, column, value, row_id)`, so even an
/// `Equal` predicate (where every matched row shares the same value)
/// produces a deterministic order by row id.
fn apply_query_order(mut rows: Vec<serde_json::Value>, query: &Query) -> Vec<serde_json::Value> {
    // After a join, the SDK's `assemble_join` prefixes every column with the
    // table name (`messages.id`, `messages.channel_id`, …). Look up both the
    // bare column and the table-prefixed form so ordering works on joined
    // and non-joined rows alike.
    let primary_column = query
        .predicate
        .as_ref()
        .map(|p| p.column.as_str())
        .filter(|c| *c != ID_FIELD)
        .map(|c| c.to_string());
    let primary_column_prefixed = primary_column
        .as_ref()
        .map(|c| format!("{}.{}", query.table, c));
    let id_field_prefixed = format!("{}.{}", query.table, ID_FIELD);

    let lookup_value = |row: &serde_json::Value, col: &str, prefixed: &str| {
        row.get(col)
            .or_else(|| row.get(prefixed))
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    let lookup_id = |row: &serde_json::Value| -> i64 {
        row.get(ID_FIELD)
            .or_else(|| row.get(&id_field_prefixed))
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
    };

    rows.sort_by(|a, b| {
        let cmp = if let Some(col) = &primary_column {
            let prefixed = primary_column_prefixed.as_deref().unwrap_or(col);
            let va = lookup_value(a, col, prefixed);
            let vb = lookup_value(b, col, prefixed);
            compare_json_values(&va, &vb)
        } else {
            Ordering::Equal
        }
        .then_with(|| lookup_id(a).cmp(&lookup_id(b)));
        match query.order {
            Order::Asc => cmp,
            Order::Desc => cmp.reverse(),
        }
    });

    rows
}

/// Compare two JSON values for ordering.
fn compare_json_values(a: &serde_json::Value, b: &serde_json::Value) -> std::cmp::Ordering {
    match (a, b) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Null, _) => Ordering::Less,
        (_, Value::Null) => Ordering::Greater,

        (Value::Number(n1), Value::Number(n2)) => {
            let f1 = n1.as_f64().unwrap_or(0.0);
            let f2 = n2.as_f64().unwrap_or(0.0);
            f1.partial_cmp(&f2).unwrap_or(Ordering::Equal)
        }

        (Value::String(s1), Value::String(s2)) => s1.cmp(s2),
        (Value::Bool(b1), Value::Bool(b2)) => b1.cmp(b2),

        (Value::Array(a1), Value::Array(a2)) => {
            for (v1, v2) in a1.iter().zip(a2.iter()) {
                let cmp = compare_json_values(v1, v2);
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }
            a1.len().cmp(&a2.len())
        }

        (Value::Bool(_), _) => Ordering::Less,
        (Value::Number(_), Value::Bool(_)) => Ordering::Greater,
        (Value::Number(_), _) => Ordering::Less,
        (Value::String(_), Value::Bool(_) | Value::Number(_)) => Ordering::Greater,
        (Value::String(_), _) => Ordering::Less,
        (Value::Array(_), Value::Object(_)) => Ordering::Less,
        (Value::Array(_), _) => Ordering::Greater,
        (Value::Object(_), _) => Ordering::Greater,
    }
}

/// Apply one update pair to the row object.
#[cfg(feature = "merk")]
fn apply_update_to_row(
    row_obj: &mut serde_json::Map<String, serde_json::Value>,
    column: &str,
    param: &QueryParam,
) -> Result<()> {
    let new_value = param_to_json(param);
    row_obj.insert(column.to_string(), new_value);
    Ok(())
}

/// Filter row columns based on SELECT column list.
fn filter_columns(row: serde_json::Value, columns: &[String]) -> serde_json::Value {
    let mut result = serde_json::Map::new();

    if let Some(obj) = row.as_object() {
        for col_spec in columns {
            let upper_spec = col_spec.to_uppercase();
            let (source_col, dest_col) = if let Some(as_pos) = upper_spec.find(" AS ") {
                let source = col_spec[..as_pos].trim();
                let alias = col_spec[(as_pos + 4)..].trim();
                (source.to_string(), alias.to_string())
            } else if let Some(dot_pos) = col_spec.rfind('.') {
                let col_name = &col_spec[(dot_pos + 1)..];
                (col_spec.clone(), col_name.to_string())
            } else {
                (col_spec.clone(), col_spec.clone())
            };

            if let Some(value) = obj.get(&source_col) {
                result.insert(dest_col, value.clone());
            } else if let Some(dot_pos) = source_col.rfind('.') {
                let col_name = &source_col[(dot_pos + 1)..];
                for (key, value) in obj {
                    if key.ends_with(&format!(".{col_name}")) || key == col_name {
                        result.insert(dest_col.clone(), value.clone());
                        break;
                    }
                }
            }
        }
    }

    serde_json::Value::Object(result)
}

/// Apply the predicate's order, cursor, and limit to a row set — the slice
/// of the table the server's read path returns to the client. Does not
/// project columns and does not re-filter on the predicate.
///
/// Used by `process_query_results` and by the SDK on a cache hit to
/// reproduce server-side LIMIT semantics before any client-side filter
/// runs (so a fully-cached table doesn't return rows the server would
/// have hidden behind LIMIT).
pub fn apply_server_view(
    main_rows: Vec<serde_json::Value>,
    query: &Query,
) -> Vec<serde_json::Value> {
    let sorted_rows = apply_query_order(main_rows, query);

    // Apply optional cursor on the Equal predicate before LIMIT, so the limit
    // counts kept rows. The cursor lives on the predicate (only meaningful
    // with `operator == Equal`) and the walk direction (`order`) decides
    // whether it's a "next page" (Asc → id > cursor) or "older page" (Desc →
    // id < cursor) bound. Joined rows carry table-prefixed column keys
    // (`messages.id`); look up both forms.
    let cursor_filtered: Vec<serde_json::Value> =
        if let Some(cursor) = query.predicate.as_ref().and_then(|p| p.cursor_id) {
            let asc = matches!(query.order, crate::query::Order::Asc);
            let id_field_prefixed = format!("{}.{}", query.table, ID_FIELD);
            sorted_rows
                .into_iter()
                .filter(|row| {
                    let id = row
                        .get(ID_FIELD)
                        .or_else(|| row.get(&id_field_prefixed))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    if asc {
                        id > cursor
                    } else {
                        id < cursor
                    }
                })
                .collect()
        } else {
            sorted_rows
        };

    if let Some(limit) = query.limit {
        cursor_filtered.into_iter().take(limit as usize).collect()
    } else {
        cursor_filtered
    }
}

/// Apply the predicate's order and limit to a row set, then project columns
/// per `Select(cols)`. Used by the server's read path and by the SDK after a
/// cache hit returns the full table.
///
/// The rows passed in must already match the predicate — this function does
/// not re-filter.
pub fn process_query_results(
    main_rows: Vec<serde_json::Value>,
    query: &Query,
) -> Result<Vec<serde_json::Value>> {
    let limited_rows = apply_server_view(main_rows, query);

    Ok(if let QueryOperation::Select(columns) = &query.operation {
        if !columns.is_empty() {
            limited_rows
                .into_iter()
                .map(|row| filter_columns(row, columns))
                .collect()
        } else {
            limited_rows
        }
    } else {
        limited_rows
    })
}

#[cfg(all(test, feature = "merk"))]
mod tests {
    use super::*;
    use crate::access_control::AuthContext;
    use crate::schema::{ColumnDefinition, ColumnType};
    use crate::SpaceId;

    fn test_auth() -> AuthContext {
        AuthContext {
            uid: Some(1),
            space_id: SpaceId::from([0u8; 16]),
        }
    }

    fn test_schema() -> Schema {
        Schema {
            name: "test_table".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "name".to_string(),
                    column_type: ColumnType::String,
                    plaintext: true,
                    indexed: true,
                },
                ColumnDefinition {
                    name: "age".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
            ],
            auto_increment: true,
        }
    }

    #[tokio::test]
    async fn test_create_table() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        let retrieved = storage.get_schema("test_table").unwrap();
        assert_eq!(retrieved.name, "test_table");
        assert_eq!(retrieved.columns.len(), 3);
    }

    #[tokio::test]
    async fn test_insert_and_select() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = test_auth();
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert a row
        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("Alice".to_string())),
                ("age".to_string(), QueryParam::Integer(30)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let id = storage.insert(insert_query, &auth).await.unwrap();
        assert_eq!(id, 1);

        // Select the row
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(1)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let result: Option<serde_json::Value> = storage.select_one(select_query).await.unwrap();

        assert!(result.is_some());
        let row = result.unwrap();
        assert_eq!(row["id"], 1);
        assert_eq!(row["name"], "Alice");
        assert_eq!(row["age"], 30);
    }

    /// Auto-increment tables reject any explicit-id insert — including
    /// the `i64::MAX` attack — before it can corrupt the counter.
    #[tokio::test]
    async fn test_insert_rejects_explicit_id_on_autoincrement_table() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = test_auth();
        let schema = test_schema();
        storage.create_table(&schema).await.unwrap();

        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(i64::MAX)),
                ("name".to_string(), QueryParam::Text("Zed".to_string())),
                ("age".to_string(), QueryParam::Integer(99)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let err = storage.insert(insert_query, &auth).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("auto-increment") && msg.contains("explicit id"),
            "unexpected error: {msg}"
        );
    }

    /// Explicit-ID tables accept `id == i64::MAX`: with no counter to
    /// corrupt, the `i64::MAX` attack is moot.
    #[tokio::test]
    async fn test_explicit_table_allows_i64_max_insert() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = test_auth();
        let mut schema = test_schema();
        schema.auto_increment = false;
        storage.create_table(&schema).await.unwrap();

        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(i64::MAX)),
                ("name".to_string(), QueryParam::Text("Zed".to_string())),
                ("age".to_string(), QueryParam::Integer(99)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let id = storage.insert(insert_query, &auth).await.unwrap();
        assert_eq!(id, i64::MAX);
    }

    #[tokio::test]
    async fn test_update() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = test_auth();
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert a row
        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("Bob".to_string())),
                ("age".to_string(), QueryParam::Integer(25)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        storage.insert(insert_query, &auth).await.unwrap();

        // Update the row
        let update_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Update(vec![("age".to_string(), QueryParam::Integer(26))]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(1)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let updated = storage.update_or_delete(update_query, &auth).await.unwrap();
        assert_eq!(updated, 1);

        // Verify the update
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(1)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let result: Option<serde_json::Value> = storage.select_one(select_query).await.unwrap();
        let row = result.unwrap();
        assert_eq!(row["age"], 26);
    }

    #[tokio::test]
    async fn test_delete() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = test_auth();
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert a row
        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("Charlie".to_string())),
                ("age".to_string(), QueryParam::Integer(35)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        storage.insert(insert_query, &auth).await.unwrap();

        // Delete the row
        let delete_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Delete,
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(1)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let deleted = storage.update_or_delete(delete_query, &auth).await.unwrap();
        assert_eq!(deleted, 1);

        // Verify deletion
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(1)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let result: Option<serde_json::Value> = storage.select_one(select_query).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_select_all() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = test_auth();
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert multiple rows
        for i in 1..=3 {
            let insert_query = Query {
                table: "test_table".to_string(),
                operation: QueryOperation::Insert(vec![
                    ("name".to_string(), QueryParam::Text(format!("User{i}"))),
                    ("age".to_string(), QueryParam::Integer(20 + i)),
                ]),
                predicate: None,
                order: crate::query::Order::Asc,
                limit: None,
                join: None,
            };
            storage.insert(insert_query, &auth).await.unwrap();
        }

        // Select all rows
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let results: Vec<serde_json::Value> = storage.select_all(select_query).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn import_actions_rejects_duplicate_names() {
        use encrypted_spaces_acl_types::{Action, ActionLeg};
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let action = |name: &str, table: &str| Action {
            name: name.to_string(),
            legs: vec![ActionLeg::Insert {
                table: table.to_string(),
            }],
            asserts: vec![],
        };
        let err = storage
            .import_actions(&[action("send_message", "a"), action("send_message", "b")])
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("send_message") && msg.contains("more than once"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn import_actions_accepts_distinct_names() {
        use encrypted_spaces_acl_types::{Action, ActionLeg};
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let action = |name: &str| Action {
            name: name.to_string(),
            legs: vec![ActionLeg::Insert {
                table: "t".to_string(),
            }],
            asserts: vec![],
        };
        storage
            .import_actions(&[action("a"), action("b"), action("c")])
            .await
            .expect("distinct names should import");
    }

    #[tokio::test]
    async fn test_unbounded_id_range_stops_at_table_prefix() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = test_auth();
        let schema = test_schema();
        let mut other_schema = test_schema();
        other_schema.name = "zz_table".to_string();

        storage.create_table(&schema).await.unwrap();
        storage.create_table(&other_schema).await.unwrap();

        let insert_first_table = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("Alice".to_string())),
                ("age".to_string(), QueryParam::Integer(30)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_first_table, &auth).await.unwrap();

        let insert_second_table = Query {
            table: "zz_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("Mallory".to_string())),
                ("age".to_string(), QueryParam::Integer(40)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_second_table, &auth).await.unwrap();

        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::GreaterThan,
                values: vec![QueryParam::Integer(1)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let results = storage.query_rows(&select_query).unwrap();
        assert!(
            results.is_empty(),
            "id > 1 on test_table must not leak rows from later table prefixes: {results:?}"
        );
    }
}
