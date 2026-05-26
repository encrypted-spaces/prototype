//! [`KvCache`] — anchored, splice-updated key/value cache for SDK queries.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_backend::merk_storage::proofs::VerifiedRows;
use encrypted_spaces_backend::merk_storage::{
    determine_query_strategy, execute_query, group_columns_into_rows, reassemble_row,
    QueryStrategy, RowReadSource,
};
use encrypted_spaces_backend::query::{Predicate, Query};
use encrypted_spaces_changelog_core::{prefix_successor, ReadOp};
use encrypted_spaces_storage_encoding::keys;

use crate::coverage_store::CoverageStore;

/// The state-commitment digest the cache is anchored to.
pub type DataCommitment = [u8; 32];

/// Hit-or-miss outcome of [`KvCache::try_select`].
#[derive(Debug, Clone)]
pub enum CacheResult<T> {
    Hit(T),
    /// Cache cannot answer this query — caller must fetch from server.
    Miss,
}

/// A single verified write to splice into the cache.
#[derive(Debug, Clone)]
pub enum CacheWrite {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

/// Bundle of verified writes to apply atomically with an anchor advance.
#[derive(Debug, Default, Clone)]
pub struct CacheUpdate {
    pub writes: Vec<CacheWrite>,
}

impl CacheUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.writes.push(CacheWrite::Put(key, value));
    }

    pub fn delete(&mut self, key: Vec<u8>) {
        self.writes.push(CacheWrite::Delete(key));
    }
}

/// Per-table set of indexed columns, used to validate non-id predicates while
/// planning a query. Maps `table_name -> set of indexed column names`.
pub type IndexedColumnsByTable = HashMap<String, BTreeSet<String>>;

/// Anchored client-side KV cache. See crate-level docs for the model.
pub struct KvCache {
    anchor: DataCommitment,
    storage: CoverageStore,
    indexed_columns: Arc<IndexedColumnsByTable>,
}

impl KvCache {
    pub fn new(anchor: DataCommitment, indexed_columns: Arc<IndexedColumnsByTable>) -> Self {
        Self {
            anchor,
            storage: CoverageStore::new(),
            indexed_columns,
        }
    }

    pub fn anchor(&self) -> &DataCommitment {
        &self.anchor
    }

    /// Drop all entries and re-anchor at `new_root`. Use after a reorg or any
    /// state transition the cache cannot splice.
    pub fn reanchor(&mut self, new_root: DataCommitment) {
        self.storage.clear();
        self.anchor = new_root;
    }

    /// Splice `update`'s writes into the cache and advance the anchor in one
    /// step. Atomic at the Rust-struct level — readers never observe an
    /// anchor that doesn't match the storage.
    pub fn advance_anchor(&mut self, new_root: DataCommitment, update: CacheUpdate) {
        for w in update.writes {
            match w {
                CacheWrite::Put(k, v) => self.storage.put_point(k, Some(v)),
                CacheWrite::Delete(k) => self.storage.put_point(k, None),
            }
        }
        self.anchor = new_root;
    }

    /// Ingest a verified server SELECT into the cache: each `(key, value)`
    /// becomes a point entry, every `ReadOp` extends coverage (or records an
    /// authenticated absence for single-key reads).
    pub fn apply_select(&mut self, verified: &VerifiedRows) {
        for (k, v) in &verified.kv_pairs {
            self.storage.put_point(k.clone(), Some(v.clone()));
        }

        let present: std::collections::HashSet<&[u8]> =
            verified.kv_pairs.iter().map(|(k, _)| k.as_slice()).collect();

        for op in &verified.read_ops {
            match op {
                ReadOp::Prefix(p) => {
                    if let Some(end) = prefix_successor(p) {
                        self.storage.extend_coverage(p.clone(), end);
                    }
                }
                ReadOp::Range { start, end } => {
                    self.storage.extend_coverage(start.clone(), end.clone());
                }
                ReadOp::Key(k) => {
                    if !present.contains(k.as_slice()) {
                        self.storage.put_point(k.clone(), None);
                    }
                }
            }
        }
    }

    /// Try to answer `query` from the cache. Returns `Hit(rows)` if every
    /// byte range the planned query would touch is fully covered; `Miss`
    /// otherwise.
    pub fn try_select(
        &self,
        query: &Query,
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        let strategy = determine_query_strategy(self, query)?;
        let required = match required_ranges_for_strategy(&strategy, &query.table)? {
            Some(r) => r,
            // ByIndex (and any other shape we don't model here) falls through
            // to the server — narrowly scoped first cut.
            None => return Ok(CacheResult::Miss),
        };
        if !required
            .iter()
            .all(|(s, e)| self.storage.covers_range(s, e))
        {
            return Ok(CacheResult::Miss);
        }
        let rows = execute_query(self, query)?;
        Ok(CacheResult::Hit(rows))
    }
}

type KeyRange = (Vec<u8>, Vec<u8>);

/// Byte ranges that a given strategy reads from the row-key space. Returns
/// `None` for strategies the cache cannot bound up-front (currently `ByIndex`).
fn required_ranges_for_strategy(
    strategy: &QueryStrategy,
    table: &str,
) -> Result<Option<Vec<KeyRange>>> {
    match strategy {
        QueryStrategy::ById(id) => {
            let start = keys::row_key(table, *id);
            let end = prefix_succ_required(&start)?;
            Ok(Some(vec![(start, end)]))
        }
        QueryStrategy::ByIds(ids) => {
            let mut ranges = Vec::with_capacity(ids.len());
            for id in ids {
                let start = keys::row_key(table, *id);
                let end = prefix_succ_required(&start)?;
                ranges.push((start, end));
            }
            Ok(Some(ranges))
        }
        QueryStrategy::ByIdRange {
            start,
            end,
            inclusive_start,
            inclusive_end,
        } => {
            let start_key = match start {
                Some(id) if *inclusive_start => keys::row_key(table, *id),
                Some(id) => prefix_succ_required(&keys::row_key(table, *id))?,
                None => keys::row_prefix(table),
            };
            let end_key = match end {
                Some(id) if *inclusive_end => prefix_succ_required(&keys::row_key(table, *id))?,
                Some(id) => keys::row_key(table, *id),
                None => prefix_succ_required(&keys::row_prefix(table))?,
            };
            Ok(Some(vec![(start_key, end_key)]))
        }
        QueryStrategy::TableScan => {
            let start = keys::row_prefix(table);
            let end = prefix_succ_required(&start)?;
            Ok(Some(vec![(start, end)]))
        }
        QueryStrategy::ByIndex { .. } => Ok(None),
    }
}

fn prefix_succ_required(prefix: &[u8]) -> Result<Vec<u8>> {
    prefix_successor(prefix).ok_or_else(|| {
        SdkError::DatabaseError(format!(
            "no lexicographic successor for prefix {prefix:02x?}"
        ))
    })
}

impl RowReadSource for KvCache {
    fn validate_column_indexed(&self, table_name: &str, column: &str) -> Result<()> {
        let ok = self
            .indexed_columns
            .get(table_name)
            .is_some_and(|cols| cols.contains(column));
        if ok {
            Ok(())
        } else {
            Err(SdkError::InvalidQuery(format!(
                "Predicate column '{column}' is not indexed on table '{table_name}'"
            )))
        }
    }

    fn get_row_by_id(
        &self,
        table_name: &str,
        row_id: i64,
    ) -> Result<Option<serde_json::Value>> {
        let prefix = keys::row_key(table_name, row_id);
        let columns: Vec<(Vec<u8>, Vec<u8>)> = self
            .storage
            .iter_prefix_present(&prefix)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if columns.is_empty() {
            return Ok(None);
        }
        reassemble_row(row_id, &columns).map(Some)
    }

    fn query_rows_by_id_range(
        &self,
        table_name: &str,
        start: Option<i64>,
        end: Option<i64>,
        inclusive_start: bool,
        inclusive_end: bool,
    ) -> Result<Vec<serde_json::Value>> {
        let start_key = match start {
            Some(id) if inclusive_start => keys::row_key(table_name, id),
            Some(id) => prefix_succ_required(&keys::row_key(table_name, id))?,
            None => keys::row_prefix(table_name),
        };
        let end_key = match end {
            Some(id) if inclusive_end => prefix_succ_required(&keys::row_key(table_name, id))?,
            Some(id) => keys::row_key(table_name, id),
            None => prefix_succ_required(&keys::row_prefix(table_name))?,
        };
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .storage
            .iter_range_present(&start_key, &end_key)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        group_columns_into_rows(&entries)
    }

    fn index_row_keys_for_predicate(
        &self,
        _table_name: &str,
        _predicate: &Predicate,
    ) -> Result<Vec<Vec<u8>>> {
        // ByIndex is currently routed to Miss by `try_select`, so this is
        // unreachable on the hit path. If `execute_query` ever reaches this,
        // the planner has diverged from `try_select`; fail loudly.
        Err(SdkError::DatabaseError(
            "KvCache::index_row_keys_for_predicate called but try_select \
             rejects indexed predicates"
                .into(),
        ))
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .storage
            .iter_prefix_present(prefix)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn scan_table(&self, table_name: &str) -> Result<Vec<serde_json::Value>> {
        let prefix = keys::row_prefix(table_name);
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .storage
            .iter_prefix_present(&prefix)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        group_columns_into_rows(&entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::query::{
        ComparisonOperator, Order, QueryOperation, QueryParam,
    };
    use encrypted_spaces_storage_encoding::stored_value;

    const TABLE: &str = "msgs";

    fn empty_indexed() -> Arc<IndexedColumnsByTable> {
        Arc::new(HashMap::new())
    }

    fn col_kv(table: &str, id: i64, col: &str, value: serde_json::Value) -> (Vec<u8>, Vec<u8>) {
        let key = keys::column_key(table, id, col);
        let val = stored_value::value_to_bytes(&value).unwrap();
        (key, val)
    }

    fn select_all_query(table: &str) -> Query {
        Query {
            table: table.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: None,
            join: None,
            order: Order::Asc,
            limit: None,
        }
    }

    fn select_by_id(table: &str, id: i64) -> Query {
        Query {
            table: table.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(id)],
                cursor_id: None,
            }),
            join: None,
            order: Order::Asc,
            limit: None,
        }
    }

    fn full_table_verified(table: &str, rows: &[(i64, &str, serde_json::Value)]) -> VerifiedRows {
        let mut kv_pairs: Vec<(Vec<u8>, Vec<u8>)> = rows
            .iter()
            .map(|(id, col, val)| col_kv(table, *id, col, val.clone()))
            .collect();
        kv_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let start = keys::row_prefix(table);
        let end = prefix_successor(&start).unwrap();
        VerifiedRows {
            main_rows: Vec::new(),
            rows_by_table: HashMap::new(),
            kv_pairs,
            read_ops: vec![ReadOp::Range { start, end }],
        }
    }

    #[test]
    fn miss_when_empty() {
        let cache = KvCache::new([0; 32], empty_indexed());
        let result = cache.try_select(&select_all_query(TABLE)).unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn hit_after_full_table_ingest() {
        let mut cache = KvCache::new([0; 32], empty_indexed());
        let verified = full_table_verified(
            TABLE,
            &[
                (1, "text", serde_json::json!("hello")),
                (2, "text", serde_json::json!("world")),
            ],
        );
        cache.apply_select(&verified);
        let result = cache.try_select(&select_all_query(TABLE)).unwrap();
        match result {
            CacheResult::Hit(rows) => {
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0].get("id").and_then(|v| v.as_i64()), Some(1));
                assert_eq!(rows[1].get("id").and_then(|v| v.as_i64()), Some(2));
            }
            CacheResult::Miss => panic!("expected Hit"),
        }
    }

    #[test]
    fn hit_by_id_after_full_table_ingest() {
        let mut cache = KvCache::new([0; 32], empty_indexed());
        let verified = full_table_verified(
            TABLE,
            &[
                (1, "text", serde_json::json!("hello")),
                (2, "text", serde_json::json!("world")),
            ],
        );
        cache.apply_select(&verified);
        let result = cache.try_select(&select_by_id(TABLE, 2)).unwrap();
        match result {
            CacheResult::Hit(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].get("id").and_then(|v| v.as_i64()), Some(2));
                assert_eq!(rows[0].get("text").and_then(|v| v.as_str()), Some("world"));
            }
            CacheResult::Miss => panic!("expected Hit"),
        }
    }

    #[test]
    fn miss_by_id_when_only_neighbor_covered() {
        let mut cache = KvCache::new([0; 32], empty_indexed());
        // Coverage only over row 1.
        let row1_key = keys::row_key(TABLE, 1);
        let row1_end = prefix_successor(&row1_key).unwrap();
        let verified = VerifiedRows {
            main_rows: Vec::new(),
            rows_by_table: HashMap::new(),
            kv_pairs: vec![col_kv(TABLE, 1, "text", serde_json::json!("hi"))],
            read_ops: vec![ReadOp::Range {
                start: row1_key,
                end: row1_end,
            }],
        };
        cache.apply_select(&verified);
        let result = cache.try_select(&select_by_id(TABLE, 2)).unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn key_read_with_no_kv_pair_records_tombstone() {
        let mut cache = KvCache::new([0; 32], empty_indexed());
        let row_key = keys::row_key(TABLE, 7);
        let verified = VerifiedRows {
            main_rows: Vec::new(),
            rows_by_table: HashMap::new(),
            kv_pairs: Vec::new(),
            read_ops: vec![ReadOp::Key(row_key.clone())],
        };
        cache.apply_select(&verified);
        assert_eq!(cache.storage.get_point(&row_key), Some(&None));
    }

    #[test]
    fn advance_anchor_splices_writes_and_bumps_anchor() {
        let mut cache = KvCache::new([0; 32], empty_indexed());
        let mut update = CacheUpdate::new();
        let (k, v) = col_kv(TABLE, 5, "text", serde_json::json!("spliced"));
        update.put(k.clone(), v.clone());
        update.delete(keys::row_key(TABLE, 6));
        cache.advance_anchor([7; 32], update);
        assert_eq!(cache.anchor(), &[7; 32]);
        assert_eq!(cache.storage.get_point(&k), Some(&Some(v)));
        assert_eq!(
            cache.storage.get_point(&keys::row_key(TABLE, 6)),
            Some(&None)
        );
    }

    #[test]
    fn reanchor_clears_storage() {
        let mut cache = KvCache::new([1; 32], empty_indexed());
        let verified = full_table_verified(TABLE, &[(1, "text", serde_json::json!("x"))]);
        cache.apply_select(&verified);
        cache.reanchor([2; 32]);
        assert_eq!(cache.anchor(), &[2; 32]);
        let result = cache.try_select(&select_all_query(TABLE)).unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn indexed_predicate_returns_miss() {
        let mut cols = HashMap::new();
        cols.insert(TABLE.to_string(), BTreeSet::from(["channel_id".to_string()]));
        let cache = KvCache::new([0; 32], Arc::new(cols));
        let q = Query {
            table: TABLE.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: Some(Predicate {
                column: "channel_id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(5)],
                cursor_id: None,
            }),
            join: None,
            order: Order::Asc,
            limit: None,
        };
        let result = cache.try_select(&q).unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }
}
