//! [`KvCache`] — anchored, splice-updated key/value cache for SDK queries.

use std::collections::{BTreeSet, HashMap};

use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_backend::merk_storage::keys::query_param_to_tuple_element;
use encrypted_spaces_backend::merk_storage::proofs::VerifiedRows;
use encrypted_spaces_backend::merk_storage::{
    determine_query_strategy, execute_query, group_columns_into_rows, index_ranges_for_predicate,
    parse_key, prefix_succ_required, process_query_results, reassemble_row, ParsedKey,
    QueryStrategy, RowReadSource, ID_FIELD,
};
use encrypted_spaces_backend::query::{Order, Predicate, Query, QueryParam};
use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_changelog_core::{prefix_successor, ReadOp};
use encrypted_spaces_storage_encoding::keys;

use super::coverage_store::CoverageStore;

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

/// Bundle of verified writes plus optional coverage extensions to apply
/// atomically with an anchor advance. Coverage extensions let a full-row
/// insert/update/delete claim the row's byte range so subsequent id-reads
/// hit without a server round-trip.
#[derive(Debug, Default, Clone)]
pub struct CacheUpdate {
    pub writes: Vec<CacheWrite>,
    pub coverage_extensions: Vec<(Vec<u8>, Vec<u8>)>,
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

    pub fn extend_coverage(&mut self, start: Vec<u8>, end: Vec<u8>) {
        self.coverage_extensions.push((start, end));
    }
}

/// Anchored client-side KV cache. See crate-level docs for the model.
pub struct KvCache {
    anchor: DataCommitment,
    storage: CoverageStore,
}

impl KvCache {
    pub fn new(anchor: DataCommitment) -> Self {
        Self {
            anchor,
            storage: CoverageStore::new(),
        }
    }

    #[cfg(test)]
    pub fn anchor(&self) -> &DataCommitment {
        &self.anchor
    }

    /// Drop all entries and re-anchor at `new_root`. Use after a reorg or any
    /// state transition the cache cannot splice.
    pub fn reanchor(&mut self, new_root: DataCommitment) {
        self.storage.clear();
        self.anchor = new_root;
    }

    /// Lower-level: insert raw `(key, value)` point entries and extend
    /// coverage by half-open `[start, end)` ranges. Caller is responsible for
    /// ensuring the inputs reflect state at the current anchor — used by
    /// SDK code paths that bootstrap or seed the cache without a server
    /// proof (e.g. local-transport tests).
    pub fn splice(
        &mut self,
        kv_pairs: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
        coverage_ranges: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) {
        for (k, v) in kv_pairs {
            self.storage.put_point(k, Some(v));
        }
        for (s, e) in coverage_ranges {
            self.storage.extend_coverage(s, e);
        }
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
        for (start, end) in update.coverage_extensions {
            self.storage.extend_coverage(start, end);
        }
        self.anchor = new_root;
    }

    /// Ingest a verified server SELECT into the cache: each `(key, value)`
    /// becomes a point entry, every `ReadOp` extends coverage (or records an
    /// authenticated absence for single-key reads).
    ///
    /// `expected_anchor` is the data commitment the proof was verified
    /// against. If the cache anchor has advanced since then (e.g. a
    /// broadcast applied during the await), the splice is dropped — we
    /// must never land data verified at an old root under a newer anchor.
    /// Returns `true` if the splice was applied.
    pub fn apply_select(
        &mut self,
        expected_anchor: DataCommitment,
        verified: &VerifiedRows,
    ) -> bool {
        if self.anchor != expected_anchor {
            return false;
        }
        for (k, v) in &verified.kv_pairs {
            self.storage.put_point(k.clone(), Some(v.clone()));
        }

        let present: std::collections::HashSet<&[u8]> = verified
            .kv_pairs
            .iter()
            .map(|(k, _)| k.as_slice())
            .collect();

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
        true
    }

    /// Try to answer `query` from the cache. Returns `Hit(rows)` if every
    /// byte range the planned query would touch is fully covered; `Miss`
    /// otherwise.
    ///
    /// The cache is schema-agnostic: non-id predicates always plan as
    /// `ByIndex` and resolve to `Miss`, so the eventual server fetch is the
    /// one that validates whether the referenced column is actually indexed.
    pub fn try_select(
        &self,
        query: &Query,
        schemas: &HashMap<String, Schema>,
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        let reader = KvCacheReader {
            storage: &self.storage,
        };

        // Predicate-on-non-indexed-non-id-column would mis-plan as ByIndex
        // (our reader's validate_column_indexed is schema-agnostic). Catch
        // it here: route to the full-table fallback or Miss.
        if let Some(pred) = &query.predicate {
            if pred.column != ID_FIELD
                && !schemas
                    .get(&query.table)
                    .is_some_and(|s| s.indexed_columns().contains(&pred.column.as_str()))
            {
                return self.full_table_fallback(query);
            }
        }

        let strategy = determine_query_strategy(&reader, query)?;

        // ByIndex needs a two-phase coverage check: first the index range,
        // then scan the index to find matching row ids and confirm each
        // row range is also covered.
        if let QueryStrategy::ByIndex { predicate } = &strategy {
            match self.indexed_predicate_coverage(&query.table, predicate)? {
                IndexedCoverage::Covered => {
                    let rows = execute_query(&reader, query)?;
                    return Ok(CacheResult::Hit(rows));
                }
                IndexedCoverage::Missing => {
                    // Bucket isn't cached; try whole-table fallback (Trevor's
                    // FullTableFallbackOptions equivalent).
                    return self.full_table_fallback(query);
                }
            }
        }

        let required = required_ranges_for_strategy(&strategy, &query.table)?;
        if required
            .iter()
            .all(|(s, e)| self.storage.covers_range(s, e))
        {
            let rows = execute_query(&reader, query)?;
            return Ok(CacheResult::Hit(rows));
        }

        // Partial coverage + LIMIT: if the first L rows of the requested
        // scan order fit inside a covered prefix (Asc) or suffix (Desc),
        // we can answer the query without needing the rest of the range.
        if let Some(limit) = query.limit {
            if let Some(rows) = self.try_select_with_limit_partial(query, &required, limit)? {
                return Ok(CacheResult::Hit(rows));
            }
        }
        Ok(CacheResult::Miss)
    }

    /// Whole-table fallback. If the cache has full coverage of the table's
    /// row-key range, scan every row, filter client-side by the query's
    /// predicate, and apply order/cursor/limit/projection. Matches Trevor's
    /// `FullTableFallbackOptions` path.
    fn full_table_fallback(&self, query: &Query) -> Result<CacheResult<Vec<serde_json::Value>>> {
        let start = keys::row_prefix(&query.table);
        let end = prefix_succ_required(&start)?;
        if !self.storage.covers_range(&start, &end) {
            return Ok(CacheResult::Miss);
        }
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .storage
            .iter_range_present(&start, &end)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let rows = group_columns_into_rows(&entries)?;
        let matching: Vec<serde_json::Value> = match &query.predicate {
            Some(pred) => rows
                .into_iter()
                .filter(|row| crate::table::row_matches_predicate(row, pred))
                .collect(),
            None => rows,
        };
        let limited = process_query_results(matching, query)?;
        Ok(CacheResult::Hit(limited))
    }

    /// Limit-aware partial-coverage path. Reads the covered prefix/suffix
    /// of the single contiguous range a non-`ByIndex` strategy would touch,
    /// applies the query's order/cursor/limit, and returns `Some(rows)` if
    /// either:
    /// - we collected at least `limit` rows (the rest is hidden by limit
    ///   regardless of whether the rest of the range is covered), or
    /// - we walked the entire requested range (so the cache has the truth
    ///   even though we got fewer than `limit` rows).
    ///
    /// Returns `None` (Miss) when partial coverage + the available rows
    /// can't decide the question.
    fn try_select_with_limit_partial(
        &self,
        query: &Query,
        required: &[KeyRange],
        limit: u32,
    ) -> Result<Option<Vec<serde_json::Value>>> {
        if limit == 0 {
            return Ok(Some(Vec::new()));
        }
        // Only single-range strategies support this; ByIds with N ids has N
        // disjoint ranges and isn't a meaningful "scan with limit".
        if required.len() != 1 {
            return Ok(None);
        }
        let (start, end) = (&required[0].0, &required[0].1);

        let (effective_start, effective_end, walks_to_full_range) = match query.order {
            Order::Asc => {
                let eff_end = self.storage.covered_prefix_end(start, end);
                let complete = eff_end.as_slice() == end.as_slice();
                (start.clone(), eff_end, complete)
            }
            Order::Desc => {
                let eff_start = self.storage.covered_suffix_start(start, end);
                let complete = eff_start.as_slice() == start.as_slice();
                (eff_start, end.clone(), complete)
            }
        };

        if effective_start >= effective_end {
            return Ok(None);
        }

        let entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .storage
            .iter_range_present(&effective_start, &effective_end)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let rows = group_columns_into_rows(&entries)?;
        let limited = process_query_results(rows, query)?;

        if (limited.len() as u32) >= limit || walks_to_full_range {
            Ok(Some(limited))
        } else {
            Ok(None)
        }
    }

    /// Coverage check for `ByIndex` predicates. Computes the index byte
    /// range the operator scans, requires it covered, enumerates matching
    /// row ids from the cached index entries, and confirms each row range
    /// is also covered.
    fn indexed_predicate_coverage(
        &self,
        table: &str,
        predicate: &Predicate,
    ) -> Result<IndexedCoverage> {
        let index_ranges = index_ranges_for_predicate(table, predicate)?;
        let mut row_ids: BTreeSet<i64> = BTreeSet::new();
        for (start, end) in &index_ranges {
            if !self.storage.covers_range(start, end) {
                return Ok(IndexedCoverage::Missing);
            }
            for (key, _) in self.storage.iter_range_present(start, end) {
                if let Ok(ParsedKey::Index { row_id, .. }) = parse_key(key) {
                    row_ids.insert(row_id);
                }
            }
        }

        for row_id in &row_ids {
            let row_key = keys::row_key(table, *row_id);
            let row_end = prefix_succ_required(&row_key)?;
            if !self.storage.covers_range(&row_key, &row_end) {
                return Ok(IndexedCoverage::Missing);
            }
        }

        Ok(IndexedCoverage::Covered)
    }

    /// Look up joined-table rows for one or more FK values. Dispatches on
    /// `pk_col`:
    ///
    /// - `pk_col == "id"` — PK join. Each FK must be an integer; each
    ///   matching row's range must be fully covered.
    /// - `pk_col` is indexed on the joined table — indexed-column join.
    ///   For each FK, both the index value range and every matching row's
    ///   range must be fully covered.
    /// - Otherwise — `Miss` (the SDK will fetch from the server, which is
    ///   also the only path the cache could be wrong).
    pub fn lookup_joined_rows(
        &self,
        joined_table: &str,
        pk_col: &str,
        fk_values: &[serde_json::Value],
        schemas: &HashMap<String, Schema>,
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        if fk_values.is_empty() {
            return Ok(CacheResult::Hit(Vec::new()));
        }

        if pk_col == ID_FIELD {
            let mut ids: Vec<i64> = Vec::with_capacity(fk_values.len());
            for v in fk_values {
                let Some(id) = v.as_i64() else {
                    return Ok(CacheResult::Miss);
                };
                ids.push(id);
            }
            return self.lookup_joined_rows_by_id(joined_table, &ids);
        }

        let Some(schema) = schemas.get(joined_table) else {
            return Ok(CacheResult::Miss);
        };
        if !schema.indexed_columns().contains(&pk_col) {
            return Ok(CacheResult::Miss);
        }

        let mut rows: Vec<serde_json::Value> = Vec::new();
        let mut seen_ids: BTreeSet<i64> = BTreeSet::new();
        for fk in fk_values {
            match self.lookup_indexed_join_value(joined_table, pk_col, fk, &mut seen_ids)? {
                CacheResult::Hit(more) => rows.extend(more),
                CacheResult::Miss => return Ok(CacheResult::Miss),
            }
        }
        Ok(CacheResult::Hit(rows))
    }

    fn lookup_joined_rows_by_id(
        &self,
        joined_table: &str,
        fk_values: &[i64],
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        let reader = KvCacheReader {
            storage: &self.storage,
        };
        let mut rows = Vec::with_capacity(fk_values.len());
        for &fk in fk_values {
            let start = keys::row_key(joined_table, fk);
            let end = prefix_succ_required(&start)?;
            if !self.storage.covers_range(&start, &end) {
                return Ok(CacheResult::Miss);
            }
            if let Some(row) = reader.get_row_by_id(joined_table, fk)? {
                rows.push(row);
            }
        }
        Ok(CacheResult::Hit(rows))
    }

    /// Resolve a single indexed-column FK value: check coverage of the
    /// index range, then enumerate matching row_ids and read each row
    /// (with its own coverage check). Dedupes against `seen_ids` so a row
    /// matching multiple FK values isn't emitted twice.
    fn lookup_indexed_join_value(
        &self,
        joined_table: &str,
        pk_col: &str,
        fk: &serde_json::Value,
        seen_ids: &mut BTreeSet<i64>,
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        let param = QueryParam::from(fk.clone());
        let tuple_element = query_param_to_tuple_element(&param);
        let index_prefix = keys::index_value_prefix(joined_table, pk_col, tuple_element)
            .map_err(|e| SdkError::InvalidQuery(format!("Invalid index value: {e}")))?;
        let index_end = prefix_succ_required(&index_prefix)?;
        if !self.storage.covers_range(&index_prefix, &index_end) {
            return Ok(CacheResult::Miss);
        }

        // Collect matching row ids from the cached index entries.
        let matching_ids: Vec<i64> = self
            .storage
            .iter_prefix_present(&index_prefix)
            .filter_map(|(key, _)| match parse_key(key).ok()? {
                ParsedKey::Index { row_id, .. } => Some(row_id),
                _ => None,
            })
            .collect();

        let reader = KvCacheReader {
            storage: &self.storage,
        };
        let mut rows = Vec::with_capacity(matching_ids.len());
        for row_id in matching_ids {
            if !seen_ids.insert(row_id) {
                continue;
            }
            let row_key = keys::row_key(joined_table, row_id);
            let row_end = prefix_succ_required(&row_key)?;
            if !self.storage.covers_range(&row_key, &row_end) {
                return Ok(CacheResult::Miss);
            }
            if let Some(row) = reader.get_row_by_id(joined_table, row_id)? {
                rows.push(row);
            }
        }
        Ok(CacheResult::Hit(rows))
    }
}

/// Borrowed `RowReadSource` over a `CoverageStore`. The cache delegates
/// schema validation (which column is indexed) to the eventual server fetch
/// triggered on `Miss`, so this reader has no schema state.
struct KvCacheReader<'a> {
    storage: &'a CoverageStore,
}

enum IndexedCoverage {
    Covered,
    Missing,
}

type KeyRange = (Vec<u8>, Vec<u8>);

/// Byte ranges a non-`ByIndex` strategy reads from the row-key space.
/// `ByIndex` predicates are handled separately via
/// [`KvCache::indexed_predicate_coverage`].
fn required_ranges_for_strategy(strategy: &QueryStrategy, table: &str) -> Result<Vec<KeyRange>> {
    match strategy {
        QueryStrategy::ById(id) => {
            let start = keys::row_key(table, *id);
            let end = prefix_succ_required(&start)?;
            Ok(vec![(start, end)])
        }
        QueryStrategy::ByIds(ids) => {
            let mut ranges = Vec::with_capacity(ids.len());
            for id in ids {
                let start = keys::row_key(table, *id);
                let end = prefix_succ_required(&start)?;
                ranges.push((start, end));
            }
            Ok(ranges)
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
            Ok(vec![(start_key, end_key)])
        }
        QueryStrategy::TableScan => {
            let start = keys::row_prefix(table);
            let end = prefix_succ_required(&start)?;
            Ok(vec![(start, end)])
        }
        QueryStrategy::ByIndex { .. } => Ok(Vec::new()),
    }
}

impl<'a> RowReadSource for KvCacheReader<'a> {
    fn validate_column_indexed(&self, _table_name: &str, _column: &str) -> Result<()> {
        // Schema-agnostic: planner returns `ByIndex` for any non-id predicate
        // and `try_select` will then return `Miss`, so the server-side fetch
        // is what actually validates indexedness. Saying Ok here keeps the
        // planner from spuriously erroring before we get to the Miss step.
        Ok(())
    }

    fn get_row_by_id(&self, table_name: &str, row_id: i64) -> Result<Option<serde_json::Value>> {
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
        table_name: &str,
        predicate: &Predicate,
    ) -> Result<Vec<Vec<u8>>> {
        // `try_select`'s indexed_predicate_coverage already enforced
        // coverage of these ranges, so iter_range_present here is reading
        // an authoritative window.
        let ranges = index_ranges_for_predicate(table_name, predicate)?;
        let mut row_keys = Vec::new();
        for (start, end) in ranges {
            for (key, _) in self
                .storage
                .iter_range_present(&start, &end)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
            {
                if let Ok(ParsedKey::Index { row_id, .. }) = parse_key(&key) {
                    row_keys.push(keys::row_key(table_name, row_id));
                }
            }
        }
        Ok(row_keys)
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
    use encrypted_spaces_backend::query::{ComparisonOperator, Order, QueryOperation, QueryParam};
    use encrypted_spaces_storage_encoding::stored_value;
    use std::collections::HashMap;

    const TABLE: &str = "msgs";

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
        let cache = KvCache::new([0; 32]);
        let result = cache
            .try_select(&select_all_query(TABLE), &HashMap::new())
            .unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn hit_after_full_table_ingest() {
        let mut cache = KvCache::new([0; 32]);
        let verified = full_table_verified(
            TABLE,
            &[
                (1, "text", serde_json::json!("hello")),
                (2, "text", serde_json::json!("world")),
            ],
        );
        cache.apply_select([0; 32], &verified);
        let result = cache
            .try_select(&select_all_query(TABLE), &HashMap::new())
            .unwrap();
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
        let mut cache = KvCache::new([0; 32]);
        let verified = full_table_verified(
            TABLE,
            &[
                (1, "text", serde_json::json!("hello")),
                (2, "text", serde_json::json!("world")),
            ],
        );
        cache.apply_select([0; 32], &verified);
        let result = cache
            .try_select(&select_by_id(TABLE, 2), &HashMap::new())
            .unwrap();
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
        let mut cache = KvCache::new([0; 32]);
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
        cache.apply_select([0; 32], &verified);
        let result = cache
            .try_select(&select_by_id(TABLE, 2), &HashMap::new())
            .unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn key_read_with_no_kv_pair_records_tombstone() {
        let mut cache = KvCache::new([0; 32]);
        let row_key = keys::row_key(TABLE, 7);
        let verified = VerifiedRows {
            main_rows: Vec::new(),
            rows_by_table: HashMap::new(),
            kv_pairs: Vec::new(),
            read_ops: vec![ReadOp::Key(row_key.clone())],
        };
        cache.apply_select([0; 32], &verified);
        assert_eq!(cache.storage.get_point(&row_key), Some(&None));
    }

    #[test]
    fn advance_anchor_splices_writes_and_bumps_anchor() {
        let mut cache = KvCache::new([0; 32]);
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
    fn apply_select_drops_splice_when_anchor_advanced() {
        // Regression: a SELECT awaits the network, a broadcast lands during
        // the await and advances the cache anchor. Splicing the stale proof
        // would land old-root data under the new anchor.
        let mut cache = KvCache::new([1; 32]);
        let verified = full_table_verified(TABLE, &[(1, "text", serde_json::json!("hi"))]);
        // Pretend the broadcast already advanced the anchor.
        cache.advance_anchor([2; 32], CacheUpdate::new());
        // Splicing with the original commitment must report "not applied".
        let applied = cache.apply_select([1; 32], &verified);
        assert!(!applied, "splice must drop when anchor has advanced");
        let result = cache
            .try_select(&select_all_query(TABLE), &HashMap::new())
            .unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn reanchor_clears_storage() {
        let mut cache = KvCache::new([1; 32]);
        let verified = full_table_verified(TABLE, &[(1, "text", serde_json::json!("x"))]);
        assert!(cache.apply_select([1; 32], &verified));
        cache.reanchor([2; 32]);
        assert_eq!(cache.anchor(), &[2; 32]);
        let result = cache
            .try_select(&select_all_query(TABLE), &HashMap::new())
            .unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn indexed_predicate_returns_miss() {
        let cache = KvCache::new([0; 32]);
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
        let result = cache.try_select(&q, &HashMap::new()).unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    fn schema_with_columns(table: &str, columns: Vec<(&str, bool, bool)>) -> Schema {
        use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType};
        Schema {
            name: table.to_string(),
            columns: columns
                .into_iter()
                .map(|(name, plaintext, indexed)| ColumnDefinition {
                    name: name.to_string(),
                    column_type: ColumnType::Integer,
                    plaintext,
                    indexed,
                })
                .collect(),
            auto_increment: true,
        }
    }

    #[test]
    fn full_table_fallback_filters_non_indexed_predicate_when_table_covered() {
        // Schema: id (plaintext, not indexed), value (plaintext, NOT indexed).
        let schema = schema_with_columns(TABLE, vec![("id", true, false), ("value", true, false)]);
        let mut schemas = HashMap::new();
        schemas.insert(TABLE.to_string(), schema);

        let mut cache = KvCache::new([0; 32]);
        let verified = full_table_verified(
            TABLE,
            &[
                (1, "value", serde_json::json!(10)),
                (2, "value", serde_json::json!(20)),
                (3, "value", serde_json::json!(20)),
            ],
        );
        cache.apply_select([0; 32], &verified);

        // WHERE value = 20 — non-indexed predicate, full table covered.
        // Fallback scans + filters client-side.
        let q = Query {
            table: TABLE.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: Some(Predicate {
                column: "value".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(20)],
                cursor_id: None,
            }),
            join: None,
            order: Order::Asc,
            limit: None,
        };
        let result = cache.try_select(&q, &schemas).unwrap();
        match result {
            CacheResult::Hit(rows) => {
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0].get("id").and_then(|v| v.as_i64()), Some(2));
                assert_eq!(rows[1].get("id").and_then(|v| v.as_i64()), Some(3));
            }
            CacheResult::Miss => panic!("expected Hit via full-table fallback"),
        }
    }

    #[test]
    fn full_table_fallback_misses_when_table_not_covered() {
        let schema = schema_with_columns(TABLE, vec![("id", true, false), ("value", true, false)]);
        let mut schemas = HashMap::new();
        schemas.insert(TABLE.to_string(), schema);

        let cache = KvCache::new([0; 32]); // empty
        let q = Query {
            table: TABLE.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: Some(Predicate {
                column: "value".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(20)],
                cursor_id: None,
            }),
            join: None,
            order: Order::Asc,
            limit: None,
        };
        let result = cache.try_select(&q, &schemas).unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn write_splice_with_coverage_extension_makes_id_read_hit() {
        // Hand-built CacheUpdate that puts a row's column value AND
        // extends coverage of the row range (what cache_update_from_writes
        // emits for a full-row insert). Subsequent id-read must hit.
        let schema = schema_with_columns(TABLE, vec![("id", true, false), ("text", true, false)]);
        let mut schemas = HashMap::new();
        schemas.insert(TABLE.to_string(), schema);

        let mut cache = KvCache::new([0; 32]);

        let mut update = CacheUpdate::new();
        let (key, value) = col_kv(TABLE, 7, "text", serde_json::json!("spliced"));
        update.put(key, value);
        let row_key = keys::row_key(TABLE, 7);
        let row_end = prefix_successor(&row_key).unwrap();
        update.extend_coverage(row_key, row_end);
        cache.advance_anchor([1; 32], update);

        let result = cache.try_select(&select_by_id(TABLE, 7), &schemas).unwrap();
        match result {
            CacheResult::Hit(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].get("id").and_then(|v| v.as_i64()), Some(7));
                assert_eq!(
                    rows[0].get("text").and_then(|v| v.as_str()),
                    Some("spliced")
                );
            }
            CacheResult::Miss => panic!("expected Hit after coverage-extending splice"),
        }
    }

    #[test]
    fn write_splice_without_coverage_extension_misses_id_read() {
        // Same setup but no coverage extension — what
        // cache_update_from_writes emits for a partial-column update.
        let schema = schema_with_columns(TABLE, vec![("id", true, false), ("text", true, false)]);
        let mut schemas = HashMap::new();
        schemas.insert(TABLE.to_string(), schema);

        let mut cache = KvCache::new([0; 32]);

        let mut update = CacheUpdate::new();
        let (key, value) = col_kv(TABLE, 7, "text", serde_json::json!("partial"));
        update.put(key, value);
        // (no extend_coverage call)
        cache.advance_anchor([1; 32], update);

        let result = cache.try_select(&select_by_id(TABLE, 7), &schemas).unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn limit_with_partial_prefix_coverage_asc_hits() {
        // Cache covers the table prefix through row 1. limit(1) Asc
        // satisfies inside the covered prefix even though rows >= 2 are
        // unknown.
        let mut cache = KvCache::new([0; 32]);
        let table_start = keys::row_prefix(TABLE);
        let row1_key = keys::row_key(TABLE, 1);
        let row1_end = prefix_successor(&row1_key).unwrap();
        let verified = VerifiedRows {
            main_rows: Vec::new(),
            rows_by_table: HashMap::new(),
            kv_pairs: vec![col_kv(TABLE, 1, "text", serde_json::json!("first"))],
            read_ops: vec![ReadOp::Range {
                start: table_start,
                end: row1_end,
            }],
        };
        cache.apply_select([0; 32], &verified);

        let q = Query {
            table: TABLE.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: None,
            join: None,
            order: Order::Asc,
            limit: Some(1),
        };
        let result = cache.try_select(&q, &HashMap::new()).unwrap();
        match result {
            CacheResult::Hit(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].get("id").and_then(|v| v.as_i64()), Some(1));
            }
            CacheResult::Miss => panic!("limit(1) should hit on covered prefix"),
        }
    }

    #[test]
    fn limit_with_insufficient_prefix_coverage_misses() {
        // Cache covers table prefix through row 1, but limit asks for 2.
        let mut cache = KvCache::new([0; 32]);
        let table_start = keys::row_prefix(TABLE);
        let row1_key = keys::row_key(TABLE, 1);
        let row1_end = prefix_successor(&row1_key).unwrap();
        let verified = VerifiedRows {
            main_rows: Vec::new(),
            rows_by_table: HashMap::new(),
            kv_pairs: vec![col_kv(TABLE, 1, "text", serde_json::json!("first"))],
            read_ops: vec![ReadOp::Range {
                start: table_start,
                end: row1_end,
            }],
        };
        cache.apply_select([0; 32], &verified);

        let q = Query {
            table: TABLE.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: None,
            join: None,
            order: Order::Asc,
            limit: Some(2),
        };
        let result = cache.try_select(&q, &HashMap::new()).unwrap();
        assert!(
            matches!(result, CacheResult::Miss),
            "limit(2) should miss when only 1 row covered"
        );
    }
}
