use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Instant;

use encrypted_spaces_backend::internal_schemas::{KEY_HISTORY_TABLE_NAME, USERS_TABLE_NAME};
use encrypted_spaces_backend::merk_storage::{
    group_columns_into_rows_by_table_resolving_hashes, parse_key, ParsedKey, ID_FIELD,
};
use encrypted_spaces_backend::query::{ComparisonOperator, Predicate, QueryParam};
use encrypted_spaces_backend::schema::{ColumnType, Schema};
use encrypted_spaces_changelog_core::changelog::Change;
use encrypted_spaces_changelog_core::BatchOp;

/// Extract cache-addressable predicates from an optional server-side predicate.
///
/// Returns `(indexed_predicates, id_lookups)`. Only integer equality predicates
/// participate in cache lookup; non-equality predicates are applied as filters
/// after rows are loaded.
pub fn extract_cache_predicates(predicate: Option<&Predicate>) -> (Vec<(String, i64)>, Vec<i64>) {
    let mut preds = Vec::new();
    let mut id_lookups = Vec::new();

    if let Some(pred) = predicate {
        if pred.operator != ComparisonOperator::Equal {
            return (preds, id_lookups);
        }
        if let Some(QueryParam::Integer(v)) = pred.values.first() {
            if pred.column == "id" {
                id_lookups.push(*v);
            } else {
                preds.push((pred.column.clone(), *v));
            }
        }
    }

    (preds, id_lookups)
}

/// Get the list of plaintext integer columns that should be indexed for a table.
pub fn indexed_columns_for_schema(schema: &Schema) -> Vec<String> {
    schema
        .columns
        .iter()
        .filter(|col| {
            col.plaintext && matches!(col.column_type, ColumnType::Integer) && col.name != "id"
        })
        .map(|col| col.name.clone())
        .collect()
}

/// Push-maintained client row cache with indexed completeness tracking.
///
/// The cache stores decrypted rows per table plus derived secondary indexes on
/// plaintext integer columns. It can only claim coverage in two cases:
/// - the whole table has been fetched (`is_complete`)
/// - a single indexed `column=value` bucket has been fetched (`complete_values`)
///
/// Queries outside those shapes miss conservatively and fall back to the
/// server. Broadcasts and changelog replay incrementally maintain resident rows
/// and indexes so cached regions stay current without TTLs.
pub struct Cache {
    pub(crate) tables: HashMap<String, TableCache>,
    config: CacheConfig,
}

pub struct TableCache {
    /// Canonical row store. Source of truth.
    pub(crate) rows: HashMap<i64, serde_json::Value>,
    /// BTreeMap indexes on plaintext integer columns.
    indexes: HashMap<String, ColumnIndex>,
    /// True when rows has every row in the table.
    is_complete: bool,
    /// For table-level LRU eviction.
    last_accessed: Instant,
}

/// Secondary index using BTreeMap<(value, row_id), ()>.
/// Mirrors server's tuple-key layout. Prefix scans via .range().
pub struct ColumnIndex {
    /// Key = (column_value, row_id). The key IS the index.
    entries: BTreeMap<(i64, i64), ()>,
    /// Values for which ALL matching rows were fetched from the server for this
    /// specific column. Only server fetches establish this completeness;
    /// broadcasts and local writes may only remove it.
    complete_values: HashSet<i64>,
}

pub struct CacheConfig {
    pub max_tables: usize,
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        let enabled = !std::env::var("CACHE_DISABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            max_tables: 64,
            enabled,
        }
    }
}

/// Tables that are exempt from LRU eviction.
const INTERNAL_TABLES: &[&str] = &[KEY_HISTORY_TABLE_NAME, USERS_TABLE_NAME];

impl Cache {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
            config: CacheConfig::default(),
        }
    }

    // --- Query ---

    /// Try to serve a query from cache.
    ///
    /// Returns `Some(rows)` on cache hit, `None` on miss.
    ///
    /// Hit conditions:
    /// 1. Table is complete → return all rows (caller applies filters)
    /// 2. Exactly one indexed integer equality predicate with a complete value
    ///    → BTreeMap prefix scan for that bucket
    /// 3. `WHERE id = X` or `WHERE id IN (...)` with no other cache predicates
    ///    → direct row store lookup
    /// 4. All other query shapes miss conservatively
    pub fn try_query(
        &mut self,
        table: &str,
        where_clauses: &[(String, i64)],
        id_lookups: &[i64],
    ) -> Option<Vec<serde_json::Value>> {
        if !self.config.enabled {
            return None;
        }
        let cache = self.tables.get_mut(table)?;
        cache.last_accessed = Instant::now();

        // 1. Table complete → return all rows
        if cache.is_complete {
            let mut rows: Vec<serde_json::Value> = cache.rows.values().cloned().collect();
            rows.sort_by_key(|r| r.get("id").and_then(|v| v.as_i64()).unwrap_or(0));
            log::debug!(
                "[cache] try_query table={} → HIT (complete table, {} rows)",
                table,
                rows.len()
            );
            return Some(rows);
        }

        // 2. Indexed predicate with complete value
        if where_clauses.len() == 1 {
            let (col, val) = &where_clauses[0];
            if let Some(index) = cache.indexes.get(col.as_str()) {
                if index.complete_values.contains(val) {
                    let mut rows = Vec::new();
                    for ((_, row_id), _) in index.entries.range((*val, i64::MIN)..=(*val, i64::MAX))
                    {
                        if let Some(row) = cache.rows.get(row_id) {
                            rows.push(row.clone());
                        }
                    }
                    rows.sort_by_key(|r| r.get("id").and_then(|v| v.as_i64()).unwrap_or(0));
                    log::debug!(
                        "[cache] try_query table={} WHERE {}={} → HIT (indexed, {} rows)",
                        table,
                        col,
                        val,
                        rows.len()
                    );
                    return Some(rows);
                } else {
                    log::debug!(
                        "[cache] try_query table={} WHERE {}={} → MISS (value not in complete_values, complete_values={:?})",
                        table,
                        col,
                        val,
                        index.complete_values
                    );
                }
            } else {
                log::debug!(
                    "[cache] try_query table={} WHERE {}={} → MISS (no index for column)",
                    table,
                    col,
                    val
                );
            }
        }

        // 3. Direct ID lookups
        if !id_lookups.is_empty() && where_clauses.is_empty() {
            let mut rows = Vec::new();
            for id in id_lookups {
                if let Some(row) = cache.rows.get(id) {
                    rows.push(row.clone());
                }
                // If ID not found in partial cache, we can't serve this
                else {
                    log::debug!(
                        "[cache] try_query table={} id={} → MISS (id not found)",
                        table,
                        id
                    );
                    return None;
                }
            }
            return Some(rows);
        }

        // 4. Miss
        log::debug!(
            "[cache] try_query table={} → MISS (no matching strategy, where_clauses={}, id_lookups={})",
            table,
            where_clauses.len(),
            id_lookups.len()
        );
        None
    }

    /// Get all rows from a table (for join queries where table is complete).
    pub fn get_all_rows(&mut self, table: &str) -> Option<Vec<serde_json::Value>> {
        let cache = self.tables.get_mut(table)?;
        if !cache.is_complete {
            return None;
        }
        cache.last_accessed = Instant::now();
        let mut rows: Vec<serde_json::Value> = cache.rows.values().cloned().collect();
        rows.sort_by_key(|r| r.get("id").and_then(|v| v.as_i64()).unwrap_or(0));
        Some(rows)
    }

    /// Check if a table is complete.
    pub fn is_table_complete(&self, table: &str) -> bool {
        self.tables.get(table).is_some_and(|c| c.is_complete)
    }

    // --- Population (after server fetch) ---

    /// Populate cache with all rows from a full-table fetch.
    pub fn populate_full(
        &mut self,
        table: &str,
        rows: Vec<serde_json::Value>,
        indexed_columns: &[String],
    ) {
        if !self.config.enabled {
            return;
        }
        self.evict_if_needed();
        let cache = self
            .tables
            .entry(table.to_string())
            .or_insert_with(|| TableCache::new(indexed_columns));

        // Ensure all indexed columns have entries
        for col in indexed_columns {
            cache
                .indexes
                .entry(col.clone())
                .or_insert_with(ColumnIndex::new);
        }

        cache.rows.clear();
        for index in cache.indexes.values_mut() {
            index.entries.clear();
            index.complete_values.clear();
        }

        for row in rows {
            if let Some(id) = row.get("id").and_then(|v| v.as_i64()) {
                for (col, index) in cache.indexes.iter_mut() {
                    if let Some(val) = row.get(col).and_then(|v| v.as_i64()) {
                        index.entries.insert((val, id), ());
                    }
                }
                cache.rows.insert(id, row);
            }
        }

        cache.is_complete = true;
        cache.last_accessed = Instant::now();
    }

    /// Populate cache for a specific column value (FK-style lookup).
    /// Marks that value as complete in the index.
    ///
    /// Refresh is authoritative for that `column=value` region: rows previously
    /// cached for the region but absent from `rows` are removed. When that
    /// happens, any overlapping completeness markers are conservatively dropped
    /// because row provenance is not tracked per region.
    pub fn populate_for_value(
        &mut self,
        table: &str,
        column: &str,
        value: i64,
        rows: Vec<serde_json::Value>,
        indexed_columns: &[String],
    ) {
        if !self.config.enabled {
            return;
        }
        self.evict_if_needed();
        let cache = self
            .tables
            .entry(table.to_string())
            .or_insert_with(|| TableCache::new(indexed_columns));

        // Ensure all indexed columns have entries
        for col in indexed_columns {
            cache
                .indexes
                .entry(col.clone())
                .or_insert_with(ColumnIndex::new);
        }

        let replacement_ids: HashSet<i64> = rows
            .iter()
            .filter_map(|row| row.get("id").and_then(|v| v.as_i64()))
            .collect();

        let stale_row_ids: Vec<i64> = cache
            .indexes
            .get(column)
            .map(|index| {
                index
                    .entries
                    .range((value, i64::MIN)..=(value, i64::MAX))
                    .map(|((_, row_id), _)| *row_id)
                    .filter(|row_id| !replacement_ids.contains(row_id))
                    .collect()
            })
            .unwrap_or_default();

        for row_id in stale_row_ids {
            if let Some(stale_row) = cache.rows.remove(&row_id) {
                for (indexed_col, index) in cache.indexes.iter_mut() {
                    if let Some(indexed_val) = stale_row.get(indexed_col).and_then(|v| v.as_i64()) {
                        index.entries.remove(&(indexed_val, row_id));
                        index.complete_values.remove(&indexed_val);
                    }
                }
            }
        }

        for row in rows {
            if let Some(id) = row.get("id").and_then(|v| v.as_i64()) {
                for (col, index) in cache.indexes.iter_mut() {
                    if let Some(val) = row.get(col).and_then(|v| v.as_i64()) {
                        index.entries.insert((val, id), ());
                    }
                }
                cache.rows.insert(id, row);
            }
        }

        // Mark this value as complete in the specified column's index
        if let Some(index) = cache.indexes.get_mut(column) {
            index.complete_values.insert(value);
        }

        cache.last_accessed = Instant::now();
    }

    // --- Invalidation ---

    pub fn invalidate_table(&mut self, table: &str) {
        self.tables.remove(table);
    }

    /// Drop per-value completeness for indexed columns that might now point at
    /// a row we don't have. Used when an update arrives for a row that isn't
    /// in the local cache: the destination bucket may no longer be complete.
    fn invalidate_destination_buckets(
        &mut self,
        table: &str,
        updates: &[(String, serde_json::Value)],
    ) {
        if let Some(cache) = self.tables.get_mut(table) {
            for (col, new_val) in updates {
                if let Some(index) = cache.indexes.get_mut(col.as_str()) {
                    if let Some(nv) = new_val.as_i64() {
                        index.complete_values.remove(&nv);
                    }
                }
            }
        }
    }

    pub fn clear_all(&mut self) {
        self.tables.clear();
    }

    // --- Join cache support ---

    /// Try to resolve joined rows from cache for a set of FK values.
    ///
    /// If the joined table is fully cached, returns all rows (the caller
    /// filters to matching FKs during assembly). Otherwise, tries per-value
    /// lookups — by id if `pk_col` is `"id"`, or by indexed column predicate
    /// otherwise. Returns `None` on any miss.
    pub fn try_query_joined(
        &mut self,
        joined_table: &str,
        pk_col: &str,
        fk_values: &[i64],
    ) -> Option<Vec<serde_json::Value>> {
        if !self.config.enabled {
            return None;
        }

        // If the joined table is fully cached, return all rows
        if self.is_table_complete(joined_table) {
            return self.get_all_rows(joined_table);
        }

        // Per-value lookups: id-based or indexed-column-based
        let mut all_rows = Vec::new();
        for &val in fk_values {
            let result = if pk_col == "id" {
                self.try_query(joined_table, &[], &[val])
            } else {
                self.try_query(joined_table, &[(pk_col.to_string(), val)], &[])
            };
            match result {
                Some(rows) => all_rows.extend(rows),
                None => return None,
            }
        }
        Some(all_rows)
    }

    /// Insert rows into a table cache without marking the table complete.
    ///
    /// Used for join results where we only have the FK-matched subset.
    /// If `pk_col` is provided, marks each distinct value of that column
    /// as complete in the index so subsequent per-value lookups hit.
    pub fn populate_partial(
        &mut self,
        table: &str,
        rows: Vec<serde_json::Value>,
        indexed_columns: &[String],
        pk_col: Option<&str>,
    ) {
        if !self.config.enabled {
            return;
        }
        self.init_table(table, indexed_columns);

        // Collect distinct pk values to mark as complete
        let mut pk_values: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
        for row in &rows {
            if let Some(col) = pk_col {
                if let Some(val) = row.get(col).and_then(|v| v.as_i64()) {
                    pk_values.insert(val);
                }
            }
        }

        for row in rows {
            self.insert_row(table, row);
        }

        // Mark each FK-matched value as complete in the pk column's index
        if let Some(col) = pk_col {
            if col != "id" {
                if let Some(cache) = self.tables.get_mut(table) {
                    if let Some(index) = cache.indexes.get_mut(col) {
                        for val in pk_values {
                            index.complete_values.insert(val);
                        }
                    }
                }
            }
        }
    }

    // --- Init ---

    pub fn init_table(&mut self, table: &str, indexed_columns: &[String]) {
        self.tables
            .entry(table.to_string())
            .or_insert_with(|| TableCache::new(indexed_columns));
    }

    // --- Row/index mutations ---

    pub fn insert_row(&mut self, table: &str, row: serde_json::Value) {
        if let Some(cache) = self.tables.get_mut(table) {
            let id_value = row.get("id");
            log::debug!(
                "[cache] insert_row table={} id_value={:?} id_as_i64={:?} total_rows_before={}",
                table,
                id_value,
                id_value.and_then(|v| v.as_i64()),
                cache.rows.len()
            );
            if let Some(id) = row.get("id").and_then(|v| v.as_i64()) {
                // Remove old index entries if replacing an existing row
                if let Some(old_row) = cache.rows.get(&id) {
                    for (col, index) in cache.indexes.iter_mut() {
                        if let Some(old_val) = old_row.get(col).and_then(|v| v.as_i64()) {
                            index.entries.remove(&(old_val, id));
                        }
                    }
                }
                // Insert new index entries
                for (col, index) in cache.indexes.iter_mut() {
                    if let Some(val) = row.get(col).and_then(|v| v.as_i64()) {
                        index.entries.insert((val, id), ());
                    }
                }
                cache.rows.insert(id, row);
            }
        }
    }

    pub fn update_row(
        &mut self,
        table: &str,
        row_id: i64,
        updates: &[(String, serde_json::Value)],
    ) -> bool {
        if let Some(cache) = self.tables.get_mut(table) {
            if let Some(row) = cache.rows.get_mut(&row_id) {
                for (col, new_val) in updates {
                    if let Some(index) = cache.indexes.get_mut(col.as_str()) {
                        let old_val = row.get(col).and_then(|v| v.as_i64());
                        let new_int = new_val.as_i64();

                        // Only touch index + completeness if value actually changed
                        if old_val != new_int {
                            if let Some(ov) = old_val {
                                index.entries.remove(&(ov, row_id));
                                index.complete_values.remove(&ov);
                            }
                            if let Some(nv) = new_int {
                                index.entries.insert((nv, row_id), ());
                                index.complete_values.remove(&nv);
                            }
                        }
                    }
                    if let serde_json::Value::Object(obj) = row {
                        obj.insert(col.clone(), new_val.clone());
                    }
                }
                return true;
            }
        }
        false
    }

    pub fn remove_row(&mut self, table: &str, row_id: i64) -> bool {
        if let Some(cache) = self.tables.get_mut(table) {
            if let Some(row) = cache.rows.remove(&row_id) {
                for (col, index) in cache.indexes.iter_mut() {
                    if let Some(val) = row.get(col).and_then(|v| v.as_i64()) {
                        index.entries.remove(&(val, row_id));
                    }
                }
                return true;
            }
        }
        false
    }

    // --- Eviction ---

    /// Evict least-recently-accessed table when over the limit.
    /// Internal tables are exempt from eviction.
    fn evict_if_needed(&mut self) {
        while self.tables.len() >= self.config.max_tables {
            let evict_key = self
                .tables
                .iter()
                .filter(|(name, _)| !INTERNAL_TABLES.contains(&name.as_str()))
                .min_by_key(|(_, cache)| cache.last_accessed)
                .map(|(name, _)| name.clone());

            if let Some(key) = evict_key {
                self.tables.remove(&key);
            } else {
                break; // all tables are internal, can't evict
            }
        }
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl TableCache {
    fn new(indexed_columns: &[String]) -> Self {
        let mut indexes = HashMap::new();
        for col in indexed_columns {
            indexes.insert(col.clone(), ColumnIndex::new());
        }
        Self {
            rows: HashMap::new(),
            indexes,
            is_complete: false,
            last_accessed: Instant::now(),
        }
    }
}

impl ColumnIndex {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            complete_values: HashSet::new(),
        }
    }
}

/// Apply the verifier's per-op writes to the local cache. Walks
/// `writes`, decodes/decrypts each column's raw bytes per the registered
/// schema, and lands each resulting row in the cache (synthesising
/// `id` for fresh rows, patching existing rows in place, removing
/// rows with `Delete` writes).
///
/// Callers must invoke this only after the change is fully validated
/// (proof + signature, where applicable) — the broadcast handler
/// defers the call until after deferred-signature retry succeeds.
pub(crate) async fn update_cache_from_proven_writes(
    space: &crate::Space,
    change: &Change,
    writes: &[BatchOp],
) {
    // 1. Resolve every write into a (column_key, value_bytes) pair the
    //    SELECT-side reassembler can consume. Deletes are tracked separately
    //    by table.
    let mut column_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut deletes: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();

    for op in writes {
        match op {
            BatchOp::Put { key, value } => {
                column_entries.push((key.clone(), value.clone()));
            }
            BatchOp::Delete { key } => {
                if let Ok(ParsedKey::Column { table, row_id, .. }) = parse_key(key) {
                    deletes.entry(table).or_default().insert(row_id);
                }
            }
        }
    }

    // 2. Reassemble the columnar writes into row JSON objects, grouped
    //    by table. `id` is injected by the reassembler, so the rows
    //    have the same shape SELECT produces. For hash-backed columns,
    //    resolve 32-byte hash digests to full values using the change's
    //    hashed values before JSON decoding. If reassembly fails for
    //    any reason, fail closed: invalidate every touched table.
    let schemas = space.with_state(|state| state.table_schemas.clone());
    let mut rows_by_table = match group_columns_into_rows_by_table_resolving_hashes(
        &column_entries,
        &schemas,
        &change.hashed_values,
    ) {
        Ok(g) => g,
        Err(e) => {
            log::warn!(
                "update_cache_from_proven_writes: row reassembly failed: {e}; \
                 invalidating every touched table"
            );
            let touched: BTreeSet<String> = writes
                .iter()
                .filter_map(|op| {
                    let key = match op {
                        BatchOp::Put { key, .. } | BatchOp::Delete { key } => key,
                    };
                    match parse_key(key) {
                        Ok(ParsedKey::Column { table, .. }) => Some(table),
                        _ => None,
                    }
                })
                .collect();
            space.with_state_mut(|state| {
                for t in &touched {
                    state.cache.invalidate_table(t);
                }
            });
            return;
        }
    };

    // 3. Apply deletes. Strip any same-row puts to keep this function
    //    order-independent should an op ever produce both for one row.
    for (table, ids) in &deletes {
        if let Some(rows) = rows_by_table.get_mut(table) {
            rows.retain(|r| {
                r.get(ID_FIELD)
                    .and_then(|v| v.as_i64())
                    .is_none_or(|id| !ids.contains(&id))
            });
        }
    }
    space.with_state_mut(|state| {
        for (table, ids) in &deletes {
            for &row_id in ids {
                state.cache.remove_row(table, row_id);
            }
        }
    });

    // 5. Per table: decrypt encrypted columns, then land each row in
    //    the cache (fresh insert for full-schema rows, in-place patch
    //    for narrower writes).
    for (table, mut rows) in rows_by_table {
        let schema = match schemas.get(&table) {
            Some(s) => s.clone(),
            None => continue, // unregistered table — cache can't materialise rows for it
        };
        let non_id_cols: BTreeSet<&str> = schema
            .columns
            .iter()
            .filter(|c| c.name != ID_FIELD)
            .map(|c| c.name.as_str())
            .collect();

        if schema.columns.iter().any(|c| !c.plaintext)
            && crate::crypto::decrypt_table_rows(&mut rows, &table, &schemas, space)
                .await
                .is_err()
        {
            log::warn!(
                "update_cache_from_proven_writes: decryption failed for {table}; \
                 invalidating table"
            );
            space.with_state_mut(|state| state.cache.invalidate_table(&table));
            continue;
        }

        space.with_state_mut(|state| {
            for row in rows {
                let serde_json::Value::Object(ref obj) = row else {
                    continue;
                };
                let row_id = match obj.get(ID_FIELD).and_then(|v| v.as_i64()) {
                    Some(id) => id,
                    None => continue,
                };
                let present: BTreeSet<&str> = obj
                    .keys()
                    .filter(|k| k.as_str() != ID_FIELD)
                    .map(String::as_str)
                    .collect();
                let is_fresh =
                    !non_id_cols.is_empty() && non_id_cols.iter().all(|c| present.contains(c));
                if is_fresh {
                    state.cache.insert_row(&table, row);
                } else {
                    let pairs: Vec<(String, serde_json::Value)> = obj
                        .iter()
                        .filter(|(k, _)| k.as_str() != ID_FIELD)
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    // If the target row is not in the cache,
                    // `update_row` no-ops — but the verified update may
                    // be moving a non-resident row into a bucket the
                    // cache currently considers complete. Drop
                    // per-value completeness for the destination indexed
                    // columns so the next read refetches.
                    if !state.cache.update_row(&table, row_id, &pairs) {
                        state.cache.invalidate_destination_buckets(&table, &pairs);
                    }
                }
            }
        });
    }
}

/// Last new-row id touching `table` in `writes`. A row counts as new
/// when its puts cover every non-id column of the registered schema —
/// the same shape `update_cache_from_validated_change` uses to decide
/// whether to insert vs. patch.
pub(crate) fn new_row_id_for_table(
    space: &crate::Space,
    writes: &[BatchOp],
    table: &str,
) -> Option<i64> {
    let schema_non_id_cols: BTreeSet<String> = space.get_table_schema(table).map(|s| {
        s.columns
            .iter()
            .filter(|c| c.name != "id")
            .map(|c| c.name.clone())
            .collect()
    })?;
    if schema_non_id_cols.is_empty() {
        return None;
    }

    let mut per_row: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    for op in writes {
        let key = match op {
            BatchOp::Put { key, .. } => key,
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
    use encrypted_spaces_changelog_core::changelog::OpType;
    use serde_json::json;

    /// Test-only helpers on `Cache` that are only used by tests in this
    /// module. Helpers used by sibling modules' tests (`list`, `changelog`)
    /// remain on the production `impl Cache` gated by `#[cfg(test)]`.
    impl Cache {
        fn with_config(config: CacheConfig) -> Self {
            Self {
                tables: HashMap::new(),
                config,
            }
        }

        /// Check if all given tables are complete (for join queries).
        fn all_tables_complete(&self, tables: &[&str]) -> bool {
            self.config.enabled
                && tables
                    .iter()
                    .all(|t| self.tables.get(*t).is_some_and(|c| c.is_complete))
        }

        /// Apply a change to the cache. Mirrors broadcast/replay handling.
        fn apply_change(
            &mut self,
            table: &str,
            op: OpType,
            row_id: Option<i64>,
            row_data: Option<serde_json::Value>,
            updates: Option<&[(String, serde_json::Value)]>,
        ) {
            match op {
                OpType::Insert => {
                    if let Some(row) = row_data {
                        self.insert_row(table, row);
                        // Do NOT add to complete_values — only fetches establish completeness
                    } else {
                        self.mark_table_incomplete(table);
                    }
                }
                OpType::Update => {
                    if let (Some(id), Some(upd)) = (row_id, updates) {
                        if !self.update_row(table, id, upd) {
                            // Row is not in the local cache, so the update can't
                            // be applied in-place. It may be moving an uncached
                            // row into a bucket we consider complete — drop
                            // per-value completeness for each indexed destination
                            // so the next query re-fetches from the server.
                            self.invalidate_destination_buckets(table, upd);
                        }
                    } else if let Some(id) = row_id {
                        self.remove_row(table, id);
                        self.mark_table_incomplete(table);
                    } else {
                        self.invalidate_table(table);
                    }
                }
                OpType::Delete => {
                    if let Some(id) = row_id {
                        self.remove_row(table, id);
                        // Cache stays complete — row is genuinely gone
                    } else {
                        self.invalidate_table(table);
                    }
                }
                _ => self.invalidate_table(table),
            }
        }

        fn mark_table_incomplete(&mut self, table: &str) {
            if let Some(cache) = self.tables.get_mut(table) {
                cache.is_complete = false;
            }
        }

        /// Index lookup via BTreeMap prefix scan — O(log N + result_size).
        fn index_lookup(&self, table: &str, column: &str, value: i64) -> Vec<i64> {
            self.tables
                .get(table)
                .and_then(|c| c.indexes.get(column))
                .map(|idx| {
                    idx.entries
                        .range((value, i64::MIN)..=(value, i64::MAX))
                        .map(|((_, row_id), _)| *row_id)
                        .collect()
                })
                .unwrap_or_default()
        }

        /// Validate all critical invariants. Panics on violation.
        /// Call after every mutation in tests to catch bugs immediately.
        ///
        /// Checks:
        /// - **Invariant 1 (index → rows)**: Every index entry `(val, row_id)`
        ///   references a row that exists and whose column actually equals `val`.
        ///
        /// - **Invariant 2 (structural completeness)**: Complete tables should not
        ///   track per-value completeness (table-level supersedes it).
        ///
        /// - **Invariant 3 (index ≤ rows)**: Index entries per column never exceed
        ///   the row count, guarding against duplicate inserts during refactors.
        ///
        /// - **Invariant 4 (rows → index)**: Every row with an indexed integer
        ///   column has a matching entry in the index.
        fn assert_invariants(&self) {
            for (table_name, table) in &self.tables {
                // Invariant 1 (forward): index → rows
                for (col, index) in &table.indexes {
                    for (val, row_id) in index.entries.keys() {
                        let row = table.rows.get(row_id).unwrap_or_else(|| {
                            panic!(
                                "table '{table_name}': index '{col}' references missing row {row_id}"
                            )
                        });
                        let actual = row.get(col).and_then(|v| v.as_i64()).unwrap_or_else(|| {
                            panic!(
                                "table '{table_name}': row {row_id} missing indexed column '{col}'"
                            )
                        });
                        assert_eq!(
                            *val, actual,
                            "table '{table_name}': index '{col}' has value {val} but row {row_id} has {actual}"
                        );
                    }
                }

                // Invariant 2 (structural): complete tables should not track per-value
                // completeness — table-level completeness supersedes it.
                if table.is_complete {
                    for (col, index) in &table.indexes {
                        assert!(
                            index.complete_values.is_empty(),
                            "table '{table_name}': index '{col}' has complete_values but table is already complete"
                        );
                    }
                }

                // Invariant 3: index entries never exceed row count (guards against
                // duplicate inserts during refactors).
                for (col, index) in &table.indexes {
                    assert!(
                        index.entries.len() <= table.rows.len(),
                        "table '{table_name}': index '{col}' has {} entries but only {} rows",
                        index.entries.len(),
                        table.rows.len()
                    );
                }

                // Invariant 4 (reverse): rows → index
                for (row_id, row) in &table.rows {
                    for (col, index) in &table.indexes {
                        if let Some(val) = row.get(col).and_then(|v| v.as_i64()) {
                            assert!(
                                index.entries.contains_key(&(val, *row_id)),
                                "table '{table_name}': row {row_id} col '{col}'={val} missing from index"
                            );
                        }
                    }
                }
            }
        }
    }

    fn make_row(id: i64, thread_id: i64, name: &str) -> serde_json::Value {
        json!({"id": id, "thread_id": thread_id, "name": name})
    }

    fn cols() -> Vec<String> {
        vec!["thread_id".to_string()]
    }

    // ---------------------------------------------------------------
    // Invariant tests
    // ---------------------------------------------------------------

    #[test]
    fn invariant_rows_are_source_of_truth() {
        let mut cache = Cache::new();
        cache.populate_full(
            "messages",
            vec![make_row(1, 10, "hello"), make_row(2, 10, "world")],
            &cols(),
        );
        cache.assert_invariants();

        assert!(cache.get_row("messages", 1).is_some());
        assert!(cache.get_row("messages", 2).is_some());
        let ids = cache.index_lookup("messages", "thread_id", 10);
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn invariant_completeness_only_from_server_queries() {
        let mut cache = Cache::new();
        cache.init_table("messages", &cols());

        // Broadcast insert should NOT establish completeness
        cache.apply_change(
            "messages",
            OpType::Insert,
            None,
            Some(make_row(1, 10, "hello")),
            None,
        );
        cache.assert_invariants();
        assert!(!cache.is_table_complete("messages"));

        // Server fetch establishes completeness
        cache.populate_for_value(
            "messages",
            "thread_id",
            10,
            vec![make_row(1, 10, "hello")],
            &cols(),
        );
        cache.assert_invariants();

        let result = cache.try_query("messages", &[("thread_id".to_string(), 10)], &[]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn invariant_index_entries_match_rows_after_update() {
        let mut cache = Cache::new();
        cache.populate_full(
            "messages",
            vec![make_row(1, 10, "hello"), make_row(2, 20, "world")],
            &cols(),
        );
        cache.assert_invariants();

        cache.update_row("messages", 1, &[("thread_id".to_string(), json!(20))]);
        cache.assert_invariants();

        assert!(cache.index_lookup("messages", "thread_id", 10).is_empty());
        let ids_20 = cache.index_lookup("messages", "thread_id", 20);
        assert_eq!(ids_20.len(), 2);
    }

    #[test]
    fn invariant_holds_after_insert_update_delete_sequence() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![], &cols());
        cache.assert_invariants();

        // Insert
        cache.insert_row("t", make_row(1, 100, "a"));
        cache.assert_invariants();
        cache.insert_row("t", make_row(2, 200, "b"));
        cache.assert_invariants();
        cache.insert_row("t", make_row(3, 100, "c"));
        cache.assert_invariants();

        // Update indexed column
        cache.update_row("t", 1, &[("thread_id".to_string(), json!(200))]);
        cache.assert_invariants();

        // Delete
        cache.remove_row("t", 2);
        cache.assert_invariants();

        // Verify final state
        assert_eq!(cache.index_lookup("t", "thread_id", 100), vec![3]);
        let ids_200 = cache.index_lookup("t", "thread_id", 200);
        assert_eq!(ids_200.len(), 1);
        assert!(ids_200.contains(&1));
    }

    #[test]
    fn invariant_holds_across_multi_column_indexes() {
        let mut cache = Cache::new();
        let cols = vec!["thread_id".to_string(), "priority".to_string()];

        let rows = vec![
            json!({"id": 1, "thread_id": 10, "priority": 1, "name": "a"}),
            json!({"id": 2, "thread_id": 10, "priority": 2, "name": "b"}),
            json!({"id": 3, "thread_id": 20, "priority": 1, "name": "c"}),
        ];
        cache.populate_full("tasks", rows, &cols);
        cache.assert_invariants();

        // Update both indexed columns
        cache.update_row(
            "tasks",
            1,
            &[
                ("thread_id".to_string(), json!(20)),
                ("priority".to_string(), json!(3)),
            ],
        );
        cache.assert_invariants();

        assert!(cache.index_lookup("tasks", "thread_id", 10).contains(&2));
        assert!(!cache.index_lookup("tasks", "thread_id", 10).contains(&1));
        assert!(cache.index_lookup("tasks", "thread_id", 20).contains(&1));
        assert_eq!(cache.index_lookup("tasks", "priority", 3), vec![1]);
    }

    // ---------------------------------------------------------------
    // Query tests
    // ---------------------------------------------------------------

    #[test]
    fn query_full_table() {
        let mut cache = Cache::new();
        cache.populate_full(
            "messages",
            vec![make_row(1, 10, "a"), make_row(2, 20, "b")],
            &[],
        );
        let result = cache.try_query("messages", &[], &[]).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn query_by_id_in_partial_cache() {
        let mut cache = Cache::new();
        cache.populate_full(
            "messages",
            vec![make_row(1, 10, "a"), make_row(2, 20, "b")],
            &[],
        );
        cache.mark_table_incomplete("messages");

        assert_eq!(cache.try_query("messages", &[], &[1]).unwrap().len(), 1);
        assert!(cache.try_query("messages", &[], &[999]).is_none());
    }

    #[test]
    fn query_by_index_with_complete_value() {
        let mut cache = Cache::new();
        cache.populate_for_value(
            "messages",
            "thread_id",
            10,
            vec![make_row(1, 10, "a"), make_row(2, 10, "b")],
            &cols(),
        );

        let result = cache.try_query("messages", &[("thread_id".to_string(), 10)], &[]);
        assert_eq!(result.unwrap().len(), 2);

        // Incomplete value is a miss
        assert!(cache
            .try_query("messages", &[("thread_id".to_string(), 20)], &[])
            .is_none());
    }

    #[test]
    fn query_nonexistent_table_is_miss() {
        let mut cache = Cache::new();
        assert!(cache.try_query("nonexistent", &[], &[]).is_none());
    }

    #[test]
    fn query_incomplete_table_no_predicates_is_miss() {
        let mut cache = Cache::new();
        cache.init_table("messages", &cols());
        cache.insert_row("messages", make_row(1, 10, "a"));
        assert!(cache.try_query("messages", &[], &[]).is_none());
    }

    // ---------------------------------------------------------------
    // apply_change tests
    // ---------------------------------------------------------------

    #[test]
    fn apply_change_insert_with_data() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());

        cache.apply_change("t", OpType::Insert, None, Some(make_row(2, 10, "b")), None);
        cache.assert_invariants();

        assert!(cache.get_row("t", 2).is_some());
        assert_eq!(cache.index_lookup("t", "thread_id", 10).len(), 2);
    }

    #[test]
    fn apply_change_insert_without_data_marks_incomplete() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &[]);
        assert!(cache.is_table_complete("t"));

        cache.apply_change("t", OpType::Insert, None, None, None);
        assert!(!cache.is_table_complete("t"));
    }

    #[test]
    fn apply_change_update_with_fields() {
        let mut cache = Cache::new();
        cache.populate_full(
            "t",
            vec![make_row(1, 10, "a"), make_row(2, 20, "b")],
            &cols(),
        );

        let updates = vec![("thread_id".to_string(), json!(30))];
        cache.apply_change("t", OpType::Update, Some(1), None, Some(&updates));
        cache.assert_invariants();

        assert!(cache.index_lookup("t", "thread_id", 10).is_empty());
        assert_eq!(cache.index_lookup("t", "thread_id", 30), vec![1]);
    }

    #[test]
    fn apply_change_update_without_fields_evicts_row() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());

        cache.apply_change("t", OpType::Update, Some(1), None, None);
        cache.assert_invariants();

        assert!(cache.get_row("t", 1).is_none());
        assert!(!cache.is_table_complete("t"));
    }

    #[test]
    fn update_for_uncached_row_drops_destination_bucket_completeness() {
        // Setup: populate the `thread_id=10` bucket, marking it complete.
        let mut cache = Cache::new();
        cache.populate_for_value(
            "messages",
            "thread_id",
            10,
            vec![make_row(1, 10, "a")],
            &cols(),
        );
        assert!(
            cache
                .try_query("messages", &[("thread_id".to_string(), 10)], &[])
                .is_some(),
            "bucket should claim completeness after populate_for_value"
        );

        // A verified update arrives for row 999 (not in the cache),
        // moving it into the `thread_id=10` bucket. `update_row`
        // returns `false`; the caller must drop bucket completeness so
        // the next read refetches.
        let updates = vec![("thread_id".to_string(), serde_json::json!(10))];
        let applied = cache.update_row("messages", 999, &updates);
        assert!(
            !applied,
            "update_row must report false for an uncached target row"
        );
        cache.invalidate_destination_buckets("messages", &updates);

        // Bucket completeness for `thread_id=10` is gone — a `try_query`
        // for it now misses and would refetch from the server.
        assert!(
            cache
                .try_query("messages", &[("thread_id".to_string(), 10)], &[])
                .is_none(),
            "bucket should no longer claim completeness after update on uncached row"
        );
    }

    #[test]
    fn apply_change_update_without_row_id_invalidates_table() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());

        cache.apply_change("t", OpType::Update, None, None, None);

        assert!(!cache.is_table_complete("t"));
    }

    #[test]
    fn apply_change_delete_preserves_completeness() {
        let mut cache = Cache::new();
        cache.populate_full(
            "t",
            vec![make_row(1, 10, "a"), make_row(2, 20, "b")],
            &cols(),
        );
        assert!(cache.is_table_complete("t"));

        cache.apply_change("t", OpType::Delete, Some(1), None, None);
        cache.assert_invariants();

        assert!(cache.get_row("t", 1).is_none());
        assert!(cache.is_table_complete("t"));
    }

    #[test]
    fn apply_change_delete_without_id_invalidates() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &[]);

        cache.apply_change("t", OpType::Delete, None, None, None);
        assert!(!cache.is_table_complete("t"));
    }

    #[test]
    fn apply_change_updates_cache_state() {
        let mut cache = Cache::new();
        cache.init_table("t", &[]);

        cache.apply_change("t", OpType::Insert, None, None, None);
        assert!(!cache.is_table_complete("t"));

        cache.apply_change("t", OpType::Delete, None, None, None);
        assert!(!cache.is_table_complete("t"));
    }

    #[test]
    fn apply_change_duplicate_is_safe() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());

        // Apply same delete twice
        cache.apply_change("t", OpType::Delete, Some(1), None, None);
        cache.assert_invariants();
        cache.apply_change("t", OpType::Delete, Some(1), None, None);
        cache.assert_invariants();
    }

    // ---------------------------------------------------------------
    // Population tests
    // ---------------------------------------------------------------

    #[test]
    fn populate_full_replaces_existing_data() {
        let mut cache = Cache::new();
        cache.populate_full(
            "t",
            vec![make_row(1, 10, "a"), make_row(2, 20, "b")],
            &cols(),
        );
        cache.assert_invariants();

        // Re-populate with different data
        cache.populate_full("t", vec![make_row(3, 30, "c")], &cols());
        cache.assert_invariants();

        assert!(cache.get_row("t", 1).is_none());
        assert!(cache.get_row("t", 2).is_none());
        assert!(cache.get_row("t", 3).is_some());
        assert!(cache.is_table_complete("t"));
    }

    #[test]
    fn populate_for_value_accumulates_distinct_buckets() {
        let mut cache = Cache::new();

        cache.populate_for_value("t", "thread_id", 10, vec![make_row(1, 10, "a")], &cols());
        cache.assert_invariants();

        cache.populate_for_value("t", "thread_id", 20, vec![make_row(2, 20, "b")], &cols());
        cache.assert_invariants();

        // Both rows present
        assert!(cache.get_row("t", 1).is_some());
        assert!(cache.get_row("t", 2).is_some());

        // Both values queryable
        assert!(cache
            .try_query("t", &[("thread_id".to_string(), 10)], &[])
            .is_some());
        assert!(cache
            .try_query("t", &[("thread_id".to_string(), 20)], &[])
            .is_some());

        // Table is NOT complete (only specific values are)
        assert!(!cache.is_table_complete("t"));
    }

    #[test]
    fn populate_for_value_replaces_stale_bucket_rows() {
        let mut cache = Cache::new();
        let cols = vec!["thread_id".to_string(), "priority".to_string()];

        let initial_rows = vec![
            json!({"id": 1, "thread_id": 10, "priority": 1, "name": "a"}),
            json!({"id": 2, "thread_id": 10, "priority": 2, "name": "b"}),
            json!({"id": 3, "thread_id": 20, "priority": 1, "name": "c"}),
        ];
        cache.populate_full("tasks", initial_rows, &cols);
        cache.mark_table_incomplete("tasks");
        cache.populate_for_value(
            "tasks",
            "thread_id",
            10,
            vec![json!({"id": 2, "thread_id": 10, "priority": 2, "name": "b"})],
            &cols,
        );
        cache.assert_invariants();

        let rows = cache
            .try_query("tasks", &[("thread_id".to_string(), 10)], &[])
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("id").and_then(|v| v.as_i64()), Some(2));

        assert!(cache.get_row("tasks", 1).is_none());
        assert!(cache
            .try_query("tasks", &[("priority".to_string(), 1)], &[])
            .is_none());
    }

    // ---------------------------------------------------------------
    // Eviction tests
    // ---------------------------------------------------------------

    #[test]
    fn eviction_respects_internal_tables() {
        let mut cache = Cache::with_config(CacheConfig {
            max_tables: 2,
            enabled: true,
        });

        cache.populate_full(USERS_TABLE_NAME, vec![], &[]);
        cache.populate_full("messages", vec![make_row(1, 10, "a")], &[]);

        assert!(cache.is_table_complete(USERS_TABLE_NAME));
        assert!(cache.is_table_complete("messages"));
    }

    #[test]
    fn eviction_removes_lru() {
        // max_tables=2: eviction runs before insert to make room.
        let mut cache = Cache::with_config(CacheConfig {
            max_tables: 2,
            enabled: true,
        });

        cache.populate_full("table_a", vec![], &[]);
        std::thread::sleep(std::time::Duration::from_millis(2));
        cache.populate_full("table_b", vec![], &[]);
        std::thread::sleep(std::time::Duration::from_millis(2));

        // Access table_a to make it more recent
        let _ = cache.try_query("table_a", &[], &[]);
        std::thread::sleep(std::time::Duration::from_millis(2));

        // Adding table_c (3rd table) should evict table_b (least recently accessed)
        cache.populate_full("table_c", vec![], &[]);

        assert!(cache.is_table_complete("table_a"));
        assert!(!cache.is_table_complete("table_b")); // evicted
        assert!(cache.is_table_complete("table_c"));
    }

    #[test]
    fn eviction_preserves_invariants() {
        let mut cache = Cache::with_config(CacheConfig {
            max_tables: 2,
            enabled: true,
        });

        cache.populate_full("a", vec![make_row(1, 10, "x")], &cols());
        std::thread::sleep(std::time::Duration::from_millis(2));
        cache.populate_full("b", vec![make_row(2, 20, "y")], &cols());
        std::thread::sleep(std::time::Duration::from_millis(2));
        cache.populate_full("c", vec![make_row(3, 30, "z")], &cols());

        cache.assert_invariants();
    }

    // ---------------------------------------------------------------
    // Invalidation tests
    // ---------------------------------------------------------------

    #[test]
    fn clear_all_resets_everything() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());

        cache.clear_all();

        assert!(!cache.is_table_complete("t"));
    }

    #[test]
    fn invalidate_table_removes_completely() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());
        cache.invalidate_table("t");

        assert!(cache.get_row("t", 1).is_none());
        assert!(!cache.is_table_complete("t"));
    }

    #[test]
    fn mark_incomplete_preserves_rows() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());
        cache.mark_table_incomplete("t");

        assert!(!cache.is_table_complete("t"));
        assert!(cache.get_row("t", 1).is_some());
        cache.assert_invariants();
    }

    // ---------------------------------------------------------------
    // Changelog replay / determinism tests
    // ---------------------------------------------------------------

    type ChangeList = Vec<(
        u32,
        OpType,
        Option<i64>,
        Option<serde_json::Value>,
        Option<Vec<(String, serde_json::Value)>>,
    )>;

    #[test]
    fn changelog_replay_deterministic() {
        // Apply a sequence of changes and verify final state
        let changes: ChangeList = vec![
            (1, OpType::Insert, None, Some(make_row(1, 10, "a")), None),
            (2, OpType::Insert, None, Some(make_row(2, 20, "b")), None),
            (3, OpType::Insert, None, Some(make_row(3, 10, "c")), None),
            (
                4,
                OpType::Update,
                Some(2),
                None,
                Some(vec![("thread_id".to_string(), json!(10))]),
            ),
            (5, OpType::Delete, Some(3), None, None),
        ];

        let mut cache = Cache::new();
        cache.init_table("t", &cols());

        for (_cid, op, row_id, row_data, updates) in &changes {
            cache.apply_change("t", *op, *row_id, row_data.clone(), updates.as_deref());
            cache.assert_invariants();
        }

        assert!(cache.get_row("t", 1).is_some());
        assert!(cache.get_row("t", 2).is_some());
        assert!(cache.get_row("t", 3).is_none()); // deleted
        assert_eq!(cache.index_lookup("t", "thread_id", 10).len(), 2);
        assert!(cache.index_lookup("t", "thread_id", 20).is_empty());
    }

    #[test]
    fn partial_replay_then_full_replay_matches() {
        let changes: ChangeList = vec![
            (1, OpType::Insert, None, Some(make_row(1, 10, "a")), None),
            (2, OpType::Insert, None, Some(make_row(2, 20, "b")), None),
            (
                3,
                OpType::Update,
                Some(1),
                None,
                Some(vec![("thread_id".to_string(), json!(20))]),
            ),
            (4, OpType::Delete, Some(2), None, None),
        ];

        // Full replay
        let mut full = Cache::new();
        full.init_table("t", &cols());
        for (_cid, op, row_id, row_data, updates) in &changes {
            full.apply_change("t", *op, *row_id, row_data.clone(), updates.as_deref());
        }

        // Partial replay (first 2), then clear and full replay
        let mut partial = Cache::new();
        partial.init_table("t", &cols());
        for (_cid, op, row_id, row_data, updates) in &changes[..2] {
            partial.apply_change("t", *op, *row_id, row_data.clone(), updates.as_deref());
        }
        partial.clear_all();
        partial.init_table("t", &cols());
        for (_cid, op, row_id, row_data, updates) in &changes {
            partial.apply_change("t", *op, *row_id, row_data.clone(), updates.as_deref());
        }

        // Same final state
        full.assert_invariants();
        partial.assert_invariants();
    }

    // ---------------------------------------------------------------
    // Broadcast simulation tests
    // ---------------------------------------------------------------

    #[test]
    fn foreign_broadcast_with_row_data_updates_cache() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());
        assert!(cache.is_table_complete("t"));

        // Simulate foreign broadcast insert with row data
        cache.apply_change("t", OpType::Insert, None, Some(make_row(2, 10, "b")), None);
        cache.assert_invariants();

        assert!(cache.get_row("t", 2).is_some());
        assert_eq!(cache.index_lookup("t", "thread_id", 10).len(), 2);
    }

    #[test]
    fn foreign_broadcast_without_row_data_marks_incomplete() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());
        assert!(cache.is_table_complete("t"));

        // Simulate foreign broadcast insert without row data
        cache.apply_change("t", OpType::Insert, None, None, None);
        cache.assert_invariants();

        assert!(!cache.is_table_complete("t"));
        // Existing rows preserved
        assert!(cache.get_row("t", 1).is_some());
    }

    #[test]
    fn update_indexed_column_via_broadcast() {
        let mut cache = Cache::new();
        cache.populate_full(
            "t",
            vec![make_row(1, 10, "a"), make_row(2, 20, "b")],
            &cols(),
        );

        // Broadcast: update row 1's thread_id from 10 → 30
        let updates = vec![("thread_id".to_string(), json!(30))];
        cache.apply_change("t", OpType::Update, Some(1), None, Some(&updates));
        cache.assert_invariants();

        assert!(cache.index_lookup("t", "thread_id", 10).is_empty());
        assert_eq!(cache.index_lookup("t", "thread_id", 30), vec![1]);
        assert_eq!(cache.index_lookup("t", "thread_id", 20), vec![2]);
    }

    #[test]
    fn update_indexed_column_invalidates_completeness_for_both_values() {
        let mut cache = Cache::new();

        // Populate thread_id=10 and thread_id=20 as complete values
        cache.populate_for_value("t", "thread_id", 10, vec![make_row(1, 10, "a")], &cols());
        cache.populate_for_value("t", "thread_id", 20, vec![make_row(2, 20, "b")], &cols());

        // Both values queryable
        assert!(cache
            .try_query("t", &[("thread_id".to_string(), 10)], &[])
            .is_some());
        assert!(cache
            .try_query("t", &[("thread_id".to_string(), 20)], &[])
            .is_some());

        // Update row 1: thread_id 10 → 20. This should invalidate completeness
        // for BOTH values (10 lost a row, 20 gained a row from outside its fetch).
        cache.update_row("t", 1, &[("thread_id".to_string(), json!(20))]);
        cache.assert_invariants();

        // Neither value should be queryable via index anymore
        assert!(cache
            .try_query("t", &[("thread_id".to_string(), 10)], &[])
            .is_none());
        assert!(cache
            .try_query("t", &[("thread_id".to_string(), 20)], &[])
            .is_none());
    }

    #[test]
    fn update_from_outside_cached_bucket_invalidates_bucket_completeness() {
        let mut cache = Cache::new();

        // Cache only the thread_id=10 bucket. Row 2 exists canonically, but it
        // was outside the fetched region so it is absent from the cache.
        cache.populate_for_value("t", "thread_id", 10, vec![make_row(1, 10, "a")], &cols());
        assert!(cache
            .try_query("t", &[("thread_id".to_string(), 10)], &[])
            .is_some());

        // Later, an authenticated update moves row 2 from some other bucket
        // into thread_id=10. Because row 2 is not cached locally, the update is
        // a no-op today, and completeness for thread_id=10 is left intact.
        let updates = vec![
            ("thread_id".to_string(), json!(10)),
            ("name".to_string(), json!("b")),
        ];
        cache.apply_change("t", OpType::Update, Some(2), None, Some(&updates));
        cache.assert_invariants();

        assert!(
            cache
                .try_query("t", &[("thread_id".to_string(), 10)], &[])
                .is_none(),
            "thread_id=10 should no longer be considered complete after an \
             uncached row is updated into that bucket"
        );
    }

    #[test]
    fn update_non_indexed_column_preserves_index() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());

        let updates = vec![("name".to_string(), json!("updated"))];
        cache.apply_change("t", OpType::Update, Some(1), None, Some(&updates));
        cache.assert_invariants();

        // Index unchanged
        assert_eq!(cache.index_lookup("t", "thread_id", 10), vec![1]);
        // Value updated
        assert_eq!(cache.get_row("t", 1).unwrap()["name"], "updated");
    }

    // ---------------------------------------------------------------
    // Recovery tests
    // ---------------------------------------------------------------

    #[test]
    fn reconnect_clears_cache_completely() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());

        // Simulate reconnect
        cache.clear_all();

        assert!(!cache.is_table_complete("t"));
        assert!(cache.try_query("t", &[], &[1]).is_none());
    }

    #[test]
    fn cache_rebuilt_after_clear() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());
        cache.clear_all();

        // Re-populate
        cache.populate_full(
            "t",
            vec![make_row(1, 10, "a"), make_row(2, 20, "b")],
            &cols(),
        );
        cache.assert_invariants();

        assert!(cache.is_table_complete("t"));
        assert_eq!(cache.try_query("t", &[], &[]).unwrap().len(), 2);
    }

    // ---------------------------------------------------------------
    // Edge case tests
    // ---------------------------------------------------------------

    #[test]
    fn insert_row_without_id_is_ignored() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![], &cols());

        cache.insert_row("t", json!({"thread_id": 10, "name": "no_id"}));
        cache.assert_invariants();

        // No rows added (missing id field)
        assert_eq!(cache.try_query("t", &[], &[]).unwrap().len(), 0);
    }

    #[test]
    fn update_nonexistent_row_is_noop() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());

        cache.update_row("t", 999, &[("thread_id".to_string(), json!(20))]);
        cache.assert_invariants();

        // Original unchanged
        assert_eq!(cache.index_lookup("t", "thread_id", 10), vec![1]);
    }

    #[test]
    fn remove_nonexistent_row_is_noop() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "a")], &cols());

        cache.remove_row("t", 999);
        cache.assert_invariants();

        assert!(cache.get_row("t", 1).is_some());
    }

    #[test]
    fn operations_on_nonexistent_table_are_safe() {
        let mut cache = Cache::new();

        cache.insert_row("ghost", make_row(1, 10, "a"));
        cache.update_row("ghost", 1, &[("thread_id".to_string(), json!(20))]);
        cache.remove_row("ghost", 1);
        cache.mark_table_incomplete("ghost");
        cache.invalidate_table("ghost");
        cache.assert_invariants();
    }

    #[test]
    fn insert_replaces_existing_row_with_same_id() {
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 10, "original")], &cols());

        // Re-inserting with a different indexed value should clean up old index entries
        cache.insert_row("t", make_row(1, 20, "replacement"));
        cache.assert_invariants();

        assert_eq!(cache.get_row("t", 1).unwrap()["name"], "replacement");
        assert!(cache.index_lookup("t", "thread_id", 10).is_empty());
        assert_eq!(cache.index_lookup("t", "thread_id", 20), vec![1]);
    }

    #[test]
    fn all_tables_complete_check() {
        let mut cache = Cache::new();
        cache.populate_full("a", vec![], &[]);
        cache.populate_full("b", vec![], &[]);

        assert!(cache.all_tables_complete(&["a", "b"]));
        assert!(!cache.all_tables_complete(&["a", "c"]));
    }

    #[test]
    fn get_all_rows_returns_none_for_incomplete() {
        let mut cache = Cache::new();
        cache.init_table("t", &[]);
        cache.insert_row("t", make_row(1, 10, "a"));

        assert!(cache.get_all_rows("t").is_none());
    }

    /// Build a cache with `n` rows. Each row has thread_id = i % 100, priority = i % 10.
    fn build_cache(n: i64) -> Cache {
        let mut cache = Cache::new();
        let rows: Vec<serde_json::Value> = (1..=n)
            .map(|i| json!({"id": i, "thread_id": i % 100, "priority": i % 10}))
            .collect();
        let cols = vec!["thread_id".to_string(), "priority".to_string()];
        cache.populate_full("t", rows, &cols);
        cache
    }

    // ---------------------------------------------------------------
    // Structural complexity tests
    //
    // These verify Big-O properties by checking the *structure* of the
    // data (result counts, index entry counts) rather than wall-clock
    // time, making them deterministic and debug-mode friendly.
    // ---------------------------------------------------------------

    #[test]
    fn complexity_index_lookup_returns_only_matching_rows() {
        // BTreeMap range scan returns O(result_size) entries, not O(N).
        // Verify by checking result counts at different table sizes.
        for n in [100, 1_000, 5_000] {
            let cache = build_cache(n);
            // With thread_id = i % 100, each bucket has exactly N/100 rows.
            let result = cache.index_lookup("t", "thread_id", 50);
            assert_eq!(
                result.len() as i64,
                n / 100,
                "index_lookup should return N/100 rows for N={n}"
            );
        }
    }

    #[test]
    fn complexity_insert_touches_k_indexes() {
        // insert_row does exactly K BTreeMap inserts (one per index).
        // Verify by checking index entry count after insert.
        let mut cache = Cache::new();
        let k_cols = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        cache.populate_full("t", vec![], &k_cols);

        cache.insert_row("t", json!({"id": 1, "a": 10, "b": 20, "c": 30}));

        // Each of the K=3 indexes should have exactly 1 entry
        let table = cache.tables.get("t").unwrap();
        for col in &k_cols {
            assert_eq!(
                table.indexes.get(col).unwrap().entries.len(),
                1,
                "index '{col}' should have 1 entry after 1 insert"
            );
        }

        // After N inserts, each index has N entries
        for i in 2..=100 {
            cache.insert_row("t", json!({"id": i, "a": i, "b": i, "c": i}));
        }
        let table = cache.tables.get("t").unwrap();
        for col in &k_cols {
            assert_eq!(
                table.indexes.get(col).unwrap().entries.len(),
                100,
                "index '{col}' should have 100 entries after 100 inserts"
            );
        }
    }

    #[test]
    fn complexity_update_replaces_exactly_one_entry_per_changed_index() {
        // update_row does at most K BTreeMap removes + K inserts.
        // Verify index entry count stays constant.
        let mut cache = build_cache(1_000);
        let table = cache.tables.get("t").unwrap();
        let entries_before: usize = table.indexes.values().map(|i| i.entries.len()).sum();

        // Update one row's indexed column
        cache.update_row("t", 1, &[("thread_id".to_string(), json!(999))]);

        let table = cache.tables.get("t").unwrap();
        let entries_after: usize = table.indexes.values().map(|i| i.entries.len()).sum();

        // Total index entries should stay the same (removed old, inserted new)
        assert_eq!(
            entries_before, entries_after,
            "update should not change total index entry count"
        );
    }

    #[test]
    fn complexity_remove_cleans_up_exactly_k_index_entries() {
        let mut cache = build_cache(100);
        let table = cache.tables.get("t").unwrap();
        let entries_before: usize = table.indexes.values().map(|i| i.entries.len()).sum();

        cache.remove_row("t", 1);

        let table = cache.tables.get("t").unwrap();
        let entries_after: usize = table.indexes.values().map(|i| i.entries.len()).sum();

        // Removed K=2 index entries (thread_id + priority)
        assert_eq!(
            entries_before - entries_after,
            2,
            "remove should clean up exactly K=2 index entries"
        );
    }

    #[test]
    fn complexity_populate_full_creates_n_times_k_index_entries() {
        let n = 500i64;
        let k = 2; // thread_id + priority
        let cache = build_cache(n);

        let table = cache.tables.get("t").unwrap();
        let total_entries: usize = table.indexes.values().map(|i| i.entries.len()).sum();

        assert_eq!(
            total_entries,
            (n as usize) * k,
            "populate_full should create N*K index entries"
        );
    }

    #[test]
    fn complexity_full_table_query_returns_all_n_rows() {
        for n in [10, 100, 1_000] {
            let mut cache = build_cache(n);
            let result = cache.try_query("t", &[], &[]).unwrap();
            assert_eq!(
                result.len() as i64,
                n,
                "full table query should return all N={n} rows"
            );
        }
    }

    #[test]
    fn complexity_id_lookup_returns_exactly_one_row() {
        // HashMap lookup is O(1) — verify it returns exactly 1 row
        // regardless of table size.
        for n in [10, 100, 1_000] {
            let mut cache = build_cache(n);
            cache.mark_table_incomplete("t");
            let result = cache.try_query("t", &[], &[1]).unwrap();
            assert_eq!(
                result.len(),
                1,
                "id lookup should return exactly 1 row for N={n}"
            );
        }
    }

    #[test]
    fn complexity_skewed_index_returns_proportional_results() {
        // Skewed distribution: 80% of rows in one bucket.
        // Index scan should return proportional to bucket size, not total N.
        let mut cache = Cache::new();
        let mut rows = Vec::new();
        for i in 1..=800 {
            rows.push(json!({"id": i, "thread_id": 1}));
        }
        for i in 801..=1000 {
            rows.push(json!({"id": i, "thread_id": i}));
        }
        cache.populate_for_value("t", "thread_id", 1, rows[..800].to_vec(), &cols());
        cache.populate_for_value("t", "thread_id", 801, vec![rows[800].clone()], &cols());

        let hot = cache
            .try_query("t", &[("thread_id".to_string(), 1)], &[])
            .unwrap();
        let cold = cache
            .try_query("t", &[("thread_id".to_string(), 801)], &[])
            .unwrap();

        assert_eq!(hot.len(), 800, "hot bucket should return 800 rows");
        assert_eq!(cold.len(), 1, "cold bucket should return 1 row");
    }

    #[test]
    fn complexity_btree_index_is_sorted() {
        // BTreeMap guarantees sorted iteration — verify index_lookup
        // returns row_ids in sorted order.
        let mut cache = Cache::new();
        // Insert in reverse order
        let rows: Vec<serde_json::Value> = (1..=100)
            .rev()
            .map(|i| json!({"id": i, "thread_id": 1}))
            .collect();
        cache.populate_full("t", rows, &cols());

        let ids = cache.index_lookup("t", "thread_id", 1);
        let sorted: Vec<i64> = (1..=100).collect();
        assert_eq!(
            ids, sorted,
            "BTreeMap index should return ids in sorted order"
        );
    }

    // ---------------------------------------------------------------
    // Index migration / pathological tests
    // ---------------------------------------------------------------

    #[test]
    fn repeated_bucket_moves_preserve_invariants() {
        // Row moves across index buckets 100 times. Catches ghost index entries.
        let mut cache = Cache::new();
        cache.populate_full("t", vec![make_row(1, 1, "a")], &cols());

        for i in 0..100 {
            cache.update_row("t", 1, &[("thread_id".to_string(), json!(i))]);
            cache.assert_invariants();
        }

        // Only the final value should be in the index
        assert_eq!(cache.index_lookup("t", "thread_id", 99), vec![1]);
        for i in 0..99 {
            assert!(
                cache.index_lookup("t", "thread_id", i).is_empty(),
                "ghost index entry at thread_id={i}"
            );
        }
    }

    #[test]
    fn noop_update_preserves_completeness() {
        // Updating a value to itself should not invalidate completeness.
        let mut cache = Cache::new();
        cache.populate_for_value("t", "thread_id", 10, vec![make_row(1, 10, "a")], &cols());

        // Update thread_id=10 → 10 (no change)
        cache.update_row("t", 1, &[("thread_id".to_string(), json!(10))]);
        cache.assert_invariants();

        // Completeness should be preserved
        let result = cache.try_query("t", &[("thread_id".to_string(), 10)], &[]);
        assert!(result.is_some(), "noop update should preserve completeness");
    }

    // ---------------------------------------------------------------
    // RefreshKeys broadcast regression tests
    // ---------------------------------------------------------------

    /// Verifies that inserting a row without an `id` field into a complete
    /// table silently no-ops, leaving the cache complete but stale.
    /// This documents why append-only broadcast inserts need special handling
    /// rather than a direct `insert_row` call.
    #[test]
    fn insert_row_without_id_leaves_complete_cache_stale() {
        let mut cache = Cache::new();
        cache.populate_full(KEY_HISTORY_TABLE_NAME, vec![make_row(1, 10, "a")], &cols());
        assert!(cache.is_table_complete(KEY_HISTORY_TABLE_NAME));
        assert!(cache.get_row(KEY_HISTORY_TABLE_NAME, 1).is_some());

        // Simulate what apply_change(Insert, None, Some(row_without_id)) does:
        // insert_row no-ops because the row has no id.
        let id_less_row = json!({"uid": 2, "old_auth_key": "abc", "valid_from_change_id": 0, "valid_to_change_id": 5});
        cache.insert_row(KEY_HISTORY_TABLE_NAME, id_less_row);
        cache.assert_invariants();

        // Cache is still complete — the insert was silently dropped.
        assert!(
            cache.is_table_complete(KEY_HISTORY_TABLE_NAME),
            "insert_row with no id should not change completeness"
        );
        // Only the original row is present.
        assert_eq!(
            cache
                .try_query(KEY_HISTORY_TABLE_NAME, &[], &[])
                .unwrap()
                .len(),
            1
        );
    }
}
