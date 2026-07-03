//! [`KvCache`] — anchored, splice-updated key/value cache for SDK queries.

use std::cell::Cell;
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_backend::merk_storage::keys::query_param_to_tuple_element;
use encrypted_spaces_backend::merk_storage::proofs::VerifiedRows;
use encrypted_spaces_backend::merk_storage::{
    determine_query_strategy, execute_query, group_columns_into_rows, index_ranges_for_predicate,
    parse_key, prefix_succ_required, process_query_results, reassemble_row,
    stored_value as merk_stored_value, ParsedKey, QueryStrategy, RowReadSource, ID_FIELD,
};
use encrypted_spaces_backend::query::{Order, Predicate, Query, QueryParam};
use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_changelog_core::{prefix_successor, ReadOp};
use encrypted_spaces_storage_encoding::keys;

use super::coverage_store::{CoverageStore, DataEntry};
use super::SyncDecryptResolver;
use crate::crypto::encrypted_field_types;

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
    /// Runtime kill-switch. When `false` the cache never returns a `Hit` and
    /// never accumulates entries. Controlled by the `CACHE_DISABLED` env var on
    /// native targets; always enabled on wasm (no `std::env` there).
    enabled: bool,
}

/// Whether the cache is enabled. On native, `CACHE_DISABLED=1`/`true` turns it
/// off; anything else (including unset) leaves it on. On wasm there is no
/// `std::env`, so the cache is always enabled.
fn cache_enabled() -> bool {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::env::var("CACHE_DISABLED")
            .map(|v| v != "1" && !v.eq_ignore_ascii_case("true"))
            .unwrap_or(true)
    }
    #[cfg(target_arch = "wasm32")]
    {
        true
    }
}

impl KvCache {
    pub fn new(anchor: DataCommitment) -> Self {
        Self {
            anchor,
            storage: CoverageStore::new(),
            enabled: cache_enabled(),
        }
    }

    #[cfg(test)]
    pub fn with_enabled(anchor: DataCommitment, enabled: bool) -> Self {
        Self {
            anchor,
            storage: CoverageStore::new(),
            enabled,
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
        if !self.enabled {
            return;
        }
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
        // When disabled, skip populating storage but still advance the anchor —
        // anchor bookkeeping is not cache data and downstream invariants depend
        // on it.
        if self.enabled {
            for w in update.writes {
                match w {
                    CacheWrite::Put(k, v) => self.storage.put_point(k, Some(v)),
                    CacheWrite::Delete(k) => self.storage.put_point(k, None),
                }
            }
            for (start, end) in update.coverage_extensions {
                self.storage.extend_coverage(start, end);
            }
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
        // Anchor matched — the splice is "applied" for the caller's purposes.
        // When disabled we skip storing anything but still report success.
        if !self.enabled {
            return true;
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
    /// A schema entry for the queried table is required before the cache may
    /// return `Hit`; this keeps encrypted cached bytes from being returned
    /// without the SDK-side decrypt pass. Non-id predicates still defer final
    /// indexed-column validation to the eventual server fetch when cache
    /// coverage cannot answer the query.
    pub fn try_select(
        &self,
        query: &Query,
        schemas: &HashMap<String, Schema>,
        decrypt: Option<&dyn SyncDecryptResolver>,
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        if !self.enabled {
            return Ok(CacheResult::Miss);
        }
        if decrypt.is_some_and(|context| context.anchor() != self.anchor) {
            return Ok(CacheResult::Miss);
        }

        let Some(schema) = schemas.get(table_schema_key(&query.table)) else {
            return Ok(CacheResult::Miss);
        };
        if decrypt.is_none() && schema_has_encrypted_columns(schema) {
            return Ok(CacheResult::Miss);
        }

        let reader = KvCacheReader::new(&self.storage, schemas, decrypt);

        if let Some(pred) = &query.predicate {
            if pred.column != ID_FIELD
                && !schemas
                    .get(table_schema_key(&query.table))
                    .is_some_and(|s| s.indexed_columns().contains(&pred.column.as_str()))
            {
                return self.full_table_fallback(query, schemas, decrypt);
            }
        }

        let strategy = determine_query_strategy(&reader, query)?;

        // ByIndex needs a two-phase coverage check: first the index range,
        // then scan the index to find matching row ids and confirm each
        // row range is also covered.
        if let QueryStrategy::ByIndex { predicate } = &strategy {
            match self.indexed_predicate_coverage(&query.table, predicate)? {
                IndexedCoverage::Covered => {
                    return self.execute_and_check(&reader, query);
                }
                IndexedCoverage::Missing => {
                    // Bucket isn't cached; try whole-table fallback (Trevor's
                    // FullTableFallbackOptions equivalent).
                    return self.full_table_fallback(query, schemas, decrypt);
                }
            }
        }

        let required = required_ranges_for_strategy(&strategy, &query.table)?;
        if required
            .iter()
            .all(|(s, e)| self.storage.covers_range(s, e))
        {
            return self.execute_and_check(&reader, query);
        }

        // Partial coverage + LIMIT: if the first L rows of the requested
        // scan order fit inside a covered prefix (Asc) or suffix (Desc),
        // we can answer the query without needing the rest of the range.
        if let Some(limit) = query.limit {
            if let Some(rows) =
                self.try_select_with_limit_partial(query, &required, limit, schemas, decrypt)?
            {
                return Ok(CacheResult::Hit(rows));
            }
        }
        Ok(CacheResult::Miss)
    }

    fn execute_and_check(
        &self,
        reader: &KvCacheReader<'_>,
        query: &Query,
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        let rows = execute_query(reader, query)?;
        if reader.decrypt_miss.get() {
            Ok(CacheResult::Miss)
        } else {
            Ok(CacheResult::Hit(rows))
        }
    }

    /// Whole-table fallback. If the cache has full coverage of the table's
    /// row-key range, scan every row, filter client-side by the query's
    /// predicate, and apply order/cursor/limit/projection. Matches Trevor's
    /// `FullTableFallbackOptions` path.
    fn full_table_fallback(
        &self,
        query: &Query,
        schemas: &HashMap<String, Schema>,
        decrypt: Option<&dyn SyncDecryptResolver>,
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        let start = keys::row_prefix(&query.table);
        let end = prefix_succ_required(&start)?;
        if !self.storage.covers_range(&start, &end) {
            return Ok(CacheResult::Miss);
        }
        let entries: CachedEntries<'_> = self
            .storage
            .iter_range_entries(&start, &end)
            .map(|(key, entry)| (key.as_slice(), entry))
            .collect();
        let Some(entries) = decrypt_cached_entries(&query.table, entries, schemas, decrypt)? else {
            return Ok(CacheResult::Miss);
        };
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
        schemas: &HashMap<String, Schema>,
        decrypt: Option<&dyn SyncDecryptResolver>,
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

        let entries: CachedEntries<'_> = self
            .storage
            .iter_range_entries(&effective_start, &effective_end)
            .map(|(key, entry)| (key.as_slice(), entry))
            .collect();
        let Some(entries) = decrypt_cached_entries(&query.table, entries, schemas, decrypt)? else {
            return Ok(None);
        };
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
        decrypt: Option<&dyn SyncDecryptResolver>,
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        if !self.enabled {
            return Ok(CacheResult::Miss);
        }
        if decrypt.is_some_and(|context| context.anchor() != self.anchor) {
            return Ok(CacheResult::Miss);
        }

        let Some(schema) = schemas.get(table_schema_key(joined_table)) else {
            return Ok(CacheResult::Miss);
        };
        if decrypt.is_none() && schema_has_encrypted_columns(schema) {
            return Ok(CacheResult::Miss);
        }

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
            return self.lookup_joined_rows_by_id(joined_table, &ids, schemas, decrypt);
        }

        if !schema.indexed_columns().contains(&pk_col) {
            return Ok(CacheResult::Miss);
        }

        let mut rows: Vec<serde_json::Value> = Vec::new();
        let mut seen_ids: BTreeSet<i64> = BTreeSet::new();
        for fk in fk_values {
            match self.lookup_indexed_join_value(
                joined_table,
                pk_col,
                fk,
                &mut seen_ids,
                schemas,
                decrypt,
            )? {
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
        schemas: &HashMap<String, Schema>,
        decrypt: Option<&dyn SyncDecryptResolver>,
    ) -> Result<CacheResult<Vec<serde_json::Value>>> {
        let reader = KvCacheReader::new(&self.storage, schemas, decrypt);
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
        if reader.decrypt_miss.get() {
            Ok(CacheResult::Miss)
        } else {
            Ok(CacheResult::Hit(rows))
        }
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
        schemas: &HashMap<String, Schema>,
        decrypt: Option<&dyn SyncDecryptResolver>,
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

        let reader = KvCacheReader::new(&self.storage, schemas, decrypt);
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
        if reader.decrypt_miss.get() {
            Ok(CacheResult::Miss)
        } else {
            Ok(CacheResult::Hit(rows))
        }
    }
}

/// Borrowed `RowReadSource` over a `CoverageStore`. The cache delegates
/// schema validation (which column is indexed) to the eventual server fetch
/// triggered on `Miss`, but row materialization still needs schemas so encrypted
/// cached columns can be decrypted before backend row assembly.
struct KvCacheReader<'a> {
    storage: &'a CoverageStore,
    schemas: &'a HashMap<String, Schema>,
    decrypt: Option<&'a dyn SyncDecryptResolver>,
    decrypt_miss: Cell<bool>,
}

impl<'a> KvCacheReader<'a> {
    fn new(
        storage: &'a CoverageStore,
        schemas: &'a HashMap<String, Schema>,
        decrypt: Option<&'a dyn SyncDecryptResolver>,
    ) -> Self {
        Self {
            storage,
            schemas,
            decrypt,
            decrypt_miss: Cell::new(false),
        }
    }

    fn decrypt_entries_for_table(
        &self,
        table_name: &str,
        entries: CachedEntries<'_>,
    ) -> Result<Option<KvPairs>> {
        let entries = decrypt_cached_entries(table_name, entries, self.schemas, self.decrypt)?;
        if entries.is_none() {
            self.decrypt_miss.set(true);
        }
        Ok(entries)
    }

    fn decrypt_entries_for_prefix(
        &self,
        prefix: &[u8],
        entries: CachedEntries<'_>,
    ) -> Result<Option<KvPairs>> {
        if entries.is_empty() {
            return Ok(Some(Vec::new()));
        }

        let table = match parse_key(prefix) {
            Ok(ParsedKey::Row { table, .. })
            | Ok(ParsedKey::RowPrefix { table })
            | Ok(ParsedKey::Column { table, .. }) => table,
            _ => match parse_key(entries[0].0) {
                Ok(ParsedKey::Column { table, .. }) => table,
                _ => {
                    return Ok(Some(
                        entries
                            .into_iter()
                            .filter_map(|(key, entry)| match entry {
                                DataEntry::Value { bytes, .. } => {
                                    Some((key.to_vec(), bytes.clone()))
                                }
                                DataEntry::Deleted => None,
                            })
                            .collect::<Vec<_>>(),
                    ));
                }
            },
        };

        self.decrypt_entries_for_table(&table, entries)
    }
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

type KvPairs = Vec<(Vec<u8>, Vec<u8>)>;
type CachedEntries<'a> = Vec<(&'a [u8], &'a DataEntry)>;

fn table_schema_key(table: &str) -> &str {
    table.split(" as ").next().unwrap_or(table).trim()
}

fn schema_has_encrypted_columns(schema: &Schema) -> bool {
    schema.columns.iter().any(|column| !column.plaintext)
}

fn decrypt_cached_entries(
    table: &str,
    entries: CachedEntries<'_>,
    schemas: &HashMap<String, Schema>,
    decrypt: Option<&dyn SyncDecryptResolver>,
) -> Result<Option<KvPairs>> {
    let table_key = table_schema_key(table);
    let Some(schema) = schemas.get(table_key) else {
        return Ok(None);
    };
    let schema_columns: BTreeSet<&str> = schema.columns.iter().map(|c| c.name.as_str()).collect();
    let encrypted_columns = encrypted_field_types(schema);

    let mut pairs = Vec::with_capacity(entries.len());
    let mut warm: Vec<(&OnceLock<Vec<u8>>, Vec<u8>)> = Vec::new();

    for (key, entry) in entries {
        let DataEntry::Value { bytes, decrypted } = entry else {
            continue;
        };

        let parsed = parse_key(key);
        let Ok(ParsedKey::Column {
            table: key_table,
            column,
            ..
        }) = parsed
        else {
            pairs.push((key.to_vec(), bytes.clone()));
            continue;
        };

        if key_table.as_str() != table_key || !schema_columns.contains(column.as_str()) {
            return Ok(None);
        }

        let Some(field_type) = encrypted_columns.get(&column) else {
            pairs.push((key.to_vec(), bytes.clone()));
            continue;
        };

        if let Some(plaintext) = decrypted.get() {
            pairs.push((key.to_vec(), plaintext.clone()));
            continue;
        }

        let value = match merk_stored_value::bytes_to_value(bytes) {
            Ok(value) => value,
            Err(error) => {
                log::warn!(
                    "Failed to decode cached encrypted-column bytes, treating as miss: {error}"
                );
                return Ok(None);
            }
        };
        let serde_json::Value::String(encoded) = value else {
            return Ok(None);
        };
        let Some(decrypt) = decrypt else {
            return Ok(None);
        };

        let plaintext = match decrypt.decrypt_column_bytes(&encoded, field_type) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                log::warn!(
                    "Failed to decrypt cached column synchronously, treating as miss: {error}"
                );
                return Ok(None);
            }
        };
        pairs.push((key.to_vec(), plaintext.clone()));
        warm.push((decrypted, plaintext));
    }

    for (slot, plaintext) in warm {
        let _ = slot.set(plaintext);
    }

    Ok(Some(pairs))
}

impl<'a> RowReadSource for KvCacheReader<'a> {
    fn validate_column_indexed(&self, _table_name: &str, _column: &str) -> Result<()> {
        // Indexed-column validation is still deferred to `try_select` coverage
        // checks and, on Miss, the server fetch. Saying Ok here keeps the
        // shared planner from spuriously erroring before the cache can decide.
        Ok(())
    }

    fn get_row_by_id(&self, table_name: &str, row_id: i64) -> Result<Option<serde_json::Value>> {
        let prefix = keys::row_key(table_name, row_id);
        let columns: CachedEntries<'_> = self
            .storage
            .iter_prefix_entries(&prefix)
            .map(|(key, entry)| (key.as_slice(), entry))
            .collect();
        if columns.is_empty() {
            return Ok(None);
        }
        let Some(columns) = self.decrypt_entries_for_table(table_name, columns)? else {
            return Ok(None);
        };
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
        let entries: CachedEntries<'_> = self
            .storage
            .iter_range_entries(&start_key, &end_key)
            .map(|(key, entry)| (key.as_slice(), entry))
            .collect();
        let Some(entries) = self.decrypt_entries_for_table(table_name, entries)? else {
            return Ok(Vec::new());
        };
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
        let entries: CachedEntries<'_> = self
            .storage
            .iter_prefix_entries(prefix)
            .map(|(key, entry)| (key.as_slice(), entry))
            .collect();
        let Some(entries) = self.decrypt_entries_for_prefix(prefix, entries)? else {
            return Ok(Vec::new());
        };
        Ok(entries)
    }

    fn scan_table(&self, table_name: &str) -> Result<Vec<serde_json::Value>> {
        let prefix = keys::row_prefix(table_name);
        let entries: CachedEntries<'_> = self
            .storage
            .iter_prefix_entries(&prefix)
            .map(|(key, entry)| (key.as_slice(), entry))
            .collect();
        let Some(entries) = self.decrypt_entries_for_table(table_name, entries)? else {
            return Ok(Vec::new());
        };
        group_columns_into_rows(&entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_decrypt::SyncDecryptContext;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use encrypted_spaces_backend::error::Result as SdkResult;
    use encrypted_spaces_backend::query::{ComparisonOperator, Order, QueryOperation, QueryParam};
    use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType};
    use encrypted_spaces_crypto::encryption::{encrypt_field, EncryptionKey, FieldType};
    use encrypted_spaces_key_manager::SimpleKeyId;
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

    fn plaintext_text_schema(table: &str) -> Schema {
        schema_with_columns(table, vec![("id", true, false), ("text", true, false)])
    }

    fn anchor(byte: u8) -> DataCommitment {
        [byte; 32]
    }

    #[test]
    fn miss_when_empty() {
        let cache = KvCache::new([0; 32]);
        let result = cache
            .try_select(&select_all_query(TABLE), &HashMap::new(), None)
            .unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn disabled_cache_always_misses() {
        let mut cache = KvCache::with_enabled([0; 32], false);
        let verified = full_table_verified(
            TABLE,
            &[
                (1, "text", serde_json::json!("hello")),
                (2, "text", serde_json::json!("world")),
            ],
        );
        // Ingest is accepted (anchor matched) but stores nothing.
        assert!(cache.apply_select([0; 32], &verified));
        assert_eq!(cache.storage.point_count(), 0);

        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let result = cache
            .try_select(&select_all_query(TABLE), &schemas, None)
            .unwrap();
        assert!(matches!(result, CacheResult::Miss));
    }

    #[test]
    fn enabled_cache_hits() {
        // Control for `disabled_cache_always_misses`: the same ingest hits when
        // the cache is enabled.
        let mut cache = KvCache::with_enabled([0; 32], true);
        let verified = full_table_verified(
            TABLE,
            &[
                (1, "text", serde_json::json!("hello")),
                (2, "text", serde_json::json!("world")),
            ],
        );
        assert!(cache.apply_select([0; 32], &verified));
        assert_eq!(cache.storage.point_count(), 2);

        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let result = cache
            .try_select(&select_all_query(TABLE), &schemas, None)
            .unwrap();
        assert!(matches!(result, CacheResult::Hit(_)));
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
        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let result = cache
            .try_select(&select_all_query(TABLE), &schemas, None)
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
        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let result = cache
            .try_select(&select_by_id(TABLE, 2), &schemas, None)
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
    fn missing_schema_misses_even_with_cached_encrypted_bytes() {
        let mut cache = KvCache::new([0; 32]);
        let verified = full_table_verified(
            TABLE,
            &[(1, "secret", serde_json::json!("encrypted-ciphertext"))],
        );
        cache.apply_select([0; 32], &verified);

        let result = cache
            .try_select(&select_all_query(TABLE), &HashMap::new(), None)
            .unwrap();

        assert!(matches!(result, CacheResult::Miss));
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
        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let result = cache
            .try_select(&select_by_id(TABLE, 2), &schemas, None)
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
        assert_eq!(cache.storage.get_point(&row_key), Some(&DataEntry::Deleted));
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
        assert_eq!(cache.storage.get_point(&k), Some(&DataEntry::value(v)));
        assert_eq!(
            cache.storage.get_point(&keys::row_key(TABLE, 6)),
            Some(&DataEntry::Deleted)
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
        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let result = cache
            .try_select(&select_all_query(TABLE), &schemas, None)
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
        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let result = cache
            .try_select(&select_all_query(TABLE), &schemas, None)
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
        let result = cache.try_select(&q, &HashMap::new(), None).unwrap();
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
        let result = cache.try_select(&q, &schemas, None).unwrap();
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
        let result = cache.try_select(&q, &schemas, None).unwrap();
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

        let result = cache
            .try_select(&select_by_id(TABLE, 7), &schemas, None)
            .unwrap();
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

        let result = cache
            .try_select(&select_by_id(TABLE, 7), &schemas, None)
            .unwrap();
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
        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let result = cache.try_select(&q, &schemas, None).unwrap();
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
        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let result = cache.try_select(&q, &schemas, None).unwrap();
        assert!(
            matches!(result, CacheResult::Miss),
            "limit(2) should miss when only 1 row covered"
        );
    }

    // ===== Stage 4 (§5.2): decrypt memoization — the "decrypt once" win =====
    //
    // The server-query counter (`CountingTransport`) cannot observe this:
    // decrypt memoization does NOT change which queries hit vs. miss. These
    // tests instrument the decrypt path directly with a spy resolver so they
    // can prove that repeated cache hits over the same cached bytes perform
    // the AES work exactly once.

    /// Test-only resolver that wraps a real [`SyncDecryptContext`] and counts
    /// how many times the cache actually performs a column decrypt.
    struct CountingResolver<'a> {
        inner: &'a SyncDecryptContext,
        calls: std::cell::Cell<usize>,
    }

    impl<'a> CountingResolver<'a> {
        fn new(inner: &'a SyncDecryptContext) -> Self {
            Self {
                inner,
                calls: std::cell::Cell::new(0),
            }
        }

        fn count(&self) -> usize {
            self.calls.get()
        }
    }

    impl SyncDecryptResolver for CountingResolver<'_> {
        fn anchor(&self) -> DataCommitment {
            self.inner.anchor()
        }

        fn decrypt_column_bytes(
            &self,
            encoded: &str,
            field_type: &FieldType,
        ) -> SdkResult<Vec<u8>> {
            self.calls.set(self.calls.get() + 1);
            self.inner.decrypt_column_bytes(encoded, field_type)
        }
    }

    /// Encrypt `plaintext` under `key_id`/`key_bytes` and base64-encode it the
    /// way an encrypted column is stored in the cache (a `Value::String`).
    fn encrypt_text(plaintext: &str, key_id: u64, key_bytes: [u8; 32]) -> String {
        let key = EncryptionKey::new(key_bytes, &SimpleKeyId(key_id));
        STANDARD.encode(encrypt_field(plaintext.as_bytes(), &key))
    }

    /// Schema with a plaintext `id` and an *encrypted* `secret` text column.
    fn encrypted_text_schema(table: &str) -> Schema {
        use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType};
        Schema {
            name: table.to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "secret".to_string(),
                    column_type: ColumnType::Text,
                    plaintext: false,
                    indexed: false,
                },
            ],
            auto_increment: true,
        }
    }

    /// A [`SyncDecryptContext`] anchored at `anchor` holding a single data key.
    fn sync_context(
        anchor: DataCommitment,
        key_id: u64,
        key_bytes: [u8; 32],
    ) -> SyncDecryptContext {
        let keys = HashMap::from([(SimpleKeyId(key_id), key_bytes)]);
        SyncDecryptContext::new(anchor, keys)
    }

    fn hit_rows(result: CacheResult<Vec<serde_json::Value>>) -> Vec<serde_json::Value> {
        match result {
            CacheResult::Hit(rows) => rows,
            CacheResult::Miss => panic!("expected cache Hit"),
        }
    }

    #[test]
    fn encrypted_cache_hit_memoizes_decrypt() {
        let anchor = [1u8; 32];
        let key_bytes = [0x42u8; 32];

        let mut cache = KvCache::new(anchor);
        let verified = full_table_verified(
            TABLE,
            &[(
                1,
                "secret",
                serde_json::Value::String(encrypt_text("secret_1", 0, key_bytes)),
            )],
        );
        assert!(cache.apply_select(anchor, &verified));

        let schemas = HashMap::from([(TABLE.to_string(), encrypted_text_schema(TABLE))]);
        let ctx = sync_context(anchor, 0, key_bytes);
        let resolver = CountingResolver::new(&ctx);

        // First read: exactly one decrypt, plaintext materialized.
        let rows1 = hit_rows(
            cache
                .try_select(&select_all_query(TABLE), &schemas, Some(&resolver))
                .unwrap(),
        );
        assert_eq!(rows1.len(), 1);
        assert_eq!(
            rows1[0].get("secret").and_then(|v| v.as_str()),
            Some("secret_1")
        );
        assert_eq!(
            resolver.count(),
            1,
            "first read should decrypt exactly once"
        );

        // The per-entry memo slot is warm after the first read.
        let col_key = keys::column_key(TABLE, 1, "secret");
        match cache.storage.get_point(&col_key).expect("cached entry") {
            DataEntry::Value { decrypted, .. } => assert!(
                decrypted.get().is_some(),
                "OnceLock memo should be populated after the first decrypt"
            ),
            DataEntry::Deleted => panic!("unexpected tombstone"),
        }

        // Second read: served from the memo — no additional decrypt.
        let rows2 = hit_rows(
            cache
                .try_select(&select_all_query(TABLE), &schemas, Some(&resolver))
                .unwrap(),
        );
        assert_eq!(rows2, rows1);
        assert_eq!(
            resolver.count(),
            1,
            "second read must reuse the memo (decrypt once across two hits)"
        );
    }

    #[test]
    fn distinct_encrypted_rows_decrypt_independently() {
        let anchor = [1u8; 32];
        let key_bytes = [0x42u8; 32];

        let mut cache = KvCache::new(anchor);
        let verified = full_table_verified(
            TABLE,
            &[
                (
                    1,
                    "secret",
                    serde_json::Value::String(encrypt_text("secret_1", 0, key_bytes)),
                ),
                (
                    2,
                    "secret",
                    serde_json::Value::String(encrypt_text("secret_2", 0, key_bytes)),
                ),
            ],
        );
        assert!(cache.apply_select(anchor, &verified));

        let schemas = HashMap::from([(TABLE.to_string(), encrypted_text_schema(TABLE))]);
        let ctx = sync_context(anchor, 0, key_bytes);
        let resolver = CountingResolver::new(&ctx);

        // Read row 1 — one decrypt.
        let r1 = hit_rows(
            cache
                .try_select(&select_by_id(TABLE, 1), &schemas, Some(&resolver))
                .unwrap(),
        );
        assert_eq!(
            r1[0].get("secret").and_then(|v| v.as_str()),
            Some("secret_1")
        );
        assert_eq!(resolver.count(), 1);

        // A *different* encrypted row is a separate entry → its own decrypt.
        let r2 = hit_rows(
            cache
                .try_select(&select_by_id(TABLE, 2), &schemas, Some(&resolver))
                .unwrap(),
        );
        assert_eq!(
            r2[0].get("secret").and_then(|v| v.as_str()),
            Some("secret_2")
        );
        assert_eq!(
            resolver.count(),
            2,
            "a distinct row must increment the decrypt count (memo is per entry)"
        );

        // Re-reading row 1 hits its warm memo — count stays at 2.
        let _ = hit_rows(
            cache
                .try_select(&select_by_id(TABLE, 1), &schemas, Some(&resolver))
                .unwrap(),
        );
        assert_eq!(
            resolver.count(),
            2,
            "row 1's memo must still be warm after reading row 2"
        );
    }

    #[test]
    fn n_encrypted_rows_decrypt_once_each_across_reread() {
        let anchor = [1u8; 32];
        let key_bytes = [0x42u8; 32];
        const N: i64 = 5;

        let mut cache = KvCache::new(anchor);
        let entries: Vec<(i64, &str, serde_json::Value)> = (1..=N)
            .map(|id| {
                let ciphertext = encrypt_text(&format!("secret_{id}"), 0, key_bytes);
                (id, "secret", serde_json::Value::String(ciphertext))
            })
            .collect();
        let verified = full_table_verified(TABLE, &entries);
        assert!(cache.apply_select(anchor, &verified));

        let schemas = HashMap::from([(TABLE.to_string(), encrypted_text_schema(TABLE))]);
        let ctx = sync_context(anchor, 0, key_bytes);
        let resolver = CountingResolver::new(&ctx);

        // First scan decrypts each of the N rows once.
        let rows1 = hit_rows(
            cache
                .try_select(&select_all_query(TABLE), &schemas, Some(&resolver))
                .unwrap(),
        );
        assert_eq!(rows1.len(), N as usize);
        assert_eq!(
            resolver.count(),
            N as usize,
            "each of N rows decrypts exactly once on the first scan"
        );

        // Re-scan: every row served from its memo — still N decrypts, not 2N.
        let rows2 = hit_rows(
            cache
                .try_select(&select_all_query(TABLE), &schemas, Some(&resolver))
                .unwrap(),
        );
        assert_eq!(rows2, rows1);
        assert_eq!(
            resolver.count(),
            N as usize,
            "re-reading N rows must reuse memos: N decrypts total, not 2N"
        );
    }

    // ===== Stage 5 (§6): safety / adversarial gates =====

    #[derive(Clone)]
    struct EncryptedFieldCase {
        label: &'static str,
        column_type: ColumnType,
        plaintext: Vec<u8>,
        expected: serde_json::Value,
    }

    #[derive(Clone, Copy, Debug)]
    enum CacheSafetyPath {
        TableScan,
        ById,
        IdRange,
        IndexedPredicate,
        FullTableFallback,
        LimitPartial,
        PkJoin,
        IndexedJoin,
    }

    impl CacheSafetyPath {
        fn label(self) -> &'static str {
            match self {
                CacheSafetyPath::TableScan => "table_scan",
                CacheSafetyPath::ById => "by_id",
                CacheSafetyPath::IdRange => "id_range",
                CacheSafetyPath::IndexedPredicate => "indexed_predicate",
                CacheSafetyPath::FullTableFallback => "full_table_fallback",
                CacheSafetyPath::LimitPartial => "limit_partial",
                CacheSafetyPath::PkJoin => "pk_join",
                CacheSafetyPath::IndexedJoin => "indexed_join",
            }
        }
    }

    fn all_safety_paths() -> [CacheSafetyPath; 8] {
        [
            CacheSafetyPath::TableScan,
            CacheSafetyPath::ById,
            CacheSafetyPath::IdRange,
            CacheSafetyPath::IndexedPredicate,
            CacheSafetyPath::FullTableFallback,
            CacheSafetyPath::LimitPartial,
            CacheSafetyPath::PkJoin,
            CacheSafetyPath::IndexedJoin,
        ]
    }

    fn encrypted_field_cases() -> Vec<EncryptedFieldCase> {
        let blob = vec![0x00, 0x01, 0x02, 0xFF];
        vec![
            EncryptedFieldCase {
                label: "integer_1_byte",
                column_type: ColumnType::Integer,
                plaintext: vec![7],
                expected: serde_json::json!(7),
            },
            EncryptedFieldCase {
                label: "integer_8_byte",
                column_type: ColumnType::Integer,
                plaintext: 7_000_000_000_i64.to_be_bytes().to_vec(),
                expected: serde_json::json!(7_000_000_000_i64),
            },
            EncryptedFieldCase {
                label: "string",
                column_type: ColumnType::String,
                plaintext: b"short-string".to_vec(),
                expected: serde_json::json!("short-string"),
            },
            EncryptedFieldCase {
                label: "real",
                column_type: ColumnType::Real,
                plaintext: 42.25_f64.to_be_bytes().to_vec(),
                expected: serde_json::json!(42.25_f64),
            },
            EncryptedFieldCase {
                label: "text",
                column_type: ColumnType::Text,
                plaintext: b"longer text value".to_vec(),
                expected: serde_json::json!("longer text value"),
            },
            EncryptedFieldCase {
                label: "blob",
                column_type: ColumnType::Blob,
                plaintext: blob.clone(),
                expected: serde_json::json!(STANDARD.encode(&blob)),
            },
        ]
    }

    fn column_def(
        name: &str,
        column_type: ColumnType,
        plaintext: bool,
        indexed: bool,
    ) -> ColumnDefinition {
        ColumnDefinition {
            name: name.to_string(),
            column_type,
            plaintext,
            indexed,
        }
    }

    fn encrypted_value_schema(
        table: &str,
        encrypted_column_type: ColumnType,
        mut extra_columns: Vec<ColumnDefinition>,
    ) -> Schema {
        let mut columns = vec![column_def("id", ColumnType::Integer, true, false)];
        columns.append(&mut extra_columns);
        columns.push(column_def("secret", encrypted_column_type, false, false));
        Schema {
            name: table.to_string(),
            columns,
            auto_increment: true,
        }
    }

    fn row_range(table: &str, row_id: i64) -> (Vec<u8>, Vec<u8>) {
        let start = keys::row_key(table, row_id);
        let end = prefix_successor(&start).unwrap();
        (start, end)
    }

    fn table_range(table: &str) -> (Vec<u8>, Vec<u8>) {
        let start = keys::row_prefix(table);
        let end = prefix_successor(&start).unwrap();
        (start, end)
    }

    fn verified_from_parts(
        mut kv_pairs: Vec<(Vec<u8>, Vec<u8>)>,
        read_ops: Vec<ReadOp>,
    ) -> VerifiedRows {
        kv_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        VerifiedRows {
            main_rows: Vec::new(),
            rows_by_table: HashMap::new(),
            kv_pairs,
            read_ops,
        }
    }

    fn encrypt_bytes(plaintext: &[u8], key_id: u64, key_bytes: [u8; 32]) -> String {
        let key = EncryptionKey::new(key_bytes, &SimpleKeyId(key_id));
        STANDARD.encode(encrypt_field(plaintext, &key))
    }

    fn encrypted_cell(plaintext: &[u8], key_id: u64, key_bytes: [u8; 32]) -> serde_json::Value {
        serde_json::Value::String(encrypt_bytes(plaintext, key_id, key_bytes))
    }

    fn index_kv(table: &str, column: &str, value: QueryParam, row_id: i64) -> (Vec<u8>, Vec<u8>) {
        let key =
            keys::index_key(table, column, query_param_to_tuple_element(&value), row_id).unwrap();
        (key, Vec::new())
    }

    fn id_between_query(table: &str, start: i64, end: i64) -> Query {
        Query {
            table: table.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Between,
                values: vec![QueryParam::Integer(start), QueryParam::Integer(end)],
                cursor_id: None,
            }),
            join: None,
            order: Order::Asc,
            limit: None,
        }
    }

    fn equality_query(table: &str, column: &str, value: QueryParam) -> Query {
        Query {
            table: table.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: Some(Predicate {
                column: column.to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![value],
                cursor_id: None,
            }),
            join: None,
            order: Order::Asc,
            limit: None,
        }
    }

    fn limited_scan_query(table: &str, limit: u32) -> Query {
        Query {
            table: table.to_string(),
            operation: QueryOperation::Select(Vec::new()),
            predicate: None,
            join: None,
            order: Order::Asc,
            limit: Some(limit),
        }
    }

    fn schemas_for(schema: Schema) -> HashMap<String, Schema> {
        HashMap::from([(schema.name.clone(), schema)])
    }

    fn expected_safety_row(path: CacheSafetyPath, case: &EncryptedFieldCase) -> serde_json::Value {
        let mut row = serde_json::Map::from_iter([
            (
                "id".to_string(),
                serde_json::Value::Number(serde_json::Number::from(1)),
            ),
            ("secret".to_string(), case.expected.clone()),
        ]);
        match path {
            CacheSafetyPath::IndexedPredicate => {
                row.insert("category".to_string(), serde_json::json!(7));
            }
            CacheSafetyPath::FullTableFallback => {
                row.insert("filter".to_string(), serde_json::json!(7));
            }
            CacheSafetyPath::IndexedJoin => {
                row.insert("code".to_string(), serde_json::json!("A"));
            }
            CacheSafetyPath::TableScan
            | CacheSafetyPath::ById
            | CacheSafetyPath::IdRange
            | CacheSafetyPath::LimitPartial
            | CacheSafetyPath::PkJoin => {}
        }
        serde_json::Value::Object(row)
    }

    fn run_safety_path(
        path: CacheSafetyPath,
        case: &EncryptedFieldCase,
        secret_value: serde_json::Value,
        anchor: DataCommitment,
        decrypt: Option<&dyn SyncDecryptResolver>,
    ) -> SdkResult<CacheResult<Vec<serde_json::Value>>> {
        let table = format!("safety_{}", path.label());
        let mut cache = KvCache::new(anchor);

        match path {
            CacheSafetyPath::TableScan => {
                let (start, end) = table_range(&table);
                let verified = verified_from_parts(
                    vec![col_kv(&table, 1, "secret", secret_value)],
                    vec![ReadOp::Range { start, end }],
                );
                assert!(cache.apply_select(anchor, &verified));
                let schemas = schemas_for(encrypted_value_schema(
                    &table,
                    case.column_type.clone(),
                    Vec::new(),
                ));
                cache.try_select(&select_all_query(&table), &schemas, decrypt)
            }
            CacheSafetyPath::ById => {
                let (start, end) = row_range(&table, 1);
                let verified = verified_from_parts(
                    vec![col_kv(&table, 1, "secret", secret_value)],
                    vec![ReadOp::Range { start, end }],
                );
                assert!(cache.apply_select(anchor, &verified));
                let schemas = schemas_for(encrypted_value_schema(
                    &table,
                    case.column_type.clone(),
                    Vec::new(),
                ));
                cache.try_select(&select_by_id(&table, 1), &schemas, decrypt)
            }
            CacheSafetyPath::IdRange => {
                let (start, end) = row_range(&table, 1);
                let verified = verified_from_parts(
                    vec![col_kv(&table, 1, "secret", secret_value)],
                    vec![ReadOp::Range { start, end }],
                );
                assert!(cache.apply_select(anchor, &verified));
                let schemas = schemas_for(encrypted_value_schema(
                    &table,
                    case.column_type.clone(),
                    Vec::new(),
                ));
                cache.try_select(&id_between_query(&table, 1, 1), &schemas, decrypt)
            }
            CacheSafetyPath::IndexedPredicate => {
                let (table_start, table_end) = table_range(&table);
                let index_prefix = keys::index_value_prefix(
                    &table,
                    "category",
                    query_param_to_tuple_element(&QueryParam::Integer(7)),
                )
                .unwrap();
                let verified = verified_from_parts(
                    vec![
                        col_kv(&table, 1, "category", serde_json::json!(7)),
                        col_kv(&table, 1, "secret", secret_value),
                        index_kv(&table, "category", QueryParam::Integer(7), 1),
                    ],
                    vec![
                        ReadOp::Range {
                            start: table_start,
                            end: table_end,
                        },
                        ReadOp::Prefix(index_prefix),
                    ],
                );
                assert!(cache.apply_select(anchor, &verified));
                let schemas = schemas_for(encrypted_value_schema(
                    &table,
                    case.column_type.clone(),
                    vec![column_def("category", ColumnType::Integer, true, true)],
                ));
                cache.try_select(
                    &equality_query(&table, "category", QueryParam::Integer(7)),
                    &schemas,
                    decrypt,
                )
            }
            CacheSafetyPath::FullTableFallback => {
                let (start, end) = table_range(&table);
                let verified = verified_from_parts(
                    vec![
                        col_kv(&table, 1, "filter", serde_json::json!(7)),
                        col_kv(&table, 1, "secret", secret_value),
                    ],
                    vec![ReadOp::Range { start, end }],
                );
                assert!(cache.apply_select(anchor, &verified));
                let schemas = schemas_for(encrypted_value_schema(
                    &table,
                    case.column_type.clone(),
                    vec![column_def("filter", ColumnType::Integer, true, false)],
                ));
                cache.try_select(
                    &equality_query(&table, "filter", QueryParam::Integer(7)),
                    &schemas,
                    decrypt,
                )
            }
            CacheSafetyPath::LimitPartial => {
                let (table_start, _) = table_range(&table);
                let (_, row_end) = row_range(&table, 1);
                let verified = verified_from_parts(
                    vec![col_kv(&table, 1, "secret", secret_value)],
                    vec![ReadOp::Range {
                        start: table_start,
                        end: row_end,
                    }],
                );
                assert!(cache.apply_select(anchor, &verified));
                let schemas = schemas_for(encrypted_value_schema(
                    &table,
                    case.column_type.clone(),
                    Vec::new(),
                ));
                cache.try_select(&limited_scan_query(&table, 1), &schemas, decrypt)
            }
            CacheSafetyPath::PkJoin => {
                let (start, end) = row_range(&table, 1);
                let verified = verified_from_parts(
                    vec![col_kv(&table, 1, "secret", secret_value)],
                    vec![ReadOp::Range { start, end }],
                );
                assert!(cache.apply_select(anchor, &verified));
                let schemas = schemas_for(encrypted_value_schema(
                    &table,
                    case.column_type.clone(),
                    Vec::new(),
                ));
                cache.lookup_joined_rows(&table, "id", &[serde_json::json!(1)], &schemas, decrypt)
            }
            CacheSafetyPath::IndexedJoin => {
                let (row_start, row_end) = row_range(&table, 1);
                let index_prefix = keys::index_value_prefix(
                    &table,
                    "code",
                    query_param_to_tuple_element(&QueryParam::Text("A".to_string())),
                )
                .unwrap();
                let verified = verified_from_parts(
                    vec![
                        col_kv(&table, 1, "code", serde_json::json!("A")),
                        col_kv(&table, 1, "secret", secret_value),
                        index_kv(&table, "code", QueryParam::Text("A".to_string()), 1),
                    ],
                    vec![
                        ReadOp::Range {
                            start: row_start,
                            end: row_end,
                        },
                        ReadOp::Prefix(index_prefix),
                    ],
                );
                assert!(cache.apply_select(anchor, &verified));
                let schemas = schemas_for(encrypted_value_schema(
                    &table,
                    case.column_type.clone(),
                    vec![column_def("code", ColumnType::String, true, true)],
                ));
                cache.lookup_joined_rows(
                    &table,
                    "code",
                    &[serde_json::json!("A")],
                    &schemas,
                    decrypt,
                )
            }
        }
    }

    fn expect_hit_for(
        result: CacheResult<Vec<serde_json::Value>>,
        path: CacheSafetyPath,
        case_label: &str,
    ) -> Vec<serde_json::Value> {
        match result {
            CacheResult::Hit(rows) => rows,
            CacheResult::Miss => panic!(
                "expected encrypted cache hit for path={} field={case_label}",
                path.label()
            ),
        }
    }

    #[test]
    fn encrypted_hit_parity_across_paths_and_field_types() {
        let anchor = anchor(11);
        let key_bytes = [0x42u8; 32];
        let ctx = sync_context(anchor, 0, key_bytes);

        for path in all_safety_paths() {
            for case in encrypted_field_cases() {
                let secret = encrypted_cell(&case.plaintext, 0, key_bytes);
                let rows = expect_hit_for(
                    run_safety_path(path, &case, secret, anchor, Some(&ctx)).unwrap(),
                    path,
                    case.label,
                );
                assert_eq!(
                    rows,
                    vec![expected_safety_row(path, &case)],
                    "cache-hit plaintext mismatch for path={} field={}",
                    path.label(),
                    case.label
                );
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum DecryptFailureKind {
        MissingKey,
        InvalidBase64,
        TruncatedCiphertext,
    }

    impl DecryptFailureKind {
        fn label(self) -> &'static str {
            match self {
                DecryptFailureKind::MissingKey => "missing_key",
                DecryptFailureKind::InvalidBase64 => "invalid_base64",
                DecryptFailureKind::TruncatedCiphertext => "truncated_ciphertext",
            }
        }
    }

    fn failure_secret(kind: DecryptFailureKind) -> serde_json::Value {
        match kind {
            DecryptFailureKind::MissingKey => encrypted_cell(b"unavailable", 99, [0x99; 32]),
            DecryptFailureKind::InvalidBase64 => {
                serde_json::Value::String("not-valid-b64!!!".to_string())
            }
            DecryptFailureKind::TruncatedCiphertext => {
                serde_json::Value::String(STANDARD.encode([0x02, 0x00]))
            }
        }
    }

    fn encrypted_text_case() -> EncryptedFieldCase {
        EncryptedFieldCase {
            label: "text",
            column_type: ColumnType::Text,
            plaintext: b"secret".to_vec(),
            expected: serde_json::json!("secret"),
        }
    }

    #[test]
    fn decrypt_failures_miss_cleanly_across_paths() {
        let anchor = anchor(12);
        let key_bytes = [0x42u8; 32];
        let ctx = sync_context(anchor, 0, key_bytes);
        let case = encrypted_text_case();
        let failures = [
            DecryptFailureKind::MissingKey,
            DecryptFailureKind::InvalidBase64,
            DecryptFailureKind::TruncatedCiphertext,
        ];

        for path in all_safety_paths() {
            for failure in failures {
                let result =
                    run_safety_path(path, &case, failure_secret(failure), anchor, Some(&ctx))
                        .unwrap();
                assert!(
                    matches!(result, CacheResult::Miss),
                    "decrypt failure must miss cleanly for path={} failure={}",
                    path.label(),
                    failure.label()
                );
            }
        }
    }

    #[test]
    fn anchor_mismatch_misses_across_paths() {
        let cache_anchor = anchor(13);
        let stale_context_anchor = anchor(14);
        let key_bytes = [0x42u8; 32];
        let ctx = sync_context(stale_context_anchor, 0, key_bytes);
        let case = encrypted_text_case();

        for path in all_safety_paths() {
            let secret = encrypted_cell(&case.plaintext, 0, key_bytes);
            let result = run_safety_path(path, &case, secret, cache_anchor, Some(&ctx)).unwrap();
            assert!(
                matches!(result, CacheResult::Miss),
                "anchor mismatch must miss for path={}",
                path.label()
            );
        }
    }

    #[test]
    fn encrypted_paths_miss_without_decrypt_context() {
        let anchor = anchor(15);
        let key_bytes = [0x42u8; 32];
        let case = encrypted_text_case();

        for path in all_safety_paths() {
            let secret = encrypted_cell(&case.plaintext, 0, key_bytes);
            let result = run_safety_path(path, &case, secret, anchor, None).unwrap();
            assert!(
                matches!(result, CacheResult::Miss),
                "encrypted path without decrypt context must miss for path={}",
                path.label()
            );
        }
    }

    #[test]
    fn plaintext_only_hits_without_decrypt_context_and_missing_schema_misses() {
        let anchor = anchor(16);
        let mut cache = KvCache::new(anchor);
        let verified = full_table_verified(TABLE, &[(1, "text", serde_json::json!("plain"))]);
        assert!(cache.apply_select(anchor, &verified));

        let schemas = HashMap::from([(TABLE.to_string(), plaintext_text_schema(TABLE))]);
        let rows = hit_rows(
            cache
                .try_select(&select_all_query(TABLE), &schemas, None)
                .unwrap(),
        );
        assert_eq!(rows, vec![serde_json::json!({"id": 1, "text": "plain"})]);

        let result = cache
            .try_select(&select_all_query(TABLE), &HashMap::new(), None)
            .unwrap();
        assert!(
            matches!(result, CacheResult::Miss),
            "missing schema must miss even for plaintext cached bytes"
        );
    }

    #[test]
    fn key_rotation_advance_anchor_and_reanchor_do_not_serve_stale_plaintext() {
        let table = "rotating_secrets";
        let anchor_before = anchor(17);
        let anchor_after = anchor(18);
        let anchor_replaced = anchor(19);
        let key_before = [0x42u8; 32];
        let key_after = [0x43u8; 32];
        let col_key = keys::column_key(table, 1, "secret");

        let mut cache = KvCache::new(anchor_before);
        let (start, end) = row_range(table, 1);
        let verified_before = verified_from_parts(
            vec![col_kv(
                table,
                1,
                "secret",
                serde_json::Value::String(encrypt_text("before", 0, key_before)),
            )],
            vec![ReadOp::Range {
                start: start.clone(),
                end: end.clone(),
            }],
        );
        assert!(cache.apply_select(anchor_before, &verified_before));

        let schemas = HashMap::from([(table.to_string(), encrypted_text_schema(table))]);
        let ctx_before = sync_context(anchor_before, 0, key_before);
        let resolver_before = CountingResolver::new(&ctx_before);
        let before_rows = hit_rows(
            cache
                .try_select(&select_by_id(table, 1), &schemas, Some(&resolver_before))
                .unwrap(),
        );
        assert_eq!(
            before_rows[0].get("secret").and_then(|v| v.as_str()),
            Some("before")
        );
        assert_eq!(resolver_before.count(), 1);

        let mut update = CacheUpdate::new();
        let (_, after_value) = col_kv(
            table,
            1,
            "secret",
            serde_json::Value::String(encrypt_text("after", 1, key_after)),
        );
        update.put(col_key.clone(), after_value);
        update.extend_coverage(start.clone(), end.clone());
        cache.advance_anchor(anchor_after, update);

        let stale_result = cache
            .try_select(&select_by_id(table, 1), &schemas, Some(&resolver_before))
            .unwrap();
        assert!(
            matches!(stale_result, CacheResult::Miss),
            "stale pre-rotation context must miss after anchor advance"
        );

        let ctx_after = sync_context(anchor_after, 1, key_after);
        let resolver_after = CountingResolver::new(&ctx_after);
        let after_rows = hit_rows(
            cache
                .try_select(&select_by_id(table, 1), &schemas, Some(&resolver_after))
                .unwrap(),
        );
        assert_eq!(
            after_rows[0].get("secret").and_then(|v| v.as_str()),
            Some("after")
        );
        assert_ne!(after_rows, before_rows);
        assert_eq!(
            resolver_after.count(),
            1,
            "replacement encrypted cell must start with a cold memo"
        );

        cache.reanchor(anchor_replaced);
        assert!(
            cache.storage.get_point(&col_key).is_none(),
            "reanchor must clear the encrypted entry and its memo"
        );
        let ctx_replaced = sync_context(anchor_replaced, 1, key_after);
        let miss_after_reanchor = cache
            .try_select(&select_by_id(table, 1), &schemas, Some(&ctx_replaced))
            .unwrap();
        assert!(matches!(miss_after_reanchor, CacheResult::Miss));

        let verified_replaced = verified_from_parts(
            vec![col_kv(
                table,
                1,
                "secret",
                serde_json::Value::String(encrypt_text("fresh", 1, key_after)),
            )],
            vec![ReadOp::Range { start, end }],
        );
        assert!(cache.apply_select(anchor_replaced, &verified_replaced));
        let resolver_replaced = CountingResolver::new(&ctx_replaced);
        let replaced_rows = hit_rows(
            cache
                .try_select(&select_by_id(table, 1), &schemas, Some(&resolver_replaced))
                .unwrap(),
        );
        assert_eq!(
            replaced_rows[0].get("secret").and_then(|v| v.as_str()),
            Some("fresh")
        );
        assert_eq!(
            resolver_replaced.count(),
            1,
            "post-reanchor replacement must decrypt once"
        );
    }

    #[test]
    fn data_entry_debug_and_equality_ignore_decrypt_memo() {
        let memoized = DataEntry::value(vec![1, 2, 3]);
        if let DataEntry::Value { decrypted, .. } = &memoized {
            decrypted.set(vec![9, 9, 9]).unwrap();
        }

        let cold = DataEntry::value(vec![1, 2, 3]);
        assert_eq!(memoized, cold);
        assert_eq!(format!("{memoized:?}"), format!("{cold:?}"));
    }
}
