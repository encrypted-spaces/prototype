use super::*;

#[cfg(feature = "merk")]
use {
    crate::query::{ComparisonOperator, QueryParam},
    encrypted_spaces_changelog_core::{
        changelog::{Change, ChangelogEntry, ChangelogError},
        collect_range, create_trace, create_trace_full,
        ops::{OpContext, OpReader, OpVerifyResult, ProverReader},
        BatchOp, InputStep, ProvenRead,
    },
    encrypted_spaces_storage_encoding::keys::parse_key,
    std::collections::BTreeSet,
};
#[cfg(any(feature = "merk", feature = "merk_verify"))]
use {
    encrypted_spaces_changelog_core::{
        prefix_successor, verify_trace, ReadOp, TraceStep, TracerProof,
    },
    merk::proofs::Query as MerkQuery,
    std::collections::HashMap,
};

/// Map a `ChangelogError` returned by `extract_and_validate` to an `SdkError`.
///
/// `ChangelogError::AclDenied` becomes `SdkError::AccessDenied` so the
/// server's response error matches the legacy `validate_insert_access`
/// path (which surfaced `AccessDenied`); other variants stay as
/// `DatabaseError` since they signal verification/shape failures.
#[cfg(feature = "merk")]
fn map_changelog_error_for_eav(err: ChangelogError) -> SdkError {
    match err {
        ChangelogError::AclDenied(msg) => SdkError::AccessDenied(msg),
        other => SdkError::DatabaseError(format!("extract_and_validate: {other}")),
    }
}

#[cfg(feature = "merk")]
fn dispatch_extract_and_validate(
    change: &ChangelogEntry,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> std::result::Result<OpVerifyResult, ChangelogError> {
    encrypted_spaces_changelog_core::ops::dispatch_extract_and_validate(change, reader, ctx)
}

/// Build a closure that resolves `ReadOp`s against the supplied tree.
///
/// Reads run against `tree` directly.  Pruned nodes propagate as
/// `ChangelogError::Generic` because the in-memory tree should not contain
/// pruned nodes for these reads.
#[cfg(feature = "merk")]
fn tree_read_resolver(
    tree: &merk::Node,
) -> impl FnMut(&ReadOp) -> std::result::Result<ProvenRead, ChangelogError> + '_ {
    move |op: &ReadOp| -> std::result::Result<ProvenRead, ChangelogError> {
        let results = match op {
            ReadOp::Key(key) => {
                match tree
                    .get_value(key)
                    .map_err(|e| ChangelogError::Generic(format!("Tree read failed: {e:?}")))?
                {
                    merk::GetResult::Found(value) => vec![(key.clone(), value)],
                    merk::GetResult::NotFound => vec![],
                    merk::GetResult::Pruned => {
                        return Err(ChangelogError::Generic(
                            "Pruned node encountered".to_string(),
                        ))
                    }
                }
            }
            ReadOp::Prefix(prefix) => {
                let end = prefix_successor(prefix);
                collect_range(tree, prefix, end.as_deref())
            }
            ReadOp::Range { start, end } => collect_range(tree, start, Some(end.as_slice())),
        };
        Ok(ProvenRead {
            op: op.clone(),
            results,
        })
    }
}

/// Run extract-and-validate (E&V) against `tree`, returning the Merk reads,
/// and stored-byte batch of writes it produced.
///
/// This is the read-and-write counterpart to `collect_reads_for_op`.  Use
/// it from per-op handlers that intend to apply the writes; use the
/// read-only variant when only the reads are needed (e.g. proof-only
/// reconstruction paths).
///
#[cfg(feature = "merk")]
fn extract_validate_and_materialize(
    tree: &merk::Node,
    change: &Change,
    current_change_id: usize,
) -> Result<(Vec<ReadOp>, Vec<BatchOp>)> {
    let ctx = OpContext::for_change_id(current_change_id);
    let mut reader = ProverReader::new(tree_read_resolver(tree));
    let result = dispatch_extract_and_validate(&change.entry, &mut reader, &ctx)
        .map_err(map_changelog_error_for_eav)?;
    let mut batch_ops: Vec<BatchOp> = Vec::new();
    for step in result.write_steps {
        match step {
            TraceStep::Write(ops) => batch_ops.extend(ops),
            TraceStep::Read(_) => {
                return Err(SdkError::DatabaseError(
                    "extract_and_validate emitted a Read in write_steps".to_string(),
                ))
            }
        }
    }
    Ok((reader.logged_reads, batch_ops))
}

#[cfg(feature = "merk")]
fn collect_reads_for_op(
    tree: &merk::Node,
    change: &ChangelogEntry,
    current_change_id: usize,
) -> Result<Vec<ReadOp>> {
    let ctx = OpContext::for_change_id(current_change_id);
    let mut reader = ProverReader::new(tree_read_resolver(tree));
    dispatch_extract_and_validate(change, &mut reader, &ctx)
        .map_err(map_changelog_error_for_eav)?;
    Ok(reader.logged_reads)
}

#[cfg(feature = "merk")]
impl MerkStorage {
    /// Collect the proven reads needed by an op's shared verifier against the
    /// current main tree, without mutating storage.
    pub fn collect_pruned_merkle_tree_reads(
        &self,
        change: &ChangelogEntry,
        current_change_id: usize,
    ) -> Result<Vec<ReadOp>> {
        let Some(tree) = self.merk.snapshot() else {
            return Err(SdkError::DatabaseError(
                "Main tree is empty, cannot collect pruned tree witness reads".to_string(),
            ));
        };
        collect_reads_for_op(&tree, change, current_change_id)
    }

    /// Apply a signed `change` through the shared extract-and-validate path,
    /// mutate storage, and return the serialized pruned Merkle tree.
    ///
    /// The server keeps validation at the request boundary. This method is the
    /// single storage write path: run E&V against a snapshot, keep stored
    /// bytes as written by the entry, build a trace from the same snapshot,
    /// apply the batch, then emit only the pruned tree bytes needed by
    /// `ChangeLog::verify_proof_and_validate`.
    pub async fn apply_change_with_pruned_tree(
        &self,
        change: &Change,
        current_change_id: usize,
    ) -> Result<Vec<u8>> {
        let Some(tree) = self.merk.snapshot() else {
            return Err(SdkError::DatabaseError(
                "Main tree is empty, cannot run extract_and_validate".to_string(),
            ));
        };
        let eav_root = tree.hash();
        let (reads, batch_ops) =
            extract_validate_and_materialize(&tree, change, current_change_id)?;
        if batch_ops.is_empty() {
            return Err(SdkError::DatabaseError(
                "extract_and_validate produced no write operations".to_string(),
            ));
        }

        let mut steps: Vec<InputStep> = reads
            .iter()
            .cloned()
            .map(|r| InputStep::Read(vec![r]))
            .collect();
        steps.push(InputStep::Write(batch_ops.clone()));
        let trace_proof = create_trace(&tree, &steps);

        // Reject snapshot drift before mutating storage.
        if trace_proof.expected_start_root != eav_root {
            return Err(SdkError::DatabaseError(
                "Trace proof start root does not match E&V tree root; \
                 concurrent writer detected"
                    .to_string(),
            ));
        }

        // BatchOp -> (key, Op). Post-materialization the batch only contains Put/Delete.
        let merk_ops: Vec<Operation> = batch_ops
            .iter()
            .map(|op| op.to_merk_batch_entry())
            .collect();
        self.apply_batch(merk_ops)?;

        let root_after = self.root_hash();
        if root_after != trace_proof.expected_end_root {
            return Err(SdkError::DatabaseError(
                "Root after apply does not match expected end root from trace proof".to_string(),
            ));
        }

        let proof = postcard::to_allocvec(&trace_proof.pruned_tree)
            .map_err(|e| SdkError::SerializationError(format!("Failed to serialize proof: {e}")))?;
        Ok(proof)
    }

    /// Generate a Merkle proof for the specified keys.
    ///
    /// Returns the proof bytes that can be verified with `verify_proof`.
    pub async fn prove_keys(&self, keys: &[Vec<u8>]) -> Result<Vec<u8>> {
        if keys.is_empty() {
            return Err(SdkError::InvalidQuery("No keys provided for proof".into()));
        }

        // Build a Merk query with all the specified keys
        let mut query = MerkQuery::new();
        for key in keys {
            query.insert_key(key.clone());
        }

        // Generate the proof using prove() which returns encoded bytes
        let proof = self
            .merk
            .prove(query)
            .map_err(|e| SdkError::DatabaseError(format!("Failed to generate proof: {e:?}")))?;

        Ok(proof)
    }

    /// Generate a Merkle proof for a range of keys with a given prefix.
    ///
    /// This is useful for proving all rows in a table or all index entries.
    pub async fn prove_prefix(&self, prefix: &[u8]) -> Result<Vec<u8>> {
        // Build a range query for the prefix
        // The range is [prefix, prefix_end) where prefix_end is the lexicographically next prefix
        let mut end_prefix = prefix.to_vec();
        // Increment the last byte to get the exclusive end bound
        // This works for our length-prefixed keys since we want all keys starting with prefix
        if let Some(last) = end_prefix.last_mut() {
            if *last < 255 {
                *last += 1;
            } else {
                // If last byte is 255, we need to handle overflow
                // For simplicity, just append 0xFF to make it larger
                end_prefix.push(0xFF);
            }
        }

        let mut query = MerkQuery::new();
        query.insert_range(prefix.to_vec()..end_prefix);

        // Generate the proof using prove() which returns encoded bytes
        let proof = self
            .merk
            .prove(query)
            .map_err(|e| SdkError::DatabaseError(format!("Failed to generate proof: {e:?}")))?;

        Ok(proof)
    }

    /// Generate a proof for a SELECT query.
    ///
    /// Routes to one of two proof strategies:
    /// - **Standard Merk proof** for id-based predicates or no predicate (table scan).
    /// - **TracerProof** for indexed column predicates and/or joins, which
    ///   uses targeted index key ranges instead of full table scans.
    ///
    /// Non-id predicates are validated to target an indexed column.
    pub async fn prove_query(&self, query: &Query) -> Result<Vec<u8>> {
        validate_predicate_cursor_supported(query)?;
        validate_self_join_alias(query)?;

        if needs_tracer_proof(query) {
            return self.prove_query_tracer(query).await;
        }

        let merk_query = merk_query_for_query(query)?;
        let proof = self
            .merk
            .prove(merk_query)
            .map_err(|e| SdkError::DatabaseError(format!("Failed to generate proof: {e:?}")))?;

        Ok(proof)
    }

    /// Generate a `TracerProof` for queries that need targeted reads
    /// (indexed WHERE clauses and/or joins).
    ///
    /// 1. Unproven reads to discover which rows to prove
    /// 2. Build a TracerProof with read steps:
    ///    - Step 1: Main table reads (index scan + row lookups, or range scan)
    ///    - Step 2: Joined table reads (non-contiguous FK lookups) — empty if no joins
    ///
    /// Returns serialized `TracerSelectProof`.
    async fn prove_query_tracer(&self, query: &Query) -> Result<Vec<u8>> {
        // Step 1: Build read ops for the main table
        let main_read_ops = self.build_main_table_read_ops(query)?;

        // Step 2: Build read ops for joined tables (if any)
        let join_read_ops = if let Some(join) = &query.join {
            let (fk_col, _) = parse_join_on_condition(&join.on_condition);
            // Execute main query (unproven) to extract FK values. The
            // discovery query honors the predicate's order/limit so we only
            // pull FK values for rows that will appear in the proven result.
            // Decode only the FK/predicate/id columns; hash-backed payload
            // columns are just hash refs and are resolved later from response
            // material.
            let main_rows = {
                let mut q = query.clone();
                q.join = None;
                q.operation = crate::query::QueryOperation::Select(Vec::new());
                self.query_rows_projecting_columns(&q, &[fk_col])?
            };
            self.build_join_read_ops(query, &main_rows)?
        } else {
            Vec::new()
        };

        let steps = vec![
            InputStep::Read(main_read_ops),
            InputStep::Read(join_read_ops),
        ];

        let Some(tree) = self.merk.snapshot() else {
            return Err(SdkError::DatabaseError(
                "Tree is empty, cannot generate trace proof".to_string(),
            ));
        };
        let tracer_proof = create_trace_full(&tree, &steps);

        let proof = TracerSelectProof { tracer_proof };
        postcard::to_allocvec(&proof).map_err(|e| {
            SdkError::SerializationError(format!("Failed to serialize TracerSelectProof: {e}"))
        })
    }

    /// Build `ReadOp`s for FK lookups on joined tables.
    fn build_join_read_ops(
        &self,
        query: &Query,
        main_rows: &[serde_json::Value],
    ) -> Result<Vec<ReadOp>> {
        let join = match &query.join {
            Some(j) => j,
            None => return Ok(Vec::new()),
        };

        let (right_table, _) = split_join_table(&join.table);
        let (fk_col, pk_col) = parse_join_on_condition(&join.on_condition);

        // Collect distinct FK values as QueryParam
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut fk_params: Vec<QueryParam> = Vec::new();
        for row in main_rows {
            if let Some(val) = row.get(&fk_col) {
                let key = val.to_string();
                if !val.is_null() && seen.insert(key) {
                    fk_params.push(QueryParam::from(val.clone()));
                }
            }
        }

        let mut ops: Vec<ReadOp> = Vec::new();
        if pk_col == ID_FIELD {
            // Direct row key lookup by id
            for param in &fk_params {
                if let QueryParam::Integer(id) = param {
                    ops.push(ReadOp::Prefix(keys::row_key(right_table, *id)));
                }
            }
        } else {
            // Validate: join target column must be indexed on the joined table.
            self.validate_column_indexed(right_table, &pk_col)?;

            // Index-based lookup on joined table's indexed column.
            // Include index ReadOps first (so the proof contains the index entries),
            // then row data ReadOps (discovered via the index scan).
            for param in &fk_params {
                let prefix = keys::index_value_prefix(
                    right_table,
                    &pk_col,
                    keys::query_param_to_tuple_element(param),
                )
                .map_err(|e| SdkError::InvalidQuery(format!("Invalid index value: {e}")))?;
                ops.push(ReadOp::Prefix(prefix));
            }

            let join_pred = Predicate {
                column: pk_col.to_string(),
                operator: if fk_params.len() == 1 {
                    ComparisonOperator::Equal
                } else {
                    ComparisonOperator::In
                },
                values: fk_params,
                cursor_id: None,
            };

            let row_keys = self.index_row_keys_for_predicate(right_table, &join_pred)?;
            for k in row_keys {
                ops.push(ReadOp::Prefix(k));
            }
        }

        Ok(ops)
    }

    /// Convert the main table query strategy into `ReadOp`s for a TracerProof.
    fn build_main_table_read_ops(&self, query: &Query) -> Result<Vec<ReadOp>> {
        let table = &query.table;

        validate_limit_supported(query)?;
        validate_predicate_cursor_supported(query)?;

        // Validate: non-id predicates must target an indexed column.
        if let Some(pred) = &query.predicate {
            if pred.column != ID_FIELD {
                self.validate_column_indexed(table, &pred.column)?;
            }
        }

        let mut ops = initial_read_ops_for_query(query)?;
        let on_id = query
            .predicate
            .as_ref()
            .is_none_or(|p| p.column == ID_FIELD);

        // Discover the kept rows (honoring order/limit) so we can both
        // narrow the first op and emit per-row Prefix ops for indexed
        // predicates. The id/no-pred path doesn't need per-row ops (the
        // initial range op already covers row data), but it does need
        // narrowing.
        let needs_narrowing = query.limit.is_some();
        if !on_id || needs_narrowing {
            let mut q = query.clone();
            q.join = None;
            q.operation = QueryOperation::Select(Vec::new());
            let matching_rows = self.query_rows_projecting_columns(&q, &[])?;

            if needs_narrowing {
                let keys = narrowing_keys_from_kept_rows(query, &matching_rows)?;
                ops[0] = narrow_first_op(&ops[0], query, &keys)?;
            }

            if !on_id {
                for row in &matching_rows {
                    if let Some(id) = row.get(ID_FIELD).and_then(|v| v.as_i64()) {
                        ops.push(ReadOp::Prefix(keys::row_key(table, id)));
                    }
                }
            }
        }

        Ok(ops)
    }
}

/// Whether a query must be served via the tracer proof path.
///
/// The simple Merk path returns the full key range and cannot bind
/// `limit` / `order` into the proof, so any limited query — even on the id
/// column or with no predicate — has to route through the tracer so the
/// server-side narrowing is verified.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn needs_tracer_proof(query: &Query) -> bool {
    query.join.is_some()
        || query
            .predicate
            .as_ref()
            .is_some_and(|p| p.column != ID_FIELD)
        || query.limit.is_some()
}

/// Build a MerkQuery for a given Query.
///
/// This function is used by both proof generation (server) and verification (client)
/// to ensure they use the same query structure. Similar to grovedb's `path_query_for_query`.
///
/// Handles JOINs by including key ranges for all joined tables.
/// Build a standard MerkQuery for id-based or no-predicate queries.
///
/// Non-id predicates, joins, and limited queries must use the tracer proof
/// path instead.
pub fn merk_query_for_query(query: &Query) -> Result<MerkQuery> {
    if query.join.is_some() {
        return Err(SdkError::InvalidQuery(
            "Queries with joins must use the tracer proof path".into(),
        ));
    }

    let mut merk_query = MerkQuery::new();

    if let Some(pred) = &query.predicate {
        if pred.column != ID_FIELD {
            return Err(SdkError::InvalidQuery(format!(
                "Non-id predicate on '{}' must use the tracer proof path",
                pred.column,
            )));
        }

        match (&pred.operator, pred.values.first()) {
            (ComparisonOperator::Equal, Some(QueryParam::Integer(id))) => {
                merk_query.insert_range(
                    keys::row_key(&query.table, *id)..keys::row_key(&query.table, *id + 1),
                );
            }
            (ComparisonOperator::In, _) => {
                for v in &pred.values {
                    if let QueryParam::Integer(id) = v {
                        merk_query.insert_range(
                            keys::row_key(&query.table, *id)..keys::row_key(&query.table, *id + 1),
                        );
                    }
                }
            }
            (ComparisonOperator::GreaterThan, Some(QueryParam::Integer(id))) => {
                merk_query.insert_range(
                    keys::row_key(&query.table, *id + 1)..row_prefix_successor(&query.table)?,
                );
            }
            (ComparisonOperator::GreaterThanOrEqual, Some(QueryParam::Integer(id))) => {
                merk_query.insert_range(
                    keys::row_key(&query.table, *id)..row_prefix_successor(&query.table)?,
                );
            }
            (ComparisonOperator::LessThan, Some(QueryParam::Integer(id))) => {
                merk_query
                    .insert_range(keys::row_prefix(&query.table)..keys::row_key(&query.table, *id));
            }
            (ComparisonOperator::LessThanOrEqual, Some(QueryParam::Integer(id))) => {
                merk_query.insert_range(
                    keys::row_prefix(&query.table)..keys::row_key(&query.table, *id + 1),
                );
            }
            (ComparisonOperator::Between, _) if pred.values.len() >= 2 => {
                if let (Some(QueryParam::Integer(lo)), Some(QueryParam::Integer(hi))) =
                    (pred.values.first(), pred.values.get(1))
                {
                    merk_query.insert_range(
                        keys::row_key(&query.table, *lo)..keys::row_key(&query.table, *hi + 1),
                    );
                }
            }
            _ => {
                return Err(SdkError::InvalidQuery(format!(
                    "Invalid id predicate: operator {:?} with {} value(s)",
                    pred.operator,
                    pred.values.len(),
                )));
            }
        }
    } else {
        // No predicate — table scan
        let start = keys::row_prefix(&query.table);
        let end = row_prefix_successor(&query.table)?;
        merk_query.insert_range(start..end);
    }

    Ok(merk_query)
}

/// Compute the exclusive upper bound for a half-open byte-range starting at `prefix`.
///
/// Wraps [`prefix_successor`] (which strips trailing `0xFF` bytes and increments the
/// last remaining byte) and converts its `None` result — meaning `prefix` is empty
/// or consists entirely of `0xFF` — into an error.
///
/// # Invariant
///
/// For any key `k` that starts with `prefix`, `k < prefix_successor_required(prefix)?`.
///
/// # Errors
///
/// Returns [`SdkError::DatabaseError`] iff `prefix` has no finite lexicographic
/// successor. Every storage prefix in this codebase is tuple-encoded and starts
/// with a type tag followed by a null-terminated string component, so this is
/// unreachable given a valid key layout — an error here signals upstream
/// corruption of the key schema.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
pub(crate) fn prefix_successor_required(prefix: &[u8]) -> Result<Vec<u8>> {
    prefix_successor(prefix).ok_or_else(|| {
        SdkError::DatabaseError(format!(
            "no lexicographic successor exists for prefix {prefix:02x?} \
             (empty or all-0xFF); storage key-layout invariant is broken"
        ))
    })
}

/// Compute the exclusive end bound for a row prefix range.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn row_prefix_successor(table: &str) -> Result<Vec<u8>> {
    prefix_successor_required(&keys::row_prefix(table))
}

#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn verify_merk_query(
    bytes: &[u8],
    query: MerkQuery,
    expected_hash: [u8; 32],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    merk::proofs::query::verify_query(bytes, &query, expected_hash)
        .map_err(|e| SdkError::DatabaseError(format!("Proof verification failed: {e:?}")))
}

/// Verify a Merkle proof against an expected root hash.
///
/// Returns the key-value pairs that were proven.
#[allow(clippy::type_complexity)]
pub fn verify_proof(
    proof: &[u8],
    expected_root: &[u8; 32],
    keys: &[Vec<u8>],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    // Build the query with the keys we want to verify
    let mut query = MerkQuery::new();
    for key in keys {
        query.insert_key(key.clone());
    }

    verify_merk_query(proof, query, *expected_root)
}

/// Verified rows from a Merk proof, organized by table.
pub struct VerifiedRows {
    /// Rows from the query's main table.
    pub main_rows: Vec<serde_json::Value>,
    /// Rows from other tables (used for JOINs), keyed by table name.
    pub rows_by_table: HashMap<String, Vec<serde_json::Value>>,
}

/// Tracer-based proof for SELECT queries that need targeted reads
/// (indexed WHERE clauses, joins, or both).
///
/// Wraps a single `TracerProof` with two `InputStep::Read` steps:
///   1. Main table reads (index scan + row lookups, ID range, or table scan)
///   2. Joined table reads (non-contiguous FK lookups) — empty if no joins
///
/// The server does unproven reads first to discover which rows to prove,
/// then builds a single proof covering all required data.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
#[derive(serde::Serialize, serde::Deserialize)]
struct TracerSelectProof {
    tracer_proof: TracerProof,
}

/// Extract column names from a join on_condition, stripping table prefixes.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn parse_join_on_condition(on_condition: &(String, String)) -> (String, String) {
    let fk = on_condition
        .0
        .rfind('.')
        .map_or(on_condition.0.as_str(), |p| &on_condition.0[p + 1..]);
    let pk = on_condition
        .1
        .rfind('.')
        .map_or(on_condition.1.as_str(), |p| &on_condition.1[p + 1..]);
    (fk.to_string(), pk.to_string())
}

#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn split_join_table(table: &str) -> (&str, Option<&str>) {
    table
        .split_once(" as ")
        .map_or((table.trim(), None), |(base, alias)| {
            (base.trim(), Some(alias.trim()))
        })
}

#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn validate_self_join_alias(query: &Query) -> Result<()> {
    if let Some(join) = &query.join {
        let (joined_table, alias) = split_join_table(&join.table);
        if joined_table == query.table {
            match alias {
                Some(alias) if !alias.is_empty() && alias != query.table => {}
                _ => {
                    return Err(SdkError::InvalidQuery(format!(
                        "self-joins require a distinct alias: '{}' joined to '{}'",
                        query.table, join.table
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Verify a Merk proof and return unprocessed (no WHERE/ORDER/LIMIT applied) rows organized by table.
///
/// Routes to tracer-based verification for joins and non-id predicates,
/// standard Merk verification for id-based or no-predicate queries.
pub fn verify_query_proof(query: &Query, proof: &[u8], commitment: &[u8]) -> Result<VerifiedRows> {
    verify_query_proof_inner(query, proof, commitment, None)
}

/// Verify a query proof and resolve schema-selected hash-backed columns through
/// response material before decoding column bytes into JSON values.
pub fn verify_query_proof_with_hashed_values(
    query: &Query,
    proof: &[u8],
    commitment: &[u8],
    schemas: &std::collections::HashMap<String, crate::schema::Schema>,
    hashed_values: &HashedValues,
) -> Result<VerifiedRows> {
    verify_query_proof_inner(query, proof, commitment, Some((schemas, hashed_values)))
}

fn verify_query_proof_inner(
    query: &Query,
    proof: &[u8],
    commitment: &[u8],
    hash_context: Option<(
        &std::collections::HashMap<String, crate::schema::Schema>,
        &HashedValues,
    )>,
) -> Result<VerifiedRows> {
    validate_predicate_cursor_supported(query)?;
    validate_self_join_alias(query)?;

    if needs_tracer_proof(query) {
        return verify_tracer_select_proof(query, proof, commitment, hash_context);
    }

    let expected_root: [u8; 32] = commitment
        .try_into()
        .map_err(|_| SdkError::ValidationError("Commitment must be 32 bytes".to_string()))?;

    let merk_query = merk_query_for_query(query)?;
    let results = verify_merk_query(proof, merk_query, expected_root)?;
    let mut rows_by_table = group_entries_for_verifier(&results, hash_context)?;
    let main_rows = rows_by_table.remove(&query.table).unwrap_or_default();

    Ok(VerifiedRows {
        main_rows,
        rows_by_table,
    })
}

fn group_entries_for_verifier(
    entries: &[(Vec<u8>, Vec<u8>)],
    hash_context: Option<(
        &std::collections::HashMap<String, crate::schema::Schema>,
        &HashedValues,
    )>,
) -> Result<std::collections::HashMap<String, Vec<serde_json::Value>>> {
    match hash_context {
        Some((schemas, hashed_values)) => {
            group_columns_into_rows_by_table_resolving_hashes(entries, schemas, hashed_values)
        }
        None => group_columns_into_rows_by_table(entries),
    }
}

/// Server-side helper for building select responses. It extracts the raw
/// key/value entries proven by a query proof so the server can attach full
/// values for any hash-backed columns present in those rows.
///
/// Client security does not rely on this helper: clients still call
/// `verify_query_proof_with_hashed_values`, which verifies query completeness
/// and validates every resolved hash/value pair.
pub fn extract_query_proof_entries_for_response_material(
    query: &Query,
    proof: &[u8],
    commitment: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    validate_predicate_cursor_supported(query)?;
    validate_self_join_alias(query)?;

    if needs_tracer_proof(query) {
        return extract_tracer_select_entries_for_response_material(proof, commitment);
    }

    let expected_root: [u8; 32] = commitment
        .try_into()
        .map_err(|_| SdkError::ValidationError("Commitment must be 32 bytes".to_string()))?;
    let merk_query = merk_query_for_query(query)?;
    verify_merk_query(proof, merk_query, expected_root)
}

/// Build the initial ReadOps for a query.
///
/// For table scans (no predicate): a single range over all row keys.
/// For id predicates: row key prefix/range ops targeting specific ids.
/// For indexed predicates: index key prefix/range ops targeting the index.
///
/// For indexed predicates, these ops only cover the index key space. The caller
/// must append additional row data ReadOps once the matching row_ids are known
/// (from the index scan results at proof time, or from verified index entries
/// at verification time).
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn initial_read_ops_for_query(query: &Query) -> Result<Vec<ReadOp>> {
    let table = &query.table;
    let pred = match &query.predicate {
        None => {
            return Ok(vec![ReadOp::Range {
                start: keys::row_prefix(table),
                end: row_prefix_successor(table)?,
            }]);
        }
        Some(p) => p,
    };

    let on_id = pred.column == ID_FIELD;

    let prefix_for = |v: &QueryParam| -> Result<Vec<u8>> {
        if on_id {
            match v {
                QueryParam::Integer(id) => Ok(row_key(table, *id)),
                _ => Err(SdkError::InvalidQuery(
                    "id predicate requires integer value".into(),
                )),
            }
        } else {
            keys::index_value_prefix(table, &pred.column, keys::query_param_to_tuple_element(v))
                .map_err(|e| SdkError::InvalidQuery(format!("Invalid index value: {e}")))
        }
    };
    let all_start = if on_id {
        keys::row_prefix(table)
    } else {
        keys::index_column_prefix(table, &pred.column)
    };
    let all_end = prefix_successor_required(&all_start)?;

    let first = pred.values.first();
    match &pred.operator {
        ComparisonOperator::Equal => {
            let v = first.ok_or_else(|| SdkError::InvalidQuery("Equal requires a value".into()))?;
            Ok(vec![ReadOp::Prefix(prefix_for(v)?)])
        }
        ComparisonOperator::In => {
            if pred.values.is_empty() {
                return Err(SdkError::InvalidQuery(
                    "In requires at least one value".into(),
                ));
            }
            pred.values
                .iter()
                .map(|v| Ok(ReadOp::Prefix(prefix_for(v)?)))
                .collect::<Result<Vec<_>>>()
        }
        ComparisonOperator::GreaterThan => {
            let v = first
                .ok_or_else(|| SdkError::InvalidQuery("GreaterThan requires a value".into()))?;
            Ok(vec![ReadOp::Range {
                start: prefix_successor_required(&prefix_for(v)?)?,
                end: all_end,
            }])
        }
        ComparisonOperator::GreaterThanOrEqual => {
            let v = first.ok_or_else(|| {
                SdkError::InvalidQuery("GreaterThanOrEqual requires a value".into())
            })?;
            Ok(vec![ReadOp::Range {
                start: prefix_for(v)?,
                end: all_end,
            }])
        }
        ComparisonOperator::LessThan => {
            let v =
                first.ok_or_else(|| SdkError::InvalidQuery("LessThan requires a value".into()))?;
            Ok(vec![ReadOp::Range {
                start: all_start,
                end: prefix_for(v)?,
            }])
        }
        ComparisonOperator::LessThanOrEqual => {
            let v = first
                .ok_or_else(|| SdkError::InvalidQuery("LessThanOrEqual requires a value".into()))?;
            Ok(vec![ReadOp::Range {
                start: all_start,
                end: prefix_successor_required(&prefix_for(v)?)?,
            }])
        }
        ComparisonOperator::Between => {
            let lo = first
                .ok_or_else(|| SdkError::InvalidQuery("Between requires two values".into()))?;
            let hi = pred
                .values
                .get(1)
                .ok_or_else(|| SdkError::InvalidQuery("Between requires two values".into()))?;
            Ok(vec![ReadOp::Range {
                start: prefix_for(lo)?,
                end: prefix_successor_required(&prefix_for(hi)?)?,
            }])
        }
    }
}

/// Reject ill-formed `limit` values:
///
/// - `limit = 0`: `narrow_first_op` would unwrap an empty `narrowing_keys`
///   (since `0 >= 0` triggers the narrowing branch but no rows remain to
///   pick first/last from). A malicious caller could panic the server.
/// - `limit` combined with an `In` predicate: `In` compiles to multiple
///   disjoint prefix scans that have no single "end to walk from", so the
///   limit has ambiguous semantics.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn validate_limit_supported(query: &Query) -> Result<()> {
    if matches!(query.limit, Some(0)) {
        return Err(SdkError::InvalidQuery("limit must be >= 1".into()));
    }
    if query.limit.is_some()
        && query
            .predicate
            .as_ref()
            .is_some_and(|p| matches!(p.operator, ComparisonOperator::In))
    {
        return Err(SdkError::InvalidQuery(
            "limit is not supported with In predicates".into(),
        ));
    }
    Ok(())
}

/// Whether a query's predicate filters on a non-id indexed column.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn predicate_on_indexed_column(query: &Query) -> bool {
    query
        .predicate
        .as_ref()
        .is_some_and(|p| p.column != ID_FIELD)
}

/// Narrow the first ReadOp of a query's predicate to the actual range walked.
/// Two independent narrowings stack:
///
/// 1. Cursor narrowing — if the predicate carries a `cursor_id`, tighten the
///    bound on the cursor side (DESC narrows the high end down to the cursor
///    key; ASC narrows the low end up past the cursor). This applies even
///    when the predicate is exhausted before hitting the limit.
/// 2. Limit narrowing — if `narrowing_keys` reached `limit`, tighten the
///    other end to the smallest/largest kept key.
///
/// `narrowing_keys` are one key per kept row in the predicate's key space —
/// index keys for non-id indexed predicates, row prefixes otherwise. The
/// `BTreeSet` gives us dedup (cheap insurance for the verifier path, where
/// multiple column entries can map to the same row prefix) and free
/// min/max via `first`/`last`. Both prove and verify call this with
/// independently-derived keys and must agree on the result.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn narrow_first_op(
    initial: &ReadOp,
    query: &Query,
    narrowing_keys: &std::collections::BTreeSet<Vec<u8>>,
) -> Result<ReadOp> {
    use crate::query::Order;

    let cursor_key = cursor_index_key(query)?;
    let limit_narrows = matches!(query.limit, Some(limit)
        if narrowing_keys.len() >= limit as usize);

    if cursor_key.is_none() && !limit_narrows {
        // No narrowing applies — predicate's natural bounds stand.
        return Ok(initial.clone());
    }

    let (mut start, mut end) = match initial {
        ReadOp::Range { start, end } => (start.clone(), end.clone()),
        ReadOp::Prefix(p) => (p.clone(), prefix_successor_required(p)?),
        ReadOp::Key(_) => return Ok(initial.clone()),
    };

    // Cursor narrowing first (independent of kept-row count). For DESC the
    // cursor caps the high end (we want id < cursor); for ASC it lifts the
    // low end (we want id > cursor).
    if let Some(key) = cursor_key {
        match query.order {
            Order::Desc => end = key,
            Order::Asc => start = prefix_successor_required(&key)?,
        }
    }

    // Limit narrowing on top of cursor.
    if limit_narrows {
        match query.order {
            Order::Asc => end = prefix_successor_required(narrowing_keys.last().unwrap())?,
            Order::Desc => start = narrowing_keys.first().unwrap().clone(),
        }
    }

    Ok(ReadOp::Range { start, end })
}

/// Build the index key the cursor refers to, used as a tight bound in
/// `narrow_first_op` when the predicate carries `cursor_id`. Returns `None`
/// if the query has no cursor (or the cursor is on an unsupported predicate
/// — `validate_predicate_cursor_supported` will surface that error
/// elsewhere).
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn cursor_index_key(query: &Query) -> Result<Option<Vec<u8>>> {
    let Some(pred) = &query.predicate else {
        return Ok(None);
    };
    let Some(cursor) = pred.cursor_id else {
        return Ok(None);
    };
    if pred.column == ID_FIELD || !matches!(pred.operator, ComparisonOperator::Equal) {
        // Validated elsewhere; fall through without narrowing.
        return Ok(None);
    }
    let Some(value) = pred.values.first() else {
        return Ok(None);
    };
    let value_elem = keys::query_param_to_tuple_element(value);
    keys::index_key(&query.table, &pred.column, value_elem, cursor)
        .map(Some)
        .map_err(|e| SdkError::InvalidQuery(format!("Invalid cursor index key: {e}")))
}

/// Server-side: build narrowing keys from the kept rows discovered by an
/// unproven query (which already honors `query.order`/`query.limit`).
#[cfg(feature = "merk")]
fn narrowing_keys_from_kept_rows(
    query: &Query,
    kept_rows: &[serde_json::Value],
) -> Result<std::collections::BTreeSet<Vec<u8>>> {
    let on_indexed = predicate_on_indexed_column(query);
    let mut keys = std::collections::BTreeSet::new();
    for row in kept_rows {
        let id = row
            .get(ID_FIELD)
            .and_then(|v| v.as_i64())
            .ok_or_else(|| SdkError::DatabaseError("kept row missing id".into()))?;
        let key = if on_indexed {
            let column = &query.predicate.as_ref().unwrap().column;
            let value = row.get(column).cloned().unwrap_or(serde_json::Value::Null);
            keys::index_key(&query.table, column, &value, id)
                .map_err(|e| SdkError::DatabaseError(format!("Failed to build index key: {e}")))?
        } else {
            keys::row_key(&query.table, id)
        };
        keys.insert(key);
    }
    Ok(keys)
}

/// Verifier-side: simulate the server's selection on top of the proven
/// entries. Returns `(row_id, narrowing_key)` pairs in walk order
/// (`query.order`), with the predicate's cursor and the query's limit
/// applied. Index entries contribute their key as-is (encoding
/// `(column_value, row_id)`); column entries are reduced to the row prefix
/// `row_key(table, id)` and deduped.
///
/// Verification needs the same kept set the server computed via
/// `process_query_results`, so both narrowing and per-row ReadOp expectations
/// stay in sync. Only Equal predicates on a non-id indexed column (or no
/// predicate / id predicate without a cursor) are supported — see
/// `validate_predicate_cursor_supported`.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn kept_walks_from_proof_entries(
    query: &Query,
    main_all_entries: &[(Vec<u8>, Vec<u8>)],
) -> Vec<(i64, Vec<u8>)> {
    let on_indexed = predicate_on_indexed_column(query);
    let mut walks: Vec<(i64, Vec<u8>)> = Vec::new();
    let mut seen_rows = std::collections::HashSet::new();

    for (key, _) in main_all_entries {
        match parse_key(key) {
            Ok(ParsedKey::Index { row_id, .. }) if on_indexed => {
                walks.push((row_id, key.clone()));
            }
            Ok(ParsedKey::Column { row_id, .. }) if !on_indexed => {
                if seen_rows.insert(row_id) {
                    walks.push((row_id, keys::row_key(&query.table, row_id)));
                }
            }
            _ => {}
        }
    }

    walks.sort_by_key(|(id, _)| *id);
    let asc = matches!(query.order, crate::query::Order::Asc);
    if !asc {
        walks.reverse();
    }
    if let Some(cursor) = query.predicate.as_ref().and_then(|p| p.cursor_id) {
        walks.retain(|(id, _)| if asc { *id > cursor } else { *id < cursor });
    }
    if let Some(limit) = query.limit {
        walks.truncate(limit as usize);
    }
    walks
}

/// Reject queries whose predicate cursor isn't backed by an Equal walk on a
/// non-id column.
///
/// The verifier's kept-set simulation sorts proof entries by row id alone.
/// That matches the server's `apply_query_order` only when the column-value
/// sort is a tie — i.e. `Equal` predicates on a non-id indexed column. Range
/// predicates (`Lt`/`Gt`/`Between`) walk a column-value range, so a cursor
/// there would need column-value-aware narrowing (out of scope). An id-column
/// "Eq with cursor" collapses to a contradiction (id == V AND id past V), so
/// it is also rejected.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn validate_predicate_cursor_supported(query: &Query) -> Result<()> {
    let Some(pred) = &query.predicate else {
        return Ok(());
    };
    if pred.cursor_id.is_none() {
        return Ok(());
    }
    if pred.column == ID_FIELD {
        return Err(SdkError::InvalidQuery(
            "cursor_id is not supported on id-column predicates".to_string(),
        ));
    }
    if !matches!(pred.operator, ComparisonOperator::Equal) {
        return Err(SdkError::InvalidQuery(format!(
            "cursor_id is only supported on Equal predicates; got operator {:?} on column '{}'",
            pred.operator, pred.column,
        )));
    }
    Ok(())
}

#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn extract_tracer_select_entries_for_response_material(
    proof: &[u8],
    commitment: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let expected_root: [u8; 32] = commitment
        .try_into()
        .map_err(|_| SdkError::ValidationError("Commitment must be 32 bytes".to_string()))?;

    let select_proof: TracerSelectProof = postcard::from_bytes(proof).map_err(|e| {
        SdkError::SerializationError(format!("Failed to deserialize TracerSelectProof: {e}"))
    })?;
    let tracer = &select_proof.tracer_proof;

    if tracer.expected_start_root != expected_root {
        return Err(SdkError::ValidationError(
            "Select proof root does not match commitment".into(),
        ));
    }
    if tracer.expected_start_root != tracer.expected_end_root {
        return Err(SdkError::ValidationError(
            "Read-only select proof must have start_root == end_root".into(),
        ));
    }
    if tracer
        .steps
        .iter()
        .any(|step| matches!(step, TraceStep::Write(_)))
    {
        return Err(SdkError::ValidationError(
            "Read-only select proof must not contain write steps".into(),
        ));
    }

    let all_read_results = verify_trace(tracer)
        .map_err(|_| SdkError::ValidationError("Select TracerProof verification failed".into()))?;

    let mut entries = Vec::new();
    for read_step in all_read_results {
        for proven_read in read_step {
            entries.extend(proven_read.results);
        }
    }
    Ok(entries)
}

/// Verify that the actual ReadOps in a proof step match the expected set exactly.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn verify_read_ops(expected: &[ReadOp], actual: &[&ReadOp], context: &str) -> Result<()> {
    for op in expected {
        if !actual.contains(&op) {
            return Err(SdkError::ValidationError(format!(
                "{context} completeness check failed: proof is missing expected ReadOp"
            )));
        }
    }
    for op in actual {
        if !expected.iter().any(|e| e == *op) {
            return Err(SdkError::ValidationError(format!(
                "{context} completeness check failed: proof contains unexpected ReadOp"
            )));
        }
    }
    Ok(())
}

/// Verify a `TracerSelectProof` (single TracerProof with 2 read steps).
///
/// Step 1 results → main table rows (may include index entries which are filtered out).
/// Step 2 results → joined table rows (empty if no joins).
#[cfg(any(feature = "merk", feature = "merk_verify"))]
fn verify_tracer_select_proof(
    query: &Query,
    proof: &[u8],
    commitment: &[u8],
    hash_context: Option<(
        &std::collections::HashMap<String, crate::schema::Schema>,
        &HashedValues,
    )>,
) -> Result<VerifiedRows> {
    let expected_root: [u8; 32] = commitment
        .try_into()
        .map_err(|_| SdkError::ValidationError("Commitment must be 32 bytes".to_string()))?;

    let select_proof: TracerSelectProof = postcard::from_bytes(proof).map_err(|e| {
        SdkError::SerializationError(format!("Failed to deserialize TracerSelectProof: {e}"))
    })?;

    let tracer = &select_proof.tracer_proof;

    // Root must match commitment
    if tracer.expected_start_root != expected_root {
        return Err(SdkError::ValidationError(
            "Select proof root does not match commitment".into(),
        ));
    }
    // Read-only: start == end
    if tracer.expected_start_root != tracer.expected_end_root {
        return Err(SdkError::ValidationError(
            "Read-only select proof must have start_root == end_root".into(),
        ));
    }
    // Reject any Write steps. A matching start/end root only proves the net
    // change is zero — a malicious server could still inject Put/Delete steps
    // that mutate the tree before a Read and undo them after, returning
    // results from a transient state that was never committed.
    if tracer
        .steps
        .iter()
        .any(|step| matches!(step, TraceStep::Write(_)))
    {
        return Err(SdkError::ValidationError(
            "Read-only select proof must not contain write steps".into(),
        ));
    }

    let all_read_results = match verify_trace(tracer) {
        Ok(results) => results,
        Err(_) => {
            return Err(SdkError::ValidationError(
                "Select TracerProof verification failed".into(),
            ))
        }
    };

    if all_read_results.len() < 2 {
        return Err(SdkError::ValidationError(format!(
            "Expected 2 read steps (main + joins), got {}",
            all_read_results.len(),
        )));
    }

    validate_limit_supported(query)?;
    validate_predicate_cursor_supported(query)?;

    // Step 1: Verify main table ReadOps match the query predicate
    let mut main_all_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for proven_read in &all_read_results[0] {
        main_all_entries.extend(proven_read.results.iter().cloned());
    }

    let mut expected_ops = initial_read_ops_for_query(query)?;

    // For non-id (indexed) predicates the proof carries per-row data
    // ReadOps for each row the server retained after sort + cursor + limit.
    // Reconstruct the same kept set so the per-row Prefix ops match exactly.
    let kept_walks = kept_walks_from_proof_entries(query, &main_all_entries);
    if predicate_on_indexed_column(query) {
        for (row_id, _) in &kept_walks {
            expected_ops.push(ReadOp::Prefix(row_key(&query.table, *row_id)));
        }
    }

    // If the query carries a limit, the server's first ReadOp was narrowed
    // to the actual range walked. Reconstruct the same narrowing from the
    // proven entries so set-equality holds.
    if query.limit.is_some() {
        let keys: std::collections::BTreeSet<Vec<u8>> =
            kept_walks.iter().map(|(_, k)| k.clone()).collect();
        expected_ops[0] = narrow_first_op(&expected_ops[0], query, &keys)?;
    }

    let actual_ops: Vec<&ReadOp> = all_read_results[0].iter().map(|pr| &pr.op).collect();
    verify_read_ops(&expected_ops, &actual_ops, "SELECT proof")?;

    let mut rows_by_table = group_entries_for_verifier(&main_all_entries, hash_context)?;
    let main_rows = rows_by_table.remove(&query.table).unwrap_or_default();

    // Step 2: Verify join ReadOps match foreign-key values from main rows
    let mut join_all_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for proven_read in &all_read_results[1] {
        join_all_entries.extend(proven_read.results.iter().cloned());
    }

    if let Some(join) = &query.join {
        let (right_table, _) = split_join_table(&join.table);
        let (fk_col, pk_col) = parse_join_on_condition(&join.on_condition);
        let on_pk = pk_col == ID_FIELD;

        // Collect distinct foreign-key values from verified main rows
        let mut fk_values: Vec<serde_json::Value> = Vec::new();
        for row in &main_rows {
            if let Some(val) = row.get(&fk_col) {
                if !val.is_null() && !fk_values.iter().any(|existing| existing == val) {
                    fk_values.push(val.clone());
                }
            }
        }

        // Build expected foreign-key lookup ReadOps mirroring build_join_read_ops:
        // row prefixes for primary key joins, index value prefixes for index joins.
        let mut expected_ops: Vec<ReadOp> = Vec::new();
        for fk_val in &fk_values {
            let prefix = if on_pk {
                fk_val
                    .as_i64()
                    .map(|id| row_key(right_table, id))
                    .ok_or_else(|| SdkError::ValidationError("FK value is not an integer".into()))?
            } else {
                encrypted_spaces_storage_encoding::keys::index_value_prefix(
                    right_table,
                    &pk_col,
                    fk_val,
                )
                .map_err(|e| {
                    SdkError::ValidationError(format!("Failed to build index prefix: {e}"))
                })?
            };
            expected_ops.push(ReadOp::Prefix(prefix));
        }

        // For index joins, also allow row data ops derived from verified
        // index entries (same pattern as step 1).
        if !on_pk {
            for (key, _) in &join_all_entries {
                if let Ok(ParsedKey::Index { row_id, .. }) = parse_key(key) {
                    expected_ops.push(ReadOp::Prefix(row_key(right_table, row_id)));
                }
            }
        }

        let actual_ops: Vec<&ReadOp> = all_read_results[1].iter().map(|pr| &pr.op).collect();
        verify_read_ops(&expected_ops, &actual_ops, "Join")?;
    }

    let joined_tables = group_entries_for_verifier(&join_all_entries, hash_context)?;
    for (table, table_rows) in joined_tables {
        rows_by_table.entry(table).or_default().extend(table_rows);
    }

    Ok(VerifiedRows {
        main_rows,
        rows_by_table,
    })
}

#[cfg(all(test, feature = "merk"))]
mod tests {
    use super::*;
    use crate::access_control::{
        AccessRule, ColumnNamespace, ComparisonOp as RuleComparisonOp, RuleValue,
        ACCESS_CONTROL_TABLE_NAME,
    };
    use crate::internal_schemas::USERS_TABLE_NAME;
    use crate::merk_storage::test_helpers::{
        delete_change_for_query, insert_change_for_query, update_change_for_query,
    };
    use crate::schema::{ColumnDefinition, ColumnType, Schema};
    use crate::SpaceId;
    use encrypted_spaces_changelog_core::changelog::{
        ChangeLog, ChangelogEntry, OpType, ROOT_TREE_PATH,
    };

    /// Test helper: verify proof, apply query processing, deserialize.
    /// Reproduces the full pipeline (without encryption/decryption) for backend tests.
    fn verify_and_process(
        query: &Query,
        proof: &[u8],
        commitment: &[u8],
    ) -> Result<Vec<serde_json::Value>> {
        let verified = verify_query_proof(query, proof, commitment)?;
        process_query_results(verified.main_rows, query)
    }

    fn sid() -> SpaceId {
        SpaceId::from([0u8; 16])
    }

    fn table_schema() -> Schema {
        Schema {
            name: "users".to_string(),
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
                    indexed: false,
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

    async fn insert_rule(storage: &MerkStorage, table: &str, operation: &str, rule: AccessRule) {
        let rule_json = serde_json::to_string(&rule).unwrap();
        let query = Query::new(
            ACCESS_CONTROL_TABLE_NAME.to_string(),
            QueryOperation::Insert(vec![
                (
                    "resource_name".to_string(),
                    QueryParam::Text(table.to_string()),
                ),
                (
                    "operation".to_string(),
                    QueryParam::Text(operation.to_string()),
                ),
                ("rule_json".to_string(), QueryParam::Text(rule_json)),
            ]),
        );
        storage
            .insert(query, &AuthContext::anonymous(sid()))
            .await
            .unwrap();
    }

    async fn insert_user_row(
        storage: &MerkStorage,
        name: &str,
        age: i64,
        auth: &AuthContext,
    ) -> i64 {
        let query = Query::new(
            "users".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(0)),
                ("name".to_string(), QueryParam::Text(name.to_string())),
                ("age".to_string(), QueryParam::Integer(age)),
            ]),
        );
        storage.insert(query, auth).await.unwrap()
    }

    async fn insert_internal_user(storage: &MerkStorage, space_id: SpaceId) -> u32 {
        storage
            .create_table(&crate::internal_schemas::users_schema())
            .await
            .unwrap();
        let uid = storage
            .insert(
                Query::new(
                    USERS_TABLE_NAME.to_string(),
                    QueryOperation::Insert(vec![
                        ("update_key".to_string(), QueryParam::Text(String::new())),
                        ("auth_key".to_string(), QueryParam::Text(String::new())),
                        ("status".to_string(), QueryParam::Integer(1)),
                    ]),
                ),
                &AuthContext::anonymous(space_id),
            )
            .await
            .unwrap();
        u32::try_from(uid).expect("test uid fits in u32")
    }

    fn delete_by_id_query(table: &str, row_id: i64) -> Query {
        let mut query = Query::new(table.to_string(), QueryOperation::Delete);
        query.predicate = Some(Predicate {
            column: ID_FIELD.to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(row_id)],
            cursor_id: None,
        });
        query
    }

    #[tokio::test]
    async fn test_insert_row_with_proof() {
        let schema = table_schema();
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&schema).await.unwrap();
        storage.finalize_acl_blob().await.unwrap();

        let sid = sid();
        let uid = insert_internal_user(&storage, sid).await;

        const REPEAT: usize = 10;
        for _ in 0..REPEAT {
            for (name, age) in [
                ("Alice", 30),
                ("Bob", 31),
                ("Charlie", 60),
                ("Dawn", 44),
                ("Eleven", 11),
                ("Frank", 82),
                ("Grace", 23),
            ] {
                let row_data = vec![
                    ("id".to_string(), QueryParam::Integer(0)),
                    ("name".to_string(), QueryParam::Text(name.to_string())),
                    ("age".to_string(), QueryParam::Integer(age)),
                ];

                let insert_query =
                    Query::new(schema.name.clone(), QueryOperation::Insert(row_data));
                let change = insert_change_for_query(&insert_query, uid).unwrap();
                let root_before = storage.root_hash();
                let proof_bytes = storage
                    .apply_change_with_pruned_tree(&change, 1)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("Failed to generate insert proof for ({name},{age}): {e}")
                    });
                let root_after = storage.root_hash();
                let result = ChangeLog::verify_proof_and_validate(
                    &change.entry,
                    &proof_bytes,
                    &root_before,
                    &root_after,
                    1,
                );
                assert!(
                    result.is_ok(),
                    "Failed to verify pruned tree witness for ({name},{age}): {:?}",
                    result.as_ref().err()
                );
                let writes = result.unwrap();

                let mut wrong_root_after = root_after;
                wrong_root_after[0] ^= 0xff;
                let wrong_root_result = ChangeLog::verify_proof_and_validate(
                    &change.entry,
                    &proof_bytes,
                    &root_before,
                    &wrong_root_after,
                    1,
                );
                assert!(
                    wrong_root_result.is_err(),
                    "insert proof should reject an incorrect end root"
                );
                println!(
                    "Inserted ({name}, {age}) with {} verified writes, proof size: {} bytes",
                    writes.len(),
                    proof_bytes.len()
                );
                assert_ne!(root_before, root_after, "Root should change after insert");
                assert_eq!(
                    root_after,
                    storage.root_hash(),
                    "Root_after from proof doesn't match actual root"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_verify_pruned_tree_returns_authenticated_insert_row_id() {
        let schema = table_schema();
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&schema).await.unwrap();
        storage.finalize_acl_blob().await.unwrap();
        let sid = sid();
        let uid = insert_internal_user(&storage, sid).await;

        let insert_query = Query::new(
            schema.name.clone(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(0)),
                ("name".to_string(), QueryParam::Text("Alice".to_string())),
                ("age".to_string(), QueryParam::Integer(30)),
            ]),
        );
        let change = insert_change_for_query(&insert_query, uid).unwrap();

        let root_before = storage.root_hash();
        let proof_bytes = storage
            .apply_change_with_pruned_tree(&change, 1)
            .await
            .unwrap();
        let root_after = storage.root_hash();

        let writes = ChangeLog::verify_proof_and_validate(
            &change.entry,
            &proof_bytes,
            &root_before,
            &root_after,
            1,
        )
        .unwrap();
        assert!(
            writes.iter().any(|op| matches!(op,
                BatchOp::Put { key, .. }
                if matches!(
                    parse_key(key),
                    Ok(ParsedKey::Column { row_id: 1, .. })
                )
            )),
            "verify_proof_and_validate should expose writes for the new row",
        );
    }

    #[tokio::test]
    async fn test_update_row_with_proof() {
        let schema = table_schema();
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&schema).await.unwrap();
        storage.finalize_acl_blob().await.unwrap();

        let sid = sid();
        let uid = insert_internal_user(&storage, sid).await;

        // Insert a row first
        let row_data = vec![
            ("id".to_string(), QueryParam::Integer(0)),
            ("name".to_string(), QueryParam::Text("Alice".to_string())),
            ("age".to_string(), QueryParam::Integer(30)),
        ];
        let insert_query = Query::new(schema.name.clone(), QueryOperation::Insert(row_data));
        let insert_change = insert_change_for_query(&insert_query, uid).unwrap();
        let insert_root_before = storage.root_hash();
        let insert_proof_bytes = storage
            .apply_change_with_pruned_tree(&insert_change, 1)
            .await
            .unwrap();
        let insert_root_after = storage.root_hash();
        let insert_writes = ChangeLog::verify_proof_and_validate(
            &insert_change.entry,
            &insert_proof_bytes,
            &insert_root_before,
            &insert_root_after,
            1,
        )
        .unwrap();
        let id = insert_writes
            .iter()
            .find_map(|op| match op {
                BatchOp::Put { key, .. } => match parse_key(key) {
                    Ok(ParsedKey::Column { table, row_id, .. }) if table == schema.name => {
                        Some(row_id)
                    }
                    _ => None,
                },
                BatchOp::Delete { .. } => None,
            })
            .expect("insert writes should contain a new row id");

        // Update the row
        let update_data = vec![
            ("id".to_string(), QueryParam::Integer(id)),
            ("name".to_string(), QueryParam::Text("Alicia".to_string())),
            ("age".to_string(), QueryParam::Integer(31)),
        ];
        let mut update_query = Query::new(schema.name.clone(), QueryOperation::Update(update_data));
        update_query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(id)],
            cursor_id: None,
        });

        let update_change = update_change_for_query(&update_query, uid).unwrap();
        let root_before = storage.root_hash();
        let proof_bytes = storage
            .apply_change_with_pruned_tree(&update_change, 2)
            .await
            .unwrap();
        let root_after = storage.root_hash();
        ChangeLog::verify_proof_and_validate(
            &update_change.entry,
            &proof_bytes,
            &root_before,
            &root_after,
            2,
        )
        .unwrap();
        println!("Updated id {id}, proof size: {} bytes", proof_bytes.len());
        assert_ne!(root_before, root_after, "Root should change after update");
        assert_eq!(
            root_after,
            storage.root_hash(),
            "Root_after from proof doesn't match actual root"
        );

        // Updating a non-existent row must fail. UpdateOp reads the
        // row prefix and rejects if no columns are present, so a fabricated
        // entry naming row_id=999 is caught inside extract_and_validate.
        let update_data = vec![
            ("id".to_string(), QueryParam::Integer(999)),
            ("name".to_string(), QueryParam::Text("Ghost".to_string())),
            ("age".to_string(), QueryParam::Integer(0)),
        ];
        let mut update_query = Query::new(schema.name.clone(), QueryOperation::Update(update_data));
        update_query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(999)],
            cursor_id: None,
        });

        let update_change = update_change_for_query(&update_query, uid).unwrap();
        let result = storage
            .apply_change_with_pruned_tree(&update_change, 3)
            .await;

        assert!(result.is_err(), "Update of non-existent row should fail");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("does not exist") || msg.contains("row_id=999"),
            "expected 'row does not exist' error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_delete_row_with_proof_by_id() {
        let schema = table_schema();
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&schema).await.unwrap();
        storage.finalize_acl_blob().await.unwrap();

        let sid = sid();
        let uid = insert_internal_user(&storage, sid).await;
        let auth = AuthContext::new(Some(uid as i64), sid);
        let id = insert_user_row(&storage, "Alice", 30, &auth).await;

        let delete_query = delete_by_id_query(&schema.name, id);
        let delete_change = delete_change_for_query(&delete_query, uid, &schema).unwrap();

        storage
            .apply_change_with_pruned_tree(&delete_change, 3)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_delete_row_with_proof_enforces_access_control() {
        let schema = table_schema();
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&schema).await.unwrap();

        let sid = sid();
        let uid = insert_internal_user(&storage, sid).await;
        let auth = AuthContext::new(Some(uid as i64), sid);
        let allowed_id = insert_user_row(&storage, "Alice", 30, &auth).await;
        let denied_id = insert_user_row(&storage, "Bob", 31, &auth).await;

        insert_rule(
            &storage,
            &schema.name,
            "delete",
            AccessRule::comparison(
                RuleValue::column(ColumnNamespace::Resource, "age"),
                RuleComparisonOp::Equal,
                RuleValue::Int(30),
            ),
        )
        .await;
        // Make the rule visible to E&V (which reads the finalized blob).
        storage.finalize_acl_blob().await.unwrap();

        let denied_query = delete_by_id_query(&schema.name, denied_id);
        let denied_change = delete_change_for_query(&denied_query, uid, &schema).unwrap();
        let denied_err = storage
            .apply_change_with_pruned_tree(&denied_change, 4)
            .await
            .unwrap_err();
        let denied_msg = denied_err.to_string();
        assert!(
            denied_msg.contains("Access denied") || denied_msg.contains("Delete access denied"),
            "unexpected error: {denied_msg}"
        );

        let still_there: Option<serde_json::Value> = storage
            .select_one(Query {
                table: schema.name.clone(),
                operation: QueryOperation::Select(vec![]),
                predicate: Some(Predicate {
                    column: ID_FIELD.to_string(),
                    operator: ComparisonOperator::Equal,
                    values: vec![QueryParam::Integer(denied_id)],
                    cursor_id: None,
                }),
                order: crate::query::Order::Asc,
                limit: None,
                join: None,
            })
            .await
            .unwrap();
        assert!(
            still_there.is_some(),
            "row should remain after denied delete"
        );

        let allowed_query = delete_by_id_query(&schema.name, allowed_id);
        let allowed_change = delete_change_for_query(&allowed_query, uid, &schema).unwrap();
        storage
            .apply_change_with_pruned_tree(&allowed_change, 5)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_delete_row_with_proof_changes_root() {
        let schema = table_schema();
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&schema).await.unwrap();
        storage.finalize_acl_blob().await.unwrap();

        let sid = sid();
        let uid = insert_internal_user(&storage, sid).await;
        let auth = AuthContext::new(Some(uid as i64), sid);
        let id = insert_user_row(&storage, "Alice", 30, &auth).await;

        let delete_query = delete_by_id_query(&schema.name, id);
        let delete_change = delete_change_for_query(&delete_query, uid, &schema).unwrap();
        let root_before = storage.root_hash();
        let proof_bytes = storage
            .apply_change_with_pruned_tree(&delete_change, 3)
            .await
            .unwrap();
        let root_after = storage.root_hash();

        ChangeLog::verify_proof_and_validate(
            &delete_change.entry,
            &proof_bytes,
            &root_before,
            &root_after,
            3,
        )
        .unwrap();
        assert_ne!(root_before, root_after, "Root should change after delete");
        assert_eq!(root_after, storage.root_hash());
    }

    #[tokio::test]
    async fn test_verify_pruned_tree_rejects_delete_key_mismatch() {
        let schema = table_schema();
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&schema).await.unwrap();
        storage.finalize_acl_blob().await.unwrap();

        let sid = sid();
        let uid = insert_internal_user(&storage, sid).await;
        let auth = AuthContext::new(Some(uid as i64), sid);
        let id = insert_user_row(&storage, "Alice", 30, &auth).await;

        let root_before = storage.root_hash();
        let delete_query = delete_by_id_query(&schema.name, id);
        let delete_change = delete_change_for_query(&delete_query, uid, &schema).unwrap();
        let proof_bytes = storage
            .apply_change_with_pruned_tree(&delete_change, 3)
            .await
            .unwrap();
        let root_after = storage.root_hash();

        // Build bad column keys (same number as non-id columns in the schema, but wrong table)
        // The delete proof skips the `id` column, so we match that count.
        let bad_keys: Vec<Vec<u8>> = schema
            .columns
            .iter()
            .filter(|col| col.name != "id")
            .map(|col| keys::column_key("other_table", id, &col.name))
            .collect();
        let bad_key_refs: Vec<&[u8]> = bad_keys.iter().map(|k| k.as_slice()).collect();
        let bad_values: Vec<&[u8]> = vec![b"" as &[u8]; bad_keys.len()];
        let change = ChangelogEntry::new(
            OpType::Delete,
            auth.uid.unwrap() as u32,
            ROOT_TREE_PATH,
            &bad_key_refs,
            &bad_values,
            0,
            0,
            [0u8; 32],
        )
        .unwrap();

        let err = ChangeLog::verify_proof_and_validate(
            &change,
            &proof_bytes,
            &root_before,
            &root_after,
            1,
        )
        .unwrap_err();
        let msg = err.to_string();
        // The op validator catches the key mismatch even without embedded reads,
        // since the VerifierReader is empty and the op tries to read.
        assert!(
            msg.contains("sorted") || msg.contains("mismatch") || msg.contains("exhausted"),
            "unexpected error: {msg}"
        );
    }

    // ========== Inclusion Proof Tests ==========

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
    async fn test_prove_and_verify_keys() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert some rows
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

        // Get the root hash
        let root = storage.root_hash();

        // Generate proof for specific column keys (per-column storage)
        let column_keys = vec![
            keys::column_key("test_table", 1, "name"),
            keys::column_key("test_table", 2, "name"),
        ];

        let proof = storage.prove_keys(&column_keys).await.unwrap();
        assert!(!proof.is_empty());

        // Verify the proof
        let verified_results = verify_proof(&proof, &root, &column_keys).unwrap();
        assert_eq!(verified_results.len(), 2);

        // Check that we got values for both keys
        for (key, _value) in &verified_results {
            // The key should be one of our column keys
            assert!(column_keys.contains(key));
        }
    }

    #[tokio::test]
    async fn test_prove_query() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert some rows
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

        // Get the root hash
        let root = storage.root_hash();

        // Create a query for a specific row by ID
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(2)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        // Generate proof for the query
        let proof = storage.prove_query(&select_query).await.unwrap();
        assert!(!proof.is_empty());

        // Verify and deserialize using verify_query_proof (same as client would)
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        // Should get exactly one row with id=2
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], 2);
        assert_eq!(rows[0]["name"], "User2");
        assert_eq!(rows[0]["age"], 22);
    }

    #[tokio::test]
    async fn test_prove_and_verify_query_proof() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert a row
        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("TestUser".to_string())),
                ("age".to_string(), QueryParam::Integer(42)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_query, &auth).await.unwrap();

        // Get the root hash
        let root = storage.root_hash();

        // Create a query
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

        // Generate proof for the query
        let proof = storage.prove_query(&select_query).await.unwrap();

        // Verify and deserialize using new signature (query, proof, commitment, schema)
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], 1);
        assert_eq!(rows[0]["name"], "TestUser");
        assert_eq!(rows[0]["age"], 42);
    }

    #[tokio::test]
    async fn test_proof_verification_fails_with_wrong_root() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
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
        storage.insert(insert_query, &auth).await.unwrap();

        // Get the root hash
        let _root = storage.root_hash();

        // Generate proof for the row key
        let row_key = keys::row_key("test_table", 1);
        let proof = storage
            .prove_keys(std::slice::from_ref(&row_key))
            .await
            .unwrap();

        // Try to verify with a wrong root hash
        let wrong_root = [0u8; 32];
        let result = verify_proof(&proof, &wrong_root, &[row_key]);

        // Should fail verification
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_prove_prefix() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert multiple rows
        for i in 1..=5 {
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

        // Get the root hash
        let root = storage.root_hash();

        // Generate proof for all rows (using row prefix)
        let row_prefix = keys::row_prefix("test_table");
        let proof = storage.prove_prefix(&row_prefix).await.unwrap();
        assert!(!proof.is_empty());

        // Build list of all column keys to verify (2 non-id columns per row: age, name)
        // The `id` column is not stored as a column key (derived from key structure).
        let column_names = ["age", "name"];
        let column_keys: Vec<Vec<u8>> = (1..=5)
            .flat_map(|i| {
                column_names
                    .iter()
                    .map(move |col| keys::column_key("test_table", i, col))
            })
            .collect();

        // Verify the proof - 5 rows * 2 columns = 10 column entries
        let verified_results = verify_proof(&proof, &root, &column_keys).unwrap();
        assert_eq!(verified_results.len(), 10);
    }

    // ========== Edge Case Tests ==========

    #[tokio::test]
    async fn test_prove_query_empty_table() {
        // Test: SELECT on an empty table (no rows inserted)
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Get the root hash (table exists but has no rows)
        let root = storage.root_hash();

        // Create a table scan query (no WHERE clause)
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        // Generate proof for the query - this might fail on empty table
        let proof = storage.prove_query(&select_query).await.unwrap();

        // Verify should return empty results
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 0);
    }

    #[tokio::test]
    async fn test_prove_query_non_id_where_clause() {
        // Test: SELECT with WHERE on non-ID column (requires table scan)
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert some rows
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

        let root = storage.root_hash();

        // Create a query with WHERE on 'name' (not ID) - triggers table scan
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "name".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Text("User2".to_string())],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        // Generate and verify proof
        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        // Should get exactly one row matching the WHERE clause
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "User2");
    }

    #[tokio::test]
    async fn test_prove_query_non_id_where_empty_table() {
        // Test: SELECT with WHERE on non-ID column on empty table
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        let root = storage.root_hash();

        // Create a query with WHERE on 'name' (not ID) on empty table
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "name".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Text("NonExistent".to_string())],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        // Generate and verify proof
        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 0);
    }

    #[tokio::test]
    async fn test_prove_query_id_not_found() {
        // Test: SELECT with WHERE id = X where X doesn't exist
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert row with id=1
        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("User1".to_string())),
                ("age".to_string(), QueryParam::Integer(25)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_query, &auth).await.unwrap();

        let root = storage.root_hash();

        // Query for id=999 which doesn't exist
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(999)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        // Generate and verify proof
        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 0);
    }

    // ========== Comprehensive verify_query_proof Tests ==========

    #[tokio::test]
    async fn test_verify_query_proof_multiple_rows_no_filter() {
        // Test: SELECT * with no WHERE clause - should return all rows
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert 5 rows
        for i in 1..=5 {
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

        let root = storage.root_hash();

        // SELECT * (no WHERE)
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 5);
    }

    #[tokio::test]
    async fn test_verify_query_proof_with_order_by() {
        // Test: SELECT with ORDER BY
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert rows in non-sorted order
        for (name, age) in [("Charlie", 30), ("Alice", 25), ("Bob", 35)] {
            let insert_query = Query {
                table: "test_table".to_string(),
                operation: QueryOperation::Insert(vec![
                    ("name".to_string(), QueryParam::Text(name.to_string())),
                    ("age".to_string(), QueryParam::Integer(age)),
                ]),
                predicate: None,
                order: crate::query::Order::Asc,
                limit: None,
                join: None,
            };
            storage.insert(insert_query, &auth).await.unwrap();
        }

        let root = storage.root_hash();

        // SELECT ascending — predicate-less, sorts by row id since column-
        // based ordering is no longer expressible in the API.
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        // Sort key is row id (no predicate, no column-based ordering).
        // Insertion order was Charlie, Alice, Bob → ids 1, 2, 3.
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["name"], "Charlie");
        assert_eq!(rows[1]["name"], "Alice");
        assert_eq!(rows[2]["name"], "Bob");
    }

    /// Helpers for the limit/order proof-binding tests below.
    async fn seed_named_rows(storage: &MerkStorage, auth: &AuthContext, n: i64, prefix: &str) {
        for i in 1..=n {
            let q = Query::new(
                "test_table".to_string(),
                QueryOperation::Insert(vec![
                    (
                        "name".to_string(),
                        QueryParam::Text(format!("{prefix}{i:03}")),
                    ),
                    ("age".to_string(), QueryParam::Integer(i)),
                ]),
            );
            storage.insert(q, auth).await.unwrap();
        }
    }

    fn select_q(
        predicate: Option<Predicate>,
        order: crate::query::Order,
        limit: Option<u32>,
    ) -> Query {
        Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate,
            order,
            limit,
            join: None,
        }
    }

    fn name_pred(op: ComparisonOperator, values: Vec<&str>) -> Option<Predicate> {
        Some(Predicate {
            column: "name".to_string(),
            operator: op,
            values: values
                .into_iter()
                .map(|s| QueryParam::Text(s.to_string()))
                .collect(),
            cursor_id: None,
        })
    }

    fn id_pred(op: ComparisonOperator, values: Vec<i64>) -> Option<Predicate> {
        Some(Predicate {
            column: ID_FIELD.to_string(),
            operator: op,
            values: values.into_iter().map(QueryParam::Integer).collect(),
            cursor_id: None,
        })
    }

    #[tokio::test]
    async fn test_provable_limit_no_predicate() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 10, "row_").await;

        let root = storage.root_hash();

        // ASC: smallest 3 by row id.
        let q = select_q(None, crate::query::Order::Asc, Some(3));
        let rows = verify_and_process(&q, &storage.prove_query(&q).await.unwrap(), &root).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["name"], "row_001");
        assert_eq!(rows[2]["name"], "row_003");

        // DESC: largest 3 by row id.
        let q = select_q(None, crate::query::Order::Desc, Some(3));
        let rows = verify_and_process(&q, &storage.prove_query(&q).await.unwrap(), &root).unwrap();
        assert_eq!(rows[0]["name"], "row_010");
        assert_eq!(rows[2]["name"], "row_008");
    }

    #[tokio::test]
    async fn test_provable_limit_indexed_predicate_descending() {
        // Indexed predicate routes through the tracer path.
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 10, "alpha_").await;

        let root = storage.root_hash();
        let q = select_q(
            name_pred(ComparisonOperator::Between, vec!["alpha_002", "alpha_009"]),
            crate::query::Order::Desc,
            Some(3),
        );
        let rows = verify_and_process(&q, &storage.prove_query(&q).await.unwrap(), &root).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["name"], "alpha_009");
        assert_eq!(rows[2]["name"], "alpha_007");
    }

    #[tokio::test]
    async fn test_provable_limit_rejects_in_predicate() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 5, "row_").await;

        let q = select_q(
            name_pred(ComparisonOperator::In, vec!["row_001", "row_003"]),
            crate::query::Order::Asc,
            Some(2),
        );
        assert!(matches!(
            storage.prove_query(&q).await,
            Err(SdkError::InvalidQuery(_))
        ));
    }

    #[tokio::test]
    async fn test_verifier_rejects_oversized_proof() {
        // Server returns a tracer proof with the FULL predicate range even
        // though the client asked for limit=3. The verifier must reject
        // because its narrowed expected ReadOp won't match the full one.
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 10, "alpha_").await;

        let root = storage.root_hash();
        let pred = name_pred(ComparisonOperator::Between, vec!["alpha_002", "alpha_009"]);
        // Server "forgets" the limit when proving.
        let server_q = select_q(pred.clone(), crate::query::Order::Asc, None);
        let proof = storage.prove_query(&server_q).await.unwrap();
        // Client verifies against the limit it actually requested.
        let client_q = select_q(pred, crate::query::Order::Asc, Some(3));
        assert!(matches!(
            verify_query_proof(&client_q, &proof, &root),
            Err(SdkError::ValidationError(_))
        ));
    }

    #[tokio::test]
    async fn test_provable_limit_id_range_asc_desc() {
        // id Between + limit must route through the tracer and bind the
        // narrowed range into the proof.
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 10, "row_").await;
        let root = storage.root_hash();

        // ASC: rows 3..=5 from id BETWEEN 3 AND 8.
        let q = select_q(
            id_pred(ComparisonOperator::Between, vec![3, 8]),
            crate::query::Order::Asc,
            Some(3),
        );
        let rows = verify_and_process(&q, &storage.prove_query(&q).await.unwrap(), &root).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["name"], "row_003");
        assert_eq!(rows[2]["name"], "row_005");

        // DESC: rows 8,7,6 from the same predicate.
        let q = select_q(
            id_pred(ComparisonOperator::Between, vec![3, 8]),
            crate::query::Order::Desc,
            Some(3),
        );
        let rows = verify_and_process(&q, &storage.prove_query(&q).await.unwrap(), &root).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["name"], "row_008");
        assert_eq!(rows[2]["name"], "row_006");
    }

    #[tokio::test]
    async fn test_provable_cursor_pagination_walks_table() {
        // Walk the table with `id > cursor` + limit, verifying each page's
        // proof under the same narrowed query the client built. Concatenated
        // pages must reconstruct the full table in id order.
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 10, "row_").await;
        let root = storage.root_hash();

        const PAGE: u32 = 3;
        let mut cursor: i64 = 0;
        let mut collected: Vec<serde_json::Value> = Vec::new();
        loop {
            let q = select_q(
                id_pred(ComparisonOperator::GreaterThan, vec![cursor]),
                crate::query::Order::Asc,
                Some(PAGE),
            );
            let proof = storage.prove_query(&q).await.unwrap();
            let page = verify_and_process(&q, &proof, &root).unwrap();
            if page.is_empty() {
                break;
            }
            cursor = page.last().unwrap()[ID_FIELD].as_i64().unwrap();
            collected.extend(page);
        }

        assert_eq!(collected.len(), 10);
        for (i, row) in collected.iter().enumerate() {
            assert_eq!(row["name"], format!("row_{:03}", i + 1));
        }
    }

    #[tokio::test]
    async fn test_verifier_rejects_undersized_proof_no_predicate() {
        // No-predicate + limit now routes through the tracer. A server that
        // tries to fool the client into thinking the table is shorter than it
        // really is — by narrowing to fewer than `limit` rows when more rows
        // would be available — must be rejected. The verifier sees
        // `narrowing_keys < limit`, treats the predicate as exhausted, and
        // expects the full natural range. The server's narrowed range won't
        // match.
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 10, "row_").await;
        let root = storage.root_hash();

        let server_q = select_q(None, crate::query::Order::Asc, Some(2));
        let proof = storage.prove_query(&server_q).await.unwrap();
        let client_q = select_q(None, crate::query::Order::Asc, Some(5));
        assert!(matches!(
            verify_query_proof(&client_q, &proof, &root),
            Err(SdkError::ValidationError(_))
        ));
    }

    #[tokio::test]
    async fn test_verifier_rejects_undersized_proof_id_predicate() {
        // Same threat as above but with an id-range predicate.
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 10, "row_").await;
        let root = storage.root_hash();

        let pred = id_pred(ComparisonOperator::Between, vec![3, 8]);
        let server_q = select_q(pred.clone(), crate::query::Order::Asc, Some(2));
        let proof = storage.prove_query(&server_q).await.unwrap();
        let client_q = select_q(pred, crate::query::Order::Asc, Some(5));
        assert!(matches!(
            verify_query_proof(&client_q, &proof, &root),
            Err(SdkError::ValidationError(_))
        ));
    }

    #[tokio::test]
    async fn test_verifier_rejects_unnarrowed_simple_proof() {
        // Earlier behavior: server produced a simple (non-tracer) Merk proof
        // for an id-only or no-predicate query and the client truncated
        // client-side. After routing limited queries through the tracer, a
        // simple proof must be rejected when the client expects a tracer
        // proof.
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 10, "row_").await;
        let root = storage.root_hash();

        // Server "forgets" the limit and produces a simple proof.
        let server_q = select_q(None, crate::query::Order::Asc, None);
        let simple_proof = storage.prove_query(&server_q).await.unwrap();
        let client_q = select_q(None, crate::query::Order::Asc, Some(3));
        assert!(verify_query_proof(&client_q, &simple_proof, &root).is_err());
    }

    #[tokio::test]
    async fn test_verify_query_proof_with_column_selection() {
        // Test: SELECT specific columns
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("TestUser".to_string())),
                ("age".to_string(), QueryParam::Integer(42)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_query, &auth).await.unwrap();

        let root = storage.root_hash();

        // SELECT only 'name' column
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec!["name".to_string()]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "TestUser");
        // 'age' should not be present (or be null) since we only selected 'name'
        assert!(rows[0].get("age").is_none() || rows[0]["age"].is_null());
    }

    #[tokio::test]
    async fn test_verify_query_proof_id_greater_than() {
        // Test: WHERE id > X
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        for i in 1..=5 {
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

        let root = storage.root_hash();

        // SELECT WHERE id > 3
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::GreaterThan,
                values: vec![QueryParam::Integer(3)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 2); // id=4 and id=5
        let ids: Vec<i64> = rows.iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert!(ids.contains(&4));
        assert!(ids.contains(&5));
    }

    #[tokio::test]
    async fn test_verify_query_proof_id_less_than() {
        // Test: WHERE id < X
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        for i in 1..=5 {
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

        let root = storage.root_hash();

        // SELECT WHERE id < 3
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::LessThan,
                values: vec![QueryParam::Integer(3)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 2); // id=1 and id=2
        let ids: Vec<i64> = rows.iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
    }

    #[tokio::test]
    async fn test_verify_query_proof_single_predicate_filter() {
        // Test: Single predicate filtering by name
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert varied data
        for (name, age) in [("Alice", 25), ("Bob", 30), ("Alice", 35), ("Charlie", 25)] {
            let insert_query = Query {
                table: "test_table".to_string(),
                operation: QueryOperation::Insert(vec![
                    ("name".to_string(), QueryParam::Text(name.to_string())),
                    ("age".to_string(), QueryParam::Integer(age)),
                ]),
                predicate: None,
                order: crate::query::Order::Asc,
                limit: None,
                join: None,
            };
            storage.insert(insert_query, &auth).await.unwrap();
        }

        let root = storage.root_hash();

        // SELECT WHERE name = 'Alice' (should match both Alices)
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "name".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Text("Alice".to_string())],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        // Should match both Alice rows
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["name"], "Alice");
        assert_eq!(rows[1]["name"], "Alice");
    }

    #[tokio::test]
    async fn test_verify_query_proof_no_matching_rows() {
        // Test: WHERE clause that matches nothing (but table has data)
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        // Insert some data
        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("Alice".to_string())),
                ("age".to_string(), QueryParam::Integer(25)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_query, &auth).await.unwrap();

        let root = storage.root_hash();

        // SELECT WHERE name = 'NonExistent'
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "name".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Text("NonExistent".to_string())],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 0);
    }

    #[tokio::test]
    async fn test_verify_query_proof_wrong_commitment_fails() {
        // Test: Verification fails with wrong commitment
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("Alice".to_string())),
                ("age".to_string(), QueryParam::Integer(25)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_query, &auth).await.unwrap();

        let _root = storage.root_hash();
        let wrong_root = [0u8; 32]; // Wrong commitment

        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let result: Result<Vec<serde_json::Value>> =
            verify_and_process(&select_query, &proof, &wrong_root);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_query_proof_tampered_proof_fails() {
        // Test: Verification fails with tampered proof bytes
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("Alice".to_string())),
                ("age".to_string(), QueryParam::Integer(25)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_query, &auth).await.unwrap();

        let root = storage.root_hash();

        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let mut proof = storage.prove_query(&select_query).await.unwrap();

        // Tamper with the proof
        if !proof.is_empty() {
            proof[0] ^= 0xFF;
        }

        let result: Result<Vec<serde_json::Value>> =
            verify_and_process(&select_query, &proof, &root);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_query_proof_order_by_desc() {
        // Test: ORDER BY DESC
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

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

        let root = storage.root_hash();

        // SELECT descending — implicit sort key is row id when no predicate.
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Desc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["id"], 3);
        assert_eq!(rows[1]["id"], 2);
        assert_eq!(rows[2]["id"], 1);
    }

    #[tokio::test]
    async fn test_verify_query_proof_single_row_table() {
        // Test: Table with exactly one row
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text("OnlyOne".to_string())),
                ("age".to_string(), QueryParam::Integer(99)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_query, &auth).await.unwrap();

        let root = storage.root_hash();

        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "OnlyOne");
        assert_eq!(rows[0]["age"], 99);
        assert_eq!(rows[0]["id"], 1);
    }

    #[tokio::test]
    async fn test_verify_query_proof_special_characters() {
        // Test: Data with special characters
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        let special_name = "Test \"User\" with 'quotes' & <tags> \n newline";
        let insert_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Insert(vec![
                (
                    "name".to_string(),
                    QueryParam::Text(special_name.to_string()),
                ),
                ("age".to_string(), QueryParam::Integer(42)),
            ]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        storage.insert(insert_query, &auth).await.unwrap();

        let root = storage.root_hash();

        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], special_name);
    }

    #[tokio::test]
    async fn test_verify_query_proof_large_dataset() {
        // Test: Larger dataset (50 rows)
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        let schema = test_schema();

        storage.create_table(&schema).await.unwrap();

        for i in 1..=50 {
            let insert_query = Query {
                table: "test_table".to_string(),
                operation: QueryOperation::Insert(vec![
                    ("name".to_string(), QueryParam::Text(format!("User{i}"))),
                    ("age".to_string(), QueryParam::Integer(i)),
                ]),
                predicate: None,
                order: crate::query::Order::Asc,
                limit: None,
                join: None,
            };
            storage.insert(insert_query, &auth).await.unwrap();
        }

        let root = storage.root_hash();

        // SELECT all
        let select_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof = storage.prove_query(&select_query).await.unwrap();
        let rows: Vec<serde_json::Value> =
            verify_and_process(&select_query, &proof, &root).unwrap();

        assert_eq!(rows.len(), 50);

        // Also test range query on larger dataset
        let range_query = Query {
            table: "test_table".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::GreaterThanOrEqual,
                values: vec![QueryParam::Integer(40)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };

        let proof2 = storage.prove_query(&range_query).await.unwrap();
        let rows2: Vec<serde_json::Value> =
            verify_and_process(&range_query, &proof2, &root).unwrap();

        assert_eq!(rows2.len(), 11); // ids 40-50 inclusive
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Indexed read tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Schema with an index on the `name` column.
    fn indexed_schema() -> Schema {
        Schema {
            name: "users".to_string(),
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

    /// Helper: insert a row into the given storage + schema, returning the new row id.
    async fn insert_row(storage: &MerkStorage, table: &str, name: &str, age: i64) -> i64 {
        let auth = AuthContext::new(None, sid());
        let q = Query::new(
            table.to_string(),
            QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text(name.to_string())),
                ("age".to_string(), QueryParam::Integer(age)),
            ]),
        );
        storage.insert(q, &auth).await.unwrap()
    }

    /// Helper: build a SELECT query with an indexed WHERE clause.
    fn indexed_select(table: &str, column: &str, value: QueryParam) -> Query {
        Query {
            table: table.to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: column.to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![value],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        }
    }

    /// Performance test: verify that proof size grows as O(k * log(n)).
    ///
    /// Strategy: fix k (number of matching rows), vary n (total rows).
    /// The ratio `proof_size / (k * log2(n))` should stay roughly constant.
    #[tokio::test]
    async fn test_indexed_query_proof_size_k_log_n() {
        // We'll test with k=5 matching rows at several values of n
        let k = 5;
        let test_sizes: Vec<usize> = vec![50, 200, 800, 3200];

        let mut size_per_k_log_n: Vec<f64> = Vec::new();

        for n in &test_sizes {
            let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
            let schema = indexed_schema();
            storage.create_table(&schema).await.unwrap();

            // Insert k rows with name "Target"
            for i in 0..k {
                insert_row(&storage, "users", "Target", 20 + i as i64).await;
            }

            // Insert (n - k) rows with other names
            for i in 0..(n - k) {
                let name = format!("Other{i}");
                insert_row(&storage, "users", &name, 100 + i as i64).await;
            }

            let root = storage.root_hash();
            let query = indexed_select("users", "name", QueryParam::Text("Target".to_string()));
            let proof = storage.prove_query(&query).await.unwrap();
            let verified = verify_query_proof(&query, &proof, &root).unwrap();
            assert_eq!(
                verified.main_rows.len(),
                k,
                "Should find {k} Target rows at n={n}"
            );

            let proof_bytes = proof;
            let proof_size = proof_bytes.len() as f64;

            // Each tree node holds both row keys and index keys, so total
            // node count is roughly 2*n (n rows + n index entries + schema).
            // Use that for log calculation.
            let total_keys = (2 * n + 1) as f64; // rows + indexes + schema key
            let log_n = total_keys.log2();
            let normalized = proof_size / (k as f64 * log_n);

            println!(
                "n={n:>5}, total_keys={total_keys:>5.0}, proof_size={proof_size:>8.0} bytes, \
                 k*log2(n)={klogn:>6.1}, normalized={normalized:.1}",
                klogn = k as f64 * log_n,
            );

            size_per_k_log_n.push(normalized);
        }

        // The normalized values should be roughly constant (within a factor of ~3x).
        // If proof size were O(n) instead of O(k*log(n)), the ratio would grow ~linearly.
        let min = size_per_k_log_n
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        let max = size_per_k_log_n
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);

        println!(
            "Normalized range: {min:.1} .. {max:.1}, ratio: {ratio:.2}x",
            ratio = max / min,
        );

        // Allow up to 4x variation (generous to account for tree overhead at small n)
        assert!(
            max / min < 4.0,
            "Proof size should scale as O(k*log(n)). \
             Normalized values ranged from {min:.1} to {max:.1} (ratio {ratio:.2}x, expected < 4x)",
            ratio = max / min,
        );
    }

    /// With `limit` bound into the proof, the proof for a small fetch from
    /// a large table should be much smaller than the full-table proof.
    /// Without binding, both would walk the whole row range.
    #[tokio::test]
    async fn test_proof_size_bounded_by_limit() {
        const N: i64 = 1000;
        const LIMIT: u32 = 10;

        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, N, "row_").await;

        let limited = select_q(None, crate::query::Order::Asc, Some(LIMIT));
        let full = select_q(None, crate::query::Order::Asc, None);
        let limited_size = storage.prove_query(&limited).await.unwrap().len();
        let full_size = storage.prove_query(&full).await.unwrap().len();

        let ratio = full_size as f64 / limited_size as f64;
        println!(
            "n={N}: limit={LIMIT} proof = {limited_size} bytes, \
             full-table proof = {full_size} bytes, ratio {ratio:.1}x"
        );
        assert!(
            limited_size * 20 < full_size,
            "limit={LIMIT} proof on {N} rows ({limited_size} bytes) should be \
             at least 20x smaller than the full-table proof ({full_size} bytes); \
             limit is not bound into the proof",
        );
    }

    /// `limit = 0` is rejected up front instead of panicking inside
    /// `narrow_first_op`'s `BTreeSet::first()` / `last()` on an empty
    /// kept-row set.
    #[tokio::test]
    async fn test_limit_zero_is_rejected() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let auth = AuthContext::new(None, sid());
        storage.create_table(&test_schema()).await.unwrap();
        seed_named_rows(&storage, &auth, 5, "row_").await;

        let q = select_q(None, crate::query::Order::Asc, Some(0));
        let prove_err = storage
            .prove_query(&q)
            .await
            .expect_err("limit=0 must be rejected at prove time");
        assert!(
            format!("{prove_err}").contains("limit"),
            "unexpected error: {prove_err}",
        );

        // Verifier path runs the same guard. Generate a real proof for
        // limit=1 then ask the verifier to honor a forged limit=0 query.
        let mut q_ok = q.clone();
        q_ok.limit = Some(1);
        let proof = storage.prove_query(&q_ok).await.unwrap();
        let root = storage.root_hash();
        let verify_err = verify_query_proof(&q, &proof, &root)
            .err()
            .expect("verifier must reject limit=0");
        assert!(
            format!("{verify_err}").contains("limit"),
            "unexpected error: {verify_err}",
        );
    }

    /// With an Eq-cursor + limit bound into the proof, fetching one page from
    /// a large indexed bucket produces a proof much smaller than the
    /// unbounded-fetch proof. Without binding both would have to walk the
    /// whole indexed bucket.
    #[tokio::test]
    async fn test_proof_size_bounded_by_eq_cursor() {
        const N: i64 = 1000;
        const LIMIT: u32 = 10;

        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = indexed_schema();
        storage.create_table(&schema).await.unwrap();
        // 1000 Alices so the Eq predicate matches every row.
        for i in 0..N {
            insert_row(&storage, "users", "Alice", i).await;
        }

        let mut cursor_q = indexed_select("users", "name", QueryParam::Text("Alice".to_string()));
        cursor_q.order = crate::query::Order::Desc;
        cursor_q.limit = Some(LIMIT);
        cursor_q.predicate.as_mut().unwrap().cursor_id = Some(N / 2);

        let full_q = indexed_select("users", "name", QueryParam::Text("Alice".to_string()));

        let cursor_size = storage.prove_query(&cursor_q).await.unwrap().len();
        let full_size = storage.prove_query(&full_q).await.unwrap().len();

        let ratio = full_size as f64 / cursor_size as f64;
        println!(
            "n={N}: cursor+limit={LIMIT} proof = {cursor_size} bytes, \
             full-bucket proof = {full_size} bytes, ratio {ratio:.1}x"
        );
        assert!(
            cursor_size * 20 < full_size,
            "cursor+limit proof on {N} rows ({cursor_size} bytes) should be at \
             least 20x smaller than the full-bucket proof ({full_size} bytes); \
             cursor is not narrowing the walked range",
        );
    }

    /// Eq-with-cursor walking newest-first should yield the largest matching
    /// ids strictly below the cursor, bounded by limit, and the proof must
    /// verify. This is the chat use case
    /// (`where_eq_cursor("channel_id", X, c)` with `.descending()`).
    /// Setup: 10 rows total — Alices at ids 1, 2, 3, 5, 6, 7, 9, 10 and
    /// Bobs at ids 4 and 8 — so cursor=8 + DESC + limit=3 over Alices only
    /// yields the three highest Alice ids strictly below 8.
    #[tokio::test]
    async fn test_eq_cursor_descending() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = indexed_schema();
        storage.create_table(&schema).await.unwrap();

        for age in 0..10 {
            let name = if age == 3 || age == 7 { "Bob" } else { "Alice" };
            insert_row(&storage, "users", name, age).await;
        }

        let mut q = indexed_select("users", "name", QueryParam::Text("Alice".to_string()));
        q.order = crate::query::Order::Desc;
        q.limit = Some(3);
        q.predicate.as_mut().unwrap().cursor_id = Some(8);

        let proof = storage.prove_query(&q).await.unwrap();
        let root = storage.root_hash();
        let rows = verify_and_process(&q, &proof, &root).unwrap();

        let ids: Vec<i64> = rows.iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, vec![7, 6, 5]);
        for row in &rows {
            assert_eq!(row["name"], "Alice");
        }
    }

    /// Eq-with-cursor walking oldest-first matches `id > cursor`, the
    /// "next page" use case.
    #[tokio::test]
    async fn test_eq_cursor_ascending() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = indexed_schema();
        storage.create_table(&schema).await.unwrap();
        for age in 0..10 {
            let name = if age == 3 || age == 7 { "Bob" } else { "Alice" };
            insert_row(&storage, "users", name, age).await;
        }

        // Alice ids: {1, 2, 3, 5, 6, 7, 9, 10}. cursor=4, ASC, limit 3 →
        // Alice ids strictly > 4 in ascending order, top 3: 5, 6, 7.
        let mut q = indexed_select("users", "name", QueryParam::Text("Alice".to_string()));
        q.order = crate::query::Order::Asc;
        q.limit = Some(3);
        q.predicate.as_mut().unwrap().cursor_id = Some(4);

        let proof = storage.prove_query(&q).await.unwrap();
        let root = storage.root_hash();
        let rows = verify_and_process(&q, &proof, &root).unwrap();

        let ids: Vec<i64> = rows.iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, vec![5, 6, 7]);
    }

    /// When the cursor reduces the kept set below `limit`, the page is
    /// strictly smaller and the proof still verifies.
    #[tokio::test]
    async fn test_eq_cursor_below_limit_returns_partial_page() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = indexed_schema();
        storage.create_table(&schema).await.unwrap();
        for age in 0..10 {
            insert_row(&storage, "users", "Alice", age).await;
        }

        // Newest-first, Alices, cursor 4, limit 10 — only ids 1..=3 qualify.
        let mut q = indexed_select("users", "name", QueryParam::Text("Alice".to_string()));
        q.order = crate::query::Order::Desc;
        q.limit = Some(10);
        q.predicate.as_mut().unwrap().cursor_id = Some(4);

        let proof = storage.prove_query(&q).await.unwrap();
        let root = storage.root_hash();
        let rows = verify_and_process(&q, &proof, &root).unwrap();

        let ids: Vec<i64> = rows.iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, vec![3, 2, 1]);
    }

    /// `cursor_id` is rejected on non-Equal column predicates — the
    /// verifier's row-id sort wouldn't reproduce the column-value walk.
    #[tokio::test]
    async fn test_cursor_rejected_with_non_eq_predicate() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = indexed_schema_with_age_index();
        storage.create_table(&schema).await.unwrap();
        insert_row(&storage, "users", "Alice", 30).await;
        insert_row(&storage, "users", "Bob", 40).await;

        let q = Query {
            table: "users".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "age".to_string(),
                operator: ComparisonOperator::GreaterThan,
                values: vec![QueryParam::Integer(20)],
                cursor_id: Some(100),
            }),
            order: crate::query::Order::Desc,
            limit: Some(5),
            join: None,
        };
        let err = storage
            .prove_query(&q)
            .await
            .expect_err("non-Eq column predicate + cursor must be rejected at prove time");
        assert!(
            format!("{err}").contains("cursor_id"),
            "unexpected error: {err}",
        );
    }

    /// `cursor_id` is rejected on id-column predicates: the cursor would
    /// contradict the eq value on the same column.
    #[tokio::test]
    async fn test_cursor_rejected_on_id_predicate() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = indexed_schema();
        storage.create_table(&schema).await.unwrap();
        insert_row(&storage, "users", "Alice", 30).await;

        let q = Query {
            table: "users".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: ID_FIELD.to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(1)],
                cursor_id: Some(0),
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        };
        let err = storage
            .prove_query(&q)
            .await
            .expect_err("cursor_id on id-column predicate must be rejected");
        assert!(
            format!("{err}").contains("cursor_id"),
            "unexpected error: {err}",
        );
    }

    #[tokio::test]
    async fn test_indexed_query_via_prove_query() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = indexed_schema();
        storage.create_table(&schema).await.unwrap();

        insert_row(&storage, "users", "Alice", 30).await;
        insert_row(&storage, "users", "Bob", 25).await;
        insert_row(&storage, "users", "Alice", 40).await;
        insert_row(&storage, "users", "Carol", 35).await;

        let root = storage.root_hash();
        let query = indexed_select("users", "name", QueryParam::Text("Alice".to_string()));
        let proof = storage.prove_query(&query).await.unwrap();

        let verified = verify_query_proof(&query, &proof, &root).unwrap();
        assert_eq!(verified.main_rows.len(), 2, "Should find 2 Alice rows");

        for row in &verified.main_rows {
            assert_eq!(row["name"], "Alice");
        }
    }

    #[tokio::test]
    async fn test_indexed_query_no_results() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = indexed_schema();
        storage.create_table(&schema).await.unwrap();

        insert_row(&storage, "users", "Alice", 30).await;

        let root = storage.root_hash();
        let query = indexed_select("users", "name", QueryParam::Text("NonExistent".to_string()));
        let proof = storage.prove_query(&query).await.unwrap();

        let verified = verify_query_proof(&query, &proof, &root).unwrap();
        assert_eq!(verified.main_rows.len(), 0, "No rows should match");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Join proof tests
    // ═══════════════════════════════════════════════════════════════════════

    use crate::query::JoinClause;

    /// Schema for an "orders" table with a plaintext integer `user_id` column.
    fn orders_schema() -> Schema {
        Schema {
            name: "orders".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "user_id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "amount".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
            ],
            auto_increment: true,
        }
    }

    /// Schema for an "orders" table with an index on `user_id`.
    fn orders_schema_indexed() -> Schema {
        let mut s = orders_schema();
        s.columns
            .iter_mut()
            .find(|c| c.name == "user_id")
            .unwrap()
            .indexed = true;
        s
    }

    /// Helper: insert an order row.
    async fn insert_order(storage: &MerkStorage, user_id: i64, amount: i64) -> i64 {
        let auth = AuthContext::new(None, sid());
        let q = Query::new(
            "orders".to_string(),
            QueryOperation::Insert(vec![
                ("user_id".to_string(), QueryParam::Integer(user_id)),
                ("amount".to_string(), QueryParam::Integer(amount)),
            ]),
        );
        storage.insert(q, &auth).await.unwrap()
    }

    /// Helper: build a SELECT on orders with a join to users.
    fn orders_join_on_pk() -> JoinClause {
        JoinClause {
            table: "users".to_string(),
            on_condition: ("user_id".to_string(), "id".to_string()),
        }
    }

    /// Schema for "users" with indexes on both `name` and `age`.
    fn indexed_schema_with_age_index() -> Schema {
        let mut s = indexed_schema();
        s.columns
            .iter_mut()
            .find(|c| c.name == "age")
            .unwrap()
            .indexed = true;
        s
    }

    /// Helper: build a join on a non-PK indexed column.
    /// Joins orders.amount to users.age (indexed on users).
    fn orders_join_on_index() -> JoinClause {
        JoinClause {
            table: "users".to_string(),
            on_condition: ("amount".to_string(), "age".to_string()),
        }
    }

    // --- Test 1: Table scan + join on PK ---

    #[tokio::test]
    async fn test_join_table_scan_pk() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_schema()).await.unwrap();
        storage.create_table(&orders_schema()).await.unwrap();

        let alice_id = insert_row(&storage, "users", "Alice", 30).await;
        let bob_id = insert_row(&storage, "users", "Bob", 25).await;
        insert_order(&storage, alice_id, 100).await;
        insert_order(&storage, bob_id, 200).await;
        insert_order(&storage, alice_id, 150).await;

        let root = storage.root_hash();
        let query = Query {
            table: "orders".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(orders_join_on_pk()),
        };

        let proof = storage.prove_query(&query).await.unwrap();
        let verified = verify_query_proof(&query, &proof, &root).unwrap();

        assert_eq!(verified.main_rows.len(), 3, "3 orders");
        let joined_users = verified.rows_by_table.get("users").unwrap();
        // Alice and Bob (deduplicated — Alice appears twice in orders but once in users)
        assert_eq!(joined_users.len(), 2, "2 distinct users");
    }

    // --- Test 2: Table scan + join on foreign index ---

    #[tokio::test]
    async fn test_join_table_scan_foreign_index() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage
            .create_table(&indexed_schema_with_age_index())
            .await
            .unwrap();
        storage.create_table(&orders_schema()).await.unwrap();

        insert_row(&storage, "users", "Alice", 100).await;
        insert_row(&storage, "users", "Bob", 200).await;
        insert_row(&storage, "users", "Carol", 100).await; // same age as Alice
        insert_order(&storage, 1, 100).await; // amount=100, matches age=100
        insert_order(&storage, 2, 200).await; // amount=200, matches age=200

        let root = storage.root_hash();
        // Join orders.amount → users.age (indexed on users)
        let query = Query {
            table: "orders".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(orders_join_on_index()),
        };

        let proof = storage.prove_query(&query).await.unwrap();
        let verified = verify_query_proof(&query, &proof, &root).unwrap();

        assert_eq!(verified.main_rows.len(), 2, "2 orders");
        let joined_users = verified.rows_by_table.get("users").unwrap();
        // age=100 matches Alice+Carol, age=200 matches Bob → 3 user rows
        assert_eq!(
            joined_users.len(),
            3,
            "3 user rows (Alice, Carol via age=100, Bob via age=200)"
        );
    }

    // --- Test 3: Indexed WHERE on main + join on PK ---

    #[tokio::test]
    async fn test_join_indexed_main_pk() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_schema()).await.unwrap();
        storage
            .create_table(&orders_schema_indexed())
            .await
            .unwrap();

        let alice_id = insert_row(&storage, "users", "Alice", 30).await;
        let bob_id = insert_row(&storage, "users", "Bob", 25).await;
        insert_order(&storage, alice_id, 100).await;
        insert_order(&storage, bob_id, 200).await;
        insert_order(&storage, alice_id, 300).await;

        let root = storage.root_hash();
        // WHERE user_id = alice_id (indexed) + JOIN users on id
        let query = Query {
            table: "orders".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "user_id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(alice_id)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(orders_join_on_pk()),
        };

        let proof = storage.prove_query(&query).await.unwrap();
        let verified = verify_query_proof(&query, &proof, &root).unwrap();

        // Main rows: only Alice's orders (filtered by indexed WHERE)
        assert_eq!(verified.main_rows.len(), 2, "2 orders for Alice");
        for row in &verified.main_rows {
            assert_eq!(row["user_id"], alice_id);
        }
        // Joined: only Alice
        let joined_users = verified.rows_by_table.get("users").unwrap();
        assert_eq!(joined_users.len(), 1);
        assert_eq!(joined_users[0]["name"], "Alice");
    }

    // --- Test 4: Indexed WHERE on main + join on foreign index ---

    #[tokio::test]
    async fn test_join_indexed_main_foreign_index() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage
            .create_table(&indexed_schema_with_age_index())
            .await
            .unwrap();
        storage
            .create_table(&orders_schema_indexed())
            .await
            .unwrap();

        let alice_id = insert_row(&storage, "users", "Alice", 100).await;
        let bob_id = insert_row(&storage, "users", "Bob", 200).await;
        insert_row(&storage, "users", "Carol", 100).await; // same age as Alice
        insert_order(&storage, alice_id, 100).await;
        insert_order(&storage, bob_id, 200).await;
        insert_order(&storage, alice_id, 999).await; // amount=999, no matching age

        let root = storage.root_hash();
        // WHERE user_id = alice_id (indexed) + JOIN on amount→age (indexed)
        let query = Query {
            table: "orders".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "user_id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(alice_id)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(orders_join_on_index()),
        };

        let proof = storage.prove_query(&query).await.unwrap();
        let verified = verify_query_proof(&query, &proof, &root).unwrap();

        // Main: Alice's 2 orders
        assert_eq!(verified.main_rows.len(), 2, "2 orders for Alice");
        // Joined: amount=100 → age=100 matches Alice+Carol, amount=999 → no match
        let joined_users = verified.rows_by_table.get("users").unwrap();
        assert_eq!(joined_users.len(), 2, "Alice and Carol matched via age=100");
    }

    // --- Test 5: ID WHERE on main + join on PK ---

    #[tokio::test]
    async fn test_join_id_where_pk() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_schema()).await.unwrap();
        storage.create_table(&orders_schema()).await.unwrap();

        let alice_id = insert_row(&storage, "users", "Alice", 30).await;
        let bob_id = insert_row(&storage, "users", "Bob", 25).await;
        let order1 = insert_order(&storage, alice_id, 100).await;
        insert_order(&storage, bob_id, 200).await;

        let root = storage.root_hash();
        // WHERE id = order1 + JOIN users
        let query = Query {
            table: "orders".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(order1)],
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(orders_join_on_pk()),
        };

        let proof = storage.prove_query(&query).await.unwrap();
        let verified = verify_query_proof(&query, &proof, &root).unwrap();

        assert_eq!(verified.main_rows.len(), 1);
        assert_eq!(verified.main_rows[0]["user_id"], alice_id);
        let joined_users = verified.rows_by_table.get("users").unwrap();
        assert_eq!(joined_users.len(), 1);
        assert_eq!(joined_users[0]["name"], "Alice");
    }

    #[tokio::test]
    async fn test_unaliased_self_join_rejected() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_schema()).await.unwrap();
        insert_row(&storage, "users", "Alice", 30).await;

        let query = Query {
            table: "users".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(JoinClause {
                table: "users".to_string(),
                on_condition: ("age".to_string(), "id".to_string()),
            }),
        };

        let err = storage.prove_query(&query).await.unwrap_err();
        assert!(
            format!("{err}").contains("self-joins require a distinct alias"),
            "unexpected error: {err}"
        );

        let err = match verify_query_proof(&query, &[], &[0u8; 32]) {
            Ok(_) => panic!("same-table join verifier should reject query"),
            Err(err) => err,
        };
        assert!(
            format!("{err}").contains("self-joins require a distinct alias"),
            "unexpected verifier error: {err}"
        );
    }

    #[tokio::test]
    async fn test_aliased_self_join_pk() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_schema()).await.unwrap();
        let alice_id = insert_row(&storage, "users", "Alice", 30).await;
        insert_row(&storage, "users", "Bob", alice_id).await;

        let root = storage.root_hash();
        let query = Query {
            table: "users".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(JoinClause {
                table: "users as parent".to_string(),
                on_condition: ("age".to_string(), "id".to_string()),
            }),
        };

        let proof = storage.prove_query(&query).await.unwrap();
        let verified = verify_query_proof(&query, &proof, &root).unwrap();

        assert_eq!(verified.main_rows.len(), 2);
        let joined_users = verified.rows_by_table.get("users").unwrap();
        assert_eq!(joined_users.len(), 1);
        assert_eq!(joined_users[0]["name"], "Alice");
    }

    // --- Test 6: Join with no matching FK values ---

    #[tokio::test]
    async fn test_join_no_fk_matches() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_schema()).await.unwrap();
        storage.create_table(&orders_schema()).await.unwrap();

        insert_row(&storage, "users", "Alice", 30).await;
        // Order with user_id=999 — no such user
        insert_order(&storage, 999, 100).await;

        let root = storage.root_hash();
        let query = Query {
            table: "orders".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(orders_join_on_pk()),
        };

        let proof = storage.prove_query(&query).await.unwrap();
        let verified = verify_query_proof(&query, &proof, &root).unwrap();

        assert_eq!(verified.main_rows.len(), 1, "1 order");
        // No matching user for user_id=999
        let joined_users = verified.rows_by_table.get("users");
        assert!(
            joined_users.is_none() || joined_users.unwrap().is_empty(),
            "no joined users"
        );
    }

    // --- Test 7: Multiple orders referencing same user (FK dedup) ---

    #[tokio::test]
    async fn test_join_fk_dedup() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_schema()).await.unwrap();
        storage.create_table(&orders_schema()).await.unwrap();

        let alice_id = insert_row(&storage, "users", "Alice", 30).await;
        // 5 orders all for Alice
        for i in 0..5 {
            insert_order(&storage, alice_id, 100 + i).await;
        }

        let root = storage.root_hash();
        let query = Query {
            table: "orders".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(orders_join_on_pk()),
        };

        let proof = storage.prove_query(&query).await.unwrap();
        let verified = verify_query_proof(&query, &proof, &root).unwrap();

        assert_eq!(verified.main_rows.len(), 5, "5 orders");
        let joined_users = verified.rows_by_table.get("users").unwrap();
        // Alice should appear only once despite 5 orders referencing her
        assert_eq!(joined_users.len(), 1, "1 user (deduplicated)");
        assert_eq!(joined_users[0]["name"], "Alice");
    }

    // --- Test 8: Proof size scales with matched rows, not joined table size ---

    /// Performance test: verify that join proof size grows as O(k * log(n)).
    ///
    /// Strategy: fix k (number of matched joined rows), vary n (total rows in
    /// the joined table). The ratio `proof_size / (k * log2(n))` should stay
    /// roughly constant.
    #[tokio::test]
    async fn test_join_proof_size_k_log_n() {
        // We'll test with k=5 orders referencing 5 distinct users, varying
        // the total number of users (n) in the joined table.
        let k = 5;
        let test_sizes: Vec<usize> = vec![50, 200, 800, 3200];

        let mut size_per_k_log_n: Vec<f64> = Vec::new();

        for n in &test_sizes {
            let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
            storage.create_table(&indexed_schema()).await.unwrap();
            storage.create_table(&orders_schema()).await.unwrap();

            // Insert n users total
            for i in 0..*n {
                let name = format!("User{i}");
                insert_row(&storage, "users", &name, 20 + i as i64).await;
            }

            // Insert k orders referencing the first k users
            for uid in 1..=(k as i64) {
                insert_order(&storage, uid, uid * 100).await;
            }

            let root = storage.root_hash();
            let query = Query {
                table: "orders".to_string(),
                operation: QueryOperation::Select(vec![]),
                predicate: None,
                order: crate::query::Order::Asc,
                limit: None,
                join: Some(orders_join_on_pk()),
            };

            let proof = storage.prove_query(&query).await.unwrap();
            let verified = verify_query_proof(&query, &proof, &root).unwrap();
            assert_eq!(
                verified.main_rows.len(),
                k,
                "Should find {k} orders at n={n}"
            );
            let joined = verified.rows_by_table.get("users").unwrap();
            assert_eq!(joined.len(), k, "Should find {k} matched users at n={n}");

            let proof_size = proof.len() as f64;

            // The joined users table has n rows + n index entries + schema key.
            // The orders table is small (k rows). The proof should scale with
            // the Merk tree depth of the joined table.
            let total_keys = (2 * n + 1) as f64; // users rows + indexes + schema key
            let log_n = total_keys.log2();
            let normalized = proof_size / (k as f64 * log_n);

            println!(
                "n={n:>5}, total_keys={total_keys:>5.0}, proof_size={proof_size:>8.0} bytes, \
                 k*log2(n)={klogn:>6.1}, normalized={normalized:.1}",
                klogn = k as f64 * log_n,
            );

            size_per_k_log_n.push(normalized);
        }

        // The normalized values should be roughly constant (within a factor of ~3x).
        // If proof size were O(n) instead of O(k*log(n)), the ratio would grow ~linearly.
        let min = size_per_k_log_n
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        let max = size_per_k_log_n
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);

        println!(
            "Normalized range: {min:.1} .. {max:.1}, ratio: {ratio:.2}x",
            ratio = max / min,
        );

        // Allow up to 4x variation (generous to account for tree overhead at small n)
        assert!(
            max / min < 4.0,
            "Join proof size should scale as O(k*log(n)). \
             Normalized values ranged from {min:.1} to {max:.1} (ratio {ratio:.2}x, expected < 4x)",
            ratio = max / min,
        );
    }

    // --- Test 9: Join proof rejects wrong root ---

    #[tokio::test]
    async fn test_join_rejects_wrong_root() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_schema()).await.unwrap();
        storage.create_table(&orders_schema()).await.unwrap();

        let alice_id = insert_row(&storage, "users", "Alice", 30).await;
        insert_order(&storage, alice_id, 100).await;

        let root = storage.root_hash();
        let query = Query {
            table: "orders".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: None,
            order: crate::query::Order::Asc,
            limit: None,
            join: Some(orders_join_on_pk()),
        };

        let proof = storage.prove_query(&query).await.unwrap();

        let mut bad_root = root;
        bad_root[0] ^= 0xFF;
        let result = verify_query_proof(&query, &proof, &bad_root);
        assert!(result.is_err(), "Should fail with wrong root");
    }

    #[tokio::test]
    async fn test_indexed_query_rejects_wrong_root() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        let schema = indexed_schema();
        storage.create_table(&schema).await.unwrap();

        insert_row(&storage, "users", "Alice", 30).await;

        let root = storage.root_hash();
        let query = indexed_select("users", "name", QueryParam::Text("Alice".to_string()));
        let proof = storage.prove_query(&query).await.unwrap();

        let mut bad_root = root;
        bad_root[0] ^= 0xFF;

        let result = verify_query_proof(&query, &proof, &bad_root);
        assert!(result.is_err(), "Should fail with wrong root");
    }

    /// A SELECT proof must not contain Write steps. Without this check, a
    /// malicious server can wrap reads with Write/undo-Write pairs that leave
    /// start_root == end_root but return data from a transient state never
    /// committed to the tree.
    #[tokio::test]
    async fn test_select_proof_rejects_write_steps() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_schema()).await.unwrap();

        insert_row(&storage, "users", "Alice", 30).await;

        let root = storage.root_hash();
        let query = indexed_select("users", "name", QueryParam::Text("Alice".to_string()));
        let proof = storage.prove_query(&query).await.unwrap();
        verify_query_proof(&query, &proof, &root).expect("baseline proof should verify");

        let mut select_proof: TracerSelectProof = postcard::from_bytes(&proof).unwrap();
        select_proof
            .tracer_proof
            .steps
            .push(TraceStep::Write(vec![BatchOp::Delete {
                key: b"nonexistent".to_vec(),
            }]));
        let tampered = postcard::to_allocvec(&select_proof).unwrap();

        let result = verify_query_proof(&query, &tampered, &root);
        match result {
            Err(SdkError::ValidationError(msg)) if msg.contains("must not contain write steps") => {
            }
            Err(e) => panic!("Expected write-step rejection, got error: {e:?}"),
            Ok(_) => panic!("Expected write-step rejection, but verification succeeded"),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // prefix_successor_required helper tests (issue #19)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn prefix_successor_required_strips_trailing_ff_and_increments() {
        assert_eq!(prefix_successor_required(b"abc").unwrap(), b"abd".to_vec());
        // Tuple encoding of i64 255 is [0x15, 0xFF]: successor is [0x16].
        assert_eq!(
            prefix_successor_required(&[0x15, 0xFF]).unwrap(),
            vec![0x16]
        );
        // Tuple encoding of i64 -256 is [0x12, 0xFE, 0xFF]: successor is [0x12, 0xFF].
        assert_eq!(
            prefix_successor_required(&[0x12, 0xFE, 0xFF]).unwrap(),
            vec![0x12, 0xFF]
        );
        // Tuple encoding of i64 65535 is [0x16, 0xFF, 0xFF] — multi-byte
        // 0xFF suffix forcing carry propagation up to the type tag.
        assert_eq!(
            prefix_successor_required(&[0x16, 0xFF, 0xFF]).unwrap(),
            vec![0x17]
        );
        // Interior 0x00 must NOT be treated like a stripped suffix.
        assert_eq!(
            prefix_successor_required(&[0x15, 0x00, 0xFF]).unwrap(),
            vec![0x15, 0x01]
        );
    }

    #[test]
    fn prefix_successor_required_errors_on_empty_or_all_ff() {
        for input in [&[][..], &[0xFF][..], &[0xFF, 0xFF][..]] {
            let err = prefix_successor_required(input).unwrap_err();
            match err {
                SdkError::DatabaseError(msg) => {
                    assert!(
                        msg.contains("no lexicographic successor"),
                        "unexpected error message: {msg}"
                    );
                }
                other => panic!("expected DatabaseError, got {other:?}"),
            }
        }
    }

    /// Randomized invariant check: for any prefix containing at least one byte
    /// less than 0xFF, every extension of that prefix must sort strictly less
    /// than its successor. This is the contract the indexed range code relies
    /// on when using `[prefix, prefix_successor(prefix))` as a half-open range.
    #[test]
    fn prefix_successor_required_bounds_all_extensions() {
        // Tiny deterministic xorshift PRNG — avoids adding `rand` as a dep
        // requirement for this single test.
        fn next(state: &mut u64) -> u64 {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            x
        }
        fn random_bytes(state: &mut u64, len: usize) -> Vec<u8> {
            (0..len).map(|_| (next(state) & 0xFF) as u8).collect()
        }

        let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
        for _ in 0..10_000 {
            let plen = ((next(&mut state) % 16) + 1) as usize;
            let mut prefix = random_bytes(&mut state, plen);
            if prefix.iter().all(|&b| b == 0xFF) {
                prefix[0] = 0;
            }
            let succ = prefix_successor_required(&prefix)
                .expect("by construction: prefix contains a byte < 0xFF");

            // succ strictly greater than prefix
            assert!(
                prefix.as_slice() < succ.as_slice(),
                "prefix={prefix:02x?} not < succ={succ:02x?}"
            );

            // Every key that extends `prefix` sorts strictly less than succ.
            let slen = (next(&mut state) % 17) as usize;
            let suffix = random_bytes(&mut state, slen);
            let mut extended = prefix.clone();
            extended.extend_from_slice(&suffix);
            assert!(
                extended.as_slice() < succ.as_slice(),
                "extended={extended:02x?} not < succ={succ:02x?} (prefix={prefix:02x?})"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Indexed-range boundary regression tests (issue #19)
    //
    // Before the fix, `increment_prefix` only bumped the last byte with
    // saturating addition, so range bounds built from tuple-encoded values
    // ending in 0xFF (e.g. i64 255 → [0x15, 0xFF]) were wrong. Both the
    // execution path and the proof verifier consumed the same broken bound,
    // so semantically-incorrect results still verified.
    // ═══════════════════════════════════════════════════════════════════════

    fn indexed_age_schema() -> Schema {
        Schema {
            name: "ages".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "age".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: true,
                },
            ],
            auto_increment: true,
        }
    }

    async fn insert_age(storage: &MerkStorage, age: i64) -> i64 {
        let auth = AuthContext::new(None, sid());
        let q = Query::new(
            "ages".to_string(),
            QueryOperation::Insert(vec![("age".to_string(), QueryParam::Integer(age))]),
        );
        storage.insert(q, &auth).await.unwrap()
    }

    fn age_query(operator: ComparisonOperator, values: Vec<i64>) -> Query {
        Query {
            table: "ages".to_string(),
            operation: QueryOperation::Select(vec![]),
            predicate: Some(Predicate {
                column: "age".to_string(),
                operator,
                values: values.into_iter().map(QueryParam::Integer).collect(),
                cursor_id: None,
            }),
            order: crate::query::Order::Asc,
            limit: None,
            join: None,
        }
    }

    async fn assert_age_query(
        storage: &MerkStorage,
        root: &[u8; 32],
        operator: ComparisonOperator,
        values: Vec<i64>,
        expected: &[i64],
    ) {
        let query = age_query(operator.clone(), values.clone());

        let proof = storage.prove_query(&query).await.unwrap();
        let verified = verify_query_proof(&query, &proof, root).unwrap();
        let mut verified_ages: Vec<i64> = verified
            .main_rows
            .iter()
            .map(|row| row["age"].as_i64().expect("age is integer"))
            .collect();
        verified_ages.sort();

        let mut expected_sorted = expected.to_vec();
        expected_sorted.sort();

        assert_eq!(
            verified_ages, expected_sorted,
            "wrong rows for op={operator:?} values={values:?}"
        );
    }

    #[tokio::test]
    async fn test_indexed_range_boundary_0xff_values() {
        let storage = MerkStorage::in_memory_with_internal_tables().await.unwrap();
        storage.create_table(&indexed_age_schema()).await.unwrap();

        // Ages chosen to exercise every 0xFF-suffix encoding case:
        //   255   → [0x15, 0xFF]            (1-byte-positive / 2-byte boundary)
        //  -256   → [0x12, 0xFE, 0xFF]      (negative one's-complement ending 0xFF)
        //   65535 → [0x16, 0xFF, 0xFF]      (multi-byte 0xFF suffix, carry propagation)
        //   254, 256, 65536 straddle those boundaries.
        for age in [-256, 254, 255, 256, 65535, 65536] {
            insert_age(&storage, age).await;
        }
        let root = storage.root_hash();

        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::GreaterThan,
            vec![255],
            &[256, 65535, 65536],
        )
        .await;
        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::GreaterThanOrEqual,
            vec![255],
            &[255, 256, 65535, 65536],
        )
        .await;
        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::LessThan,
            vec![255],
            &[-256, 254],
        )
        .await;
        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::LessThanOrEqual,
            vec![255],
            &[-256, 254, 255],
        )
        .await;
        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::GreaterThan,
            vec![65535],
            &[65536],
        )
        .await;
        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::LessThanOrEqual,
            vec![65535],
            &[-256, 254, 255, 256, 65535],
        )
        .await;
        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::Between,
            vec![254, 255],
            &[254, 255],
        )
        .await;
        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::Between,
            vec![255, 256],
            &[255, 256],
        )
        .await;
        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::Between,
            vec![254, 65535],
            &[254, 255, 256, 65535],
        )
        .await;
        assert_age_query(
            &storage,
            &root,
            ComparisonOperator::Between,
            vec![-256, 255],
            &[-256, 254, 255],
        )
        .await;
    }
}
