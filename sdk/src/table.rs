use crate::crypto::{decrypt_table_rows, encrypt_query_fields};
use crate::schema::ColumnType;
use crate::{changelog::ChangeBuilder, Space};
use encrypted_spaces_backend::{
    error::{Result, SdkError},
    merk_storage::{apply_server_view, process_query_results, ID_FIELD},
    query::{ComparisonOperator, JoinClause, Order, Predicate, Query, QueryOperation, QueryParam},
    schema::Schema,
};
use encrypted_spaces_changelog_core::changelog::{Change, OpType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

use crate::cache::{extract_cache_predicates, indexed_columns_for_schema};

/// Typestate marker: no server-side predicate has been set yet.
pub struct Unpredicated;
/// Typestate marker: a server-side predicate has been set.
pub struct Predicated;

/// Generate `where_*` methods on an `Unpredicated` builder that transition to `Predicated`.
///
/// `$Builder` is the builder type (e.g. `SelectBuilder`).
/// `$into_predicated` is an expression that constructs the `Predicated` variant from `self`.
macro_rules! impl_where_methods {
    ($Builder:ident, |$self:ident| $into_predicated:expr) => {
        #[allow(unused_mut)]
        impl<T: Send + Sync> $Builder<T, Unpredicated> {
            pub fn where_eq<V: Into<QueryParam>>($self, column: &str, value: V) -> $Builder<T, Predicated> {
                $self.set_predicate(column, ComparisonOperator::Equal, vec![value.into()], None)
            }
            pub fn where_in($self, column: &str, values: &[QueryParam]) -> $Builder<T, Predicated> {
                $self.set_predicate(column, ComparisonOperator::In, values.to_vec(), None)
            }
            pub fn where_gt<V: Into<QueryParam>>($self, column: &str, value: V) -> $Builder<T, Predicated> {
                $self.set_predicate(column, ComparisonOperator::GreaterThan, vec![value.into()], None)
            }
            pub fn where_gte<V: Into<QueryParam>>($self, column: &str, value: V) -> $Builder<T, Predicated> {
                $self.set_predicate(column, ComparisonOperator::GreaterThanOrEqual, vec![value.into()], None)
            }
            pub fn where_lt<V: Into<QueryParam>>($self, column: &str, value: V) -> $Builder<T, Predicated> {
                $self.set_predicate(column, ComparisonOperator::LessThan, vec![value.into()], None)
            }
            pub fn where_lte<V: Into<QueryParam>>($self, column: &str, value: V) -> $Builder<T, Predicated> {
                $self.set_predicate(column, ComparisonOperator::LessThanOrEqual, vec![value.into()], None)
            }
            pub fn where_between<V: Into<QueryParam>>($self, column: &str, low: V, high: V) -> $Builder<T, Predicated> {
                $self.set_predicate(column, ComparisonOperator::Between, vec![low.into(), high.into()], None)
            }

            fn set_predicate(
                mut $self,
                column: &str,
                operator: ComparisonOperator,
                mut values: Vec<QueryParam>,
                cursor_id: Option<i64>,
            ) -> $Builder<T, Predicated> {
                if let Some(schema) = $self.space.get_table_schema(&$self.query.table) {
                    assert!(
                        is_column_indexed_or_pk(&schema, column),
                        "where_* predicate column '{column}' must be the primary key or an indexed column on table '{}'",
                        $self.query.table
                    );
                    normalize_predicate_values_for_schema(&schema, column, &mut values);
                }
                $self.query.predicate = Some(Predicate {
                    column: column.to_string(),
                    operator,
                    values,
                    cursor_id,
                });
                $into_predicated
            }
        }
    };
}

/// A typed handle to relational data.
///
/// `Table<T>` represents a concrete table named [`Table::name`]. The type
/// parameter `T` is your row model used for inserts and typed builders;
/// it is not stored at runtime (carried via `PhantomData`).
///
/// # Examples
///
/// ```ignore
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct UserRow { id: Option<i64>, name: String, age: u32 }
///
/// let users: Table<UserRow> = space.table("users");
/// let new_id = users.insert(&UserRow { id: None, name: "Ada".into(), age: 36 }).execute().await?;
/// ```
pub struct Table<T> {
    /// Table name in the database.
    pub(crate) name: String,
    /// Parent space containing backend and auth context.
    pub(crate) space: Arc<Space>,
    /// Marker for the row type `T`.
    _phantom: PhantomData<T>,
}

impl<T> Table<T> {
    /// Create a new table handle (crate-internal).
    ///
    /// Prefer constructing tables via [`Space::table`](crate::Space::table)
    /// so callers don't have to manage the space directly.
    pub(crate) fn new(name: String, space: Arc<Space>) -> Self {
        Self {
            name,
            space,
            _phantom: PhantomData,
        }
    }

    /// Return this table's database name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Begin building a `SELECT` query on this table.
    ///
    /// The returned [`SelectBuilder<T>`] lets you specify predicates, ordering,
    /// limits, and then fetch typed rows.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let rows = users
    ///     .select()
    ///     .where_gte("age", 18)
    ///     .descending()
    ///     .limit(10)
    ///     .all::<UserRow>()?;
    /// ```
    pub fn select(&self) -> SelectBuilder<T, Unpredicated> {
        SelectBuilder::new(self.name.clone(), Arc::clone(&self.space))
    }

    /// Insert a row and return an insert builder.
    ///
    /// Construction is infallible. If `data` fails to serialize to a JSON
    /// object the error is captured inside the builder and surfaced when
    /// you call [`InsertBuilder::execute`] (or one of the related execute
    /// methods). This keeps the call site uniform with `update()` /
    /// `delete()` / `select()`, which also return builders directly.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let id = users.insert(&UserRow { id: None, name: "Grace".into(), age: 37 }).execute().await?;
    /// ```
    pub fn insert(&self, data: &T) -> InsertBuilder<T>
    where
        T: Serialize,
    {
        InsertBuilder::new(self.name.clone(), Arc::clone(&self.space), data)
    }

    /// Begin building an `UPDATE` query on this table.
    ///
    /// The returned [`UpdateBuilder<T>`] lets you specify sets and predicates.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let affected = users
    ///     .update()
    ///     .set("name", "Ada Lovelace")
    ///     .where_eq("id", 1)
    ///     .execute()?;
    /// ```
    pub fn update(&self) -> UpdateBuilder<T, Unpredicated> {
        UpdateBuilder::new(self.name.clone(), Arc::clone(&self.space))
    }

    /// Begin building a `DELETE` query on this table.
    ///
    /// The returned [`DeleteBuilder<T>`] lets you specify predicates.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let removed = users
    ///     .delete()
    ///     .where_eq("id", 1)
    ///     .execute()?;
    /// ```
    pub fn delete(&self) -> DeleteBuilder<T, Unpredicated> {
        DeleteBuilder::new(self.name.clone(), Arc::clone(&self.space))
    }
}

impl<T> Clone for Table<T> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            space: Arc::clone(&self.space),
            _phantom: PhantomData,
        }
    }
}

/// Check whether `column` is the primary key or appears in a secondary index.
fn is_column_indexed_or_pk(schema: &Schema, column: &str) -> bool {
    column == ID_FIELD || schema.indexed_columns().contains(&column)
}

/// Parse a table name that may contain an alias: `"users as u"` → `("users", Some("u"))`.
fn parse_table_alias(table: &str) -> (&str, Option<&str>) {
    if let Some(pos) = table.find(" as ") {
        (table[..pos].trim(), Some(table[(pos + 4)..].trim()))
    } else {
        (table.trim(), None)
    }
}

/// Strip a `"table.column"` prefix, returning just `"column"`.
fn strip_table_prefix(col: &str) -> &str {
    col.rfind('.').map_or(col, |pos| &col[(pos + 1)..])
}

fn validate_join(query: &Query, schemas: &HashMap<String, Schema>) -> Result<()> {
    let Some(join) = &query.join else {
        return Ok(());
    };

    let (joined_table, alias) = parse_table_alias(&join.table);
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

    let pk_col = strip_table_prefix(&join.on_condition.1);
    if let Some(schema) = schemas.get(joined_table) {
        if !is_column_indexed_or_pk(schema, pk_col) {
            return Err(SdkError::InvalidQuery(format!(
                "join target column '{pk_col}' on table '{joined_table}' must be the \
                 primary key or an indexed column"
            )));
        }
    }

    Ok(())
}

fn validate_original_select_predicate(
    query: &Query,
    schemas: &HashMap<String, Schema>,
) -> Result<()> {
    let Some(pred) = &query.predicate else {
        return Ok(());
    };
    let Some(schema) = schemas.get(&query.table) else {
        return Ok(());
    };

    validate_predicate_arity(pred)?;

    if pred.column == ID_FIELD {
        validate_predicate_values(
            pred,
            |value| matches!(value, QueryParam::Integer(_)),
            || "id predicate requires integer value(s)".to_string(),
        )?;
        return Ok(());
    }

    let Some(column) = schema
        .columns
        .iter()
        .find(|column| column.name == pred.column)
    else {
        return Err(SdkError::InvalidQuery(format!(
            "predicate column '{}' not found on table '{}'",
            pred.column, query.table
        )));
    };

    if !column.indexed {
        return Err(SdkError::InvalidQuery(format!(
            "predicate column '{}' must be the primary key or an indexed column on table '{}'",
            pred.column, query.table
        )));
    }

    validate_predicate_values(
        pred,
        |value| query_param_matches_column_type(value, &column.column_type),
        || {
            format!(
                "predicate column '{}.{}' expects {:?} value(s)",
                query.table, pred.column, column.column_type
            )
        },
    )
}

fn validate_predicate_arity(pred: &Predicate) -> Result<()> {
    let ok = match pred.operator {
        ComparisonOperator::In => !pred.values.is_empty(),
        ComparisonOperator::Between => pred.values.len() >= 2,
        _ => !pred.values.is_empty(),
    };
    if ok {
        return Ok(());
    }

    let message = match pred.operator {
        ComparisonOperator::Equal => "Equal requires a value",
        ComparisonOperator::In => "In requires at least one value",
        ComparisonOperator::GreaterThan => "GreaterThan requires a value",
        ComparisonOperator::GreaterThanOrEqual => "GreaterThanOrEqual requires a value",
        ComparisonOperator::LessThan => "LessThan requires a value",
        ComparisonOperator::LessThanOrEqual => "LessThanOrEqual requires a value",
        ComparisonOperator::Between => "Between requires two values",
    };
    Err(SdkError::InvalidQuery(message.into()))
}

fn validate_predicate_values(
    pred: &Predicate,
    mut valid: impl FnMut(&QueryParam) -> bool,
    message: impl FnOnce() -> String,
) -> Result<()> {
    let values_to_check = match pred.operator {
        ComparisonOperator::In => pred.values.len(),
        ComparisonOperator::Between => 2,
        _ => 1,
    };

    if pred.values.iter().take(values_to_check).all(&mut valid) {
        Ok(())
    } else {
        Err(SdkError::InvalidQuery(message()))
    }
}

fn query_param_matches_column_type(param: &QueryParam, column_type: &ColumnType) -> bool {
    if matches!(param, QueryParam::Null) {
        return true;
    }

    match column_type {
        ColumnType::Integer => matches!(param, QueryParam::Integer(_)),
        ColumnType::Real => matches!(param, QueryParam::Real(_) | QueryParam::Integer(_)),
        ColumnType::String | ColumnType::FileRef | ColumnType::Text => {
            matches!(param, QueryParam::Text(_))
        }
        ColumnType::Blob => matches!(param, QueryParam::Blob(_)),
        ColumnType::List => matches!(param, QueryParam::Integer(_)),
    }
}

fn normalize_predicate_values_for_schema(schema: &Schema, column: &str, values: &mut [QueryParam]) {
    let Some(column_def) = schema.columns.iter().find(|c| c.name == column) else {
        return;
    };

    if !matches!(column_def.column_type, ColumnType::Real) {
        return;
    }

    for value in values {
        if let QueryParam::Integer(i) = value {
            *value = QueryParam::Real(*i as f64);
        }
    }
}

/// Enrich List/TextArea column values in a row JSON for hydration.
///
/// Transforms plain integer list_number values into enriched objects that
/// `List<T>::Deserialize` and `TextArea::Deserialize` can read to auto-hydrate
/// with address info.
fn hydrate_list_columns(row: &mut serde_json::Value, table_name: &str, list_columns: &[String]) {
    let Some(row_id) = row.get("id").and_then(|v| v.as_i64()) else {
        return;
    };

    if let serde_json::Value::Object(ref mut map) = row {
        for col_name in list_columns {
            if let Some(val) = map.get(col_name).cloned() {
                if let Some(list_number) = val.as_i64() {
                    map.insert(
                        col_name.clone(),
                        serde_json::json!({
                            "_li": list_number,
                            "_lt": table_name,
                            "_lr": row_id,
                            "_lc": col_name,
                        }),
                    );
                }
            }
        }
    }
}

/// Assemble a join: merge left rows with right rows by matching FK→PK values.
/// Columns are prefixed with their table name.
fn assemble_join(
    left_rows: &[serde_json::Value],
    right_rows: &[serde_json::Value],
    left_table: &str,
    right_prefix: &str,
    fk_col: &str,
    pk_col: &str,
) -> Vec<serde_json::Value> {
    // Index right rows by PK value for efficient lookup
    let mut right_by_pk: HashMap<String, Vec<&serde_json::Value>> = HashMap::new();
    for row in right_rows {
        if let Some(pk_val) = row.get(pk_col) {
            right_by_pk.entry(pk_val.to_string()).or_default().push(row);
        }
    }

    let mut assembled = Vec::new();
    for left_row in left_rows {
        if let Some(fk_val) = left_row.get(fk_col).filter(|v| !v.is_null()) {
            if let Some(matching) = right_by_pk.get(&fk_val.to_string()) {
                for right_row in matching {
                    let mut merged = serde_json::Map::new();
                    if let Some(obj) = left_row.as_object() {
                        for (key, val) in obj {
                            merged.insert(format!("{left_table}.{key}"), val.clone());
                        }
                    }
                    if let Some(obj) = right_row.as_object() {
                        for (key, val) in obj {
                            merged.insert(format!("{right_prefix}.{key}"), val.clone());
                        }
                    }
                    assembled.push(serde_json::Value::Object(merged));
                }
            }
        }
    }
    assembled
}

/// Check whether a single row matches a server-side predicate.
///
/// Used when rows are served from a full-table cache hit that doesn't
/// pre-filter by the predicate.
fn row_matches_predicate(row: &serde_json::Value, pred: &Predicate) -> bool {
    let cell = row.get(&pred.column).unwrap_or(&serde_json::Value::Null);

    match pred.operator {
        ComparisonOperator::Equal => pred.values.first().is_some_and(|v| json_eq_param(cell, v)),
        ComparisonOperator::In => pred.values.iter().any(|v| json_eq_param(cell, v)),
        ComparisonOperator::GreaterThan => pred
            .values
            .first()
            .is_some_and(|v| json_cmp_param(cell, v) == Some(std::cmp::Ordering::Greater)),
        ComparisonOperator::GreaterThanOrEqual => pred.values.first().is_some_and(|v| {
            json_cmp_param(cell, v).is_some_and(|o| o != std::cmp::Ordering::Less)
        }),
        ComparisonOperator::LessThan => pred
            .values
            .first()
            .is_some_and(|v| json_cmp_param(cell, v) == Some(std::cmp::Ordering::Less)),
        ComparisonOperator::LessThanOrEqual => pred.values.first().is_some_and(|v| {
            json_cmp_param(cell, v).is_some_and(|o| o != std::cmp::Ordering::Greater)
        }),
        ComparisonOperator::Between => {
            if let (Some(lo), Some(hi)) = (pred.values.first(), pred.values.get(1)) {
                let ge_lo = json_cmp_param(cell, lo).is_some_and(|o| o != std::cmp::Ordering::Less);
                let le_hi =
                    json_cmp_param(cell, hi).is_some_and(|o| o != std::cmp::Ordering::Greater);
                ge_lo && le_hi
            } else {
                false
            }
        }
    }
}

/// Test equality between a JSON value and a QueryParam.
fn json_eq_param(val: &serde_json::Value, param: &QueryParam) -> bool {
    match param {
        QueryParam::Null => val.is_null(),
        QueryParam::Integer(i) => val.as_i64() == Some(*i),
        QueryParam::Real(f) => val.as_f64() == Some(*f),
        QueryParam::Text(s) => val.as_str() == Some(s.as_str()),
        QueryParam::Boolean(b) => {
            val.as_bool() == Some(*b) || val.as_i64() == Some(if *b { 1 } else { 0 })
        }
        QueryParam::Blob(_) => false,
    }
}

/// Compare a JSON value against a QueryParam, returning an Ordering.
fn json_cmp_param(val: &serde_json::Value, param: &QueryParam) -> Option<std::cmp::Ordering> {
    match param {
        QueryParam::Integer(i) => val.as_i64().map(|v| v.cmp(i)),
        QueryParam::Real(f) => val.as_f64().and_then(|v| v.partial_cmp(f)),
        QueryParam::Text(s) => val.as_str().map(|v| v.cmp(s.as_str())),
        _ => None,
    }
}

/// Rows fetched for a query — main table rows plus optional joined rows.
struct FetchedRows {
    main: Vec<serde_json::Value>,
    joined: Option<Vec<serde_json::Value>>,
}

/// Specification for a join operation.
///
/// The server generates a single `TracerProof` covering both the main table
/// and targeted FK lookups on the joined table — no full table scans.
pub(crate) struct JoinSpec {
    /// Joined table name (may include alias: `"users"` or `"users as u"`).
    pub table: String,
    /// Column in the *main* table containing the foreign key.
    pub fk_col: String,
    /// Column in the *joined* table to match against (typically `"id"`).
    pub pk_col: String,
}

/// A client-side filter closure: (column_name, predicate).
type ClientFilter = (
    String,
    Box<dyn Fn(&serde_json::Value) -> bool + Send + Sync>,
);

pub struct SelectBuilder<T, W = Unpredicated> {
    pub(crate) query: Query,
    space: Arc<Space>,
    join: Option<JoinSpec>,
    client_filters: Vec<ClientFilter>,
    _phantom: PhantomData<(T, W)>,
}

impl<T> SelectBuilder<T, Unpredicated> {
    fn new(table_name: String, space: Arc<Space>) -> Self {
        Self {
            query: Query::new(table_name, QueryOperation::Select(Vec::new())),
            space,
            join: None,
            client_filters: Vec::new(),
            _phantom: PhantomData,
        }
    }
}

impl_where_methods!(SelectBuilder, |self| SelectBuilder {
    query: self.query,
    space: self.space,
    join: self.join,
    client_filters: self.client_filters,
    _phantom: PhantomData,
});

impl<T, W> SelectBuilder<T, W> {
    /// Add a client-side filter that runs after server-side predicates.
    ///
    /// This filter is evaluated in-process against the decrypted row value
    /// for `column`. It works on any column, including non-indexed ones.
    pub fn filter(
        mut self,
        column: &str,
        f: impl Fn(&serde_json::Value) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.client_filters.push((column.to_string(), Box::new(f)));
        self
    }

    pub fn columns(mut self, columns: &[&str]) -> Self {
        if let QueryOperation::Select(_) = &mut self.query.operation {
            self.query.operation =
                QueryOperation::Select(columns.iter().map(|s| s.to_string()).collect());
        }
        self
    }

    /// Join with another table using a foreign key relationship.
    ///
    /// The server generates a single proof covering both the main table and
    /// targeted FK lookups on the joined table. Only matching rows from the
    /// joined table are included — no full table scans.
    ///
    /// Only one join per query is supported.
    ///
    /// # Arguments
    /// * `table` — joined table name, optionally with alias (`"users"` or `"users as u"`)
    /// * `fk_col` — column in the main table containing the foreign key
    /// * `pk_col` — column in the joined table to match against (typically `"id"`)
    ///
    /// # Panics
    /// - If called more than once on the same query.
    ///
    /// # Examples
    /// ```ignore
    /// let results = posts.select()
    ///     .join("users", "user_id", "id")
    ///     .columns(&["posts.title", "users.name"])
    ///     .all_as::<PostWithUser>()
    ///     .await?;
    /// ```
    pub fn join(mut self, table: &str, fk_col: &str, pk_col: &str) -> Self {
        assert!(self.join.is_none(), "Only one join per query is supported");

        self.join = Some(JoinSpec {
            table: table.to_string(),
            fk_col: fk_col.to_string(),
            pk_col: pk_col.to_string(),
        });
        self.query.join = Some(JoinClause {
            table: table.to_string(),
            on_condition: (fk_col.to_string(), pk_col.to_string()),
        });
        self
    }

    /// Walk the predicate's range from the low end. With `.limit(n)`,
    /// returns the n smallest matches.
    pub fn ascending(mut self) -> Self {
        self.query.order = Order::Asc;
        self
    }

    /// Walk the predicate's range from the high end. With `.limit(n)`,
    /// returns the n largest matches.
    pub fn descending(mut self) -> Self {
        self.query.order = Order::Desc;
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.query.limit = Some(limit);
        self
    }

    /// Collect schemas for the main table and the joined table (if any).
    fn collect_schemas(&self) -> HashMap<String, Schema> {
        let mut schemas = HashMap::new();
        if let Some(s) = self.space.get_table_schema(&self.query.table) {
            schemas.insert(self.query.table.clone(), s);
        }
        if let Some(join) = &self.join {
            let (table_name, _) = parse_table_alias(&join.table);
            if let Some(s) = self.space.get_table_schema(table_name) {
                schemas.insert(table_name.to_string(), s);
            }
        }
        schemas
    }

    /// Try to serve the entire query (main + join) from cache.
    fn try_get_cached(&self) -> Option<FetchedRows> {
        let (predicates, id_lookups) = extract_cache_predicates(self.query.predicate.as_ref());
        let main = self.space.with_state_mut(|state| {
            state
                .cache
                .try_query(&self.query.table, &predicates, &id_lookups)
        })?;

        let joined = if let Some(join) = &self.join {
            let (table_name, _) = parse_table_alias(&join.table);
            let fk_col = strip_table_prefix(&join.fk_col);
            let pk_col = strip_table_prefix(&join.pk_col);

            // Extract FK values from main rows for the joined table lookup
            let mut fk_values = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            for row in &main {
                if let Some(val) = row.get(fk_col).and_then(|v| v.as_i64()) {
                    if seen.insert(val) {
                        fk_values.push(val);
                    }
                }
            }
            Some(self.space.with_state_mut(|state| {
                state.cache.try_query_joined(table_name, pk_col, &fk_values)
            })?)
        } else {
            None
        };

        Some(FetchedRows { main, joined })
    }

    /// Fetch from server (main table + optional join) and populate cache.
    async fn fetch_and_populate_cache(&self) -> Result<FetchedRows> {
        if self.join.is_some() {
            return self.fetch_and_populate_with_join().await;
        }

        let indexed_columns = self.get_indexed_columns(&self.query.table);

        // Check if we can do a targeted fetch for a single indexed predicate
        let (predicates, _) = extract_cache_predicates(self.query.predicate.as_ref());
        if predicates.len() == 1 {
            let (col, val) = &predicates[0];
            let rows = self.fetch_and_populate_for_predicate(col, *val).await?;
            return Ok(FetchedRows {
                main: rows,
                joined: None,
            });
        }

        // Full table fetch (no join)
        let cache_query = Query::new(self.query.table.clone(), QueryOperation::Select(Vec::new()));
        let commitment = self.space.current_data_commitment();
        let schemas = self.collect_schemas();
        let verified = self
            .space
            .transport
            .select(cache_query, &commitment, &schemas)
            .await?;

        let mut main_rows = verified.main_rows;
        decrypt_table_rows(&mut main_rows, &self.query.table, &schemas, &self.space).await?;
        let main_clone = main_rows.clone();
        self.space.with_state_mut(|state| {
            state
                .cache
                .populate_full(&self.query.table, main_rows, &indexed_columns);
        });

        Ok(FetchedRows {
            main: main_clone,
            joined: None,
        })
    }

    /// Fetch both main and joined tables from server in a single proven call.
    async fn fetch_and_populate_with_join(&self) -> Result<FetchedRows> {
        let join = self.join.as_ref().unwrap();
        let (table_name, _) = parse_table_alias(&join.table);
        let pk_col = strip_table_prefix(&join.pk_col);

        let commitment = self.space.current_data_commitment();
        let schemas = self.collect_schemas();
        let verified = self
            .space
            .transport
            .select(self.query.clone(), &commitment, &schemas)
            .await?;

        // Decrypt main rows and decide whether they imply a sound cache
        // claim. The user's JOIN query is sent verbatim to the server, so
        // `verified.main_rows` may be a partial slice of the table. We can
        // only mark a region of the cache "complete" when the proof
        // covers that whole region:
        //
        //   - No predicate, no limit, no cursor → proof covers the whole
        //     table; safe to populate_full.
        //   - Single Eq predicate on an indexed column, no limit, no
        //     cursor → proof covers the whole bucket; safe to
        //     populate_for_value.
        //   - Anything else (limit, cursor, range/id predicate, multi-Eq)
        //     → skip cache population. Otherwise a later
        //     `select().all()` could be served from a stale partial
        //     result without ever consulting a fresh proof.
        let mut main_rows = verified.main_rows;
        decrypt_table_rows(&mut main_rows, &self.query.table, &schemas, &self.space).await?;
        let main_clone = main_rows.clone();
        let main_indexed = self.get_indexed_columns(&self.query.table);
        let (predicates, _) = extract_cache_predicates(self.query.predicate.as_ref());
        let has_partial_predicate = self
            .query
            .predicate
            .as_ref()
            .is_some_and(|p| p.cursor_id.is_some() || predicates.len() != 1);
        let returns_partial_slice = self.query.limit.is_some() || has_partial_predicate;
        if !returns_partial_slice {
            if predicates.len() == 1 {
                let (col, val) = &predicates[0];
                self.space.with_state_mut(|state| {
                    state.cache.populate_for_value(
                        &self.query.table,
                        col,
                        *val,
                        main_rows,
                        &main_indexed,
                    );
                });
            } else {
                // No predicate, no limit, no cursor — full-table fetch.
                self.space.with_state_mut(|state| {
                    state
                        .cache
                        .populate_full(&self.query.table, main_rows, &main_indexed);
                });
            }
        } else {
            // Partial slice: insert rows into the cache by id without
            // claiming the bucket / table is complete. This still pays
            // off — subsequent `where_eq("id", N)` lookups (e.g. before
            // edit / delete) can be served locally. The next bucket /
            // full-table query still misses the cache and fetches a
            // fresh proof.
            self.space.with_state_mut(|state| {
                state
                    .cache
                    .populate_partial(&self.query.table, main_rows, &main_indexed, None);
            });
        }

        // Decrypt and cache joined table (partially — only FK-matched rows)
        let mut joined = verified
            .rows_by_table
            .get(table_name)
            .cloned()
            .unwrap_or_default();
        decrypt_table_rows(&mut joined, table_name, &schemas, &self.space).await?;
        let joined_clone = joined.clone();
        let join_indexed = self.get_indexed_columns(table_name);
        self.space.with_state_mut(|state| {
            state
                .cache
                .populate_partial(table_name, joined, &join_indexed, Some(pk_col));
        });

        Ok(FetchedRows {
            main: main_clone,
            joined: Some(joined_clone),
        })
    }

    /// Fetch a complete indexed `column=value` bucket and refresh that cache region.
    async fn fetch_and_populate_for_predicate(
        &self,
        column: &str,
        value: i64,
    ) -> Result<Vec<serde_json::Value>> {
        let mut pred_query =
            Query::new(self.query.table.clone(), QueryOperation::Select(Vec::new()));
        pred_query.predicate = Some(Predicate {
            column: column.to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(value)],
            cursor_id: None,
        });

        let commitment = self.space.current_data_commitment();
        let schemas = self.collect_schemas();
        let verified = self
            .space
            .transport
            .select(pred_query, &commitment, &schemas)
            .await?;

        let mut rows = verified.main_rows;
        decrypt_table_rows(&mut rows, &self.query.table, &schemas, &self.space).await?;

        let rows_clone = rows.clone();
        let indexed_columns = self.get_indexed_columns(&self.query.table);
        self.space.with_state_mut(|state| {
            state.cache.populate_for_value(
                &self.query.table,
                column,
                value,
                rows,
                &indexed_columns,
            );
        });

        Ok(rows_clone)
    }

    /// Get the list of plaintext integer columns that should be indexed for a table.
    fn get_indexed_columns(&self, table_name: &str) -> Vec<String> {
        self.space.with_state(|state| {
            state
                .table_schemas
                .get(table_name)
                .map(indexed_columns_for_schema)
                .unwrap_or_default()
        })
    }

    /// Get the names of columns with `ColumnType::List` for the current table.
    fn get_list_columns(&self) -> Vec<String> {
        self.space.with_state(|state| {
            state
                .table_schemas
                .get(&self.query.table)
                .map(|schema| {
                    schema
                        .columns
                        .iter()
                        .filter(|c| matches!(c.column_type, ColumnType::List))
                        .map(|c| c.name.clone())
                        .collect()
                })
                .unwrap_or_default()
        })
    }

    /// Fetch verified rows, decrypt, apply client filters and query
    /// post-processing (ORDER BY / LIMIT / OFFSET / column selection),
    /// then deserialize to `R`.
    async fn fetch_and_decrypt<R>(&self) -> Result<Vec<R>>
    where
        R: for<'de> Deserialize<'de>,
    {
        let mut schemas = self.collect_schemas();
        validate_original_select_predicate(&self.query, &schemas)?;
        validate_join(&self.query, &schemas)?;

        let fetched = match self.try_get_cached() {
            Some(cached) => cached,
            None => match self.fetch_and_populate_cache().await {
                Ok(rows) => rows,
                Err(SdkError::FastForwardRequired { .. }) => {
                    Box::pin(self.space.recover_via_fast_forward()).await?;
                    schemas = self.collect_schemas();
                    validate_original_select_predicate(&self.query, &schemas)?;
                    validate_join(&self.query, &schemas)?;
                    self.fetch_and_populate_cache().await?
                }
                Err(e) => return Err(e),
            },
        };

        // Apply server-side predicate client-side (needed when rows come
        // from a complete-table cache hit, which returns all rows).
        let predicate_filtered: Vec<serde_json::Value> = if let Some(pred) = &self.query.predicate {
            fetched
                .main
                .into_iter()
                .filter(|row| row_matches_predicate(row, pred))
                .collect()
        } else {
            fetched.main
        };

        // Apply ORDER BY / cursor / LIMIT before client filters so a
        // cache-hit (which returns the full table) sees the same row
        // slice the server would have returned.  Without this step,
        // `.filter(...).first()` on a fully-populated cache would let
        // the client filter scan every row before LIMIT applied, while
        // a cache miss has the server LIMIT first — producing different
        // results for the same query.  Idempotent on cache miss because
        // the server already applied this transform.
        let server_view = apply_server_view(predicate_filtered, &self.query);

        // Apply client-side filters on unprefixed main rows (before join).
        let filtered_main: Vec<serde_json::Value> = server_view
            .into_iter()
            .filter(|row| {
                for (col, predicate_fn) in &self.client_filters {
                    let val = row.get(col).unwrap_or(&serde_json::Value::Null);
                    if !predicate_fn(val) {
                        return false;
                    }
                }
                true
            })
            .collect();

        // If join: assemble with joined rows (prefixes columns)
        let rows = if let Some(join) = &self.join {
            let (table_name, alias) = parse_table_alias(&join.table);
            let prefix = alias.unwrap_or(table_name);
            let fk_col = strip_table_prefix(&join.fk_col);
            let pk_col = strip_table_prefix(&join.pk_col);
            let right_rows = fetched.joined.unwrap_or_default();
            assemble_join(
                &filtered_main,
                &right_rows,
                &self.query.table,
                prefix,
                fk_col,
                pk_col,
            )
        } else {
            filtered_main
        };

        // Apply ORDER BY, LIMIT/OFFSET, column selection
        let final_rows = process_query_results(rows, &self.query)?;

        // Hydrate List/TextArea columns: enrich JSON values with address info
        // so that List<T>/TextArea::Deserialize can create fully operational instances.
        let list_columns = self.get_list_columns();
        let table_name = self.query.table.clone();

        let hydrated_rows: Vec<serde_json::Value> = if list_columns.is_empty() {
            final_rows
        } else {
            final_rows
                .into_iter()
                .map(|mut row| {
                    hydrate_list_columns(&mut row, &table_name, &list_columns);
                    row
                })
                .collect()
        };

        crate::list::with_list_space_ctx(Arc::new((*self.space).clone()), || {
            hydrated_rows
                .into_iter()
                .map(|row| {
                    serde_json::from_value(row.clone()).map_err(|e| {
                        SdkError::SerializationError(format!(
                            "Failed to deserialize row into {}: {e}\n  Row JSON: {row}",
                            std::any::type_name::<R>()
                        ))
                    })
                })
                .collect()
        })
    }

    /// Smallest matching row (low end of the predicate's range). Forces
    /// `.ascending().limit(1)`, overriding any prior calls.
    pub async fn first(mut self) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.query.order = Order::Asc;
        self.query.limit = Some(1);
        Ok(self.fetch_and_decrypt::<T>().await?.into_iter().next())
    }

    /// Largest matching row (high end of the predicate's range). Forces
    /// `.descending().limit(1)`, overriding any prior calls.
    pub async fn last(mut self) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.query.order = Order::Desc;
        self.query.limit = Some(1);
        Ok(self.fetch_and_decrypt::<T>().await?.into_iter().next())
    }

    pub async fn all(self) -> Result<Vec<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.fetch_and_decrypt().await
    }

    pub async fn all_as<U>(self) -> Result<Vec<U>>
    where
        U: for<'de> Deserialize<'de>,
    {
        self.fetch_and_decrypt().await
    }
}

pub struct UpdateBuilder<T, W = Unpredicated> {
    query: Query,
    space: Arc<Space>,
    _phantom: PhantomData<(T, W)>,
}

impl<T> UpdateBuilder<T, Unpredicated> {
    fn new(table_name: String, space: Arc<Space>) -> Self {
        Self {
            query: Query::new(table_name, QueryOperation::Update(Vec::new())),
            space,
            _phantom: PhantomData,
        }
    }
}

impl_where_methods!(UpdateBuilder, |self| UpdateBuilder {
    query: self.query,
    space: self.space,
    _phantom: PhantomData,
});

impl<T, W> UpdateBuilder<T, W> {
    pub fn set<V>(mut self, column: &str, value: V) -> Self
    where
        V: Into<QueryParam>,
    {
        if let QueryOperation::Update(ref mut fields) = &mut self.query.operation {
            fields.push((column.to_string(), value.into()));
        }
        self
    }

    pub async fn execute(self) -> Result<usize> {
        self.execute_as(None).await
    }

    /// Execute an update with a changelog entry, optionally overriding the
    /// `OpType` (e.g. `RefreshKeys`, `ListUpdate`).
    pub(crate) async fn execute_as(mut self, op_type: Option<OpType>) -> Result<usize> {
        // Build the signed change exactly once: `encrypt_query_fields`
        // mutates the query in place and isn't idempotent. Stale-parent
        // retries re-anchor and re-sign this same change
        // (see `Space::submit_change_with_ff_retry`).
        encrypt_query_fields(&mut self.query, &self.space).await?;
        let change = {
            let mut builder = ChangeBuilder::new(&mut self.query, self.space.clone());
            if let Some(op) = op_type {
                builder = builder.with_op_type(op);
            }
            match builder.build().await? {
                Some(c) => c,
                None => return Ok(0),
            }
        };
        let completed = self.space.submit_and_complete(change).await?;

        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(&self.space, &completed.change, writes)
                .await;
        }
        Ok(completed.response.rows_affected as usize)
    }
}

pub struct DeleteBuilder<T, W = Unpredicated> {
    pub(crate) query: Query,
    space: Arc<Space>,
    _phantom: PhantomData<(T, W)>,
}

impl<T> DeleteBuilder<T, Unpredicated> {
    fn new(table_name: String, space: Arc<Space>) -> Self {
        Self {
            query: Query::new(table_name, QueryOperation::Delete),
            space,
            _phantom: PhantomData,
        }
    }
}

impl_where_methods!(DeleteBuilder, |self| DeleteBuilder {
    query: self.query,
    space: self.space,
    _phantom: PhantomData,
});

impl<T, W> DeleteBuilder<T, W> {
    /// Build the changelog entry for this delete, optionally overriding the
    /// `OpType`. Used by callers that need the entry and the matching
    /// hash-only-value sidecar separately (e.g. remove_member, list ops).
    pub(crate) async fn prepare_change_as(
        &mut self,
        op_type: Option<OpType>,
    ) -> Result<Option<Change>> {
        encrypt_query_fields(&mut self.query, &self.space).await?;
        let mut builder = ChangeBuilder::new(&mut self.query, self.space.clone());
        if let Some(op) = op_type {
            builder = builder.with_op_type(op);
        }
        builder.build().await
    }

    pub async fn execute(self) -> Result<usize> {
        self.execute_as(None).await
    }

    pub(crate) async fn execute_as(mut self, op_type: Option<OpType>) -> Result<usize> {
        // For Delete operations encrypt_query_fields is a no-op (see
        // sdk/src/crypto.rs), but routing through prepare_change_as keeps
        // the call shape uniform. The change is built once; stale-parent
        // retries re-anchor and re-sign it (see
        // `Space::submit_change_with_ff_retry`).
        let change = match self.prepare_change_as(op_type).await? {
            Some(c) => c,
            None => return Ok(0),
        };
        let completed = self.space.submit_and_complete(change).await?;

        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(&self.space, &completed.change, writes)
                .await;
        }
        Ok(completed.response.rows_affected as usize)
    }
}

pub struct InsertBuilder<T> {
    pub(crate) query: Query,
    space: Arc<Space>,
    /// Serialization error captured during [`InsertBuilder::new`]. Surfaced
    /// from `prepare_change_as` / `execute*` so the builder constructor can
    /// stay infallible and the user only deals with one `?` per insert.
    pending_error: Option<SdkError>,
    _phantom: PhantomData<T>,
}

impl<T> InsertBuilder<T> {
    /// Construct an `InsertBuilder` directly from a list of `(column, value)`
    /// pairs, bypassing the `Serialize`-based field extraction. Useful for
    /// internal call sites that work with `QueryParam` (e.g. blob payloads
    /// that don't round-trip through JSON cleanly).
    pub(crate) fn from_fields(
        table_name: String,
        space: Arc<Space>,
        fields: Vec<(String, QueryParam)>,
    ) -> Self {
        Self {
            query: Query::new(table_name, QueryOperation::Insert(fields)),
            space,
            pending_error: None,
            _phantom: PhantomData,
        }
    }

    pub(crate) fn new(table_name: String, space: Arc<Space>, data: &T) -> Self
    where
        T: Serialize,
    {
        match serde_json::to_value(data) {
            Ok(serde_json::Value::Object(obj)) => {
                let fields: Vec<(String, QueryParam)> = obj
                    .into_iter()
                    .map(|(k, v)| (k, QueryParam::from(v)))
                    .collect();
                Self {
                    query: Query::new(table_name, QueryOperation::Insert(fields)),
                    space,
                    pending_error: None,
                    _phantom: PhantomData,
                }
            }
            Ok(_) => Self {
                query: Query::new(table_name, QueryOperation::Insert(Vec::new())),
                space,
                pending_error: Some(SdkError::SerializationError(
                    "insert payload must serialize to a JSON object".to_string(),
                )),
                _phantom: PhantomData,
            },
            Err(e) => Self {
                query: Query::new(table_name, QueryOperation::Insert(Vec::new())),
                space,
                pending_error: Some(SdkError::SerializationError(format!(
                    "JSON serialization error: {e}"
                ))),
                _phantom: PhantomData,
            },
        }
    }

    /// Take any captured serialization error, leaving `None` behind.
    ///
    /// Internal callers that read or mutate [`InsertBuilder::query`]
    /// directly (rather than going through `execute*`) must call this
    /// first, otherwise a silent failure during `serde_json::to_value`
    /// would let them build an empty-field change.
    pub(crate) fn take_pending_error(&mut self) -> Result<()> {
        match self.pending_error.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Build the signed `Change` for this insert, optionally overriding
    /// the `OpType`. Used by callers that need the change separate from
    /// transport submission (e.g. add_member, list ops). `execute_as`
    /// submits via `Space::submit_change_with_ff_retry`; this helper produces
    /// a one-shot build for callers that drive submission themselves.
    #[allow(dead_code)]
    pub(crate) async fn prepare_change_as(&mut self, op_type: Option<OpType>) -> Result<Change> {
        self.take_pending_error()?;
        encrypt_query_fields(&mut self.query, &self.space).await?;
        let mut builder = ChangeBuilder::new(&mut self.query, self.space.clone());
        if let Some(op) = op_type {
            builder = builder.with_op_type(op);
        }
        builder
            .build()
            .await?
            .ok_or_else(|| SdkError::DatabaseError("No rows matched for insert".to_string()))
    }

    pub async fn execute(self) -> Result<i64> {
        self.execute_as(None).await
    }

    pub(crate) async fn execute_as(mut self, op_type: Option<OpType>) -> Result<i64> {
        // Surface any serialization error captured by `InsertBuilder::new`
        // before touching the backend; otherwise the downstream "table
        // not registered" / encryption paths would mask the real
        // failure (see `insert_serialization_failure_propagates_to_execute`).
        self.take_pending_error()?;
        // Build the signed change exactly once: `encrypt_query_fields`
        // mutates the query in place and is not idempotent. Stale-parent
        // retries re-anchor and re-sign this same change
        // (see `Space::submit_change_with_ff_retry`).
        encrypt_query_fields(&mut self.query, &self.space).await?;
        let change = {
            let mut builder = ChangeBuilder::new(&mut self.query, self.space.clone());
            if let Some(op) = op_type {
                builder = builder.with_op_type(op);
            }
            builder
                .build()
                .await?
                .ok_or_else(|| SdkError::DatabaseError("No rows matched for insert".to_string()))?
        };
        let completed = self.space.submit_and_complete(change).await?;

        // Sequential append: derive the new row id from the verified
        // sequential writes (and warm the cache).
        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(&self.space, &completed.change, writes)
                .await;
            return crate::cache::new_row_id_for_table(&self.space, writes, &self.query.table)
                .ok_or_else(|| {
                    SdkError::InsertError(format!(
                        "Insert proof for {:?} did not write any new row to {}",
                        completed.change.entry.message.op_type, self.query.table
                    ))
                });
        }

        // Ragged fast-forward: the row id was captured from the FF-verified
        // ragged change keyed by the submitted entry's signature.
        if let Some(row_id) = completed
            .ff_inserted_ids
            .get(&completed.change.entry.signature)
            .copied()
        {
            return Ok(row_id);
        }

        // Proof-covered fast-forward: `submit_and_complete` already proved the
        // exact entry is incorporated via an inclusion proof, but its writes
        // are inside the FF proof boundary (not the ragged tail). Re-verify the
        // acknowledged response in isolation *only* to extract the row id — the
        // issue-#212 discharge guarantee (the exact entry is on the verified CLC
        // chain) already came from the inclusion proof, so the success/failure
        // decision is NOT taken here; `validate_and_apply_change` takes its
        // already-applied, verify-without-mutate branch.
        //
        // Known limitation: in this rare branch the auto-id row id comes from an
        // unanchored response witness (never a false success; the entry is
        // proven incorporated). Tracked in
        // https://github.com/encrypted-spaces/prototype/issues/232.
        let writes = self
            .space
            .validate_and_apply_change(&completed.change.entry, &completed.response)?;
        crate::cache::update_cache_from_proven_writes(&self.space, &completed.change, &writes)
            .await;
        crate::cache::new_row_id_for_table(&self.space, &writes, &self.query.table).ok_or_else(
            || {
                SdkError::InsertError(format!(
                    "Insert proof for {:?} did not write any new row to {}",
                    completed.change.entry.message.op_type, self.query.table
                ))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use encrypted_spaces_backend::{
        error::SdkError,
        merk_storage::{
            parse_key,
            proofs::{
                extract_query_proof_entries_for_response_material,
                verify_query_proof_with_hashed_values,
            },
            ParsedKey,
        },
        query::{Query, QueryOperation},
        schema::Schema,
    };
    use encrypted_spaces_backend_server::SpaceState;
    use encrypted_spaces_storage_encoding::HASH_LEN;
    use serde::{Deserialize, Serialize};

    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
    use crate::users::USERS_TABLE_NAME;
    use crate::Space;

    #[derive(Deserialize, Serialize)]
    struct HashBackedSelectNote {
        id: Option<i64>,
        content: String,
        title: String,
    }

    async fn hash_backed_select_space(
    ) -> std::result::Result<(LocalTransport, Space, Schema), Box<dyn std::error::Error>> {
        let schema = SchemaBuilder::new("hash_select_notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", ColumnType::Text)?
            .column("title", ColumnType::String)?
            .plaintext()
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing(vec![schema.clone()], root),
        )
        .await?;
        Ok((transport, space, schema))
    }

    #[tokio::test]
    async fn hash_backed_select_returns_full_values_and_caches_them(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_transport, space, _schema) = hash_backed_select_space().await?;
        let notes = space.table::<HashBackedSelectNote>("hash_select_notes");

        let row_id = notes
            .insert(&HashBackedSelectNote {
                id: None,
                content: "large hash-backed body".to_string(),
                title: "inline title".to_string(),
            })
            .execute()
            .await?;

        let rows: Vec<HashBackedSelectNote> = notes.select().all().await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].content, "large hash-backed body");
        assert_eq!(rows[0].title, "inline title");

        let cached =
            space.with_state(|state| state.cache.get_row("hash_select_notes", row_id).cloned());
        let cached = cached.expect("select should populate cache");
        assert_eq!(cached["content"], "large hash-backed body");
        assert_eq!(cached["title"], "inline title");

        Ok(())
    }

    #[tokio::test]
    async fn hash_backed_select_client_rejects_missing_and_tampered_material(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (transport, space, schema) = hash_backed_select_space().await?;
        let notes = space.table::<HashBackedSelectNote>("hash_select_notes");
        notes
            .insert(&HashBackedSelectNote {
                id: None,
                content: "material integrity body".to_string(),
                title: "title".to_string(),
            })
            .execute()
            .await?;

        let query = Query::new(
            "hash_select_notes".to_string(),
            QueryOperation::Select(Vec::new()),
        );
        let commitment = space.current_data_commitment();
        let proof = transport.select_proof_bytes(&query).await?;
        let entries =
            extract_query_proof_entries_for_response_material(&query, &proof, &commitment)?;
        let content_hash: [u8; HASH_LEN] = entries
            .iter()
            .find_map(|(key, value)| match parse_key(key) {
                Ok(ParsedKey::Column { column, .. }) if column == "content" => {
                    value.as_slice().try_into().ok()
                }
                _ => None,
            })
            .expect("content hash should be proven");
        let full_value = transport
            .hash_store_get(&content_hash)
            .await
            .expect("server HashStore should contain content");
        use encrypted_spaces_changelog_core::changelog::HashedValues;
        use encrypted_spaces_storage_encoding::hashstore_hash;
        // Build sidecars keyed by `hashstore_hash` exactly as the wire decode does.
        let material: HashedValues = [(hashstore_hash(&full_value), full_value.clone())]
            .into_iter()
            .collect();
        let schemas = std::collections::HashMap::from([("hash_select_notes".to_string(), schema)]);

        let missing = verify_query_proof_with_hashed_values(
            &query,
            &proof,
            &commitment,
            &schemas,
            &HashedValues::new(),
        );
        assert!(matches!(missing, Err(SdkError::ValidationError(_))));

        // Tampered bytes hash to a different key, so they never land under the
        // committed hash the proof references.
        let mut tampered_value = full_value.clone();
        tampered_value.push(0);
        let tampered: HashedValues = [(hashstore_hash(&tampered_value), tampered_value)]
            .into_iter()
            .collect();
        let tampered_result =
            verify_query_proof_with_hashed_values(&query, &proof, &commitment, &schemas, &tampered);
        assert!(matches!(tampered_result, Err(SdkError::ValidationError(_))));

        let verified = verify_query_proof_with_hashed_values(
            &query,
            &proof,
            &commitment,
            &schemas,
            &material,
        )?;
        assert_eq!(verified.main_rows.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_select_validates_original_predicate_before_server_fetch(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        let schema = SchemaBuilder::new("predicate_validation_items")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;
        space.create_table(&schema).await?;

        let table = space.table::<serde_json::Value>("predicate_validation_items");
        let result = table
            .select()
            .where_between("id", "not-an-integer-low", "not-an-integer-high")
            .all()
            .await;

        assert!(
            matches!(result, Err(SdkError::InvalidQuery(_))),
            "wrong-typed id range must be rejected before cache miss broadening"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_real_index_predicate_integer_bound_is_normalized(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        let schema = SchemaBuilder::new("real_index_items")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("score", ColumnType::Real)?
            .plaintext()
            .index()
            .column("label", ColumnType::String)?
            .plaintext()
            .build()?;
        space.create_table(&schema).await?;

        #[derive(Deserialize, Serialize)]
        struct Item {
            id: Option<i64>,
            score: f64,
            label: String,
        }

        let table = space.table::<Item>("real_index_items");
        table
            .insert(&Item {
                id: None,
                score: 2.5,
                label: "target".to_string(),
            })
            .execute()
            .await?;

        let affected = table
            .update()
            .set("score", 0)
            .where_eq("id", 1)
            .execute()
            .await?;
        assert_eq!(affected, 1);

        let rows: Vec<Item> = table.select().where_eq("score", 0).all().await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "target");
        assert_eq!(rows[0].score, 0.0);
        Ok(())
    }

    #[tokio::test]
    async fn test_join_query() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        // Space::create already inserts user 1 (the owner) with status=Full.
        let user_id: i64 = 1;

        // Create posts table
        let post_schema = SchemaBuilder::new("posts")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("user_id", ColumnType::Integer)?
            .plaintext()
            .column("title", ColumnType::String)?
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Post {
            id: Option<i64>,
            user_id: i64,
            title: String,
        }

        let post = Post {
            id: None,
            user_id,
            title: "Hello World".to_string(),
        };

        let posts_table = space.table::<Post>("posts");
        space.create_table(&post_schema).await?;

        posts_table.insert(&post).execute().await?;

        #[derive(Deserialize)]
        struct JoinedData {
            id: i64,
            user_id: i64,
            title: String,
            status: i64,
        }

        // Test join query — join posts with _users on user_id to get user status
        let joined_data: Vec<JoinedData> = posts_table
            .select()
            .columns(&["posts.id", "posts.user_id", "posts.title", "_users.status"])
            .join(USERS_TABLE_NAME, "user_id", "id")
            .all_as()
            .await?;

        assert_eq!(joined_data.len(), 1);

        let first_result = &joined_data[0];
        assert_eq!(first_result.id, 1);
        assert_eq!(first_result.user_id, 1);
        assert_eq!(first_result.title, "Hello World");
        assert_eq!(first_result.status, 1); // Full

        Ok(())
    }

    #[tokio::test]
    async fn test_join_multiple_rows() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        space.authenticate_as_id(1).await?;
        let alice = space.invite_user().await?.user;
        let bob = space.invite_user().await?.user;

        let post_schema = SchemaBuilder::new("posts")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("user_id", ColumnType::Integer)?
            .plaintext()
            .column("title", ColumnType::String)?
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Post {
            id: Option<i64>,
            user_id: i64,
            title: String,
        }

        let posts_table = space.table::<Post>("posts");
        space.create_table(&post_schema).await?;

        // Insert posts by different users
        posts_table
            .insert(&Post {
                id: None,
                user_id: alice.id.unwrap(),
                title: "Alice post 1".into(),
            })
            .execute()
            .await?;
        posts_table
            .insert(&Post {
                id: None,
                user_id: bob.id.unwrap(),
                title: "Bob post 1".into(),
            })
            .execute()
            .await?;
        posts_table
            .insert(&Post {
                id: None,
                user_id: alice.id.unwrap(),
                title: "Alice post 2".into(),
            })
            .execute()
            .await?;

        #[derive(Deserialize)]
        struct JoinedData {
            title: String,
            user_id: i64,
            status: i64,
        }

        // Join should match each post with its author
        let joined: Vec<JoinedData> = posts_table
            .select()
            .columns(&["posts.title", "posts.user_id", "_users.status"])
            .join(USERS_TABLE_NAME, "user_id", "id")
            .all_as()
            .await?;

        assert_eq!(joined.len(), 3);
        let alice_posts: Vec<_> = joined
            .iter()
            .filter(|j| j.user_id == alice.id.unwrap())
            .collect();
        let bob_posts: Vec<_> = joined
            .iter()
            .filter(|j| j.user_id == bob.id.unwrap())
            .collect();
        assert_eq!(alice_posts.len(), 2);
        assert_eq!(bob_posts.len(), 1);
        assert_eq!(bob_posts[0].title, "Bob post 1");
        assert_eq!(bob_posts[0].status, 0); // Provisional (invited but not joined)

        Ok(())
    }

    #[tokio::test]
    async fn test_join_with_where_and_order() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        space.authenticate_as_id(1).await?;
        let alice = space.invite_user().await?.user;
        let bob = space.invite_user().await?.user;

        let msg_schema = SchemaBuilder::new("messages")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("user_id", ColumnType::Integer)?
            .plaintext()
            .column("channel_id", ColumnType::Integer)?
            .plaintext()
            .index()
            .column("content", ColumnType::String)?
            .column("ts", ColumnType::Integer)?
            .plaintext()
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Msg {
            id: Option<i64>,
            user_id: i64,
            channel_id: i64,
            content: String,
            ts: i64,
        }

        let msgs = space.table::<Msg>("messages");
        space.create_table(&msg_schema).await?;

        // Insert messages in two channels
        for (uid, ch, content, ts) in [
            (alice.id.unwrap(), 1, "hello", 100),
            (bob.id.unwrap(), 1, "hi", 200),
            (alice.id.unwrap(), 2, "other channel", 150),
            (alice.id.unwrap(), 1, "how are you", 300),
        ] {
            msgs.insert(&Msg {
                id: None,
                user_id: uid,
                channel_id: ch,
                content: content.into(),
                ts,
            })
            .execute()
            .await?;
        }

        #[derive(Deserialize)]
        struct MsgWithUser {
            content: String,
            user_id: i64,
        }

        // Join with WHERE on channel_id, ascending — implicit sort is by
        // channel_id (the predicate column); within equal channel_id, rows
        // come back in row-id order.
        let result: Vec<MsgWithUser> = msgs
            .select()
            .columns(&["messages.content", "messages.user_id"])
            .join(USERS_TABLE_NAME, "user_id", "id")
            .where_eq("channel_id", 1)
            .ascending()
            .all_as()
            .await?;

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].content, "hello");
        assert_eq!(result[0].user_id, alice.id.unwrap());
        assert_eq!(result[1].content, "hi");
        assert_eq!(result[1].user_id, bob.id.unwrap());
        assert_eq!(result[2].content, "how are you");
        assert_eq!(result[2].user_id, alice.id.unwrap());

        Ok(())
    }

    #[tokio::test]
    async fn test_join_with_alias() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        space.authenticate_as_id(1).await?;
        space.invite_user().await?;

        let post_schema = SchemaBuilder::new("posts")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("user_id", ColumnType::Integer)?
            .plaintext()
            .column("title", ColumnType::String)?
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Post {
            id: Option<i64>,
            user_id: i64,
            title: String,
        }

        let posts = space.table::<Post>("posts");
        space.create_table(&post_schema).await?;
        posts
            .insert(&Post {
                id: None,
                user_id: 1,
                title: "Test".into(),
            })
            .execute()
            .await?;

        #[derive(Deserialize)]
        struct PostWithAuthor {
            title: String,
            user_status: i64,
        }

        // Use table alias and column alias
        let result: Vec<PostWithAuthor> = posts
            .select()
            .columns(&["posts.title", "u.status AS user_status"])
            .join(&format!("{USERS_TABLE_NAME} as u"), "user_id", "id")
            .all_as()
            .await?;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "Test");
        assert_eq!(result[0].user_status, 1); // Full

        Ok(())
    }

    #[tokio::test]
    async fn test_unaliased_self_join_rejected_as_invalid_query(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        let result = space
            .table::<serde_json::Value>("nodes")
            .select()
            .join("nodes", "parent_id", "id")
            .all()
            .await;

        assert!(
            matches!(result, Err(SdkError::InvalidQuery(_))),
            "unaliased self-join should be rejected as InvalidQuery, got {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_aliased_self_join_projects_distinct_sides(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        let node_schema = SchemaBuilder::new("nodes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("parent_id", ColumnType::Integer)?
            .plaintext()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Node {
            id: Option<i64>,
            parent_id: i64,
            name: String,
        }

        #[derive(Debug, Deserialize, PartialEq)]
        struct NodeWithParent {
            child_id: i64,
            parent_id: i64,
            child_name: String,
            parent_name: String,
        }

        let nodes = space.table::<Node>("nodes");
        space.create_table(&node_schema).await?;
        let root_id = nodes
            .insert(&Node {
                id: None,
                parent_id: 0,
                name: "root".into(),
            })
            .execute()
            .await?;
        let child_id = nodes
            .insert(&Node {
                id: None,
                parent_id: root_id,
                name: "child".into(),
            })
            .execute()
            .await?;

        let first: Vec<NodeWithParent> = nodes
            .select()
            .columns(&[
                "nodes.id AS child_id",
                "parent.id AS parent_id",
                "nodes.name AS child_name",
                "parent.name AS parent_name",
            ])
            .join("nodes as parent", "parent_id", "id")
            .all_as()
            .await?;

        assert_eq!(
            first,
            vec![NodeWithParent {
                child_id,
                parent_id: root_id,
                child_name: "child".into(),
                parent_name: "root".into(),
            }]
        );
        assert!(space.with_state(|s| s.cache.is_table_complete("nodes")));

        let second: Vec<NodeWithParent> = nodes
            .select()
            .columns(&[
                "nodes.id AS child_id",
                "parent.id AS parent_id",
                "nodes.name AS child_name",
                "parent.name AS parent_name",
            ])
            .join("nodes as parent", "parent_id", "id")
            .all_as()
            .await?;
        assert_eq!(second, first);

        Ok(())
    }

    #[tokio::test]
    async fn stale_insert_returns_row_id_when_fast_forward_proof_covers_insert(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        #[derive(Deserialize, Serialize, Debug)]
        struct Item {
            id: Option<i64>,
            label: String,
        }

        let schema = SchemaBuilder::new("ff_insert_id_items")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("label", ColumnType::String)?
            .plaintext()
            .build()?;
        let transport = LocalTransport::new(std::slice::from_ref(&schema), None, Some(1)).await?;
        let root = transport.get_root_hash().await?;
        let space = Space::create(
            transport,
            ApplicationSchema::for_testing(vec![schema], root),
        )
        .await?;

        let table = space.table::<Item>("ff_insert_id_items");
        let stale_state = space.with_state(|state| {
            (
                state.current_change_id,
                state.current_data_commitment,
                state.current_clc_state.clone(),
                state.current_change_entry.clone(),
                state.sigref_map.clone(),
            )
        });

        let first_id = table
            .insert(&Item {
                id: None,
                label: "remote".to_string(),
            })
            .execute()
            .await?;
        assert_eq!(first_id, 1);

        let (change_id, dc, clc, entry, sigref_map) = stale_state;
        space.with_state_mut(|state| {
            state.current_change_id = change_id;
            state.current_data_commitment = dc;
            state.current_clc_state = clc;
            state.current_change_entry = entry;
            // Roll back local view of applied changes alongside
            // current_change_id — but leave `my_last_change_id` alone:
            // it tracks server-acknowledged submissions, and the first
            // insert really committed server-side at change_id=2.
            state.sigref_map = sigref_map;
            state.cache.clear_all();
        });

        let second_id = table
            .insert(&Item {
                id: None,
                label: "submitted-while-stale".to_string(),
            })
            .execute()
            .await?;
        assert_eq!(second_id, 2);

        let third_id = table
            .insert(&Item {
                id: None,
                label: "after-ff-proof".to_string(),
            })
            .execute()
            .await?;
        assert_eq!(third_id, 3);

        let mut rows: Vec<Item> = table.select().all().await?;
        rows.sort_by_key(|row| row.id.unwrap_or_default());
        let labels: Vec<String> = rows.into_iter().map(|row| row.label).collect();
        assert_eq!(
            labels,
            vec![
                "remote".to_string(),
                "submitted-while-stale".to_string(),
                "after-ff-proof".to_string()
            ]
        );

        Ok(())
    }

    /// Regression test for the MEDIUM finding in the gz/sigref-02 code
    /// review: when the server rejects a change because the client's
    /// `parent_change` is older than `MAX_PARENT_DISTANCE` (so the FF
    /// guest would also reject), the SDK must recover via fast-forward
    /// and re-submit transparently rather than surfacing a hard error.
    ///
    /// We simulate "client missed many concurrent broadcasts" by
    /// snapshotting state, advancing the server with `> MAX_PARENT_DISTANCE`
    /// changes, then restoring the snapshot. A naive submit at this point
    /// would be rejected by `validate_parent_change` on the server; the
    /// recovery loop in `execute_as` must kick in and succeed.
    #[tokio::test]
    async fn stale_parent_beyond_window_auto_recovers_on_insert(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        #[derive(Deserialize, Serialize, Debug)]
        struct Item {
            id: Option<i64>,
            label: String,
        }

        let schema = SchemaBuilder::new("stale_window_items")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("label", ColumnType::Text)?
            .plaintext()
            .build()?;
        let transport = LocalTransport::new(std::slice::from_ref(&schema), None, Some(1)).await?;
        let root = transport.get_root_hash().await?;
        let space = Space::create(
            transport,
            ApplicationSchema::for_testing(vec![schema], root),
        )
        .await?;

        let table = space.table::<Item>("stale_window_items");

        // Seed an initial change so the snapshot has a non-trivial anchor.
        let seed_id = table
            .insert(&Item {
                id: None,
                label: "seed".to_string(),
            })
            .execute()
            .await?;
        assert_eq!(seed_id, 1);

        let stale_state = space.with_state(|state| {
            (
                state.current_change_id,
                state.current_data_commitment,
                state.current_clc_state.clone(),
                state.current_change_entry.clone(),
                state.sigref_map.clone(),
            )
        });

        // Advance the server's chain by more than MAX_PARENT_DISTANCE so
        // the snapshot above is unambiguously outside the window.
        use encrypted_spaces_changelog_core::changelog::MAX_PARENT_DISTANCE;
        let advances = (MAX_PARENT_DISTANCE as usize) + 2;
        for i in 0..advances {
            table
                .insert(&Item {
                    id: None,
                    label: format!("advance-{i}"),
                })
                .execute()
                .await?;
        }

        // Snap the client back to its pre-advance view. The server is
        // now `advances` changes ahead; any change built from this state
        // will carry a parent_change that is `advances` behind the
        // server's prospective_change_id, well outside the window.
        let (change_id, dc, clc, entry, sigref_map) = stale_state;
        space.with_state_mut(|state| {
            state.current_change_id = change_id;
            state.current_data_commitment = dc;
            state.current_clc_state = clc;
            state.current_change_entry = entry;
            state.sigref_map = sigref_map;
            state.cache.clear_all();
        });

        // Without auto-recovery, this insert would fail with
        // `SdkError::FastForwardRequired { reason: "parent_change ... is invalid ..." }`
        // because the server's `validate_parent_change` would reject the
        // submission. Instead, `submit_change_with_ff_retry` catches that
        // error, runs `recover_via_fast_forward`, re-anchors and re-signs
        // the entry against the new anchor, and re-submits.
        let recovered_id = table
            .insert(&Item {
                id: None,
                label: "after-stale-window-recovery".to_string(),
            })
            .execute()
            .await?;
        assert!(
            recovered_id >= 1,
            "auto-recovered insert returned implausible row id {recovered_id}"
        );

        // The recovered insert plus the seed plus the advance inserts
        // should all be readable via the recovered client view.
        let rows: Vec<Item> = table.select().all().await?;
        assert_eq!(
            rows.len(),
            1 + advances + 1,
            "expected seed + {advances} advances + 1 recovered insert, got {} rows",
            rows.len()
        );
        assert!(
            rows.iter()
                .any(|r| r.label == "after-stale-window-recovery"),
            "recovered insert missing from final read; rows={:?}",
            rows.iter().map(|r| &r.label).collect::<Vec<_>>()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_join_no_matches() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let post_schema = SchemaBuilder::new("posts")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("user_id", ColumnType::Integer)?
            .plaintext()
            .column("title", ColumnType::String)?
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Post {
            id: Option<i64>,
            user_id: i64,
            title: String,
        }

        let posts = space.table::<Post>("posts");
        space.create_table(&post_schema).await?;

        // Insert a post with user_id=999 which doesn't exist in users table
        posts
            .insert(&Post {
                id: None,
                user_id: 999,
                title: "Orphan".into(),
            })
            .execute()
            .await?;

        #[derive(Deserialize)]
        struct JoinedData {
            #[allow(dead_code)]
            title: String,
            #[allow(dead_code)]
            name: String,
        }

        // Inner join should return no results since user_id=999 doesn't exist
        let result: Vec<JoinedData> = posts
            .select()
            .columns(&["posts.title", "users.name"])
            .join(USERS_TABLE_NAME, "user_id", "id")
            .all_as()
            .await?;

        assert_eq!(result.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_join_cache_behavior() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        // Use two regular (non-internal) tables to avoid pre-warmed caches.
        let authors_schema = SchemaBuilder::new("authors")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;

        let articles_schema = SchemaBuilder::new("articles")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("author_id", ColumnType::Integer)?
            .plaintext()
            .column("title", ColumnType::String)?
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Author {
            id: Option<i64>,
            name: String,
        }

        #[derive(Deserialize, Serialize)]
        struct Article {
            id: Option<i64>,
            author_id: i64,
            title: String,
        }

        #[derive(Deserialize)]
        struct ArticleWithAuthor {
            title: String,
            name: String,
        }

        let authors = space.table::<Author>("authors");
        let articles = space.table::<Article>("articles");
        space.create_table(&authors_schema).await?;
        space.create_table(&articles_schema).await?;

        let alice_id = authors
            .insert(&Author {
                id: None,
                name: "Alice".into(),
            })
            .execute()
            .await?;
        let bob_id = authors
            .insert(&Author {
                id: None,
                name: "Bob".into(),
            })
            .execute()
            .await?;
        // A third author that is NOT referenced by any article
        authors
            .insert(&Author {
                id: None,
                name: "Carol".into(),
            })
            .execute()
            .await?;

        articles
            .insert(&Article {
                id: None,
                author_id: alice_id,
                title: "Article A".into(),
            })
            .execute()
            .await?;
        articles
            .insert(&Article {
                id: None,
                author_id: bob_id,
                title: "Article B".into(),
            })
            .execute()
            .await?;

        // Verify neither table is cached yet
        assert!(!space.with_state(|s| s.cache.is_table_complete("articles")));
        assert!(!space.with_state(|s| s.cache.is_table_complete("authors")));

        // First join query — cache miss, fetches from server
        let result1: Vec<ArticleWithAuthor> = articles
            .select()
            .columns(&["articles.title", "authors.name"])
            .join("authors", "author_id", "id")
            .all_as()
            .await?;
        assert_eq!(result1.len(), 2);
        assert!(result1
            .iter()
            .any(|r| r.title == "Article A" && r.name == "Alice"));
        assert!(result1
            .iter()
            .any(|r| r.title == "Article B" && r.name == "Bob"));

        // Main table fully cached; joined table NOT complete (only Alice + Bob, not Carol)
        assert!(space.with_state(|s| s.cache.is_table_complete("articles")));
        assert!(!space.with_state(|s| s.cache.is_table_complete("authors")));

        // But the individual matched author rows should be in cache by id
        assert!(space
            .with_state_mut(|s| s.cache.try_query("authors", &[], &[alice_id]))
            .is_some());
        assert!(space
            .with_state_mut(|s| s.cache.try_query("authors", &[], &[bob_id]))
            .is_some());

        // Second join query — served entirely from cache, same results
        let result2: Vec<ArticleWithAuthor> = articles
            .select()
            .columns(&["articles.title", "authors.name"])
            .join("authors", "author_id", "id")
            .all_as()
            .await?;
        assert_eq!(result2.len(), 2);
        assert!(result2
            .iter()
            .any(|r| r.title == "Article A" && r.name == "Alice"));

        // Insert a new article (cache stays complete — changelog insert updates in-place)
        articles
            .insert(&Article {
                id: None,
                author_id: alice_id,
                title: "Article C".into(),
            })
            .execute()
            .await?;
        assert!(space.with_state(|s| s.cache.is_table_complete("articles")));

        // Third join query — served from cache (articles cache is still complete)
        let result3: Vec<ArticleWithAuthor> = articles
            .select()
            .columns(&["articles.title", "authors.name"])
            .join("authors", "author_id", "id")
            .all_as()
            .await?;
        assert_eq!(result3.len(), 3);
        assert!(result3
            .iter()
            .any(|r| r.title == "Article C" && r.name == "Alice"));

        Ok(())
    }

    #[tokio::test]
    async fn test_join_cache_on_indexed_column(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        // "categories" has an indexed "code" column (non-PK).
        // "products" joins on code, not id.
        let cat_schema = SchemaBuilder::new("categories")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("code", ColumnType::Integer)?
            .plaintext()
            .index()
            .column("label", ColumnType::String)?
            .plaintext()
            .build()?;

        let prod_schema = SchemaBuilder::new("products")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("cat_code", ColumnType::Integer)?
            .plaintext()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Category {
            id: Option<i64>,
            code: i64,
            label: String,
        }
        #[derive(Deserialize, Serialize)]
        struct Product {
            id: Option<i64>,
            cat_code: i64,
            name: String,
        }
        #[derive(Deserialize)]
        struct ProductWithCategory {
            name: String,
            label: String,
        }

        let cats = space.table::<Category>("categories");
        let prods = space.table::<Product>("products");
        space.create_table(&cat_schema).await?;
        space.create_table(&prod_schema).await?;

        cats.insert(&Category {
            id: None,
            code: 10,
            label: "Electronics".into(),
        })
        .execute()
        .await?;
        cats.insert(&Category {
            id: None,
            code: 20,
            label: "Books".into(),
        })
        .execute()
        .await?;
        cats.insert(&Category {
            id: None,
            code: 30,
            label: "Clothing".into(),
        })
        .execute()
        .await?;

        prods
            .insert(&Product {
                id: None,
                cat_code: 10,
                name: "Laptop".into(),
            })
            .execute()
            .await?;
        prods
            .insert(&Product {
                id: None,
                cat_code: 20,
                name: "Novel".into(),
            })
            .execute()
            .await?;

        // First join — fetches from server, caches individual code values
        let result1: Vec<ProductWithCategory> = prods
            .select()
            .columns(&["products.name", "categories.label"])
            .join("categories", "cat_code", "code")
            .all_as()
            .await?;
        assert_eq!(result1.len(), 2);
        assert!(result1
            .iter()
            .any(|r| r.name == "Laptop" && r.label == "Electronics"));
        assert!(result1
            .iter()
            .any(|r| r.name == "Novel" && r.label == "Books"));

        // Categories table should NOT be fully cached (code=30 was never fetched)
        assert!(
            !space.with_state(|s| s.cache.is_table_complete("categories")),
            "categories should not be marked complete"
        );

        // But code=10 and code=20 should be cached as complete index values
        let code10 =
            space.with_state_mut(|s| s.cache.try_query("categories", &[("code".into(), 10)], &[]));
        let code20 =
            space.with_state_mut(|s| s.cache.try_query("categories", &[("code".into(), 20)], &[]));
        let code30 =
            space.with_state_mut(|s| s.cache.try_query("categories", &[("code".into(), 30)], &[]));
        assert!(code10.is_some(), "code=10 should be cached");
        assert!(code20.is_some(), "code=20 should be cached");
        assert!(
            code30.is_none(),
            "code=30 should NOT be cached (never fetched)"
        );

        // Second query — should hit cache for categories
        let result2: Vec<ProductWithCategory> = prods
            .select()
            .columns(&["products.name", "categories.label"])
            .join("categories", "cat_code", "code")
            .all_as()
            .await?;
        assert_eq!(result2.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_join_cache_partial_miss() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let authors_schema = SchemaBuilder::new("authors")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;

        let articles_schema = SchemaBuilder::new("articles")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("author_id", ColumnType::Integer)?
            .plaintext()
            .column("title", ColumnType::String)?
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Author {
            id: Option<i64>,
            name: String,
        }
        #[derive(Deserialize, Serialize)]
        struct Article {
            id: Option<i64>,
            author_id: i64,
            title: String,
        }
        #[derive(Deserialize)]
        struct ArticleWithAuthor {
            title: String,
            name: String,
        }

        let authors = space.table::<Author>("authors");
        let articles = space.table::<Article>("articles");
        space.create_table(&authors_schema).await?;
        space.create_table(&articles_schema).await?;

        let alice_id = authors
            .insert(&Author {
                id: None,
                name: "Alice".into(),
            })
            .execute()
            .await?;
        let bob_id = authors
            .insert(&Author {
                id: None,
                name: "Bob".into(),
            })
            .execute()
            .await?;
        let carol_id = authors
            .insert(&Author {
                id: None,
                name: "Carol".into(),
            })
            .execute()
            .await?;

        // Only Alice's article initially
        articles
            .insert(&Article {
                id: None,
                author_id: alice_id,
                title: "A1".into(),
            })
            .execute()
            .await?;

        // First join — caches Alice in authors
        let r1: Vec<ArticleWithAuthor> = articles
            .select()
            .columns(&["articles.title", "authors.name"])
            .join("authors", "author_id", "id")
            .all_as()
            .await?;
        assert_eq!(r1.len(), 1);
        assert_eq!(r1[0].title, "A1");
        assert_eq!(r1[0].name, "Alice");

        // Alice is cached, Bob and Carol are not
        assert!(space
            .with_state_mut(|s| s.cache.try_query("authors", &[], &[alice_id]))
            .is_some());
        assert!(space
            .with_state_mut(|s| s.cache.try_query("authors", &[], &[bob_id]))
            .is_none());

        // Add an article by Carol — articles cache invalidated
        articles
            .insert(&Article {
                id: None,
                author_id: carol_id,
                title: "C1".into(),
            })
            .execute()
            .await?;

        // Second join — Alice is cached but Carol is not → cache miss for
        // joined table → full re-fetch from server
        let r2: Vec<ArticleWithAuthor> = articles
            .select()
            .columns(&["articles.title", "authors.name"])
            .join("authors", "author_id", "id")
            .all_as()
            .await?;
        assert_eq!(r2.len(), 2);
        assert!(r2.iter().any(|r| r.title == "A1" && r.name == "Alice"));
        assert!(r2.iter().any(|r| r.title == "C1" && r.name == "Carol"));

        // Now both Alice and Carol should be cached
        assert!(space
            .with_state_mut(|s| s.cache.try_query("authors", &[], &[alice_id]))
            .is_some());
        assert!(space
            .with_state_mut(|s| s.cache.try_query("authors", &[], &[carol_id]))
            .is_some());
        // Bob still not cached (never referenced)
        assert!(space
            .with_state_mut(|s| s.cache.try_query("authors", &[], &[bob_id]))
            .is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_join_cache_reused_across_different_where(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let authors_schema = SchemaBuilder::new("authors")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;

        let articles_schema = SchemaBuilder::new("articles")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("author_id", ColumnType::Integer)?
            .plaintext()
            .column("category", ColumnType::Integer)?
            .plaintext()
            .index()
            .column("title", ColumnType::String)?
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Author {
            id: Option<i64>,
            name: String,
        }
        #[derive(Deserialize, Serialize)]
        struct Article {
            id: Option<i64>,
            author_id: i64,
            category: i64,
            title: String,
        }
        #[derive(Deserialize)]
        struct ArticleWithAuthor {
            title: String,
            name: String,
        }

        let authors = space.table::<Author>("authors");
        let articles = space.table::<Article>("articles");
        space.create_table(&authors_schema).await?;
        space.create_table(&articles_schema).await?;

        let alice_id = authors
            .insert(&Author {
                id: None,
                name: "Alice".into(),
            })
            .execute()
            .await?;

        articles
            .insert(&Article {
                id: None,
                author_id: alice_id,
                category: 1,
                title: "Cat1 Article".into(),
            })
            .execute()
            .await?;
        articles
            .insert(&Article {
                id: None,
                author_id: alice_id,
                category: 2,
                title: "Cat2 Article".into(),
            })
            .execute()
            .await?;

        // First query: WHERE category=1, joins Alice
        let r1: Vec<ArticleWithAuthor> = articles
            .select()
            .columns(&["articles.title", "authors.name"])
            .join("authors", "author_id", "id")
            .where_eq("category", 1)
            .all_as()
            .await?;
        assert_eq!(r1.len(), 1);
        assert_eq!(r1[0].title, "Cat1 Article");
        assert_eq!(r1[0].name, "Alice");

        // Alice should be cached by id
        assert!(space
            .with_state_mut(|s| s.cache.try_query("authors", &[], &[alice_id]))
            .is_some());

        // Second query: WHERE category=2 — different main rows, but same
        // author (Alice) should be served from cache
        let r2: Vec<ArticleWithAuthor> = articles
            .select()
            .columns(&["articles.title", "authors.name"])
            .join("authors", "author_id", "id")
            .where_eq("category", 2)
            .all_as()
            .await?;
        assert_eq!(r2.len(), 1);
        assert_eq!(r2[0].title, "Cat2 Article");
        assert_eq!(r2[0].name, "Alice");

        Ok(())
    }

    #[tokio::test]
    async fn test_crud_operations() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let schema = SchemaBuilder::new("test_items")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .index()
            .column("value", ColumnType::Integer)?
            .plaintext()
            .build()?;

        #[derive(Deserialize, Serialize, Debug)]
        struct Item {
            id: Option<i64>,
            name: String,
            value: i64,
        }

        let table = space.table::<Item>("test_items");
        space.create_table(&schema).await?;

        // Test INSERT
        let item1 = Item {
            id: None,
            name: "item1".to_string(),
            value: 100,
        };
        let item2 = Item {
            id: None,
            name: "item2".to_string(),
            value: 200,
        };

        let id1 = table.insert(&item1).execute().await?;
        let id2 = table.insert(&item2).execute().await?;

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);

        // Test SELECT ALL
        let all_items = table.select().all().await?;
        assert_eq!(all_items.len(), 2);

        // Test SELECT with WHERE
        let item = table.select().where_eq("name", "item1").first().await?;
        assert!(item.is_some());
        let item = item.unwrap();
        assert_eq!(item.name, "item1");
        assert_eq!(item.value, 100);

        // Test UPDATE
        let updated_count = table
            .update()
            .set("value", 150)
            .where_eq("name", "item1")
            .execute()
            .await?;
        assert_eq!(updated_count, 1);

        // Verify update worked
        let updated_item = table
            .select()
            .where_eq("name", "item1")
            .first()
            .await?
            .unwrap();
        assert_eq!(updated_item.value, 150);

        // Test DELETE
        let deleted_count = table.delete().where_eq("name", "item2").execute().await?;
        assert_eq!(deleted_count, 1);

        // Verify delete worked
        let remaining_items = table.select().all().await?;
        assert_eq!(remaining_items.len(), 1);
        assert_eq!(remaining_items[0].name, "item1");

        Ok(())
    }

    #[tokio::test]
    async fn test_where_conditions() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let schema = SchemaBuilder::new("numbers")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("value", ColumnType::Integer)?
            .plaintext()
            .index()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;

        let table = space.table::<serde_json::Value>("numbers");
        space.create_table(&schema).await?;

        // Insert test data
        for i in 1..=10 {
            let item = serde_json::json!({
                "id": null,
                "value": i * 10,
                "name": if i % 2 == 0 { serde_json::Value::String(format!("even{i}")) } else { serde_json::Value::Null }
            });
            table.insert(&item).execute().await?;
        }

        // Test greater than
        let gt_results = table.select().where_gt("value", 50).all().await?;
        assert_eq!(gt_results.len(), 5);

        // Test less than or equal
        let lte_results = table.select().where_lte("value", 30).all().await?;
        assert_eq!(lte_results.len(), 3);

        // Test not equal (client-side filter)
        let ne_results = table
            .select()
            .filter("value", |v| v.as_i64() != Some(50))
            .all()
            .await?;
        assert_eq!(ne_results.len(), 9);

        // Test IS NULL (client-side filter)
        let null_results = table.select().filter("name", |v| v.is_null()).all().await?;
        assert_eq!(null_results.len(), 5);

        // Test IS NOT NULL (client-side filter)
        let not_null_results = table
            .select()
            .filter("name", |v| !v.is_null())
            .all()
            .await?;
        assert_eq!(not_null_results.len(), 5);

        Ok(())
    }

    #[tokio::test]
    async fn test_ordering_and_limiting() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let schema = SchemaBuilder::new("ordered_items")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("priority", ColumnType::Integer)?
            .plaintext()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;

        #[derive(Deserialize, Serialize)]
        struct Item {
            id: Option<i64>,
            priority: i64,
            name: String,
        }
        let table = space.table::<Item>("ordered_items");
        space.create_table(&schema).await?;

        // Insert in monotonic priority order so row-id order matches it
        // (the new API only sorts by the implicit column — row id here).
        for (name, priority) in [
            ("low", 1),
            ("lower", 3),
            ("medium", 5),
            ("higher", 8),
            ("high", 10),
        ] {
            let item = Item {
                id: None,
                name: name.to_string(),
                priority,
            };
            table.insert(&item).execute().await?;
        }

        let asc = table.select().ascending().all().await?;
        assert_eq!(asc.len(), 5);
        assert_eq!(asc[0].name, "low");
        assert_eq!(asc[4].name, "high");

        let desc = table.select().descending().all().await?;
        assert_eq!(desc[0].name, "high");
        assert_eq!(desc[4].name, "low");

        let limited = table.select().ascending().limit(3).all().await?;
        assert_eq!(limited.len(), 3);
        assert_eq!(limited[2].name, "medium");

        // Cursor-style paging (replaces .offset()).
        let page = table
            .select()
            .where_gt("id", 1)
            .ascending()
            .limit(2)
            .all()
            .await?;
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].name, "lower");
        assert_eq!(page[1].name, "medium");

        assert_eq!(table.select().last().await?.unwrap().name, "high");

        Ok(())
    }

    #[tokio::test]
    async fn test_auto_increment_behavior() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let schema = SchemaBuilder::new("auto_test")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("data", ColumnType::String)?
            .plaintext()
            .build()?;

        let table = space.table::<serde_json::Value>("auto_test");
        space.create_table(&schema).await?;

        // Auto-increment table: server assigns sequential ids.
        let id1 = table
            .insert(&serde_json::json!({"id": null, "data": "first"}))
            .execute()
            .await?;
        let id2 = table
            .insert(&serde_json::json!({"id": null, "data": "second"}))
            .execute()
            .await?;
        let id3 = table
            .insert(&serde_json::json!({"id": null, "data": "third"}))
            .execute()
            .await?;

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);

        // Explicit ids are forbidden on an auto-increment table.
        let err = table
            .insert(&serde_json::json!({"id": 100, "data": "explicit"}))
            .execute()
            .await
            .expect_err("explicit id on auto-increment table must be rejected");
        assert!(
            format!("{err}").contains("auto-increment"),
            "unexpected error: {err}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_explicit_ids_schema() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let schema = SchemaBuilder::new("manual")
            .explicit_ids()
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("data", ColumnType::String)?
            .plaintext()
            .build()?;

        let table = space.table::<serde_json::Value>("manual");
        space.create_table(&schema).await?;

        // Explicit ids are required — including i64::MAX, which on an
        // auto-increment table would be a counter-corruption attack.
        let id = table
            .insert(&serde_json::json!({"id": 42, "data": "forty-two"}))
            .execute()
            .await?;
        assert_eq!(id, 42);

        let id_max = table
            .insert(&serde_json::json!({"id": i64::MAX, "data": "max"}))
            .execute()
            .await?;
        assert_eq!(id_max, i64::MAX);

        // Missing id is rejected on an explicit-id table.
        let err = table
            .insert(&serde_json::json!({"id": null, "data": "no-id"}))
            .execute()
            .await
            .expect_err("missing id on explicit-id table must be rejected");
        assert!(
            format!("{err}").contains("explicit id"),
            "unexpected error: {err}"
        );

        // Duplicate explicit id is still rejected.
        let err = table
            .insert(&serde_json::json!({"id": 42, "data": "duplicate"}))
            .execute()
            .await
            .expect_err("duplicate explicit id must be rejected");
        assert!(
            format!("{err}").contains("already exists") || format!("{err}").contains("overwrite"),
            "unexpected error: {err}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_table_cache_behavior() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let schema = SchemaBuilder::new("cached_items")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .column("value", ColumnType::Integer)?
            .plaintext()
            .build()?;

        #[derive(serde::Deserialize, serde::Serialize, Debug)]
        struct Item {
            id: Option<i64>,
            name: String,
            value: i64,
        }

        let table = space.table::<Item>("cached_items");
        space.create_table(&schema).await?;

        // Insert some items
        table
            .insert(&Item {
                id: None,
                name: "item1".to_string(),
                value: 100,
            })
            .execute()
            .await?;
        table
            .insert(&Item {
                id: None,
                name: "item2".to_string(),
                value: 200,
            })
            .execute()
            .await?;

        // First read should populate the cache
        let items = table.select().all().await?;
        assert_eq!(items.len(), 2);

        // Verify cache is populated
        let is_complete = space.with_state(|state| state.cache.is_table_complete("cached_items"));
        assert!(is_complete, "Cache should be complete after full fetch");

        // Second read should serve from cache (same result)
        let items2 = table.select().all().await?;
        assert_eq!(items2.len(), 2);

        // Insert another item — cache should remain complete (changelog insert updates in-place)
        table
            .insert(&Item {
                id: None,
                name: "item3".to_string(),
                value: 300,
            })
            .execute()
            .await?;

        let is_complete = space.with_state(|state| state.cache.is_table_complete("cached_items"));
        assert!(
            is_complete,
            "Cache should remain complete after changelog insert"
        );

        // Read again, should have 3 items served from cache
        let items3 = table.select().all().await?;
        assert_eq!(items3.len(), 3);

        // Delete an item — cache should remain complete (changelog delete updates in-place)
        table.delete().where_eq("id", 2).execute().await?;

        let is_complete = space.with_state(|state| state.cache.is_table_complete("cached_items"));
        assert!(
            is_complete,
            "Cache should remain complete after changelog delete"
        );

        // Verify data is correct after delete
        let items4 = table.select().all().await?;
        assert_eq!(items4.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_cache_with_filtered_queries(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;

        let schema = SchemaBuilder::new("filtered_items")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .column("value", ColumnType::Integer)?
            .plaintext()
            .build()?;

        #[derive(serde::Deserialize, serde::Serialize, Debug)]
        struct Item {
            id: Option<i64>,
            name: String,
            value: i64,
        }

        let table = space.table::<Item>("filtered_items");
        space.create_table(&schema).await?;

        for i in 1..=5 {
            table
                .insert(&Item {
                    id: None,
                    name: format!("item{i}"),
                    value: i * 10,
                })
                .execute()
                .await?;
        }

        // First query with a filter — should populate full table cache
        let high_items = table
            .select()
            .filter("value", |v| v.as_i64().is_some_and(|n| n > 30))
            .all()
            .await?;
        assert_eq!(high_items.len(), 2); // value=40, value=50

        // Cache should be complete (full table)
        let is_complete = space.with_state(|state| state.cache.is_table_complete("filtered_items"));
        assert!(is_complete, "Cache should be complete after full fetch");

        // Subsequent filtered query should serve from cache
        let low_items = table
            .select()
            .filter("value", |v| v.as_i64().is_some_and(|n| n <= 20))
            .all()
            .await?;
        assert_eq!(low_items.len(), 2); // value=10, value=20

        // Limit + descending should serve from cache. Values monotonic with
        // row id, so descending by id matches descending by value here.
        let limited = table.select().descending().limit(3).all().await?;
        assert_eq!(limited.len(), 3);
        assert_eq!(limited[0].value, 50);
        assert_eq!(limited[1].value, 40);
        assert_eq!(limited[2].value, 30);

        Ok(())
    }

    #[tokio::test]
    async fn test_self_update_of_uncached_row_invalidates_partial_cache(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        space.authenticate_as_id(1).await?;

        let schema = SchemaBuilder::new("threaded_items")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("thread_id", ColumnType::Integer)?
            .plaintext()
            .index()
            .column("name", ColumnType::String)?
            .plaintext()
            .build()?;

        #[derive(serde::Deserialize, serde::Serialize, Debug)]
        struct Item {
            id: Option<i64>,
            thread_id: i64,
            name: String,
        }

        let table = space.table::<Item>("threaded_items");
        space.create_table(&schema).await?;

        table
            .insert(&Item {
                id: None,
                thread_id: 10,
                name: "in_bucket".to_string(),
            })
            .execute()
            .await?;
        table
            .insert(&Item {
                id: None,
                thread_id: 20,
                name: "moves_into_bucket".to_string(),
            })
            .execute()
            .await?;

        let bucket_before = table.select().where_eq("thread_id", 10).all().await?;
        assert_eq!(bucket_before.len(), 1);

        table
            .update()
            .set("id", 2)
            .set("thread_id", 10)
            .set("name", "moves_into_bucket")
            .where_eq("id", 2)
            .execute()
            .await?;

        let is_complete = space.with_state(|state| state.cache.is_table_complete("threaded_items"));
        assert!(
            is_complete,
            "update of a cached row should keep the table cache complete"
        );

        let bucket_after = table.select().where_eq("thread_id", 10).all().await?;
        assert_eq!(bucket_after.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_single_row_with_changelog(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        space.authenticate_as_id(1).await?;

        let schema = SchemaBuilder::new("products")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .column("price", ColumnType::Real)?
            .plaintext()
            .build()?;

        #[derive(Deserialize, Serialize, Debug)]
        struct Product {
            id: Option<i64>,
            name: String,
            price: f64,
        }

        let table = space.table::<Product>("products");
        space.create_table(&schema).await?;

        // Insert 3 products (untracked for simplicity)
        table
            .insert(&Product {
                id: None,
                name: "Apple".into(),
                price: 1.0,
            })
            .execute()
            .await?;
        table
            .insert(&Product {
                id: None,
                name: "Banana".into(),
                price: 2.0,
            })
            .execute()
            .await?;
        table
            .insert(&Product {
                id: None,
                name: "Cherry".into(),
                price: 3.0,
            })
            .execute()
            .await?;

        // Delete one product by id using changelog
        let deleted = table.delete().where_eq("id", 2).execute().await?;
        assert_eq!(deleted, 1);

        // Verify only 2 remain
        let remaining: Vec<Product> = table.select().all().await?;
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().all(|p| p.name != "Banana"));

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_multiple_rows_with_changelog(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let space = Space::new(LocalTransport::in_memory().await?).await?;
        space.authenticate_as_id(1).await?;

        let schema = SchemaBuilder::new("products")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .plaintext()
            .column("price", ColumnType::Real)?
            .plaintext()
            .index()
            .build()?;

        #[derive(Deserialize, Serialize, Debug)]
        struct Product {
            id: Option<i64>,
            name: String,
            price: f64,
        }

        let table = space.table::<Product>("products");
        space.create_table(&schema).await?;

        // Insert 5 products
        for (name, price) in &[
            ("Apple", 1.0),
            ("Banana", 2.0),
            ("Cherry", 3.0),
            ("Date", 4.0),
            ("Elderberry", 5.0),
        ] {
            table
                .insert(&Product {
                    id: None,
                    name: name.to_string(),
                    price: *price,
                })
                .execute()
                .await?;
        }

        // Delete all products with price < 3.0 (Apple=id 1, Banana=id 2) using changelog
        let deleted = table.delete().where_lt("price", 3.0).execute().await?;
        assert_eq!(deleted, 2);

        // Verify 3 remain
        let remaining: Vec<Product> = table.select().all().await?;
        assert_eq!(remaining.len(), 3);
        assert!(remaining.iter().all(|p| p.price >= 3.0));

        Ok(())
    }

    /// `Table::insert` is now infallible — any serialization failure is
    /// captured inside the returned `InsertBuilder` and must resurface
    /// when the caller awaits `.execute()` (or any other terminal
    /// method that goes through `prepare_change_as`).
    #[tokio::test]
    async fn insert_serialization_failure_propagates_to_execute(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use encrypted_spaces_backend::error::SdkError;

        let space = Space::new(LocalTransport::in_memory().await?).await?;

        // Case 1: serialization succeeds but does not produce a JSON object.
        // `i64` round-trips to a `Number`, which has no column/value pairs.
        // The error fires inside `prepare_change_as` before any backend
        // interaction, so the table does not need to exist.
        let primitive_result = space
            .table::<i64>("anything")
            .insert(&42_i64)
            .execute()
            .await;
        match primitive_result {
            Err(SdkError::SerializationError(msg)) => assert!(
                msg.contains("must serialize to a JSON object"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected SerializationError for non-object, got {other:?}"),
        }

        // Case 2: the value's `Serialize` impl returns an error.
        struct AlwaysFails;
        impl Serialize for AlwaysFails {
            fn serialize<S: serde::Serializer>(
                &self,
                _ser: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("synthetic boom"))
            }
        }

        let serde_err_result = space
            .table::<AlwaysFails>("anything")
            .insert(&AlwaysFails)
            .execute()
            .await;
        match serde_err_result {
            Err(SdkError::SerializationError(msg)) => {
                assert!(
                    msg.contains("JSON serialization error"),
                    "unexpected prefix: {msg}"
                );
                assert!(
                    msg.contains("synthetic boom"),
                    "missing inner serde error: {msg}"
                );
            }
            other => panic!("expected SerializationError for serde Err, got {other:?}"),
        }

        Ok(())
    }
}
