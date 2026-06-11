//! Random generators for schemas, rows, and predicates.
//!
//! All generators use the supplied `StdRng` so a single seed reproduces a full
//! fuzzing run end-to-end.

use std::cmp::Ordering;

use encrypted_spaces_acl_types::{Action, ActionLeg, Assertion};
use encrypted_spaces_backend::{
    access_control::{AccessOperation, AccessRule, ColumnNamespace, ComparisonOp, RuleValue},
    query::{ComparisonOperator, QueryParam},
    schema::{ColumnDefinition, ColumnType, Schema},
};
use rand::Rng;
use serde_json::{Map, Value};

use crate::model::TableModel;

/// Plain column types — generated freely. `Blob` is excluded (serde_json
/// round-trips `Vec<u8>` as an array of integers, which `QueryParam::from`
/// then maps to `Text`, defeating the round-trip invariant).
const PLAIN_COLUMN_TYPES: &[ColumnType] =
    &[ColumnType::Integer, ColumnType::String, ColumnType::Real];

/// `ColumnType::List` cells need a placeholder `0` on insert and can't
/// participate in predicates / joins; `ColumnType::FileRef` cells store a
/// hex SHA-256 hash and require an upload before insert.  Those types live
/// behind dedicated ops, so we mix them in less frequently than plain
/// scalars.
const SPECIAL_COLUMN_TYPES: &[ColumnType] = &[ColumnType::List, ColumnType::FileRef];

pub fn random_table_name(rng: &mut impl Rng, existing: &[&str]) -> String {
    loop {
        let len = rng.random_range(3..=10);
        let name: String = (0..len)
            .map(|i| {
                if i == 0 {
                    (b'a' + rng.random_range(0..26)) as char
                } else {
                    let pool = b"abcdefghijklmnopqrstuvwxyz0123456789";
                    pool[rng.random_range(0..pool.len())] as char
                }
            })
            .collect();
        if !existing.iter().any(|n| *n == name) {
            return name;
        }
    }
}

pub fn random_reserved_name(rng: &mut impl Rng) -> String {
    let len = rng.random_range(3..=10);
    let suffix: String = (0..len)
        .map(|_| {
            let pool = b"abcdefghijklmnopqrstuvwxyz";
            pool[rng.random_range(0..pool.len())] as char
        })
        .collect();
    format!("_{suffix}")
}

pub fn random_schema(rng: &mut impl Rng, name: String) -> Schema {
    let n_extra_cols = rng.random_range(2..=4);
    let mut columns = Vec::with_capacity(n_extra_cols + 1);

    columns.push(ColumnDefinition {
        name: "id".to_string(),
        column_type: ColumnType::Integer,
        plaintext: true,
        indexed: false,
    });

    let mut used_names: Vec<String> = vec!["id".to_string()];
    // Guarantee at least one indexed non-id scalar column so predicate / join
    // ops always have a valid target beyond `id`.
    let force_indexed_slot = rng.random_range(0..n_extra_cols);
    for i in 0..n_extra_cols {
        let col_name = loop {
            let len = rng.random_range(2..=8);
            let name: String = (0..len)
                .map(|i| {
                    if i == 0 {
                        (b'a' + rng.random_range(0..26)) as char
                    } else {
                        let pool = b"abcdefghijklmnopqrstuvwxyz0123456789";
                        pool[rng.random_range(0..pool.len())] as char
                    }
                })
                .collect();
            if !used_names.contains(&name) {
                break name;
            }
        };
        used_names.push(col_name.clone());

        // Force the indexed slot to a plain scalar (List / FileRef can't be
        // indexed). Otherwise pick a special type ~20% of the time.
        let column_type = if i == force_indexed_slot || !rng.random_bool(0.2) {
            PLAIN_COLUMN_TYPES[rng.random_range(0..PLAIN_COLUMN_TYPES.len())].clone()
        } else {
            SPECIAL_COLUMN_TYPES[rng.random_range(0..SPECIAL_COLUMN_TYPES.len())].clone()
        };
        let is_special = matches!(column_type, ColumnType::List | ColumnType::FileRef);
        // List / FileRef can't be indexed.
        let indexed = !is_special && (i == force_indexed_slot || rng.random_bool(0.4));
        // Indexed columns must be plaintext.  List and FileRef columns must
        // also be plaintext: List cells carry the placeholder 0 on insert
        // (the verifier substitutes the allocated list_number), and FileRef
        // cells need the server to read the hash for lifecycle management.
        let plaintext = indexed
            || matches!(column_type, ColumnType::FileRef | ColumnType::List)
            || rng.random_bool(0.5);
        columns.push(ColumnDefinition {
            name: col_name,
            column_type,
            plaintext,
            indexed,
        });
    }

    // Roll for `auto_increment = false` 25% of the time. Client-supplied ids
    // are a separate verifier path with its own duplicate-id rejection rule.
    let auto_increment = !rng.random_bool(0.25);

    Schema {
        name,
        columns,
        auto_increment,
    }
}

/// Per-cell row-generation override. The fuzzer fills FileRef cells with
/// pre-uploaded hashes (decided at insert time, not in the generator) and
/// fills List cells with the placeholder integer `0`. Build a row generic
/// over scalar columns and pass these overrides for the special ones.
pub struct RowOverrides {
    pub map: std::collections::HashMap<String, Value>,
}

impl Default for RowOverrides {
    fn default() -> Self {
        Self::new()
    }
}

impl RowOverrides {
    pub fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
        }
    }

    pub fn set_owned(&mut self, col: String, value: Value) {
        self.map.insert(col, value);
    }
}

/// Generate a JSON object suitable for `space.table::<Value>(name).insert(&row)`.
///
/// * `id` defaults to `Value::Null` (caller overrides it for explicit-id
///   tables).
/// * `ColumnType::List` cells default to the placeholder integer `0`.
/// * `ColumnType::FileRef` cells default to `Value::Null` and must be
///   overridden — the caller has to upload the file first to know the hash.
pub fn random_row(rng: &mut impl Rng, schema: &Schema) -> Value {
    random_row_with_overrides_owned(rng, schema, &RowOverrides::new())
}

pub fn random_row_with_overrides_owned(
    rng: &mut impl Rng,
    schema: &Schema,
    overrides: &RowOverrides,
) -> Value {
    let mut map = Map::new();
    map.insert(
        "id".to_string(),
        overrides.map.get("id").cloned().unwrap_or(Value::Null),
    );
    for col in &schema.columns {
        if col.name == "id" {
            continue;
        }
        if let Some(v) = overrides.map.get(col.name.as_str()) {
            map.insert(col.name.clone(), v.clone());
            continue;
        }
        let value = match col.column_type {
            ColumnType::List => Value::from(0),
            ColumnType::FileRef => Value::Null,
            _ => random_scalar_value(rng, &col.column_type),
        };
        map.insert(col.name.clone(), value);
    }
    Value::Object(map)
}

/// Random scalar value generator (Integer / Text / Real). Not for List /
/// FileRef / Blob — those need overrides.
pub fn random_scalar_value(rng: &mut impl Rng, ty: &ColumnType) -> Value {
    match ty {
        ColumnType::Integer => Value::from(rng.random_range(-1_000_000_i64..=1_000_000)),
        ColumnType::Real => {
            // Full f64 range — the storage format now preserves bit-exact f64
            // values via `encrypted_spaces_storage_encoding::stored_value`. Skip
            // NaN/Inf because those do not survive JSON; the round-trip
            // invariant treats them as Null.
            let bits: u64 = rng.random();
            let v = f64::from_bits(bits);
            if v.is_finite() {
                serde_json::Number::from_f64(v)
                    .map(Value::Number)
                    .unwrap_or(Value::from(0))
            } else {
                Value::from(0)
            }
        }
        ColumnType::String | ColumnType::Text => Value::String(random_text(rng, 0, 16)),
        // Special types have no scalar representation here — caller must
        // override via `RowOverrides`.
        ColumnType::Blob | ColumnType::FileRef | ColumnType::List => Value::Null,
    }
}

/// Random ASCII text of length `[lo, hi]`.
pub fn random_text(rng: &mut impl Rng, lo: usize, hi: usize) -> String {
    let len = rng.random_range(lo..=hi);
    (0..len)
        .map(|_| {
            let pool = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            pool[rng.random_range(0..pool.len())] as char
        })
        .collect()
}

/// Random bytes of length `[lo, hi]` for FileRef uploads.
pub fn random_bytes(rng: &mut impl Rng, lo: usize, hi: usize) -> Vec<u8> {
    let len = rng.random_range(lo..=hi);
    (0..len).map(|_| rng.random()).collect()
}

/// A random predicate that is guaranteed legal under the SDK's
/// `where_*` preconditions (column is PK or indexed; for `Between`, `lo <= hi`;
/// for `In`, at least one value).
pub struct RandomPredicate {
    pub column: String,
    /// Retained for diagnostics and future column-type-aware invariants.
    #[allow(dead_code)]
    pub column_type: ColumnType,
    pub operator: ComparisonOperator,
    pub values: Vec<Value>,
}

impl RandomPredicate {
    /// Evaluate the predicate against a single shadow row. Mirrors the
    /// SDK's `row_matches_predicate` behaviour in `sdk/src/table.rs:285-316`.
    pub fn matches(&self, row: &Value) -> bool {
        let cell = row.get(&self.column).unwrap_or(&Value::Null);
        match self.operator {
            ComparisonOperator::Equal => {
                let want = self.values.first().unwrap_or(&Value::Null);
                values_logically_eq(cell, want)
            }
            ComparisonOperator::In => self
                .values
                .iter()
                .any(|want| values_logically_eq(cell, want)),
            ComparisonOperator::GreaterThan => {
                compare_cells(cell, self.values.first().unwrap_or(&Value::Null))
                    .is_some_and(|o| o == Ordering::Greater)
            }
            ComparisonOperator::GreaterThanOrEqual => {
                compare_cells(cell, self.values.first().unwrap_or(&Value::Null))
                    .is_some_and(|o| o != Ordering::Less)
            }
            ComparisonOperator::LessThan => {
                compare_cells(cell, self.values.first().unwrap_or(&Value::Null))
                    .is_some_and(|o| o == Ordering::Less)
            }
            ComparisonOperator::LessThanOrEqual => {
                compare_cells(cell, self.values.first().unwrap_or(&Value::Null))
                    .is_some_and(|o| o != Ordering::Greater)
            }
            ComparisonOperator::Between => {
                if self.values.len() != 2 {
                    return false;
                }
                let lo = &self.values[0];
                let hi = &self.values[1];
                let ge_lo = compare_cells(cell, lo).is_some_and(|o| o != Ordering::Less);
                let le_hi = compare_cells(cell, hi).is_some_and(|o| o != Ordering::Greater);
                ge_lo && le_hi
            }
        }
    }

    pub fn to_query_params(&self) -> Vec<QueryParam> {
        self.values.iter().cloned().map(QueryParam::from).collect()
    }
}

fn values_logically_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(xf), Some(yf)) => xf == yf,
            _ => x == y,
        },
        _ => a == b,
    }
}

fn compare_cells(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(xf), Some(yf)) => xf.partial_cmp(&yf),
            _ => None,
        },
        (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

/// Pick a random predicate-legal column for `table` (PK or indexed). List
/// and FileRef columns are skipped — predicate comparison on a hex hash is
/// pointless, and the schema generator already prevents them from being
/// indexed.
fn pick_predicate_column<'a>(rng: &mut impl Rng, table: &'a TableModel) -> &'a ColumnDefinition {
    let mut pool: Vec<&ColumnDefinition> = table
        .schema
        .columns
        .iter()
        .filter(|c| {
            (c.name == "id" || c.indexed)
                && !matches!(c.column_type, ColumnType::List | ColumnType::FileRef)
        })
        .collect();
    debug_assert!(!pool.is_empty(), "schema must have id");
    let idx = rng.random_range(0..pool.len());
    pool.remove(idx)
}

pub fn random_predicate(rng: &mut impl Rng, table: &TableModel) -> RandomPredicate {
    let col = pick_predicate_column(rng, table);
    let column_type = col.column_type.clone();
    let column = col.name.clone();
    let operator = random_operator(rng);
    let values = match operator {
        ComparisonOperator::Equal
        | ComparisonOperator::GreaterThan
        | ComparisonOperator::GreaterThanOrEqual
        | ComparisonOperator::LessThan
        | ComparisonOperator::LessThanOrEqual => {
            vec![sample_value_for_column(rng, table, &column, &column_type)]
        }
        ComparisonOperator::In => {
            let n = rng.random_range(1..=3);
            (0..n)
                .map(|_| sample_value_for_column(rng, table, &column, &column_type))
                .collect()
        }
        ComparisonOperator::Between => {
            let a = sample_value_for_column(rng, table, &column, &column_type);
            let b = sample_value_for_column(rng, table, &column, &column_type);
            match compare_cells(&a, &b) {
                Some(Ordering::Greater) => vec![b, a],
                _ => vec![a, b],
            }
        }
    };
    RandomPredicate {
        column,
        column_type,
        operator,
        values,
    }
}

fn random_operator(rng: &mut impl Rng) -> ComparisonOperator {
    const OPS: &[ComparisonOperator] = &[
        ComparisonOperator::Equal,
        ComparisonOperator::In,
        ComparisonOperator::GreaterThan,
        ComparisonOperator::GreaterThanOrEqual,
        ComparisonOperator::LessThan,
        ComparisonOperator::LessThanOrEqual,
        ComparisonOperator::Between,
    ];
    OPS[rng.random_range(0..OPS.len())].clone()
}

/// Sample a value for `column`. 50% chance draws from the column values that
/// actually appear in the shadow rows (biases toward matching predicates).
fn sample_value_for_column(
    rng: &mut impl Rng,
    table: &TableModel,
    column: &str,
    column_type: &ColumnType,
) -> Value {
    if rng.random_bool(0.5) {
        let candidates: Vec<Value> = table
            .rows
            .values()
            .filter_map(|row| row.get(column).cloned())
            .filter(|v| !v.is_null())
            .collect();
        if !candidates.is_empty() {
            return candidates[rng.random_range(0..candidates.len())].clone();
        }
    }
    random_scalar_value(rng, column_type)
}

/// All SDK-recognised ACL operations.
pub const ACL_OPERATIONS: &[AccessOperation] = &[AccessOperation::Write, AccessOperation::Delete];

/// Generate a random ACL rule against `schema`.
///
/// The variants split into permissive (always-true), uid-selective
/// (denies some uids regardless of row content), and
/// row-selective (per-row predicates that the model filters one row at
/// a time, mirroring the SDK's `validate_insert_access` path).
///
/// `row.<col>` resolves to an `i64` (`evaluate` calls
/// `as_i64` on the JSON value), so the row-selective variants only
/// reference Integer columns. They also need the column to actually
/// exist on the table — schemas without an Integer column fall back to
/// uid-only rules.
pub fn random_acl_rule(rng: &mut impl Rng, schema: &Schema) -> AccessRule {
    // Encrypted columns are unreadable to the SDK at evaluate time —
    // `validate_insert_access` extracts column values from `main_rows`
    // *before* decryption, so a `ResourceColumn` rule against an
    // encrypted column trips `ValidationError("resource column 'X' is
    // not an integer")` against the ciphertext. Restrict
    // `ResourceColumn` rules to plaintext Integer columns. (Same
    // constraint as encrypted FK columns in joins.)
    let int_columns: Vec<&str> = schema
        .columns
        .iter()
        .filter(|c| c.plaintext && matches!(c.column_type, ColumnType::Integer))
        .map(|c| c.name.as_str())
        .collect();

    // 60% pure uid/literal, 40% row-selective if we have an Integer
    // column to anchor the comparison on.
    if int_columns.is_empty() || rng.random_bool(0.6) {
        return random_uid_only_rule(rng);
    }
    let col = int_columns[rng.random_range(0..int_columns.len())].to_string();
    match rng.random_range(0..3) {
        0 => {
            // `ResourceColumn(col) == Int(K)` — only rows where
            // `row[col] == K` pass.
            let k = rng.random_range(-1_000_000..=1_000_000);
            AccessRule::comparison(
                RuleValue::column(ColumnNamespace::Resource, col),
                ComparisonOp::Equal,
                RuleValue::Int(k),
            )
        }
        1 => {
            // `ResourceColumn(col) == AuthUserId` — only rows where
            // `row[col] == auth.uid` pass (the canonical "user can only
            // touch their own rows" pattern).
            AccessRule::comparison(
                RuleValue::column(ColumnNamespace::Resource, col),
                ComparisonOp::Equal,
                RuleValue::AuthUserId,
            )
        }
        _ => {
            // `ResourceColumn(col) >= Int(K)` — only rows above some
            // threshold pass.
            let k = rng.random_range(-500_000..=500_000);
            AccessRule::comparison(
                RuleValue::column(ColumnNamespace::Resource, col),
                ComparisonOp::GreaterEqual,
                RuleValue::Int(k),
            )
        }
    }
}

fn random_uid_only_rule(rng: &mut impl Rng) -> AccessRule {
    match rng.random_range(0..6) {
        // ── Permissive ──────────────────────────────────────────────
        0 => {
            let k = rng.random_range(0..1000);
            AccessRule::comparison(RuleValue::Int(k), ComparisonOp::Equal, RuleValue::Int(k))
        }
        1 => AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::GreaterEqual,
            RuleValue::Int(0),
        ),
        2 => {
            let m = rng.random_range(0..500);
            let n = m + rng.random_range(1..500);
            AccessRule::comparison(RuleValue::Int(n), ComparisonOp::Greater, RuleValue::Int(m))
        }
        // ── Selective (denies some uids) ────────────────────────────
        3 => AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::Int(1),
        ),
        4 => {
            let k = rng.random_range(1..=3);
            AccessRule::comparison(
                RuleValue::AuthUserId,
                ComparisonOp::LessEqual,
                RuleValue::Int(k),
            )
        }
        _ => {
            let k = rng.random_range(1..=5);
            AccessRule::comparison(
                RuleValue::AuthUserId,
                ComparisonOp::NotEqual,
                RuleValue::Int(k),
            )
        }
    }
}

/// A random legal join: `left.fk_col` joined to `right.pk_col` where `pk_col`
/// is PK or indexed on `right`. `right` may equal `left`; the executor aliases
/// those self-joins because the SDK rejects unaliased self-joins as ambiguous.
pub struct RandomJoin {
    pub left: String,
    pub right: String,
    pub fk_col: String,
    pub pk_col: String,
}

pub fn random_join(
    rng: &mut impl Rng,
    tables: &std::collections::HashMap<String, TableModel>,
) -> Option<RandomJoin> {
    if tables.is_empty() {
        return None;
    }
    let names: Vec<&String> = tables.keys().collect();
    let left_name = names[rng.random_range(0..names.len())].clone();
    let right_name = names[rng.random_range(0..names.len())].clone();

    let left = &tables[&left_name];
    let right = &tables[&right_name];

    let pk_candidates: Vec<&ColumnDefinition> = right
        .schema
        .columns
        .iter()
        .filter(|c| {
            (c.name == "id" || c.indexed)
                && !matches!(c.column_type, ColumnType::List | ColumnType::FileRef)
        })
        .collect();
    if pk_candidates.is_empty() {
        return None;
    }
    let pk_def = pk_candidates[rng.random_range(0..pk_candidates.len())];
    let pk_col = pk_def.name.clone();

    // FK-col pool is constrained two ways:
    //
    //   1. The FK value is read from the main row before decryption
    //      (`backend/src/merk_storage/proofs.rs:2548-2565`). For encrypted
    //      columns the cell still holds the ciphertext string at that point,
    //      so any encrypted FK column trips
    //      `ValidationError("FK value is not an integer")` against `pk_col=id`
    //      and a generally-malformed lookup against indexed pk_cols. Restrict
    //      FK to plaintext columns.
    //   2. When `pk_col == "id"`, FK values must be integers at runtime,
    //      else the same `ValidationError("FK value is not an integer")`
    //      fires. Restrict to Integer plaintext cols.
    let fk_candidates: Vec<&str> = if pk_col == "id" {
        left.schema
            .columns
            .iter()
            .filter(|c| c.plaintext && matches!(c.column_type, ColumnType::Integer))
            .map(|c| c.name.as_str())
            .collect()
    } else {
        left.schema
            .columns
            .iter()
            .filter(|c| {
                c.plaintext && !matches!(c.column_type, ColumnType::List | ColumnType::FileRef)
            })
            .map(|c| c.name.as_str())
            .collect()
    };
    if fk_candidates.is_empty() {
        return None;
    }
    let fk_col = fk_candidates[rng.random_range(0..fk_candidates.len())].to_string();

    Some(RandomJoin {
        left: left_name,
        right: right_name,
        fk_col,
        pk_col,
    })
}

// ─── Actions ─────────────────────────────────────────────────────────────────

/// Primary-leg shapes the action generator can produce.
#[derive(Debug, Clone)]
pub enum PrimaryShape {
    Insert,
    /// `update cols="a,b,..."` when `Some(cols)`; unrestricted `update`
    /// when `None`.
    Update(Option<Vec<String>>),
    Delete,
}

/// Generate a random action targeting `schema`.  Picks a fresh name not
/// in `existing_action_names`.  Only `auto_increment` tables are
/// suitable, since actions can't be declared on explicit-id tables (the
/// schema validator rejects them at parse time).
///
/// The output spans:
///   - primary leg: roughly even mix of insert / update / delete;
///   - update `cols`: ~50% restricted (1..N cols), ~50% unrestricted;
///   - `asserts`: 0..3 assertions over `self.<int_col>`, `auth.user_id`,
///     and integer literals, with random compound `and` / `or` / `not`.
///     Insert/Update see all plaintext-integer self-cols; Delete sees
///     only `self.id` (the verifier's `self_row` for a delete leg is
///     built from the row_id alone).
///
/// `exists()` and cascade legs are deferred; the bootstrap +
/// invocation + predict-outcome plumbing is the load-bearing piece
/// here.  Adding either later means wiring a peer-table picker into
/// this function and a `read_indexed_row_ids` mirror in the model.
pub fn random_action(
    rng: &mut impl Rng,
    schema: &Schema,
    existing_action_names: &std::collections::HashSet<String>,
) -> Option<Action> {
    if !schema.auto_increment {
        return None;
    }
    let shape = random_primary_shape(rng, schema);
    let primary = match &shape {
        PrimaryShape::Insert => ActionLeg::Insert {
            table: schema.name.clone(),
        },
        PrimaryShape::Update(cols) => ActionLeg::Update {
            table: schema.name.clone(),
            cols: cols.clone(),
        },
        PrimaryShape::Delete => ActionLeg::Delete {
            table: schema.name.clone(),
        },
    };
    let asserts = random_asserts(rng, schema, &shape);
    Some(Action {
        name: random_action_name(rng, existing_action_names),
        asserts,
        legs: vec![primary],
    })
}

fn random_primary_shape(rng: &mut impl Rng, schema: &Schema) -> PrimaryShape {
    let scalar_cols: Vec<&str> = schema
        .columns
        .iter()
        .filter(|c| {
            c.name != "id" && !matches!(c.column_type, ColumnType::List | ColumnType::FileRef)
        })
        .map(|c| c.name.as_str())
        .collect();

    // Roughly even mix of insert / update / delete.  Update needs at
    // least one updatable scalar col; without one we fall back to
    // insert.
    match (rng.random_range(0..3), scalar_cols.is_empty()) {
        (0, _) => PrimaryShape::Insert,
        (1, true) => PrimaryShape::Insert,
        (1, false) => {
            // ~50% of update legs restrict cols; the other half stays
            // open ("any column the table's schema declares").
            let cols = if rng.random_bool(0.5) {
                let max = scalar_cols.len().min(3);
                let n = rng.random_range(1..=max);
                let mut picked: Vec<String> = scalar_cols.iter().map(|s| s.to_string()).collect();
                for i in 0..n {
                    let j = rng.random_range(i..picked.len());
                    picked.swap(i, j);
                }
                picked.truncate(n);
                Some(picked)
            } else {
                None
            };
            PrimaryShape::Update(cols)
        }
        _ => PrimaryShape::Delete,
    }
}

/// Build 0..3 random assertions referring to `self.<col>`,
/// `auth.user_id`, and integer literals.  Each is either a single
/// comparison or a small compound (`and`, `or`, `not`).  The columns
/// available depend on the primary-leg variant: inserts see every
/// plaintext-integer column (the verifier's self-row is built from the
/// whole row); updates and deletes only see `self.id`.  For an update
/// the leg's kvs only carry the column being updated at call time, and
/// the fuzzer doesn't know in advance which one the runtime will pick;
/// for a delete the kvs are empty values and only `self.id` survives
/// the `self_row_from_leg_kvs` reconstruction (`action_op.rs`).
fn random_asserts(rng: &mut impl Rng, schema: &Schema, shape: &PrimaryShape) -> Vec<Assertion> {
    let int_cols: Vec<&str> = match shape {
        PrimaryShape::Insert => schema
            .columns
            .iter()
            .filter(|c| c.plaintext && matches!(c.column_type, ColumnType::Integer))
            .map(|c| c.name.as_str())
            .collect(),
        PrimaryShape::Update(_) | PrimaryShape::Delete => vec!["id"],
    };
    if int_cols.is_empty() {
        return Vec::new();
    }
    let n = match shape {
        PrimaryShape::Delete | PrimaryShape::Update(_) => rng.random_range(0..=1),
        PrimaryShape::Insert => rng.random_range(0..=3),
    };
    (0..n).map(|_| random_assertion(rng, &int_cols)).collect()
}

fn random_assertion(rng: &mut impl Rng, int_cols: &[&str]) -> Assertion {
    // 70% atomic, 20% compound (and / or), 10% not.
    match rng.random_range(0..10) {
        0..=6 => Assertion::Rule(random_self_rule(rng, int_cols)),
        7 => {
            let a = Assertion::Rule(random_self_rule(rng, int_cols));
            let b = Assertion::Rule(random_self_rule(rng, int_cols));
            a.and(b)
        }
        8 => {
            let a = Assertion::Rule(random_self_rule(rng, int_cols));
            let b = Assertion::Rule(random_self_rule(rng, int_cols));
            a.or(b)
        }
        _ => Assertion::Rule(random_self_rule(rng, int_cols)).not(),
    }
}

fn random_self_rule(rng: &mut impl Rng, int_cols: &[&str]) -> AccessRule {
    let col = int_cols[rng.random_range(0..int_cols.len())].to_string();
    let left = RuleValue::column(ColumnNamespace::SelfRow, col);
    let (op, right) = match rng.random_range(0..6) {
        // `self.<col> == auth.user_id` — canonical owner pattern.
        0 => (ComparisonOp::Equal, RuleValue::AuthUserId),
        // `self.<col> != 0` — non-zero check.
        1 => (ComparisonOp::NotEqual, RuleValue::Int(0)),
        // `self.<col> >= <K>` — lower bound.
        2 => (
            ComparisonOp::GreaterEqual,
            RuleValue::Int(rng.random_range(-1_000_000..=1_000_000)),
        ),
        // `self.<col> <= <K>` — upper bound.
        3 => (
            ComparisonOp::LessEqual,
            RuleValue::Int(rng.random_range(-1_000_000..=1_000_000)),
        ),
        // `self.<col> == <K>` — equality with literal.
        4 => (
            ComparisonOp::Equal,
            RuleValue::Int(rng.random_range(-1_000..=1_000)),
        ),
        // `self.<col> > 0` — positive check.
        _ => (ComparisonOp::Greater, RuleValue::Int(0)),
    };
    AccessRule::comparison(left, op, right)
}

fn random_action_name(rng: &mut impl Rng, existing: &std::collections::HashSet<String>) -> String {
    // Same shape as `random_table_name`: lowercase letters + digits,
    // starts with a letter.  Prefixed with `act_` so action names don't
    // collide with table names in printed traces.
    loop {
        let len = rng.random_range(4..=10);
        let body: String = (0..len)
            .map(|i| {
                if i == 0 {
                    (b'a' + rng.random_range(0..26)) as char
                } else {
                    let pool = b"abcdefghijklmnopqrstuvwxyz0123456789";
                    pool[rng.random_range(0..pool.len())] as char
                }
            })
            .collect();
        let name = format!("act_{body}");
        if !existing.contains(&name) {
            return name;
        }
    }
}
