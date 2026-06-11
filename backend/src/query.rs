use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    pub table: String,
    pub operation: QueryOperation,
    pub predicate: Option<Predicate>,
    pub join: Option<JoinClause>,
    /// Direction of the predicate's range walk. `Asc` returns rows from the
    /// low end of the matching range; `Desc` from the high end. With `limit`
    /// set, this selects which rows are returned.
    pub order: Order,
    /// Maximum number of rows the server returns. Bound into the proof.
    pub limit: Option<u32>,
}

impl Query {
    /// Create a new query
    pub fn new(table: String, operation: QueryOperation) -> Self {
        Self {
            table,
            operation,
            predicate: None,
            join: None,
            order: Order::Asc,
            limit: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryParam {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
    Boolean(bool),
}

// From implementations for QueryParam
impl From<i32> for QueryParam {
    fn from(value: i32) -> Self {
        QueryParam::Integer(value as i64)
    }
}

impl From<i64> for QueryParam {
    fn from(value: i64) -> Self {
        QueryParam::Integer(value)
    }
}

impl From<f32> for QueryParam {
    fn from(value: f32) -> Self {
        QueryParam::Real(value as f64)
    }
}

impl From<f64> for QueryParam {
    fn from(value: f64) -> Self {
        QueryParam::Real(value)
    }
}

impl From<String> for QueryParam {
    fn from(value: String) -> Self {
        QueryParam::Text(value)
    }
}

impl From<&str> for QueryParam {
    fn from(value: &str) -> Self {
        QueryParam::Text(value.to_string())
    }
}

impl From<bool> for QueryParam {
    fn from(value: bool) -> Self {
        QueryParam::Integer(if value { 1 } else { 0 })
    }
}

impl From<Vec<u8>> for QueryParam {
    fn from(value: Vec<u8>) -> Self {
        QueryParam::Blob(value)
    }
}

impl From<serde_json::Value> for QueryParam {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => QueryParam::Null,
            serde_json::Value::Bool(b) => QueryParam::Boolean(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    QueryParam::Integer(i)
                } else if let Some(f) = n.as_f64() {
                    QueryParam::Real(f)
                } else {
                    QueryParam::Integer(0) // fallback
                }
            }
            serde_json::Value::String(s) => QueryParam::Text(s),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                // Serialize complex JSON values as text
                match serde_json::to_string(&value) {
                    Ok(s) => QueryParam::Text(s),
                    Err(_) => QueryParam::Null,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryOperation {
    Select(Vec<String>),
    Insert(Vec<(String, QueryParam)>),
    Update(Vec<(String, QueryParam)>),
    Delete,
}

/// A server-side predicate on a single column. Must target the primary key
/// (id) or a secondary index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Predicate {
    pub column: String,
    pub operator: ComparisonOperator,
    /// For Eq/Gt/Lt/etc.: single value in `values[0]`.
    /// For In: list of values.
    /// For Between: `[low, high]` (inclusive).
    pub values: Vec<QueryParam>,
    /// Cursor id for pagination. Only meaningful with `operator == Equal`
    /// on a non-id column: restricts matches to rows whose `id` is on the
    /// next-page side of `cursor_id`, where the side is decided by
    /// `Query.order`:
    ///   - `Order::Asc`  → `id > cursor_id` (oldest-first walk, next page)
    ///   - `Order::Desc` → `id < cursor_id` (newest-first walk, older page)
    ///
    /// Validation rejects this with non-Equal operators or id-column eq.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComparisonOperator {
    Equal,
    In,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Between,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinClause {
    pub table: String,
    /// `(fk_col, pk_col)` — foreign key column in main table, primary/indexed
    /// column in joined table.
    pub on_condition: (String, String),
}

/// Direction of the predicate's range walk. `Asc` starts from the low end of
/// the matching range; `Desc` starts from the high end. With a `limit`, this
/// determines which rows are returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Order {
    #[default]
    Asc,
    Desc,
}
